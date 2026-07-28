# -*- coding: utf-8 -*-
"""Pont Alertmanager -> HolmesGPT -> Slack (v2).

Reçoit les webhooks Alertmanager (POST /webhook), déclenche une investigation
HolmesGPT (/api/chat) pour chaque alerte firing nouvelle, et poste le
diagnostic sur le canal Slack dédié à l'agent (#sre-agent), séparé des
canaux d'alerte.

Zéro dépendance externe (stdlib uniquement) : tourne tel quel dans
python:3.11-slim.

v2 (27/07/2026) — retours d'expérience de la mise en service :
 1. Retry sur quota LLM saturé (429, vécu avec le free tier Gemini) : une
    enquête n'est plus perdue au premier 429, on retente après RETRY_WAIT_S.
 2. Messages Slack riches (Block Kit) : couleur par sévérité, en-tête
    structuré, bouton Dashboard (runbook_url), troncature propre.
 3. TL;DR : le prompt exige une ligne « Verdict : … » en tête — c'est la
    seule ligne visible dans une notification push Slack.
 4. Dédup persistante : _seen est sérialisé dans DEDUP_STATE_FILE (volume
    emptyDir) — un restart du conteneur ne redéclenche plus une rafale
    d'enquêtes (vécu : rollout pendant un orage d'alertes => quota pulvérisé).
 5. Anti-fatigue post-mortem : seuls les incidents « dignes d'un post-mortem »
    en produisent un (sévérité dans POSTMORTEM_SEVERITIES ET durée >=
    POSTMORTEM_MIN_S) — sinon le canal 📋 devient du bruit qu'on ignore.
"""
import json
import os
import re
import time
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOLMES_URL = os.environ.get(
    "HOLMES_URL", "http://holmesgpt-holmes.monitoring.svc.cluster.local:80")
HOLMES_MODEL = os.environ.get("HOLMES_MODEL", "gemini-flash")
SLACK_WEBHOOK_FILE = os.environ.get(
    "SLACK_WEBHOOK_FILE", "/etc/slack/slack-url-agent")
DEDUP_TTL_S = int(os.environ.get("DEDUP_TTL_S", "3600"))       # 1 h / alerte
MAX_PER_HOUR = int(os.environ.get("MAX_PER_HOUR", "10"))        # quota LLM
HOLMES_TIMEOUT_S = int(os.environ.get("HOLMES_TIMEOUT_S", "180"))
# Fichier de persistance de la dédup (volume emptyDir monté sur /state).
DEDUP_STATE_FILE = os.environ.get("DEDUP_STATE_FILE", "/state/seen.json")
# Retry quand le quota LLM est saturé (429 du free tier Gemini).
RETRY_MAX = int(os.environ.get("RETRY_MAX", "3"))
RETRY_WAIT_S = int(os.environ.get("RETRY_WAIT_S", "75"))
# Rapport post-incident quand l'alerte passe resolved (nécessite aussi
# send_resolved: true sur le receiver holmes-bridge d'Alertmanager).
POSTMORTEM = os.environ.get("POSTMORTEM_ENABLED", "false").lower() == "true"
# Anti-fatigue : post-mortem seulement si la sévérité est dans cette liste
# (CSV) ET si l'incident a duré au moins POSTMORTEM_MIN_S secondes.
POSTMORTEM_SEVERITIES = set(
    s.strip() for s in
    os.environ.get("POSTMORTEM_SEVERITIES", "critical").split(",") if s.strip())
POSTMORTEM_MIN_S = int(os.environ.get("POSTMORTEM_MIN_S", "300"))
# Amélioration D : annotation Grafana à chaque verdict (marqueur sur les
# dashboards). Auto-désactivée si le fichier token n'existe pas.
GRAFANA_URL = os.environ.get(
    "GRAFANA_URL", "http://grafana.monitoring.svc.cluster.local:80")
GRAFANA_TOKEN_FILE = os.environ.get(
    "GRAFANA_TOKEN_FILE", "/etc/grafana/annotator-token")
# Amélioration E : modèles de secours (CSV, essayés dans l'ordre) quand le
# quota du modèle courant est épuisé après RETRY_MAX tentatives. Chaque
# modèle doit exister dans le modelList de holmes-values.yaml. Les quotas
# free tier Gemini étant comptés PAR MODÈLE, un 2e Flash-Lite d'une autre
# génération double la capacité/minute avant de tomber sur Groq.
FALLBACK_MODELS = [m.strip() for m in
                   os.environ.get("FALLBACK_MODEL", "").split(",") if m.strip()]
# RAG post-mortems : chaque diagnostic/post-mortem publié est aussi poussé
# vers l'index vectoriel (service postmortem-rag). Vide = désactivé.
RAG_URL = os.environ.get("RAG_URL", "").strip()

# Méta-observabilité : compteurs exposés en format Prometheus sur GET /metrics
# (scrappés via les annotations prometheus.io/* du Deployment). L'agent
# s'observe lui-même : enquêtes, skips par raison, 429, fallbacks, durées.
_metrics = {
    "investigations_posted": 0, "postmortems_posted": 0,
    "skips_dedup": 0, "skips_cap": 0, "skips_postmortem_filter": 0,
    "skips_synthetic": 0, "errors": 0, "quota_429": 0,
    "fallback_switch": 0, "annotations_posted": 0,
    "duration_sum": 0.0, "duration_count": 0,
}


def _metrics_text():
    m = _metrics
    lines = ["# Métriques du bridge holmes (agent SRE)"]
    for k in ("investigations_posted", "postmortems_posted", "skips_dedup",
              "skips_cap", "skips_postmortem_filter", "skips_synthetic",
              "errors", "quota_429", "fallback_switch", "annotations_posted"):
        lines.append(f"holmes_bridge_{k}_total {m[k]}")
    lines.append(f"holmes_bridge_investigation_duration_seconds_sum {m['duration_sum']:.1f}")
    lines.append(f"holmes_bridge_investigation_duration_seconds_count {m['duration_count']}")
    return "\n".join(lines) + "\n"


def _rag_add(title, text, tags):
    """Alimente l'index vectoriel des incidents. No-op si RAG_URL est vide."""
    if not RAG_URL:
        return
    try:
        body = json.dumps({"title": title, "text": text[:8000],
                           "tags": tags}).encode()
        req = urllib.request.Request(
            f"{RAG_URL}/add", data=body,
            headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=20)
        log(f"rag: document indexé ({title})")
    except Exception as e:
        log(f"rag add error: {e}")

_seen = {}           # fingerprint -> timestamp (persisté dans DEDUP_STATE_FILE)
_hour_window = []    # timestamps des investigations lancées
_lock = threading.Lock()

# Chaînage diagnostic -> post-mortem : le diagnostic rendu À CHAUD pendant
# l'incident est conservé (par fingerprint) et injecté dans le prompt du
# post-mortem — l'agent confronte alors ses mesures d'après-coup aux preuves
# capturées au moment des faits, au lieu d'enquêter de mémoire froide.
DIAG_STATE_FILE = os.environ.get("DIAG_STATE_FILE", "/state/diags.json")
DIAG_TTL_S = int(os.environ.get("DIAG_TTL_S", "86400"))   # 24 h
_diags = {}          # fingerprint -> {"t": ts, "text": diagnostic}

SEV_COLORS = {"critical": "#D40E0D", "warning": "#F2A100"}

# Amélioration A : connaissance permanente de la plateforme, injectée en tête
# de chaque prompt. L'agent n'a plus à redécouvrir la topologie à chaque
# enquête, et il connaît les modes de panne DÉJÀ observés sur CE cluster.
PLATFORM_CONTEXT = """CONTEXTE PLATEFORME (connaissance permanente — utilise-la
pour orienter l'enquête, mais vérifie toujours par la mesure) :
- Topologie (namespace online-boutique, mesh Istio AMBIENT, SLI mesurés par le
  waypoint via istio_requests_total) : loadgenerator -> frontend (2 replicas)
  -> productcatalog / cart / currency / recommendation / ad ;
  checkout -> payment + shipping + email + currency + cart ;
  cartservice -> redis-cart (Redis, dépendance non instrumentée directement).
- SLO : checkout_success 99,95 % | frontend_availability 99,9 % |
  productcatalog & cart 99 % | user_journey 99,5 % (produit des 4 maillons).
  Recording rules Prometheus : sli:* et slo:* (burnrates multi-fenêtres).
- MODES DE PANNE DÉJÀ OBSERVÉS sur ce cluster :
  1) Après un reboot du nœud K3s, les pods créés AVANT le reboot peuvent
     garder un enrôlement mesh ambient cassé. Signature : gRPC 14 UNAVAILABLE
     vers le service, "upstream connect error" ou "SocketClosed" côté client,
     alors que le pod cible est Running/Ready. Remède prouvé : rollout
     restart du deployment CIBLE (vécu le 27/07/2026 : redis-cart, puis
     paymentservice).
  2) Pannes "pod vert" : pod 1/1 Running mais service indisponible — toujours
     confronter le SLI mesuré à l'état des pods.
  3) Le loadgenerator est la seule source de trafic : s'il est HS, les SLI
     deviennent VIDES (absence de données ≠ panne à 100 %).
"""

PROMPT = """Tu es l'agent SRE de la plateforme Online Boutique (K3s mono-node,
namespace online-boutique, mesh Istio ambient, SLI/SLO mesurés par le waypoint).
L'alerte Prometheus suivante vient de passer en firing :

- alertname : {alertname}
- sévérité : {severity}
- slo : {slo}
- description : {description}
- labels : {labels}

AVANT de conclure, tu DOIS avoir exécuté TOI-MÊME, avec tes outils, au
minimum ces 3 inspections (ne saute aucune étape) :
a) une requête PromQL ventilant les erreurs par service pour localiser le
   coupable, par exemple :
   sum by (destination_workload, grpc_response_status)
     (rate(istio_requests_total{{grpc_response_status=~"2|4|8|12|13|14|15"}}[5m]))
b) la lecture des LOGS des pods du ou des services que (a) incrimine ;
c) kubectl describe / events de ces pods (restarts, OOM, probes).
RÈGLE ABSOLUE : ne recommande JAMAIS à l'humain une action d'inspection
(« vérifier les logs », « analyser les métriques ») que tes outils te
permettent de faire toi-même — fais-la pendant l'enquête et cite le résultat.

Rends un diagnostic en FRANÇAIS.
IMPÉRATIF : ta TOUTE PREMIÈRE ligne doit être exactement de la forme
« Verdict : <cause racine en une phrase> » (c'est la seule ligne visible dans
la notification Slack), suivie d'une ligne vide. Puis structure ainsi :
1. Cause racine la plus probable (développée, avec le service précis).
2. Preuves (valeurs mesurées : SLI, burn rate, codes gRPC PAR SERVICE,
   extraits de logs, état des pods).
3. Vérification clé : les pods sont-ils Running/Ready ? (si oui et que le SLI
   plonge, dis explicitement que c'est une panne invisible pour Kubernetes).
4. Actions CORRECTIVES recommandées — uniquement de la remédiation (jamais de
   l'inspection), classées :
   a) mitigation immédiate (ex. rollout restart du service incriminé),
   b) correctif durable si identifiable,
   c) prévention.
   Chaque action cite la preuve qui la justifie et donne la commande exacte
   avec les VRAIS noms de ressources (ex. `deploy/paymentservice`, jamais un
   nom de pod recopié en nom de deployment). Si tu n'as pas la preuve qu'une
   action corrigera le problème, dis-le au lieu de la recommander.
Termine par UNE ligne : « Confiance : haute|moyenne|basse — <ce qui pourrait
falsifier ce diagnostic> » (haute = cause directement observée ; moyenne =
déduite de mesures concordantes ; basse = hypothèse restante).
Sois factuel : cite uniquement ce que tes outils ont réellement retourné."""

PROMPT_POSTMORTEM = """Tu es l'agent SRE de la plateforme Online Boutique
(K3s, namespace online-boutique, mesh Istio ambient). L'incident suivant vient
de se RÉSOUDRE — rédige un brouillon de post-mortem SANS BLÂME, en FRANÇAIS :

- alertname : {alertname}  (sévérité {severity}, slo {slo})
- début : {starts_at} — fin : {ends_at}
- description initiale : {description}
{prior_diag}
IMPÉRATIF : ta TOUTE PREMIÈRE ligne doit être exactement de la forme
« Verdict : <cause racine et durée en une phrase> », suivie d'une ligne vide.
AVANT de rédiger, tu DOIS avoir exécuté TOI-MÊME :
a) des RANGE QUERIES Prometheus sur la fenêtre EXACTE de l'incident
   (start={starts_at}, end={ends_at}, élargie de 15 min de chaque côté) sur
   le SLI et le burn rate concernés — pas des instant queries d'après-coup ;
b) la lecture des logs des pods impliqués sur cette fenêtre ;
c) le budget d'erreur avant/après (slo:*:error_budget_remaining_ratio).
Puis produis :
1. Chronologie (début, pic, retour au nominal — valeurs mesurées à l'appui).
2. Cause racine probable et périmètre impacté. Si un diagnostic à chaud est
   fourni ci-dessus, CONFRONTE-le à tes mesures : confirme-le ou corrige-le
   explicitement.
3. Impact contractuel : durée, et budget d'erreur consommé (avant/après).
4. Recommandations de PRÉVENTION classées :
   a) Configuration (limits, replicas, PDB…),
   b) Alerting (seuil/fenêtre à ajuster, angle mort éventuel),
   c) Architecture (retry, timeout, isolation de dépendance).
RÈGLE : chaque recommandation doit citer la preuve mesurée qui la motive ;
une recommandation générique sans preuve est interdite — supprime-la.
Termine par UNE ligne : « Confiance : haute|moyenne|basse — <ce qui pourrait
falsifier cette analyse> ».
Sois factuel : cite uniquement ce que tes outils ont réellement retourné."""


def log(msg):
    print(f"[bridge] {msg}", flush=True)


# --------------------------------------------------------------------------
#  Dédup persistante (amélioration 4)
# --------------------------------------------------------------------------
def _load_seen():
    try:
        with open(DEDUP_STATE_FILE) as f:
            data = json.load(f)
        return {str(k): float(v) for k, v in data.items()}
    except Exception:
        return {}


def _save_seen():
    # Appelé sous _lock. Écriture atomique (tmp + rename) pour ne jamais
    # laisser un fichier corrompu.
    try:
        tmp = DEDUP_STATE_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(_seen, f)
        os.replace(tmp, DEDUP_STATE_FILE)
    except Exception as e:
        log(f"state save error: {e}")


def _load_diags():
    try:
        with open(DIAG_STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def _store_diag(fp, text):
    now = time.time()
    with _lock:
        for k in [k for k, v in _diags.items() if now - v.get("t", 0) > DIAG_TTL_S]:
            del _diags[k]
        _diags[fp] = {"t": now, "text": text[:4000]}
        try:
            tmp = DIAG_STATE_FILE + ".tmp"
            with open(tmp, "w") as f:
                json.dump(_diags, f)
            os.replace(tmp, DIAG_STATE_FILE)
        except Exception as e:
            log(f"diag save error: {e}")


def _alert_fp(alert):
    labels = alert.get("labels", {})
    return (alert.get("fingerprint")
            or (labels.get("alertname", "") + alert.get("startsAt", "")))


def _recent_incidents(exclude_fp=None, n=3):
    # Amélioration A (mémoire) : les verdicts des derniers diagnostics (24 h)
    # sont injectés dans le prompt — l'agent peut reconnaître une récidive.
    with _lock:
        items = sorted(
            ((fp, v) for fp, v in _diags.items() if fp != exclude_fp),
            key=lambda kv: kv[1].get("t", 0), reverse=True)[:n]
    if not items:
        return ""
    lines = []
    for _, v in items:
        when = datetime.fromtimestamp(v.get("t", 0), timezone.utc)
        first = (v.get("text") or "").strip().split("\n")[0][:220]
        lines.append(f"  - [{when.strftime('%d/%m %H:%M')} UTC] {first}")
    return ("\nINCIDENTS RÉCENTS déjà diagnostiqués sur ce cluster (mémoire de "
            "l'agent — si la panne actuelle ressemble à l'un d'eux, dis-le et "
            "vérifie si c'est une récidive) :\n" + "\n".join(lines) + "\n")


# --------------------------------------------------------------------------
#  Slack (amélioration 2 : Block Kit)
# --------------------------------------------------------------------------
def _slack_send(payload):
    try:
        with open(SLACK_WEBHOOK_FILE) as f:
            url = f.read().strip()
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=15)
    except Exception as e:
        log(f"slack error: {e}")


def slack_post(text):
    """Message simple (erreurs, avertissements)."""
    _slack_send({"text": text[:3900]})


def grafana_annotate(text, tags):
    """Amélioration D : pose le verdict en annotation sur les dashboards
    Grafana (marqueur temporel visible sur les graphes SLI, aux côtés des
    annotations de chaos). No-op silencieux si le token n'est pas monté."""
    try:
        with open(GRAFANA_TOKEN_FILE) as f:
            token = f.read().strip()
    except Exception:
        return                       # feature désactivée : pas de token
    try:
        body = json.dumps({
            "time": int(time.time() * 1000),
            "tags": ["sre-agent"] + tags,
            "text": text[:600],
        }).encode()
        req = urllib.request.Request(
            f"{GRAFANA_URL}/api/annotations", data=body,
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {token}"})
        urllib.request.urlopen(req, timeout=10)
        _metrics["annotations_posted"] += 1
        log("grafana annotation posted")
    except Exception as e:
        log(f"grafana annotation error: {e}")


def _to_mrkdwn(text):
    # Holmes rend du Markdown standard ; Slack parle « mrkdwn » :
    # **gras** -> *gras*, "## Titre" -> *Titre*.
    text = re.sub(r"^#{1,6}\s*(.+)$", r"*\1*", text, flags=re.M)
    return text.replace("**", "*")


def _split_chunks(text, size=2800):
    # Un bloc section Slack est limité à 3000 caractères : on coupe sur une
    # fin de ligne pour ne jamais trancher une phrase (amélioration 2).
    parts = []
    while text:
        if len(text) <= size:
            parts.append(text)
            break
        cut = text.rfind("\n", 0, size)
        if cut < size // 2:
            cut = size
        parts.append(text[:cut])
        text = text[cut:].lstrip("\n")
    return parts


def slack_post_rich(title, severity, slo, analysis, runbook_url=None):
    blocks = [{"type": "header",
               "text": {"type": "plain_text", "text": title[:150]}}]
    ts = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M UTC")
    blocks.append({"type": "context", "elements": [{
        "type": "mrkdwn",
        "text": f"sévérité : *{severity}*  •  slo : `{slo}`  •  {ts}"}]})
    chunks = _split_chunks(_to_mrkdwn(analysis))
    for c in chunks[:4]:                      # 4 sections max (~11 000 car.)
        blocks.append({"type": "section",
                       "text": {"type": "mrkdwn", "text": c[:2950]}})
    if len(chunks) > 4:
        blocks.append({"type": "context", "elements": [{
            "type": "mrkdwn",
            "text": "… _(diagnostic tronqué — version complète dans les "
                    "logs du pod Holmes)_"}]})
    if runbook_url and runbook_url.startswith("http"):
        blocks.append({"type": "actions", "elements": [{
            "type": "button",
            "text": {"type": "plain_text", "text": "📊 Dashboard"},
            "url": runbook_url}]})
    _slack_send({"attachments": [{
        "color": SEV_COLORS.get(severity, "#439FE0"), "blocks": blocks}]})


# --------------------------------------------------------------------------
#  Appel Holmes : retry quota (v2) + fallback de modèle (amélioration E)
# --------------------------------------------------------------------------
def _is_quota_error(code, body):
    # Holmes propage le 429 Gemini tel quel, ou parfois en 500
    # contenant RateLimitError : les deux sont transitoires.
    return code == 429 or (code == 500 and ("RateLimit" in body or "429" in body))


def _call_holmes(ask):
    models = [HOLMES_MODEL] + FALLBACK_MODELS
    last_exc = None
    for model in models:
        payload = json.dumps({"ask": ask, "model": model}).encode()
        for attempt in range(1, RETRY_MAX + 1):
            try:
                req = urllib.request.Request(
                    f"{HOLMES_URL}/api/chat", data=payload,
                    headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=HOLMES_TIMEOUT_S) as r:
                    return json.loads(r.read())
            except urllib.error.HTTPError as e:
                body = ""
                try:
                    body = e.read().decode(errors="replace")[:300]
                except Exception:
                    pass
                if _is_quota_error(e.code, body):
                    _metrics["quota_429"] += 1
                    if attempt < RETRY_MAX:
                        log(f"quota LLM saturé sur {model} (tentative "
                            f"{attempt}/{RETRY_MAX}), retry dans {RETRY_WAIT_S}s")
                        time.sleep(RETRY_WAIT_S)
                        continue
                    last_exc = e
                    idx = models.index(model)
                    if idx < len(models) - 1:
                        _metrics["fallback_switch"] += 1
                        log(f"quota épuisé sur {model} -> bascule sur le "
                            f"modèle de secours {models[idx + 1]}")
                    break        # modèle suivant (ou abandon si dernier)
                raise            # erreur non-quota : inutile d'insister
    raise last_exc


def investigate(alert, postmortem=False):
    labels = alert.get("labels", {})
    ann = alert.get("annotations", {})
    fp = _alert_fp(alert)
    if postmortem:
        prior = _diags.get(fp, {}).get("text")
        prior_diag = (
            "\n- Diagnostic rendu À CHAUD pendant l'incident (à confronter "
            "aux données de la fenêtre) :\n« " + prior + " »\n"
        ) if prior else "\n"
        ask = PROMPT_POSTMORTEM.format(
            alertname=labels.get("alertname", "?"),
            severity=labels.get("severity", "?"),
            slo=labels.get("slo", "?"),
            starts_at=alert.get("startsAt", "?"),
            ends_at=alert.get("endsAt", "?"),
            description=ann.get("description", ann.get("summary", "?")),
            prior_diag=prior_diag,
        )
    else:
        ask = PROMPT.format(
            alertname=labels.get("alertname", "?"),
            severity=labels.get("severity", "?"),
            slo=labels.get("slo", "?"),
            description=ann.get("description", ann.get("summary", "?")),
            labels=json.dumps(labels, ensure_ascii=False),
        )
    # Amélioration A : contexte plateforme + mémoire des incidents récents
    # injectés en tête de chaque enquête (diagnostic ET post-mortem).
    ask = PLATFORM_CONTEXT + _recent_incidents(exclude_fp=fp) + "\n" + ask
    resp = _call_holmes(ask)
    analysis = resp.get("analysis") or resp.get("response") or json.dumps(resp)
    if not postmortem:
        _store_diag(fp, analysis)    # servira au post-mortem de cette alerte
    icon = "📋 Post-mortem" if postmortem else "🤖 Diagnostic"
    slack_post_rich(
        title=f"{icon} — {labels.get('alertname', '?')}",
        severity=labels.get("severity", "?"),
        slo=labels.get("slo", "?"),
        analysis=analysis,
        runbook_url=ann.get("runbook_url"),
    )
    # Amélioration D : le verdict devient un marqueur sur les dashboards.
    verdict_line = analysis.strip().split("\n")[0]
    grafana_annotate(
        f"{icon} {labels.get('alertname', '?')} — {verdict_line}",
        tags=[labels.get("alertname", "?"), labels.get("severity", "?")])
    # RAG : le document rejoint l'index vectoriel des incidents.
    when = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    _rag_add(
        title=f"{icon} {labels.get('alertname', '?')} — {when}",
        text=analysis,
        tags=[labels.get("alertname", "?"), labels.get("slo", "?"),
              labels.get("severity", "?"),
              "postmortem" if postmortem else "diagnostic"])
    _metrics["postmortems_posted" if postmortem
             else "investigations_posted"] += 1
    log(f"{'postmortem' if postmortem else 'investigation'} posted "
        f"for {labels.get('alertname')}")


def _incident_duration_s(alert):
    try:
        s = datetime.fromisoformat(alert["startsAt"].replace("Z", "+00:00"))
        e = datetime.fromisoformat(alert["endsAt"].replace("Z", "+00:00"))
        return (e - s).total_seconds()
    except Exception:
        return None    # date illisible -> on ne filtre pas


def handle(alerts):
    now = time.time()
    for alert in alerts:
        status = alert.get("status")
        postmortem = status == "resolved" and POSTMORTEM
        if status != "firing" and not postmortem:
            continue
        name = alert.get("labels", {}).get("alertname", "")
        if name == "Watchdog":
            continue
        # Alertes de test explicitement taguées (recommandation émise par
        # l'agent lui-même) : jamais d'enquête ni de post-mortem.
        if alert.get("labels", {}).get("synthetic") == "true":
            _metrics["skips_synthetic"] += 1
            log(f"skip (alerte synthetic) : {name}")
            continue
        # Anti-fatigue post-mortem (amélioration 5) : seuls les incidents
        # significatifs méritent un 📋 dans le canal.
        if postmortem:
            sev = alert.get("labels", {}).get("severity", "")
            if sev not in POSTMORTEM_SEVERITIES:
                _metrics["skips_postmortem_filter"] += 1
                log(f"skip post-mortem (sévérité {sev or '?'} hors "
                    f"{sorted(POSTMORTEM_SEVERITIES)}) : {name}")
                continue
            dur = _incident_duration_s(alert)
            if dur is not None and dur < POSTMORTEM_MIN_S:
                _metrics["skips_postmortem_filter"] += 1
                log(f"skip post-mortem (durée {int(dur)}s < "
                    f"{POSTMORTEM_MIN_S}s) : {name}")
                continue
        fp = alert.get("fingerprint") or (name + alert.get("startsAt", ""))
        fp += "|pm" if postmortem else ""
        with _lock:
            for k, t in list(_seen.items()):
                if now - t > DEDUP_TTL_S:
                    del _seen[k]
            while _hour_window and now - _hour_window[0] > 3600:
                _hour_window.pop(0)
            if fp in _seen:
                _metrics["skips_dedup"] += 1
                log(f"skip (déjà investiguée) : {name}")
                continue
            if len(_hour_window) >= MAX_PER_HOUR:
                _metrics["skips_cap"] += 1
                log(f"skip (plafond {MAX_PER_HOUR}/h atteint) : {name}")
                continue
            _seen[fp] = now
            _hour_window.append(now)
            _save_seen()
        threading.Thread(target=_safe_investigate, args=(alert, postmortem),
                         daemon=True).start()


def _safe_investigate(alert, postmortem=False):
    name = alert.get("labels", {}).get("alertname", "?")
    t0 = time.time()
    try:
        investigate(alert, postmortem=postmortem)
        _metrics["duration_sum"] += time.time() - t0
        _metrics["duration_count"] += 1
    except Exception as e:
        _metrics["errors"] += 1
        log(f"holmes error for {name}: {e}")
        if "429" in str(e) or "RateLimit" in str(e):
            slack_post(f"⏳ Quota LLM saturé : enquête sur *{name}* abandonnée "
                       f"après {RETRY_MAX} tentatives — le pipeline d'alerting "
                       f"Slack reste intact, réessayer plus tard via une "
                       f"question ad hoc (/api/chat).")
        else:
            slack_post(f"🤖 HolmesGPT n'a pas pu investiguer *{name}* : `{e}`")


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/webhook":
            self.send_response(404)
            self.end_headers()
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(length))
            handle(data.get("alerts", []))
            self.send_response(200)
        except Exception as e:
            log(f"webhook error: {e}")
            self.send_response(500)
        self.end_headers()

    def do_GET(self):  # probes liveness/readiness + métriques Prometheus
        if self.path == "/metrics":
            body = _metrics_text().encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(200 if self.path == "/healthz" else 404)
        self.end_headers()

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    _seen = _load_seen()
    _diags = _load_diags()
    log(f"listening :8000 -> holmes={HOLMES_URL} model={HOLMES_MODEL} "
        f"dedup={DEDUP_TTL_S}s max={MAX_PER_HOUR}/h retry={RETRY_MAX}x{RETRY_WAIT_S}s "
        f"state={DEDUP_STATE_FILE} ({len(_seen)} empreintes rechargées) "
        f"postmortem={'on' if POSTMORTEM else 'off'}"
        f"[sev={','.join(sorted(POSTMORTEM_SEVERITIES))},min={POSTMORTEM_MIN_S}s] "
        f"fallback={','.join(FALLBACK_MODELS) or 'off'} "
        f"grafana={'on' if os.path.exists(GRAFANA_TOKEN_FILE) else 'off'} "
        f"memoire={len(_diags)} diag(s)")
    ThreadingHTTPServer(("", 8000), Handler).serve_forever()

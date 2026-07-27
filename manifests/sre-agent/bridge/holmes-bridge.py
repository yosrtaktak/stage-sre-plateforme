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

_seen = {}           # fingerprint -> timestamp (persisté dans DEDUP_STATE_FILE)
_hour_window = []    # timestamps des investigations lancées
_lock = threading.Lock()

SEV_COLORS = {"critical": "#D40E0D", "warning": "#F2A100"}

PROMPT = """Tu es l'agent SRE de la plateforme Online Boutique (K3s mono-node,
namespace online-boutique, mesh Istio ambient, SLI/SLO mesurés par le waypoint).
L'alerte Prometheus suivante vient de passer en firing :

- alertname : {alertname}
- sévérité : {severity}
- slo : {slo}
- description : {description}
- labels : {labels}

Mène l'enquête avec tes outils (PromQL sur les recording rules sli:* et slo:*,
kubectl, logs) et rends un diagnostic en FRANÇAIS.
IMPÉRATIF : ta TOUTE PREMIÈRE ligne doit être exactement de la forme
« Verdict : <cause racine en une phrase> » (c'est la seule ligne visible dans
la notification Slack), suivie d'une ligne vide. Puis structure ainsi :
1. Cause racine la plus probable (développée).
2. Preuves (valeurs mesurées : SLI, burn rate, statuts gRPC, état des pods).
3. Vérification clé : les pods sont-ils Running/Ready ? (si oui et que le SLI
   plonge, dis explicitement que c'est une panne invisible pour Kubernetes).
4. Actions recommandées (2-3, concrètes, commandes incluses).
Sois factuel : cite uniquement ce que tes outils ont réellement retourné."""

PROMPT_POSTMORTEM = """Tu es l'agent SRE de la plateforme Online Boutique
(K3s, namespace online-boutique, mesh Istio ambient). L'incident suivant vient
de se RÉSOUDRE — rédige un brouillon de post-mortem SANS BLÂME, en FRANÇAIS :

- alertname : {alertname}  (sévérité {severity}, slo {slo})
- début : {starts_at} — fin : {ends_at}
- description initiale : {description}

IMPÉRATIF : ta TOUTE PREMIÈRE ligne doit être exactement de la forme
« Verdict : <cause racine et durée en une phrase> », suivie d'une ligne vide.
Avec tes outils (PromQL sur sli:* / slo:*, kubectl, logs), reconstitue la
fenêtre de l'incident et produis :
1. Chronologie (début, pic, retour au nominal — avec les valeurs de SLI/burn
   rate mesurées sur la fenêtre).
2. Cause racine probable et périmètre impacté.
3. Impact contractuel : durée, et budget d'erreur consommé
   (slo:*:error_budget_remaining_ratio avant/après si disponible).
4. Recommandations de PRÉVENTION classées :
   a) Configuration (limits, replicas, PDB…),
   b) Alerting (seuil/fenêtre à ajuster, angle mort éventuel),
   c) Architecture (retry, timeout, isolation de dépendance).
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
#  Appel Holmes avec retry quota (amélioration 1)
# --------------------------------------------------------------------------
def _call_holmes(ask):
    payload = json.dumps({"ask": ask, "model": HOLMES_MODEL}).encode()
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
            # Holmes propage le 429 Gemini tel quel, ou parfois en 500
            # contenant RateLimitError : les deux sont transitoires.
            quota = (e.code == 429
                     or (e.code == 500 and ("RateLimit" in body or "429" in body)))
            if quota and attempt < RETRY_MAX:
                log(f"quota LLM saturé (tentative {attempt}/{RETRY_MAX}), "
                    f"retry dans {RETRY_WAIT_S}s")
                time.sleep(RETRY_WAIT_S)
                continue
            raise


def investigate(alert, postmortem=False):
    labels = alert.get("labels", {})
    ann = alert.get("annotations", {})
    if postmortem:
        ask = PROMPT_POSTMORTEM.format(
            alertname=labels.get("alertname", "?"),
            severity=labels.get("severity", "?"),
            slo=labels.get("slo", "?"),
            starts_at=alert.get("startsAt", "?"),
            ends_at=alert.get("endsAt", "?"),
            description=ann.get("description", ann.get("summary", "?")),
        )
    else:
        ask = PROMPT.format(
            alertname=labels.get("alertname", "?"),
            severity=labels.get("severity", "?"),
            slo=labels.get("slo", "?"),
            description=ann.get("description", ann.get("summary", "?")),
            labels=json.dumps(labels, ensure_ascii=False),
        )
    resp = _call_holmes(ask)
    analysis = resp.get("analysis") or resp.get("response") or json.dumps(resp)
    icon = "📋 Post-mortem" if postmortem else "🤖 Diagnostic"
    slack_post_rich(
        title=f"{icon} — {labels.get('alertname', '?')}",
        severity=labels.get("severity", "?"),
        slo=labels.get("slo", "?"),
        analysis=analysis,
        runbook_url=ann.get("runbook_url"),
    )
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
        # Anti-fatigue post-mortem (amélioration 5) : seuls les incidents
        # significatifs méritent un 📋 dans le canal.
        if postmortem:
            sev = alert.get("labels", {}).get("severity", "")
            if sev not in POSTMORTEM_SEVERITIES:
                log(f"skip post-mortem (sévérité {sev or '?'} hors "
                    f"{sorted(POSTMORTEM_SEVERITIES)}) : {name}")
                continue
            dur = _incident_duration_s(alert)
            if dur is not None and dur < POSTMORTEM_MIN_S:
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
                log(f"skip (déjà investiguée) : {name}")
                continue
            if len(_hour_window) >= MAX_PER_HOUR:
                log(f"skip (plafond {MAX_PER_HOUR}/h atteint) : {name}")
                continue
            _seen[fp] = now
            _hour_window.append(now)
            _save_seen()
        threading.Thread(target=_safe_investigate, args=(alert, postmortem),
                         daemon=True).start()


def _safe_investigate(alert, postmortem=False):
    name = alert.get("labels", {}).get("alertname", "?")
    try:
        investigate(alert, postmortem=postmortem)
    except Exception as e:
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

    def do_GET(self):  # probes liveness/readiness
        self.send_response(200 if self.path == "/healthz" else 404)
        self.end_headers()

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    _seen = _load_seen()
    log(f"listening :8000 -> holmes={HOLMES_URL} model={HOLMES_MODEL} "
        f"dedup={DEDUP_TTL_S}s max={MAX_PER_HOUR}/h retry={RETRY_MAX}x{RETRY_WAIT_S}s "
        f"state={DEDUP_STATE_FILE} ({len(_seen)} empreintes rechargées) "
        f"postmortem={'on' if POSTMORTEM else 'off'}"
        f"[sev={','.join(sorted(POSTMORTEM_SEVERITIES))},min={POSTMORTEM_MIN_S}s]")
    ThreadingHTTPServer(("", 8000), Handler).serve_forever()


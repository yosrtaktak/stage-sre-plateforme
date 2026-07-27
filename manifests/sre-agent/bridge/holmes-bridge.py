# -*- coding: utf-8 -*-
"""Pont Alertmanager -> HolmesGPT -> Slack.

Reçoit les webhooks Alertmanager (POST /webhook), déclenche une investigation
HolmesGPT (/api/chat) pour chaque alerte firing nouvelle, et poste le
diagnostic sur le canal Slack dédié à l'agent (#sre-agent), séparé des
canaux d'alerte.

Zéro dépendance externe (stdlib uniquement) : tourne tel quel dans
python:3.11-slim. Déduplication par fingerprint (TTL) + plafond horaire pour
protéger le quota du free tier LLM.
"""
import json
import os
import time
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOLMES_URL = os.environ.get(
    "HOLMES_URL", "http://holmesgpt-holmes.monitoring.svc.cluster.local:80")
HOLMES_MODEL = os.environ.get("HOLMES_MODEL", "gemini-flash")
SLACK_WEBHOOK_FILE = os.environ.get(
    "SLACK_WEBHOOK_FILE", "/etc/slack/slack-url-agent")
DEDUP_TTL_S = int(os.environ.get("DEDUP_TTL_S", "3600"))       # 1 h / alerte
MAX_PER_HOUR = int(os.environ.get("MAX_PER_HOUR", "10"))        # quota LLM
HOLMES_TIMEOUT_S = int(os.environ.get("HOLMES_TIMEOUT_S", "180"))
# Rapport post-incident quand l'alerte passe resolved (nécessite aussi
# send_resolved: true sur le receiver holmes-bridge d'Alertmanager).
POSTMORTEM = os.environ.get("POSTMORTEM_ENABLED", "false").lower() == "true"

_seen = {}           # fingerprint -> timestamp
_hour_window = []    # timestamps des investigations lancées
_lock = threading.Lock()

PROMPT = """Tu es l'agent SRE de la plateforme Online Boutique (K3s mono-node,
namespace online-boutique, mesh Istio ambient, SLI/SLO mesurés par le waypoint).
L'alerte Prometheus suivante vient de passer en firing :

- alertname : {alertname}
- sévérité : {severity}
- slo : {slo}
- description : {description}
- labels : {labels}

Mène l'enquête avec tes outils (PromQL sur les recording rules sli:* et slo:*,
kubectl, logs) et rends un diagnostic en FRANÇAIS, structuré ainsi :
1. Cause racine la plus probable (une phrase).
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


def slack_post(text):
    try:
        with open(SLACK_WEBHOOK_FILE) as f:
            url = f.read().strip()
        body = json.dumps({"text": text[:3900]}).encode()
        req = urllib.request.Request(
            url, data=body, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=15)
    except Exception as e:
        log(f"slack error: {e}")


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
    payload = json.dumps({"ask": ask, "model": HOLMES_MODEL}).encode()
    req = urllib.request.Request(
        f"{HOLMES_URL}/api/chat", data=payload,
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=HOLMES_TIMEOUT_S) as r:
        resp = json.loads(r.read())
    analysis = resp.get("analysis") or resp.get("response") or json.dumps(resp)
    icon = "📋 *Post-mortem" if postmortem else "🤖 *Diagnostic"
    header = (f"{icon} HolmesGPT — {labels.get('alertname', '?')}* "
              f"(slo: `{labels.get('slo', '?')}`)\n")
    slack_post(header + analysis)
    log(f"{'postmortem' if postmortem else 'investigation'} posted "
        f"for {labels.get('alertname')}")


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
        threading.Thread(target=_safe_investigate, args=(alert, postmortem),
                         daemon=True).start()


def _safe_investigate(alert, postmortem=False):
    name = alert.get("labels", {}).get("alertname", "?")
    try:
        investigate(alert, postmortem=postmortem)
    except Exception as e:
        log(f"holmes error for {name}: {e}")
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
    log(f"listening :8000 -> holmes={HOLMES_URL} model={HOLMES_MODEL} "
        f"dedup={DEDUP_TTL_S}s max={MAX_PER_HOUR}/h")
    ThreadingHTTPServer(("", 8000), Handler).serve_forever()

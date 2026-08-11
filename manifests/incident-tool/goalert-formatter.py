#!/usr/bin/env python3
# =============================================================================
#  goalert-formatter — traducteur Alertmanager -> GoAlert (API generic)
# -----------------------------------------------------------------------------
#  Pourquoi : l'intégration prometheusalertmanager de GoAlert colle le payload
#  JSON brut dans les détails de l'alerte (emails illisibles) et son template
#  n'est pas personnalisable. Ce service reçoit le webhook Alertmanager et
#  poste sur /api/v2/generic/incoming un résumé court (sujet du mail / SMS)
#  et des détails markdown propres. Bonus non cosmétiques :
#    - dedup = fingerprint Alertmanager (déduplication exacte par alerte,
#      au lieu du couple summary+details) ;
#    - action=close sur les resolved (clôture explicite, plus fiable que la
#      déduction du chemin prometheusalertmanager).
#  Règles d'architecture (mêmes que slack-gateway) : stdlib uniquement, pas
#  de LLM, pas de dépendances — le chemin d'astreinte doit rester bête.
#  En cas d'échec de transfert on répond 502 : Alertmanager RETENTE le
#  webhook, on ne perd pas de page en silence.
#  Le token (clé d'intégration Generic API du service checkout-sre) est monté
#  depuis le Secret goalert-generic — jamais dans Git (repo public) ni dans
#  l'URL (3 corruptions d'URL vécues le 07/08 : le token voyage dans le body).
# =============================================================================
import json
import os
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

GOALERT_URL = os.environ.get(
    "GOALERT_URL",
    "http://incident-tool.monitoring.svc.cluster.local:8081"
    "/api/v2/generic/incoming")
GOALERT_TOKEN_FILE = os.environ.get("GOALERT_TOKEN_FILE", "/etc/goalert/token")
PORT = int(os.environ.get("PORT", "8020"))
TZ = timezone(timedelta(hours=1))  # Africa/Tunis (pas de tzdata en slim)


def log(msg):
    print(f"[formatter] {msg}", flush=True)


def _token():
    # Relu à chaque envoi : une rotation du Secret est prise en compte
    # sans redémarrage (propagation du montage ~75 s).
    with open(GOALERT_TOKEN_FILE) as f:
        return f.read().strip()


def _fmt_ts(iso):
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00")).astimezone(TZ)
        return dt.strftime("%d/%m %H:%M")
    except Exception:
        return iso or "?"


def _build(alert):
    labels = alert.get("labels", {})
    ann = alert.get("annotations", {})
    name = labels.get("alertname", "?")
    slo = labels.get("slo") or labels.get("service") or "?"
    firing = alert.get("status") == "firing"
    # Le summary devient le sujet de l'email ET le texte SMS/voix : court.
    summary = (f"🚨 {name} — {slo}" if firing
               else f"✅ {name} — {slo} (résolu)")
    lines = [
        f"**Service :** `{slo}` · **Sévérité :** "
        f"{labels.get('severity', '?')}",
        f"**Description :** {ann.get('description') or '—'}",
        f"**Depuis :** {_fmt_ts(alert.get('startsAt', ''))}",
    ]
    runbook = ann.get("runbook_url")
    if runbook:
        lines.append(f"**Dashboard :** {runbook}")
    return summary, "\n\n".join(lines)


def _forward(alert):
    summary, details = _build(alert)
    token = _token()
    body = {
        "token": token,
        "summary": summary[:118],
        "details": details,
        # Fingerprint stable sur toute la vie de l'alerte : firing et
        # resolved retombent sur la même alerte GoAlert.
        "dedup": alert.get("fingerprint") or summary,
    }
    if alert.get("status") == "resolved":
        body["action"] = "close"
    # Token AUSSI en query : certaines versions de GoAlert ne lisent pas le
    # token dans le corps JSON (401 vécu le 11/08). L'URL est construite par
    # programme — pas de risque de corruption manuelle.
    req = urllib.request.Request(
        GOALERT_URL + "?token=" + token, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"})
    # Timeout court : Alertmanager attend la réponse (5 alertes max/groupe,
    # il faut rester sous son timeout webhook de 10 s au total).
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.status


class Handler(BaseHTTPRequestHandler):

    def log_message(self, *a):        # silence les logs d'accès par défaut
        pass

    def do_GET(self):
        code = 200 if self.path == "/healthz" else 404
        self.send_response(code)
        self.end_headers()

    def do_POST(self):
        if self.path != "/webhook":
            self.send_response(404)
            self.end_headers()
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length) or b"{}")
        except Exception as e:
            log(f"payload invalide : {e}")
            self.send_response(400)
            self.end_headers()
            return
        failed = 0
        for alert in payload.get("alerts", []):
            name = alert.get("labels", {}).get("alertname", "?")
            try:
                status = _forward(alert)
                log(f"{alert.get('status')} -> GoAlert {status} : {name}")
            except Exception as e:
                failed += 1
                log(f"échec transfert {name} : {e}")
        # 502 si au moins un transfert a échoué -> Alertmanager retente
        # le groupe entier ; la dédup GoAlert absorbe les doublons.
        self.send_response(502 if failed else 200)
        self.end_headers()


if __name__ == "__main__":
    log(f"écoute :{PORT}, cible {GOALERT_URL}")
    ThreadingHTTPServer(("", PORT), Handler).serve_forever()


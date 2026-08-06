# -*- coding: utf-8 -*-
"""slack-gateway — le SEUL composant exposé à internet (via tunnel ngrok).

Rôle unique : recevoir les clics de boutons Slack ([✋ ACK] / [✅ Resolve]
postés par la war room), VÉRIFIER la signature Slack, et traduire le clic en
appel interne au bridge (/incident/ack|resolve). Périmètre volontairement
minuscule : même compromis, ce service ne sait ni injecter d'alertes, ni
parler au cluster — il ne connaît que deux verbes du bridge.

Sécurité (non négociable, c'est la contrepartie de l'exposition) :
 1. Signature Slack : X-Slack-Signature = v0=HMAC_SHA256(secret,
    "v0:<timestamp>:<corps>") — rejet 401 si invalide.
 2. Anti-rejeu : horodatage à ±300 s, sinon 401.
 3. Allow-list de verbes : action_id ∈ {ack, resolve}, rien d'autre.
Secret impératif (signing secret de l'app Slack, jamais dans Git) :
  kubectl -n monitoring create secret generic slack-gateway \
    --from-literal=signing-secret='<Basic Information -> Signing Secret>'

Zéro dépendance (stdlib pure), même image python:3.11-slim que le bridge.
"""
import hashlib
import hmac
import json
import os
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SIGNING_SECRET_FILE = os.environ.get(
    "SLACK_SIGNING_SECRET_FILE", "/etc/slack-gw/signing-secret")
BRIDGE_URL = os.environ.get(
    "BRIDGE_URL", "http://holmes-bridge.monitoring.svc.cluster.local:8000")
PORT = int(os.environ.get("PORT", "8010"))
MAX_AGE_S = 300                      # fenêtre anti-rejeu Slack (5 min)
ALLOWED_VERBS = {"ack", "resolve"}   # tout le reste est refusé


def log(msg):
    print(f"[slack-gateway] {msg}", flush=True)


def _secret():
    try:
        with open(SIGNING_SECRET_FILE) as f:
            return f.read().strip().encode()
    except OSError:
        return b""


def _verify(headers, body):
    """La vérification officielle Slack : HMAC du corps brut + timestamp."""
    secret = _secret()
    if not secret:
        return False                 # pas de secret monté = tout est refusé
    ts = headers.get("X-Slack-Request-Timestamp", "")
    try:
        if abs(time.time() - int(ts)) > MAX_AGE_S:
            return False             # anti-rejeu
    except ValueError:
        return False
    base = b"v0:" + ts.encode() + b":" + body
    expected = "v0=" + hmac.new(secret, base, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, headers.get("X-Slack-Signature", ""))


def _forward(verb, alertname, actor):
    body = json.dumps({"alertname": alertname,
                       "actor": f"{actor}@slack",
                       "detail": "clic bouton Slack (war room)"}).encode()
    req = urllib.request.Request(
        f"{BRIDGE_URL}/incident/{verb}", data=body,
        headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=5)


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/slack/actions":
            self.send_response(404)
            self.end_headers()
            return
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if not _verify(self.headers, body):
            log("requête REFUSÉE (signature/horodatage invalide)")
            self.send_response(401)
            self.end_headers()
            return
        try:
            # Slack envoie du x-www-form-urlencoded : payload=<JSON>
            payload = json.loads(
                urllib.parse.parse_qs(body.decode())["payload"][0])
            action = (payload.get("actions") or [{}])[0]
            verb = action.get("action_id", "")
            alertname = action.get("value", "")
            user = payload.get("user", {})
            actor = user.get("username") or user.get("name") or "inconnu"
            if verb in ALLOWED_VERBS and alertname:
                _forward(verb, alertname, actor)
                log(f"{verb} sur {alertname} par {actor}")
            else:
                log(f"action ignorée (verb={verb!r})")
            # Slack exige une réponse < 3 s ; 200 vide = « bien reçu »
            # (la confirmation visible arrive par la war room elle-même).
            self.send_response(200)
        except Exception as e:
            log(f"payload error: {e}")
            self.send_response(400)
        self.end_headers()

    def do_GET(self):                # probes liveness/readiness
        self.send_response(200 if self.path == "/healthz" else 404)
        self.end_headers()

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    log(f"écoute sur :{PORT} — bridge={BRIDGE_URL} "
        f"(secret {'présent' if _secret() else 'ABSENT: tout sera refusé'})")
    ThreadingHTTPServer(("", PORT), Handler).serve_forever()


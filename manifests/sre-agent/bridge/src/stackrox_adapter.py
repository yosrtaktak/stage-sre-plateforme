#!/usr/bin/env python3
# =============================================================================
#  stackrox_adapter — traducteur StackRox (notifier Generic Webhook) ->
#  Alertmanager (POST /api/v2/alerts).
# -----------------------------------------------------------------------------
#  Pourquoi : StackRox sait notifier, mais son propre canal serait un DEUXIÈME
#  chemin vers l'équipe, à côté de celui de l'agent. On veut UN seul canal :
#  les violations entrent dans Alertmanager comme n'importe quelle alerte, et
#  suivent le même circuit (route -> holmes-bridge -> enquête -> décision).
#  Les notifications natives StackRox restent éteintes.
#
#  Règles d'architecture (mêmes que slack-gateway et goalert-formatter) :
#  stdlib uniquement, pas de LLM, pas de dépendance — un traducteur doit être
#  bête et incassable. Il tourne dans l'image ghcr.io/yosrtaktak/sre-bridge
#  (command override), donc il traverse trivy + SBOM + cosign et doit passer
#  l'admission StackRox comme les autres : la boucle se referme sur elle-même.
#
#  DÉCISIONS ENCAPSULÉES ICI (chacune se discute, aucune n'est un hasard) :
#
#  1. `source: stackrox` en label -> c'est LUI que la route Alertmanager
#     dédiée matche. Cette route est en tête et `continue: false` : les
#     violations vont à l'agent et NE réveillent PAS l'astreinte. Une image
#     non signée refusée à l'admission n'est pas un incident de production ;
#     si c'en devient un, c'est l'agent qui escalade, après enquête.
#
#  2. `endsAt` posé à +HOLD_HOURS sur les violations ACTIVE. StackRox notifie
#     au CHANGEMENT d'état, il ne réémet pas en boucle ; or Alertmanager
#     auto-résout ce qu'on ne lui répète pas (resolve_timeout = 5 min). Sans
#     cette borne, toute violation disparaîtrait de l'UI au bout de 5 minutes
#     comme si elle avait été corrigée. Sur RESOLVED, on pose endsAt = maintenant
#     -> Alertmanager clôture, le bridge reçoit le resolved (send_resolved:true).
#
#  3. Clé de dédup = l'ensemble des labels, donc `policy` + `deployment`
#     + `namespace` (cf. group_by de la route). Pour une dédup orientée CVE,
#     basculer `image` des annotations vers les labels : une ligne, commentée
#     plus bas — mais alors chaque nouveau tag rouvre une alerte.
#
#  4. 502 si le POST échoue -> StackRox retente la notification. On ne perd
#     pas une violation en silence (même contrat que goalert-formatter).
# =============================================================================
import json
import os
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ALERTMANAGER_URL = os.environ.get(
    "ALERTMANAGER_URL",
    "http://obs-alertmanager.monitoring.svc.cluster.local:9093/api/v2/alerts")
# Base de l'URL de la console, pour le lien cliquable en war room.
CENTRAL_URL = os.environ.get("CENTRAL_URL", "https://localhost:8443")
PORT = int(os.environ.get("PORT", "8030"))
# Durée pendant laquelle une violation ACTIVE reste "firing" sans être
# réémise (cf. décision 2). 24 h = un cycle de travail : au-delà, si personne
# n'a traité, la violation retombera et sera re-notifiée au prochain
# changement d'état côté StackRox.
HOLD_HOURS = int(os.environ.get("HOLD_HOURS", "24"))
# Capture du payload BRUT de StackRox, eteint par defaut. A n allumer que le
# temps d une capture : un payload porte des noms d images et de namespaces
# qu on ne veut pas laisser trainer dans les logs en permanence.
DEBUG_PAYLOAD = os.environ.get("DEBUG_PAYLOAD", "") == "1"

# StackRox -> Prometheus. `info` n'est routé nulle part aujourd'hui : les LOW
# entrent dans Alertmanager pour l'historique, sans déranger personne.
SEVERITY_MAP = {
    "CRITICAL_SEVERITY": "critical",
    "HIGH_SEVERITY": "critical",
    "MEDIUM_SEVERITY": "warning",
    "LOW_SEVERITY": "info",
}


def log(msg):
    print(f"[stackrox-adapter] {msg}", flush=True)


def _now():
    return datetime.now(timezone.utc)


def _rfc3339(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _s(value, default="-"):
    """Un label Alertmanager doit être une chaîne non vide."""
    if value is None:
        return default
    text = str(value).strip()
    return text or default


def build_alerts(payload):
    """StackRox (dict) -> liste d'alertes au format Alertmanager.

    Fonction PURE : aucun I/O. C'est elle que les tests couvrent — la logique
    de traduction est la seule partie qui peut se tromper en silence.
    """
    # Le notifier generic enveloppe dans {"alert": {...}} ; certains tests
    # manuels (curl) envoient l'objet nu. On accepte les deux.
    alert = payload.get("alert", payload) or {}
    policy = alert.get("policy") or {}
    deployment = alert.get("deployment") or {}
    violations = alert.get("violations") or []

    resolved = str(alert.get("state", "")).upper() == "RESOLVED"
    severity = SEVERITY_MAP.get(_s(policy.get("severity"), ""), "warning")

    # Première image du déploiement : suffit à identifier la charge dans 99 %
    # des cas, et évite un label multi-valué.
    image = "-"
    containers = deployment.get("containers") or []
    if containers:
        name = (containers[0].get("image") or {}).get("name") or {}
        image = _s(name.get("fullName"), "-")

    categories = policy.get("categories") or []
    # Le notifier generic ne place pas lifecycleStage sur l alerte (constate
    # le 18/08 : le label sortait a '-'). La policy, elle, porte la liste des
    # etages ou elle s applique : on s en sert comme repli.
    stages = policy.get("lifecycleStages") or []

    labels = {
        "alertname": "StackRoxPolicyViolation",
        "source": "stackrox",                      # <- matcher de la route
        "severity": severity,
        "policy": _s(policy.get("name")),
        "deployment": _s(deployment.get("name")),
        "namespace": _s(deployment.get("namespace")),
        "cluster": _s(deployment.get("clusterName")),
        "category": _s(categories[0] if categories else None),
        "lifecycle": _s(alert.get("lifecycleStage")
                        or (stages[0] if stages else None)),
        # Pour une dédup orientée CVE (une alerte par image plutôt que par
        # déploiement), décommenter la ligne suivante :
        # "image": image,
    }

    # Les violations portent le DÉTAIL concret ("signature non vérifiée par
    # l'intégration"), là où la policy ne porte que l'intention.
    messages = [_s(v.get("message"), "") for v in violations]
    messages = [m for m in messages if m and m != "-"]

    annotations = {
        "summary": f"{labels['policy']} — {labels['namespace']}/"
                   f"{labels['deployment']}",
        "description": " | ".join(messages) or _s(policy.get("description")),
        "rationale": _s(policy.get("rationale"), ""),
        "remediation": _s(policy.get("remediation"), ""),
        "image": image,
    }

    now = _now()
    starts = _s(alert.get("firstOccurred") or alert.get("time"), _rfc3339(now))
    ends = now if resolved else now + timedelta(hours=HOLD_HOURS)

    return [{
        "labels": labels,
        "annotations": annotations,
        "startsAt": starts,
        "endsAt": _rfc3339(ends),
        "generatorURL": f"{CENTRAL_URL}/main/violations/"
                        f"{_s(alert.get('id'), '')}",
    }]


def _forward(alerts):
    req = urllib.request.Request(
        ALERTMANAGER_URL, data=json.dumps(alerts).encode(),
        headers={"Content-Type": "application/json"})
    # Alertmanager répond 200 avec un corps vide. Timeout court : StackRox
    # attend la réponse du webhook.
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.status


class Handler(BaseHTTPRequestHandler):

    def log_message(self, *a):        # silence les logs d'accès par défaut
        pass

    def do_GET(self):
        self.send_response(200 if self.path == "/healthz" else 404)
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
        if DEBUG_PAYLOAD:
            log(f"payload brut : {json.dumps(payload)[:2000]}")
        try:
            alerts = build_alerts(payload)
            status = _forward(alerts)
            lab = alerts[0]["labels"]
            log(f"{lab['policy']} @ {lab['namespace']}/{lab['deployment']} "
                f"-> Alertmanager {status}")
            self.send_response(200)
        except Exception as e:
            # 502 -> StackRox retente : aucune violation perdue en silence.
            log(f"échec transfert : {e}")
            self.send_response(502)
        self.end_headers()


if __name__ == "__main__":
    log(f"écoute :{PORT}, cible {ALERTMANAGER_URL}")
    ThreadingHTTPServer(("", PORT), Handler).serve_forever()


# -*- coding: utf-8 -*-
"""Incident Adapter — la couche d'isolation de la checklist anti lock-in.

Rôle (point 7) : c'est le SEUL code de la plateforme qui sait où et comment
sont enregistrés les incidents. Il parle à incident-db-api (PostgREST devant
incident_db, NOTRE vérité neutre) en HTTP/stdlib — jamais à GoAlert, jamais
en SQL. Le bridge appelle des verbes métier standards (open/ack/close/event,
point 10) ; si l'outil d'astreinte change (OneUptime, Grafana IRM,
PagerDuty…), RIEN ne change ici ni dans le bridge : seuls Alertmanager
(receiver) et le Service `incident-tool` bougent.

Dégradable (point 9) : INCIDENT_API_URL vide ou API en panne -> no-op
journalisé, l'enquête HolmesGPT et le pipeline Slack continuent. Aucune
exception ne remonte jamais à l'appelant.

Cycle de vie enregistré (source des vues MTTA/MTTR de incident_metrics) :
  - firing   -> ligne incidents (status=open, opened_at=startsAt du
                Alertmanager) + événement `created` (idempotent par
                fingerprint : les renvois Alertmanager ne dupliquent rien)
  - ACK      -> acked_at posé UNE fois (premier ack = MTTA) + événement
  - resolved -> closed_at posé (MTTR), status=closed + événement
  - agent    -> événements `diagnosed` / `postmortem` / `pr_opened`
"""
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

# URL de l'API incident (PostgREST). Vide = adapter désactivé (no-op).
INCIDENT_API = os.environ.get("INCIDENT_API_URL", "").strip().rstrip("/")
TIMEOUT_S = int(os.environ.get("INCIDENT_API_TIMEOUT_S", "5"))

# Compteurs exposés dans le /metrics du bridge (méta-observabilité : si
# errors monte, la base d'incidents décroche du réel sans casser l'agent).
counters = {"writes": 0, "errors": 0}


def log(msg):
    print(f"[incident-adapter] {msg}", flush=True)


def enabled():
    return bool(INCIDENT_API)


def _req(method, path, body=None, prefer=None):
    """Un appel PostgREST. Retourne l'objet JSON décodé (ou None si corps
    vide). Lève urllib.error.* — c'est aux verbes publics d'attraper."""
    headers = {"Content-Type": "application/json"}
    if prefer:
        headers["Prefer"] = prefer
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        INCIDENT_API + path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
        raw = r.read()
    return json.loads(raw) if raw else None


def _q(v):
    # Valeur dans un filtre PostgREST (?col=eq.<v>) : URL-encodée, toujours.
    return urllib.parse.quote(str(v), safe="")


def _find(fp):
    """L'incident (id, status) portant ce fingerprint, ou None."""
    rows = _req("GET", f"/incidents?fingerprint=eq.{_q(fp)}"
                       "&select=id,status,acked_at,summary")
    return rows[0] if rows else None


def _event(incident_id, actor, action, detail=""):
    _req("POST", "/incident_events",
         body={"incident_id": incident_id, "actor": actor,
               "action": action, "detail": detail[:2000]})


def _safe(fn, what):
    """Exécute un verbe ; toute erreur devient un log + compteur, jamais une
    exception (l'adapter ne doit JAMAIS casser une enquête)."""
    try:
        fn()
        counters["writes"] += 1
    except Exception as e:
        counters["errors"] += 1
        log(f"{what} error (non bloquant): {e}")


# --------------------------------------------------------------------------
#  Verbes métier — le vocabulaire STANDARD du point 10, rien de propre à
#  un outil. C'est tout ce que le bridge connaît.
# --------------------------------------------------------------------------
def on_alert(alert):
    """Dispatch du webhook Alertmanager : firing -> open, resolved -> close.
    Appelé dans un thread daemon par le bridge (jamais bloquant)."""
    status = alert.get("status")
    if status == "firing":
        _safe(lambda: _open(alert), "open")
    elif status == "resolved":
        _safe(lambda: _close(alert), "close")


def _open(alert):
    labels = alert.get("labels", {})
    fp = (alert.get("fingerprint")
          or (labels.get("alertname", "") + alert.get("startsAt", "")))
    if _find(fp):
        return          # renvoi Alertmanager (repeat_interval) : déjà ouvert
    ann = alert.get("annotations", {})
    row = _req("POST", "/incidents", prefer="return=representation", body={
        "fingerprint": fp,
        "alertname": labels.get("alertname", "?"),
        "service": labels.get("service") or labels.get("slo"),
        "severity": labels.get("severity"),
        "status": "open",
        "opened_at": alert.get("startsAt")
        or datetime.now(timezone.utc).isoformat(),
        "summary": (ann.get("description") or ann.get("summary") or "")[:500],
    })
    _event(row[0]["id"], "alertmanager", "created",
           f"alerte {labels.get('alertname', '?')} "
           f"sévérité {labels.get('severity', '?')}")
    log(f"incident ouvert : {labels.get('alertname', '?')} ({fp})")


def _close(alert):
    fp = (alert.get("fingerprint")
          or (alert.get("labels", {}).get("alertname", "")
              + alert.get("startsAt", "")))
    found = _find(fp)
    if not found or found["status"] == "closed":
        return          # inconnu (ouvert avant l'adapter) ou déjà clos
    _req("PATCH", f"/incidents?fingerprint=eq.{_q(fp)}&status=neq.closed",
         body={"status": "closed",
               "closed_at": alert.get("endsAt")
               or datetime.now(timezone.utc).isoformat()})
    _event(found["id"], "alertmanager", "closed", "alerte resolved")
    log(f"incident clos : {fp}")


def ack(fingerprint=None, alertname=None, actor="humain", detail=""):
    """Premier ACK = MTTA. Cible par fingerprint, ou à défaut par alertname
    (le plus récent encore ouvert) — c'est la voie qu'empruntera n'importe
    quel outil d'astreinte (webhook, curl, workflow Slack) : l'outil n'a
    besoin de connaître QUE ce vocabulaire, pas notre schéma."""
    def _do():
        if fingerprint:
            found = _find(fingerprint)
        else:
            # `open` OU `acked` : un 2e humain qui acquitte en war room doit
            # rester visible dans la timeline (le MTTA, lui, est déjà figé).
            rows = _req("GET", "/incidents?alertname=eq." + _q(alertname)
                        + "&status=in.(open,acked)&order=opened_at.desc"
                          "&limit=1&select=id,status,acked_at,fingerprint")
            found = rows[0] if rows else None
        if not found:
            log(f"ack ignoré : aucun incident ouvert pour "
                f"{fingerprint or alertname}")
            return
        if not found.get("acked_at"):     # acked_at ne bouge qu'au PREMIER ack
            _req("PATCH", f"/incidents?id=eq.{found['id']}&acked_at=is.null",
                 body={"acked_at": datetime.now(timezone.utc).isoformat(),
                       "status": "acked"})
        _event(found["id"], actor, "acknowledged", detail)
        log(f"incident acké par {actor} : {fingerprint or alertname}")
    _safe(_do, "ack")


def record_analysis(fp, postmortem, verdict):
    """Trace du travail de l'agent dans la timeline (auditable) : action
    `diagnosed` ou `postmortem`, détail = ligne de verdict."""
    def _do():
        found = _find(fp)
        if not found:
            return      # incident jamais ouvert (adapter activé en cours de vie)
        _event(found["id"], "agent-sre",
               "postmortem" if postmortem else "diagnosed", verdict[:500])
        if not postmortem and not (found.get("summary") or "").strip():
            _req("PATCH", f"/incidents?id=eq.{found['id']}",
                 body={"summary": verdict[:500]})
    _safe(_do, "record_analysis")


def add_event(fp, actor, action, detail=""):
    """Événement libre sur la timeline (ex. pr_opened avec l'URL en preuve)."""
    def _do():
        found = _find(fp)
        if found:
            _event(found["id"], actor, action, detail)
    _safe(_do, f"event {action}")

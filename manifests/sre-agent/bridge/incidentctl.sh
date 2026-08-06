#!/usr/bin/env bash
# =============================================================================
#  incidentctl — ChatOps CLI de la plateforme incident (idée n°6, war room)
# -----------------------------------------------------------------------------
#  Parle UNIQUEMENT aux portes neutres (incident-db-api en lecture, bridge
#  /incident/* en écriture) — zéro dépendance à l'outil d'astreinte : le CLI
#  survivra à un remplacement de GoAlert. S'exécute depuis la VM (utilise
#  kubectl exec dans le pod bridge : aucun port à exposer).
#
#  Usage :
#    ./incidentctl.sh list                          # incidents ouverts
#    ./incidentctl.sh timeline [N]                  # N derniers événements (déf. 15)
#    ./incidentctl.sh metrics                       # MTTA / MTTR par service
#    ./incidentctl.sh ack     <alertname> <acteur> [note]
#    ./incidentctl.sh note    <alertname> <acteur> <texte...>
#    ./incidentctl.sh resolve <alertname> <acteur> [raison]   # clôture humaine
#
#  Exemple war room (multi-utilisateurs) :
#    ./incidentctl.sh ack  CheckoutFastBurn yosr "je prends"
#    ./incidentctl.sh note CheckoutFastBurn yosr "rollback du dernier sync en cours"
#    ./incidentctl.sh note CheckoutFastBurn sami "je surveille le burn rate"
#  -> chaque commande = un événement horodaté dans incident_db (timeline
#     auditable + dashboard) + un message dans #sre-war-room.
# =============================================================================
set -euo pipefail
NS=monitoring
API="http://incident-db-api.monitoring.svc.cluster.local:3000"
BRIDGE="http://localhost:8000"

_get() {  # $1 = chemin PostgREST ; affichage JSON lisible
  kubectl -n "$NS" exec deploy/holmes-bridge -- python -c "
import json, urllib.request
rows = json.load(urllib.request.urlopen('$API$1', timeout=10))
print(json.dumps(rows, indent=1, ensure_ascii=False))"
}

_post() {  # $1 = /incident/ack|note ; $2 = corps JSON
  kubectl -n "$NS" exec deploy/holmes-bridge -- python -c "
import urllib.request
r = urllib.request.Request('$BRIDGE$1', data='''$2'''.encode(),
                           headers={'Content-Type': 'application/json'})
print('HTTP', urllib.request.urlopen(r, timeout=10).status)"
}

cmd="${1:-help}"
case "$cmd" in
  list)
    _get "/incidents?status=neq.closed&order=opened_at.desc&select=id,alertname,service,severity,status,opened_at,acked_at" ;;
  timeline)
    _get "/incident_events?order=at.desc&limit=${2:-15}&select=at,incident_id,actor,action,detail" ;;
  metrics)
    _get "/incident_metrics" ;;
  ack|note|resolve)
    alert="${2:?alertname requis}" ; actor="${3:?acteur requis}"
    shift 3 || shift $# ; detail="${*:-}"
    if [ "$cmd" = note ] && [ -z "$detail" ]; then
      echo "une note sans texte n'a pas de sens" >&2 ; exit 1
    fi
    body=$(printf '{"alertname":"%s","actor":"%s","detail":"%s"}' \
                  "$alert" "$actor" "$detail")
    _post "/incident/$cmd" "$body" ;;
  *)
    grep '^#  ' "$0" | sed 's/^#  //' ;;
esac


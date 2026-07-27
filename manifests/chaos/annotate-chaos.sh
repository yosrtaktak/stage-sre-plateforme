#!/usr/bin/env bash
STATUS=$1
DESC=$2
kubectl port-forward svc/grafana -n monitoring 3000:80 > /dev/null 2>&1 &
PF_PID=$!
sleep 2
curl -s -X POST http://admin:admin123@localhost:3000/api/annotations \
  -H "Content-Type: application/json" \
  -d "{\"text\":\"${STATUS}: ${DESC}\",\"tags\":[\"chaos\"],\"time\":$(date +%s000)}"
echo
kill $PF_PID

# -*- coding: utf-8 -*-
"""Digest hebdomadaire : l'agent rédige le rapport d'astreinte de la semaine.

Lancé par un CronJob (lundi 07:00). Demande à HolmesGPT une synthèse des
incidents des 7 derniers jours (via ses outils : RAG des incidents, Prometheus,
Loki) et la poste sur le canal Slack de l'agent.
"""
import json
import os
import time
import urllib.error
import urllib.request

HOLMES_URL = os.environ.get(
    "HOLMES_URL", "http://holmesgpt-holmes.monitoring.svc.cluster.local:80")
HOLMES_MODEL = os.environ.get("HOLMES_MODEL", "gemini-flash")
SLACK_WEBHOOK_FILE = os.environ.get(
    "SLACK_WEBHOOK_FILE", "/etc/slack/slack-url-agent")

ASK = """Rédige le DIGEST SRE HEBDOMADAIRE de la plateforme Online Boutique,
en FRANÇAIS, pour le canal de l'équipe. Utilise tes outils :
- search_similar_incidents (requête « incidents de la semaine ») pour
  retrouver les diagnostics et post-mortems récents ;
- Prometheus : budgets d'erreur restants (slo:*:error_budget_remaining_ratio)
  et SLI 30 jours des 4 SLO ;
- si utile, Loki pour vérifier un point précis.
Structure (concis, max ~30 lignes) :
1. 📊 État des SLO : budget d'erreur restant par SLO (chiffres).
2. 🔥 Incidents de la semaine : pour chacun — quoi, cause racine, remède,
   durée. S'il n'y en a pas eu, dis-le.
3. 📈 Tendance : ce qui s'améliore / se dégrade.
4. ✅ Actions recommandées pour la semaine à venir (max 3, avec preuve).
Sois factuel : uniquement ce que tes outils retournent réellement."""


def main():
    body = json.dumps({"ask": ASK, "model": HOLMES_MODEL}).encode()
    resp = None
    # Correctif F7 : sans retry, le digest du lundi était perdu au premier
    # 429 du free tier (backoffLimit: 1 côté CronJob).
    for attempt in range(1, 4):
        req = urllib.request.Request(
            f"{HOLMES_URL}/api/chat", data=body,
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=280) as r:
                resp = json.loads(r.read())
            break
        except urllib.error.HTTPError as e:
            detail = ""
            try:
                detail = e.read().decode(errors="replace")[:300]
            except Exception:
                pass
            transient = e.code == 429 or (e.code == 500 and
                                          ("RateLimit" in detail
                                           or "429" in detail))
            if transient and attempt < 3:
                print(f"[digest] quota LLM saturé (tentative {attempt}/3), "
                      f"retry dans 75 s", flush=True)
                time.sleep(75)
                continue
            raise
    text = resp.get("analysis") or resp.get("response") or json.dumps(resp)

    with open(SLACK_WEBHOOK_FILE) as f:
        url = f.read().strip()
    msg = {"text": ("📅 *Digest SRE hebdomadaire — rédigé par l'agent*\n\n"
                    + text)[:3900]}
    req = urllib.request.Request(
        url, data=json.dumps(msg).encode(),
        headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=15)
    print("[digest] posté sur Slack", flush=True)


if __name__ == "__main__":
    main()


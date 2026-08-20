#!/usr/bin/env python3
# =============================================================================
#  rescan — l'agent apprend à CLORE un dossier (phase F, L1).
# -----------------------------------------------------------------------------
#  Depuis E1, chaque corps de PR promet à l'humain : « Vérification après merge
#  — rescan StackRox, le finding doit avoir disparu (rescan-confirm) ». Cette
#  vérification n'existait pas. `marquer_corrigee()` n'avait aucun appelant :
#  aucun problème ne passait jamais à l'état « corrigé », `tentatives` ne
#  redescendait jamais, et au troisième passage la porte `trop-de-tentatives`
#  se fermait définitivement sur un problème peut-être déjà résolu.
#
#  Ce module ferme la boucle. Il ne corrige rien et n'écrit pas dans le dépôt :
#  il REGARDE, et il enregistre ce qu'il a vu.
#
#  DÉCISIONS ENCAPSULÉES ICI :
#
#  1. ZÉRO N'EST PAS « JE N'AI PAS PU REGARDER ». `violations_actives()` rend
#     un entier, ou None. None n'est PAS zéro. C'est toute la leçon « un vert
#     qui n'a rien vérifié n'est pas une preuve » : une requête qui échoue ne
#     doit surtout pas se lire comme une violation disparue, sinon l'agent se
#     décernerait des succès en pannant. Sur None, on ne marque RIEN.
#
#  2. UN ÉCHEC DE MESURE NE CONSOMME PAS DE TENTATIVE. `MAX_TENTATIVES` borne
#     l'acharnement de l'agent, pas la fiabilité de Central. Compter une
#     tentative parce qu'une API n'a pas répondu ferait abandonner un problème
#     réel pour une raison qui n'a rien à voir avec lui.
#
#  3. LA CONFIRMATION EST LE CHRONOMÈTRE. L'écart entre `marquer_proposee` et
#     `marquer_corrigee` EST le MTTR d'un correctif de sécurité — la mesure
#     que la première boucle (§12.7) déclarait manquante. Elle est lue AVANT
#     d'écrire, parce que `marquer_corrigee` écrase l'horodatage.
#
#  4. LE RÉSEAU EST INJECTÉ. `get` est passé par l'appelant (les tests) ou pris
#     dans security_context (la production) : même client, même CA, même mode
#     dégradé qu'en phase D. Le module se teste sans Central.
#
#  5. NE LÈVE JAMAIS. Il est appelé depuis `_confirm_remedies`, au milieu de la
#     vérification post-sync. Une exception ici ferait perdre la confirmation
#     des remèdes de performance, qui n'ont rien demandé à personne.
#
#  ⚠️ À VÉRIFIER SUR TON CENTRAL avant de merger — la forme exacte de la
#  réponse de /v1/alerts n'est pas documentée dans les sources consultées :
#    curl -sk -H "Authorization: Bearer $ROX_API_TOKEN" \
#      "$CENTRAL/v1/alerts?query=Deployment:frontend" | head -40
#  Si la clé de liste n'est pas « alerts », ajuste CLES_LISTE ci-dessous.
#  Destination : manifests/sre-agent/bridge/src/rescan.py
# =============================================================================
import os
from datetime import datetime, timezone

import findings_ledger

# Clés sous lesquelles Central peut rendre la liste. On en accepte plusieurs
# plutôt que d'échouer sur un nom : une réponse valide mal lue serait comptée
# comme « aucune violation », c'est-à-dire un faux succès (décision n° 1).
CLES_LISTE = ("alerts", "violations", "results")
# États qui signifient « ce n'est plus actif ». Tout le reste compte.
ETATS_CLOS = ("RESOLVED", "ATTEMPTED", "SNOOZED")
RESCAN_TIMEOUT_S = int(os.environ.get("RESCAN_TIMEOUT_S", "10"))


def log(msg):
    print(f"[rescan] {msg}", flush=True)


def _ok(raison, detail, **extra):
    d = {"ok": True, "raison": raison, "detail": detail}
    d.update(extra)
    return d


def _ko(raison, detail, **extra):
    d = {"ok": False, "raison": raison, "detail": detail}
    d.update(extra)
    return d


# ------------------------------------------------------------------ requête
def _client():
    """Le client de la phase D, avec son jeton et son CA. Import tardif :
    security_context lit ROX_API_TOKEN à l'import, et rescan doit rester
    importable dans les tests sans jeton."""
    import security_context as S

    def get(query):
        return S._get(f"{S.CENTRAL_API}/v1/alerts?query={query}",
                      headers={"Authorization": f"Bearer {S.ROX_API_TOKEN}"},
                      insecure=True)
    return get


def _query(policy=None, deployment=None, namespace=None):
    """Le langage de recherche de Central : clauses jointes par « + »,
    exactement comme `fetch_runtime()` en phase D."""
    import urllib.parse
    clauses = []
    if policy:
        clauses.append(f"Policy:{policy}")
    if deployment:
        clauses.append(f"Deployment:{deployment}")
    if namespace:
        clauses.append(f"Namespace:{namespace}")
    return urllib.parse.quote("+".join(clauses), safe=":+")


def _liste(data):
    """La liste d'alertes, ou None si la réponse n'a pas la forme attendue.

    None plutôt que [] : une réponse qu'on ne sait pas lire n'est PAS une
    absence de violation (décision n° 1).
    """
    if not isinstance(data, dict):
        return None
    for cle in CLES_LISTE:
        if isinstance(data.get(cle), list):
            return data[cle]
    return None


def violations_actives(policy=None, deployment=None, namespace=None, get=None):
    """Nombre de violations ENCORE actives pour ce couple, ou None.

    None veut dire « je n'ai pas pu regarder » — jamais « il n'y en a plus ».
    """
    if not (policy or deployment):
        return None
    try:
        data = (get or _client())(_query(policy, deployment, namespace))
    except Exception as e:
        log(f"Central injoignable ({e}) : verdict INDETERMINE, on ne marque "
            f"rien")
        return None
    alertes = _liste(data)
    if alertes is None:
        log("reponse de Central non reconnue : verdict INDETERMINE. Verifier "
            f"les cles de liste attendues {CLES_LISTE}")
        return None
    return sum(1 for a in alertes
               if str((a or {}).get("state", "")).upper() not in ETATS_CLOS)


# --------------------------------------------------------------- chronomètre
def _mttr_minutes(vu):
    """Minutes écoulées depuis l'horodatage du registre, ou None.

    Lu AVANT d'écrire : `marquer_corrigee` écrase le champ `vu`.
    """
    if not vu:
        return None
    try:
        t = datetime.strptime(vu, "%Y-%m-%d %H:%M UTC").replace(
            tzinfo=timezone.utc)
    except Exception:
        return None
    return max(0, int((datetime.now(timezone.utc) - t).total_seconds() // 60))


# ------------------------------------------------------------- point d'entrée
def confirmer(fkey, policy=None, deployment=None, namespace=None, get=None):
    """Le rescan, et ce qu'on en fait. Ne lève jamais.

    - violation disparue  -> marquer_corrigee, et le MTTR est rendu
    - violation présente  -> marquer_tentative (la boucle reste bornée)
    - mesure impossible   -> RIEN. Ni succès, ni tentative (décision n° 2).
    """
    if not fkey:
        return _ko("fkey-absente", "rien à confirmer sans clé de problème")
    # Lu avant d'écrire : c'est le chronomètre (décision n° 3).
    avant = findings_ledger.finding(fkey) or {}
    mttr = _mttr_minutes(avant.get("vu"))

    n = violations_actives(policy, deployment, namespace, get=get)
    if n is None:
        return _ko("indetermine",
                   "Central n'a pas répondu ou sa réponse est illisible : "
                   "ni confirmation, ni tentative — un échec de mesure n'est "
                   "pas un échec du correctif")
    if n == 0:
        findings_ledger.marquer_corrigee(fkey)
        detail = "violation disparue au rescan"
        if mttr is not None:
            detail += f" — {mttr} min entre la proposition et la preuve"
        log(f"corrigé : {fkey} ({detail})")
        return _ok("corrigee", detail, mttr_minutes=mttr)
    findings_ledger.marquer_tentative(fkey)
    tentatives = (findings_ledger.finding(fkey) or {}).get("tentatives", 0)
    detail = (f"{n} violation(s) encore active(s) après le déploiement "
              f"(tentative {tentatives}/{findings_ledger.MAX_TENTATIVES})")
    log(f"non corrigé : {fkey} ({detail})")
    return _ko("toujours-presente", detail, restantes=n)


def confirmer_pr(info, notify=None, get=None):
    """Adaptateur pour `_confirm_remedies` du bridge : une entrée `_prs`.

    No-op silencieux pour une PR de performance (pas de `fkey`) — c'est la
    même fonction qui voit passer les deux familles de remèdes.
    """
    try:
        fkey = (info or {}).get("fkey")
        if not fkey:
            return None
        # La cible vient soit des labels rendus par maybe_open_pr, soit du
        # dictionnaire lui-même : le bridge a stocké l'un ou l'autre selon
        # les versions, et une confirmation perdue pour une clé mal placée
        # serait invisible.
        lab = info.get("labels") or {}

        def cible(nom):
            return lab.get(nom) or info.get(nom)

        r = confirmer(fkey, policy=cible("policy"),
                      deployment=cible("deployment"),
                      namespace=cible("namespace"), get=get)
        if notify:
            num = info.get("number", "?")
            if r["ok"]:
                notify(f"🏅 Correctif sécurité confirmé — PR #{num} mergée, "
                       f"la violation a disparu au rescan. {r['detail']}.")
            elif r["raison"] == "toujours-presente":
                notify(f"⚠️ PR #{num} mergée mais la violation persiste — "
                       f"{r['detail']}. Le correctif n'a pas tenu ses "
                       f"promesses.")
        return r
    except Exception as e:                      # décision n° 5
        log(f"confirmation impossible : {e}")
        return None

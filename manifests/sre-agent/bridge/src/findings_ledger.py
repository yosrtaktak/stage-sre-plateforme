#!/usr/bin/env python3
# =============================================================================
#  findings_ledger — la mémoire des propositions de l'agent (phase E2).
# -----------------------------------------------------------------------------
#  E1 a appris à l'agent à proposer. Sans mémoire, il proposerait la MÊME chose
#  à chaque cycle de scan — et surtout, il rouvrirait ce qu'un humain vient de
#  refuser. Trois jours de ce régime suffisent à ce que plus personne ne
#  regarde ses PRs. Le registre est donc moins un confort qu'un garde-fou :
#  c'est lui qui rend l'agent supportable.
#
#  C'est le pendant exact de la dédup des alertes (§6.2, décision n° 3) :
#  là-bas on évitait le doublon d'alerte, ici le doublon de proposition.
#
#  DEUX CLÉS, ET C'EST LA DÉCISION CENTRALE :
#
#    finding_key   ce qui ne va pas        CVE|policy + déploiement + namespace
#    proposal_key  ce qu'on a suggéré      finding_key + « old -> new »
#
#  Le refus humain est enregistré sur la PROPOSITION, pas sur le problème. Si
#  l'équipe refuse le bump vers 1.2.4 et que 1.2.5 sort avec un vrai correctif,
#  l'agent a le droit de reproposer : c'est une autre proposition. Mais après
#  DEUX refus sur le même problème, il abandonne — à ce stade, le refus ne
#  porte plus sur la version, il porte sur le fond, et insister serait du
#  harcèlement automatisé.
#
#  AUTRES DÉCISIONS :
#
#  1. LES PORTES GLOBALES D'ABORD. Incident ouvert, puis plafond de PRs, puis
#     seulement l'historique du finding. Une porte globale ferme tout : inutile
#     d'aller consulter le registre pour se le faire dire.
#
#  2. RIEN PENDANT UN INCIDENT OUVERT. Une PR de sécurité pendant qu'un service
#     brûle, c'est du bruit au pire moment — et un risque de merge précipité.
#
#  3. UN PLAFOND DE PRs OUVERTES. Au-delà, on ne protège plus : on noie la
#     revue. Une file de quarante PRs de sécurité vaut zéro PR.
#
#  4. LA BOUCLE EST BORNÉE. Après MAX_TENTATIVES rescans non concluants, on
#     arrête de reproposer et on escalade en issue. Une boucle
#     « corriger -> rescan -> pas corrigé -> corriger » sans borne est un
#     robot qui s'acharne.
#
#  5. LE REGISTRE VIT SUR LE PVC. `/state` survit aux redémarrages du pod — un
#     registre qui s'oublie au premier restart ne protège de rien.
# =============================================================================
import hashlib
import json
import os
import threading
import time

LEDGER_FILE = os.environ.get("LEDGER_FILE", "/state/findings-ledger.json")
MAX_PRS_OUVERTES = int(os.environ.get("MAX_PRS_OUVERTES", "5"))
MAX_REFUS = int(os.environ.get("MAX_REFUS", "2"))
MAX_TENTATIVES = int(os.environ.get("MAX_TENTATIVES", "3"))

ETATS = ("proposee", "issue", "refusee", "corrigee", "abandonnee")

_lock = threading.Lock()
_state = {"findings": {}, "propositions": {}}


def log(msg):
    print(f"[ledger] {msg}", flush=True)


def _now():
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())


# ------------------------------------------------------------------ clés
def finding_key(cve=None, policy=None, deployment=None, namespace=None):
    """CE QUI NE VA PAS. Stable dans le temps : c'est lui qui porte le
    compteur de refus et de tentatives."""
    brut = "|".join(str(x or "-") for x in (cve, policy, deployment, namespace))
    return hashlib.sha1(brut.encode()).hexdigest()[:12]


def proposal_key(fkey, old, new):
    """CE QU'ON A SUGGÉRÉ. Un correctif différent pour le même problème est
    une nouvelle proposition — et mérite d'être soumis."""
    brut = f"{fkey}|{old or '-'}|{new or '-'}"
    return hashlib.sha1(brut.encode()).hexdigest()[:12]


# ------------------------------------------------------------- persistance
def charger(path=None):
    global _state
    chemin = path or LEDGER_FILE
    try:
        with open(chemin) as f:
            _state = json.load(f)
        _state.setdefault("findings", {})
        _state.setdefault("propositions", {})
    except Exception:
        _state = {"findings": {}, "propositions": {}}
    return _state


def _sauver(path=None):
    chemin = path or LEDGER_FILE
    try:
        os.makedirs(os.path.dirname(chemin), exist_ok=True)
        tmp = chemin + ".tmp"
        with open(tmp, "w") as f:
            json.dump(_state, f)
        os.replace(tmp, chemin)
    except Exception as e:                    # un registre qui n'écrit pas ne
        log(f"registre non écrit : {e}")      # doit pas casser la remédiation


def reinitialiser():
    """Uniquement pour les tests."""
    global _state
    _state = {"findings": {}, "propositions": {}}


def _finding(fkey):
    return _state["findings"].setdefault(
        fkey, {"refus": 0, "tentatives": 0, "etat": "", "vu": _now()})


# ------------------------------------------------------------------ lecture
def proposition(pkey):
    return _state["propositions"].get(pkey)


def finding(fkey):
    return _state["findings"].get(fkey)


def prs_ouvertes():
    """Nombre de propositions encore à l'état « proposée »."""
    return sum(1 for p in _state["propositions"].values()
               if p.get("etat") == "proposee")


def _ko(raison, detail):
    return {"ok": False, "raison": raison, "detail": detail}


def _ok(detail=""):
    return {"ok": True, "raison": "", "detail": detail}


# ------------------------------------------------------------------ la porte
def autorise(fkey, pkey, statut_pr=None, incident_ouvert=False):
    """L'agent a-t-il le droit de proposer ceci, maintenant ?

    `statut_pr(numero) -> {"state": "open"|"closed", "merged": bool}` est
    injecté par l'appelant : le registre ne fait AUCUN appel réseau, ce qui le
    rend testable sans GitHub. Même principe que `evaluate()` en phase D.
    """
    # --- portes globales (décision n° 1) ---------------------------------
    if incident_ouvert:
        return _ko("incident-ouvert",
                   "un incident est en cours : aucune PR de sécurité ne part "
                   "pendant qu'un service brûle")
    ouvertes = prs_ouvertes()
    if ouvertes >= MAX_PRS_OUVERTES:
        return _ko("plafond-prs",
                   f"{ouvertes} PRs de l'agent déjà ouvertes (plafond "
                   f"{MAX_PRS_OUVERTES}) : au-delà, on noie la revue au lieu "
                   f"de la servir")

    # --- historique du problème ------------------------------------------
    f = _state["findings"].get(fkey)
    if f:
        if f.get("etat") == "abandonnee" or f.get("refus", 0) >= MAX_REFUS:
            return _ko("abandonnee",
                       f"{f.get('refus', 0)} refus humains sur ce problème : "
                       f"le désaccord ne porte plus sur la version proposée, "
                       f"insister serait du harcèlement automatisé")
        if f.get("tentatives", 0) >= MAX_TENTATIVES:
            return _ko("trop-de-tentatives",
                       f"{f['tentatives']} tentatives sans correction "
                       f"confirmée : escalade en issue, pas une de plus")

    # --- historique de CETTE proposition ---------------------------------
    p = _state["propositions"].get(pkey)
    if p:
        if p.get("etat") == "refusee":
            return _ko("refusee",
                       f"proposition déjà refusée par un humain le "
                       f"{p.get('vu', '?')}")
        if p.get("etat") == "corrigee":
            return _ko("deja-corrigee",
                       "cette proposition a déjà été appliquée et confirmée")
        if p.get("etat") == "proposee":
            numero = p.get("pr")
            if not numero or not statut_pr:
                return _ko("pr-deja-ouverte",
                           f"PR déjà ouverte pour cette proposition "
                           f"({numero or 'numéro inconnu'})")
            try:
                st = statut_pr(numero)
            except Exception as e:
                # Sans réponse de GitHub, on NE reproposé PAS : le doute
                # profite au silence, jamais au doublon.
                return _ko("statut-pr-inconnu",
                           f"état de la PR #{numero} indisponible ({e}) : "
                           f"on ne repropose pas dans le doute")
            if st.get("state") == "open":
                return _ko("pr-deja-ouverte",
                           f"PR #{numero} toujours ouverte")
            if st.get("merged"):
                # Mergée puis le problème revient = régression. On repropose,
                # mais ça compte comme une tentative.
                marquer_tentative(fkey)
                return _ok(f"PR #{numero} mergée puis problème réapparu : "
                           f"régression, nouvelle proposition")
            # Fermée sans merge = refus humain. On l'enregistre MAINTENANT :
            # personne ne viendra le faire à la main.
            marquer_refusee(pkey, fkey)
            return _ko("refusee",
                       f"PR #{numero} fermée sans merge : refus humain, "
                       f"enregistré")
    return _ok()


# ------------------------------------------------------------------ écriture
def marquer_proposee(fkey, pkey, pr=None, url="", resume=""):
    with _lock:
        f = _finding(fkey)
        f["tentatives"] = f.get("tentatives", 0) + 1
        f["etat"] = "proposee"
        f["vu"] = _now()
        _state["propositions"][pkey] = {
            "finding": fkey, "etat": "proposee", "pr": pr, "url": url,
            "resume": resume, "vu": _now()}
        _sauver()
    log(f"proposée : {pkey} (finding {fkey}, PR {pr})")


def marquer_refusee(pkey, fkey=None):
    with _lock:
        p = _state["propositions"].setdefault(
            pkey, {"finding": fkey, "etat": "", "vu": _now()})
        if p.get("etat") != "refusee":
            p["etat"] = "refusee"
            p["vu"] = _now()
            cle = fkey or p.get("finding")
            if cle:
                f = _finding(cle)
                f["refus"] = f.get("refus", 0) + 1
                if f["refus"] >= MAX_REFUS:
                    f["etat"] = "abandonnee"
                    log(f"abandonné après {f['refus']} refus : {cle}")
        _sauver()


def marquer_corrigee(fkey, pkey=None):
    """Appelé après un rescan-confirm concluant."""
    with _lock:
        f = _finding(fkey)
        f["etat"] = "corrigee"
        f["tentatives"] = 0
        f["vu"] = _now()
        if pkey and pkey in _state["propositions"]:
            _state["propositions"][pkey]["etat"] = "corrigee"
            _state["propositions"][pkey]["vu"] = _now()
        _sauver()
    log(f"corrigé (rescan confirmé) : {fkey}")


def marquer_tentative(fkey):
    with _lock:
        f = _finding(fkey)
        f["tentatives"] = f.get("tentatives", 0) + 1
        f["vu"] = _now()
        _sauver()


def marquer_issue(fkey, url=""):
    with _lock:
        f = _finding(fkey)
        f["etat"] = "issue"
        f["url"] = url
        f["vu"] = _now()
        _sauver()


def resume():
    """Une ligne pour les logs et le rapport."""
    f = _state["findings"]
    p = _state["propositions"]
    par_etat = {}
    for v in p.values():
        par_etat[v.get("etat", "?")] = par_etat.get(v.get("etat", "?"), 0) + 1
    detail = ", ".join(f"{n} {e}" for e, n in sorted(par_etat.items()))
    return (f"{len(f)} problèmes suivis, {len(p)} propositions"
            + (f" ({detail})" if detail else "")
            + f" — {prs_ouvertes()}/{MAX_PRS_OUVERTES} PRs ouvertes")

# =============================================================================
#  Tests du rescan-confirm (phase F, L1).
# -----------------------------------------------------------------------------
#  Le danger de ce module n'est pas de casser un manifeste : c'est de se
#  DÉCERNER UN SUCCÈS QU'IL N'A PAS MESURÉ. Une requête qui échoue, une
#  réponse qu'on ne sait pas lire, une clé de liste renommée — chacun de ces
#  cas, mal traité, ferait passer un problème à « corrigé » alors que
#  personne n'a rien vérifié. C'est exactement la leçon « un vert qui n'a rien
#  vérifié n'est pas une preuve », appliquée au code qui décerne les verts.
#
#  La moitié des tests portent donc sur le cas None, et vérifient à chaque
#  fois la même chose : le registre n'a PAS bougé.
# =============================================================================
import sys
from pathlib import Path

_ICI = Path(__file__).resolve().parent
for _c in (_ICI.parent / "src", _ICI):     # arborescence VM, puis copie locale
    if (_c / "rescan.py").exists():
        sys.path.insert(0, str(_c))
        break

import findings_ledger as L                # noqa: E402
import rescan as R                         # noqa: E402


FKEY = "probleme-un"


def poser(fkey=FKEY, vu=None):
    """Un problème déjà proposé, tel que le registre le connaît."""
    L.reinitialiser()
    L.marquer_proposee(fkey, "prop-un", pr=12, url="u", resume="r")
    if vu:
        L._state["findings"][fkey]["vu"] = vu
    return L.finding(fkey)


def rep(*etats):
    """Une réponse de Central portant ces états de violation."""
    return lambda q: {"alerts": [{"state": e} for e in etats]}


def casse(exc=RuntimeError("Central 503")):
    def get(q):
        raise exc
    return get


# ------------------------------------------------------- la violation a disparu
def test_aucune_violation_marque_corrigee():
    poser()
    r = R.confirmer(FKEY, deployment="frontend", get=rep())
    assert r["ok"] and r["raison"] == "corrigee"
    assert L.finding(FKEY)["etat"] == "corrigee"


def test_les_violations_resolues_ne_comptent_pas():
    poser()
    r = R.confirmer(FKEY, deployment="frontend",
                    get=rep("RESOLVED", "SNOOZED", "ATTEMPTED"))
    assert r["ok"], r
    assert L.finding(FKEY)["etat"] == "corrigee"


def test_la_correction_remet_les_tentatives_a_zero():
    poser()
    assert L.finding(FKEY)["tentatives"] == 1
    R.confirmer(FKEY, deployment="frontend", get=rep())
    assert L.finding(FKEY)["tentatives"] == 0


# ------------------------------------------------------ la violation persiste
def test_une_violation_active_compte_une_tentative():
    poser()
    avant = L.finding(FKEY)["tentatives"]
    r = R.confirmer(FKEY, deployment="frontend", get=rep("ACTIVE"))
    assert not r["ok"] and r["raison"] == "toujours-presente"
    assert r["restantes"] == 1
    assert L.finding(FKEY)["tentatives"] == avant + 1


def test_un_etat_inconnu_est_compte_comme_actif():
    """Dans le doute sur l'état, on ne déclare pas la victoire."""
    poser()
    r = R.confirmer(FKEY, deployment="frontend", get=rep("ETAT_INCONNU"))
    assert not r["ok"] and r["restantes"] == 1


# ============================================================================
#  Le coeur : « je n'ai pas pu regarder » n'est PAS « il n'y a plus rien »
# ============================================================================
def test_central_injoignable_ne_marque_rien():
    poser()
    etat_avant = dict(L.finding(FKEY))
    r = R.confirmer(FKEY, deployment="frontend", get=casse())
    assert not r["ok"] and r["raison"] == "indetermine"
    assert L.finding(FKEY) == etat_avant      # le registre n'a PAS bougé


def test_une_reponse_illisible_ne_marque_rien():
    poser()
    etat_avant = dict(L.finding(FKEY))
    r = R.confirmer(FKEY, deployment="frontend", get=lambda q: {"oups": 1})
    assert r["raison"] == "indetermine"
    assert L.finding(FKEY) == etat_avant


def test_une_reponse_non_dict_ne_marque_rien():
    poser()
    etat_avant = dict(L.finding(FKEY))
    R.confirmer(FKEY, deployment="frontend", get=lambda q: "erreur html")
    assert L.finding(FKEY) == etat_avant


def test_un_echec_de_mesure_ne_consomme_pas_de_tentative():
    """MAX_TENTATIVES borne l'acharnement de l'agent, pas la fiabilite de
    Central. Sinon un probleme reel serait abandonne pour une panne d'API."""
    poser()
    for _ in range(L.MAX_TENTATIVES + 3):
        R.confirmer(FKEY, deployment="frontend", get=casse())
    assert L.finding(FKEY)["tentatives"] == 1     # celle de marquer_proposee


def test_violations_actives_rend_none_et_pas_zero():
    assert R.violations_actives(deployment="f", get=casse()) is None
    assert R.violations_actives(deployment="f", get=rep()) == 0


def test_sans_cible_on_ne_requete_meme_pas():
    appels = []
    R.violations_actives(get=lambda q: appels.append(q) or {"alerts": []})
    assert appels == []


# ------------------------------------------------------------- le chronomètre
def test_le_mttr_est_mesure():
    poser(vu="2026-08-20 09:00 UTC")
    r = R.confirmer(FKEY, deployment="frontend", get=rep())
    assert isinstance(r["mttr_minutes"], int) and r["mttr_minutes"] >= 0


def test_un_horodatage_illisible_ne_casse_pas_la_confirmation():
    poser(vu="hier vers midi")
    r = R.confirmer(FKEY, deployment="frontend", get=rep())
    assert r["ok"] and r["mttr_minutes"] is None


# ------------------------------------------------------------ la requête
def test_la_requete_joint_les_clauses():
    vus = []
    R.violations_actives(policy="Fixable", deployment="frontend",
                         namespace="online-boutique",
                         get=lambda q: vus.append(q) or {"alerts": []})
    q, = vus
    assert "Policy:Fixable" in q and "Deployment:frontend" in q
    assert "Namespace:online-boutique" in q


# --------------------------------------------------- l'adaptateur du bridge
def test_une_pr_de_performance_est_ignoree():
    """Pas de fkey = remede de perf : le module passe son chemin."""
    L.reinitialiser()
    assert R.confirmer_pr({"number": 7}) is None


def test_l_adaptateur_notifie_la_confirmation():
    poser()
    messages = []
    R.confirmer_pr({"fkey": FKEY, "number": 7, "deployment": "frontend"},
                   notify=messages.append, get=rep())
    assert len(messages) == 1 and "confirmé" in messages[0]


def test_l_adaptateur_notifie_la_persistance():
    poser()
    messages = []
    R.confirmer_pr({"fkey": FKEY, "number": 7, "deployment": "frontend"},
                   notify=messages.append, get=rep("ACTIVE"))
    assert len(messages) == 1 and "persiste" in messages[0]


def test_l_adaptateur_ne_notifie_pas_un_indetermine():
    """Un silence de Central ne merite pas un message : rien ne s'est passe."""
    poser()
    messages = []
    R.confirmer_pr({"fkey": FKEY, "number": 7, "deployment": "frontend"},
                   notify=messages.append, get=casse())
    assert messages == []


def test_l_adaptateur_ne_leve_jamais():
    """Appele au milieu de la verification post-sync : une exception ici
    ferait perdre la confirmation des remedes de performance."""
    assert R.confirmer_pr({"fkey": FKEY}, get=casse(ValueError("x"))) is not None
    assert R.confirmer_pr(None) is None


def test_l_adaptateur_lit_la_cible_dans_les_labels():
    """maybe_open_pr rend les labels ; le bridge les stocke tels quels."""
    poser()
    vus = []
    R.confirmer_pr({"fkey": FKEY, "number": 7,
                    "labels": {"deployment": "redis-cart",
                               "namespace": "online-boutique"}},
                   get=lambda q: vus.append(q) or {"alerts": []})
    q, = vus
    assert "Deployment:redis-cart" in q and "Namespace:online-boutique" in q

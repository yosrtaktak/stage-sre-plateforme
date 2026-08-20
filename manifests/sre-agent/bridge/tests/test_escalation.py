# =============================================================================
#  Tests de l'escalade en issue (phase F).
# -----------------------------------------------------------------------------
#  Le module n'écrit rien dans un manifeste : le risque n'est pas le dégât, il
#  est le BRUIT. Un module d'escalade qui se duplique se fait ignorer en trois
#  jours, et onze violations correctement analysées redeviennent invisibles.
#  Les tests portent donc d'abord sur la dédup, et sur les deux pièges qui la
#  cassent silencieusement : la reformulation du titre, et les pull requests
#  que l'API GitHub range parmi les issues.
#
#  Aucun test ne touche au réseau : `gh` est injecté (décision n° 8).
# =============================================================================
import sys
from pathlib import Path

_ICI = Path(__file__).resolve().parent
for _c in (_ICI.parent / "src", _ICI):     # arborescence VM, puis copie locale
    if (_c / "escalation.py").exists():
        sys.path.insert(0, str(_c))
        break

import escalation as E                      # noqa: E402


FKEY = "finding-un"
AUTRE = "finding-deux"


class FauxGH:
    """Client GitHub factice : enregistre les appels, ne sort jamais du test.

    C'est le pendant de `statut_pr` en E2 — la seule façon de tester une
    décision qui dépend de l'état distant sans dépendre du distant.
    """

    def __init__(self, issues=None, echoue_get=False, echoue_post=False):
        self.issues = list(issues or [])
        self.appels = []
        self.echoue_get = echoue_get
        self.echoue_post = echoue_post
        self._n = 100

    def __call__(self, method, path, body=None):
        self.appels.append((method, path, body))
        if method == "GET":
            if self.echoue_get:
                raise RuntimeError("GitHub 502")
            return self.issues
        if method == "POST":
            if self.echoue_post:
                raise RuntimeError("GitHub 422 validation failed")
            self._n += 1
            return {"number": self._n,
                    "html_url": f"https://github.com/o/r/issues/{self._n}"}
        raise AssertionError(f"méthode inattendue : {method}")

    def posts(self):
        return [a for a in self.appels if a[0] == "POST"]


def issue(fkey=None, state="open", number=7, pr=False, corps_sup=""):
    """Fabrique une issue telle que l'API la rend."""
    d = {"number": number, "state": state,
         "html_url": f"https://github.com/o/r/issues/{number}",
         "body": (E.marqueur(fkey) if fkey else "") + corps_sup}
    if pr:
        d["pull_request"] = {"url": "…"}
    return d


def ouvrir(gh, **kw):
    base = dict(fkey=FKEY, sujet="runAsNonRoot à arbitrer",
                resume="L'image tourne en root.", repo="o/r", gh=gh)
    base.update(kw)
    return E.ouvrir(**base)


# --------------------------------------------------------------- le marqueur
def test_le_marqueur_est_dans_le_corps():
    c = E.corps(FKEY, "résumé")
    assert E.marqueur(FKEY) in c


def test_le_marqueur_est_stable_pour_une_meme_cle():
    assert E.marqueur(FKEY) == E.marqueur(FKEY)
    assert E.marqueur(FKEY) != E.marqueur(AUTRE)


def test_le_marqueur_est_un_commentaire_html():
    # Il ne doit pas polluer la lecture humaine de l'issue.
    m = E.marqueur(FKEY)
    assert m.startswith("<!--") and m.endswith("-->")


# ------------------------------------------------------------- la création
def test_creation_poste_le_label_de_l_agent():
    gh = FauxGH()
    r = ouvrir(gh)
    assert r["ok"] and r["raison"] == "creee"
    (_, chemin, charge), = gh.posts()
    assert chemin == "/repos/o/r/issues"
    assert E.LABEL in charge["labels"]
    assert E.marqueur(FKEY) in charge["body"]


def test_les_labels_supplementaires_sont_conserves():
    gh = FauxGH()
    ouvrir(gh, labels=("critical", "securite", ""))
    (_, _, charge), = gh.posts()
    assert set(charge["labels"]) == {E.LABEL, "critical", "securite"}


def test_le_titre_porte_la_cible():
    t = E.titre("capabilities à arbitrer", deployment="frontend",
                namespace="online-boutique")
    assert "frontend" in t and "online-boutique" in t
    assert t.startswith("[sre-agent]")


def test_le_corps_reprend_les_raisons_de_la_regle():
    # On ne reformule pas : la phrase vient de la règle qui a refusé.
    raisons = [("readOnlyRootFilesystem",
                "aucune lecture statique ne dit où le programme écrit")]
    c = E.corps(FKEY, "résumé", raisons)
    assert "readOnlyRootFilesystem" in c
    assert "aucune lecture statique" in c


def test_le_contexte_mesure_apparait():
    c = E.corps(FKEY, "résumé", contexte=[("image", "redis:alpine"),
                                          ("utilisateur", "root")])
    assert "redis:alpine" in c and "root" in c


# ------------------------------------------------------------------ la dédup
def test_une_issue_ouverte_bloque_la_creation():
    gh = FauxGH([issue(FKEY, "open", 42)])
    r = ouvrir(gh)
    assert not r["ok"] and r["raison"] == "deja-ouverte"
    assert r["number"] == 42
    assert gh.posts() == []          # aucune écriture


def test_reformuler_le_titre_ne_rouvre_pas():
    """Décision n° 1 : la clé est le PROBLÈME, pas la formulation."""
    gh = FauxGH([issue(FKEY, "open", 42)])
    r = ouvrir(gh, sujet="Tout autre libellé, écrit par un autre modèle")
    assert not r["ok"] and r["raison"] == "deja-ouverte"
    assert gh.posts() == []


def test_une_issue_fermee_n_est_jamais_rouverte():
    """Décision n° 3 : fermer, c'est répondre."""
    gh = FauxGH([issue(FKEY, "closed", 42)])
    r = ouvrir(gh)
    assert not r["ok"] and r["raison"] == "fermee-par-humain"
    assert gh.posts() == []


def test_une_autre_cle_cree_bien_une_issue():
    gh = FauxGH([issue(AUTRE, "open", 42)])
    r = ouvrir(gh)
    assert r["ok"] and r["raison"] == "creee"
    assert len(gh.posts()) == 1


# ----------------------------------------- le piège : les PRs sont des issues
def test_une_pr_portant_le_marqueur_n_est_pas_prise_pour_l_issue():
    """Décision n° 6 : /repos/{repo}/issues rend AUSSI les pull requests.

    Sans le filtre, une PR de l'agent citant le marqueur ferait croire que le
    problème est déjà documenté — et l'issue ne serait jamais ouverte.
    """
    gh = FauxGH([issue(FKEY, "open", 42, pr=True)])
    r = ouvrir(gh)
    assert r["ok"] and r["raison"] == "creee"


def test_les_prs_ne_comptent_pas_dans_le_plafond():
    prs = [issue(f"pr{i}", "open", i, pr=True)
           for i in range(E.MAX_ISSUES_OUVERTES + 5)]
    gh = FauxGH(prs)
    r = ouvrir(gh)
    assert r["ok"], r


# ------------------------------------------------------------------ plafond
def test_le_plafond_ferme_la_porte():
    pleines = [issue(f"f{i}", "open", i)
               for i in range(E.MAX_ISSUES_OUVERTES)]
    gh = FauxGH(pleines)
    r = ouvrir(gh)
    assert not r["ok"] and r["raison"] == "plafond-issues"
    assert gh.posts() == []


def test_les_issues_fermees_ne_remplissent_pas_le_plafond():
    fermees = [issue(f"f{i}", "closed", i)
               for i in range(E.MAX_ISSUES_OUVERTES + 3)]
    gh = FauxGH(fermees)
    r = ouvrir(gh)
    assert r["ok"], r


# --------------------------------------------------------------- le doute
def test_liste_indisponible_ne_cree_rien():
    """Décision n° 4 : sans la liste, créer serait le doublon assuré."""
    gh = FauxGH(echoue_get=True)
    r = ouvrir(gh)
    assert not r["ok"] and r["raison"] == "liste-indisponible"
    assert gh.posts() == []


def test_une_creation_qui_echoue_ne_leve_pas():
    # Une escalade qui plante empêcherait la remédiation qui l'entoure
    # de se terminer.
    gh = FauxGH(echoue_post=True)
    r = ouvrir(gh)
    assert not r["ok"] and r["raison"] == "creation-echouee"


def test_sans_client_le_module_se_desactive():
    r = E.ouvrir(FKEY, "sujet", "résumé", repo="o/r", gh=None)
    assert not r["ok"] and r["raison"] == "desactive"


def test_sans_cle_de_probleme_on_refuse():
    gh = FauxGH()
    r = ouvrir(gh, fkey="")
    assert not r["ok"] and r["raison"] == "fkey-absente"
    assert gh.appels == []           # même pas de lecture


# ------------------------------------------------------- liste pré-collectée
def test_la_liste_peut_etre_injectee_sans_aucun_get():
    """L'appelant qui a déjà la liste ne doit pas la redemander."""
    gh = FauxGH()
    r = ouvrir(gh, issues=[issue(FKEY, "open", 42)])
    assert not r["ok"] and r["raison"] == "deja-ouverte"
    assert gh.appels == []

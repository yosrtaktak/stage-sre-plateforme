# =============================================================================
#  Tests du registre des findings (phase E2).
# -----------------------------------------------------------------------------
#  Chaque test répond à : « si cette règle saute, que subit l'équipe ? ». Le
#  registre ne protège pas le cluster — il protège la REVUE HUMAINE. Un agent
#  sans mémoire est un agent qu'on finit par ignorer, et un agent ignoré ne
#  sert à rien, si correct soit-il.
# =============================================================================
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import findings_ledger as L          # noqa: E402


def frais(tmp_path):
    """Un registre vide, sur un fichier jetable."""
    L.LEDGER_FILE = str(tmp_path / "ledger.json")
    L.reinitialiser()
    return L.finding_key(cve="CVE-2026-1", deployment="frontend",
                         namespace="online-boutique")


# ------------------------------------------------------------------- les clés
def test_meme_probleme_meme_cle():
    a = L.finding_key(cve="CVE-1", deployment="d", namespace="n")
    b = L.finding_key(cve="CVE-1", deployment="d", namespace="n")
    assert a == b


def test_probleme_different_cle_differente():
    a = L.finding_key(cve="CVE-1", deployment="d", namespace="n")
    b = L.finding_key(cve="CVE-1", deployment="d", namespace="autre")
    assert a != b


def test_proposition_distincte_du_probleme():
    """La décision centrale : refuser 1.2.4 ne doit pas interdire 1.2.5."""
    f = L.finding_key(cve="CVE-1", deployment="d", namespace="n")
    assert L.proposal_key(f, "x:1.2.3", "x:1.2.4") != \
           L.proposal_key(f, "x:1.2.3", "x:1.2.5")


# --------------------------------------------------------- le cas nominal
def test_premiere_proposition_autorisee(tmp_path):
    f = frais(tmp_path)
    p = L.proposal_key(f, "x:1", "x:2")
    assert L.autorise(f, p)["ok"] is True


def test_deuxieme_fois_bloquee_si_la_pr_est_ouverte(tmp_path):
    """Sans ça, chaque cycle de scan rouvre la même PR."""
    f = frais(tmp_path)
    p = L.proposal_key(f, "x:1", "x:2")
    L.marquer_proposee(f, p, pr=42, url="http://pr/42")
    v = L.autorise(f, p, statut_pr=lambda n: {"state": "open", "merged": False})
    assert v["ok"] is False and v["raison"] == "pr-deja-ouverte"


# ----------------------------------------------- le refus humain, LE sujet
def test_pr_fermee_sans_merge_devient_un_refus(tmp_path):
    """Personne ne viendra enregistrer le refus à la main : le registre le
    déduit de l'état de la PR, au moment où il consulte."""
    f = frais(tmp_path)
    p = L.proposal_key(f, "x:1", "x:2")
    L.marquer_proposee(f, p, pr=42)
    v = L.autorise(f, p, statut_pr=lambda n: {"state": "closed",
                                              "merged": False})
    assert v["ok"] is False and v["raison"] == "refusee"
    assert L.proposition(p)["etat"] == "refusee"
    assert L.finding(f)["refus"] == 1


def test_une_proposition_refusee_ne_revient_jamais(tmp_path):
    f = frais(tmp_path)
    p = L.proposal_key(f, "x:1", "x:2")
    L.marquer_refusee(p, f)
    assert L.autorise(f, p)["raison"] == "refusee"


def test_un_autre_correctif_reste_proposable_apres_un_refus(tmp_path):
    """Refuser le bump vers 1.2.4 n'interdit pas 1.2.5 : c'est une autre
    proposition, et le correctif peut être réel cette fois."""
    f = frais(tmp_path)
    L.marquer_refusee(L.proposal_key(f, "x:1", "x:2"), f)
    assert L.autorise(f, L.proposal_key(f, "x:1", "x:3"))["ok"] is True


def test_deux_refus_et_l_agent_abandonne(tmp_path):
    """Au deuxième refus, le désaccord ne porte plus sur la version mais sur
    le fond. Insister serait du harcèlement automatisé."""
    f = frais(tmp_path)
    L.marquer_refusee(L.proposal_key(f, "x:1", "x:2"), f)
    L.marquer_refusee(L.proposal_key(f, "x:1", "x:3"), f)
    v = L.autorise(f, L.proposal_key(f, "x:1", "x:4"))
    assert v["ok"] is False and v["raison"] == "abandonnee"
    assert L.finding(f)["etat"] == "abandonnee"


# ------------------------------------------------------ les portes globales
def test_rien_pendant_un_incident(tmp_path):
    f = frais(tmp_path)
    v = L.autorise(f, L.proposal_key(f, "x:1", "x:2"), incident_ouvert=True)
    assert v["ok"] is False and v["raison"] == "incident-ouvert"


def test_l_incident_passe_avant_tout(tmp_path):
    """Décision n° 1 : une porte globale ferme tout, inutile de consulter
    l'historique pour se le faire dire."""
    f = frais(tmp_path)
    p = L.proposal_key(f, "x:1", "x:2")
    L.marquer_refusee(p, f)
    assert L.autorise(f, p, incident_ouvert=True)["raison"] == "incident-ouvert"


def test_plafond_de_prs_ouvertes(tmp_path):
    """Une file de quarante PRs de sécurité vaut zéro PR."""
    f = frais(tmp_path)
    for i in range(L.MAX_PRS_OUVERTES):
        fi = L.finding_key(cve=f"CVE-{i}", deployment="d", namespace="n")
        L.marquer_proposee(fi, L.proposal_key(fi, "a", "b"), pr=i)
    v = L.autorise(f, L.proposal_key(f, "x:1", "x:2"))
    assert v["ok"] is False and v["raison"] == "plafond-prs"


def test_le_plafond_se_libere_quand_une_pr_se_ferme(tmp_path):
    f = frais(tmp_path)
    cles = []
    for i in range(L.MAX_PRS_OUVERTES):
        fi = L.finding_key(cve=f"CVE-{i}", deployment="d", namespace="n")
        pi = L.proposal_key(fi, "a", "b")
        L.marquer_proposee(fi, pi, pr=i)
        cles.append((fi, pi))
    L.marquer_corrigee(cles[0][0], cles[0][1])
    assert L.prs_ouvertes() == L.MAX_PRS_OUVERTES - 1
    assert L.autorise(f, L.proposal_key(f, "x:1", "x:2"))["ok"] is True


# --------------------------------------------------------- la boucle bornée
def test_la_boucle_est_bornee(tmp_path):
    """Sans borne, « corriger -> rescan -> pas corrigé -> corriger » est un
    robot qui s'acharne."""
    f = frais(tmp_path)
    for _ in range(L.MAX_TENTATIVES):
        L.marquer_tentative(f)
    v = L.autorise(f, L.proposal_key(f, "x:1", "x:9"))
    assert v["ok"] is False and v["raison"] == "trop-de-tentatives"


def test_un_rescan_confirme_remet_le_compteur_a_zero(tmp_path):
    f = frais(tmp_path)
    L.marquer_tentative(f)
    L.marquer_tentative(f)
    L.marquer_corrigee(f)
    assert L.finding(f)["tentatives"] == 0


def test_regression_apres_merge_est_reproposable(tmp_path):
    """Mergée puis le problème revient : c'est une régression, elle mérite
    une nouvelle proposition — mais elle compte comme une tentative."""
    f = frais(tmp_path)
    p = L.proposal_key(f, "x:1", "x:2")
    L.marquer_proposee(f, p, pr=7)
    avant = L.finding(f)["tentatives"]
    v = L.autorise(f, p, statut_pr=lambda n: {"state": "closed",
                                              "merged": True})
    assert v["ok"] is True
    assert L.finding(f)["tentatives"] == avant + 1


# --------------------------------------------------- le doute et la panne
def test_statut_pr_indisponible_ne_repropose_pas(tmp_path):
    """Le doute profite au silence, jamais au doublon : une panne de l'API
    GitHub ne doit pas produire une deuxième PR."""
    f = frais(tmp_path)
    p = L.proposal_key(f, "x:1", "x:2")
    L.marquer_proposee(f, p, pr=42)

    def boum(_):
        raise OSError("github injoignable")
    v = L.autorise(f, p, statut_pr=boum)
    assert v["ok"] is False and v["raison"] == "statut-pr-inconnu"


# ------------------------------------------------------------ persistance
def test_le_registre_survit_au_redemarrage(tmp_path):
    """Sur le PVC /state. Un registre qui s'oublie au premier restart ne
    protège de rien."""
    f = frais(tmp_path)
    p = L.proposal_key(f, "x:1", "x:2")
    L.marquer_refusee(p, f)
    L.reinitialiser()                      # simule un redémarrage du pod
    L.charger()
    assert L.proposition(p)["etat"] == "refusee"


def test_registre_absent_ne_plante_pas(tmp_path):
    L.LEDGER_FILE = str(tmp_path / "nexistepas" / "l.json")
    L.reinitialiser()
    L.charger()
    f = L.finding_key(cve="X", deployment="d", namespace="n")
    assert L.autorise(f, L.proposal_key(f, "a", "b"))["ok"] is True


def test_resume_lisible(tmp_path):
    f = frais(tmp_path)
    L.marquer_proposee(f, L.proposal_key(f, "a", "b"), pr=1)
    r = L.resume()
    assert "1 problèmes suivis" in r and "PRs ouvertes" in r

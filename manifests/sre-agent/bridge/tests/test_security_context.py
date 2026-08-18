# =============================================================================
#  Tests du toolset sécurité (phase D).
# -----------------------------------------------------------------------------
#  Ce qui est couvert, c'est `evaluate()` — la fonction PURE qui décide. Le
#  réseau (EPSS, KEV, Central) n'est pas testé ici : il est remplacé par des
#  données, exactement comme `build_alerts()` en phase C. Les seuls tests
#  d'I/O sont ceux de la DÉGRADATION, parce que le comportement en panne est
#  une décision d'architecture, pas un détail d'implémentation.
#
#  La question à laquelle chaque test répond : « si cette règle se casse un
#  jour, qu'est-ce qui se passe de mal en production ? »
# =============================================================================
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import security_context as sc          # noqa: E402


KEV_OUI = {"added": "2026-03-01", "due": "2026-03-22", "ransomware": False}
KEV_RANSOM = {"added": "2026-03-01", "due": "2026-03-22", "ransomware": True}
TOURNE = {"running": True, "exposed": False, "deployments": ["frontend"]}
TOURNE_EXPOSE = {"running": True, "exposed": True, "deployments": ["frontend"]}
NE_TOURNE_PAS = {"running": False, "exposed": False, "deployments": []}


# --------------------------------------------------------- le socle : EPSS
def test_epss_eleve_donne_priorite_haute():
    v = sc.evaluate("CVE-2026-1111", {"epss": 0.42, "percentile": 0.97})
    assert v["priorite"] == "haute"
    assert "0.420" in v["justification"]


def test_epss_faible_donne_priorite_basse():
    v = sc.evaluate("CVE-2026-2222", {"epss": 0.0004, "percentile": 0.10})
    assert v["priorite"] == "basse"


def test_epss_intermediaire_donne_moyenne():
    v = sc.evaluate("CVE-2026-3333", {"epss": 0.05, "percentile": 0.70})
    assert v["priorite"] == "moyenne"


def test_cve_sans_score_epss_ne_tombe_pas_en_bas():
    """Une CVE trop récente pour être scorée ne doit PAS être enterrée :
    l'absence de score n'est pas une preuve d'innocuité."""
    v = sc.evaluate("CVE-2026-9999", None)
    assert v["priorite"] == "moyenne"
    assert "aucun score EPSS" in v["justification"]


# ------------------------------------------------- KEV : le signal d'escalade
def test_kev_ecrase_un_epss_faible():
    """Le cas qui justifie tout le module : EPSS ridicule, mais exploitée en
    réel. Sans KEV, cette CVE serait classée 'basse' et jamais traitée."""
    v = sc.evaluate("CVE-2026-4444", {"epss": 0.0001, "percentile": 0.05},
                    KEV_OUI, TOURNE_EXPOSE)
    assert v["priorite"] == "immediate"
    assert v["kev"] is True
    assert "CISA KEV" in v["justification"]


def test_seul_kev_autorise_l_escalade():
    """Décision n° 4 : la porte vers l'astreinte ne s'ouvre que sur KEV."""
    haute = sc.evaluate("CVE-2026-5555", {"epss": 0.99, "percentile": 0.999},
                        None, TOURNE_EXPOSE)
    assert haute["priorite"] == "haute"
    assert haute["escalade"] is False


def test_ransomware_est_signale():
    v = sc.evaluate("CVE-2026-6666", {"epss": 0.3}, KEV_RANSOM, TOURNE_EXPOSE)
    assert v["kev_ransomware"] is True
    assert "rançongiciel" in v["justification"]


# ------------------------------------- le contexte déclasse, jamais l'inverse
def test_image_qui_ne_tourne_plus_devient_vex():
    v = sc.evaluate("CVE-2026-7777", {"epss": 0.9}, KEV_OUI, NE_TOURNE_PAS)
    assert v["priorite"] == "vex"
    assert "VEX" in v["justification"]


def test_kev_non_expose_redescend_a_haute():
    """Exploitée mais injoignable de l'extérieur : on reste haut sans
    réveiller quelqu'un. C'est la nuance qui évite les fausses urgences."""
    v = sc.evaluate("CVE-2026-8888", {"epss": 0.2}, KEV_OUI, TOURNE)
    assert v["priorite"] == "haute"
    assert v["escalade"] is False
    assert "non exposée" in v["justification"]


def test_le_contexte_ne_surclasse_jamais():
    """Une charge exposée ne transforme pas une CVE inoffensive en urgence."""
    v = sc.evaluate("CVE-2026-1212", {"epss": 0.0001}, None, TOURNE_EXPOSE)
    assert v["priorite"] == "basse"
    assert v["escalade"] is False


def test_sans_contexte_central_le_verdict_sort_quand_meme():
    v = sc.evaluate("CVE-2026-1313", {"epss": 0.5}, None, {})
    assert v["priorite"] == "haute"
    assert v["running"] is None


# ------------------------------------------------------------ tri et résumé
def test_le_tri_met_les_urgences_en_tete(monkeypatch):
    monkeypatch.setattr(sc, "fetch_kev", lambda: {"CVE-2026-B": KEV_OUI})
    monkeypatch.setattr(sc, "fetch_epss", lambda c: {
        "CVE-2026-A": {"epss": 0.0001, "percentile": 0.02},
        "CVE-2026-B": {"epss": 0.3, "percentile": 0.9}})
    monkeypatch.setattr(sc, "fetch_runtime",
                        lambda *a, **k: dict(TOURNE_EXPOSE))
    out = sc.collect(["CVE-2026-A", "CVE-2026-B"])
    assert [v["cve"] for v in out["verdicts"]] == ["CVE-2026-B", "CVE-2026-A"]
    assert out["escalade"] is True
    assert out["degraded"] == []


def test_resume_lisible_en_war_room():
    verdicts = [sc.evaluate("CVE-2026-A", {"epss": 0.3}, KEV_OUI,
                            TOURNE_EXPOSE),
                sc.evaluate("CVE-2026-B", {"epss": 0.0001}, None,
                            TOURNE_EXPOSE)]
    texte = sc.resume(verdicts)
    assert "2 CVE triées" in texte
    assert "CVE-2026-A" in texte


# --------------------------------------------- la dégradation est un contrat
def test_une_api_en_panne_ne_fait_pas_echouer_le_tri(monkeypatch):
    """Décision n° 2 : le pipeline de sécurité ne dépend pas de la
    disponibilité d'Internet. Si ce test casse, une panne de FIRST.org rend
    l'agent muet — le pire scénario possible."""
    def boum(*a, **k):
        raise OSError("réseau injoignable")
    monkeypatch.setattr(sc, "fetch_kev", boum)
    monkeypatch.setattr(sc, "fetch_epss", boum)
    monkeypatch.setattr(sc, "fetch_runtime", boum)
    out = sc.collect(["CVE-2026-A"])
    assert len(out["verdicts"]) == 1
    assert sorted(out["degraded"]) == ["central", "epss", "kev"]
    assert "tri dégradé" in out["resume"]


def test_degradation_signalee_dans_le_resume(monkeypatch):
    monkeypatch.setattr(sc, "fetch_kev", lambda: (_ for _ in ()).throw(
        OSError("KEV HS")))
    monkeypatch.setattr(sc, "fetch_epss", lambda c: {
        "CVE-2026-A": {"epss": 0.5, "percentile": 0.95}})
    monkeypatch.setattr(sc, "fetch_runtime", lambda *a, **k: dict(TOURNE))
    out = sc.collect(["CVE-2026-A"])
    assert out["degraded"] == ["kev"]
    assert "kev" in out["resume"]


def test_liste_vide_ne_plante_pas():
    out = sc.resume([], [])
    assert "aucune CVE" in out


# ----------------------------------------------- extraction des CVE du texte
def test_extraction_des_cve_dans_un_message_de_violation():
    """StackRox ne fournit aucun champ structuré : les CVE sont dans le texte
    des violations. Si cette extraction rate, le toolset trie une liste vide
    et l'agent perd tout son contexte sans rien signaler."""
    msg = ("Container 'server' includes component 'openssl' (version 3.0.1) "
           "which contains CVE-2022-3602, resolved by version 3.0.7")
    assert sc.extract_cves(msg) == ["CVE-2022-3602"]


def test_extraction_dedupliquee_triee_et_en_majuscules():
    a = "cve-2021-44228 encore CVE-2021-44228"
    b = "et aussi CVE-2020-1938"
    assert sc.extract_cves(a, b) == ["CVE-2020-1938", "CVE-2021-44228"]


def test_extraction_ignore_les_faux_positifs():
    """Un identifiant tronqué n'est pas une CVE : mieux vaut rien extraire
    qu'interroger EPSS avec un identifiant inventé."""
    assert sc.extract_cves("CVE-20-1 et CVE-abcd-1234") == []


def test_extraction_sur_textes_vides_ou_absents():
    assert sc.extract_cves(None, "", "aucune reference") == []


def test_violation_sans_cve_reste_traitee(monkeypatch):
    """Une violation de signature ne cite aucune CVE. Le toolset doit quand
    même rendre le contexte d'exécution — sinon la phase C perd son intérêt
    pour tout ce qui n'est pas une vulnérabilité."""
    monkeypatch.setattr(sc, "fetch_kev", dict)
    monkeypatch.setattr(sc, "fetch_epss", lambda c: {})
    monkeypatch.setattr(sc, "fetch_runtime", lambda *a, **k: dict(TOURNE))
    out = sc.collect(sc.extract_cves("image signature is not verified"))
    assert out["verdicts"] == []
    assert out["escalade"] is False
    assert "aucune CVE" in out["resume"]


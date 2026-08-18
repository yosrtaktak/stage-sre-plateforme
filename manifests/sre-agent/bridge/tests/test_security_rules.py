# =============================================================================
#  Tests des règles de correction sécurité (phase E1).
# -----------------------------------------------------------------------------
#  Chaque test répond à : « si cette règle saute, qu'est-ce que l'agent
#  proposerait de faire au cluster ? ». Les tests de REFUS sont les plus
#  importants — une allow-list ne se prouve pas par ce qu'elle laisse passer.
# =============================================================================
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import security_rules as r          # noqa: E402


IMG = "ghcr.io/yosrtaktak/sre-bridge"
APP = "us-central1-docker.pkg.dev/google-samples/microservices-demo/frontend"
D64 = "sha256:" + "a" * 64
D64B = "sha256:" + "b" * 64


# ------------------------------------------------- 1. le dépôt de l'agent
def test_l_agent_ne_touche_pas_a_ses_propres_manifestes():
    """LE test de la phase E. Un agent qui peut proposer une PR élargissant
    sa propre allow-list n'a plus d'allow-list."""
    v = r.file_allowed("manifests/sre-agent/bridge/deploy/bridge-deployment.yaml")
    assert v["ok"] is False
    assert v["reason"] == "file-denied"


def test_le_refus_passe_avant_l_allow_list():
    """Même si une entrée d'allow-list devenait trop large un jour, le refus
    tiendrait : l'ordre des vérifications est lui-même un garde-fou."""
    v = r.file_allowed("manifests/sre-agent/rag/postmortem-rag.py")
    assert v["ok"] is False and v["reason"] == "file-denied"


def test_fichiers_autorises():
    assert r.file_allowed("manifests/app/frontend/deployment.yaml")["ok"]
    assert r.file_allowed("manifests/monitoring/values.yaml")["ok"]


def test_litmus_values_reste_hors_perimetre():
    """Ce fichier a porté des credentials (dette B7) : aucune PR automatique
    ne s'en approche."""
    assert r.file_allowed("manifests/monitoring/litmus-values.yaml")["ok"] is False


def test_chemins_autorises_et_refuses():
    assert r.path_allowed("spec.template.spec.containers[0].image")["ok"]
    assert r.path_allowed("grafana.image.tag")["ok"]
    assert r.path_allowed("spec.template.spec.serviceAccountName")["ok"] is False


# ------------------------------------------------------ 2. lecture des refs
def test_parse_ref_complete():
    p = r.parse_ref(f"{IMG}:sha-abc1234@{D64}")
    assert p["repo"] == IMG and p["tag"] == "sha-abc1234" and p["digest"] == D64


def test_parse_ref_sans_tag_ni_digest():
    p = r.parse_ref("nginx")
    assert p["repo"] == "nginx" and p["tag"] is None


def test_tag_flottant_reconnu():
    assert r.is_floating("latest") and r.is_floating(None)
    assert r.is_floating("stable-alpine")
    assert not r.is_floating("1.2.3")


def test_base_de_donnees_reconnue_sur_le_dernier_segment():
    assert r.is_database("docker.io/library/postgres")
    assert r.is_database("redis")
    assert not r.is_database("docker.io/library/nginx")


def test_classification_des_bumps():
    assert r.classify_bump("1.2.3", "1.2.4") == "patch"
    assert r.classify_bump("1.2.3", "1.3.0") == "minor"
    assert r.classify_bump("1.2.3", "2.0.0") == "major"
    assert r.classify_bump("2.0.0", "1.9.9") == "downgrade"
    assert r.classify_bump("v1.2.3", "1.2.3") == "same"
    assert r.classify_bump("16", "16.4") == "minor"


# ------------------------------------------------------ 3. ce qui est permis
def test_bump_patch_accepte():
    v = r.check_image_change(f"{APP}:v0.10.2", f"{APP}:v0.10.3")
    assert v["ok"] and v["kind"] == "bump-patch"


def test_bump_mineur_accepte():
    v = r.check_image_change(f"{APP}:v0.10.2", f"{APP}:v0.11.0")
    assert v["ok"] and v["kind"] == "bump-minor"


def test_epinglage_d_un_tag_flottant():
    """`latest` ne se bumpe pas : il s'épingle. Les deux opérations sont
    distinctes, et le verdict le dit."""
    v = r.check_image_change(f"{APP}:latest", f"{APP}:v0.10.3")
    assert v["ok"] and v["kind"] == "pin"


def test_image_sans_tag_est_traitee_comme_flottante():
    v = r.check_image_change(APP, f"{APP}:v0.10.3")
    assert v["ok"] and v["kind"] == "pin"


def test_digest_rafraichi_sur_la_meme_version():
    """Rebuild amont : même tag, contenu différent. C'est un correctif
    légitime — souvent le seul disponible pour une CVE de couche de base."""
    v = r.check_image_change(f"{APP}:v0.10.3@{D64}", f"{APP}:v0.10.3@{D64B}")
    assert v["ok"] and v["kind"] == "bump-digest"


def test_ajouter_un_digest_est_accepte():
    v = r.check_image_change(f"{APP}:v0.10.2", f"{APP}:v0.10.3@{D64}")
    assert v["ok"]


# --------------------------------------------------- 4. ce qui est REFUSÉ
def test_bump_majeur_refuse():
    v = r.check_image_change(f"{APP}:v1.2.3", f"{APP}:v2.0.0")
    assert v["ok"] is False and v["reason"] == "major"


def test_base_de_donnees_majeur_refuse():
    """postgres 16 -> 17 migre le format sur disque : issue, jamais de PR."""
    v = r.check_image_change("docker.io/library/postgres:16.4",
                             "docker.io/library/postgres:17.0")
    assert v["ok"] is False and v["reason"] == "major"


def test_base_de_donnees_correctif_accepte_mais_signale():
    """postgres 16.4 -> 16.5 est LE correctif de sécurité qu'on veut
    automatiser : même majeur, donc même format sur disque. Une première
    version de la règle (« patch seulement ») l'aurait bloqué à tort. On
    l'accepte, et on signale ce que l'agent ne peut pas vérifier."""
    v = r.check_image_change("docker.io/library/postgres:16.4",
                             "docker.io/library/postgres:16.5")
    assert v["ok"] and v["kind"] == "bump-minor"
    assert "sauvegarde" in v["warn"]


def test_image_ordinaire_sans_avertissement():
    v = r.check_image_change(f"{APP}:v0.10.2", f"{APP}:v0.10.3")
    assert v["warn"] is None


def test_changement_de_depot_refuse():
    """Une substitution de charge déguisée en mise à jour."""
    v = r.check_image_change(f"{APP}:v0.10.2", f"{IMG}:v0.10.3")
    assert v["ok"] is False and v["reason"] == "repo-change"


def test_perte_de_digest_refusee():
    """Un correctif de sécurité qui affaiblit la chaîne de signature des
    phases A et B n'est pas un correctif."""
    v = r.check_image_change(f"{APP}:v0.10.2@{D64}", f"{APP}:v0.10.3")
    assert v["ok"] is False and v["reason"] == "digest-perdu"


def test_downgrade_refuse():
    v = r.check_image_change(f"{APP}:v0.11.0", f"{APP}:v0.10.3")
    assert v["ok"] is False and v["reason"] == "downgrade"


def test_flottant_vers_flottant_refuse():
    v = r.check_image_change(f"{APP}:latest", f"{APP}:stable")
    assert v["ok"] is False and v["reason"] == "toujours-flottant"


def test_changement_de_variante_refuse():
    """1.2.3 -> 1.2.3-alpine change la distribution de base, pas la version :
    ce n'est pas un correctif de CVE, c'est une décision d'architecture."""
    v = r.check_image_change(f"{APP}:1.2.3", f"{APP}:1.2.3-alpine")
    assert v["ok"] is False and v["reason"] == "variante"


def test_no_op_refuse():
    v = r.check_image_change(f"{APP}:v0.10.3", f"{APP}:v0.10.3")
    assert v["ok"] is False and v["reason"] == "no-op"


def test_reference_illisible_refusee():
    assert r.check_image_change("", f"{APP}:1.0.0")["ok"] is False
    assert r.check_image_change(f"{APP}:1.0.0", "PAS UNE REF")["ok"] is False


# ------------------------------------------------------ 5. le corps de PR
def test_corps_de_pr_porte_les_preuves():
    verdict = {"cve": "CVE-2026-1234", "epss": 0.42, "epss_percentile": 0.973,
               "kev": True, "kev_ransomware": False, "running": True,
               "exposed": False, "priorite": "haute",
               "justification": "inscrite au catalogue CISA KEV"}
    body = r.pr_body(f"{APP}:v0.10.2", f"{APP}:v0.10.3", verdict,
                     deployment="frontend", namespace="online-boutique")
    assert "CVE-2026-1234" in body
    assert "0.42" in body and "97.3%" in body
    assert "exploitée en réel" in body
    assert "rescan-confirm" in body
    assert "online-boutique/frontend" in body


def test_corps_de_pr_signale_la_degradation():
    """Une PR produite sans contexte doit le dire : l'humain qui merge doit
    savoir sur quoi le verdict repose."""
    body = r.pr_body(f"{APP}:v1", f"{APP}:v2", {"cve": "CVE-X"},
                     degraded=["central"])
    assert "dégradé" in body and "central" in body
    assert "la priorité n'est jamais abaissée" in body


def test_avertissement_bd_present_dans_la_pr():
    v = r.check_image_change("docker.io/library/postgres:16.4",
                             "docker.io/library/postgres:16.5")
    body = r.pr_body("postgres:16.4", "postgres:16.5", {"cve": "CVE-X"},
                     warn=v["warn"])
    assert "À vérifier avant de merger" in body
    assert "sauvegarde" in body


def test_l_agent_ne_touche_pas_aux_workflows_qui_le_controlent():
    """Le trou le moins évident. Les workflows font tourner les 6 checks
    requis sur les PRs de l'agent : une PR « réduire les permissions du
    workflow » pourrait désarmer le gate qui le contrôle, en ayant l'air
    d'une amélioration. zizmor et Renovate couvrent déjà ce terrain."""
    for f in (".github/workflows/security-scan.yml",
              ".github/workflows/agent-ci.yml",
              ".github/CODEOWNERS"):
        v = r.file_allowed(f)
        assert v["ok"] is False and v["reason"] == "file-denied", f

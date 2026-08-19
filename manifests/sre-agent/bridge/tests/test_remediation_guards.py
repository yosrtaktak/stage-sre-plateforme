import py_compile
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

import remediation as R  # noqa: E402


def test_all_sources_compile():
    """Erreur de syntaxe = échec en CI, pas au déploiement. Les entrypoints
    hyphénés (holmes-bridge.py, slack-gateway.py) ne sont pas importables :
    on les compile."""
    files = sorted(SRC.glob("*.py"))
    assert files, f"aucune source trouvée dans {SRC}"
    for f in files:
        py_compile.compile(str(f), doraise=True)


# ---- _qty_units : conversion des quantités k8s ------------------------------

def test_qty_units():
    assert R._qty_units("250m") == 0.25
    assert R._qty_units("2") == 2.0
    assert R._qty_units("512Mi") == 512 * 1024.0 ** 2
    assert R._qty_units("1Gi") == 1024.0 ** 3
    assert R._qty_units("abc") is None
    assert R._qty_units("1.5Gi") is None  # décimaux non admis par l'allow-list


# ---- replicas : jamais 0 (extinction), jamais l'emballement -----------------

def test_replicas_zero_rejected():
    with pytest.raises(R._Reject):
        R._check_values("spec.replicas", "2", "0")


def test_replicas_above_max_rejected():
    with pytest.raises(R._Reject):
        R._check_values("spec.replicas", "2", "6")


def test_replicas_in_bounds_ok():
    R._check_values("spec.replicas", "1", "3")


# ---- resources : baisse bornée à 50 % + plancher absolu ---------------------

def test_memory_increase_ok():
    R._check_values("resources.limits.memory", "128Mi", "1Gi")


def test_memory_halving_ok():
    R._check_values("resources.limits.memory", "1Gi", "512Mi")


def test_memory_crash_diet_rejected():
    # 512Mi -> 128Mi : baisse de 75 % > le max de 50 %
    with pytest.raises(R._Reject):
        R._check_values("resources.limits.memory", "512Mi", "128Mi")


def test_memory_below_floor_rejected():
    # 24Mi -> 12Mi : exactement -50 % (admis), mais sous le plancher de 16Mi
    with pytest.raises(R._Reject):
        R._check_values("resources.limits.memory", "24Mi", "12Mi")


def test_cpu_aggressive_cut_rejected():
    with pytest.raises(R._Reject):
        R._check_values("resources.requests.cpu", "500m", "200m")


def test_garbage_value_rejected():
    with pytest.raises(R._Reject):
        R._check_values("resources.limits.memory", "512Mi", "$(rm -rf /)")


# ---- rollout : maxSurge/maxUnavailable & progressDeadlineSeconds ------------

def test_surge_percent_bounds():
    R._check_values("rollingUpdate.maxSurge", "25%", "50%")
    with pytest.raises(R._Reject):
        R._check_values("rollingUpdate.maxSurge", "25%", "60%")


def test_progress_deadline_bounds():
    R._check_values("spec.progressDeadlineSeconds", "300", "600")
    with pytest.raises(R._Reject):
        R._check_values("spec.progressDeadlineSeconds", "600", "30")


# ---- parse_patch : le parseur UNIQUE du bloc PATCH_PROPOSAL -----------------

PATCH = """verdict: OOMKilled récurrent sur emailservice
PATCH_PROPOSAL:
file: manifests/app/emailservice.yaml
path: spec.template.spec.containers.0.resources.limits.memory
old: 128Mi
new: 256Mi
reason: OOMKilled récurrent, P95 mémoire à 118Mi
"""


def test_parse_patch_single():
    fichier, changes = R.parse_patch(PATCH)
    assert fichier == "manifests/app/emailservice.yaml"
    assert changes == [(
        "spec.template.spec.containers.0.resources.limits.memory",
        "128Mi", "256Mi", "OOMKilled récurrent, P95 mémoire à 118Mi")]


def test_parse_patch_absent():
    assert R.parse_patch("aucune proposition dans ce verdict") is None


def test_harden_les_cles_s_arretent_en_fin_de_ligne():
    """1er run reel (19/08) : la prose du LLM suit le bloc ; la capture des cles doit s arreter au saut de ligne."""
    analyse = ("Verdict : violation.\n\n" "HARDEN_PROPOSAL:\n" "file: manifests/app/loadgenerator/deployment.yaml\n" "container: 0\n" "keys: allowPrivilegeEscalation\n" "\n" "Confiance : haute - alerte confirmee.\n")
    m = R.HARDEN_RE.search(analyse)
    assert m is not None
    cles = [c.strip() for c in m.group("keys").split(",") if c.strip()]
    assert cles == ["allowPrivilegeEscalation"]

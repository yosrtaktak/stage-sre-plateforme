# =============================================================================
#  Tests du traducteur StackRox -> Alertmanager. La traduction est la seule
#  partie qui peut se tromper EN SILENCE : une alerte mal étiquetée n'échoue
#  pas, elle part simplement dans la mauvaise route (ou réveille l'astreinte).
#  D'où une fonction pure `build_alerts` et ces tests, lancés par le job
#  `test` de agent-ci.yml — check requis de la protection de branche.
#  Destination : manifests/sre-agent/bridge/tests/test_stackrox_adapter.py
# =============================================================================
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

import stackrox_adapter as A  # noqa: E402


# Payload réel du notifier Generic Webhook, réduit aux champs utilisés.
# Modelé sur la violation qui a servi de preuve à B6 (§5.5 du rapport).
PAYLOAD = {
    "alert": {
        "id": "b0d0c1a2-1111-2222-3333-444455556666",
        "state": "ACTIVE",
        "lifecycleStage": "DEPLOY",
        "time": "2026-08-17T08:43:20Z",
        "policy": {
            "name": "GHCR image non signée par le pipeline",
            "severity": "HIGH_SEVERITY",
            "categories": ["Supply Chain Security"],
            "description": "Bloque au déploiement toute image ghcr.io…",
            "rationale": "Seules les images signées par build-images.yml…",
            "remediation": "Faire construire l'image par le workflow…",
        },
        "deployment": {
            "name": "test-unsigned",
            "namespace": "argocd",
            "clusterName": "stage",
            "containers": [
                {"image": {"name": {
                    "fullName": "ghcr.io/stefanprodan/podinfo:6.7.1"}}}
            ],
        },
        "violations": [
            {"message": "Container 'podinfo' has image with registry 'ghcr.io'"},
            {"message": "Container 'podinfo' image signature is not verified "
                        "by the specified signature integration(s)."},
        ],
    }
}


def _one(payload):
    alerts = A.build_alerts(payload)
    assert len(alerts) == 1
    return alerts[0]


# ---- le contrat de routage --------------------------------------------------

def test_label_source_present():
    """Sans `source: stackrox`, la route dédiée ne matche pas et la violation
    part dans le circuit générique — donc vers GoAlert. C'est LE label qui
    protège l'astreinte."""
    assert _one(PAYLOAD)["labels"]["source"] == "stackrox"


def test_severity_mapping():
    assert A.SEVERITY_MAP["CRITICAL_SEVERITY"] == "critical"
    assert A.SEVERITY_MAP["HIGH_SEVERITY"] == "critical"
    assert A.SEVERITY_MAP["MEDIUM_SEVERITY"] == "warning"
    assert A.SEVERITY_MAP["LOW_SEVERITY"] == "info"
    assert _one(PAYLOAD)["labels"]["severity"] == "critical"


def test_severity_inconnue_devient_warning():
    """Une sévérité que StackRox ajouterait demain ne doit ni faire planter
    l'adapter, ni être silencieusement traitée comme critique."""
    p = json.loads(json.dumps(PAYLOAD))
    p["alert"]["policy"]["severity"] = "APOCALYPSE_SEVERITY"
    assert _one(p)["labels"]["severity"] == "warning"


# ---- la clé de dédup --------------------------------------------------------

def test_cle_de_dedup_policy_deployment_namespace():
    lab = _one(PAYLOAD)["labels"]
    assert lab["policy"] == "GHCR image non signée par le pipeline"
    assert lab["deployment"] == "test-unsigned"
    assert lab["namespace"] == "argocd"


def test_labels_tous_non_vides():
    """Alertmanager rejette un label vide : tout champ absent doit tomber sur
    un défaut, jamais sur une chaîne vide."""
    for k, v in _one({"alert": {}})["labels"].items():
        assert isinstance(v, str) and v, f"label {k} vide"


# ---- le contenu que l'agent va lire ----------------------------------------

def test_description_porte_le_detail_des_violations():
    """La policy dit l'intention, les violations disent le fait. C'est le fait
    que l'agent doit recevoir."""
    desc = _one(PAYLOAD)["annotations"]["description"]
    assert "signature is not verified" in desc
    assert "registry 'ghcr.io'" in desc


def test_description_retombe_sur_la_policy_si_pas_de_violation():
    p = json.loads(json.dumps(PAYLOAD))
    p["alert"]["violations"] = []
    assert _one(p)["annotations"]["description"].startswith("Bloque")


def test_image_en_annotation():
    ann = _one(PAYLOAD)["annotations"]
    assert ann["image"] == "ghcr.io/stefanprodan/podinfo:6.7.1"


def test_generator_url_pointe_la_violation():
    url = _one(PAYLOAD)["generatorURL"]
    assert url.endswith("/main/violations/b0d0c1a2-1111-2222-3333-444455556666")


# ---- la fenêtre de vie (décision 2 de l'en-tête) ----------------------------

def test_active_ne_sauto_resout_pas():
    """endsAt doit être LOIN devant : sinon Alertmanager efface la violation
    au bout de resolve_timeout (5 min) comme si elle avait été corrigée."""
    a = _one(PAYLOAD)
    ends = datetime.strptime(a["endsAt"], "%Y-%m-%dT%H:%M:%SZ")
    delta = ends - datetime.utcnow()
    assert delta > timedelta(hours=A.HOLD_HOURS - 1)


def test_resolved_cloture_immediatement():
    p = json.loads(json.dumps(PAYLOAD))
    p["alert"]["state"] = "RESOLVED"
    ends = datetime.strptime(_one(p)["endsAt"], "%Y-%m-%dT%H:%M:%SZ")
    assert ends - datetime.utcnow() < timedelta(minutes=1)


# ---- robustesse -------------------------------------------------------------

def test_payload_nu_accepte():
    """curl de test manuel : l'objet alert sans l'enveloppe {"alert": …}."""
    assert _one(PAYLOAD["alert"])["labels"]["deployment"] == "test-unsigned"


def test_payload_vide_ne_plante_pas():
    a = _one({})
    assert a["labels"]["alertname"] == "StackRoxPolicyViolation"
    assert a["labels"]["deployment"] == "-"


def test_violation_runtime_sans_deployment():
    """Les policies runtime peuvent notifier sans bloc deployment complet."""
    p = {"alert": {"policy": {"name": "Shell dans un conteneur",
                              "severity": "MEDIUM_SEVERITY"},
                   "lifecycleStage": "RUNTIME"}}
    lab = _one(p)["labels"]
    assert lab["severity"] == "warning"
    assert lab["lifecycle"] == "RUNTIME"
    assert lab["namespace"] == "-"

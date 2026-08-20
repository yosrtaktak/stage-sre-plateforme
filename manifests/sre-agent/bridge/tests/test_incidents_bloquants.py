# =============================================================================
#  Tests de la porte « un service brûle-t-il ? » (phase F, L4).
# -----------------------------------------------------------------------------
#  Le filtrage lui-même est fait par PostgREST, pas par nous : ce qui se teste
#  ici est donc la REQUÊTE. C'est le bon niveau — les trois réglages de la
#  décision L4 vivent tous dans l'URL, et une URL fausse est exactement le
#  genre de défaut qu'on ne voit pas en production (la porte s'ouvre ou se
#  ferme, sans jamais dire pourquoi).
#
#  Le seul comportement de code testé est celui qui compte le plus : que
#  l'indisponibilité de la base laisse la porte OUVERTE. C'est l'inverse du
#  réglage de la dédup, et c'est délibéré.
# =============================================================================
import os
import sys
from pathlib import Path

# L'adapter se désactive tout seul quand l'URL est vide : on la pose AVANT
# l'import, sinon `enabled()` rend False et tous les tests passent à vide.
os.environ.setdefault("INCIDENT_API_URL", "http://incident-db-api.test:3000")

_ICI = Path(__file__).resolve().parent
for _c in (_ICI.parent / "src", _ICI):     # arborescence VM, puis copie locale
    if (_c / "incident_adapter.py").exists():
        sys.path.insert(0, str(_c))
        break

import incident_adapter as A                # noqa: E402


class FauxReq:
    """Remplace `_req` : enregistre le chemin appelé, rend ce qu'on lui dit."""

    def __init__(self, rows=None, echoue=False):
        self.rows = rows
        self.echoue = echoue
        self.chemins = []

    def __call__(self, method, path, body=None, prefer=None):
        self.chemins.append(path)
        if self.echoue:
            raise RuntimeError("PostgREST 503")
        return self.rows


def brancher(monkey_rows=None, echoue=False):
    faux = FauxReq(monkey_rows, echoue)
    A._req = faux
    return faux


def incident(nom="HighErrorRate", sev="critical", ident=1):
    return {"id": ident, "alertname": nom, "severity": sev,
            "opened_at": "2026-08-20T10:00:00+00:00"}


# ------------------------------------------------------------- la voie libre
def test_aucun_incident_rend_une_liste_vide():
    brancher([])
    assert A.incidents_bloquants() == []


def test_un_incident_de_production_bloque():
    brancher([incident()])
    r = A.incidents_bloquants()
    assert len(r) == 1 and r[0]["alertname"] == "HighErrorRate"


# ------------------------------- réglage n° 1 : StackRox n'est pas un feu
def test_les_violations_stackrox_sont_exclues_de_la_requete():
    """Sans ce filtre, la première violation bloquerait sa propre correction."""
    faux = brancher([])
    A.incidents_bloquants()
    chemin, = faux.chemins
    assert "alertname=not.in.(" in chemin
    assert "StackRoxPolicyViolation" in chemin


def test_seuls_les_statuts_vivants_comptent():
    faux = brancher([])
    A.incidents_bloquants()
    assert "status=in.(open,acked)" in faux.chemins[0]


# --------------------------------- réglage n° 2 : une ligne n'est pas un feu
def test_la_fenetre_borne_la_requete():
    """Un `resolved` perdu laisse une ligne `open` pour toujours (§12.4)."""
    faux = brancher([])
    A.incidents_bloquants()
    assert "opened_at=gte." in faux.chemins[0]


def test_la_fenetre_est_reglable():
    assert isinstance(A.INCIDENT_FENETRE_H, int)
    assert A.INCIDENT_FENETRE_H > 0


# ------------------------- réglage n° 3 : injoignable = laissez-passer
def test_une_base_muette_laisse_la_porte_ouverte():
    """Le contraire de la dédup, et c'est voulu : un agent muet pendant six
    jours ne se voit pas, une PR de trop se rattrape en un clic."""
    avant = A.counters["errors"]
    brancher(echoue=True)
    assert A.incidents_bloquants() == []
    assert A.counters["errors"] == avant + 1


def test_une_reponse_nulle_ne_casse_rien():
    brancher(None)
    assert A.incidents_bloquants() == []


# ------------------------------------------------------------- désactivation
def test_adapter_desactive_ne_bloque_jamais(monkeypatch):
    faux = brancher([incident()])
    monkeypatch.setattr(A, "INCIDENT_API", "")
    assert A.incidents_bloquants() == []
    assert faux.chemins == []          # aucune requête tentée

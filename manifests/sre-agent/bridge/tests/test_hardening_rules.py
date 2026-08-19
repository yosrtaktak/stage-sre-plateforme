# =============================================================================
#  Tests du durcissement additif (phase E3).
# -----------------------------------------------------------------------------
#  C'est le lot le plus dangereux des cinq : E1 et E2 décidaient, E3 ÉCRIT du
#  YAML dans un manifeste de production. Un bloc mal indenté et le déploiement
#  ne se rend plus. Les tests portent donc autant sur le TEXTE PRODUIT que sur
#  la décision — et le plus important d'entre eux vérifie qu'on ne touche
#  jamais à ce qui existe déjà.
# =============================================================================
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import hardening_rules as H          # noqa: E402


NU = """apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: frontend
          image: registry/frontend:1.0
          ports:
            - containerPort: 8080
          resources:
            requests: { cpu: 10m }
      volumes:
        - name: tmp
          emptyDir: {}
"""

AVEC_SC = """spec:
  template:
    spec:
      containers:
        - name: bridge
          image: registry/bridge:1.0
          securityContext:
            runAsNonRoot: true
            allowPrivilegeEscalation: false
          ports:
            - containerPort: 8000
"""

PORT_PRIVILEGIE = NU.replace("containerPort: 8080", "containerPort: 80")

DEUX = """spec:
  template:
    spec:
      containers:
        - name: premier
          image: a:1
        - name: second
          image: b:1
"""


# ------------------------------------------------------------- lecture du YAML
def test_trouve_le_bon_conteneur():
    lignes = DEUX.split("\n")
    d0, f0 = H.bloc_conteneur(lignes, 0)
    d1, _ = H.bloc_conteneur(lignes, 1)
    assert "premier" in lignes[d0]
    assert "second" in lignes[d1]
    assert f0 == d1                      # le premier s'arrête où le second commence


def test_conteneur_inexistant():
    assert H.bloc_conteneur(DEUX.split("\n"), 5) is None


def test_les_volumes_ne_sont_pas_pris_pour_un_conteneur():
    """`volumes:` est une autre liste au même niveau : si on la confondait,
    on écrirait un securityContext dans un volume."""
    lignes = NU.split("\n")
    d, f = H.bloc_conteneur(lignes, 0)
    assert all("emptyDir" not in ln for ln in lignes[d:f])


def test_lit_les_ports():
    assert H.ports_declares(NU.split("\n"), *H.bloc_conteneur(NU.split("\n"))) \
        == [8080]


# ------------------------------------------------------------------- décision
def test_conteneur_nu_tout_est_proposable_sauf_les_deux_prudents():
    a = H.analyser(NU)
    assert a["ok"]
    assert set(a["proposer"]) == {"allowPrivilegeEscalation", "seccompProfile",
                                  "capabilities"}
    noms = [n for n, _ in a["issue"]]
    assert "readOnlyRootFilesystem" in noms      # décision n° 5
    assert "runAsNonRoot" in noms                # décision n° 4, sans preuve


def test_runAsNonRoot_propose_si_la_preuve_est_fournie():
    a = H.analyser(NU, image_non_root=True)
    assert "runAsNonRoot" in a["proposer"]


def test_image_root_part_en_issue_avec_la_vraie_raison():
    a = H.analyser(NU, image_non_root=False)
    raison = dict(a["issue"])["runAsNonRoot"]
    assert "changer l'image" in raison


def test_readOnlyRootFilesystem_ne_part_JAMAIS_en_pr():
    """Le bridge l'a prouvé : le durcir a demandé un volume, et pas sur /tmp
    comme on l'aurait cru. Un correctif qui produit un CrashLoopBackOff n'est
    pas un correctif."""
    for preuve in (True, False, None):
        a = H.analyser(NU, image_non_root=preuve)
        assert "readOnlyRootFilesystem" not in a["proposer"]


def test_port_privilegie_bloque_le_drop_des_capabilities():
    """Un conteneur qui écoute sur 80 a besoin de NET_BIND_SERVICE : lui
    retirer toutes les capabilities le casse au démarrage."""
    a = H.analyser(PORT_PRIVILEGIE)
    assert "capabilities" not in a["proposer"]
    assert "NET_BIND_SERVICE" in dict(a["issue"])["capabilities"]


def test_ce_qui_existe_deja_n_est_pas_repropose():
    a = H.analyser(AVEC_SC)
    assert "allowPrivilegeEscalation" not in a["proposer"]
    assert "runAsNonRoot" not in a["proposer"]
    assert set(a["deja_present"]) == {"runAsNonRoot", "allowPrivilegeEscalation"}


# --------------------------------------------------------- fabrication du YAML
def test_cree_le_bloc_quand_il_manque():
    r = H.inserer(NU, cles=["allowPrivilegeEscalation"])
    assert r["ok"]
    assert "          securityContext:" in r["texte"]
    assert "            allowPrivilegeEscalation: false" in r["texte"]


def test_l_indentation_suit_celle_du_conteneur():
    """Un bloc mal indenté et le déploiement ne se rend plus."""
    r = H.inserer(NU, cles=["allowPrivilegeEscalation"])
    lignes = r["texte"].split("\n")
    i = [n for n, ln in enumerate(lignes) if "securityContext:" in ln][0]
    assert H._indent(lignes[i]) == 10          # clés du conteneur
    assert H._indent(lignes[i + 1]) == 12      # sous-clés


def test_valeurs_imbriquees_rendues_correctement():
    r = H.inserer(NU, cles=["capabilities", "seccompProfile"])
    t = r["texte"]
    assert "            capabilities:" in t
    assert '              drop: ["ALL"]' in t
    assert "            seccompProfile:" in t
    assert "              type: RuntimeDefault" in t


def test_ajoute_dans_un_bloc_existant_sans_le_reecrire():
    """Décision n° 1 : additif strict. Les deux clés déjà là doivent rester
    intactes, à l'identique."""
    r = H.inserer(AVEC_SC, cles=["seccompProfile"])
    assert r["ok"]
    t = r["texte"]
    assert t.count("securityContext:") == 1
    assert "            runAsNonRoot: true" in t
    assert "            allowPrivilegeEscalation: false" in t
    assert "            seccompProfile:" in t


def test_ne_touche_jamais_une_cle_existante():
    r = H.inserer(AVEC_SC, cles=["runAsNonRoot"])
    assert r["ok"] is False and r["raison"] == "deja-present"


def test_idempotent():
    """Rejouer la même insertion ne doit rien produire de neuf — sinon chaque
    cycle de scan empilerait des doublons dans le manifeste."""
    r1 = H.inserer(NU, cles=["allowPrivilegeEscalation"])
    r2 = H.inserer(r1["texte"], cles=["allowPrivilegeEscalation"])
    assert r2["ok"] is False and r2["raison"] == "deja-present"


def test_n_affecte_que_le_conteneur_vise():
    r = H.inserer(DEUX, index=1, cles=["allowPrivilegeEscalation"])
    lignes = r["texte"].split("\n")
    i_premier = [n for n, ln in enumerate(lignes) if "premier" in ln][0]
    i_sc = [n for n, ln in enumerate(lignes) if "securityContext" in ln][0]
    i_second = [n for n, ln in enumerate(lignes) if "second" in ln][0]
    assert i_premier < i_second < i_sc


def test_le_reste_du_fichier_est_intact():
    """Le manifeste garde ses commentaires et son ordre : on manipule du
    texte, pas un arbre YAML re-dumpé."""
    r = H.inserer(NU, cles=["allowPrivilegeEscalation"])
    for ligne in NU.split("\n"):
        if ligne.strip():
            assert ligne in r["texte"].split("\n")


def test_cle_hors_catalogue_refusee():
    r = H.inserer(NU, cles=["privileged"])
    assert r["ok"] is False and r["raison"] == "cle-inconnue"


def test_conteneur_absent_refuse():
    assert H.inserer(NU, index=9, cles=["seccompProfile"])["ok"] is False


# --------------------------------------------------------------- corps de PR
def test_corps_de_pr_explique_chaque_ajout():
    a = H.analyser(NU)
    body = H.pr_body("manifests/app/frontend/deployment.yaml", "frontend",
                     a["proposer"], a["issue"], a["deja_present"])
    assert "allowPrivilegeEscalation" in body
    assert "RuntimeDefault" in body
    assert "rescan-confirm" in body
    assert "arbitrage humain" in body


def test_corps_de_pr_dit_ce_qui_n_a_pas_ete_touche():
    a = H.analyser(AVEC_SC)
    body = H.pr_body("f.yaml", "bridge", a["proposer"], a["issue"],
                     a["deja_present"])
    assert "non touché" in body and "runAsNonRoot" in body

def test_inserer_apres_un_bloc_imbrique():
      """emailservice, 19/08 : la derniere cle du conteneur est livenessProbe,
      qui OUVRE un bloc. Inserer juste apres elle separe la sonde de ses
      enfants — le manifeste produit n'est plus applicable. Le point
      d'insertion doit etre la derniere LIGNE du conteneur, pas la derniere
      cle de meme niveau."""
      sp = " "
      t = "\n".join([
          "spec:",
          sp * 2 + "template:",
          sp * 4 + "spec:",
          sp * 6 + "containers:",
          sp * 8 + "- name: server",
          sp * 10 + "image: a:1",
          sp * 10 + "livenessProbe:",
          sp * 12 + "grpc:",
          sp * 14 + "port: 8080",
          sp * 12 + "timeoutSeconds: 5",
          "",
      ])
      r = H.inserer(t, cles=["allowPrivilegeEscalation"])
      assert r["ok"], r
      lignes = r["texte"].split("\n")
      i = [n for n, ln in enumerate(lignes) if ln.strip() == "securityContext:"][0]
      assert lignes[i - 1].strip() == "timeoutSeconds: 5"

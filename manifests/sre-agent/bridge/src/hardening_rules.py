#!/usr/bin/env python3
# =============================================================================
#  hardening_rules — le durcissement additif des conteneurs (phase E3).
# -----------------------------------------------------------------------------
#  C'est ici que vivent les ~80 findings HIGH de `trivy config` : securityContext
#  absent, capabilities non restreintes, seccomp par défaut. E1 savait remplacer
#  une valeur ; E3 doit INSÉRER une clé qui n'existe pas — machinerie neuve.
#
#  Le module DÉCIDE et FABRIQUE LE TEXTE. Il n'écrit rien : `remediation.py`
#  garde la main sur le dépôt, comme depuis le premier jour.
#
#  DÉCISIONS ENCAPSULÉES ICI :
#
#  1. ADDITIF STRICT, JAMAIS DE MODIFICATION. Si une clé existe déjà — même
#     avec une valeur dangereuse — on n'y touche pas. `allowPrivilegeEscalation:
#     true` peut être délibéré (un conteneur qui a besoin de setuid) ; le
#     retourner serait une décision, pas un durcissement. Ces cas partent en
#     ISSUE, avec la question posée à un humain.
#
#  2. ON N'ENTRE JAMAIS DANS UN BLOC EXISTANT. Si `capabilities:` ou
#     `seccompProfile:` sont déjà là, on ne fusionne pas dedans : on passe. Une
#     fusion YAML par manipulation de texte est une source d'erreurs sans
#     rapport avec le gain.
#
#  3. `capabilities.drop: [ALL]` DEMANDE DE REGARDER LES PORTS. Un conteneur
#     qui écoute sous 1024 a besoin de NET_BIND_SERVICE : lui retirer toutes
#     les capabilities le casse au démarrage. Le manifeste porte la réponse
#     (`containerPort`), donc on la lit — et en cas de port privilégié, on part
#     en issue plutôt que de deviner.
#
#  4. `runAsNonRoot` DEMANDE UNE PREUVE EXTÉRIEURE. Savoir si l'image tourne en
#     root n'est pas dans le manifeste : c'est dans la config de l'image. La
#     preuve est INJECTÉE par l'appelant (`image_non_root`) ; sans elle, issue.
#     On ne propose pas un correctif dont on ne peut pas prédire l'effet.
#
#  5. `readOnlyRootFilesystem` NE PART JAMAIS EN PR AUTOMATIQUE. Aucune lecture
#     statique ne dit où un programme écrit. Le bridge lui-même l'a montré : le
#     durcir a demandé un volume, et pas sur /tmp comme on l'aurait cru, mais
#     sur /state. Un correctif qui produit un CrashLoopBackOff n'est pas un
#     correctif — celui-là reste une issue, avec l'explication.
# =============================================================================
import re

# --- les cinq durcissements, et ce qu'il faut savoir avant de les proposer ---
# tier : "manifeste"  -> le fichier suffit à décider (PR)
#        "preuve"     -> demande une information extérieure (PR si fournie)
#        "humain"     -> demande un jugement (issue, toujours)
DURCISSEMENTS = {
    "allowPrivilegeEscalation": {
        "tier": "manifeste", "valeur": "false",
        "pourquoi": "empêche un processus d'obtenir plus de privilèges que son "
                    "parent (setuid, file capabilities)"},
    "seccompProfile": {
        "tier": "manifeste", "valeur": {"type": "RuntimeDefault"},
        "pourquoi": "applique le filtre d'appels système par défaut du "
                    "runtime, au lieu d'aucun filtre"},
    "capabilities": {
        "tier": "manifeste", "valeur": {"drop": '["ALL"]'},
        "pourquoi": "retire toutes les capabilities Linux ; le conteneur n'en "
                    "utilise aucune déclarée"},
    "runAsNonRoot": {
        "tier": "preuve", "valeur": "true",
        "pourquoi": "refuse le démarrage si l'image tourne en root"},
    "readOnlyRootFilesystem": {
        "tier": "humain", "valeur": "true",
        "pourquoi": "rend le système de fichiers immuable — mais exige un "
                    "volume pour chaque chemin où le programme écrit"},
}

PORT_PRIVILEGIE = 1024


def _ok(kind, detail, **extra):
    d = {"ok": True, "kind": kind, "detail": detail}
    d.update(extra)
    return d


def _ko(raison, detail, **extra):
    d = {"ok": False, "raison": raison, "detail": detail}
    d.update(extra)
    return d


# ---------------------------------------------------------------- lecture YAML
def _indent(ligne):
    return len(ligne) - len(ligne.lstrip(" "))


def bloc_conteneur(lignes, index=0):
    """(début, fin) du Nième conteneur dans une liste de lignes.

    Travail sur le TEXTE et non sur un arbre YAML : le dépôt doit garder ses
    commentaires et son ordre, qu'un dump YAML détruirait. C'est le même parti
    pris que `_apply()` dans remediation.py.
    """
    debut_liste = None
    indent_liste = 0
    for i, ligne in enumerate(lignes):
        if re.match(r"^\s*containers:\s*$", ligne):
            debut_liste = i
            indent_liste = _indent(ligne)
            break
    if debut_liste is None:
        return None
    items = []
    for i in range(debut_liste + 1, len(lignes)):
        ligne = lignes[i]
        if not ligne.strip() or ligne.lstrip().startswith("#"):
            continue
        ind = _indent(ligne)
        if ind <= indent_liste and ligne.strip():
            break                                   # fin de la liste
        if ind == indent_liste + 2 and ligne.lstrip().startswith("- "):
            items.append(i)
    if index >= len(items):
        return None
    debut = items[index]
    fin = len(lignes)
    for i in range(debut + 1, len(lignes)):
        ligne = lignes[i]
        if not ligne.strip():
            continue
        ind = _indent(ligne)
        if ind <= indent_liste or (ind == indent_liste + 2
                                   and ligne.lstrip().startswith("- ")):
            fin = i
            break
    return (debut, fin)


def cles_existantes(lignes, debut, fin, indent_cle):
    """Clés déjà présentes sous `securityContext:` du conteneur, ou None si le
    bloc n'existe pas du tout."""
    for i in range(debut, fin):
        if re.match(rf"^{' ' * indent_cle}securityContext:\s*$", lignes[i]):
            trouvees = []
            for j in range(i + 1, fin):
                if not lignes[j].strip():
                    continue
                if _indent(lignes[j]) <= indent_cle:
                    break
                if _indent(lignes[j]) == indent_cle + 2:
                    m = re.match(r"^\s*([A-Za-z][A-Za-z0-9]*):", lignes[j])
                    if m:
                        trouvees.append(m.group(1))
            return {"ligne": i, "cles": trouvees}
    return None


def ports_declares(lignes, debut, fin):
    return [int(m.group(1)) for m in
            (re.match(r"^\s*-?\s*containerPort:\s*(\d+)", ln)
             for ln in lignes[debut:fin]) if m]


# ------------------------------------------------------------------- décision
def analyser(texte, index=0, image_non_root=None):
    """Que peut-on durcir sur ce conteneur, et que faut-il envoyer en issue ?

    `image_non_root` : True/False/None — la preuve extérieure (décision n° 4).
    Fonction PURE : aucun I/O, aucune écriture.
    """
    lignes = texte.split("\n")
    bornes = bloc_conteneur(lignes, index)
    if not bornes:
        return _ko("conteneur-introuvable",
                   f"aucun conteneur d'index {index} dans ce manifeste")
    debut, fin = bornes
    indent_cle = _indent(lignes[debut]) + 2
    sc = cles_existantes(lignes, debut, fin, indent_cle)
    deja = set(sc["cles"]) if sc else set()
    ports = ports_declares(lignes, debut, fin)
    prives = [p for p in ports if p < PORT_PRIVILEGIE]

    a_proposer, en_issue = [], []
    for nom, regle in DURCISSEMENTS.items():
        if nom in deja:
            # Décision n° 1 et n° 2 : présent = on ne touche pas.
            continue
        if regle["tier"] == "humain":
            en_issue.append((nom, "demande de savoir où le programme écrit : "
                                  "aucune lecture statique ne le dit"))
            continue
        if regle["tier"] == "preuve":
            if image_non_root is True:
                a_proposer.append(nom)
            elif image_non_root is False:
                en_issue.append((nom, "l'image tourne en root : la corriger "
                                      "demande de changer l'image, pas le "
                                      "manifeste"))
            else:
                en_issue.append((nom, "impossible de prouver que l'image ne "
                                      "tourne pas en root"))
            continue
        if nom == "capabilities" and prives:
            en_issue.append((nom, f"le conteneur écoute sur {prives} (< "
                                  f"{PORT_PRIVILEGIE}) : retirer toutes les "
                                  f"capabilities lui ôterait NET_BIND_SERVICE "
                                  f"et il ne démarrerait plus"))
            continue
        a_proposer.append(nom)

    return _ok("analyse",
               f"{len(a_proposer)} durcissement(s) proposable(s), "
               f"{len(en_issue)} à arbitrer",
               proposer=a_proposer, issue=en_issue,
               deja_present=sorted(deja), ports=ports,
               bloc_existant=bool(sc), bornes=(debut, fin),
               indent=indent_cle)


# ------------------------------------------------------------- fabrication
def _rendu(nom, indent):
    """Les lignes YAML d'un durcissement, à l'indentation demandée."""
    valeur = DURCISSEMENTS[nom]["valeur"]
    p = " " * indent
    if isinstance(valeur, dict):
        lignes = [f"{p}{nom}:"]
        for k, v in valeur.items():
            lignes.append(f"{p}  {k}: {v}")
        return lignes
    return [f"{p}{nom}: {valeur}"]


def inserer(texte, index=0, cles=None):
    """Ajoute les durcissements demandés et rend le NOUVEAU texte.

    Idempotent : une clé déjà présente n'est jamais réécrite (décision n° 1).
    Rend {ok, texte, ajoutees} ou {ok: False, raison}.
    """
    cles = list(cles or [])
    if not cles:
        return _ko("rien-a-faire", "aucune clé demandée")
    inconnues = [c for c in cles if c not in DURCISSEMENTS]
    if inconnues:
        return _ko("cle-inconnue",
                   f"hors catalogue de durcissement : {inconnues}")

    lignes = texte.split("\n")
    bornes = bloc_conteneur(lignes, index)
    if not bornes:
        return _ko("conteneur-introuvable", f"index {index} absent")
    debut, fin = bornes
    indent_cle = _indent(lignes[debut]) + 2
    sc = cles_existantes(lignes, debut, fin, indent_cle)
    deja = set(sc["cles"]) if sc else set()
    a_ajouter = [c for c in cles if c not in deja]
    if not a_ajouter:
        return _ko("deja-present",
                   f"toutes les clés demandées sont déjà là : {sorted(deja)}")

    nouvelles = []
    for nom in a_ajouter:
        nouvelles.extend(_rendu(nom, indent_cle + 2))

    if sc:
        point = sc["ligne"] + 1          # juste sous `securityContext:`
    else:
        # Pas de bloc : on le crée en fin de conteneur, après la dernière clé
        # de même niveau — jamais au milieu d'une sous-liste.
        point = fin
        for i in range(fin - 1, debut, -1):
            if lignes[i].strip() and _indent(lignes[i]) == indent_cle:
                point = i + 1
                break
        nouvelles = [f"{' ' * indent_cle}securityContext:"] + nouvelles

    resultat = lignes[:point] + nouvelles + lignes[point:]
    return _ok("insere", f"{len(a_ajouter)} clé(s) ajoutée(s)",
               texte="\n".join(resultat), ajoutees=a_ajouter)


# --------------------------------------------------------------- corps de PR
def pr_body(fichier, conteneur, ajoutees, en_issue=None, deja=None):
    """Ce que l'humain lit avant de merger un durcissement."""
    lignes = [f"## 🛡️ Durcissement de `{conteneur}` — {fichier}", "",
              "Ajouts **strictement additifs** : aucune valeur existante n'est "
              "modifiée.", "", "| Clé ajoutée | Valeur | Pourquoi |", "|---|---|---|"]
    for nom in ajoutees:
        r = DURCISSEMENTS[nom]
        v = r["valeur"]
        v = (", ".join(f"{k}: {x}" for k, x in v.items())
             if isinstance(v, dict) else v)
        lignes.append(f"| `{nom}` | `{v}` | {r['pourquoi']} |")
    if deja:
        lignes += ["", f"_Déjà présent, non touché : "
                       f"{', '.join('`' + d + '`' for d in deja)}._"]
    if en_issue:
        lignes += ["", "### Non proposé ici — arbitrage humain nécessaire", ""]
        for nom, raison in en_issue:
            lignes.append(f"- **`{nom}`** : {raison}")
    lignes += ["", "**Vérification après merge** : le pod redémarre et reste "
                   "`Ready` ; puis rescan `trivy config` — le finding doit "
                   "avoir disparu (rescan-confirm).", ""]
    return "\n".join(lignes)

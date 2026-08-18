#!/usr/bin/env python3
# =============================================================================
#  security_rules — les règles de correction sécurité de l'agent (phase E1).
# -----------------------------------------------------------------------------
#  La phase D a appris à l'agent CE QUI COMPTE (EPSS, CISA KEV, contexte
#  d'exécution). E1 lui apprend le premier geste correctif : changer une
#  référence d'image — soit pour la BUMPER vers une version qui corrige une
#  CVE, soit pour l'ÉPINGLER quand elle flotte.
#
#  Ce module ne touche à rien. Il DÉCIDE, et rien d'autre : chaque fonction est
#  pure et rend un verdict motivé. `remediation.py` garde seule la main sur
#  l'écriture, comme avant. Même découpage qu'en phase D — et pour la même
#  raison : ce qui décide doit être testable sans réseau, sans dépôt, sans
#  cluster.
#
#  DÉCISIONS ENCAPSULÉES ICI :
#
#  1. L'AGENT NE TOUCHE PAS À CE QUI LE CONTRÔLE. Deux répertoires sont refusés
#     AVANT toute autre vérification : `manifests/sre-agent/**` (ses propres
#     garde-fous) et `.github/**` (les workflows qui font tourner les six checks
#     requis sur SES pull requests). Le second est le moins évident et le plus
#     dangereux : une PR intitulée « réduire les permissions du workflow »
#     pourrait désarmer le gate qui contrôle les propositions de l'agent, et
#     elle aurait l'air d'une amélioration. Ce ne sont pas des omissions qu'on
#     pourrait « corriger » un jour : ce sont des règles, avec leurs tests.
#
#  2. JAMAIS DE MAJEUR, JAMAIS D'AUTRE IMAGE. Un bump majeur part en issue, pas
#     en PR. Et le dépôt/registre ne change JAMAIS : bumper `frontend` vers une
#     autre image serait une substitution de charge déguisée en mise à jour.
#
#  3. LES BASES DE DONNÉES : JAMAIS DE MAJEUR, ET UN AVERTISSEMENT SUR LE
#     RESTE. Le format sur disque d'une base suit son MAJEUR : postgres 16 -> 17
#     migre, 16.4 -> 16.5 non. Une première version de cette règle interdisait
#     tout sauf le patch — elle aurait bloqué `postgres 16.4 -> 16.5`, qui est
#     précisément le correctif de sécurité qu'on veut automatiser. La règle
#     juste : le majeur part en issue (comme partout), et tout bump de base
#     porte un AVERTISSEMENT de sauvegarde dans le corps de la PR. On signale
#     ce qu'on ne peut pas vérifier, au lieu de l'interdire à tort.
#
#  4. ON N'ENLÈVE JAMAIS D'ÉPINGLAGE. Si l'ancienne référence portait un
#     digest, la nouvelle doit en porter un. Sinon le bump ferait reculer la
#     chaîne de signature construite en phases A et B — un correctif de
#     sécurité qui affaiblit la sécurité.
#
#  5. UN TAG FLOTTANT EST UN DÉFAUT, PAS UNE VERSION. `latest` n'est pas
#     comparable : on ne « bumpe » pas depuis `latest`, on l'ÉPINGLE. Les deux
#     opérations sont distinctes et rendues comme telles (`kind`).
# =============================================================================
import re

# --------------------------------------------------------------------- refus
# Vérifié en PREMIER, avant toute allow-list (décision n° 1).
DENIED_FILES = (
    # les garde-fous de l'agent
    re.compile(r"^manifests/sre-agent/"),
    # les gates qui contrôlent ses PRs — zizmor et Renovate s'en occupent
    # déjà, l'agent n'a aucune raison d'y toucher
    re.compile(r"^\.github/"),
)

# --------------------------------------------------------------- autorisés
ALLOWED_FILES_SEC = (
    # les charges applicatives (Online Boutique)
    re.compile(r"^manifests/app/[a-z0-9-]+/deployment\.yaml$"),
    re.compile(r"^manifests/app/patches/[a-z0-9.-]+\.yaml$"),
    # la plateforme d'observabilité — chart Helm, les images vivent dans les
    # values. `litmus-values.yaml` est VOLONTAIREMENT exclu : il a porté des
    # credentials (dette B7), on ne laisse pas une PR automatique s'en
    # approcher.
    re.compile(r"^manifests/monitoring/values\.yaml$"),
)

ALLOWED_PATHS_SEC = (
    # référence complète d'un conteneur (manifestes k8s)
    re.compile(r"^spec\.template\.spec\.containers\[\d\]\.image$"),
    # tag d'image dans un values.yaml Helm (`grafana.image.tag`, …)
    re.compile(r"^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+){0,3}\.image\.tag$"),
)

# --------------------------------------------------------------- références
# registry/repository:tag@sha256:...   (registry et tag optionnels)
REF_RE = re.compile(
    r"^(?P<repo>[a-z0-9][a-z0-9._/-]*[a-z0-9])"
    r"(?::(?P<tag>[A-Za-z0-9][A-Za-z0-9._-]*))?"
    r"(?:@(?P<digest>sha256:[0-9a-f]{64}))?$")

# v1.2.3, 1.2.3, 1.2, 1.2.3-alpine, 16.4-alpine3.20 …
SEMVER_RE = re.compile(
    r"^v?(?P<maj>\d+)(?:\.(?P<min>\d+))?(?:\.(?P<pat>\d+))?"
    r"(?P<suffix>[-.][A-Za-z0-9._-]+)?$")

FLOATING = ("latest", "stable", "main", "master", "edge", "dev", "nightly",
            "release", "prod", "current")

# Le format sur disque suit le MAJEUR (decision n° 3) : le majeur est refuse
# comme partout, et le reste part avec un avertissement de sauvegarde. La liste
# porte le NOM D'IMAGE, pas le produit.
DATABASE_IMAGES = (
    "postgres", "postgresql", "timescaledb", "mysql", "mariadb", "percona",
    "mongo", "mongodb", "redis", "valkey", "memcached", "etcd", "cassandra",
    "elasticsearch", "opensearch", "clickhouse", "influxdb", "cockroachdb",
    "neo4j", "qdrant", "couchdb", "rabbitmq", "kafka", "zookeeper",
)


def _ok(kind, detail, warn=None):
    return {"ok": True, "kind": kind, "detail": detail, "warn": warn}


def _ko(reason, detail):
    return {"ok": False, "reason": reason, "detail": detail}


def file_allowed(path):
    """Un chemin de fichier est-il modifiable par l'agent ?

    Refus d'abord, autorisation ensuite. L'ordre compte : si un jour une
    entrée d'allow-list devenait trop large, le refus resterait.
    """
    for deny in DENIED_FILES:
        if deny.search(path):
            return _ko("file-denied",
                       f"« {path} » appartient à l'agent lui-même : il ne "
                       f"modifie pas ses propres garde-fous")
    for allow in ALLOWED_FILES_SEC:
        if allow.match(path):
            return _ok("file", path)
    return _ko("file-not-allowed", f"« {path} » hors allow-list sécurité")


def path_allowed(dotted):
    for allow in ALLOWED_PATHS_SEC:
        if allow.match(dotted):
            return _ok("path", dotted)
    return _ko("path-not-allowed", f"« {dotted} » hors allow-list sécurité")


def parse_ref(ref):
    """« ghcr.io/org/app:1.2.3@sha256:… » -> ses morceaux, ou None."""
    m = REF_RE.match((ref or "").strip())
    if not m:
        return None
    return {"repo": m.group("repo"), "tag": m.group("tag"),
            "digest": m.group("digest")}


def is_floating(tag):
    """Un tag qui ne désigne pas un contenu : absent, ou mouvant."""
    if not tag:
        return True
    return tag.lower().split("-")[0] in FLOATING


def is_database(repo):
    """Le dernier segment du dépôt est-il une base de données connue ?"""
    name = (repo or "").rsplit("/", 1)[-1].lower()
    return name in DATABASE_IMAGES


def _version(tag):
    m = SEMVER_RE.match(tag or "")
    if not m:
        return None
    return (int(m.group("maj")), int(m.group("min") or 0),
            int(m.group("pat") or 0), m.group("suffix") or "")


def classify_bump(old_tag, new_tag):
    """patch | minor | major | downgrade | same | suffix | unknown."""
    o, n = _version(old_tag), _version(new_tag)
    if o is None or n is None:
        return "unknown"
    if n[:3] == o[:3]:
        # meme version, variante differente (1.2.3 -> 1.2.3-alpine) : ce n'est
        # pas une mise a jour de securite, c'est un changement de base.
        return "same" if n[3] == o[3] else "suffix"
    if n[:3] < o[:3]:
        return "downgrade"
    if n[0] != o[0]:
        return "major"
    if n[1] != o[1]:
        return "minor"
    return "patch"


def check_image_change(old, new):
    """La règle centrale : ce changement de référence est-il proposable ?

    Rend {ok, kind, detail} ou {ok: False, reason, detail}. `kind` vaut
    « pin » (on épingle un tag flottant) ou « bump-patch » / « bump-minor ».
    """
    o, n = parse_ref(old), parse_ref(new)
    if not o or not n:
        return _ko("ref-illisible",
                   f"référence non conforme : « {old} » -> « {new} »")
    if old.strip() == new.strip():
        return _ko("no-op", "l'ancienne et la nouvelle référence sont égales")

    # Décision n° 2 : on ne change jamais l'image, seulement sa version.
    if o["repo"] != n["repo"]:
        return _ko("repo-change",
                   f"le dépôt change ({o['repo']} -> {n['repo']}) : ce n'est "
                   f"pas une mise à jour, c'est une substitution de charge")

    # Décision n° 4 : on n'enlève jamais un épinglage.
    if o["digest"] and not n["digest"]:
        return _ko("digest-perdu",
                   "l'ancienne référence portait un digest, pas la nouvelle : "
                   "un correctif ne doit pas affaiblir la chaîne de signature")

    # Décision n° 5 : depuis un tag flottant, on ÉPINGLE, on ne bumpe pas.
    if is_floating(o["tag"]):
        if is_floating(n["tag"]):
            return _ko("toujours-flottant",
                       f"« {n['tag'] or '(aucun tag)'} » ne désigne pas un "
                       f"contenu : épingler une version concrète")
        if _version(n["tag"]) is None:
            return _ko("tag-non-versionne",
                       f"« {n['tag']} » n'est pas une version reconnaissable")
        return _ok("pin", f"tag flottant « {o['tag'] or '(aucun)'} » épinglé "
                          f"sur « {n['tag']} »")

    niveau = classify_bump(o["tag"], n["tag"])
    if niveau == "unknown":
        return _ko("version-illisible",
                   f"versions non comparables : {o['tag']} -> {n['tag']}")
    if niveau == "downgrade":
        return _ko("downgrade",
                   f"retour en arrière {o['tag']} -> {n['tag']} : jamais "
                   f"automatiquement")
    if niveau == "same":
        # seul le digest a change : rebuild amont de la meme version.
        if o["digest"] and n["digest"] and o["digest"] != n["digest"]:
            return _ok("bump-digest",
                       f"même version {n['tag']}, digest rafraîchi")
        return _ko("no-op", "aucun changement de version ni de digest")
    if niveau == "suffix":
        return _ko("variante",
                   f"changement de variante ({o['tag']} -> {n['tag']}) : "
                   f"c'est un changement de base, pas un correctif")
    if niveau == "major":
        return _ko("major",
                   f"bump MAJEUR {o['tag']} -> {n['tag']} : issue GitHub, "
                   f"jamais de PR automatique")
    warn = None
    if is_database(o["repo"]):
        # Ni blocage ni silence : on signale ce que l'agent ne peut pas
        # verifier lui-meme (decision n° 3).
        warn = (f"« {o['repo'].rsplit('/', 1)[-1]} » est une base de données : "
                f"vérifier qu'une sauvegarde récente existe avant de merger. "
                f"Le format sur disque suit le majeur ({o['tag']} et "
                f"{n['tag']} le partagent), mais l'agent ne peut pas le "
                f"garantir pour une image tierce.")
    return _ok(f"bump-{niveau}", f"{o['tag']} -> {n['tag']} ({niveau})", warn)


# ------------------------------------------------------------- corps de PR
def pr_body(image_old, image_new, verdict, deployment=None, namespace=None,
            degraded=None, warn=None):
    """Le corps de la PR : ce que l'humain lit avant de merger.

    La différence avec une PR Renovate tient dans ce tableau : Renovate dit
    « une version plus récente existe », l'agent dit « voici POURQUOI celle-ci
    est urgente », avec ses sources.
    """
    v = verdict or {}
    lignes = [f"## 🔐 {v.get('cve', 'correctif sécurité')} — "
              f"{deployment or 'charge'} {image_old.split(':')[-1]} → "
              f"{image_new.split(':')[-1]}", ""]
    lignes += ["| Signal | Valeur |", "|---|---|"]
    epss = v.get("epss")
    if epss is not None:
        pct = v.get("epss_percentile")
        lignes.append(f"| EPSS | **{epss:.5f}**"
                      + (f" (percentile {pct:.1%})" if pct is not None else "")
                      + " |")
    else:
        lignes.append("| EPSS | aucun score (CVE trop récente ou non scorée) |")
    lignes.append("| CISA KEV | "
                  + ("✅ **exploitée en réel**" if v.get("kev") else "non")
                  + (" — campagnes de rançongiciel"
                     if v.get("kev_ransomware") else "") + " |")
    lignes.append(f"| Charge | `{namespace or '?'}/{deployment or '?'}` — "
                  + ("**en service**" if v.get("running")
                     else "plus en service" if v.get("running") is False
                     else "état inconnu") + " |")
    lignes.append("| Exposition | "
                  + ("hors du cluster" if v.get("exposed")
                     else "interne au cluster") + " |")
    lignes.append(f"| Priorité | **{v.get('priorite', '?')}** |")
    lignes += ["", f"**Justification** : {v.get('justification', '—')}", ""]
    lignes.append(f"**Correctif** : `{image_old}` → `{image_new}`")
    if warn:
        lignes += ["", f"> ⚠️ **À vérifier avant de merger** : {warn}", ""]
    lignes += ["", "**Vérification après merge** : rescan StackRox — la CVE "
                   "doit avoir disparu de l'image (rescan-confirm).", ""]
    src = "EPSS (FIRST.org), CISA KEV, API Central"
    if degraded:
        lignes.append(f"> ⚠️ Tri **dégradé** : {', '.join(degraded)} "
                      f"indisponible(s) au moment de l'analyse. En l'absence "
                      f"de contexte, la priorité n'est jamais abaissée.")
    else:
        lignes.append(f"_Sources du verdict : {src}. Aucune source dégradée._")
    return "\n".join(lignes)

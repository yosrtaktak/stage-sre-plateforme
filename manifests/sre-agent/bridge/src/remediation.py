# -*- coding: utf-8 -*-
"""B1 — Remediation-as-PR (module du bridge, stdlib uniquement).

Transforme un correctif durable de type manifeste, émis par l'agent dans un
bloc machine-parsable (PATCH_PROPOSAL / ROLLBACK_PROPOSAL en fin de
diagnostic), en pull request GitHub sur la branche de base. L'agent ne peut
structurellement PAS merger : la protection de branche (require PR + status
check validate-manifests) laisse la décision à l'humain.

Sécurité — dans CET ordre, l'allow-list AVANT tout appel réseau :
 1. parse strict du bloc (regex, un seul bloc) ;
 2. allow-list EN DUR (fichiers + chemins YAML + forme des valeurs) — jamais
    dans le prompt : un LLM ne peut pas désobéir à du code. Tout refus est
    journalisé/compté par le bridge, le correctif reste une recommandation
    Slack ;
 3. vérification que la valeur actuelle sur la branche de base == `old`
    annoncé (l'agent raisonne parfois sur un état périmé -> abandon) ;
 4. seulement alors, les appels REST (urllib) : ref -> branche -> commit(s)
    -> PR -> labels.

Le YAML est modifié par navigation d'indentation (pas de PyYAML dans
python:slim) : recherche déterministe de LA ligne du scalaire ciblé ; toute
ambiguïté (clé en double, chemin introuvable, ligne non triviale) => refus.
On ne modifie que des valeurs scalaires sur des lignes existantes — jamais
de restructuration du fichier. 05/08 : un bloc peut porter jusqu'à
MAX_CHANGES (5) changements, TOUS dans le même fichier, en répétant le
quadruplet path/old/new/reason — chaque ligne du diff a SA justification,
reprise dans un tableau du corps de la PR. Chaque changement passe
individuellement l'allow-list, les bornes et le stale-old.
"""
import base64
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

import findings_ledger
import hardening_rules
import security_rules

# E2 : le registre est charge une fois, au demarrage du module. Il vit sur le
# PVC /state — un registre qui s'oublie au premier restart ne protege de rien.
findings_ledger.charger()

API = "https://api.github.com"
# Secret github-remediation monté en fichiers (clés : token, repo, base).
GH_DIR = os.environ.get("GITHUB_SECRET_DIR", "/etc/github")

# ---------------------------------------------------------------------------
#  Allow-list — LE cœur de la sécurité. En dur, jamais dérivée du prompt.
# ---------------------------------------------------------------------------
ALLOWED_FILES = (
    re.compile(r"^manifests/app/[a-z0-9-]+/deployment\.yaml$"),
    re.compile(r"^manifests/app/patches/[a-z0-9.-]+\.yaml$"),
    # E1 (18/08) : la plateforme d'observabilite est un chart Helm, les images
    # y vivent dans les values. `litmus-values.yaml` reste VOLONTAIREMENT hors
    # perimetre : il a porte des credentials (dette B7).
    re.compile(r"^manifests/monitoring/values\.yaml$"),
)
ALLOWED_PATHS = (
    re.compile(r"^spec\.template\.spec\.containers\[\d\]\."
               r"(livenessProbe|readinessProbe|startupProbe)\."
               r"(initialDelaySeconds|periodSeconds|timeoutSeconds"
               r"|failureThreshold|successThreshold)$"),
    re.compile(r"^spec\.template\.spec\.containers\[\d\]\."
               r"resources\.(requests|limits)\."
               r"(cpu|memory|ephemeral-storage)$"),
    re.compile(r"^spec\.replicas$"),
    re.compile(r"^spec\.template\.spec\.terminationGracePeriodSeconds$"),
    re.compile(r"^spec\.strategy\.rollingUpdate\.(maxSurge|maxUnavailable)$"),
    re.compile(r"^spec\.progressDeadlineSeconds$"),
    # E1 (18/08) : la reference d'image. La FORME de la valeur n'est pas
    # verifiee ici mais dans security_rules.check_image_change() — semver,
    # majeur interdit, digest jamais perdu, depot jamais change.
    re.compile(r"^spec\.template\.spec\.containers\[\d\]\.image$"),
    re.compile(r"^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+){0,3}\.image\.tag$"),
)
# Scalaires k8s simples uniquement : entiers, cpu (500m), mémoire (128Mi).
VALUE_RE = re.compile(r"^[0-9]+(m|Ki|Mi|Gi)?$")
# maxSurge/maxUnavailable acceptent aussi les pourcentages ("25%").
PCT_RE = re.compile(r"^([0-9]{1,3})(%)?$")
# Planchers absolus des ressources (05/08) : en dessous, le conteneur ne peut
# tout simplement pas fonctionner — un sous-dimensionnement brutal crashe le
# service aussi sûrement qu'un OOM.
RESOURCE_FLOORS = {"cpu": 0.01, "memory": 16 * 1024.0 ** 2,
                   "ephemeral-storage": 16 * 1024.0 ** 2}


def _qty_units(v):
    """Quantité k8s -> unité comparable (cpu en cores, mémoire en octets)."""
    m = re.match(r"^([0-9]+)(m|Ki|Mi|Gi)?$", v)
    if not m:
        return None
    n, u = int(m.group(1)), m.group(2)
    return {None: float(n), "m": n / 1000.0, "Ki": n * 1024.0,
            "Mi": n * 1024.0 ** 2, "Gi": n * 1024.0 ** 3}[u]


def _check_values(path, old, new):
    """Forme des DEUX valeurs + bornes sur `new` seulement : `old` est l'état
    courant (possiblement hors bornes — c'est ce qu'on corrige)."""
    field = path.split(".")[-1]
    if field in ("maxSurge", "maxUnavailable"):
        # rollout : jamais de bascule brutale — 100% couperait tout le service
        if not (PCT_RE.match(old) and PCT_RE.match(new)):
            raise _Reject("value-not-allowed")
        n, pct = PCT_RE.match(new).groups()
        n = int(n)
        if pct and not 1 <= n <= 50:
            raise _Reject(f"value-out-of-bounds({new}, 1-50%)")
        if not pct and not 0 <= n <= 5:
            raise _Reject(f"value-out-of-bounds({new}, 0-5)")
    elif field == "progressDeadlineSeconds":
        if not (old.isdigit() and new.isdigit()):
            raise _Reject("value-not-allowed")
        if not 60 <= int(new) <= 1200:
            raise _Reject(f"value-out-of-bounds({new}, 60-1200s)")
    elif field == "replicas":
        # 05/08 : jamais 0 (extinction du service via une PR plausible) ni
        # d'emballement — la garde de capacité du bridge borne déjà le haut
        # par la mesure, ceci est le garde-fou statique.
        if not (old.isdigit() and new.isdigit()):
            raise _Reject("value-not-allowed")
        if not 1 <= int(new) <= 5:
            raise _Reject(f"value-out-of-bounds({new}, 1-5)")
    elif field in ("cpu", "memory", "ephemeral-storage"):
        if not (VALUE_RE.match(old) and VALUE_RE.match(new)):
            raise _Reject("value-not-allowed")
        o, n = _qty_units(old), _qty_units(new)
        # 05/08 : une BAISSE ne va jamais plus loin que la moitié, ni sous le
        # plancher absolu. (Une réduction légitime plus forte reste possible
        # pour l'humain — mais pas via une PR automatique de l'agent.)
        if n < o and (n < o / 2 or n < RESOURCE_FLOORS[field]):
            raise _Reject(
                f"value-out-of-bounds({new}, baisse max 50% de {old} "
                f"et >= plancher)")
    elif field in ("image", "tag"):
        # E1 : VALUE_RE ne sait lire que des scalaires k8s (128Mi, 500m). Une
        # reference d'image a ses propres regles, et elles sont ailleurs pour
        # rester testables sans depot ni cluster.
        verdict = security_rules.check_image_change(old, new)
        if not verdict["ok"]:
            raise _Reject(f"image-{verdict['reason']}: {verdict['detail']}")
    else:
        if not (VALUE_RE.match(old) and VALUE_RE.match(new)):
            raise _Reject("value-not-allowed")

# 05/08 : le bloc accepte 1 à MAX_CHANGES quadruplets path/old/new/reason —
# l'ancien format mono-changement est un cas particulier (1 quadruplet).
MAX_CHANGES = 5
PATCH_RE = re.compile(
    r"PATCH_PROPOSAL:\s*\n"
    r"\s*file:\s*(?P<file>\S+)\s*\n"
    r"(?P<changes>(?:\s*(?:path|old|new|reason):[ \t]*[^\n]*\n?)+)")
CHANGE_RE = re.compile(
    r"path:\s*(?P<path>\S+)\s*\n"
    r"\s*old:\s*(?P<old>\S+)\s*\n"
    r"\s*new:\s*(?P<new>\S+)\s*\n"
    r"\s*reason:\s*(?P<reason>[^\n]+)")
# E3 : le durcissement additif. Pas de old/new — on nomme les cles a AJOUTER,
# et hardening_rules refuse tout ce qui n'est pas strictement additif.
HARDEN_RE = re.compile(
    r"HARDEN_PROPOSAL:\s*\n"
    r"\s*file:\s*(?P<file>\S+)\s*\n"
    r"\s*container:\s*(?P<container>\d+)\s*\n"
    r"\s*keys:\s*(?P<keys>[A-Za-z0-9, \t]+)")

ROLLBACK_RE = re.compile(
    r"ROLLBACK_PROPOSAL:\s*\n"
    r"\s*commit:\s*(?P<commit>[0-9a-f]{7,40})\s*\n"
    r"\s*reason:\s*(?P<reason>[^\n]+)")


def parse_patch(analysis):
    """(file, [(path, old, new, reason), ...]) ou None. Parseur UNIQUE,
    utilisé aussi par les gardes du bridge (capacité, cohérence, dédup par
    cible) — une seule interprétation du bloc pour tout le monde."""
    m = PATCH_RE.search(analysis)
    if not m:
        return None
    changes = [(c.group("path"), c.group("old"), c.group("new"),
                c.group("reason").strip())
               for c in CHANGE_RE.finditer(m.group("changes"))]
    return (m.group("file"), changes)


class _Reject(Exception):
    """Refus contrôlé : la raison remonte au bridge (log + métrique), le
    correctif reste une recommandation Slack. Jamais d'appel réseau après."""


def enabled():
    return os.path.exists(f"{GH_DIR}/token")


def _cfg(name):
    with open(f"{GH_DIR}/{name}") as f:
        return f.read().strip()


def _gh(method, path, body=None, token=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        API + path, data=data, method=method,
        headers={"Authorization": f"Bearer {token}",
                 "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28",
                 "User-Agent": "sre-agent-bridge",
                 "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode(errors="replace")[:200]
        except Exception:
            pass
        raise RuntimeError(f"GitHub {method} {path} -> {e.code} {detail}") from e


# ---------------------------------------------------------------------------
#  Navigation YAML par indentation (sous-ensemble k8s : mappings + listes)
# ---------------------------------------------------------------------------
def _indent(line):
    return len(line) - len(line.lstrip(" "))


def _tokens(dotted):
    toks = []
    for part in dotted.split("."):
        m = re.match(r"^([A-Za-z][A-Za-z0-9_-]*)(?:\[(\d+)\])?$", part)
        if not m:
            return None
        toks.append(m.group(1))
        if m.group(2) is not None:
            toks.append(int(m.group(2)))
    return toks


def _locate(lines, toks, lo, hi):
    """Index de la ligne portant le scalaire final du chemin, ou None si
    introuvable/ambigu (l'appelant refuse — jamais de meilleure supposition)."""
    indent = None
    for i in range(lo, hi):
        s = lines[i].strip()
        if s and not s.startswith("#"):
            indent = _indent(lines[i])
            break
    if indent is None:
        return None
    for pos, tok in enumerate(toks):
        if isinstance(tok, int):
            # éléments « - » les moins indentés du bloc courant
            item_indent, items = None, []
            for i in range(lo, hi):
                s = lines[i].strip()
                if (s.startswith("- ") or s == "-"):
                    ind = _indent(lines[i])
                    if item_indent is None or ind < item_indent:
                        item_indent = ind
            if item_indent is None:
                return None
            for i in range(lo, hi):
                s = lines[i].strip()
                if (s.startswith("- ") or s == "-") \
                        and _indent(lines[i]) == item_indent:
                    items.append(i)
            if tok >= len(items):
                return None
            lo = items[tok]
            hi = items[tok + 1] if tok + 1 < len(items) else hi
            indent = item_indent + 2
        else:
            hit = None
            for i in range(lo, hi):
                line = lines[i]
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                ind = _indent(line)
                body = s
                if s.startswith("- "):        # 1re clé inline d'un item
                    ind += 2
                    body = s[2:].strip()
                if ind != indent:
                    continue
                if body == f"{tok}:" or body.startswith(f"{tok}: "):
                    if hit is not None:
                        return None           # clé en double : ambigu
                    hit = i
            if hit is None:
                return None
            if pos == len(toks) - 1:
                return hit
            key_ind = _indent(lines[hit]) \
                + (2 if lines[hit].strip().startswith("- ") else 0)
            lo2 = hit + 1
            hi2, nxt = lo2, None
            while hi2 < hi:
                s2 = lines[hi2].strip()
                if not s2 or s2.startswith("#"):
                    hi2 += 1
                    continue
                i2 = _indent(lines[hi2])
                # fin du bloc enfant : dé-indentation, ou clé sœur au même
                # niveau (les items « - » au même niveau restent DANS le bloc)
                if i2 < key_ind or (i2 == key_ind
                                    and not s2.startswith("- ")):
                    break
                if nxt is None:
                    nxt = i2 + (2 if s2.startswith("- ") else 0)
                hi2 += 1
            if nxt is None:
                return None
            lo, hi, indent = lo2, hi2, nxt
    return None


def _apply(text, dotted, old, new):
    """Remplace le scalaire à `dotted` (valeur attendue `old`) par `new`.
    Diff d'une seule ligne, ou _Reject."""
    toks = _tokens(dotted)
    if toks is None:
        raise _Reject("path-unparsable")
    lines = text.split("\n")
    # documents séparés par --- : le chemin doit matcher dans UN seul
    bounds, start = [], 0
    for i, ln in enumerate(lines):
        if ln.strip() == "---":
            bounds.append((start, i))
            start = i + 1
    bounds.append((start, len(lines)))
    hits = [h for lo, hi in bounds
            if (h := _locate(lines, toks, lo, hi)) is not None]
    if len(hits) != 1:
        raise _Reject("yaml-ambiguous" if hits else "yaml-path-not-found")
    i = hits[0]
    m = re.match(r"""^(\s*(?:- )?[A-Za-z0-9_-]+:[ \t]+)(["']?)"""
                 r"""([^#"']*?)\2([ \t]*(?:#.*)?)$""", lines[i])
    if not m:
        raise _Reject("yaml-line-unparsable")
    if m.group(3).strip() != old:
        # l'agent raisonne sur un état périmé : abandon (vérification n°3)
        raise _Reject(f"stale-old(actuel={m.group(3).strip()})")
    lines[i] = f"{m.group(1)}{new}{m.group(4)}"
    return "\n".join(lines)


# ---------------------------------------------------------------------------
#  Construction des changements (patch / rollback)
# ---------------------------------------------------------------------------
def _build_patch(parsed, repo, base, token):
    """05/08 : 1 à MAX_CHANGES changements dans le MÊME fichier. Chaque
    changement passe l'allow-list, les bornes et le stale-old ; le diff fait
    exactement len(changes) lignes ; le corps de la PR justifie CHAQUE ligne
    (tableau chemin/avant/après/preuve)."""
    f, changes = parsed
    if not changes:
        raise _Reject("patch-unparsable")
    if len(changes) > MAX_CHANGES:
        raise _Reject(f"too-many-changes({len(changes)}, max {MAX_CHANGES})")
    # E1 : le REFUS passe avant l'allow-list, et il est ecrit a part. Si une
    # entree d'allow-list devenait trop large un jour, celui-ci tiendrait.
    # L'agent ne modifie pas ses propres garde-fous.
    denied = security_rules.file_allowed(f)
    if not denied["ok"] and denied["reason"] == "file-denied":
        raise _Reject(f"file-denied({f})")
    if not any(r.match(f) for r in ALLOWED_FILES):
        raise _Reject(f"file-not-allowed({f})")
    for p, old, new, reason in changes:
        if not any(rx.match(p) for rx in ALLOWED_PATHS):
            raise _Reject(f"path-not-allowed({p})")
        _check_values(p, old, new)
        if not reason:
            raise _Reject(f"reason-required({p})")
    cur = _gh("GET", f"/repos/{repo}/contents/"
              f"{urllib.parse.quote(f, safe='/')}?ref={base}", token=token)
    text = base64.b64decode(cur["content"]).decode()
    # Application séquentielle : chaque changement modifie SA ligne. Un même
    # chemin proposé deux fois échoue au 2e passage (stale-old) — les
    # propositions contradictoires s'auto-refusent.
    for p, old, new, _ in changes:
        text = _apply(text, p, old, new)
    files = {f: (text, cur["sha"])}
    svc = f.split("/")[-2] if "/" in f else f
    if len(changes) == 1:
        p, old, new, reason = changes[0]
        title = f"[sre-agent] {svc} : {p.split('.')[-1]} {old} → {new}"
    else:
        fields = ", ".join(dict.fromkeys(
            p.split(".")[-1] for p, *_ in changes))
        title = f"[sre-agent] {svc} : {len(changes)} ajustements ({fields})"
    rows = "\n".join(
        f"| {i} | `{p}` | `{old}` | `{new}` | {reason} |"
        for i, (p, old, new, reason) in enumerate(changes, 1))
    diff = (f"`{f}` — {len(changes)} ligne(s) modifiée(s), chacune justifiée :\n\n"
            f"| # | Chemin | Avant | Après | Justification (preuve mesurée) |\n"
            f"|---|--------|-------|-------|--------------------------------|\n"
            f"{rows}")
    reason = (changes[0][3] if len(changes) == 1 else
              f"{len(changes)} ajustements complémentaires sur {svc} — "
              f"la preuve de chaque ligne est dans le tableau ci-dessus.")
    return files, title, diff, reason, "fix"


def _build_hardening(m, repo, base, token):
    """HARDEN_PROPOSAL -> le meme quintuplet que _build_patch.

    L'allow-list des FICHIERS est celle des patchs : durcir un manifeste hors
    perimetre serait aussi grave que d'y changer une valeur.
    """
    f = m.group("file")
    index = int(m.group("container"))
    cles = [c.strip() for c in m.group("keys").split(",") if c.strip()]
    if not cles:
        raise _Reject("harden-no-keys")

    denied = security_rules.file_allowed(f)
    if not denied["ok"] and denied["reason"] == "file-denied":
        raise _Reject(f"file-denied({f})")
    if not any(r.match(f) for r in ALLOWED_FILES):
        raise _Reject(f"file-not-allowed({f})")

    cur = _gh("GET", f"/repos/{repo}/contents/"
              f"{urllib.parse.quote(f, safe='/')}?ref={base}", token=token)
    text = base64.b64decode(cur["content"]).decode()

    # On ne fait PAS confiance aux cles proposees par le LLM : on redemande a
    # hardening_rules ce qui est licite, et on garde l'intersection.
    vue = hardening_rules.analyser(text, index)
    if not vue["ok"]:
        raise _Reject(f"harden-{vue['raison']}")
    licites = [c for c in cles if c in vue["proposer"]]
    refusees = [c for c in cles if c not in vue["proposer"]]
    if not licites:
        raise _Reject(f"harden-rien-de-licite(demande={cles}, "
                      f"proposable={vue['proposer']})")

    res = hardening_rules.inserer(text, index, licites)
    if not res["ok"]:
        raise _Reject(f"harden-{res['raison']}")

    files = {f: (res["texte"], cur["sha"])}
    svc = f.split("/")[-2] if "/" in f else f
    title = (f"[sre-agent] {svc} : durcissement "
             f"({', '.join(licites)})")
    diff = hardening_rules.pr_body(f, svc, licites, vue["issue"],
                                   vue["deja_present"])
    reason = (f"{len(licites)} cle(s) de securityContext ajoutee(s), "
              f"strictement additives — aucune valeur existante modifiee."
              + (f" Ecartees comme non licites : {refusees}."
                 if refusees else ""))
    return files, title, diff, reason, "harden"


def _build_rollback(m, repo, base, token):
    sha = m.group("commit")
    c = _gh("GET", f"/repos/{repo}/commits/{sha}", token=token)
    if not c.get("parents"):
        raise _Reject("rollback-no-parent")
    parent = c["parents"][0]["sha"]
    files, skipped = {}, []
    for fi in c.get("files", []):
        fn = fi["filename"]
        # même allow-list que les patchs : on ne revert QUE ces fichiers
        if not any(r.match(fn) for r in ALLOWED_FILES) \
                or fi.get("status") != "modified":
            skipped.append(fn)
            continue
        prev = _gh("GET", f"/repos/{repo}/contents/"
                   f"{urllib.parse.quote(fn, safe='/')}?ref={parent}",
                   token=token)
        cur = _gh("GET", f"/repos/{repo}/contents/"
                  f"{urllib.parse.quote(fn, safe='/')}?ref={base}",
                  token=token)
        # 05/08 — anti-écrasement (équivalent du stale-old des patchs) : si le
        # fichier a été modifié DEPUIS le commit incriminé, le revert
        # annulerait silencieusement ces changements intermédiaires -> refus,
        # le retour arrière devient une décision humaine.
        at_commit = _gh("GET", f"/repos/{repo}/contents/"
                        f"{urllib.parse.quote(fn, safe='/')}?ref={sha}",
                        token=token)
        if base64.b64decode(cur["content"]) != \
                base64.b64decode(at_commit["content"]):
            raise _Reject(f"rollback-stale({fn} modifié depuis {sha[:7]})")
        files[fn] = (base64.b64decode(prev["content"]).decode(), cur["sha"])
    if not files:
        raise _Reject("rollback-no-allowed-files")
    title = f"[sre-agent] Rollback proposé — corrèle avec l'incident " \
            f"(commit {sha[:7]})"
    diff = "Retour à l'état `" + parent[:7] + "` pour :\n" \
        + "\n".join(f"- `{fn}`" for fn in files)
    if skipped:
        diff += ("\n\nFichiers du commit HORS allow-list, non touchés : "
                 + ", ".join(f"`{s}`" for s in skipped))
    return files, title, diff, m.group("reason").strip(), "rollback"


# ---------------------------------------------------------------------------
#  Point d'entrée
# ---------------------------------------------------------------------------
def maybe_open_pr(analysis, labels):
    """Retourne ({url, number}, None) si une PR a été ouverte,
    (None, raison) sinon. Ne lève que sur erreur réseau/API inattendue."""
    if not enabled():
        return None, "disabled"
    patch = parse_patch(analysis)
    rb = ROLLBACK_RE.search(analysis)
    hd = HARDEN_RE.search(analysis)
    if not patch and not rb and not hd:
        return None, "no-proposal"
    token, repo, base = _cfg("token"), _cfg("repo"), _cfg("base")
    alert = labels.get("alertname", "alert")
    severity = labels.get("severity", "")
    try:
        if patch:
            files, title, diff, reason, kind = _build_patch(
                patch, repo, base, token)
        elif hd:
            files, title, diff, reason, kind = _build_hardening(
                hd, repo, base, token)
        else:
            files, title, diff, reason, kind = _build_rollback(
                rb, repo, base, token)
    except _Reject as r:
        return None, str(r)

    # --- E2 : la porte du registre ---------------------------------------
    # Placee APRES _build_patch (l'allow-list a deja parle) mais AVANT le
    # moindre appel d'ecriture GitHub : on ne cree jamais une branche pour la
    # refermer ensuite.
    fkey = findings_ledger.finding_key(
        cve=labels.get("cve"), policy=labels.get("policy"),
        deployment=labels.get("deployment"), namespace=labels.get("namespace"))
    pkey = findings_ledger.proposal_key(fkey, title, diff[:200])
    porte = findings_ledger.autorise(
        fkey, pkey, statut_pr=pr_status,
        incident_ouvert=bool(labels.get("incident_ouvert")))
    if not porte["ok"]:
        return None, f"ledger-{porte['raison']}: {porte['detail']}"

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", alert).strip("-").lower()[:40]
    branch = f"sre-agent/{kind}-{slug}-{stamp}"
    verdict = analysis.strip().split("\n")[0][:300]
    conf = ""
    cm = re.search(r"^Confiance\s*:.*$", analysis, re.M)
    if cm:
        conf = cm.group(0)[:300]
    body = (
        f"## 🤖 Remédiation proposée par l'agent SRE\n\n"
        f"**Alerte** : `{alert}` (sévérité {severity or '?'})\n"
        f"**{verdict}**\n\n"
        f"### Changement\n{diff}\n\n"
        f"### Justification (preuve mesurée)\n{reason}\n\n"
        f"{conf}\n\n"
        f"---\n"
        f"⚠️ Cette PR a été ouverte automatiquement (champs dans l'allow-list "
        f"probes/resources/replicas/rollout, {MAX_CHANGES} lignes max, "
        f"chaque ligne justifiée ci-dessus). **Le merge reste une décision "
        f"humaine** — branche protégée, CI `validate-manifests` requise. "
        f"Si l'alerte se résout avant merge, la PR sera fermée avec un "
        f"commentaire.\n\n"
        f"<details><summary>Diagnostic complet</summary>\n\n"
        f"```\n{analysis[:6000]}\n```\n</details>\n")

    ref = _gh("GET", f"/repos/{repo}/git/ref/heads/{base}", token=token)
    _gh("POST", f"/repos/{repo}/git/refs",
        {"ref": f"refs/heads/{branch}", "sha": ref["object"]["sha"]}, token=token)
    for fn, (content, cur_sha) in files.items():
        _gh("PUT", f"/repos/{repo}/contents/"
            f"{urllib.parse.quote(fn, safe='/')}",
            {"message": title, "branch": branch, "sha": cur_sha,
             "content": base64.b64encode(content.encode()).decode()},
            token=token)
    pr = _gh("POST", f"/repos/{repo}/pulls",
             {"title": title, "head": branch, "base": base, "body": body},
             token=token)
    lbls = ["ai-remediation"] + ([severity] if severity else [])
    try:
        _gh("POST", f"/repos/{repo}/issues/{pr['number']}/labels",
            {"labels": lbls}, token=token)
    except Exception:
        pass          # les labels sont cosmétiques : jamais bloquants
    # E2 : la PR existe, le registre la connait. Sans cette ligne, le prochain
    # cycle de scan rouvrirait exactement la meme.
    findings_ledger.marquer_proposee(fkey, pkey, pr=pr["number"],
                                     url=pr["html_url"], resume=title)
    return {"url": pr["html_url"], "number": pr["number"],
            "title": title, "branch": branch}, None


def pr_status(number):
    """Boucle fermée : état d'une PR suivie. merged=True + merge_sha
    permettent à B4 de reconnaître le sync du remède et de le confirmer."""
    token, repo = _cfg("token"), _cfg("repo")
    pr = _gh("GET", f"/repos/{repo}/pulls/{number}", token=token)
    return {"state": pr.get("state", "?"),
            "merged": bool(pr.get("merged")),
            "merge_sha": pr.get("merge_commit_sha") or ""}


def close_pr(number, comment):
    """Borne n°6 du guide : alerte résolue avant merge -> commentaire + close."""
    token, repo = _cfg("token"), _cfg("repo")
    _gh("POST", f"/repos/{repo}/issues/{number}/comments",
        {"body": comment}, token=token)
    _gh("PATCH", f"/repos/{repo}/pulls/{number}",
        {"state": "closed"}, token=token)


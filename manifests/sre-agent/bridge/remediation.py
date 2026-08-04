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
On ne modifie qu'une valeur scalaire sur une ligne existante — jamais de
restructuration du fichier, le diff de PR reste d'UNE ligne.
"""
import base64
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

API = "https://api.github.com"
# Secret github-remediation monté en fichiers (clés : token, repo, base).
GH_DIR = os.environ.get("GITHUB_SECRET_DIR", "/etc/github")

# ---------------------------------------------------------------------------
#  Allow-list — LE cœur de la sécurité. En dur, jamais dérivée du prompt.
# ---------------------------------------------------------------------------
ALLOWED_FILES = (
    re.compile(r"^manifests/app/[a-z0-9-]+/deployment\.yaml$"),
    re.compile(r"^manifests/app/patches/[a-z0-9.-]+\.yaml$"),
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
)
# Scalaires k8s simples uniquement : entiers, cpu (500m), mémoire (128Mi).
VALUE_RE = re.compile(r"^[0-9]+(m|Ki|Mi|Gi)?$")
# maxSurge/maxUnavailable acceptent aussi les pourcentages ("25%").
PCT_RE = re.compile(r"^([0-9]{1,3})(%)?$")


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
    else:
        if not (VALUE_RE.match(old) and VALUE_RE.match(new)):
            raise _Reject("value-not-allowed")

PATCH_RE = re.compile(
    r"PATCH_PROPOSAL:\s*\n"
    r"\s*file:\s*(?P<file>\S+)\s*\n"
    r"\s*path:\s*(?P<path>\S+)\s*\n"
    r"\s*old:\s*(?P<old>\S+)\s*\n"
    r"\s*new:\s*(?P<new>\S+)\s*\n"
    r"\s*reason:\s*(?P<reason>[^\n]+)")
ROLLBACK_RE = re.compile(
    r"ROLLBACK_PROPOSAL:\s*\n"
    r"\s*commit:\s*(?P<commit>[0-9a-f]{7,40})\s*\n"
    r"\s*reason:\s*(?P<reason>[^\n]+)")


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
        raise RuntimeError(f"GitHub {method} {path} -> {e.code} {detail}")


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
    for i, l in enumerate(lines):
        if l.strip() == "---":
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
def _build_patch(m, repo, base, token):
    f, p = m.group("file"), m.group("path")
    old, new = m.group("old"), m.group("new")
    if not any(r.match(f) for r in ALLOWED_FILES):
        raise _Reject(f"file-not-allowed({f})")
    if not any(r.match(p) for r in ALLOWED_PATHS):
        raise _Reject(f"path-not-allowed({p})")
    _check_values(p, old, new)
    cur = _gh("GET", f"/repos/{repo}/contents/"
              f"{urllib.parse.quote(f, safe='/')}?ref={base}", token=token)
    text = base64.b64decode(cur["content"]).decode()
    files = {f: (_apply(text, p, old, new), cur["sha"])}
    svc = f.split("/")[-2] if "/" in f else f
    title = f"[sre-agent] {svc} : {p.split('.')[-1]} {old} → {new}"
    diff = f"`{f}`\n`{p}` : **{old} → {new}**"
    return files, title, diff, m.group("reason").strip(), "fix"


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
    patch = PATCH_RE.search(analysis)
    rb = ROLLBACK_RE.search(analysis)
    if not patch and not rb:
        return None, "no-proposal"
    token, repo, base = _cfg("token"), _cfg("repo"), _cfg("base")
    alert = labels.get("alertname", "alert")
    severity = labels.get("severity", "")
    try:
        if patch:
            files, title, diff, reason, kind = _build_patch(
                patch, repo, base, token)
        else:
            files, title, diff, reason, kind = _build_rollback(
                rb, repo, base, token)
    except _Reject as r:
        return None, str(r)

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
        f"⚠️ Cette PR a été ouverte automatiquement (champ dans l'allow-list "
        f"probes/resources/replicas). **Le merge reste une décision "
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


#!/usr/bin/env python3
"""
deploy-annotator.py — B0 : traçabilité incident → commit
Pour chaque Application Argo CD :
  1. Lit operationState.syncResult.revision
  2. Compare au dernier hash connu (état persistant)
  3. Si nouveau sync : annotation Grafana + écriture du contexte pour le bridge
Aucun droit d'écriture sur le cluster — lecture seule (kubectl get uniquement).
"""
import json
import subprocess
import urllib.request
import urllib.error
import os
import sys

APPS = ["dashboards", "online-boutique", "monitoring"]
STATE_FILE = "/state/deploy-tracking.json"
CONTEXT_FILE = "/state/last-deploys.json"  # lu par le bridge
GRAFANA_URL = os.environ.get("GRAFANA_URL", "").rstrip("/")
GRAFANA_TOKEN = os.environ.get("GRAFANA_TOKEN", "")
REPO_DIR = os.environ.get("REPO_DIR", "/repo")  # clone local en lecture seule


def log(msg):
    print(f"[deploy-annotator] {msg}", file=sys.stderr)


def get_app_sync_state(app):
    try:
        out = subprocess.run(
            ["kubectl", "get", "application", app, "-n", "argocd", "-o", "json"],
            capture_output=True, text=True, check=True, timeout=10
        )
    except subprocess.CalledProcessError as e:
        log(f"kubectl error for {app}: {e.stderr}")
        return None
    d = json.loads(out.stdout)
    op = d.get("status", {}).get("operationState", {}) or {}
    sync_result = op.get("syncResult", {}) or {}
    return {
        "revision": sync_result.get("revision"),
        "finishedAt": op.get("finishedAt"),
        "phase": op.get("phase"),
    }


def load_json(path, default):
    if os.path.exists(path):
        try:
            with open(path) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return default
    return default


def save_json_atomic(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)  # écriture atomique


def get_changed_files(old_rev, new_rev):
    if not old_rev or old_rev == new_rev:
        return []
    try:
        out = subprocess.run(
            ["git", "-C", REPO_DIR, "diff", "--name-only", old_rev, new_rev],
            capture_output=True, text=True, check=True, timeout=10
        )
        return [line for line in out.stdout.splitlines() if line.strip()]
    except subprocess.CalledProcessError as e:
        log(f"git diff error: {e.stderr}")
        return []


def get_commit_message(rev):
    try:
        out = subprocess.run(
            ["git", "-C", REPO_DIR, "log", "-1", "--pretty=%s", rev],
            capture_output=True, text=True, check=True, timeout=10
        )
        return out.stdout.strip()
    except subprocess.CalledProcessError:
        return ""


def post_grafana_annotation(app, revision, files, message):
    if not GRAFANA_URL or not GRAFANA_TOKEN:
        log("Grafana non configuré (GRAFANA_URL/GRAFANA_TOKEN absents) — skip annotation")
        return
    text = f"🚀 Sync {app} → {revision[:8]} — {message}"
    if files:
        text += f" ({len(files)} fichier(s): {', '.join(files[:5])}{'...' if len(files) > 5 else ''})"
    payload = json.dumps({
        "text": text,
        "tags": ["deploy", app],
    }).encode()
    req = urllib.request.Request(
        f"{GRAFANA_URL}/api/annotations",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {GRAFANA_TOKEN}",
        },
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=10)
        log(f"Annotation Grafana postée pour {app} ({revision[:8]})")
    except urllib.error.URLError as e:
        log(f"Erreur annotation Grafana pour {app}: {e}")


def main():
    state = load_json(STATE_FILE, {})
    context = load_json(CONTEXT_FILE, {})

    for app in APPS:
        sync_state = get_app_sync_state(app)
        if not sync_state or sync_state["phase"] != "Succeeded":
            continue

        new_rev = sync_state["revision"]
        old_rev = state.get(app, {}).get("revision")

        if new_rev and new_rev != old_rev:
            log(f"{app}: nouveau sync détecté {old_rev} → {new_rev}")
            files = get_changed_files(old_rev, new_rev)
            message = get_commit_message(new_rev)

            post_grafana_annotation(app, new_rev, files, message)

            # Contexte pour le bridge — jamais l'auteur, uniquement le commit (no-blame)
            context[app] = {
                "git_commit": new_rev,
                "git_repo_paths": files,
                "synced_at": sync_state["finishedAt"],
                "commit_message": message,
            }
            save_json_atomic(CONTEXT_FILE, context)

        state[app] = sync_state
        save_json_atomic(STATE_FILE, state)

    log("Cycle terminé")


if __name__ == "__main__":
    main()

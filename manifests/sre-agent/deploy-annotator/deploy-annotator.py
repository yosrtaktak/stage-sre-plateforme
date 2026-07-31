#!/usr/bin/env python3
"""
deploy-annotator.py — B0 : traçabilité incident → commit
Interroge l'API Kubernetes directement en HTTPS (ServiceAccount token),
sans dépendance à kubectl — cohérent avec le reste du système (stdlib pur).
"""
import json
import urllib.request
import urllib.error
import ssl
import os
import sys

APPS = ["dashboards", "online-boutique", "monitoring"]
STATE_FILE = "/state/deploy-tracking.json"
CONTEXT_FILE = "/state/last-deploys.json"
GRAFANA_URL = os.environ.get("GRAFANA_URL", "").rstrip("/")
GRAFANA_TOKEN = os.environ.get("GRAFANA_TOKEN", "")

GITHUB_API = "https://api.github.com"
GITHUB_REPO = os.environ.get("GITHUB_REPO", "yosrtaktak/stage-sre-plateforme")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")

K8S_API = "https://kubernetes.default.svc"
SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"


def log(msg):
    print(f"[deploy-annotator] {msg}", file=sys.stderr)


def k8s_get(path):
    with open(f"{SA_DIR}/token") as f:
        token = f.read().strip()
    ctx = ssl.create_default_context(cafile=f"{SA_DIR}/ca.crt")
    req = urllib.request.Request(
        f"{K8S_API}{path}",
        headers={"Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
        return json.loads(resp.read())


def github_get(path):
    headers = {"Accept": "application/vnd.github+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    req = urllib.request.Request(f"{GITHUB_API}{path}", headers=headers)
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def get_app_sync_state(app):
    try:
        d = k8s_get(f"/apis/argoproj.io/v1alpha1/namespaces/argocd/applications/{app}")
    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        log(f"API error for {app}: {e}")
        return None
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
    os.replace(tmp, path)


def get_changed_files(old_rev, new_rev):
    if not old_rev or old_rev == new_rev:
        return []
    try:
        d = github_get(f"/repos/{GITHUB_REPO}/compare/{old_rev}...{new_rev}")
        return [f["filename"] for f in d.get("files", [])]
    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        log(f"GitHub compare error: {e}")
        return []


def get_commit_message(rev):
    try:
        d = github_get(f"/repos/{GITHUB_REPO}/commits/{rev}")
        return d.get("commit", {}).get("message", "").splitlines()[0] if d.get("commit", {}).get("message") else ""
    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        log(f"GitHub commit error: {e}")
        return ""


def post_grafana_annotation(app, revision, files, message):
    if not GRAFANA_URL or not GRAFANA_TOKEN:
        log("Grafana non configuré — skip annotation")
        return
    text = f"🚀 Sync {app} → {revision[:8]} — {message}"
    if files:
        text += f" ({len(files)} fichier(s): {', '.join(files[:5])}{'...' if len(files) > 5 else ''})"
    payload = json.dumps({"text": text, "tags": ["deploy", app]}).encode()
    req = urllib.request.Request(
        f"{GRAFANA_URL}/api/annotations",
        data=payload,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {GRAFANA_TOKEN}"},
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

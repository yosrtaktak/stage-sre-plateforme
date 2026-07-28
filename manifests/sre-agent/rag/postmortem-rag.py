# -*- coding: utf-8 -*-
"""Base vectorielle des incidents (post-mortems + diagnostics) — RAG v2.

v2 : le stockage/la recherche vectorielle sont délégués à **Qdrant Cloud**
(free tier 1 Go, API REST pure — le service reste stdlib, zéro dépendance).
Le fichier local devient un **cache write-through + file d'attente** : si
Qdrant est injoignable, le document est indexé localement, marqué "pending"
et resynchronisé plus tard (at-least-once). Sans QDRANT_URL, le service
fonctionne comme la v1 (index local seul) — rollback trivial.

Façade HTTP INCHANGÉE vs v1 (le bridge et le toolset Holmes ne bougent pas) :
  POST /add     {title, text, tags[], meta{}}  -> embedde et indexe
  POST /search  {query, k=3}                   -> top-k similaires (cosinus)
  GET  /list                                    -> inventaire de l'index
  GET  /export[?tag=...]                        -> dump Markdown archivable
  GET  /healthz

Lisibilité en base : chaque point Qdrant porte un payload STRUCTURÉ
(title, date, type, alert, severity, slo, verdict, tags, text) — dans l'UI
Qdrant Cloud, un post-mortem se lit champ par champ au lieu d'un blob.

Anti-suspension free tier : un thread keepalive interroge la collection
toutes les 12 h (suspension à 7 jours d'inactivité, suppression à 28).

Embeddings : API Gemini (gratuite, même clé que l'agent), 3072 dimensions
par défaut — les vecteurs 3072d sont pré-normalisés par Gemini, la distance
Cosine de Qdrant s'applique directement.
"""
import json
import math
import os
import re
import threading
import time
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
EMBED_MODEL = os.environ.get("EMBED_MODEL", "gemini-embedding-001")
QDRANT_URL = os.environ.get("QDRANT_URL", "").strip().rstrip("/")
QDRANT_API_KEY = os.environ.get("QDRANT_API_KEY", "")
COLLECTION = os.environ.get("COLLECTION", "incidents")
CACHE_FILE = os.environ.get("CACHE_FILE", "/data/cache.json")
LEGACY_INDEX = os.environ.get("INDEX_FILE", "/data/index.json")  # migration v1
PORT = int(os.environ.get("PORT", "8100"))
RESYNC_MIN_S = 60          # au plus 1 tentative de resync par minute
KEEPALIVE_S = 12 * 3600    # ping Qdrant 2x/jour (anti-suspension free tier)

SEVERITIES = ("critical", "warning", "info")

_lock = threading.Lock()
_cache = {"docs": [], "pending": []}   # docs: [{id, payload, vec}]
_coll_ready = False
_last_resync = 0.0


def log(msg):
    print(f"[rag] {msg}", flush=True)


# ---------------------------------------------------------------- cache local
def _load():
    global _cache
    try:
        with open(CACHE_FILE) as f:
            _cache = json.load(f)
        _cache.setdefault("docs", [])
        _cache.setdefault("pending", [])
    except Exception:
        _cache = {"docs": [], "pending": []}
    # Migration v1 : reprend l'ancien index.json (docs marqués à pousser).
    if not _cache["docs"]:
        try:
            with open(LEGACY_INDEX) as f:
                for d in json.load(f):
                    pid = _doc_id(d["title"])
                    _cache["docs"].append({
                        "id": pid,
                        "payload": _payload(d["title"], d["text"],
                                            d.get("tags", []), None),
                        "vec": d["vec"]})
                    _cache["pending"].append(pid)
            if _cache["docs"]:
                log(f"migration v1 : {len(_cache['docs'])} documents repris "
                    f"de {LEGACY_INDEX} (poussés vers Qdrant au resync)")
                _save()
        except Exception:
            pass


def _save():
    try:
        tmp = CACHE_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(_cache, f)
        os.replace(tmp, CACHE_FILE)
    except Exception as e:
        log(f"save error: {e}")


# ------------------------------------------------------------------ embeddings
def _embed(text):
    """Vecteur d'embedding via l'API Gemini (free tier)."""
    body = json.dumps({
        "content": {"parts": [{"text": text[:7000]}]},
    }).encode()
    req = urllib.request.Request(
        f"https://generativelanguage.googleapis.com/v1beta/models/"
        f"{EMBED_MODEL}:embedContent",
        data=body,
        headers={"Content-Type": "application/json",
                 "x-goog-api-key": GEMINI_API_KEY})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())["embedding"]["values"]


def _cosine(a, b):
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(x * x for x in b))
    return dot / (na * nb) if na and nb else 0.0


# ---------------------------------------------------------------- client Qdrant
def _qdrant(method, path, body=None, timeout=15):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        QDRANT_URL + path, data=data, method=method,
        headers={"Content-Type": "application/json",
                 "api-key": QDRANT_API_KEY})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def _ensure_collection(dim):
    global _coll_ready
    if _coll_ready:
        return
    try:
        _qdrant("GET", f"/collections/{COLLECTION}")
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise
        _qdrant("PUT", f"/collections/{COLLECTION}",
                {"vectors": {"size": dim, "distance": "Cosine"}})
        log(f"collection Qdrant créée : {COLLECTION} ({dim} dims, Cosine)")
    _coll_ready = True


def _upsert(pid, vec, payload):
    _qdrant("PUT", f"/collections/{COLLECTION}/points?wait=true",
            {"points": [{"id": pid, "vector": vec, "payload": payload}]})


def _doc_id(title):
    # UUID déterministe dérivé du titre : même titre = même point Qdrant
    # = mise à jour, pas doublon (sémantique v1 conservée).
    return str(uuid.uuid5(uuid.NAMESPACE_URL, title))


# ----------------------------------------------------- payload structuré (v2)
def _payload(title, text, tags, meta):
    """Un champ par information -> post-mortem lisible dans l'UI Qdrant.

    Le bridge envoie `meta` explicitement ; à défaut (curl manuel, docs v1),
    les champs sont dérivés du titre/texte/tags par heuristique.
    """
    m = meta or {}
    first = next((l.strip() for l in text.splitlines() if l.strip()), "")
    dt = re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC", title)
    return {
        "title": title,
        "date": m.get("date") or (dt.group(0) if dt else ""),
        "type": m.get("type") or ("postmortem" if "postmortem" in tags
                                  else "diagnostic"),
        "alert": m.get("alert") or (tags[0] if tags else ""),
        "severity": m.get("severity")
                    or next((t for t in tags if t in SEVERITIES), ""),
        "slo": m.get("slo", ""),
        "verdict": (m.get("verdict") or first)[:300],
        "tags": tags,
        "text": text,
    }


# ------------------------------------------------------------------ opérations
def add_doc(title, text, tags, meta=None):
    """Write-through : cache local d'abord, puis Qdrant ; en échec Qdrant le
    doc est mis en file (pending) et rejoué au prochain resync."""
    vec = _embed(f"{title}\n{text}")
    pid = _doc_id(title)
    payload = _payload(title, text, tags, meta)
    queued = False
    with _lock:
        _cache["docs"] = [d for d in _cache["docs"] if d["id"] != pid]
        _cache["docs"].append({"id": pid, "payload": payload, "vec": vec})
        if pid in _cache["pending"]:
            _cache["pending"].remove(pid)
    if QDRANT_URL:
        try:
            _ensure_collection(len(vec))
            _upsert(pid, vec, payload)
        except Exception as e:
            log(f"qdrant injoignable, doc mis en file : {e}")
            queued = True
    with _lock:
        if queued and pid not in _cache["pending"]:
            _cache["pending"].append(pid)
        _save()
        n, p = len(_cache["docs"]), len(_cache["pending"])
    log(f"indexé : {title} ({n} documents, file d'attente : {p})")
    return queued


def resync(force=False):
    """Rejoue la file des documents jamais poussés vers Qdrant."""
    global _last_resync
    if not QDRANT_URL:
        return
    now = time.time()
    if not force and now - _last_resync < RESYNC_MIN_S:
        return
    _last_resync = now
    with _lock:
        pending = list(_cache["pending"])
        docs = {d["id"]: d for d in _cache["docs"]}
    for pid in pending:
        d = docs.get(pid)
        try:
            if d:
                _ensure_collection(len(d["vec"]))
                _upsert(pid, d["vec"], d["payload"])
                log(f"resync ok : {d['payload']['title']}")
        except Exception as e:
            log(f"resync en échec (retentera) : {e}")
            return
        with _lock:
            if pid in _cache["pending"]:
                _cache["pending"].remove(pid)
                _save()


def search(query, k=3):
    qv = _embed(query)
    k = max(1, min(int(k), 10))
    if QDRANT_URL:
        try:
            res = _qdrant("POST",
                          f"/collections/{COLLECTION}/points/search",
                          {"vector": qv, "limit": k, "with_payload": True})
            return [{"title": p["payload"].get("title"),
                     "date": p["payload"].get("date"),
                     "verdict": p["payload"].get("verdict"),
                     "tags": p["payload"].get("tags", []),
                     "score": round(p.get("score", 0.0), 4),
                     "text": (p["payload"].get("text") or "")[:2500]}
                    for p in res.get("result", [])]
        except Exception as e:
            log(f"search qdrant KO, repli sur le cache local : {e}")
    with _lock:
        scored = sorted(
            ({"title": d["payload"]["title"], "date": d["payload"]["date"],
              "verdict": d["payload"]["verdict"], "tags": d["payload"]["tags"],
              "score": round(_cosine(qv, d["vec"]), 4),
              "text": d["payload"]["text"][:2500]} for d in _cache["docs"]),
            key=lambda d: d["score"], reverse=True)
    return scored[:k]


def all_payloads():
    """Tous les documents (Qdrant si joignable, sinon cache local)."""
    if QDRANT_URL:
        try:
            res = _qdrant("POST",
                          f"/collections/{COLLECTION}/points/scroll",
                          {"limit": 1000, "with_payload": True})
            return [p["payload"] for p in res["result"]["points"]]
        except Exception as e:
            log(f"list qdrant KO, repli sur le cache local : {e}")
    with _lock:
        return [d["payload"] for d in _cache["docs"]]


def _keepalive():
    """Ping périodique : le free tier Qdrant suspend un cluster inactif
    après 7 jours (et le SUPPRIME après 28) — 2 requêtes/jour l'évitent."""
    while True:
        time.sleep(KEEPALIVE_S)
        try:
            resync(force=True)
            _qdrant("GET", f"/collections/{COLLECTION}")
            log("keepalive qdrant ok")
        except Exception as e:
            log(f"keepalive qdrant KO : {e}")


# ------------------------------------------------------------------------ HTTP
class Handler(BaseHTTPRequestHandler):
    def _json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/healthz":
            with _lock:
                n, p = len(_cache["docs"]), len(_cache["pending"])
            if p:   # relance la file en arrière-plan (throttlé à 1/min)
                threading.Thread(target=resync, daemon=True).start()
            self._json({"ok": True, "documents": n, "pending": p,
                        "backend": "qdrant" if QDRANT_URL else "local"})
        elif self.path == "/list":
            self._json([{k: d.get(k) for k in
                         ("title", "date", "type", "severity", "tags")}
                        for d in all_payloads()])
        elif self.path.startswith("/export"):
            # Archivage : dump Markdown structuré, prêt à commiter dans Git.
            # /export           -> tout ; /export?tag=postmortem -> filtré
            tag = ""
            if "tag=" in self.path:
                tag = self.path.split("tag=", 1)[1].split("&")[0]
            docs = [d for d in all_payloads()
                    if not tag or tag in d.get("tags", [])]
            parts = [f"# Archive des incidents ({len(docs)} documents)\n"]
            for d in docs:
                parts.append(f"\n---\n\n## {d.get('title', '?')}\n\n")
                parts.append(f"| Date | Type | Alerte | Sévérité | SLO |\n"
                             f"|---|---|---|---|---|\n"
                             f"| {d.get('date', '?')} | {d.get('type', '?')} "
                             f"| {d.get('alert', '?')} "
                             f"| {d.get('severity', '?')} "
                             f"| {d.get('slo', '?')} |\n\n")
                parts.append(f"**Verdict** : {d.get('verdict', '?')}\n\n")
                parts.append(d.get("text", "") + "\n")
            body = "".join(parts).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/markdown; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(length))
            if self.path == "/add":
                queued = add_doc(data["title"], data["text"],
                                 data.get("tags", []), data.get("meta"))
                with _lock:
                    n = len(_cache["docs"])
                self._json({"ok": True, "documents": n, "queued": queued})
            elif self.path == "/search":
                self._json(search(data["query"], data.get("k", 3)))
            else:
                self.send_response(404)
                self.end_headers()
        except Exception as e:
            log(f"error {self.path}: {e}")
            self._json({"error": str(e)}, code=500)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    _load()
    log(f"listening :{PORT} model={EMBED_MODEL} "
        f"backend={'qdrant ' + QDRANT_URL if QDRANT_URL else 'local'} "
        f"cache={CACHE_FILE} ({len(_cache['docs'])} documents, "
        f"{len(_cache['pending'])} en attente)")
    if QDRANT_URL:
        threading.Thread(target=_keepalive, daemon=True).start()
        threading.Thread(target=resync, kwargs={"force": True},
                         daemon=True).start()
    ThreadingHTTPServer(("", PORT), Handler).serve_forever()


# -*- coding: utf-8 -*-
"""Base vectorielle des incidents (post-mortems + diagnostics) — RAG.

Micro-service stdlib (zéro dépendance, comme le bridge) :
  POST /add     {title, text, tags[]}    -> embedde et indexe le document
  POST /search  {query, k=3}            -> top-k documents similaires (cosinus)
  GET  /list                             -> inventaire de l'index
  GET  /healthz

Embeddings : API Gemini (gratuite, même clé que l'agent). Index persisté dans
INDEX_FILE (JSON) sur un volume — à cette échelle (dizaines à centaines de
documents), la similarité cosinus en pur Python est instantanée : inutile de
déployer une vraie base vectorielle (Qdrant/Chroma), c'est le même principe.

Consommé par :
  - le bridge (chaque diagnostic/post-mortem publié est POSTé sur /add) ;
  - HolmesGPT via un toolset custom (curl /search) : l'agent peut chercher
    « incidents similaires » PENDANT son enquête — c'est du RAG agentique.
"""
import json
import math
import os
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
EMBED_MODEL = os.environ.get("EMBED_MODEL", "gemini-embedding-001")
INDEX_FILE = os.environ.get("INDEX_FILE", "/data/index.json")
PORT = int(os.environ.get("PORT", "8100"))

_lock = threading.Lock()
_docs = []      # [{title, text, tags, vec}]


def log(msg):
    print(f"[rag] {msg}", flush=True)


def _load():
    global _docs
    try:
        with open(INDEX_FILE) as f:
            _docs = json.load(f)
    except Exception:
        _docs = []


def _save():
    try:
        tmp = INDEX_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(_docs, f)
        os.replace(tmp, INDEX_FILE)
    except Exception as e:
        log(f"save error: {e}")


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


def add_doc(title, text, tags):
    vec = _embed(f"{title}\n{text}")
    with _lock:
        # même titre = mise à jour, pas doublon
        _docs[:] = [d for d in _docs if d["title"] != title]
        _docs.append({"title": title, "text": text, "tags": tags, "vec": vec})
        _save()
    log(f"indexé : {title} ({len(_docs)} documents)")


def search(query, k=3):
    qv = _embed(query)
    with _lock:
        scored = sorted(
            ({"title": d["title"], "tags": d["tags"],
              "score": round(_cosine(qv, d["vec"]), 4),
              "text": d["text"][:2500]} for d in _docs),
            key=lambda d: d["score"], reverse=True)
    return scored[:max(1, min(int(k), 10))]


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
            self._json({"ok": True, "documents": len(_docs)})
        elif self.path == "/list":
            with _lock:
                self._json([{"title": d["title"], "tags": d["tags"]}
                            for d in _docs])
        elif self.path.startswith("/export"):
            # Archivage : dump Markdown de l'index, prêt à commiter dans Git.
            # /export           -> tout ; /export?tag=postmortem -> filtré
            tag = ""
            if "tag=" in self.path:
                tag = self.path.split("tag=", 1)[1].split("&")[0]
            with _lock:
                docs = [d for d in _docs if not tag or tag in d.get("tags", [])]
            parts = [f"# Archive des incidents ({len(docs)} documents)\n"]
            for d in docs:
                parts.append(f"\n---\n\n## {d['title']}\n")
                parts.append(f"*Tags : {', '.join(d.get('tags', []))}*\n\n")
                parts.append(d["text"] + "\n")
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
                add_doc(data["title"], data["text"], data.get("tags", []))
                self._json({"ok": True, "documents": len(_docs)})
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
    log(f"listening :{PORT} model={EMBED_MODEL} index={INDEX_FILE} "
        f"({len(_docs)} documents chargés)")
    ThreadingHTTPServer(("", PORT), Handler).serve_forever()


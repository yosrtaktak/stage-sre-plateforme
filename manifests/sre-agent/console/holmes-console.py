# -*- coding: utf-8 -*-
"""Mini-console web pour interroger HolmesGPT depuis le navigateur.

Zéro dépendance (stdlib). Sert une page de chat sur :8090 et relaie les
questions vers l'API Holmes (/api/chat) — le proxy côté serveur évite tout
problème CORS.

Usage sur la VM (avec le port-forward Holmes actif sur 8080) :
    kubectl -n monitoring port-forward svc/holmesgpt-holmes 8080:80 &
    python3 manifests/sre-agent/console/holmes-console.py
    # puis ouvrir http://localhost:8090 dans le navigateur de la VM

Variables : HOLMES_URL (défaut http://localhost:8080), PORT (défaut 8090).
"""
import json
import os
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOLMES_URL = os.environ.get("HOLMES_URL", "http://localhost:8080")
PORT = int(os.environ.get("PORT", "8090"))
TIMEOUT_S = int(os.environ.get("HOLMES_TIMEOUT_S", "280"))

PAGE = """<!doctype html><html lang="fr"><head><meta charset="utf-8">
<title>Console SRE — HolmesGPT</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body{font-family:system-ui,sans-serif;max-width:880px;margin:2rem auto;
       padding:0 1rem;background:#0f1420;color:#e6e9f0}
  h1{font-size:1.2rem} h1 span{color:#7aa2f7}
  textarea{width:100%;min-height:90px;padding:.7rem;border-radius:8px;
       border:1px solid #2a3350;background:#161b2c;color:#e6e9f0;
       font-size:1rem;box-sizing:border-box}
  select,button{padding:.55rem 1rem;border-radius:8px;border:1px solid #2a3350;
       background:#161b2c;color:#e6e9f0;font-size:.95rem}
  button{background:#2b4a9e;cursor:pointer;border:none}
  button:disabled{opacity:.5;cursor:wait}
  #out{white-space:pre-wrap;background:#161b2c;border:1px solid #2a3350;
       border-radius:8px;padding:1rem;margin-top:1rem;min-height:60px;
       line-height:1.5}
  .bar{display:flex;gap:.6rem;align-items:center;margin-top:.6rem}
  .hint{color:#8b93a7;font-size:.85rem;margin-top:.4rem}
  .ex{color:#7aa2f7;cursor:pointer;text-decoration:underline}
</style></head><body>
<h1>🤖 Console SRE — <span>HolmesGPT</span></h1>
<textarea id="q" placeholder="Pose ta question d'enquête… (PromQL sli:/slo:, kubectl, logs Loki, traces Tempo)"></textarea>
<div class="bar">
  <select id="model">
    <option value="gemini-flash">gemini-flash (principal — 3.5-flash-lite)</option>
    <option value="gemini-flash-31">gemini-flash-31 (secours — quota/min séparé)</option>
    <option value="groq-llama70b">groq-llama70b (dernier recours — quota jour limité)</option>
  </select>
  <button id="go" onclick="ask()">Enquêter</button>
  <span id="st" class="hint"></span>
</div>
<div class="hint">Exemples :
  <span class="ex" onclick="fill('Le SLI checkout est-il conforme à son SLO 99,95 % en ce moment ?')">SLI checkout</span> ·
  <span class="ex" onclick="fill('Retrouve dans les logs historiques Loki les erreurs vers redis-cart:6379 de ce matin 08h-10h UTC et dis quel pod les émettait')">logs historiques</span> ·
  <span class="ex" onclick="fill('Analyse les traces Tempo des requêtes /cart/checkout de la dernière heure : quel service consomme le plus de temps ?')">traces lentes</span>
</div>
<div id="out">La réponse s'affichera ici. Une enquête prend 1 à 3 minutes (boucle ReAct).</div>
<script>
function fill(t){document.getElementById('q').value=t}
async function ask(){
  const q=document.getElementById('q').value.trim(); if(!q)return;
  const b=document.getElementById('go'), st=document.getElementById('st'),
        out=document.getElementById('out');
  b.disabled=true; out.textContent='';
  let s=0; st.textContent='enquête en cours… 0 s';
  const t=setInterval(()=>{st.textContent='enquête en cours… '+(++s)+' s'},1000);
  try{
    const r=await fetch('/ask',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({ask:q,model:document.getElementById('model').value})});
    const j=await r.json();
    out.textContent=j.analysis||j.response||j.detail||JSON.stringify(j,null,2);
  }catch(e){out.textContent='Erreur : '+e}
  clearInterval(t); st.textContent=''; b.disabled=false;
}
document.getElementById('q').addEventListener('keydown',e=>{
  if(e.key==='Enter'&&(e.ctrlKey||e.metaKey))ask()});
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/", "/index.html"):
            body = PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path != "/ask":
            self.send_response(404)
            self.end_headers()
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            payload = self.rfile.read(length)
            req = urllib.request.Request(
                f"{HOLMES_URL}/api/chat", data=payload,
                headers={"Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
                    body = r.read()
                    code = 200
            except urllib.error.HTTPError as e:
                body = e.read()          # relaie l'erreur Holmes (ex. 429)
                code = 200               # la page l'affiche dans "detail"
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception as e:
            msg = json.dumps({"detail": f"console error: {e}"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(msg)))
            self.end_headers()
            self.wfile.write(msg)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print(f"[console] http://localhost:{PORT} -> {HOLMES_URL}/api/chat", flush=True)
    ThreadingHTTPServer(("", PORT), Handler).serve_forever()

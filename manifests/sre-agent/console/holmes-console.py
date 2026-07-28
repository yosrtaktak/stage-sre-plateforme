# -*- coding: utf-8 -*-
"""Console web de l'agent SRE — HolmesGPT + mémoire des incidents (v2).

Zéro dépendance (stdlib). Sert une page de chat sur :8090 et relaie :
  POST /ask  -> HolmesGPT /api/chat  (enquête LLM, 1-3 min, consomme du quota)
  POST /rag  -> postmortem-rag /search (mémoire vectorielle, instantané, 0 quota)

v2 : interface refondue (conversation en bulles, timer d'enquête, panneau
« Mémoire des incidents » qui interroge le RAG sans consommer de quota LLM,
bouton copier) + correctif T6.1 : chaque question est préfixée d'une consigne
imposant la consultation de la mémoire des incidents — le chemin console est
aligné sur le protocole du bridge.

Usage sur la VM (avec les port-forwards actifs) :
    kubectl -n monitoring port-forward svc/holmesgpt-holmes 8080:80 &
    kubectl -n monitoring port-forward svc/postmortem-rag 8100:8100 &
    python3 manifests/sre-agent/console/holmes-console.py
    # depuis Windows : ssh -p 2222 -L 8090:localhost:8090 yosr@<ip>
    # puis ouvrir http://localhost:8090

Variables : HOLMES_URL (déf. http://localhost:8080),
            RAG_URL (déf. http://localhost:8100), PORT (déf. 8090).
⚠️ Console locale sans authentification : à utiliser via port-forward
uniquement, ne JAMAIS l'exposer en Service dans le cluster.
"""
import json
import os
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOLMES_URL = os.environ.get("HOLMES_URL", "http://localhost:8080")
RAG_URL = os.environ.get("RAG_URL", "http://localhost:8100")
PORT = int(os.environ.get("PORT", "8090"))
TIMEOUT_S = int(os.environ.get("HOLMES_TIMEOUT_S", "280"))

# Correctif T6.1 : sans cette consigne, une question console partait BRUTE
# vers Holmes — l'agent pouvait répondre de mémoire générique sans consulter
# la mémoire des incidents (constaté en test le 28/07).
CONSOLE_PREAMBLE = (
    "CONSIGNES (console SRE) : si la question concerne une panne, un "
    "incident ou un comportement passé, tu DOIS d'abord consulter la "
    "mémoire des incidents (outil search_similar_incidents) avec les "
    "symptômes décrits, et citer titre/date/score des résultats retenus "
    "(ignore ceux sous 0,6). Vérifie ensuite par la mesure (PromQL, "
    "kubectl, logs) avant de conclure — un incident passé est une piste, "
    "jamais une preuve. Réponds en français, en citant tes mesures.\n\n"
    "QUESTION : ")

PAGE = """<!doctype html><html lang="fr"><head><meta charset="utf-8">
<title>Console SRE — Agent HolmesGPT</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root{
    --bg:#0b0f1a; --panel:#121828; --panel2:#0e1422; --line:#232d47;
    --ink:#e8ecf6; --muted:#8b95ad; --acc:#5b8cff; --acc2:#7aa2f7;
    --green:#34d399; --amber:#fbbf24; --red:#f87171; --purple:#a78bfa;
  }
  *{box-sizing:border-box;margin:0}
  body{font-family:"Segoe UI",system-ui,sans-serif;background:
       radial-gradient(1100px 500px at 80% -10%, #17203a 0%, var(--bg) 55%);
       color:var(--ink);height:100vh;display:flex;flex-direction:column}
  header{display:flex;align-items:center;gap:.8rem;padding:.7rem 1.2rem;
       border-bottom:1px solid var(--line);background:rgba(11,15,26,.7);
       backdrop-filter:blur(6px)}
  header .logo{font-size:1.4rem}
  header h1{font-size:1.02rem;font-weight:650;letter-spacing:.2px}
  header h1 span{color:var(--acc2)}
  header .status{margin-left:auto;display:flex;gap:1rem;font-size:.78rem;
       color:var(--muted)}
  .dot{display:inline-block;width:.55em;height:.55em;border-radius:50%;
       background:var(--green);margin-right:.35em;vertical-align:middle}
  .layout{flex:1;display:grid;grid-template-columns:1fr 360px;gap:0;
       min-height:0}
  @media(max-width:980px){.layout{grid-template-columns:1fr}aside{display:none}}

  /* ---- colonne chat ---- */
  .chat{display:flex;flex-direction:column;min-height:0}
  #log{flex:1;overflow-y:auto;padding:1.2rem 1.4rem;display:flex;
       flex-direction:column;gap:.9rem}
  .msg{max-width:76%;padding:.75rem 1rem;border-radius:14px;line-height:1.55;
       font-size:.92rem;white-space:pre-wrap;word-wrap:break-word}
  .msg.user{align-self:flex-end;background:linear-gradient(135deg,#2b4a9e,#3757b8);
       border-bottom-right-radius:4px}
  .msg.agent{align-self:flex-start;background:var(--panel);
       border:1px solid var(--line);border-bottom-left-radius:4px}
  .msg.agent.err{border-color:var(--red);color:#fecaca}
  .meta{align-self:flex-start;display:flex;gap:.6rem;align-items:center;
       font-size:.72rem;color:var(--muted);margin:-.4rem 0 0 .4rem}
  .meta.user{align-self:flex-end;margin-right:.4rem}
  .chip{border:1px solid var(--line);border-radius:10px;padding:.05em .55em}
  .copy{cursor:pointer;color:var(--acc2);background:none;border:none;
       font-size:.72rem;padding:0}
  .copy:hover{text-decoration:underline}
  .thinking{align-self:flex-start;color:var(--muted);font-size:.85rem;
       display:flex;align-items:center;gap:.6rem;padding:.4rem .6rem}
  .spinner{width:14px;height:14px;border:2px solid var(--line);
       border-top-color:var(--acc);border-radius:50%;
       animation:spin 0.9s linear infinite}
  @keyframes spin{to{transform:rotate(360deg)}}

  .composer{border-top:1px solid var(--line);background:var(--panel2);
       padding:.8rem 1.2rem}
  .composer textarea{width:100%;min-height:64px;max-height:180px;resize:vertical;
       padding:.65rem .8rem;border-radius:10px;border:1px solid var(--line);
       background:var(--panel);color:var(--ink);font-size:.92rem;
       font-family:inherit;outline:none}
  .composer textarea:focus{border-color:var(--acc)}
  .bar{display:flex;gap:.6rem;align-items:center;margin-top:.55rem}
  select,button.primary{padding:.5rem .9rem;border-radius:9px;
       border:1px solid var(--line);background:var(--panel);color:var(--ink);
       font-size:.85rem}
  button.primary{background:linear-gradient(135deg,#2b4a9e,#3f66d4);
       border:none;cursor:pointer;font-weight:600;padding:.5rem 1.3rem}
  button.primary:disabled{opacity:.45;cursor:wait}
  .hint{color:var(--muted);font-size:.74rem;margin-left:auto}
  .examples{display:flex;gap:.5rem;flex-wrap:wrap;margin-top:.5rem}
  .ex{font-size:.74rem;color:var(--acc2);border:1px solid var(--line);
       border-radius:12px;padding:.15em .7em;cursor:pointer;background:none}
  .ex:hover{border-color:var(--acc)}

  /* ---- panneau mémoire ---- */
  aside{border-left:1px solid var(--line);background:var(--panel2);
       display:flex;flex-direction:column;min-height:0}
  aside h2{font-size:.85rem;font-weight:650;padding:.9rem 1rem .4rem;
       color:var(--purple)}
  aside .sub{font-size:.72rem;color:var(--muted);padding:0 1rem .6rem}
  .ragbar{display:flex;gap:.5rem;padding:0 1rem .6rem}
  .ragbar input{flex:1;padding:.5rem .7rem;border-radius:9px;
       border:1px solid var(--line);background:var(--panel);color:var(--ink);
       font-size:.83rem;outline:none}
  .ragbar input:focus{border-color:var(--purple)}
  .ragbar button{padding:.5rem .8rem;border-radius:9px;border:none;
       background:#6b46c1;color:#fff;font-size:.8rem;cursor:pointer}
  #ragout{flex:1;overflow-y:auto;padding:0 1rem 1rem;display:flex;
       flex-direction:column;gap:.6rem}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:10px;
       padding:.6rem .7rem;font-size:.78rem}
  .card .t{font-weight:600;margin-bottom:.25rem}
  .card .v{color:var(--muted);line-height:1.45}
  .badges{display:flex;gap:.4rem;margin-top:.4rem;flex-wrap:wrap}
  .badge{font-size:.68rem;border-radius:9px;padding:.08em .5em;font-weight:600}
  .b-score{background:#123c2b;color:var(--green)}
  .b-pm{background:#2a1f47;color:var(--purple)}
  .b-diag{background:#1c2a4a;color:var(--acc2)}
  .b-sev{background:#3a1a1a;color:var(--red)}
</style></head><body>
<header>
  <div class="logo">🤖</div>
  <h1>Console SRE — <span>Agent HolmesGPT</span></h1>
  <div class="status">
    <span><span class="dot"></span>Holmes</span>
    <span><span class="dot" style="background:var(--purple)"></span>Mémoire RAG</span>
  </div>
</header>
<div class="layout">
  <div class="chat">
    <div id="log">
      <div class="msg agent">Bienvenue 👋 — pose une question d'enquête à l'agent
(PromQL sli:/slo:, kubectl, logs Loki, traces Tempo, mémoire des incidents).
Une enquête ReAct prend 1 à 3 minutes et consomme du quota LLM.
Pour chercher un incident passé SANS consommer de quota, utilise le panneau
« Mémoire des incidents » à droite.</div>
    </div>
    <div class="composer">
      <textarea id="q" placeholder="Pose ta question d'enquête…"></textarea>
      <div class="bar">
        <select id="model">
          <option value="gemini-flash">gemini-flash (principal)</option>
          <option value="gemini-flash-31">gemini-flash-31 (secours)</option>
          <option value="groq-llama70b">groq-llama70b (dernier recours)</option>
        </select>
        <button class="primary" id="go" onclick="ask()">Enquêter</button>
        <span class="hint">Ctrl+Entrée pour envoyer</span>
      </div>
      <div class="examples">
        <button class="ex" onclick="fill('Le SLI checkout est-il conforme à son SLO 99,95 % en ce moment ?')">SLI checkout</button>
        <button class="ex" onclick="fill('Cette panne a-t-elle déjà eu lieu : erreurs gRPC UNAVAILABLE, pods pourtant Running ? Quel remède avait fonctionné ?')">récidive ?</button>
        <button class="ex" onclick="fill('Analyse les traces Tempo des requêtes checkout de la dernière heure : quel service consomme le plus de temps ?')">traces lentes</button>
        <button class="ex" onclick="fill('Quel est l état des budgets d erreur des 4 SLO et lequel se dégrade le plus vite ?')">budgets d'erreur</button>
      </div>
    </div>
  </div>
  <aside>
    <h2>🧠 Mémoire des incidents</h2>
    <div class="sub">Recherche sémantique directe dans Qdrant — instantanée,
    zéro quota LLM. Les post-mortems (cause confirmée) sont classés en tête.</div>
    <div class="ragbar">
      <input id="ragq" placeholder="symptômes… ex : erreurs gRPC vers payment"
             onkeydown="if(event.key==='Enter')ragSearch()">
      <button onclick="ragSearch()">Chercher</button>
    </div>
    <div id="ragout"></div>
  </aside>
</div>
<script>
const log=document.getElementById('log');
function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}
function fill(t){document.getElementById('q').value=t;document.getElementById('q').focus()}
function bubble(cls,text){const m=document.createElement('div');
  m.className='msg '+cls;m.textContent=text;log.appendChild(m);
  log.scrollTop=log.scrollHeight;return m}
function meta(cls,html){const d=document.createElement('div');
  d.className='meta '+cls;d.innerHTML=html;log.appendChild(d);
  log.scrollTop=log.scrollHeight;return d}
async function ask(){
  const q=document.getElementById('q').value.trim();if(!q)return;
  const b=document.getElementById('go'),model=document.getElementById('model').value;
  document.getElementById('q').value='';b.disabled=true;
  bubble('user',q);meta('user','<span class="chip">'+esc(model)+'</span>');
  const th=document.createElement('div');th.className='thinking';
  th.innerHTML='<div class="spinner"></div><span id="tm">enquête ReAct en cours… 0 s</span>';
  log.appendChild(th);log.scrollTop=log.scrollHeight;
  let s=0;const t=setInterval(()=>{const e=document.getElementById('tm');
    if(e)e.textContent='enquête ReAct en cours… '+(++s)+' s'},1000);
  try{
    const r=await fetch('/ask',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({ask:q,model:model})});
    const j=await r.json();
    th.remove();clearInterval(t);
    const txt=j.analysis||j.response||j.detail||JSON.stringify(j,null,2);
    const ok=!!(j.analysis||j.response);
    bubble('agent'+(ok?'':' err'),txt);
    const m=meta('',`<span class="chip">⏱ ${s}s</span>`);
    const c=document.createElement('button');c.className='copy';
    c.textContent='copier';c.onclick=()=>{navigator.clipboard.writeText(txt);
      c.textContent='copié ✓';setTimeout(()=>c.textContent='copier',1500)};
    m.appendChild(c);
  }catch(e){th.remove();clearInterval(t);bubble('agent err','Erreur : '+e)}
  b.disabled=false;
}
async function ragSearch(){
  const q=document.getElementById('ragq').value.trim();if(!q)return;
  const out=document.getElementById('ragout');
  out.innerHTML='<div class="card"><div class="v">recherche…</div></div>';
  try{
    const r=await fetch('/rag',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({query:q,k:5})});
    const docs=await r.json();
    if(!Array.isArray(docs)||!docs.length){
      out.innerHTML='<div class="card"><div class="v">aucun résultat</div></div>';return}
    out.innerHTML='';
    for(const d of docs){
      const c=document.createElement('div');c.className='card';
      const type=d.type==='postmortem'
        ?'<span class="badge b-pm">📋 post-mortem</span>'
        :'<span class="badge b-diag">🤖 diagnostic</span>';
      const sev=(d.tags||[]).includes('critical')
        ?'<span class="badge b-sev">critical</span>':'';
      c.innerHTML='<div class="t">'+esc(d.title||'?')+'</div>'
        +'<div class="v">'+esc((d.verdict||'').slice(0,220))+'</div>'
        +'<div class="badges"><span class="badge b-score">score '
        +(d.score??'?')+'</span>'+type+sev+'</div>';
      out.appendChild(c);
    }
  }catch(e){out.innerHTML='<div class="card"><div class="v">Erreur : '
    +esc(String(e))+'</div></div>'}
}
document.getElementById('q').addEventListener('keydown',e=>{
  if(e.key==='Enter'&&(e.ctrlKey||e.metaKey))ask()});
</script></body></html>"""


def _forward(url, payload, timeout):
    req = urllib.request.Request(
        url, data=payload, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        return e.read()          # relaie l'erreur telle quelle (ex. 429)


class Handler(BaseHTTPRequestHandler):
    def _send(self, body, ctype="application/json; charset=utf-8", code=200):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(PAGE.encode(), "text/html; charset=utf-8")
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            payload = self.rfile.read(length)
            if self.path == "/ask":
                try:   # préfixe la consigne mémoire (correctif T6.1)
                    data = json.loads(payload)
                    if data.get("ask"):
                        data["ask"] = CONSOLE_PREAMBLE + data["ask"]
                    payload = json.dumps(data, ensure_ascii=False).encode()
                except Exception:
                    pass
                self._send(_forward(f"{HOLMES_URL}/api/chat", payload,
                                    TIMEOUT_S))
            elif self.path == "/rag":
                self._send(_forward(f"{RAG_URL}/search", payload, 30))
            else:
                self.send_response(404)
                self.end_headers()
        except Exception as e:
            self._send(json.dumps(
                {"detail": f"console error: {e}"}).encode())

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print(f"[console] http://localhost:{PORT} -> holmes={HOLMES_URL} "
          f"rag={RAG_URL}", flush=True)
    ThreadingHTTPServer(("", PORT), Handler).serve_forever()


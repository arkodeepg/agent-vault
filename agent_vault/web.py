
from __future__ import annotations

import json
import os
import shlex
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

from . import core

HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Agent Vault</title>
  <link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Cdefs%3E%3ClinearGradient id='g' x1='12' y1='8' x2='52' y2='58'%3E%3Cstop stop-color='%2366d9a6'/%3E%3Cstop offset='1' stop-color='%232c7be5'/%3E%3C/linearGradient%3E%3C/defs%3E%3Crect width='64' height='64' rx='16' fill='%230b0f14'/%3E%3Cpath d='M22 28v-7c0-6 4.7-11 10-11s10 5 10 11v7' fill='none' stroke='url(%23g)' stroke-width='5' stroke-linecap='round'/%3E%3Crect x='16' y='26' width='32' height='27' rx='8' fill='url(%23g)'/%3E%3Ccircle cx='32' cy='39' r='4' fill='%230b0f14'/%3E%3Cpath d='M32 42v5' stroke='%230b0f14' stroke-width='4' stroke-linecap='round'/%3E%3C/svg%3E" />
  <style>
    :root { color-scheme: dark; --bg:#080c11; --panel:#111821; --panel2:#0d131b; --text:#e6edf3; --muted:#8b98a5; --line:#253246; --accent:#66d9a6; --accent2:#2c7be5; --shadow:0 18px 60px rgba(0,0,0,.35); }
    * { box-sizing: border-box; }
    body { margin:0; background:radial-gradient(circle at top left, rgba(102,217,166,.10), transparent 30%), var(--bg); color:var(--text); font:14px/1.45 system-ui, -apple-system, Segoe UI, sans-serif; }
    header { display:flex; align-items:center; justify-content:space-between; padding:18px 22px; border-bottom:1px solid var(--line); background:rgba(13,19,26,.92); backdrop-filter: blur(14px); position:sticky; top:0; z-index:2; }
    .brand { display:flex; align-items:center; gap:12px; }
    .logo { width:34px; height:34px; border-radius:10px; display:grid; place-items:center; background:linear-gradient(135deg,var(--accent),var(--accent2)); box-shadow:0 10px 30px rgba(44,123,229,.25); }
    .logo svg { width:21px; height:21px; color:#071018; }
    h1 { margin:0; font-size:18px; letter-spacing:0; }
    .subhead { color:var(--muted); font-size:12px; margin-top:1px; }
    main { display:grid; grid-template-columns: 360px 1fr; min-height:calc(100vh - 62px); }
    aside { border-right:1px solid var(--line); padding:16px; background:var(--panel2); }
    section { padding:18px; }
    input, textarea, select { width:100%; background:#0a1017; border:1px solid var(--line); color:var(--text); border-radius:6px; padding:10px; font:inherit; }
    textarea { min-height:74px; resize:vertical; }
    button { background:#172231; color:var(--text); border:1px solid var(--line); border-radius:6px; padding:9px 11px; cursor:pointer; font:inherit; }
    button:hover { border-color:#3b4e65; }
    button.primary { background:#123326; border-color:#1f7a50; color:#dffbed; }
    .danger { border-color:#7a3a34; background:#261412; color:#ffd8d2; }
    .alert { color:#ffe4e1; border:1px solid #8f2f2a; background:#2b1010; border-radius:8px; padding:10px; font-weight:700; }
    .grid { display:grid; gap:10px; }
    .row { display:flex; gap:8px; align-items:center; }
    .row > * { flex:1; }
    .toolbar { display:flex; gap:8px; align-items:center; }
    .card { border:1px solid var(--line); border-radius:8px; background:linear-gradient(180deg, rgba(255,255,255,.025), rgba(255,255,255,0)), var(--panel); padding:12px; margin-bottom:10px; box-shadow:var(--shadow); }
    .item { cursor:pointer; }
    .item.active { border-color:#2f8f63; }
    .name { font-weight:700; }
    .meta { color:var(--muted); font-size:12px; margin-top:4px; }
    .comment { margin-top:8px; color:#c8d1da; }
    .pill { display:inline-block; border:1px solid var(--line); border-radius:999px; padding:2px 7px; margin:2px 3px 0 0; color:#b9c4ce; font-size:12px; }
    .status { color:var(--muted); white-space:pre-wrap; }
    .tabs { display:flex; gap:8px; margin-bottom:14px; }
    .tabs button.active { border-color:#2f8f63; color:var(--accent); }
    .hidden { display:none; }
    pre { background:#080d12; border:1px solid var(--line); border-radius:8px; padding:12px; overflow:auto; max-height:300px; }
    label { color:var(--muted); font-size:12px; }
    @media (max-width: 860px) { main { grid-template-columns:1fr; } aside { border-right:0; border-bottom:1px solid var(--line); } }
  </style>
</head>
<body>
<header>
  <div class="brand">
    <div class="logo" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none"><path d="M7 10V7a5 5 0 0 1 10 0v3" stroke="currentColor" stroke-width="2.3" stroke-linecap="round"/><rect x="5" y="10" width="14" height="10" rx="3" fill="currentColor"/><circle cx="12" cy="15" r="1.4" fill="#66d9a6"/></svg></div>
    <div><h1>Agent Vault</h1><div class="subhead">Private command and secret vault</div></div>
  </div>
  <div class="toolbar"><button id="copyDocs">Copy agent docs</button><button id="refresh">Refresh</button></div>
</header>
<main>
  <aside>
    <input id="search" placeholder="Search names, comments, tags" autocomplete="off" />
    <div class="row" style="margin-top:10px"><select id="typeFilter"><option value="">All types</option><option>secret</option><option>command</option><option>note</option></select><button id="showAll">All</button></div>
    <div id="items" style="margin-top:14px"></div>
  </aside>
  <section>
    <div class="tabs"><button data-tab="details" class="active">Details</button><button data-tab="add">Add</button><button data-tab="command">Command</button><button data-tab="master">Master key</button><button data-tab="audit">Audit</button></div>
    <div id="msg" class="status"></div>
    <div id="details" class="tab"></div>
    <div id="add" class="tab hidden card grid">
      <div><label>Name</label><input id="addName" /></div>
      <div><label>Value</label><textarea id="addValue"></textarea></div>
      <div><label>Comment</label><textarea id="addComment"></textarea></div>
      <div><label>Tags, comma separated</label><input id="addTags" /></div>
      <button class="primary" id="addBtn">Add item</button>
    </div>
    <div id="command" class="tab hidden card grid">
      <div><label>Name</label><input id="cmdName" /></div>
      <div><label>Command</label><textarea id="cmdValue" placeholder="python -c 'print(123)'"></textarea></div>
      <div><label>Uses, comma separated secret names</label><input id="cmdUses" /></div>
      <div><label>Comment</label><textarea id="cmdComment"></textarea></div>
      <button class="primary" id="cmdAdd">Add command</button>
    </div>
    <div id="master" class="tab hidden card grid">
      <div id="masterWarn" class="alert hidden">Default master key is password. Please change it, for fuck's sake.</div>
      <div><label>Current master key</label><input id="currentMaster" type="password" autocomplete="current-password" /></div>
      <div><label>New master key</label><input id="newMaster" type="password" autocomplete="new-password" /></div>
      <div><label>Repeat new master key</label><input id="repeatMaster" type="password" autocomplete="new-password" /></div>
      <button class="danger" id="changeMaster">Update master key</button>
    </div>
    <div id="audit" class="tab hidden"><pre id="auditBox"></pre></div>
  </section>
</main>
<script>
let state = { items: [], selected: null, all: false, status: null };
const $ = id => document.getElementById(id);
function tags(v){ return (v||'').split(',').map(x=>x.trim()).filter(Boolean); }
async function api(path, opts={}){ const res = await fetch(path, {headers:{'content-type':'application/json'}, ...opts}); const text = await res.text(); let data; try { data = text ? JSON.parse(text) : {}; } catch { data = {text}; } if(!res.ok) throw new Error(data.error || text || res.statusText); return data; }
function setMsg(m){ $('msg').textContent = m || ''; }
function esc(s){ return String(s||'').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function renderItems(){ const q = $('search').value.toLowerCase(); const tf = $('typeFilter').value; const rows = state.items.filter(i => (!tf || i.type===tf) && JSON.stringify(i).toLowerCase().includes(q)); $('items').innerHTML = rows.map(i => `<div class="card item ${state.selected===i.name?'active':''}" data-name="${esc(i.name)}"><div class="name">${esc(i.name)}</div><div class="meta">${esc(i.type)}${i.archived?' archived':''} | uses ${esc((i.uses||[]).join(',')||'-')}</div><div>${(i.tags||[]).map(t=>`<span class="pill">${esc(t)}</span>`).join('')}</div><div class="comment">${esc(i.comment||'')}</div></div>`).join('') || '<div class="status">No items</div>'; document.querySelectorAll('.item').forEach(el => el.onclick = () => { state.selected = el.dataset.name; render(); }); }
function selected(){ return state.items.find(i=>i.name===state.selected); }
function renderDetails(){ const i = selected(); if(!i){ $('details').innerHTML = '<div class="card status">Select an item or add a new one.</div>'; return; } $('details').innerHTML = `<div class="card grid"><div><label>Name</label><input id="editName" value="${esc(i.name)}" /></div><div><label>Comment</label><textarea id="editComment">${esc(i.comment||'')}</textarea></div><div><label>Tags</label><input id="editTags" value="${esc((i.tags||[]).join(','))}" /></div><div><label>New value, optional</label><textarea id="editValue" placeholder="Leave empty to keep existing value"></textarea></div><div class="row"><button class="primary" id="saveEdit">Save</button><button id="archiveBtn">${i.archived?'Restore':'Archive'}</button>${i.type==='command'?'<button id="runCmd">Run command</button>':''}</div></div><pre id="runOut"></pre>`; $('saveEdit').onclick = saveEdit; $('archiveBtn').onclick = toggleArchive; if($('runCmd')) $('runCmd').onclick = runCommand; }
function renderMasterWarning(){ const active = state.status?.password_source?.default_password_active === true; $('masterWarn').classList.toggle('hidden', !active); }
function render(){ renderItems(); renderDetails(); renderMasterWarning(); }
async function load(){ const qs = state.all ? '?all=1' : ''; const [items,status] = await Promise.all([api('/api/items'+qs), api('/api/status')]); state.items = items; state.status = status; if(state.selected && !state.items.find(i=>i.name===state.selected)) state.selected=null; render(); }
async function saveEdit(){ const i = selected(); const body = {comment:$('editComment').value, tags:tags($('editTags').value)}; if($('editName').value !== i.name) body.name = $('editName').value; if($('editValue').value) body.value = $('editValue').value; const r = await api('/api/items/'+encodeURIComponent(i.name), {method:'PATCH', body:JSON.stringify(body)}); state.selected = r.name; setMsg('Saved'); await load(); }
async function toggleArchive(){ const i=selected(); await api('/api/items/'+encodeURIComponent(i.name)+'/'+(i.archived?'restore':'archive'), {method:'POST'}); setMsg(i.archived?'Restored':'Archived'); await load(); }
async function runCommand(){ const i=selected(); const r=await api('/api/commands/'+encodeURIComponent(i.name)+'/run', {method:'POST'}); $('runOut').textContent = `exit ${r.code}\n${r.out}${r.err}`; }
$('addBtn').onclick = async()=>{ await api('/api/items',{method:'POST', body:JSON.stringify({name:$('addName').value,type:'secret',value:$('addValue').value,comment:$('addComment').value,tags:tags($('addTags').value)})}); setMsg('Added'); await load(); };
$('cmdAdd').onclick = async()=>{ await api('/api/commands',{method:'POST', body:JSON.stringify({name:$('cmdName').value,command:$('cmdValue').value,uses:tags($('cmdUses').value),comment:$('cmdComment').value})}); setMsg('Command added'); await load(); };
$('changeMaster').onclick = async()=>{ if($('newMaster').value !== $('repeatMaster').value){ setMsg('New master keys do not match'); return; } await api('/api/master-key',{method:'POST', body:JSON.stringify({current_password:$('currentMaster').value,new_password:$('newMaster').value})}); $('currentMaster').value=''; $('newMaster').value=''; $('repeatMaster').value=''; setMsg('Master key updated'); await load(); };
$('refresh').onclick = load; $('search').oninput = renderItems; $('typeFilter').onchange = renderItems; $('showAll').onclick=async()=>{state.all=!state.all; $('showAll').textContent=state.all?'Active':'All'; await load();};
document.querySelectorAll('[data-tab]').forEach(b=>b.onclick=async()=>{document.querySelectorAll('[data-tab]').forEach(x=>x.classList.remove('active')); b.classList.add('active'); document.querySelectorAll('.tab').forEach(x=>x.classList.add('hidden')); $(b.dataset.tab).classList.remove('hidden'); if(b.dataset.tab==='audit') $('auditBox').textContent=JSON.stringify(await api('/api/audit'),null,2);});
$('copyDocs').onclick = async()=>{ const t=await fetch('/api/agent-docs').then(r=>r.text()); await navigator.clipboard.writeText(t); setMsg('Agent documentation copied'); };
load().catch(e=>setMsg(e.message));
</script>
</body>
</html>"""


def json_response(handler: BaseHTTPRequestHandler, status: int, payload: object) -> None:
    body = json.dumps(payload).encode()
    handler.send_response(status)
    handler.send_header("content-type", "application/json")
    handler.send_header("content-length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class Handler(BaseHTTPRequestHandler):
    server_version = "AgentVaultWeb/0.1"

    def log_message(self, fmt: str, *args: object) -> None:
        if os.environ.get("S_WEB_LOG") == "1":
            super().log_message(fmt, *args)

    def read_json(self) -> dict:
        n = int(self.headers.get("content-length", "0"))
        if n > 1024 * 1024:
            raise core.VaultError("request body too large")
        raw = self.rfile.read(n).decode() if n else "{}"
        return json.loads(raw or "{}")

    def send_html(self) -> None:
        body = HTML.encode()
        self.send_response(200)
        self.send_header("content-type", "text/html; charset=utf-8")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_text(self, text: str) -> None:
        body = text.encode()
        self.send_response(200)
        self.send_header("content-type", "text/plain; charset=utf-8")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def handle_error(self, exc: Exception) -> None:
        json_response(self, 400, {"error": str(exc)})

    def do_GET(self) -> None:
        try:
            parsed = urlparse(self.path)
            if parsed.path == "/":
                return self.send_html()
            if parsed.path == "/api/items":
                include_all = "all=1" in parsed.query
                return json_response(self, 200, core.list_items(include_all=include_all))
            if parsed.path == "/api/audit":
                return json_response(self, 200, core.audit_rows())
            if parsed.path == "/api/agent-docs":
                doc = Path(__file__).resolve().parents[1] / "docs" / "AGENT_README.md"
                return self.send_text(doc.read_text())
            if parsed.path == "/api/status":
                return json_response(self, 200, core.status())
            json_response(self, 404, {"error": "not found"})
        except Exception as exc:
            self.handle_error(exc)

    def do_POST(self) -> None:
        try:
            path = urlparse(self.path).path
            if path == "/api/items":
                body = self.read_json()
                core.add_item(body.get("name", ""), body.get("value", ""), item_type=body.get("type", "secret"), comment=body.get("comment", ""), tags=body.get("tags", []))
                return json_response(self, 200, {"ok": True})
            if path == "/api/commands":
                body = self.read_json()
                cmd = shlex.split(body.get("command", ""))
                core.add_command(body.get("name", ""), cmd, comment=body.get("comment", ""), tags=body.get("tags", []), uses=body.get("uses", []))
                return json_response(self, 200, {"ok": True})
            if path.startswith("/api/items/") and path.endswith("/archive"):
                name = unquote(path.split("/")[3])
                core.archive_item(name, True)
                return json_response(self, 200, {"ok": True})
            if path.startswith("/api/items/") and path.endswith("/restore"):
                name = unquote(path.split("/")[3])
                core.archive_item(name, False)
                return json_response(self, 200, {"ok": True})
            if path.startswith("/api/commands/") and path.endswith("/run"):
                name = unquote(path.split("/")[3])
                result = core.run_command(name)
                return json_response(self, 200, {"code": result.code, "out": result.out, "err": result.err})
            if path == "/api/backup":
                body = self.read_json()
                return json_response(self, 200, {"path": core.backup(body.get("to"))})
            if path == "/api/master-key":
                body = self.read_json()
                core.rotate_password(body.get("current_password", ""), body.get("new_password", ""))
                return json_response(self, 200, {"ok": True})
            json_response(self, 404, {"error": "not found"})
        except Exception as exc:
            self.handle_error(exc)

    def do_PATCH(self) -> None:
        try:
            path = urlparse(self.path).path
            if path.startswith("/api/items/"):
                name = unquote(path.split("/")[3])
                body = self.read_json()
                final = core.update_item(name, value=body.get("value") or None, comment=body.get("comment"), new_name=body.get("name"), tags=body.get("tags"))
                return json_response(self, 200, {"ok": True, "name": final})
            json_response(self, 404, {"error": "not found"})
        except Exception as exc:
            self.handle_error(exc)


def run(host: str = "127.0.0.1", port: int = 8787) -> None:
    if host == "0.0.0.0":
        print("warning: binding to 0.0.0.0 exposes Agent Vault beyond localhost", flush=True)
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"Agent Vault web UI listening on http://{host}:{port}", flush=True)
    httpd.serve_forever()

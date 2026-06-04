
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
    :root { color-scheme: dark; --bg:#141514; --panel:#1d1e1d; --panel2:#181918; --panel3:#222322; --text:#eee9e1; --muted:#96938d; --line:#30322f; --line2:#3c3e3a; --accent:#6f58ff; --accent2:#38a169; --warm:#b89563; --danger:#d56b61; --shadow:0 8px 24px rgba(0,0,0,.18); --space-2xs:4px; --space-xs:8px; --space-sm:12px; --space-md:16px; --space-lg:24px; }
    * { box-sizing: border-box; }
    body { margin:0; background:var(--bg); color:var(--text); font:13px/1.45 system-ui, -apple-system, Segoe UI, sans-serif; }
    header { display:flex; align-items:center; justify-content:space-between; padding:12px 18px; border-bottom:1px solid var(--line); background:#151615; position:sticky; top:0; z-index:2; }
    .brand { display:flex; align-items:center; gap:12px; }
    .logo { width:30px; height:30px; border-radius:7px; display:grid; place-items:center; background:linear-gradient(135deg,var(--accent2),var(--accent)); box-shadow:0 8px 18px rgba(0,0,0,.22); }
    .logo svg { width:21px; height:21px; color:#121312; }
    h1 { margin:0; font-size:15px; letter-spacing:0; }
    .subhead { color:var(--muted); font-size:11px; margin-top:1px; }
    main { display:grid; grid-template-columns:minmax(440px, 50%) minmax(420px, 50%); height:calc(100vh - 55px); min-height:620px; }
    aside { border-right:1px solid var(--line); padding:var(--space-sm); background:var(--panel2); min-width:0; display:flex; flex-direction:column; overflow:hidden; }
    section { padding:var(--space-sm) var(--space-md); background:#191a19; min-width:0; overflow:auto; }
    input, textarea, select { width:100%; background:#151615; border:1px solid var(--line); color:var(--text); border-radius:5px; padding:8px 9px; font:inherit; }
    textarea { min-height:70px; resize:vertical; }
    button { background:#20211f; color:var(--text); border:1px solid var(--line2); border-radius:5px; padding:8px 10px; cursor:pointer; font:inherit; }
    button:hover { border-color:#5a5c58; background:#262824; }
    button.primary { background:#5944df; border-color:#7563ff; color:#f4f1ff; }
    .danger { border-color:#7a3a34; background:#261412; color:#ffd8d2; }
    .alert { color:#ffe4e1; border:1px solid #8f2f2a; background:#2b1010; border-radius:8px; padding:10px; font-weight:700; }
    .grid { display:grid; gap:var(--space-sm); }
    .row { display:flex; gap:8px; align-items:center; }
    .row > * { flex:1; }
    .toolbar { display:flex; gap:8px; align-items:center; }
    .card { border:1px solid var(--line); border-radius:7px; background:var(--panel); padding:var(--space-sm); margin-bottom:var(--space-sm); box-shadow:var(--shadow); }
    .sidebar-title { margin:var(--space-sm) 0 var(--space-xs); color:#76736e; font-size:10px; font-weight:700; letter-spacing:.08em; text-transform:uppercase; }
    .index-controls { flex:0 0 auto; padding-bottom:var(--space-xs); border-bottom:1px solid var(--line); }
    .items-list { flex:1 1 auto; min-height:0; overflow:auto; margin-top:var(--space-xs); border-top:1px solid #242623; }
    .item { cursor:pointer; box-shadow:none; display:grid; grid-template-columns:14px minmax(150px, 1.1fr) minmax(170px, .9fr); column-gap:8px; align-items:start; padding:9px 8px; margin-bottom:0; border-radius:0; border-width:0 0 1px; }
    .item.active { border-color:var(--accent); background:#26243a; }
    .item-check { width:11px; height:11px; border:1px solid var(--line2); border-radius:2px; margin-top:3px; }
    .item.active .item-check { background:var(--accent); border-color:var(--accent); box-shadow:inset 0 0 0 2px #26243a; }
    .name { font-weight:700; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    .meta { color:var(--muted); font-size:11px; margin-top:3px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    .comment { color:#d4cfc7; font-size:12px; line-height:1.35; display:-webkit-box; -webkit-line-clamp:2; -webkit-box-orient:vertical; overflow:hidden; }
    .pill { display:inline-block; border:1px solid #3e443f; border-radius:999px; padding:1px 6px; margin:3px 3px 0 0; color:#bfe5cc; font-size:10px; background:#1d2b22; }
    .pill.type { color:#d7d1ff; border-color:#403a6f; background:#26233f; }
    .pill.archived { color:#f0c6bf; border-color:#63403a; background:#33201d; }
    .status { color:var(--muted); white-space:pre-wrap; }
    .tabs { display:flex; gap:6px; margin-bottom:var(--space-sm); border-bottom:1px solid var(--line); padding-bottom:8px; position:sticky; top:0; z-index:1; background:#191a19; }
    .tabs button.active { border-color:var(--accent); color:#d8d1ff; background:#25223c; }
    .hidden { display:none; }
    pre { background:#151615; border:1px solid var(--line); border-radius:8px; padding:12px; overflow:auto; max-height:300px; }
    label { color:var(--muted); font-size:11px; font-weight:650; }
    .empty { padding:14px 8px; color:var(--muted); }
    .form-grid { display:grid; grid-template-columns:1fr 1fr; gap:var(--space-sm); }
    .form-grid .wide { grid-column:1 / -1; }
    @media (max-width: 1020px) { main { grid-template-columns:1fr; height:auto; min-height:calc(100vh - 55px); } aside { max-height:46vh; border-right:0; border-bottom:1px solid var(--line); } section { overflow:visible; } }
    @media (max-width: 640px) { header { align-items:flex-start; gap:10px; flex-direction:column; } main { min-height:calc(100vh - 98px); } .toolbar { flex-wrap:wrap; } .item { grid-template-columns:14px minmax(0, 1fr); } .comment { grid-column:2; margin-top:2px; } .form-grid { grid-template-columns:1fr; } }
  </style>
</head>
<body>
<header>
  <div class="brand">
    <div class="logo" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none"><path d="M7 10V7a5 5 0 0 1 10 0v3" stroke="currentColor" stroke-width="2.3" stroke-linecap="round"/><rect x="5" y="10" width="14" height="10" rx="3" fill="currentColor"/><circle cx="12" cy="15" r="1.4" fill="#6f58ff"/></svg></div>
    <div><h1>Agent Vault</h1><div class="subhead">Private command and secret vault</div></div>
  </div>
  <div class="toolbar"><button id="copyDocs">Copy agent docs</button><button id="refresh">Refresh</button><button id="exportCsv">Export CSV</button></div>
</header>
<main>
  <aside>
    <div class="index-controls">
      <div class="sidebar-title">Vault Index</div>
      <input id="search" placeholder="Search names, comments, tags" autocomplete="off" />
      <div class="row" style="margin-top:8px"><select id="typeFilter"><option value="">All types</option><option>secret</option><option>command</option><option>note</option></select><button id="showAll">All</button></div>
    </div>
    <div class="sidebar-title">Secrets & Commands</div>
    <div id="items" class="items-list"></div>
  </aside>
  <section>
    <div class="tabs"><button data-tab="details" class="active">Details</button><button data-tab="add">Add</button><button data-tab="command">Command</button><button data-tab="master">Master key</button><button data-tab="audit">Activity Log</button></div>
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
function hint(i){ return i.value_hint ? '...' + i.value_hint : '-'; }
function renderItems(){ const q = $('search').value.toLowerCase(); const tf = $('typeFilter').value; const rows = state.items.filter(i => (!tf || i.type===tf) && JSON.stringify(i).toLowerCase().includes(q)); $('items').innerHTML = rows.map(i => `<div class="item ${state.selected===i.name?'active':''}" data-name="${esc(i.name)}"><span class="item-check"></span><div><div class="name" title="${esc(i.name)}">${esc(i.name)}</div><div class="meta"><span class="pill type">${esc(i.type)}</span>${i.archived?'<span class="pill archived">archived</span>':''}${(i.tags||[]).slice(0,3).map(t=>`<span class="pill">${esc(t)}</span>`).join('')}</div><div class="meta">hint ${esc(hint(i))} · uses ${esc((i.uses||[]).join(',')||'-')}</div></div><div class="comment">${esc(i.comment||'')}</div></div>`).join('') || '<div class="empty">No items</div>'; document.querySelectorAll('.item').forEach(el => el.onclick = () => { state.selected = el.dataset.name; render(); }); }
function selected(){ return state.items.find(i=>i.name===state.selected); }
function renderDetails(){ const i = selected(); if(!i){ $('details').innerHTML = '<div class="card status">Select an item or add a new one.</div>'; return; } $('details').innerHTML = `<div class="card grid form-grid"><div><label>Name</label><input id="editName" value="${esc(i.name)}" /></div><div><label>Value hint</label><input value="${esc(hint(i))}" readonly /></div><div class="wide"><label>Comment</label><textarea id="editComment">${esc(i.comment||'')}</textarea></div><div><label>Tags</label><input id="editTags" value="${esc((i.tags||[]).join(','))}" /></div><div><label>New value, optional</label><textarea id="editValue" placeholder="Leave empty to keep existing value"></textarea></div><div class="row wide"><button class="primary" id="saveEdit">Save</button><button id="archiveBtn">${i.archived?'Restore':'Archive'}</button>${i.type==='command'?'<button id="runCmd">Run command</button>':''}</div></div><pre id="runOut"></pre>`; $('saveEdit').onclick = saveEdit; $('archiveBtn').onclick = toggleArchive; if($('runCmd')) $('runCmd').onclick = runCommand; }
function renderMasterWarning(){ const active = state.status?.password_source?.default_password_active === true; $('masterWarn').classList.toggle('hidden', !active); }
function render(){ renderItems(); renderDetails(); renderMasterWarning(); }
async function load(){ const qs = state.all ? '?all=1' : ''; const [items,status] = await Promise.all([api('/api/items'+qs), api('/api/status')]); state.items = items; state.status = status; if(state.selected && !state.items.find(i=>i.name===state.selected)) state.selected=null; render(); }
async function saveEdit(){ const i = selected(); const body = {comment:$('editComment').value, tags:tags($('editTags').value)}; if($('editName').value !== i.name) body.name = $('editName').value; if($('editValue').value) body.value = $('editValue').value; const r = await api('/api/items/'+encodeURIComponent(i.name), {method:'PATCH', body:JSON.stringify(body)}); state.selected = r.name; setMsg('Saved'); await load(); }
async function toggleArchive(){ const i=selected(); await api('/api/items/'+encodeURIComponent(i.name)+'/'+(i.archived?'restore':'archive'), {method:'POST'}); setMsg(i.archived?'Restored':'Archived'); await load(); }
async function runCommand(){ const i=selected(); const r=await api('/api/commands/'+encodeURIComponent(i.name)+'/run', {method:'POST'}); $('runOut').textContent = `exit ${r.code}\n${r.out}${r.err}`; }
async function exportCsv(){ const password = prompt('Master key required for CSV export'); if(!password) return; const res = await fetch('/api/export.csv', {method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({password})}); const text = await res.text(); if(!res.ok){ let err = text; try { err = JSON.parse(text).error || text; } catch {} setMsg(err); return; } const blob = new Blob([text], {type:'text/csv;charset=utf-8'}); const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = 'agent-vault-export.csv'; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url); setMsg('CSV exported'); }
$('addBtn').onclick = async()=>{ await api('/api/items',{method:'POST', body:JSON.stringify({name:$('addName').value,type:'secret',value:$('addValue').value,comment:$('addComment').value,tags:tags($('addTags').value)})}); setMsg('Added'); await load(); };
$('cmdAdd').onclick = async()=>{ await api('/api/commands',{method:'POST', body:JSON.stringify({name:$('cmdName').value,command:$('cmdValue').value,uses:tags($('cmdUses').value),comment:$('cmdComment').value})}); setMsg('Command added'); await load(); };
$('changeMaster').onclick = async()=>{ if($('newMaster').value !== $('repeatMaster').value){ setMsg('New master keys do not match'); return; } await api('/api/master-key',{method:'POST', body:JSON.stringify({current_password:$('currentMaster').value,new_password:$('newMaster').value})}); $('currentMaster').value=''; $('newMaster').value=''; $('repeatMaster').value=''; setMsg('Master key updated'); await load(); };
$('refresh').onclick = load; $('exportCsv').onclick = exportCsv; $('search').oninput = renderItems; $('typeFilter').onchange = renderItems; $('showAll').onclick=async()=>{state.all=!state.all; $('showAll').textContent=state.all?'Active':'All'; await load();};
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

    def send_csv(self, text: str) -> None:
        body = text.encode()
        self.send_response(200)
        self.send_header("content-type", "text/csv; charset=utf-8")
        self.send_header("content-disposition", 'attachment; filename="agent-vault-export.csv"')
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
            if path == "/api/export.csv":
                body = self.read_json()
                return self.send_csv(core.export_csv(body.get("password", "")))
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

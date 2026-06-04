import csv
import io
import json
import os
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent_vault import core
from agent_vault.web import Handler, HTML


def request(url, method="GET", payload=None, key="test-password"):
    data = None if payload is None else json.dumps(payload).encode()
    headers = {"content-type": "application/json"}
    if key is not None:
        headers["x-agent-vault-key"] = key
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=5) as res:
        body = res.read().decode()
        ctype = res.headers.get("content-type", "")
        return body if "json" not in ctype else json.loads(body)


def test_html_is_dark_and_has_copy_docs():
    assert "color-scheme: dark" in HTML
    assert "Copy agent docs" in HTML
    assert "Search names, comments, tags" in HTML
    assert 'rel="icon"' in HTML
    assert "Private command and secret vault" in HTML
    assert "Master key" in HTML
    assert "Export CSV" in HTML
    assert "Activity Log" in HTML
    assert "Unlock Agent Vault" in HTML
    assert "x-agent-vault-key" in HTML
    assert "grid-template-columns:minmax(440px, 50%) minmax(420px, 50%)" in HTML
    assert "items-list" in HTML
    assert "Please change it, for fuck's sake" in HTML
    assert "addType" not in HTML


def test_web_api_safe_routes(tmp_path, monkeypatch):
    monkeypatch.setenv("S_KEY", "test-password")
    monkeypatch.setenv("S_VAULT_PATH", str(tmp_path / "vault.senv"))
    core.init_vault()
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"
    try:
        html = request(base + "/")
        assert "Agent Vault" in html
        doc = urllib.request.urlopen(base + "/api/agent-docs", timeout=5).read().decode()
        assert "S_AGENT_MODE=1" in doc
        try:
            request(base + "/api/items", key=None)
            raise AssertionError("unauthenticated items request succeeded")
        except urllib.error.HTTPError as exc:
            assert exc.code == 400
        request(base + "/api/items", method="POST", payload={"name":"WEB_API_KEY","value":"test_web_fake_secret","comment":"Web fake, with comma","tags":["web"]})
        rows = request(base + "/api/items")
        assert rows[0]["name"] == "WEB_API_KEY"
        assert rows[0]["value_hint"] == "ret"
        assert "test_web_fake_secret" not in json.dumps(rows)
        req = urllib.request.Request(
            base + "/api/export.csv",
            data=json.dumps({"password": "test-password"}).encode(),
            method="POST",
            headers={"content-type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as res:
            assert "text/csv" in res.headers.get("content-type", "")
            csv_text = res.read().decode()
        parsed = list(csv.DictReader(io.StringIO(csv_text)))
        assert parsed[0]["name"] == "WEB_API_KEY"
        assert parsed[0]["value"] == "test_web_fake_secret"
        assert parsed[0]["value_hint"] == "ret"
        assert parsed[0]["comment"] == "Web fake, with comma"
        request(base + "/api/commands", method="POST", payload={"name":"WEB_PRINT","command": f"{sys.executable} -c 'import os; print(os.environ[\"WEB_API_KEY\"])'","uses":["WEB_API_KEY"],"comment":"Prints fake"})
        result = request(base + "/api/commands/WEB_PRINT/run", method="POST", payload={})
        assert result["out"].strip() == "[REDACTED]"
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_web_master_key_rotation_reencrypts_existing_values(tmp_path, monkeypatch):
    monkeypatch.delenv("S_KEY", raising=False)
    monkeypatch.setenv("S_KEY_FILE", str(tmp_path / "master.key"))
    monkeypatch.setenv("S_VAULT_PATH", str(tmp_path / "vault.senv"))
    core.init_vault()
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"
    try:
        request(base + "/api/items", method="POST", payload={"name":"ROTATE_KEY","value":"rotate_fake_secret","comment":"Rotate fake"}, key="password")
        request(base + "/api/master-key", method="POST", payload={"current_password":"password","new_password":"new-test-password"})
        assert (tmp_path / "master.key").read_text().strip() == "new-test-password"
        code = f"{sys.executable} -c 'import os; print(os.environ[\"ROTATE_KEY\"])'"
        request(base + "/api/commands", method="POST", payload={"name":"ROTATE_PRINT","command": code,"uses":["ROTATE_KEY"],"comment":"Prints rotated fake"}, key="new-test-password")
        result = request(base + "/api/commands/ROTATE_PRINT/run", method="POST", payload={}, key="new-test-password")
        assert result["out"].strip() == "[REDACTED]"
    finally:
        server.shutdown()
        thread.join(timeout=5)

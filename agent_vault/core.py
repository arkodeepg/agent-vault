from __future__ import annotations

import base64
import copy
import datetime as dt
import getpass
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

VERSION = 1
DEFAULT_COMMENT_WORD_LIMIT = 180
SAFE_TYPES = {"secret", "command", "note"}
HUMAN_ONLY = {"get", "export", "delete", "purge", "rollback", "restore-backup"}


class VaultError(Exception):
    pass


@dataclass
class Result:
    code: int = 0
    out: str = ""
    err: str = ""


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def vault_path() -> Path:
    if os.environ.get("S_VAULT_PATH"):
        return Path(os.environ["S_VAULT_PATH"]).expanduser()
    if Path(".senv").exists():
        return Path(".senv")
    return Path.home() / ".config" / "agent-vault" / "vault.senv"


def is_agent_mode() -> bool:
    return os.environ.get("S_AGENT_MODE") == "1"


def require_not_agent(action: str) -> None:
    if is_agent_mode():
        raise VaultError(f"refusing to {action} in agent mode")


def require_tty(action: str) -> None:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise VaultError(f"refusing to {action} without an interactive terminal")


def get_password(prompt: str = "vault password: ") -> str:
    val = os.environ.get("S_KEY")
    if val:
        if val.startswith("!"):
            cmd = val[1:].strip()
            if not cmd:
                raise VaultError("empty S_KEY command")
            proc = subprocess.run(cmd, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if proc.returncode != 0:
                raise VaultError(f"S_KEY command failed: {proc.stderr.strip()}")
            pw = proc.stdout.strip()
            if not pw:
                raise VaultError("S_KEY command returned empty password")
            return pw
        return val
    require_tty("read vault password")
    return getpass.getpass(prompt)


def get_master_password() -> str:
    require_not_agent("perform human-only action")
    require_tty("perform human-only action")
    return getpass.getpass("master password: ")


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password.encode())


def encrypt_text(text: str, password: str) -> dict[str, str]:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(password, salt)
    ct = AESGCM(key).encrypt(nonce, text.encode(), None)
    return {
        "v": "scrypt-aesgcm-v1",
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ct": base64.b64encode(ct).decode(),
    }


def decrypt_text(blob: dict[str, str], password: str) -> str:
    if blob.get("v") != "scrypt-aesgcm-v1":
        raise VaultError("unsupported encrypted value version")
    salt = base64.b64decode(blob["salt"])
    nonce = base64.b64decode(blob["nonce"])
    ct = base64.b64decode(blob["ct"])
    key = derive_key(password, salt)
    try:
        return AESGCM(key).decrypt(nonce, ct, None).decode()
    except Exception as exc:
        raise VaultError("decryption failed, wrong password or corrupted vault") from exc


def empty_vault() -> dict[str, Any]:
    return {"version": VERSION, "items": {}, "audit": []}


def load_vault(path: Path | None = None) -> dict[str, Any]:
    path = path or vault_path()
    if not path.exists():
        raise VaultError(f"vault not found: {path}. run `s init`")
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise VaultError(f"vault is not valid JSON: {path}") from exc
    if data.get("version") != VERSION:
        raise VaultError(f"unsupported vault version: {data.get('version')}")
    data.setdefault("items", {})
    data.setdefault("audit", [])
    return data


def save_vault(data: dict[str, Any], path: Path | None = None) -> None:
    path = path or vault_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, indent=2, sort_keys=True) + "\n"
    with tempfile.NamedTemporaryFile("w", dir=str(path.parent), delete=False) as tmp:
        tmp.write(payload)
        tmp_path = Path(tmp.name)
    tmp_path.replace(path)
    try:
        path.chmod(0o600)
    except PermissionError:
        pass


def audit(data: dict[str, Any], action: str, name: str = "", ok: bool = True) -> None:
    data.setdefault("audit", []).append({
        "ts": now_iso(),
        "action": action,
        "name": name,
        "mode": "agent" if is_agent_mode() else "human-or-cli",
        "ok": ok,
    })
    data["audit"] = data["audit"][-200:]


def validate_name(name: str) -> None:
    if not name:
        raise VaultError("name is required")
    allowed = all(c.isalnum() or c == "_" for c in name)
    if not allowed or not (name[0].isalpha() or name[0] == "_"):
        raise VaultError("name must start with a letter or underscore and contain only letters, numbers, and underscores")


def validate_comment(comment: str) -> None:
    if len(comment.split()) > DEFAULT_COMMENT_WORD_LIMIT:
        raise VaultError(f"comment exceeds {DEFAULT_COMMENT_WORD_LIMIT} words")


def item_public(name: str, item: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": name,
        "type": item.get("type", "secret"),
        "comment": item.get("comment", ""),
        "tags": item.get("tags", []),
        "uses": item.get("uses", []),
        "archived": bool(item.get("archived", False)),
        "created_at": item.get("created_at", ""),
        "updated_at": item.get("updated_at", ""),
    }


def parse_tags(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [x.strip() for x in raw.split(",") if x.strip()]


def init_vault(force: bool = False) -> str:
    path = vault_path()
    if path.exists() and not force:
        raise VaultError(f"vault already exists: {path}")
    data = empty_vault()
    audit(data, "init")
    save_vault(data, path)
    return str(path)


def list_items(include_all: bool = False, type_filter: str | None = None, tag: str | None = None) -> list[dict[str, Any]]:
    data = load_vault()
    rows = []
    for name, item in sorted(data["items"].items()):
        if item.get("archived") and not include_all:
            continue
        if type_filter and item.get("type") != type_filter:
            continue
        if tag and tag not in item.get("tags", []):
            continue
        rows.append(item_public(name, item))
    return rows


def add_item(name: str, value: str, item_type: str = "secret", comment: str = "", tags: list[str] | None = None, uses: list[str] | None = None) -> None:
    validate_name(name)
    if item_type not in SAFE_TYPES:
        raise VaultError(f"invalid type: {item_type}")
    validate_comment(comment)
    data = load_vault()
    if name in data["items"] and not data["items"][name].get("archived"):
        raise VaultError(f"{name} already exists. use `s update {name}`")
    password = get_password()
    ts = now_iso()
    data["items"][name] = {
        "type": item_type,
        "value": encrypt_text(value, password),
        "comment": comment,
        "tags": tags or [],
        "uses": uses or [],
        "archived": False,
        "created_at": ts,
        "updated_at": ts,
        "history": [],
    }
    audit(data, "add", name)
    save_vault(data)


def update_item(name: str, value: str | None = None, comment: str | None = None, new_name: str | None = None, tags: list[str] | None = None, uses: list[str] | None = None) -> str:
    data = load_vault()
    if name not in data["items"]:
        raise VaultError(f"{name} not found")
    item = data["items"][name]
    if comment is not None:
        validate_comment(comment)
        item["comment"] = comment
    if tags is not None:
        item["tags"] = tags
    if uses is not None:
        item["uses"] = uses
    if value is not None:
        password = get_password()
        item.setdefault("history", []).insert(0, {"value": item["value"], "ts": now_iso()})
        item["history"] = item["history"][:5]
        item["value"] = encrypt_text(value, password)
    item["updated_at"] = now_iso()
    final_name = name
    if new_name:
        validate_name(new_name)
        if new_name in data["items"]:
            raise VaultError(f"{new_name} already exists")
        data["items"][new_name] = item
        del data["items"][name]
        final_name = new_name
    audit(data, "update", final_name)
    save_vault(data)
    return final_name


def archive_item(name: str, archived: bool) -> None:
    data = load_vault()
    if name not in data["items"]:
        raise VaultError(f"{name} not found")
    data["items"][name]["archived"] = archived
    data["items"][name]["updated_at"] = now_iso()
    audit(data, "restore" if not archived else "archive", name)
    save_vault(data)


def get_value(name: str) -> str:
    require_not_agent("show secret")
    require_tty("show secret")
    data = load_vault()
    if name not in data["items"]:
        raise VaultError(f"{name} not found")
    get_master_password()
    password = get_password("vault password: ")
    audit(data, "get", name)
    save_vault(data)
    return decrypt_text(data["items"][name]["value"], password)


def decrypt_many(names: list[str]) -> dict[str, str]:
    data = load_vault()
    password = get_password()
    values = {}
    for name in names:
        if name not in data["items"]:
            raise VaultError(f"{name} not found")
        item = data["items"][name]
        if item.get("archived"):
            raise VaultError(f"{name} is archived")
        if item.get("type") != "secret":
            raise VaultError(f"{name} is not a secret")
        values[name] = decrypt_text(item["value"], password)
    return values


def redact(text: str, secrets: list[str]) -> str:
    out = text
    for secret in sorted([s for s in secrets if s], key=len, reverse=True):
        out = out.replace(secret, "[REDACTED]")
    return out


def run_with_secrets(names: list[str], cmd: list[str]) -> Result:
    if not cmd:
        raise VaultError("missing command after --")
    values = decrypt_many(names)
    env = os.environ.copy()
    env.update(values)
    proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    secrets = list(values.values())
    return Result(proc.returncode, redact(proc.stdout, secrets), redact(proc.stderr, secrets))


def add_command(name: str, cmd: list[str], comment: str = "", tags: list[str] | None = None, uses: list[str] | None = None) -> None:
    if not cmd:
        raise VaultError("command is required after --")
    add_item(name, json.dumps(cmd), item_type="command", comment=comment, tags=tags, uses=uses)


def command_rows() -> list[dict[str, Any]]:
    return list_items(type_filter="command")


def run_command(name: str) -> Result:
    data = load_vault()
    if name not in data["items"]:
        raise VaultError(f"{name} not found")
    item = data["items"][name]
    if item.get("type") != "command":
        raise VaultError(f"{name} is not a command")
    if item.get("archived"):
        raise VaultError(f"{name} is archived")
    password = get_password()
    cmd = json.loads(decrypt_text(item["value"], password))
    values = decrypt_many(item.get("uses", []))
    env = os.environ.copy()
    env.update(values)
    proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    return Result(proc.returncode, redact(proc.stdout, list(values.values())), redact(proc.stderr, list(values.values())))


def status() -> dict[str, Any]:
    path = vault_path()
    if not path.exists():
        return {"vault_path": str(path), "exists": False}
    data = load_vault(path)
    items = data.get("items", {})
    return {
        "vault_path": str(path),
        "exists": True,
        "items": len(items),
        "archived": sum(1 for item in items.values() if item.get("archived")),
        "agent_mode": is_agent_mode(),
    }


def audit_rows() -> list[dict[str, Any]]:
    return load_vault().get("audit", [])


def backup(to_dir: str | None = None) -> str:
    path = vault_path()
    if not path.exists():
        raise VaultError("vault not found")
    dest = Path(to_dir or "./backups").expanduser()
    dest.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_path = dest / f"agent-vault-backup-{stamp}.tar.gz"
    data = load_vault(path)
    manifest = {
        "created_at": now_iso(),
        "vault_path": str(path),
        "items": len(data.get("items", {})),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        shutil.copy2(path, tmp / "vault.senv")
        (tmp / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        (tmp / "audit.json").write_text(json.dumps(data.get("audit", []), indent=2, sort_keys=True) + "\n")
        with tarfile.open(backup_path, "w:gz") as tar:
            tar.add(tmp / "vault.senv", arcname="vault.senv")
            tar.add(tmp / "manifest.json", arcname="manifest.json")
            tar.add(tmp / "audit.json", arcname="audit.json")
    audit(data, "backup", str(backup_path))
    save_vault(data, path)
    return str(backup_path)


def doctor() -> list[str]:
    s = status()
    lines = [f"vault_path={s['vault_path']}", f"exists={s['exists']}", f"agent_mode={s.get('agent_mode', is_agent_mode())}"]
    if s.get("exists"):
        lines.append(f"items={s['items']}")
        mode = oct(vault_path().stat().st_mode & 0o777)
        lines.append(f"file_mode={mode}")
    lines.append("network=not_started")
    return lines

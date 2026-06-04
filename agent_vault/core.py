from __future__ import annotations

import base64
import contextlib
import contextvars
import csv
import datetime as dt
import getpass
import hashlib
import hmac
import io
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

from . import __version__

VERSION = 1
DEFAULT_COMMENT_WORD_LIMIT = 180
SAFE_TYPES = {"secret", "command", "note"}
HUMAN_ONLY = {"get", "export", "delete", "purge", "rollback", "restore-backup"}
MAX_VALUE_BYTES = 1024 * 1024
DEFAULT_PASSWORD = "password"
DEFAULT_PASSWORD_FILE = "master.key"
MASTER_CONFIG_FILE = "master.json"
RECOVERY_CODE_COUNT = 8
_MASTER_PASSWORD_OVERRIDE: contextvars.ContextVar[str | None] = contextvars.ContextVar("master_password_override", default=None)


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


def configured_password_file() -> Path | None:
    raw = os.environ.get("S_KEY_FILE")
    if raw:
        path = Path(raw).expanduser()
        return path if path.exists() else None
    default = vault_path().parent / DEFAULT_PASSWORD_FILE
    if default.exists():
        return default
    return None


def master_config_path() -> Path:
    if os.environ.get("S_MASTER_FILE"):
        return Path(os.environ["S_MASTER_FILE"]).expanduser()
    return vault_path().parent / MASTER_CONFIG_FILE


def master_config_exists() -> bool:
    return master_config_path().exists()


def load_master_config() -> dict[str, Any]:
    path = master_config_path()
    if not path.exists():
        raise VaultError(f"master config not found: {path}")
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise VaultError(f"master config is not valid JSON: {path}") from exc
    if data.get("version") != 1:
        raise VaultError(f"unsupported master config version: {data.get('version')}")
    return data


def save_master_config(data: dict[str, Any]) -> None:
    path = master_config_path()
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


@contextlib.contextmanager
def master_password_context(password: str):
    token = _MASTER_PASSWORD_OVERRIDE.set(password)
    try:
        yield
    finally:
        _MASTER_PASSWORD_OVERRIDE.reset(token)


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def unb64(data: str) -> bytes:
    return base64.b64decode(data)


def derive_scrypt_bytes(secret: str, salt: bytes, length: int = 32) -> bytes:
    kdf = Scrypt(salt=salt, length=length, n=2**14, r=8, p=1)
    return kdf.derive(secret.encode())


def wrap_secret(secret: bytes, password: str) -> dict[str, str]:
    validate_value(password)
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_scrypt_bytes(password, salt)
    ct = AESGCM(key).encrypt(nonce, secret, None)
    return {"kdf": "scrypt-v1", "salt": b64(salt), "nonce": b64(nonce), "ct": b64(ct)}


def unwrap_secret(blob: dict[str, str], password: str) -> bytes:
    validate_value(password)
    if blob.get("kdf") != "scrypt-v1":
        raise VaultError("unsupported key wrapper")
    key = derive_scrypt_bytes(password, unb64(blob["salt"]))
    try:
        return AESGCM(key).decrypt(unb64(blob["nonce"]), unb64(blob["ct"]), None)
    except Exception as exc:
        raise VaultError("master password did not match") from exc


def password_verifier(password: str, salt: bytes | None = None) -> dict[str, str]:
    validate_value(password)
    salt = salt or os.urandom(16)
    return {"kdf": "scrypt-v1", "salt": b64(salt), "hash": b64(derive_scrypt_bytes(password, salt))}


def verify_password(verifier: dict[str, str], password: str) -> None:
    if verifier.get("kdf") != "scrypt-v1":
        raise VaultError("unsupported password verifier")
    actual = derive_scrypt_bytes(password, unb64(verifier["salt"]))
    if not hmac.compare_digest(actual, unb64(verifier["hash"])):
        raise VaultError("master password did not match")


def format_recovery_code(raw: bytes | None = None) -> str:
    raw = raw or os.urandom(12)
    text = base64.b32encode(raw).decode().rstrip("=")
    return "AV-" + "-".join(text[i:i + 4] for i in range(0, len(text), 4))


def recovery_entry(code: str, vault_key: bytes) -> dict[str, Any]:
    return {"created_at": now_iso(), "verifier": password_verifier(code), "wrapped_vault_key": wrap_secret(vault_key, code)}


def generate_recovery_entries(vault_key: bytes, count: int = RECOVERY_CODE_COUNT) -> tuple[list[dict[str, Any]], list[str]]:
    codes = [format_recovery_code() for _ in range(count)]
    return [recovery_entry(code, vault_key) for code in codes], codes


def make_master_config(master_password: str, vault_key: bytes | None = None, recovery_count: int = RECOVERY_CODE_COUNT) -> tuple[dict[str, Any], list[str]]:
    vault_key = vault_key or os.urandom(32)
    entries, codes = generate_recovery_entries(vault_key, recovery_count)
    return {
        "version": 1,
        "created_at": now_iso(),
        "updated_at": now_iso(),
        "default_password_active": master_password == DEFAULT_PASSWORD,
        "verifier": password_verifier(master_password),
        "wrapped_vault_key": wrap_secret(vault_key, master_password),
        "recovery": entries,
    }, codes


def set_master_password_config(config: dict[str, Any], vault_key: bytes, new_password: str) -> dict[str, Any]:
    config["updated_at"] = now_iso()
    config["default_password_active"] = False
    config["verifier"] = password_verifier(new_password)
    config["wrapped_vault_key"] = wrap_secret(vault_key, new_password)
    return config


def read_password_file(path: Path) -> str:
    try:
        pw = path.read_text().strip()
    except OSError as exc:
        raise VaultError(f"could not read password file: {path}") from exc
    if not pw:
        raise VaultError(f"password file is empty: {path}")
    return pw


def get_master_secret(prompt: str = "master password: ") -> str:
    override = _MASTER_PASSWORD_OVERRIDE.get()
    if override is not None:
        return override
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
    key_file = configured_password_file()
    if key_file:
        return read_password_file(key_file)
    return DEFAULT_PASSWORD


def get_password(prompt: str = "vault password: ") -> str:
    return get_master_secret(prompt)


def get_vault_key(prompt: str = "master password: ") -> str:
    if not master_config_exists():
        return get_master_secret(prompt)
    password = get_master_secret(prompt)
    config = load_master_config()
    try:
        verify_password(config["verifier"], password)
    except VaultError:
        if os.environ.get("S_KEY") or configured_password_file() or _MASTER_PASSWORD_OVERRIDE.get() is not None or not sys.stdin.isatty():
            raise
        password = getpass.getpass(prompt)
        verify_password(config["verifier"], password)
    return b64(unwrap_secret(config["wrapped_vault_key"], password))


def vault_key_from_master_password(password: str) -> str:
    verify_master_password(password)
    if not master_config_exists():
        return password
    config = load_master_config()
    return b64(unwrap_secret(config["wrapped_vault_key"], password))


def password_source_status() -> dict[str, Any]:
    if master_config_exists():
        config = load_master_config()
        return {
            "source": "master_config",
            "path": str(master_config_path()),
            "writable": True,
            "default_password_active": bool(config.get("default_password_active", False)),
            "recovery_codes": len(config.get("recovery", [])),
        }
    if os.environ.get("S_KEY"):
        return {"source": "S_KEY", "writable": False, "default_password_active": False}
    key_file = configured_password_file()
    if key_file:
        return {"source": "S_KEY_FILE", "path": str(key_file), "writable": True, "default_password_active": False}
    raw = os.environ.get("S_KEY_FILE")
    if raw:
        return {"source": "S_KEY_FILE", "path": str(Path(raw).expanduser()), "writable": True, "default_password_active": True}
    return {"source": "default", "writable": True, "default_password_active": True}


def writable_password_file() -> Path:
    if os.environ.get("S_KEY"):
        raise VaultError("password is configured through S_KEY and cannot be changed from the dashboard. Unset S_KEY or migrate to master.json mode.")
    key_file = os.environ.get("S_KEY_FILE")
    return Path(key_file).expanduser() if key_file else vault_path().parent / DEFAULT_PASSWORD_FILE


def write_password_file(new_password: str) -> Path:
    validate_value(new_password)
    path = writable_password_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=str(path.parent), delete=False) as tmp:
        tmp.write(new_password + "\n")
        tmp_path = Path(tmp.name)
    tmp_path.replace(path)
    try:
        path.chmod(0o600)
    except PermissionError:
        pass
    return path


def get_master_password() -> str:
    require_not_agent("perform human-only action")
    require_tty("perform human-only action")
    pw = getpass.getpass("master password: ")
    verify_master_password(pw, action="perform human-only action")
    return pw


def derive_key(password: str, salt: bytes) -> bytes:
    return derive_scrypt_bytes(password, salt)


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


def validate_value(value: str) -> None:
    if value == "":
        raise VaultError("empty value")
    if len(value.encode()) > MAX_VALUE_BYTES:
        raise VaultError("value exceeds 1 MiB limit")


def value_hint(value: str) -> str:
    return value[-3:] if value else ""


def item_public(name: str, item: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": name,
        "type": item.get("type", "secret"),
        "value_hint": item.get("value_hint", ""),
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
    if not master_config_exists():
        config, _codes = make_master_config(get_master_secret())
        save_master_config(config)
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
    validate_value(value)
    if item_type not in SAFE_TYPES:
        raise VaultError(f"invalid type: {item_type}")
    validate_comment(comment)
    data = load_vault()
    if name in data["items"] and not data["items"][name].get("archived"):
        raise VaultError(f"{name} already exists. use `s update {name}`")
    password = get_vault_key()
    ts = now_iso()
    data["items"][name] = {
        "type": item_type,
        "value": encrypt_text(value, password),
        "value_hint": value_hint(value),
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
    if value is None and comment is None and new_name is None and tags is None and uses is None:
        raise VaultError("nothing to update")
    if value is not None:
        validate_value(value)
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
        password = get_vault_key()
        item.setdefault("history", []).insert(0, {"value": item["value"], "ts": now_iso()})
        item["history"] = item["history"][:5]
        item["value"] = encrypt_text(value, password)
        item["value_hint"] = value_hint(value)
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
    if bool(data["items"][name].get("archived", False)) == archived:
        state = "archived" if archived else "active"
        raise VaultError(f"{name} is already {state}")
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
    password = get_vault_key("vault password: ")
    audit(data, "get", name)
    save_vault(data)
    return decrypt_text(data["items"][name]["value"], password)


def decrypt_many(names: list[str]) -> dict[str, str]:
    data = load_vault()
    password = get_vault_key()
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


def command_rows(include_all: bool = False) -> list[dict[str, Any]]:
    return list_items(include_all=include_all, type_filter="command")


def update_command(name: str, comment: str | None = None, tags: list[str] | None = None, uses: list[str] | None = None, cmd: list[str] | None = None) -> str:
    value = json.dumps(cmd) if cmd is not None else None
    return update_item(name, value=value, comment=comment, tags=tags, uses=uses)


def run_command(name: str) -> Result:
    data = load_vault()
    if name not in data["items"]:
        raise VaultError(f"{name} not found")
    item = data["items"][name]
    if item.get("type") != "command":
        raise VaultError(f"{name} is not a command")
    if item.get("archived"):
        raise VaultError(f"{name} is archived")
    password = get_vault_key()
    cmd = json.loads(decrypt_text(item["value"], password))
    values = decrypt_many(item.get("uses", []))
    env = os.environ.copy()
    env.update(values)
    proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    return Result(proc.returncode, redact(proc.stdout, list(values.values())), redact(proc.stderr, list(values.values())))



def rotate_password(current_password: str, new_password: str) -> None:
    require_not_agent("change master key")
    validate_value(current_password)
    validate_value(new_password)
    if current_password == new_password:
        raise VaultError("new password must be different")
    if master_config_exists():
        config = load_master_config()
        verify_password(config["verifier"], current_password)
        vault_key = unwrap_secret(config["wrapped_vault_key"], current_password)
        save_master_config(set_master_password_config(config, vault_key, new_password))
        return
    if current_password != get_master_secret():
        raise VaultError("current password did not match the configured master key")
    data = load_vault()
    writable_password_file()
    for item in data.get("items", {}).values():
        plain = decrypt_text(item["value"], current_password)
        item["value"] = encrypt_text(plain, new_password)
        item["value_hint"] = value_hint(plain)
        history = []
        for entry in item.get("history", []):
            hist_plain = decrypt_text(entry["value"], current_password)
            new_entry = dict(entry)
            new_entry["value"] = encrypt_text(hist_plain, new_password)
            history.append(new_entry)
        item["history"] = history
        item["updated_at"] = now_iso()
    audit(data, "password-rotate")
    save_vault(data)
    write_password_file(new_password)


def migrate_master_config(recovery_count: int = RECOVERY_CODE_COUNT) -> list[str]:
    require_not_agent("migrate master key")
    if master_config_exists():
        raise VaultError("master config already exists")
    legacy_password = get_master_secret()
    path = vault_path()
    original_vault = path.read_bytes() if path.exists() else None
    data = load_vault()
    vault_key = os.urandom(32)
    vault_key_text = b64(vault_key)
    for item in data.get("items", {}).values():
        plain = decrypt_text(item["value"], legacy_password)
        item["value"] = encrypt_text(plain, vault_key_text)
        item["value_hint"] = value_hint(plain)
        history = []
        for entry in item.get("history", []):
            hist_plain = decrypt_text(entry["value"], legacy_password)
            new_entry = dict(entry)
            new_entry["value"] = encrypt_text(hist_plain, vault_key_text)
            history.append(new_entry)
        item["history"] = history
        item["updated_at"] = now_iso()
    config, codes = make_master_config(legacy_password, vault_key, recovery_count=recovery_count)
    audit(data, "master-config-migrate")
    try:
        save_master_config(config)
        save_vault(data)
        key_file = configured_password_file()
        if key_file and key_file.exists():
            key_file.unlink()
    except Exception:
        if original_vault is not None:
            path.write_bytes(original_vault)
            try:
                path.chmod(0o600)
            except PermissionError:
                pass
        master_path = master_config_path()
        if master_path.exists():
            master_path.unlink()
        raise
    return codes


def rotate_recovery_codes(master_password: str, count: int = RECOVERY_CODE_COUNT) -> list[str]:
    require_not_agent("rotate recovery codes")
    if not master_config_exists():
        raise VaultError("master config not found. run migration first")
    config = load_master_config()
    verify_password(config["verifier"], master_password)
    vault_key = unwrap_secret(config["wrapped_vault_key"], master_password)
    entries, codes = generate_recovery_entries(vault_key, count)
    config["recovery"] = entries
    config["updated_at"] = now_iso()
    save_master_config(config)
    return codes


def recover_master_password(recovery_code: str, new_password: str) -> None:
    require_not_agent("recover master key")
    validate_value(recovery_code)
    validate_value(new_password)
    if not master_config_exists():
        raise VaultError("master config not found")
    config = load_master_config()
    for i, entry in enumerate(config.get("recovery", [])):
        try:
            verify_password(entry["verifier"], recovery_code)
            vault_key = unwrap_secret(entry["wrapped_vault_key"], recovery_code)
        except VaultError:
            continue
        del config["recovery"][i]
        save_master_config(set_master_password_config(config, vault_key, new_password))
        return
    raise VaultError("recovery code did not match")


def parse_env_lines(text: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
            value = value[1:-1]
        validate_name(key)
        validate_value(value)
        if key in seen:
            raise VaultError(f"duplicate key in import: {key}")
        seen.add(key)
        pairs.append((key, value))
    return pairs


def import_env_text(text: str, comment: str = "Imported from env text") -> int:
    pairs = parse_env_lines(text)
    if not pairs:
        return 0
    data = load_vault()
    password = get_vault_key()
    ts = now_iso()
    for key, value in pairs:
        if key in data["items"]:
            item = data["items"][key]
            item.setdefault("history", []).insert(0, {"value": item["value"], "ts": ts})
            item["history"] = item["history"][:5]
            item["value"] = encrypt_text(value, password)
            item["value_hint"] = value_hint(value)
            item["updated_at"] = ts
            item["archived"] = False
        else:
            data["items"][key] = {
                "type": "secret",
                "value": encrypt_text(value, password),
                "value_hint": value_hint(value),
                "comment": comment,
                "tags": ["imported"],
                "uses": [],
                "archived": False,
                "created_at": ts,
                "updated_at": ts,
                "history": [],
            }
        audit(data, "import", key)
    save_vault(data)
    return len(pairs)


def import_env_file(path: str) -> int:
    return import_env_text(Path(path).read_text())



def history_rows(name: str) -> list[dict[str, Any]]:
    data = load_vault()
    if name not in data["items"]:
        raise VaultError(f"{name} not found")
    return [{"version": i + 1, "ts": h.get("ts", "")} for i, h in enumerate(data["items"][name].get("history", []))]

def export_values() -> str:
    require_not_agent("export secrets")
    require_tty("export secrets")
    get_master_password()
    data = load_vault()
    password = get_vault_key("vault password: ")
    lines = []
    for name, item in sorted(data["items"].items()):
        if item.get("archived") or item.get("type") != "secret":
            continue
        value = decrypt_text(item["value"], password)
        escaped = value.replace('\\', '\\\\').replace('"', '\\"')
        lines.append(f'{name}="{escaped}"')
    audit(data, "export")
    save_vault(data)
    return "\n".join(lines) + ("\n" if lines else "")


def verify_master_password(password: str, action: str = "export secrets") -> str:
    require_not_agent(action)
    validate_value(password)
    if master_config_exists():
        verify_password(load_master_config()["verifier"], password)
    elif password != get_master_secret():
        raise VaultError("master password did not match")
    return password


def export_csv(password: str) -> str:
    vault_key = vault_key_from_master_password(password)
    data = load_vault()
    out = io.StringIO()
    fieldnames = [
        "name",
        "type",
        "value",
        "value_hint",
        "comment",
        "tags",
        "uses",
        "created_at",
        "updated_at",
    ]
    writer = csv.DictWriter(out, fieldnames=fieldnames)
    writer.writeheader()
    for name, item in sorted(data["items"].items()):
        if item.get("archived"):
            continue
        writer.writerow({
            "name": name,
            "type": item.get("type", "secret"),
            "value": decrypt_text(item["value"], vault_key),
            "value_hint": item.get("value_hint", ""),
            "comment": item.get("comment", ""),
            "tags": ",".join(item.get("tags", [])),
            "uses": ",".join(item.get("uses", [])),
            "created_at": item.get("created_at", ""),
            "updated_at": item.get("updated_at", ""),
        })
    audit(data, "export-csv")
    save_vault(data)
    return out.getvalue()


def confirm_name(name: str, action: str) -> None:
    require_not_agent(action)
    require_tty(action)
    typed = input(f"type {name} to confirm {action}: ")
    if typed != name:
        raise VaultError("confirmation did not match")


def delete_item(name: str, purge_history: bool = False) -> None:
    data = load_vault()
    if name not in data["items"]:
        raise VaultError(f"{name} not found")
    get_master_password()
    confirm_name(name, "delete" if not purge_history else "purge")
    if purge_history:
        del data["items"][name]
        audit(data, "purge", name)
    else:
        data["items"][name]["archived"] = True
        data["items"][name]["deleted_at"] = now_iso()
        audit(data, "delete", name)
    save_vault(data)


def rollback_item(name: str, version: int) -> None:
    require_not_agent("rollback secret")
    require_tty("rollback secret")
    data = load_vault()
    if name not in data["items"]:
        raise VaultError(f"{name} not found")
    item = data["items"][name]
    hist = item.get("history", [])
    if version < 1 or version > len(hist):
        raise VaultError(f"version {version} not found")
    password = get_master_password()
    confirm_name(name, "rollback")
    current = item["value"]
    restored = hist.pop(version - 1)
    hist.insert(0, {"value": current, "ts": now_iso()})
    item["value"] = restored["value"]
    item["value_hint"] = value_hint(decrypt_text(item["value"], password))
    item["history"] = hist[:5]
    item["updated_at"] = now_iso()
    audit(data, "rollback", name)
    save_vault(data)


def restore_backup(backup_file: str, replace: bool = False) -> str:
    require_not_agent("restore backup")
    require_tty("restore backup")
    get_master_password()
    src = Path(backup_file).expanduser()
    if not src.exists():
        raise VaultError(f"backup not found: {src}")
    dest = vault_path() if replace else vault_path().with_suffix(".restored.senv")
    with tarfile.open(src, "r:gz") as tar:
        member = tar.getmember("vault.senv")
        extracted = tar.extractfile(member)
        if extracted is None:
            raise VaultError("backup missing vault.senv")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(extracted.read())
    try:
        dest.chmod(0o600)
    except PermissionError:
        pass
    return str(dest)

def status() -> dict[str, Any]:
    path = vault_path()
    if not path.exists():
        return {"app_version": __version__, "vault_path": str(path), "exists": False}
    data = load_vault(path)
    items = data.get("items", {})
    return {
        "app_version": __version__,
        "vault_path": str(path),
        "exists": True,
        "items": len(items),
        "archived": sum(1 for item in items.values() if item.get("archived")),
        "agent_mode": is_agent_mode(),
        "password_source": password_source_status(),
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
        path = vault_path()
        mode_int = path.stat().st_mode & 0o777
        mode = oct(mode_int)
        lines.append(f"file_mode={mode}")
        lines.append("file_permissions=ok" if mode_int & 0o077 == 0 else "file_permissions=too_open")
        try:
            load_vault(path)
            lines.append("vault_parse=ok")
        except VaultError as exc:
            lines.append(f"vault_parse=error:{exc}")
    lines.append("network=not_started")
    lines.append("server=not_started")
    return lines

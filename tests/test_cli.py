import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable
FAKE = "test_sk_1234567890abcdef_FAKE_ONLY"

sys.path.insert(0, str(ROOT))
from agent_vault import core


def run_s(tmp_path, *args, input_text=None, extra_env=None):
    env = os.environ.copy()
    env.update({
        "PYTHONPATH": str(ROOT),
        "S_KEY": "test-password",
        "S_VAULT_PATH": str(tmp_path / "vault.senv"),
    })
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [PY, "-m", "agent_vault.cli", *args],
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=ROOT,
        env=env,
    )


def test_help_exists(tmp_path):
    proc = run_s(tmp_path, "help")
    assert proc.returncode == 0
    assert "s help <command>" in proc.stdout
    proc = run_s(tmp_path, "help", "ls")
    assert proc.returncode == 0
    assert "Never prints raw values" in proc.stdout


def test_add_list_update_archive_restore(tmp_path):
    assert run_s(tmp_path, "init").returncode == 0
    proc = run_s(tmp_path, "add", "TEST_API_KEY", "--stdin", "--comment", "Fake test key", "--tags", "api,test", input_text=FAKE)
    assert proc.returncode == 0, proc.stderr
    proc = run_s(tmp_path, "ls", "--json")
    rows = json.loads(proc.stdout)
    assert rows[0]["name"] == "TEST_API_KEY"
    assert rows[0]["comment"] == "Fake test key"
    assert FAKE not in proc.stdout
    proc = run_s(tmp_path, "update", "TEST_API_KEY", "--comment", "Updated comment")
    assert proc.returncode == 0, proc.stderr
    proc = run_s(tmp_path, "archive", "TEST_API_KEY")
    assert proc.returncode == 0, proc.stderr
    proc = run_s(tmp_path, "ls", "--json")
    assert json.loads(proc.stdout) == []
    proc = run_s(tmp_path, "restore", "TEST_API_KEY")
    assert proc.returncode == 0, proc.stderr
    proc = run_s(tmp_path, "ls", "--json")
    assert json.loads(proc.stdout)[0]["name"] == "TEST_API_KEY"


def test_run_redacts_python_output(tmp_path):
    assert run_s(tmp_path, "init").returncode == 0
    assert run_s(tmp_path, "add", "TEST_API_KEY", "--stdin", "--comment", "Fake test key", input_text=FAKE).returncode == 0
    code = "import os; print(os.environ['TEST_API_KEY'])"
    proc = run_s(tmp_path, "run", "TEST_API_KEY", "--", PY, "-c", code)
    assert proc.returncode == 0, proc.stderr
    assert "[REDACTED]" in proc.stdout
    assert FAKE not in proc.stdout


def test_command_registry_redacts(tmp_path):
    assert run_s(tmp_path, "init").returncode == 0
    assert run_s(tmp_path, "add", "TEST_API_KEY", "--stdin", input_text=FAKE).returncode == 0
    code = "import os; print(os.environ['TEST_API_KEY'])"
    proc = run_s(tmp_path, "cmd", "add", "PRINT_FAKE", "--uses", "TEST_API_KEY", "--comment", "Prints fake key", "--", PY, "-c", code)
    assert proc.returncode == 0, proc.stderr
    proc = run_s(tmp_path, "cmd", "run", "PRINT_FAKE")
    assert proc.returncode == 0, proc.stderr
    assert "[REDACTED]" in proc.stdout
    assert FAKE not in proc.stdout


def test_agent_mode_blocks_get(tmp_path):
    assert run_s(tmp_path, "init").returncode == 0
    assert run_s(tmp_path, "add", "TEST_API_KEY", "--stdin", input_text=FAKE).returncode == 0
    proc = run_s(tmp_path, "get", "TEST_API_KEY", "--auth", extra_env={"S_AGENT_MODE": "1"})
    assert proc.returncode == 1
    assert "agent mode" in proc.stderr


def test_backup_does_not_decrypt_secret(tmp_path):
    assert run_s(tmp_path, "init").returncode == 0
    assert run_s(tmp_path, "add", "TEST_API_KEY", "--stdin", input_text=FAKE).returncode == 0
    backup_dir = tmp_path / "backups"
    proc = run_s(tmp_path, "backup", "--to", str(backup_dir))
    assert proc.returncode == 0, proc.stderr
    backup_file = Path(proc.stdout.strip())
    assert backup_file.exists()
    assert FAKE not in backup_file.read_bytes().decode("latin1", errors="ignore")


def test_status_and_doctor(tmp_path):
    assert run_s(tmp_path, "init").returncode == 0
    proc = run_s(tmp_path, "status")
    assert proc.returncode == 0
    assert json.loads(proc.stdout)["exists"] is True
    proc = run_s(tmp_path, "doctor")
    assert proc.returncode == 0
    assert "network=not_started" in proc.stdout


def test_import_stdin_redacts_from_list_and_run(tmp_path):
    assert run_s(tmp_path, "init").returncode == 0
    env_text = "IMPORTED_API_KEY=test_imported_123456789_FAKE_ONLY\n"
    proc = run_s(tmp_path, "import", "--stdin", input_text=env_text)
    assert proc.returncode == 0, proc.stderr
    proc = run_s(tmp_path, "ls", "--json")
    assert "IMPORTED_API_KEY" in proc.stdout
    assert "test_imported_123456789_FAKE_ONLY" not in proc.stdout
    code = "import os; print(os.environ['IMPORTED_API_KEY'])"
    proc = run_s(tmp_path, "run", "IMPORTED_API_KEY", "--", PY, "-c", code)
    assert proc.returncode == 0, proc.stderr
    assert "[REDACTED]" in proc.stdout
    assert "test_imported_123456789_FAKE_ONLY" not in proc.stdout


def test_human_only_commands_refuse_without_tty(tmp_path):
    assert run_s(tmp_path, "init").returncode == 0
    assert run_s(tmp_path, "add", "TEST_API_KEY", "--stdin", input_text=FAKE).returncode == 0
    for args in [
        ("get", "TEST_API_KEY", "--auth"),
        ("export", "--auth"),
        ("delete", "TEST_API_KEY", "--auth"),
        ("purge", "TEST_API_KEY", "--auth"),
        ("rollback", "TEST_API_KEY", "--to", "1", "--auth"),
    ]:
        proc = run_s(tmp_path, *args)
        assert proc.returncode == 1, args
        assert "without an interactive terminal" in proc.stderr or "version 1 not found" in proc.stderr


def test_agent_mode_blocks_human_only_commands(tmp_path):
    assert run_s(tmp_path, "init").returncode == 0
    assert run_s(tmp_path, "add", "TEST_API_KEY", "--stdin", input_text=FAKE).returncode == 0
    for args in [
        ("get", "TEST_API_KEY", "--auth"),
        ("export", "--auth"),
        ("delete", "TEST_API_KEY", "--auth"),
        ("purge", "TEST_API_KEY", "--auth"),
        ("rollback", "TEST_API_KEY", "--to", "1", "--auth"),
    ]:
        proc = run_s(tmp_path, *args, extra_env={"S_AGENT_MODE": "1"})
        assert proc.returncode == 1, args
        assert "agent mode" in proc.stderr or "version 1 not found" in proc.stderr


def test_restore_backup_refuses_without_tty(tmp_path):
    assert run_s(tmp_path, "init").returncode == 0
    assert run_s(tmp_path, "add", "TEST_API_KEY", "--stdin", input_text=FAKE).returncode == 0
    backup_dir = tmp_path / "backups"
    proc = run_s(tmp_path, "backup", "--to", str(backup_dir))
    assert proc.returncode == 0, proc.stderr
    backup_file = proc.stdout.strip()
    proc = run_s(tmp_path, "restore-backup", backup_file, "--auth")
    assert proc.returncode == 1
    assert "without an interactive terminal" in proc.stderr


def test_empty_stdin_and_noop_update_fail(tmp_path):
    assert run_s(tmp_path, "init").returncode == 0
    proc = run_s(tmp_path, "add", "EMPTY_KEY", "--stdin", input_text="")
    assert proc.returncode == 1
    assert "empty value" in proc.stderr
    assert run_s(tmp_path, "add", "TEST_API_KEY", "--stdin", input_text=FAKE).returncode == 0
    proc = run_s(tmp_path, "update", "TEST_API_KEY")
    assert proc.returncode == 1
    assert "nothing to update" in proc.stderr


def test_note_requires_comment_and_lists_without_value(tmp_path):
    assert run_s(tmp_path, "init").returncode == 0
    proc = run_s(tmp_path, "add", "MY_NOTE", "--type", "note")
    assert proc.returncode == 1
    assert "note requires --comment" in proc.stderr
    proc = run_s(tmp_path, "add", "MY_NOTE", "--type", "note", "--comment", "Remember this operational note")
    assert proc.returncode == 0, proc.stderr
    proc = run_s(tmp_path, "ls", "--json")
    rows = json.loads(proc.stdout)
    assert rows[0]["type"] == "note"
    assert "Remember this operational note" in proc.stdout


def test_duplicate_import_key_fails(tmp_path):
    assert run_s(tmp_path, "init").returncode == 0
    proc = run_s(tmp_path, "import", "--stdin", input_text="A_KEY=one\nA_KEY=two\n")
    assert proc.returncode == 1
    assert "duplicate key" in proc.stderr


def test_history_metadata_after_update(tmp_path):
    assert run_s(tmp_path, "init").returncode == 0
    assert run_s(tmp_path, "add", "TEST_API_KEY", "--stdin", input_text=FAKE).returncode == 0
    assert run_s(tmp_path, "update", "TEST_API_KEY", "--stdin", input_text="test_sk_updated_fake_only").returncode == 0
    proc = run_s(tmp_path, "history", "TEST_API_KEY")
    assert proc.returncode == 0, proc.stderr
    assert "v1" in proc.stdout
    assert FAKE not in proc.stdout
    assert "test_sk_updated_fake_only" not in proc.stdout


def test_command_update_archive_restore(tmp_path):
    assert run_s(tmp_path, "init").returncode == 0
    assert run_s(tmp_path, "add", "TEST_API_KEY", "--stdin", input_text=FAKE).returncode == 0
    code1 = "import os; print(os.environ['TEST_API_KEY'])"
    code2 = "print('no-secret-output')"
    assert run_s(tmp_path, "cmd", "add", "PRINT_FAKE", "--uses", "TEST_API_KEY", "--", PY, "-c", code1).returncode == 0
    proc = run_s(tmp_path, "cmd", "update", "PRINT_FAKE", "--uses", "", "--comment", "No secret command", "--", PY, "-c", code2)
    assert proc.returncode == 0, proc.stderr
    proc = run_s(tmp_path, "cmd", "run", "PRINT_FAKE")
    assert proc.returncode == 0, proc.stderr
    assert "no-secret-output" in proc.stdout
    proc = run_s(tmp_path, "cmd", "archive", "PRINT_FAKE")
    assert proc.returncode == 0, proc.stderr
    proc = run_s(tmp_path, "cmd", "run", "PRINT_FAKE")
    assert proc.returncode == 1
    assert "archived" in proc.stderr
    proc = run_s(tmp_path, "cmd", "restore", "PRINT_FAKE")
    assert proc.returncode == 0, proc.stderr
    proc = run_s(tmp_path, "cmd", "run", "PRINT_FAKE")
    assert proc.returncode == 0, proc.stderr


def test_migrate_key_and_recover_master_password(tmp_path, monkeypatch):
    monkeypatch.setenv("S_KEY", "legacy-test-password")
    monkeypatch.setenv("S_VAULT_PATH", str(tmp_path / "vault.senv"))
    core.init_vault()
    (tmp_path / "master.json").unlink()
    core.add_item("LEGACY_KEY", FAKE, comment="Legacy fake")

    codes = core.migrate_master_config()
    assert len(codes) == core.RECOVERY_CODE_COUNT
    master_config_text = (tmp_path / "master.json").read_text()
    assert "legacy-test-password" not in master_config_text
    assert FAKE not in (tmp_path / "vault.senv").read_text()

    with core.master_password_context("legacy-test-password"):
        assert core.decrypt_many(["LEGACY_KEY"])["LEGACY_KEY"] == FAKE

    core.recover_master_password(codes[0], "new-recovered-password")
    with core.master_password_context("new-recovered-password"):
        assert core.decrypt_many(["LEGACY_KEY"])["LEGACY_KEY"] == FAKE
    with core.master_password_context("legacy-test-password"):
        try:
            core.decrypt_many(["LEGACY_KEY"])
            raise AssertionError("old password still worked after recovery")
        except core.VaultError:
            pass


def test_doctor_reports_permissions_and_parse(tmp_path):
    assert run_s(tmp_path, "init").returncode == 0
    proc = run_s(tmp_path, "doctor")
    assert proc.returncode == 0
    assert "file_permissions=ok" in proc.stdout
    assert "vault_parse=ok" in proc.stdout
    assert "server=not_started" in proc.stdout

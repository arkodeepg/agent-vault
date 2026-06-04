from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from . import core

HELP = """Agent Vault

Usage:
  s help <command>
  s init
  s ls [--json] [--all] [--type TYPE] [--tag TAG]
  s add NAME [--stdin] [--type secret|note] [--comment TEXT] [--tags a,b]
  s update NAME [--stdin] [--comment TEXT] [--name NEW_NAME] [--tags a,b]
  s archive NAME
  s restore NAME
  s get NAME --auth
  s run NAME [NAME...] -- command [args...]
  s cmd ls
  s cmd add NAME --uses KEY1,KEY2 [--comment TEXT] -- command [args...]
  s cmd run NAME
  s status
  s doctor
  s audit [--json]
  s import FILE|--stdin
  s export --auth
  s delete NAME --auth
  s purge NAME --auth
  s rollback NAME --to VERSION --auth
  s restore-backup FILE --auth
  s backup [--to DIR]
"""

COMMAND_HELP = {
    "ls": "s ls [--json] [--all] [--type TYPE] [--tag TAG]\nLists safe metadata only. Never prints raw values.",
    "add": "s add NAME [--stdin] [--type secret|note] [--comment TEXT] [--tags a,b]\nAdds a secret or note. Values are never echoed.",
    "update": "s update NAME [--stdin] [--comment TEXT] [--name NEW_NAME] [--tags a,b]\nUpdates value or safe metadata.",
    "run": "s run NAME [NAME...] -- command [args...]\nInjects secrets as env vars and redacts output.",
    "cmd": "s cmd ls | s cmd add NAME --uses KEY -- command | s cmd run NAME\nStores and runs command templates.",
    "backup": "s backup [--to DIR]\nCreates an encrypted backup without decrypting secret values.",
    "get": "s get NAME --auth\nHuman-only raw reveal. Refuses in agent mode and without TTY.",
    "import": "s import FILE | s import --stdin\nImports KEY=VALUE lines without echoing values.",
    "export": "s export --auth\nHuman-only export. Refuses in agent mode and without TTY.",
    "delete": "s delete NAME --auth\nHuman-only destructive action. Agents should use archive instead.",
    "purge": "s purge NAME --auth\nHuman-only permanent removal including history.",
    "rollback": "s rollback NAME --to VERSION --auth\nHuman-only value rollback.",
    "restore-backup": "s restore-backup FILE --auth\nHuman-only restore to a .restored vault file by default.",
}


def print_rows(rows: list[dict]) -> None:
    if not rows:
        print("no items")
        return
    for r in rows:
        tags = ",".join(r.get("tags", [])) or "-"
        uses = ",".join(r.get("uses", [])) or "-"
        archived = " archived" if r.get("archived") else ""
        print(f"{r['name']:30} {r['type']:8} tags={tags:18} uses={uses:18} {r.get('comment','')}{archived}")


def split_double_dash(argv: list[str]) -> tuple[list[str], list[str]]:
    if "--" not in argv:
        return argv, []
    i = argv.index("--")
    return argv[:i], argv[i + 1:]


def read_value(use_stdin: bool) -> str:
    if use_stdin:
        return sys.stdin.read().rstrip("\n")
    import getpass
    value = getpass.getpass("value: ")
    if not value:
        raise core.VaultError("empty value")
    return value


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        if not argv or argv[0] in {"help", "-h", "--help"}:
            if len(argv) > 1:
                print(COMMAND_HELP.get(argv[1], f"no focused help for {argv[1]}"))
            else:
                print(HELP)
            return 0

        cmd = argv[0]

        if cmd == "init":
            p = core.init_vault(force="--force" in argv)
            print(f"created {p}")
            return 0

        if cmd in {"ls", "list"}:
            parser = argparse.ArgumentParser(prog="s ls")
            parser.add_argument("--json", action="store_true")
            parser.add_argument("--all", action="store_true")
            parser.add_argument("--type")
            parser.add_argument("--tag")
            ns = parser.parse_args(argv[1:])
            rows = core.list_items(include_all=ns.all, type_filter=ns.type, tag=ns.tag)
            print(json.dumps(rows, indent=2) if ns.json else "", end="") if ns.json else print_rows(rows)
            return 0

        if cmd == "add":
            parser = argparse.ArgumentParser(prog="s add")
            parser.add_argument("name")
            parser.add_argument("--stdin", action="store_true")
            parser.add_argument("--type", default="secret")
            parser.add_argument("--comment", default="")
            parser.add_argument("--tags")
            ns = parser.parse_args(argv[1:])
            value = ns.comment if ns.type == "note" and not ns.stdin else read_value(ns.stdin)
            core.add_item(ns.name, value, item_type=ns.type, comment=ns.comment, tags=core.parse_tags(ns.tags))
            print(f"added {ns.name}")
            return 0

        if cmd == "update":
            parser = argparse.ArgumentParser(prog="s update")
            parser.add_argument("name")
            parser.add_argument("--stdin", action="store_true")
            parser.add_argument("--comment")
            parser.add_argument("--name", dest="new_name")
            parser.add_argument("--tags")
            ns = parser.parse_args(argv[1:])
            value = read_value(True) if ns.stdin else None
            final = core.update_item(ns.name, value=value, comment=ns.comment, new_name=ns.new_name, tags=core.parse_tags(ns.tags) if ns.tags is not None else None)
            print(f"updated {final}")
            return 0

        if cmd in {"archive", "restore"}:
            if len(argv) < 2:
                raise core.VaultError(f"usage: s {cmd} NAME")
            core.archive_item(argv[1], archived=(cmd == "archive"))
            print(f"{cmd}d {argv[1]}")
            return 0

        if cmd == "get":
            if len(argv) < 3 or argv[2] != "--auth":
                raise core.VaultError("usage: s get NAME --auth")
            print(core.get_value(argv[1]))
            return 0

        if cmd == "run":
            before, after = split_double_dash(argv[1:])
            result = core.run_with_secrets(before, after)
            sys.stdout.write(result.out)
            sys.stderr.write(result.err)
            return result.code

        if cmd == "cmd":
            if len(argv) < 2:
                raise core.VaultError("usage: s cmd ls|add|run")
            sub = argv[1]
            if sub == "ls":
                print_rows(core.command_rows())
                return 0
            if sub == "add":
                before, after = split_double_dash(argv[2:])
                parser = argparse.ArgumentParser(prog="s cmd add")
                parser.add_argument("name")
                parser.add_argument("--uses", default="")
                parser.add_argument("--comment", default="")
                parser.add_argument("--tags")
                ns = parser.parse_args(before)
                core.add_command(ns.name, after, comment=ns.comment, tags=core.parse_tags(ns.tags), uses=core.parse_tags(ns.uses))
                print(f"added command {ns.name}")
                return 0
            if sub == "run":
                if len(argv) < 3:
                    raise core.VaultError("usage: s cmd run NAME")
                result = core.run_command(argv[2])
                sys.stdout.write(result.out)
                sys.stderr.write(result.err)
                return result.code
            raise core.VaultError(f"unknown cmd subcommand: {sub}")

        if cmd == "status":
            print(json.dumps(core.status(), indent=2, sort_keys=True))
            return 0

        if cmd == "doctor":
            print("\n".join(core.doctor()))
            return 0

        if cmd == "audit":
            rows = core.audit_rows()
            if "--json" in argv:
                print(json.dumps(rows, indent=2))
            else:
                for r in rows:
                    print(f"{r.get('ts')} {r.get('action')} {r.get('name')} ok={r.get('ok')} mode={r.get('mode')}")
            return 0


        if cmd == "import":
            parser = argparse.ArgumentParser(prog="s import")
            parser.add_argument("source", nargs="?")
            parser.add_argument("--stdin", action="store_true")
            ns = parser.parse_args(argv[1:])
            if ns.stdin:
                count = core.import_env_text(sys.stdin.read())
            elif ns.source:
                count = core.import_env_file(ns.source)
            else:
                raise core.VaultError("usage: s import FILE | s import --stdin")
            print(f"imported {count} secret(s)")
            return 0

        if cmd == "export":
            if "--auth" not in argv[1:]:
                raise core.VaultError("usage: s export --auth")
            sys.stdout.write(core.export_values())
            return 0

        if cmd in {"delete", "purge"}:
            if len(argv) < 3 or argv[2] != "--auth":
                raise core.VaultError(f"usage: s {cmd} NAME --auth")
            core.delete_item(argv[1], purge_history=(cmd == "purge"))
            print(f"{cmd}d {argv[1]}")
            return 0

        if cmd == "rollback":
            parser = argparse.ArgumentParser(prog="s rollback")
            parser.add_argument("name")
            parser.add_argument("--to", type=int, required=True)
            parser.add_argument("--auth", action="store_true")
            ns = parser.parse_args(argv[1:])
            if not ns.auth:
                raise core.VaultError("usage: s rollback NAME --to VERSION --auth")
            core.rollback_item(ns.name, ns.to)
            print(f"rolled back {ns.name} to v{ns.to}")
            return 0

        if cmd == "restore-backup":
            parser = argparse.ArgumentParser(prog="s restore-backup")
            parser.add_argument("file")
            parser.add_argument("--auth", action="store_true")
            parser.add_argument("--replace", action="store_true")
            ns = parser.parse_args(argv[1:])
            if not ns.auth:
                raise core.VaultError("usage: s restore-backup FILE --auth")
            print(core.restore_backup(ns.file, replace=ns.replace))
            return 0

        if cmd == "backup":
            parser = argparse.ArgumentParser(prog="s backup")
            parser.add_argument("--to")
            ns = parser.parse_args(argv[1:])
            print(core.backup(ns.to))
            return 0

        raise core.VaultError(f"unknown command: {cmd}. try `s help`")
    except core.VaultError as exc:
        print(f"s: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

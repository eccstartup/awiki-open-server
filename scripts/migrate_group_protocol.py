#!/usr/bin/env python3
"""Inspect or explicitly migrate one locally hosted Community group."""

from __future__ import annotations

import argparse
from dataclasses import replace
import json
from pathlib import Path
import re
import subprocess
import sqlite3

from awiki_open_server.app.settings import load_settings
from awiki_open_server.messaging.groups.migration import apply_group, cancel_group, inspect_group, prepare_group
from awiki_open_server.shared.errors import AwikiError


def require_stopped_unit(unit: str | None) -> None:
    if not unit or not re.fullmatch(r"[A-Za-z0-9_.@:-]+\.service", unit):
        raise ValueError("mutations require --stopped-unit naming the actual managed Open Server unit")
    result = subprocess.run(["systemctl", "show", unit, "--property=LoadState,ActiveState,MainPID"], text=True, capture_output=True, check=True)
    properties = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    if properties.get("LoadState") != "loaded" or properties.get("ActiveState") != "inactive" or properties.get("MainPID") != "0":
        raise ValueError("the managed Open Server must be stopped before migration commands")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["inspect", "prepare", "apply", "cancel"])
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--group-did", required=True)
    parser.add_argument("--plan-digest")
    parser.add_argument("--backup-dir", type=Path)
    parser.add_argument("--stopped-unit")
    args = parser.parse_args()
    try:
        settings = replace(load_settings(), data_dir=args.data_dir.resolve())
        if args.action == "inspect":
            result = inspect_group(settings, args.group_did)
        else:
            require_stopped_unit(args.stopped_unit)
            if not args.plan_digest:
                raise ValueError("--plan-digest is required")
            if args.action == "prepare":
                if args.backup_dir is None:
                    raise ValueError("--backup-dir is required")
                result = prepare_group(settings, args.group_did, args.plan_digest, args.backup_dir)
            elif args.action == "apply":
                result = apply_group(settings, args.group_did, args.plan_digest)
            else:
                result = cancel_group(settings, args.group_did, args.plan_digest)
        print(json.dumps({"ok": True, "result": result}, ensure_ascii=False, indent=2))
        return 0
    except AwikiError as exc:
        print(json.dumps({"ok": False, "error": exc.error_message}, ensure_ascii=False))
    except (OSError, ValueError, sqlite3.Error, subprocess.SubprocessError):
        print(json.dumps({"ok": False, "error": "migration_precondition_failed"}))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

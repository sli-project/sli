#!/usr/bin/env python3
"""Write a read-only Windows token and remote Event Log access diagnostic."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.maintenance.collection_block_control import probe_windows_event_context
from server.sli.sources.windows_runtime_identity import current_windows_identity


def _enable_security_privilege() -> dict[str, object]:
    """Enable SeSecurityPrivilege only in this short-lived diagnostic process."""
    try:
        import win32api
        import win32con
        import win32security

        token = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(),
            win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY,
        )
        privilege_id = win32security.LookupPrivilegeValue(
            None,
            win32security.SE_SECURITY_NAME,
        )
        win32security.AdjustTokenPrivileges(
            token,
            False,
            [(privilege_id, win32security.SE_PRIVILEGE_ENABLED)],
        )
        return {"status": "enabled"}
    except Exception as exc:
        return {
            "status": "failed",
            "error_type": type(exc).__name__,
            "error": str(exc),
        }


def _whoami(argument: str) -> dict[str, object]:
    proc = subprocess.run(
        ["whoami", argument, "/fo", "csv", "/nh"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=15,
    )
    return {
        "returncode": proc.returncode,
        "output": (proc.stdout or "").splitlines(),
        "error": (proc.stderr or "").strip(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", required=True)
    parser.add_argument("--channel", default="Security")
    parser.add_argument("--output", required=True)
    parser.add_argument("--enable-security-privilege", action="store_true")
    args = parser.parse_args()

    output = Path(args.output).resolve()
    if ROOT not in output.parents:
        parser.error("output must be inside the project")

    privilege_adjustment = (
        _enable_security_privilege()
        if args.enable_security_privilege
        else {"status": "not_requested"}
    )
    payload = {
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "identity": current_windows_identity(),
        "privilege_adjustment": privilege_adjustment,
        "groups": _whoami("/groups"),
        "privileges": _whoami("/priv"),
        "event_log_probe": probe_windows_event_context(
            str(args.server),
            channel=str(args.channel),
        ),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return 0 if payload["event_log_probe"].get("status") == "ok" else 2


if __name__ == "__main__":
    raise SystemExit(main())

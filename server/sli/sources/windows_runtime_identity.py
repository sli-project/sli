"""Fail-closed identity checks for the external Windows collection worker."""
from __future__ import annotations

import csv
import getpass
import io
import os
import subprocess
from typing import Any

EXAMPLE_COLLECTION_PRINCIPAL = r"EXAMPLE\operator"
EXAMPLE_COLLECTION_PRINCIPAL_SID = (
    "S-1-5-21-100000004-200000004-300000004-6995"
)


def expected_collection_identity() -> tuple[str, str]:
    principal = os.environ.get("ADLOG_COLLECTION_PRINCIPAL", "").strip()
    sid = os.environ.get("ADLOG_COLLECTION_PRINCIPAL_SID", "").strip()
    return principal, sid


def current_windows_identity() -> dict[str, Any]:
    domain = os.environ.get("USERDOMAIN", "").strip()
    user = getpass.getuser()
    principal = f"{domain}\\{user}" if domain else user
    if os.name != "nt":
        return {
            "principal": principal,
            "sid": None,
            "session_id": None,
            "interactive": False,
            "elevated": False,
            "error": "windows_required",
        }
    try:
        result = subprocess.run(
            ["whoami", "/user", "/fo", "csv", "/nh"],
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            capture_output=True,
            text=True,
            # whoami's redirected Windows output uses the OEM code page, not
            # Python's UTF-8 default. Never replace undecodable identity bytes.
            encoding="oem",
            errors="strict",
            timeout=10,
            check=False,
        )
    except Exception as exc:
        return {
            "principal": principal,
            "sid": None,
            "session_id": None,
            "interactive": False,
            "elevated": False,
            "error": f"identity_probe_failed:{type(exc).__name__}",
        }
    if result.returncode != 0:
        return {
            "principal": principal,
            "sid": None,
            "session_id": None,
            "interactive": False,
            "elevated": False,
            "error": "whoami_failed",
        }
    try:
        row = next(csv.reader(io.StringIO(result.stdout.strip())))
        whoami_principal, sid = row[0].strip(), row[1].strip()
        import ctypes

        session_id = int(ctypes.windll.kernel32.WTSGetActiveConsoleSessionId())
        current_process_id = os.getpid()
        process_session = ctypes.c_uint()
        if not ctypes.windll.kernel32.ProcessIdToSessionId(
            current_process_id, ctypes.byref(process_session)
        ):
            raise OSError("ProcessIdToSessionId failed")
        process_session_id = int(process_session.value)
        elevated = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception as exc:
        return {
            "principal": principal,
            "sid": None,
            "session_id": None,
            "interactive": False,
            "elevated": False,
            "error": f"identity_parse_failed:{type(exc).__name__}",
        }
    return {
        "principal": whoami_principal or principal,
        "sid": sid,
        "session_id": process_session_id,
        "active_console_session_id": session_id,
        "interactive": process_session_id != 0,
        "elevated": elevated,
        "error": None,
    }


def verify_collection_identity(
    *,
    expected_principal: str | None = None,
    expected_sid: str | None = None,
) -> dict[str, Any]:
    if expected_principal is None and expected_sid is None:
        expected_principal, expected_sid = expected_collection_identity()
    else:
        expected_principal = str(expected_principal or "").strip()
        expected_sid = str(expected_sid or "").strip()
    current = current_windows_identity()
    reasons: list[str] = []
    if not expected_principal:
        reasons.append("expected_principal_missing")
    if not expected_sid:
        reasons.append("expected_sid_missing")
    if not current.get("interactive"):
        reasons.append("interactive_session_required")
    if str(current.get("principal") or "").casefold() != expected_principal.casefold():
        reasons.append("principal_mismatch")
    if str(current.get("sid") or "").casefold() != expected_sid.casefold():
        reasons.append("sid_mismatch")
    if current.get("error"):
        reasons.append(str(current["error"]))
    return {
        "status": "ok" if not reasons else "failed",
        "reason": None if not reasons else "windows_collection_identity_invalid",
        "reasons": reasons,
        "expected_principal": expected_principal,
        "expected_sid": expected_sid,
        "current_principal": current.get("principal"),
        "current_sid": current.get("sid"),
        "session_id": current.get("session_id"),
        "interactive": bool(current.get("interactive")),
        "elevated": bool(current.get("elevated")),
    }

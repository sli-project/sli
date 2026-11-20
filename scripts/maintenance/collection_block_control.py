"""Explicit recovery control for the durable collection circuit breaker."""
from __future__ import annotations

import argparse
import getpass
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.sources.windows_event_probe import _close_evt_handle, probe_windows_event_context  # noqa: E402,F401

CONFIRMATION = "SLI-RECHECK-WINDOWS-CONTEXT"


def _internal_probe(server: str, *, ad_source_credential_mode: str = "process") -> int:
    result = probe_windows_event_context(
        server, ad_source_credential_mode=ad_source_credential_mode, configured_dc=True,
    )
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result.get("status") == "ok" else 2


def main() -> int:
    parser = argparse.ArgumentParser(description="Read or recover the SLI collection circuit breaker.")
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--probe-server")
    parser.add_argument("--ad-source-credential-mode", default=None)
    parser.add_argument("--confirm")
    parser.add_argument("--timeout-seconds", type=int, default=15)
    parser.add_argument("--internal-probe", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.internal_probe:
        return _internal_probe(str(args.probe_server or ""), ad_source_credential_mode=(
            args.ad_source_credential_mode if args.ad_source_credential_mode is not None else "process"
        ))

    from server.sli.sources.collection_runtime_block import get_active_collection_block, record_probe_and_clear

    if args.status:
        block = get_active_collection_block()
        print(json.dumps({"status": "blocked" if block else "clear", "block": block}, ensure_ascii=False, default=str, indent=2))
        return 2 if block else 0
    if not args.probe_server or args.confirm != CONFIRMATION:
        parser.error(f"recovery requires --probe-server and --confirm {CONFIRMATION}")

    from server.sli.sources.ad_source_auth import validate_ad_source_credential_mode
    from server.sli.sources.collection_failure_policy import AD_SOURCE_OPERATOR_FAILURE_CODES

    block = get_active_collection_block()
    if block and block.get("reason_code") in AD_SOURCE_OPERATOR_FAILURE_CODES and args.ad_source_credential_mode is None:
        print(json.dumps({"status": "blocked", "failure_reason": "ad_source_recovery_mode_required"}))
        return 2
    try:
        mode = validate_ad_source_credential_mode(
            args.ad_source_credential_mode if args.ad_source_credential_mode is not None else "process",
        )
    except RuntimeError:
        print(json.dumps({"status": "blocked", "failure_reason": "ad_source_credential_mode_invalid"}))
        return 2

    command = [
        sys.executable, str(Path(__file__).resolve()), "--internal-probe",
        "--probe-server", str(args.probe_server),
        "--ad-source-credential-mode", mode,
    ]
    try:
        probe = subprocess.run(
            command, text=True, capture_output=True,
            timeout=max(1, min(int(args.timeout_seconds), 60)),
        )
    except subprocess.TimeoutExpired:
        print(json.dumps({"status": "blocked", "failure_reason": "probe_timeout"}, ensure_ascii=False))
        return 2
    if probe.returncode != 0:
        print(probe.stdout.strip() or json.dumps({"status": "blocked", "failure_reason": "probe_failed"}, ensure_ascii=False))
        return 2

    cleared = record_probe_and_clear(
        probe_server=str(args.probe_server),
        cleared_by=getpass.getuser(),
    )
    status = (
        "already_cleared_after_successful_probe"
        if cleared.get("clear_outcome") == "already_clear"
        else "cleared_after_successful_probe"
    )
    print(
        json.dumps(
            {"status": status, "block": cleared},
            ensure_ascii=False,
            default=str,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

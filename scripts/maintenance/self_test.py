#!/usr/bin/env python3
"""Stage 1 self-test for Security Log Intelligence.

Offline mode is safe by default and never touches AD/DC. Live mode performs only
read-only availability probes and is explicitly opt-in.
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.maintenance.bundle_common import (  # noqa: E402
    DATA_DIR,
    LOG_DIR,
    PROJECT_ROOT,
    PYTEST_BASETEMP,
    TMP_DIR,
    redact_env_file,
    safe_pytest_env,
    should_exclude_from_dev_handoff,
    timestamp,
    utc_now,
    write_json,
)
from server.sli.ops.diagnostics import make_structured_log_payload, validate_structured_log_payload, write_jsonl  # noqa: E402
from server.sli.ops.version import get_release_metadata  # noqa: E402

SELF_TEST_LOG = LOG_DIR / "self-test.log"
STATUS_RANK = {"ok": 0, "warn": 1, "warning": 1, "skipped": 1, "failed": 2, "error": 2}


def _rank(status: str) -> int:
    return STATUS_RANK.get(str(status or "ok").lower(), 1)


def _overall(checks: list[dict[str, Any]]) -> str:
    worst = max((_rank(item.get("status")) for item in checks), default=0)
    return "failed" if worst >= 2 else ("warn" if worst == 1 else "ok")


def _timed(name: str, func: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    started = time.monotonic()
    try:
        result = func()
        if "status" not in result:
            result["status"] = "ok"
    except Exception as exc:  # self-test must report all failures and continue
        result = {"status": "failed", "error_type": type(exc).__name__, "error": str(exc)}
    result["name"] = name
    result["duration_ms"] = int((time.monotonic() - started) * 1000)
    return result


def _check_python() -> dict[str, Any]:
    version = sys.version_info
    status = "ok" if version.major == 3 and version.minor >= 10 else "warn"
    return {
        "status": status,
        "python": sys.version,
        "executable": sys.executable,
        "platform": platform.platform(),
    }


def _check_imports() -> dict[str, Any]:
    modules = [
        "server.sli.core.paths",
        "server.sli.core.database",
        "server.sli.sources.collector_health",
        "server.sli.ops.system_health",
        "server.sli.ops.logging_config",
        "scripts.maintenance.collect_diagnostics",
        "scripts.maintenance.release_check",
    ]
    failures: list[dict[str, Any]] = []
    for module in modules:
        try:
            importlib.import_module(module)
        except Exception as exc:
            failures.append({"module": module, "error_type": type(exc).__name__, "error": str(exc)})
    return {"status": "failed" if failures else "ok", "modules": modules, "failures": failures}


def _check_dirs() -> dict[str, Any]:
    paths = {
        "data": DATA_DIR,
        "raw": DATA_DIR / "raw",
        "processed": DATA_DIR / "processed",
        "logs": LOG_DIR,
        "tmp": TMP_DIR,
    }
    items: list[dict[str, Any]] = []
    failures: list[str] = []
    for name, path in paths.items():
        path.mkdir(parents=True, exist_ok=True)
        probe = path / f".selftest-write-{timestamp()}.tmp"
        writable = False
        try:
            probe.write_text("ok", encoding="utf-8")
            writable = probe.read_text(encoding="utf-8") == "ok"
        except Exception as exc:
            failures.append(f"{name}: {type(exc).__name__}: {exc}")
        finally:
            try:
                probe.unlink(missing_ok=True)
            except Exception:
                pass
        items.append({"name": name, "path": str(path), "exists": path.exists(), "writable": writable})
    return {"status": "failed" if failures else "ok", "items": items, "failures": failures}


def _check_postgres_runtime_contract() -> dict[str, Any]:
    from server.sli.core.app_config import load_config
    from server.sli.storage.storage_v2_config import load_storage_v2_settings

    config = load_config()
    storage = load_storage_v2_settings(strict=True)
    backend = str(config.db_backend or "postgres").strip().lower()
    failures: list[str] = []
    if backend != "postgres":
        failures.append(f"runtime backend must be postgres, got {backend!r}")
    if not config.postgres_dsn:
        failures.append("postgres_dsn is not configured")
    if storage.read_mode != "v2":
        failures.append(f"Storage V2 read mode is {storage.read_mode!r}")
    return {
        "status": "failed" if failures else "ok",
        "runtime_backend": backend,
        "storage_read_mode": storage.read_mode,
        "storage_write_mode": storage.write_mode,
        "postgres_dsn_configured": bool(config.postgres_dsn),
        "connections_opened": 0,
        "failures": failures,
    }


def _check_config_env() -> dict[str, Any]:
    redacted = redact_env_file(PROJECT_ROOT / ".env")
    leaked = []
    for line in redacted.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if any(token in key.upper() for token in ("SECRET", "TOKEN", "PASSWORD", "API_KEY", "PRIVATE")) and value and value != "<REDACTED>":
            leaked.append(key)
    try:
        from server.sli.core.app_config import load_config

        cfg = load_config().to_dict()
    except Exception as exc:
        return {"status": "failed", "error_type": type(exc).__name__, "error": str(exc), "env_leaks": leaked}
    return {"status": "failed" if leaked else "ok", "config": cfg, "env_leaks": leaked}


def _check_runtime_exclusions() -> dict[str, Any]:
    samples = [
        "data/raw/DC1/Security/file.jsonl",
        "data/processed/ad_logs.sqlite",
        "data/logs/adlog-monitor.log",
        ".env",
        ".venv/Lib/site-packages/x.py",
        "server/sli/reporting/reports.py",
        "scripts/maintenance/self_test.py",
    ]
    decisions = {item: should_exclude_from_dev_handoff(item) for item in samples}
    failures = [item for item in samples[:5] if not decisions.get(item)]
    failures.extend(item for item in samples[5:] if decisions.get(item))
    return {"status": "failed" if failures else "ok", "decisions": decisions, "failures": failures}


def _check_log_schema() -> dict[str, Any]:
    payload = make_structured_log_payload(
        component="selftest",
        event="schema_probe",
        message="Structured log schema probe.",
        status="completed",
        stage="offline",
        duration_ms=1,
        trace_id="selftest-probe",
    )
    validation = validate_structured_log_payload(payload)
    return {"status": validation["status"], "payload": payload, "validation": validation}


def _check_pytest_temp() -> dict[str, Any]:
    env = safe_pytest_env()
    attempted: list[dict[str, Any]] = []
    fallback_basetemp = TMP_DIR / "pytest-selftest"
    for basetemp in (PYTEST_BASETEMP, fallback_basetemp):
        probe = basetemp / f"selftest-{timestamp()}.tmp"
        try:
            basetemp.mkdir(parents=True, exist_ok=True)
            probe.write_text("ok", encoding="utf-8")
            probe.unlink(missing_ok=True)
            status = "ok" if basetemp == PYTEST_BASETEMP else "warn"
            result = {
                "status": status,
                "TEMP": env["TEMP"],
                "TMP": env["TMP"],
                "PYTEST_ADDOPTS": env["PYTEST_ADDOPTS"],
                "basetemp": str(basetemp),
                "configured_basetemp": str(PYTEST_BASETEMP),
            }
            if attempted:
                result["message"] = "Configured pytest basetemp is not writable; using data/tmp fallback for self-test."
                result["attempted"] = attempted
            return result
        except Exception as exc:
            attempted.append({"basetemp": str(basetemp), "error_type": type(exc).__name__, "error": str(exc)})
        finally:
            try:
                probe.unlink(missing_ok=True)
            except Exception:
                pass
    return {"status": "failed", "attempted": attempted, "error": "No writable pytest temp directory is available."}


def _check_powershell_available() -> dict[str, Any]:
    candidates = [["pwsh", "-NoProfile", "-Command", "$PSVersionTable.PSVersion.ToString()"], ["powershell", "-NoProfile", "-Command", "$PSVersionTable.PSVersion.ToString()"]]
    for command in candidates:
        try:
            proc = subprocess.run(command, text=True, capture_output=True, timeout=8)
        except FileNotFoundError:
            continue
        except Exception as exc:
            return {"status": "warn", "error_type": type(exc).__name__, "error": str(exc)}
        if proc.returncode == 0:
            return {"status": "ok", "command": command[0], "version": proc.stdout.strip()}
    return {"status": "warn", "message": "PowerShell executable not found in this environment"}


def _live_pywin32_probe(server: str | None = None, channels: list[str] | None = None, limit: int = 3) -> dict[str, Any]:
    channels = channels or ["Security", "System"]
    try:
        import win32evtlog  # type: ignore
    except Exception as exc:
        return {"status": "warn", "pywin32_available": False, "error_type": type(exc).__name__, "error": str(exc)}
    # Keep live self-test conservative. The local or remote EventLog read path is
    # opt-in and read-only; failures are warnings unless the caller depends on live checks.
    results: list[dict[str, Any]] = []
    for channel in channels:
        item: dict[str, Any] = {"channel": channel, "server": server or "localhost"}
        try:
            # Local fallback keeps this safe on developer machines. Remote sessions
            # can be implemented later with the collector session helper.
            handle = win32evtlog.OpenEventLog(server, channel) if server else win32evtlog.OpenEventLog(None, channel)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(handle, flags, 0) or []
            item["events_read"] = min(len(events), limit)
            item["status"] = "ok"
            win32evtlog.CloseEventLog(handle)
        except Exception as exc:
            item.update({"status": "warn", "error_type": type(exc).__name__, "error": str(exc)})
        results.append(item)
    return {"status": "warn" if any(x.get("status") != "ok" for x in results) else "ok", "pywin32_available": True, "items": results}


def run_self_test(*, live: bool = False, server: str | None = None, json_log: bool = True) -> dict[str, Any]:
    started = time.monotonic()
    checks = [
        _timed("python", _check_python),
        _timed("imports", _check_imports),
        _timed("directories", _check_dirs),
        _timed("postgres_runtime_contract", _check_postgres_runtime_contract),
        _timed("config_env", _check_config_env),
        _timed("runtime_exclusions", _check_runtime_exclusions),
        _timed("structured_log_schema", _check_log_schema),
        _timed("pytest_temp", _check_pytest_temp),
        _timed("powershell", _check_powershell_available),
    ]
    if live:
        channels = [item.strip() for item in os.environ.get("ADLOG_SELFTEST_CHANNELS", "Security,System").split(",") if item.strip()]
        checks.append(_timed("live_eventlog_readonly", lambda: _live_pywin32_probe(server=server or os.environ.get("ADLOG_SELFTEST_DC"), channels=channels)))
    result = {
        "package_type": "SELF_TEST",
        "mode": "live" if live else "offline",
        "status": _overall(checks),
        "generated_at_utc": utc_now(),
        "duration_ms": int((time.monotonic() - started) * 1000),
        "release_metadata": get_release_metadata(PROJECT_ROOT),
        "checks": checks,
        "warnings": [f"{c['name']}: {c.get('message') or c.get('error') or c.get('status')}" for c in checks if c.get("status") in {"warn", "warning"}],
        "failures": [c for c in checks if c.get("status") in {"failed", "error"}],
    }
    if json_log and os.environ.get("ADLOG_SELFTEST_NO_LOG") != "1":
        write_jsonl(SELF_TEST_LOG, make_structured_log_payload(component="selftest", event="self_test_completed", message="Self-test completed.", status=result["status"], mode=result["mode"], duration_ms=result["duration_ms"]))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Run AD Log Reports self-test.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--offline", action="store_true", help="offline self-test; default")
    group.add_argument("--live", action="store_true", help="include read-only EventLog probes")
    parser.add_argument("--server", help="optional DC/server for live EventLog probe")
    parser.add_argument("--out", type=Path, help="write JSON result to file")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = run_self_test(live=args.live, server=args.server)
    if args.out:
        write_json(args.out, result)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"Self-test: {result['status']} ({result['mode']}, {result['duration_ms']} ms)")
        for item in result.get("warnings") or []:
            print(f"- {item}")
        for item in result.get("failures") or []:
            print(f"- FAILED {item.get('name')}: {item.get('error') or item.get('failures')}")
    return 0 if result["status"] in {"ok", "warn"} else 1


if __name__ == "__main__":
    raise SystemExit(main())

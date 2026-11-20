#!/usr/bin/env python3
"""One strict, revision-bound acceptance gate for the current SLI baseline.

The gate is read-only with respect to the working runtime. PostgreSQL tests
require an explicitly separate disposable DSN; the live check is one loopback
HTTP GET; collection and surveyed systems are never contacted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from urllib.request import urlopen

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.maintenance.bundle_common import (  # noqa: E402
    run_command,
    sanitized_pytest_env,
    timestamp,
    unique_pytest_basetemp,
    write_json,
)


FINGERPRINT_PATHS = (
    "package.json",
    "package-lock.json",
    "requirements.lock.txt",
    "frontend/package.json",
    "frontend/package-lock.json",
    "frontend/src",
    "frontend/tsconfig.app.json",
    "frontend/tsconfig.json",
    "frontend/vite.config.ts",
    "server",
    "sli_collect",
    "sli_agent",
    "scripts",
    "tests",
    "config",
    "web/app",
)
FINGERPRINT_EXCLUDED_PARTS = {
    "__pycache__",
    ".pytest_cache",
    ".sli-v4-parity-build",
    "node_modules",
}
FINGERPRINT_EXCLUDED_PREFIXES = ("web/app/react/", "artifacts/", "data/")


def source_fingerprint(root: Path = PROJECT_ROOT) -> str:
    rows: list[tuple[str, Path | None]] = []
    for relative in FINGERPRINT_PATHS:
        candidate = root / relative
        if candidate.is_file():
            rows.append((relative.replace("\\", "/"), candidate))
        elif candidate.is_dir():
            for file in candidate.rglob("*"):
                if not file.is_file():
                    continue
                rel = file.relative_to(root).as_posix()
                if any(part in FINGERPRINT_EXCLUDED_PARTS for part in file.parts):
                    continue
                if any(rel.startswith(prefix) for prefix in FINGERPRINT_EXCLUDED_PREFIXES):
                    continue
                rows.append((rel, file))
        else:
            rows.append((f"<missing>/{relative}", None))
    digest = hashlib.sha256()
    for rel, file in sorted(rows, key=lambda item: item[0]):
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        if file is not None:
            with file.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
        digest.update(b"\0")
    return digest.hexdigest()


def validate_loopback_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "http":
        raise ValueError("baseline live URL must use the isolated HTTP copy")
    if parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("baseline live URL must be loopback-only")
    if parsed.username or parsed.password:
        raise ValueError("credentials are forbidden in baseline live URL")
    base = url.rstrip("/")
    return base if base.endswith("/api/health") else f"{base}/api/health"


def probe_loopback_health(url: str, *, timeout: float = 10.0) -> dict[str, Any]:
    health_url = validate_loopback_url(url)
    with urlopen(health_url, timeout=timeout) as response:  # noqa: S310 - loopback validated above
        body = response.read(64 * 1024).decode("utf-8", errors="replace")
        status_code = int(response.status)
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        payload = None
    healthy = (
        status_code == 200
        and isinstance(payload, dict)
        and str(payload.get("status") or "").lower() in {"ok", "healthy"}
    )
    return {
        "exit_code": 0 if healthy else 1,
        "url": health_url,
        "http_status": status_code,
        "application_status": payload.get("status") if isinstance(payload, dict) else None,
        "method": "GET",
        "collection_started": False,
        "surveyed_system_contacted": False,
    }


def disposable_postgres_env(source: dict[str, str] | None = None) -> dict[str, str]:
    values = os.environ if source is None else source
    test_dsn = str(values.get("ADLOG_TEST_PG_DSN") or "").strip()
    production_dsn = str(values.get("ADLOG_PG_DSN") or "").strip()
    if not test_dsn:
        raise RuntimeError("ADLOG_TEST_PG_DSN is required for a disposable PostgreSQL gate")
    if production_dsn and test_dsn == production_dsn:
        raise RuntimeError("ADLOG_TEST_PG_DSN must not equal the production ADLOG_PG_DSN")
    parsed = urlparse(test_dsn)
    if parsed.scheme not in {"postgresql", "postgres"}:
        raise RuntimeError("ADLOG_TEST_PG_DSN must be a PostgreSQL URL")
    if parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise RuntimeError("ADLOG_TEST_PG_DSN must use an isolated loopback PostgreSQL")
    database = parsed.path.lstrip("/")
    if not database.startswith("sli_test_"):
        raise RuntimeError("disposable PostgreSQL database name must start with sli_test_")
    env = sanitized_pytest_env(values)
    env["ADLOG_TEST_PG_DSN"] = test_dsn
    return env


def _pytest_command(marker: str, label: str) -> list[str]:
    return [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "-m",
        marker,
        "--basetemp",
        str(unique_pytest_basetemp(label)),
    ]


def run_current_baseline_gate(
    *,
    root: Path = PROJECT_ROOT,
    live_url: str,
    plan_only: bool = False,
) -> dict[str, Any]:
    before = source_fingerprint(root)
    if plan_only:
        return {
            "status": "planned",
            "source_fingerprint": before,
            "required": {
                "disposable_postgres_env": "ADLOG_TEST_PG_DSN",
                "live_url": validate_loopback_url(live_url),
                "source_only": True,
                "windows_host": True,
                "ui_acceptance": True,
            },
            "production_mutation": False,
            "collection_started": False,
        }

    checks: dict[str, Any] = {}
    try:
        pg_env = disposable_postgres_env()
        validate_loopback_url(live_url)
    except Exception as exc:
        checks["preflight"] = {
            "exit_code": 1,
            "error_type": type(exc).__name__,
            "error": str(exc),
        }
        return {
            "status": "failed",
            "generated_at": timestamp(),
            "source_fingerprint": before,
            "failed_checks": ["preflight"],
            "checks": checks,
            "gate_classes": {
                "source_only": "not_run",
                "postgres_integration": "failed",
                "host_dependent": "not_run",
                "live": "not_run",
                "ui": "not_run",
                "same_revision": "not_run",
            },
            "production_mutation": False,
            "collection_started": False,
            "surveyed_system_contacted": False,
        }
    clean_env = sanitized_pytest_env()
    release_env = dict(clean_env)
    release_env.update(
        {
            "ADLOG_DB_BACKEND": "postgres",
            "ADLOG_PG_DSN": pg_env["ADLOG_TEST_PG_DSN"],
            "ADLOG_STORAGE_READ_MODE": "v2",
            "ADLOG_STORAGE_WRITE_MODE": "v2",
        }
    )
    checks["release_check"] = run_command(
        [sys.executable, "scripts/maintenance/release_check.py", "--json"],
        cwd=root,
        timeout=120,
        env=release_env,
    )
    checks["core"] = run_command(
        _pytest_command("core", "baseline-core"),
        cwd=root,
        timeout=600,
        env=clean_env,
    )
    checks["postgres_integration"] = run_command(
        _pytest_command("postgres_integration", "baseline-postgres"),
        cwd=root,
        timeout=900,
        env=pg_env,
    )
    checks["windows_host"] = run_command(
        _pytest_command("windows", "baseline-windows"),
        cwd=root,
        timeout=300,
        env=clean_env,
    )
    try:
        checks["live_http"] = probe_loopback_health(live_url)
    except Exception as exc:
        checks["live_http"] = {
            "exit_code": 1,
            "error_type": type(exc).__name__,
            "error": str(exc),
            "collection_started": False,
            "surveyed_system_contacted": False,
        }
    pre_ui_failures = [
        name
        for name in (
            "release_check",
            "core",
            "postgres_integration",
            "windows_host",
            "live_http",
        )
        if checks[name].get("exit_code") != 0
    ]
    if pre_ui_failures:
        checks["ui_acceptance"] = {
            "exit_code": None,
            "status": "not_run",
            "reason": "prior_gate_failed",
            "blocked_by": pre_ui_failures,
        }
    else:
        npm = shutil.which("npm.cmd") or shutil.which("npm") or "npm.cmd"
        ui_env = dict(clean_env)
        ui_env.update(
            {
                "ADLOG_DB_BACKEND": "postgres",
                "ADLOG_PG_DSN": pg_env["ADLOG_TEST_PG_DSN"],
                "ADLOG_STORAGE_READ_MODE": "v2",
                "ADLOG_STORAGE_WRITE_MODE": "v2",
                "ADLOG_DISABLE_SCHEDULER": "1",
                "ADLOG_DISABLE_COLLECTION": "1",
                "ADLOG_CONTINUOUS_RECOVERY": "false",
            }
        )
        checks["ui_acceptance"] = run_command(
            [npm, "run", "beta:menu-walk", "--", "--results", str(root / "artifacts" / "acceptance" / "beta-menu")],
            cwd=root,
            timeout=1800,
            env=ui_env,
        )
    after = source_fingerprint(root)
    checks["same_revision"] = {
        "exit_code": 0 if before == after else 1,
        "before": before,
        "after": after,
    }
    failed = [
        name
        for name, result in checks.items()
        if not isinstance(result, dict) or result.get("exit_code") != 0
    ]
    return {
        "status": "ok" if not failed else "failed",
        "generated_at": timestamp(),
        "source_fingerprint": before,
        "failed_checks": failed,
        "checks": checks,
        "gate_classes": {
            "source_only": "passed" if not {"release_check", "core"} & set(failed) else "failed",
            "postgres_integration": "passed" if "postgres_integration" not in failed else "failed",
            "host_dependent": "passed" if "windows_host" not in failed else "failed",
            "live": "passed" if "live_http" not in failed else "failed",
            "ui": (
                "not_run"
                if checks["ui_acceptance"].get("status") == "not_run"
                else ("passed" if "ui_acceptance" not in failed else "failed")
            ),
            "same_revision": "passed" if "same_revision" not in failed else "failed",
        },
        "production_mutation": False,
        "collection_started": False,
        "surveyed_system_contacted": False,
    }


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(
        description="Run the strict current-baseline SLI acceptance gate."
    )
    parser.add_argument(
        "--live-url",
        default=os.environ.get("SLI_BASELINE_LIVE_URL", "http://127.0.0.1:18082"),
    )
    parser.add_argument("--plan", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = run_current_baseline_gate(
        live_url=args.live_url,
        plan_only=args.plan,
    )
    if not args.plan:
        write_json(
            PROJECT_ROOT / "artifacts" / "acceptance" / "current_baseline_gate.json",
            result,
        )
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"Current baseline gate: {result['status']}")
        for name in result.get("failed_checks") or []:
            print(f"- failed: {name}")
    return 0 if result["status"] in {"ok", "planned"} else 1


if __name__ == "__main__":
    raise SystemExit(main())

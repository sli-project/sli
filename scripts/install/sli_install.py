"""Orchestrating installer for a Windows SLI installation (plan 9.3, first chunk).

It does not re-implement anything: the database comes from
``existing_postgres_bootstrap.py`` (baseline + later migrations), Storage V2
admission from ``storage_v2_fresh_bootstrap.py``, users from
``server.sli.access.auth``.  It never registers services or changes system
settings: service definitions are only generated into an output folder.

  python scripts/install/sli_install.py [plan]
  python scripts/install/sli_install.py apply --confirm INSTALL-SLI

Credentials come only from the environment or an interactive prompt:
  ADLOG_PG_DSN              runtime DSN of the target database (never printed)
  ADLOG_PG_ADMIN_PASSWORD   PostgreSQL ``postgres`` password (bootstrap, Storage V2)
  ADLOG_PG_ADMIN_USER       optional, default ``postgres``
  SLI_ADMIN_PASSWORD        password of the first administrator (>= 12 chars)
  SLI_PG_BIN_DIR / SLI_PG_DATA_DIR  PostgreSQL 18 bin and data directories
"""
from __future__ import annotations

import argparse
import getpass
import ipaddress
import json
import os
import re
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

CONFIRM_TOKEN = "INSTALL-SLI"
MIN_PYTHON = (3, 12)
MIN_PASSWORD_LENGTH = 12
DEFAULT_ADMIN_USERNAME = "platform-owner"
DEFAULT_PG_BIN_DIR = r"C:\Program Files\PostgreSQL\18\bin"
STORAGE_V2_TARGET = ("sli_local", 55433)
STORAGE_V2_APPLY_TOKEN = "INITIALIZE-EMPTY-LOCAL-STORAGE-V2"
LOOPBACK_NAMES = {"", "localhost", "127.0.0.1", "::1"}
STEP_ORDER = ("db_bootstrap", "storage_v2_admission", "first_admin", "tls", "service_definitions")
_SAFE_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}")


class InstallError(RuntimeError):
    """Message is always a fixed lowercase diagnostic code, never user data."""


# --------------------------------------------------------------------------
# target description (no secrets ever leave this block)
# --------------------------------------------------------------------------

def _is_loopback(host: str) -> bool:
    host = host.strip().strip("[]").lower()
    if host in LOOPBACK_NAMES:
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    mapped = getattr(address, "ipv4_mapped", None)
    return address.is_loopback or bool(mapped is not None and mapped.is_loopback)


def parse_dsn_target(dsn: str) -> dict[str, Any]:
    """Return only host/port/database of a DSN; raise a fixed code if unusable."""
    if not dsn:
        raise InstallError("dsn_missing")
    try:
        from psycopg.conninfo import conninfo_to_dict
        parts = conninfo_to_dict(dsn)
    except Exception:  # noqa: BLE001 - fixed diagnostic codes only
        raise InstallError("dsn_invalid") from None
    hosts = [h for h in str(parts.get("host") or "").split(",")]
    hostaddrs = [h for h in str(parts.get("hostaddr") or "").split(",") if h]
    try:
        port = int(str(parts.get("port") or "5432").split(",")[0])
    except ValueError:
        raise InstallError("dsn_invalid") from None
    database = str(parts.get("dbname") or "")
    if not database:
        raise InstallError("dsn_invalid")
    return {
        "host": hosts[0] if hosts else "",
        "port": port,
        "database": database,
        "loopback": all(_is_loopback(h) for h in [*hosts, *hostaddrs]),
    }


# --------------------------------------------------------------------------
# side-effecting seams (monkeypatched in tests)
# --------------------------------------------------------------------------

def probe_database(dsn: str) -> dict[str, Any]:
    """Read-only look at the target database.

    Returns ``{"reachable": False}`` or ``{"reachable": True, "versions": set,
    "has_ledger": bool, "admins": [lowercase usernames], "storage_v2_admitted": bool}``.
    """
    try:
        import psycopg
        with psycopg.connect(dsn, connect_timeout=5, autocommit=True,
                             application_name="sli_install_probe") as conn:
            conn.read_only = True
            cur = conn.cursor()
            cur.execute("select to_regclass('public.schema_migrations') is not null,"
                        " to_regclass('public.auth_users') is not null,"
                        " to_regclass('public.storage_v2_runtime_authorizations') is not null")
            has_ledger, has_users, has_admission = cur.fetchone()
            versions: set[int] = set()
            admins: list[str] = []
            admitted = False
            if has_ledger:
                cur.execute("select version from public.schema_migrations")
                versions = {int(row[0]) for row in cur.fetchall()}
            if has_users:
                cur.execute("select lower(username) from public.auth_users"
                            " where role='admin' and is_active")
                admins = [str(row[0]) for row in cur.fetchall()]
            if has_admission:
                cur.execute("select count(*) from public.storage_v2_runtime_authorizations")
                admitted = int(cur.fetchone()[0]) > 0
            return {"reachable": True, "has_ledger": bool(has_ledger), "versions": versions,
                    "admins": admins, "storage_v2_admitted": admitted}
    except Exception:  # noqa: BLE001 - fixed diagnostic codes only
        return {"reachable": False}


def run_child(argv: Sequence[str], *, env: Mapping[str, str] | None = None,
              stdin_text: str | None = None) -> tuple[int, str]:
    """Run an existing project script; output is returned, never echoed."""
    result = subprocess.run(
        list(argv), env=dict(env) if env is not None else None, input=stdin_text,
        capture_output=True, text=True, encoding="utf-8", errors="replace", check=False,
        stdin=None if stdin_text is not None else subprocess.DEVNULL, cwd=str(ROOT),
    )
    return result.returncode, (result.stdout or "") + (result.stderr or "")


def create_admin_user(username: str, password: str) -> None:
    from server.sli.access.auth import create_user
    create_user(username=username, password=password, role="admin")


def read_secret(env_name: str, prompt: str, *, confirm: bool = False) -> str:
    value = os.environ.get(env_name, "")
    if value:
        return value
    if not sys.stdin.isatty():
        raise InstallError(env_name.lower() + "_required")
    value = getpass.getpass(prompt)
    if confirm and getpass.getpass("Repeat: ") != value:
        raise InstallError("password_mismatch")
    return value


def _frontend_built(root: Path) -> bool:
    return any((root / rel / "index.html").is_file()
               for rel in ("web/app/react", "frontend/dist"))


def _child_code(output: str) -> str:
    """Pull the fixed ``code``/``status`` token out of a child's JSON, nothing else."""
    for line in reversed(output.strip().splitlines()):
        try:
            payload = json.loads(line)
        except ValueError:
            continue
        if isinstance(payload, dict):
            for key in ("code", "status"):
                value = payload.get(key)
                if isinstance(value, str) and _SAFE_CODE.fullmatch(value):
                    return value
    return "child_failed"


# --------------------------------------------------------------------------
# service definitions (generated, never executed)
# --------------------------------------------------------------------------

def _ps(value: str | Path) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def render_service_definitions(*, root: Path, host: str, port: int,
                               tls_cert: Path | None, tls_key: Path | None,
                               output_dir: Path | None = None) -> dict[str, str]:
    launcher = (output_dir if output_dir is not None else root / "artifacts" / "install") / "start-sli-web.cmd"
    python = root / ".venv" / "Scripts" / "python.exe"
    cmd = ["@echo off", "rem Generated by scripts/install/sli_install.py. No secrets here:",
           "rem ADLOG_PG_DSN is loaded by run_server.py from the worker-supervisor DPAPI profile.",
           f'cd /d "{root}"', 'set "ADLOG_AUTH_REQUIRED=1"']
    if tls_cert and tls_key:
        cmd += [f'set "ADLOG_TLS_CERT_PATH={tls_cert}"', f'set "ADLOG_TLS_KEY_PATH={tls_key}"']
    cmd.append(f'"{python}" "{root / "scripts" / "run_server.py"}" --host {host} --port {int(port)}')
    ps = f"""# Generated by scripts/install/sli_install.py. REVIEW, then run from an elevated PowerShell.
# The installer does not execute this file. Alternatives that already exist in the repo:
#   scripts\\ops\\Install-SLIWebServer-Service.ps1  (Windows service)
#   scripts\\ops\\Install-SLIWorkerSupervisor.ps1   (supervisor task)
$ErrorActionPreference = 'Stop'
$Root = {_ps(root)}
$WebLauncher = {_ps(launcher)}
$Principal = (& whoami).Trim()
$PowerShell = (Get-Command powershell.exe -ErrorAction Stop).Source
$Settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable
$TaskPrincipal = New-ScheduledTaskPrincipal -UserId $Principal -LogonType Interactive -RunLevel Limited

$WebAction = New-ScheduledTaskAction -Execute 'cmd.exe' `
    -Argument ('/c "' + $WebLauncher + '"') -WorkingDirectory $Root
Register-ScheduledTask -TaskName 'SLI Web Server' -Action $WebAction `
    -Trigger (New-ScheduledTaskTrigger -AtLogOn -User $Principal) -Principal $TaskPrincipal `
    -Settings $Settings -Description 'SLI web server (HTTP, ADR 0016)' -Force | Out-Null

$SupervisorScript = Join-Path $Root 'scripts\\ops\\Start-SLIWorkerSupervisor.ps1'
$WorkerAction = New-ScheduledTaskAction -Execute $PowerShell `
    -Argument ('-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $SupervisorScript + '" -IntervalSeconds 120') `
    -WorkingDirectory $Root
$WorkerTriggers = @(
    (New-ScheduledTaskTrigger -AtLogOn -User $Principal),
    (New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(1)) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 3650))
)
Register-ScheduledTask -TaskName 'SLI Worker Supervisor' -Action $WorkerAction -Trigger $WorkerTriggers `
    -Principal $TaskPrincipal -Settings $Settings -Description 'SLI worker supervisor' -Force | Out-Null
# Before the supervisor can run: provision its DPAPI environment once
#   & {_ps(python)} scripts\\maintenance\\worker_supervisor.py --provision-environment
"""
    return {"start-sli-web.cmd": "\r\n".join(cmd) + "\r\n", "register-sli-tasks.ps1": ps}


# --------------------------------------------------------------------------
# plan
# --------------------------------------------------------------------------

def _env_path(name: str, default: str | None = None) -> str:
    return os.environ.get(name, "").strip() or (default or "")


def build_plan(args: argparse.Namespace, *, environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    environ = os.environ if environ is None else environ
    root = Path(args.root).resolve()
    prerequisites: list[dict[str, Any]] = []
    blockers: list[str] = []

    def prereq(name: str, ok: bool, blocker: str | None = None) -> None:
        prerequisites.append({"id": name, "ok": bool(ok)})
        if not ok and blocker:
            blockers.append(blocker)

    prereq("python_version", sys.version_info >= MIN_PYTHON, "python_version_unsupported")
    prereq("frontend_build_present", _frontend_built(root), "frontend_build_missing")

    migrations: tuple = ()
    try:
        from scripts.maintenance.existing_postgres_bootstrap import (
            forward_migration_inventory,
            load_baseline,
        )
        migrations = forward_migration_inventory(root / "config" / "postgres_migrations")
        load_baseline(root / "config" / "postgres_baseline", migrations)
        prereq("baseline_verified", True)
    except Exception:  # noqa: BLE001 - fixed diagnostic codes only
        prereq("baseline_verified", False, "baseline_invalid")
    expected_versions = {item.version for item in migrations}

    # database target
    dsn = environ.get("ADLOG_PG_DSN", "")
    target: dict[str, Any] | None = None
    try:
        target = parse_dsn_target(dsn)
    except InstallError as exc:
        blockers.append(str(exc))
    prereq("dsn_from_environment", target is not None)
    state = "unknown"
    snapshot: dict[str, Any] = {"reachable": False}
    db: dict[str, Any] = {"state": state}
    if target is not None:
        db.update(host_loopback=target["loopback"], port=target["port"], database=target["database"])
        if not target["loopback"] and not args.allow_remote_db:
            blockers.append("remote_dsn_refused")
            db["state"] = "not_probed"
        else:
            snapshot = probe_database(dsn)
            if not snapshot["reachable"]:
                state = "absent_or_unreachable"
            elif not snapshot["has_ledger"]:
                state = "no_ledger"
                blockers.append("database_exists_without_ledger")
            elif expected_versions and expected_versions <= snapshot["versions"]:
                state = "current"
            else:
                state = "behind_baseline"
                blockers.append("database_behind_baseline")
            db["state"] = state
            db["admins_present"] = len(snapshot.get("admins", []))
    admins = list(snapshot.get("admins", [])) if target is not None else []

    steps: list[dict[str, Any]] = []

    # 1. database bootstrap
    bin_dir = args.pg_bin_dir or _env_path("SLI_PG_BIN_DIR", DEFAULT_PG_BIN_DIR)
    data_dir = args.pg_data_dir or _env_path("SLI_PG_DATA_DIR")
    if state == "current":
        steps.append({"id": "db_bootstrap", "status": "skip", "reason": "already_at_baseline"})
    elif state == "absent_or_unreachable" and target is not None:
        if target["host"] not in ("127.0.0.1", "localhost", "") or not target["loopback"]:
            blockers.append("bootstrap_requires_127_0_0_1")
        if not re.fullmatch(r"sli_[a-z0-9_]{0,58}", target["database"]):
            blockers.append("bootstrap_database_name_invalid")
        if not (bin_dir and (Path(bin_dir) / "psql.exe").is_file()):
            blockers.append("pg_bin_dir_invalid")
        if not (data_dir and Path(data_dir).is_dir()):
            blockers.append("pg_data_dir_invalid")
        steps.append({"id": "db_bootstrap", "status": "pending",
                      "action": "existing_postgres_bootstrap.py --apply-after-plan "
                                "(baseline + later migrations, platform-owner)",
                      "needs": ["ADLOG_PG_ADMIN_PASSWORD", "SLI_ADMIN_PASSWORD"]})
    else:
        steps.append({"id": "db_bootstrap", "status": "blocked", "reason": state})

    # 2. Storage V2 admission (script is pinned to sli_local:55433)
    if target is not None and (target["database"], target["port"]) != STORAGE_V2_TARGET:
        steps.append({"id": "storage_v2_admission", "status": "manual",
                      "reason": "storage_v2_fresh_bootstrap_pinned_to_sli_local_55433"})
    elif snapshot.get("storage_v2_admitted"):
        steps.append({"id": "storage_v2_admission", "status": "skip", "reason": "already_admitted"})
    else:
        steps.append({"id": "storage_v2_admission", "status": "pending",
                      "action": "storage_v2_fresh_bootstrap.py verify, then apply if missing",
                      "needs": ["ADLOG_PG_ADMIN_PASSWORD"]})

    # 3. first administrator
    wanted = (args.admin_username or "").strip().lower()
    if state == "absent_or_unreachable":
        if wanted and wanted != DEFAULT_ADMIN_USERNAME:
            steps.append({"id": "first_admin", "status": "manual",
                          "reason": "rerun_apply_after_runtime_profile_activation"})
        else:
            steps.append({"id": "first_admin", "status": "pending", "via": "db_bootstrap",
                          "username": DEFAULT_ADMIN_USERNAME})
    elif state == "current":
        done = (wanted in admins) if wanted else bool(admins)
        if done:
            steps.append({"id": "first_admin", "status": "skip", "reason": "administrator_present"})
        else:
            steps.append({"id": "first_admin", "status": "pending",
                          "action": "server.sli.access.auth.create_user(role=admin)",
                          "username": wanted or DEFAULT_ADMIN_USERNAME, "needs": ["SLI_ADMIN_PASSWORD"]})
    else:
        steps.append({"id": "first_admin", "status": "blocked", "reason": state})

    # 4. TLS: the server reads ADLOG_TLS_CERT_PATH / ADLOG_TLS_KEY_PATH
    cert, key = args.tls_cert, args.tls_key
    if bool(cert) != bool(key):
        blockers.append("tls_cert_and_key_required_together")
    if cert and key:
        if not (Path(cert).is_file() and Path(key).is_file()):
            blockers.append("tls_file_missing")
        steps.append({"id": "tls", "status": "pending",
                      "action": "reference cert/key paths in generated start-sli-web.cmd"})
    else:
        if not _is_loopback(args.host):
            blockers.append("non_loopback_bind_requires_tls")
        steps.append({"id": "tls", "status": "skip", "reason": "not_requested_http_on_loopback_or_reverse_proxy"})

    # 5. service definitions (generated only)
    steps.append({"id": "service_definitions", "status": "pending",
                  "action": "write register-sli-tasks.ps1 and start-sli-web.cmd (not executed)",
                  "output_dir": str(Path(args.output_dir).resolve() if args.output_dir
                                    else root / "artifacts" / "install")})
    return {"contract_version": 1, "mode": "plan", "status": "blocked" if blockers else "ready",
            "prerequisites": prerequisites, "database": db, "blockers": sorted(set(blockers)),
            "steps": steps}


# --------------------------------------------------------------------------
# apply
# --------------------------------------------------------------------------

def _validate_admin_password(value: str) -> str:
    if len(value) < MIN_PASSWORD_LENGTH or len(value) > 4096 or "\x00" in value:
        raise InstallError("admin_password_invalid")
    return value


def apply_plan(args: argparse.Namespace, plan: dict[str, Any]) -> dict[str, Any]:
    root = Path(args.root).resolve()
    dsn = os.environ.get("ADLOG_PG_DSN", "")
    target = parse_dsn_target(dsn)
    by_id = {step["id"]: step for step in plan["steps"]}
    results: list[dict[str, Any]] = []
    secrets: dict[str, str] = {}

    def secret(name: str) -> str:
        if name not in secrets:
            if name == "admin":
                secrets[name] = _validate_admin_password(
                    read_secret("SLI_ADMIN_PASSWORD", "First administrator password: ", confirm=True))
            else:
                secrets[name] = read_secret("ADLOG_PG_ADMIN_PASSWORD", "PostgreSQL administrator password: ")
        return secrets[name]

    def record(step_id: str, status: str, **extra: Any) -> None:
        results.append({"id": step_id, "status": status, **extra})

    def fail(step_id: str, code: str) -> dict[str, Any]:
        record(step_id, "failed", code=code)
        return {"contract_version": 1, "mode": "apply", "status": "failed", "steps": results}

    # Collect every needed secret before the first side effect.
    needs_admin_pw = any(by_id[s]["status"] == "pending" and "ADLOG_PG_ADMIN_PASSWORD" in by_id[s].get("needs", [])
                         for s in ("db_bootstrap", "storage_v2_admission"))
    needs_owner_pw = any(by_id[s]["status"] == "pending" and "SLI_ADMIN_PASSWORD" in by_id[s].get("needs", [])
                         for s in ("db_bootstrap", "first_admin"))
    if needs_admin_pw:
        secret("pg")
    if needs_owner_pw:
        secret("admin")

    bootstrapped = False
    for step_id in STEP_ORDER:
        step = by_id[step_id]
        if step["status"] in ("skip", "manual"):
            record(step_id, step["status"], reason=step.get("reason"))
            continue
        if step_id == "db_bootstrap":
            bin_dir = args.pg_bin_dir or _env_path("SLI_PG_BIN_DIR", DEFAULT_PG_BIN_DIR)
            data_dir = args.pg_data_dir or _env_path("SLI_PG_DATA_DIR")
            argv = [sys.executable, str(root / "scripts" / "maintenance" / "existing_postgres_bootstrap.py"),
                    "--app-root", str(root), "--bin-dir", bin_dir, "--data-dir", data_dir,
                    "--database", target["database"], "--host", "127.0.0.1",
                    "--port", str(target["port"]), "--admin-password-stdin",
                    "--platform-owner-password-stdin", "--apply-after-plan"]
            code, output = run_child(argv, env=_child_env(),
                                     stdin_text=secrets["pg"] + "\n" + secrets["admin"] + "\n")
            if code != 0:
                return fail(step_id, _child_code(output))
            bootstrapped = True
            record(step_id, "done")
        elif step_id == "storage_v2_admission":
            env = _child_env()
            env["ADLOG_PG_ADMIN_USER"] = os.environ.get("ADLOG_PG_ADMIN_USER", "").strip() or "postgres"
            env["ADLOG_PG_ADMIN_PASSWORD"] = secrets["pg"]
            script = str(root / "scripts" / "maintenance" / "storage_v2_fresh_bootstrap.py")
            code, _ = run_child([sys.executable, script, "verify"], env=env)
            if code == 0:
                record(step_id, "skip", reason="already_admitted")
                continue
            code, output = run_child(
                [sys.executable, script, "apply", "--confirm", STORAGE_V2_APPLY_TOKEN], env=env)
            if code != 0:
                return fail(step_id, _child_code(output))
            record(step_id, "done")
        elif step_id == "first_admin":
            if step.get("via") == "db_bootstrap":
                record(step_id, "done" if bootstrapped else "skip", via="db_bootstrap")
                continue
            try:
                create_admin_user(step["username"], secrets["admin"])
            except Exception:  # noqa: BLE001 - never leak driver text
                return fail(step_id, "admin_creation_failed")
            record(step_id, "done", username=step["username"])
        elif step_id == "tls":
            record(step_id, "done" if step["status"] == "pending" else "skip", reason=step.get("reason"))
        elif step_id == "service_definitions":
            out = Path(step["output_dir"])
            files = render_service_definitions(
                root=root, host=args.host, port=args.port, output_dir=out,
                tls_cert=Path(args.tls_cert).resolve() if args.tls_cert else None,
                tls_key=Path(args.tls_key).resolve() if args.tls_key else None)
            out.mkdir(parents=True, exist_ok=True)
            changed = []
            for name, content in files.items():
                path = out / name
                if not path.is_file() or path.read_bytes() != content.encode("utf-8"):
                    path.write_bytes(content.encode("utf-8"))
                    changed.append(name)
            record(step_id, "done" if changed else "skip", written=changed, output_dir=str(out),
                   registered=False)
    outcome = {"contract_version": 1, "mode": "apply", "status": "complete", "steps": results,
               "credential_values_exposed": False}
    receipt = Path(by_id["service_definitions"]["output_dir"])
    receipt.mkdir(parents=True, exist_ok=True)
    (receipt / "install-receipt.json").write_text(json.dumps(outcome, indent=2), encoding="utf-8")
    return outcome


def _child_env() -> dict[str, str]:
    """Environment for a child script: no ADLOG_PG_ADMIN_* unless set explicitly by the caller."""
    env = dict(os.environ)
    env.pop("ADLOG_PG_ADMIN_PASSWORD", None)
    env.pop("ADLOG_PG_ADMIN_USER", None)
    env["PYTHONUTF8"] = "1"
    return env


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--root", default=str(ROOT), help=argparse.SUPPRESS)
    common.add_argument("--allow-remote-db", action="store_true",
                        help="permit a non-loopback ADLOG_PG_DSN (only for an already installed database)")
    common.add_argument("--pg-bin-dir", help="PostgreSQL 18 bin dir (or SLI_PG_BIN_DIR)")
    common.add_argument("--pg-data-dir", help="PostgreSQL data dir (or SLI_PG_DATA_DIR)")
    common.add_argument("--admin-username", help=f"first administrator (default {DEFAULT_ADMIN_USERNAME})")
    common.add_argument("--host", default="127.0.0.1", help="web server bind host for generated definitions")
    common.add_argument("--port", type=int, default=8080)
    common.add_argument("--tls-cert", help="certificate file for the SLI web server (needs --tls-key)")
    common.add_argument("--tls-key", help="private key file for the SLI web server")
    common.add_argument("--output-dir", help="where service definitions are written "
                                              "(default artifacts/install)")
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("plan", parents=[common], help="read-only prerequisites check and step list (default)")
    apply_parser = sub.add_parser("apply", parents=[common], help="run the installation steps")
    apply_parser.add_argument("--confirm", help=f"must be {CONFIRM_TOKEN}")
    return parser


def _emit(payload: Mapping[str, Any], stream=None) -> None:
    print(json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True), file=stream or sys.stdout)


def main(argv: Sequence[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    if not raw or raw[0].startswith("-"):
        raw.insert(0, "plan")
    try:
        args = build_parser().parse_args(raw)
    except SystemExit as exc:
        return int(exc.code or 0)
    try:
        if args.command == "apply" and args.confirm != CONFIRM_TOKEN:
            raise InstallError("confirmation_required")
        plan = build_plan(args)
        if args.command == "plan":
            _emit(plan)
            return 0 if plan["status"] == "ready" else 2
        if plan["status"] != "ready":
            _emit({**plan, "mode": "apply", "status": "blocked"}, sys.stderr)
            return 2
        outcome = apply_plan(args, plan)
        _emit(outcome)
        return 0 if outcome["status"] == "complete" else 2
    except InstallError as exc:
        _emit({"status": "error", "code": str(exc)}, sys.stderr)
        return 2
    except Exception:  # noqa: BLE001 - fixed diagnostic codes only
        _emit({"status": "error", "code": "internal_error"}, sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

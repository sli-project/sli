"""Plan-first, one-shot native Windows PostgreSQL 18 bootstrap.

Creates only a NEW cluster, two login roles, a database and inactive DPAPI
candidates. Never loads .env, the default supervisor profile or AD credentials.
No services, scheduled tasks, application schema, migrations or workers.
Partial failure is intentionally NOT retried/cleaned up: preserve the new
private state and its safe receipt for explicit operator recovery.
"""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
from typing import Callable, Mapping, Sequence
from urllib.parse import quote, urlunparse


SYSTEM_SID = "S-1-5-18"
DEFAULT_PORT = 55433
PROFILE_RELATIVE_PATH = Path("data") / "runtime" / "local-postgres-18"
POSTGRES_TOOLS = ("initdb", "pg_ctl", "psql", "postgres")
_ALLOWED_ENVIRONMENT = ("SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP")
_SID_PATTERN = re.compile(r"S-\d+(?:-\d+)+")
_IDENTIFIER_PATTERN = re.compile(r"[a-z_][a-z0-9_]{0,62}")
_ERROR_CODE_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,63}")


class BootstrapError(RuntimeError):
    """Only fixed, nonsecret diagnostic codes may cross the CLI boundary."""


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        del message
        raise BootstrapError("invalid_arguments")


def parse_args(argv=None):
    parser = SafeParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--app-root", required=True, type=Path)
    parser.add_argument("--bin-dir", required=True, type=Path)
    parser.add_argument("--data-dir", required=True, type=Path)
    parser.add_argument("--database", required=True)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--confirm-new-cluster", help="SHA256 from the read-only plan")
    opts = parser.parse_args(argv)
    if (not _IDENTIFIER_PATTERN.fullmatch(opts.database)
            or opts.database in {"postgres", "template0", "template1"}):
        raise BootstrapError("invalid_database")
    if not 1024 <= opts.port <= 65535:
        raise BootstrapError("invalid_port")
    return opts


def _canonical_path(path: Path) -> Path:
    if not path.is_absolute():
        raise BootstrapError("unsafe_path")
    return Path(os.path.abspath(os.path.normpath(os.fspath(path))))


def _lexists(path: Path) -> bool:
    return os.path.lexists(os.fspath(path))


def _is_reparse_point(path: Path) -> bool:
    try:
        details = os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise BootstrapError("unsafe_path") from exc
    attributes = getattr(details, "st_file_attributes", 0)
    reparse_attribute = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(details.st_mode) or bool(attributes & reparse_attribute)


def _contains_reparse_point(path: Path) -> bool:
    current = path
    while True:
        if _lexists(current) and _is_reparse_point(current):
            return True
        parent = current.parent
        if parent == current:
            return False
        current = parent


def _path_key(path: Path) -> str:
    return os.path.normcase(os.path.normpath(os.fspath(path)))


def _paths_overlap(left: Path, right: Path) -> bool:
    left_key = _path_key(left)
    right_key = _path_key(right)
    try:
        return os.path.commonpath((left_key, right_key)) in {left_key, right_key}
    except ValueError:
        return False


def validate_paths(opts) -> dict[str, Path]:
    raw = {
        "app": opts.app_root,
        "bin": opts.bin_dir,
        "data": opts.data_dir,
    }
    paths = {name: _canonical_path(path) for name, path in raw.items()}
    paths["profiles"] = _canonical_path(paths["app"] / PROFILE_RELATIVE_PATH)

    for name in ("app", "bin"):
        path = paths[name]
        if not _lexists(path) or not path.is_dir():
            raise BootstrapError("required_path_missing")
        if _contains_reparse_point(path):
            raise BootstrapError("unsafe_reparse_point")

    for name in ("data", "profiles"):
        path = paths[name]
        if _contains_reparse_point(path):
            raise BootstrapError("unsafe_reparse_point")
        if _lexists(path):
            raise BootstrapError("target_exists")

    disallowed_pairs = (
        (paths["data"], paths["profiles"]),
        (paths["data"], paths["app"]),
        (paths["data"], paths["bin"]),
        (paths["profiles"], paths["bin"]),
    )
    if any(_paths_overlap(left, right) for left, right in disallowed_pairs):
        raise BootstrapError("overlapping_paths")
    return paths


def child_environment(bin_dir: Path, source: Mapping[str, str] | None = None) -> dict[str, str]:
    source = os.environ if source is None else source
    folded = {str(key).upper(): str(value) for key, value in source.items()}
    result = {
        key: folded[key]
        for key in _ALLOWED_ENVIRONMENT
        if folded.get(key)
    }
    result["PATH"] = str(bin_dir)
    return result


def _system_root(source: Mapping[str, str]) -> Path:
    folded = {str(key).upper(): str(value) for key, value in source.items()}
    value = folded.get("SYSTEMROOT")
    if not value:
        current = {str(key).upper(): str(value) for key, value in os.environ.items()}
        value = current.get("SYSTEMROOT") or current.get("WINDIR")
    if not value:
        raise BootstrapError("windows_native_tool_unavailable")
    return Path(value)


def _native_executable(name: str, source: Mapping[str, str]) -> Path:
    executable = _system_root(source) / "System32" / name
    if not executable.is_file() or _is_reparse_point(executable):
        raise BootstrapError("windows_native_tool_unavailable")
    return executable


def _powershell_executable(source: Mapping[str, str]) -> Path:
    executable = (_system_root(source) / "System32" / "WindowsPowerShell" /
                  "v1.0" / "powershell.exe")
    if not executable.is_file() or _is_reparse_point(executable):
        raise BootstrapError("windows_native_tool_unavailable")
    return executable


def _run_process(
    command: Sequence[str],
    *,
    env: Mapping[str, str],
    input_text: str | None = None,
    capture_output: bool = True,
):
    try:
        if not capture_output:
            return subprocess.run(
                list(command),
                env=dict(env),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                shell=False,
            )
        return subprocess.run(
            list(command),
            env=dict(env),
            input=input_text,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            shell=False,
        )
    except OSError as exc:
        raise BootstrapError("command_failed") from exc


def _run_checked(
    runner: Callable,
    command: Sequence[str],
    *,
    env: Mapping[str, str],
    input_text: str | None = None,
    capture_output: bool = True,
):
    try:
        runner_kwargs = {"env": dict(env), "input_text": input_text}
        if not capture_output:
            runner_kwargs["capture_output"] = False
        result = runner(list(command), **runner_kwargs)
    except BootstrapError:
        raise
    except Exception as exc:
        raise BootstrapError("command_failed") from exc
    if result.returncode != 0:
        raise BootstrapError("command_failed")
    return result


def local_identity(
    source: Mapping[str, str] | None = None,
    *,
    runner: Callable = _run_process,
) -> dict[str, str]:
    source = os.environ if source is None else source
    whoami = _native_executable("whoami.exe", source)
    environment = child_environment(whoami.parent, source)
    result = _run_checked(
        runner,
        [str(whoami), "/user", "/fo", "csv", "/nh"],
        env=environment,
    )
    try:
        row = next(csv.reader([(result.stdout or "").strip()]))
    except (csv.Error, StopIteration) as exc:
        raise BootstrapError("identity_readback_failed") from exc
    if len(row) != 2:
        raise BootstrapError("identity_readback_failed")
    principal, sid = (item.strip() for item in row)
    if "\\" not in principal or not _SID_PATTERN.fullmatch(sid):
        raise BootstrapError("identity_readback_failed")
    return {"principal": principal, "sid": sid}


def _powershell_command(executable: Path, script: str) -> list[str]:
    return [
        str(executable),
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        script,
    ]


def create_private_directory(
    target: Path,
    sid: str,
    *,
    source: Mapping[str, str] | None = None,
    runner: Callable = _run_process,
) -> None:
    source = os.environ if source is None else source
    target = _canonical_path(target)
    if not _SID_PATTERN.fullmatch(sid):
        raise BootstrapError("invalid_identity")
    if _contains_reparse_point(target):
        raise BootstrapError("unsafe_reparse_point")
    if _lexists(target):
        raise BootstrapError("target_exists")
    powershell = _powershell_executable(source)
    environment = child_environment(powershell.parent, source)
    environment["SLI_BOOTSTRAP_TARGET"] = str(target)
    environment["SLI_BOOTSTRAP_SID"] = sid
    script = r"""
$ErrorActionPreference = 'Stop'
$security = New-Object System.Security.AccessControl.DirectorySecurity
$security.SetAccessRuleProtection($true, $false)
$inheritance = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
$propagation = [System.Security.AccessControl.PropagationFlags]::None
$allow = [System.Security.AccessControl.AccessControlType]::Allow
foreach ($value in @($env:SLI_BOOTSTRAP_SID, 'S-1-5-18')) {
    $identity = New-Object System.Security.Principal.SecurityIdentifier($value)
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $identity, [System.Security.AccessControl.FileSystemRights]::FullControl,
        $inheritance, $propagation, $allow)
    [void]$security.AddAccessRule($rule)
}
$directory = New-Object System.IO.DirectoryInfo($env:SLI_BOOTSTRAP_TARGET)
$directory.Create($security)
[Console]::Out.Write('created')
""".strip()
    _run_checked(
        runner,
        _powershell_command(powershell, script),
        env=environment,
    )
    if not target.is_dir() or _contains_reparse_point(target):
        raise BootstrapError("private_directory_failed")


def verify_private_directory(
    target: Path,
    sid: str,
    *,
    source: Mapping[str, str] | None = None,
    runner: Callable = _run_process,
) -> bool:
    source = os.environ if source is None else source
    target = _canonical_path(target)
    if not target.is_dir() or _contains_reparse_point(target):
        return False
    if not _SID_PATTERN.fullmatch(sid):
        raise BootstrapError("invalid_identity")
    powershell = _powershell_executable(source)
    environment = child_environment(powershell.parent, source)
    environment["SLI_BOOTSTRAP_TARGET"] = str(target)
    script = r"""
$ErrorActionPreference = 'Stop'
$rows = @()
foreach ($entry in (Get-Acl -LiteralPath $env:SLI_BOOTSTRAP_TARGET).Access) {
    $translated = $entry.IdentityReference.Translate(
        [System.Security.Principal.SecurityIdentifier]).Value
    $rows += [pscustomobject]@{
        sid = $translated
        type = $entry.AccessControlType.ToString()
        rights = $entry.FileSystemRights.ToString()
        inherited = [bool]$entry.IsInherited
        inheritance = $entry.InheritanceFlags.ToString()
        propagation = $entry.PropagationFlags.ToString()
    }
}
[Console]::Out.Write((ConvertTo-Json -InputObject @($rows) -Compress))
""".strip()
    result = _run_checked(
        runner,
        _powershell_command(powershell, script),
        env=environment,
    )
    try:
        rows = json.loads((result.stdout or "").strip())
    except (json.JSONDecodeError, TypeError) as exc:
        raise BootstrapError("acl_readback_failed") from exc
    if isinstance(rows, dict):
        rows = [rows]
    if not isinstance(rows, list) or len(rows) != 2:
        return False
    expected_sids = {sid, SYSTEM_SID}
    observed_sids = set()
    for row in rows:
        if not isinstance(row, dict):
            return False
        observed_sids.add(row.get("sid"))
        inheritance = {
            item.strip()
            for item in str(row.get("inheritance", "")).split(",")
            if item.strip()
        }
        if (
            row.get("type") != "Allow"
            or row.get("rights") != "FullControl"
            or row.get("inherited") is not False
            or inheritance != {"ContainerInherit", "ObjectInherit"}
            or row.get("propagation") != "None"
        ):
            return False
    return observed_sids == expected_sids


def validate_postgres_tools(
    bin_dir: Path,
    *,
    runner: Callable = _run_process,
    source: Mapping[str, str] | None = None,
) -> dict[str, dict[str, str]]:
    source = os.environ if source is None else source
    bin_dir = _canonical_path(bin_dir)
    if not bin_dir.is_dir() or _contains_reparse_point(bin_dir):
        raise BootstrapError("required_path_missing")
    environment = child_environment(bin_dir, source)
    tools: dict[str, dict[str, str]] = {}
    for name in POSTGRES_TOOLS:
        executable = bin_dir / f"{name}.exe"
        if (not executable.is_file() or _contains_reparse_point(executable)):
            raise BootstrapError("postgresql_18_required")
        result = _run_checked(
            runner,
            [str(executable), "--version"],
            env=environment,
        )
        output = (result.stdout or "").strip()
        match = re.fullmatch(
            re.escape(name) + r" \(PostgreSQL\) (18(?:\.\d+)*)",
            output,
        )
        if not match:
            raise BootstrapError("postgresql_18_required")
        tools[name] = {"path": str(executable), "version": match.group(1)}
    return tools


def _role_names(database: str) -> dict[str, str]:
    suffix = hashlib.sha256(database.encode("ascii")).hexdigest()[:12]
    return {
        "migration": f"sli_migration_{suffix}",
        "runtime": f"sli_runtime_{suffix}",
    }


def build_plan(opts, paths, identity, tools) -> dict:
    roles = _role_names(opts.database)
    return {
        "contract_version": 1,
        "operation": "new_local_postgresql_18_cluster",
        "paths": {
            "app_root": str(paths["app"]),
            "bin_dir": str(paths["bin"]),
            "data_dir": str(paths["data"]),
            "profile_candidates_dir": str(paths["profiles"]),
        },
        "identity": {
            "principal": identity["principal"],
            "sid": identity["sid"],
        },
        "postgresql": {
            "major": 18,
            "listen_address": "127.0.0.1",
            "port": opts.port,
            "tools": {
                name: {
                    "path": str(tools[name]["path"]),
                    "version": str(tools[name]["version"]),
                }
                for name in POSTGRES_TOOLS
            },
        },
        "database": opts.database,
        "roles": roles,
        "profile_candidates": [
            "migration.candidate.json",
            "runtime.candidate.json",
        ],
        "planned_actions": [
            "create_private_directories",
            "initialize_new_cluster",
            "configure_loopback_only",
            "create_separated_login_roles",
            "create_database",
            "write_inactive_dpapi_candidates",
            "write_safe_receipt",
        ],
        "excluded_actions": [
            "application_schema",
            "migration",
            "worker",
            "service",
            "scheduled_task",
            "source_access",
            "existing_target_modification",
        ],
    }


def canonical_json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def plan_confirmation(plan) -> str:
    return hashlib.sha256(canonical_json(plan).encode("utf-8")).hexdigest()


def plan_envelope(plan) -> dict:
    return {
        "confirmation_sha256": plan_confirmation(plan),
        "mode": "plan",
        "plan": plan,
    }


def _safe_error_code(error: BaseException) -> str:
    code = str(error)
    return code if _ERROR_CODE_PATTERN.fullmatch(code) else "internal_error"


def _write_json_atomic(path: Path, value, *, must_be_new: bool = False) -> None:
    if must_be_new and _lexists(path):
        raise BootstrapError("target_exists")
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(canonical_json(value))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        if must_be_new and _lexists(path):
            raise BootstrapError("target_exists")
        if must_be_new:
            # Native Windows rename fails rather than replacing a raced target.
            os.rename(temporary, path)
        else:
            os.replace(temporary, path)
    except BootstrapError:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    except OSError as exc:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise BootstrapError("receipt_write_failed") from exc


def _append_cluster_configuration(data_dir: Path, port: int) -> None:
    configuration = data_dir / "postgresql.conf"
    access = data_dir / "pg_hba.conf"
    for path in (configuration, access):
        if not path.is_file() or _is_reparse_point(path):
            raise BootstrapError("cluster_configuration_failed")
    try:
        with configuration.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write("\n# SLI isolated native bootstrap\n")
            stream.write("listen_addresses = '127.0.0.1'\n")
            stream.write(f"port = {port}\n")
            stream.write("password_encryption = 'scram-sha-256'\n")
            # Never let a failed credential-bearing statement reach the server log.
            stream.write("log_statement = 'none'\n")
            stream.write("log_min_error_statement = 'panic'\n")
            stream.write("log_parameter_max_length = 0\n")
            stream.write("log_parameter_max_length_on_error = 0\n")
        access_text = (
            "# SLI isolated native bootstrap: loopback IPv4 only\n"
            "host all all 127.0.0.1/32 scram-sha-256\n"
            "host all all 0.0.0.0/0 reject\n"
            "host all all ::0/0 reject\n"
        )
        temporary = access.with_name(f".{access.name}.{secrets.token_hex(8)}.tmp")
        with temporary.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(access_text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, access)
    except OSError as exc:
        raise BootstrapError("cluster_configuration_failed") from exc


def _quote_identifier(value: str) -> str:
    if not _IDENTIFIER_PATTERN.fullmatch(value):
        raise BootstrapError("invalid_identifier")
    return f'"{value}"'


def _quote_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _password(label: str) -> str:
    del label
    return secrets.token_urlsafe(36)


def _single_user_command(postgres: str, data_dir: Path, database: str) -> list[str]:
    if database != "postgres" and not _IDENTIFIER_PATTERN.fullmatch(database):
        raise BootstrapError("invalid_database")
    return [postgres, "--single", "-D", str(data_dir), database]


def _superuser_password_sql(secret: str) -> str:
    return "\n".join((
        "SET password_encryption = 'scram-sha-256';",
        f"ALTER ROLE postgres PASSWORD {_quote_literal(secret)};",
        "",
    ))


def _create_database_sql(database: str, roles: Mapping[str, str], credentials: Mapping[str, str]) -> str:
    migration = _quote_identifier(roles["migration"])
    runtime = _quote_identifier(roles["runtime"])
    target_database = _quote_identifier(database)
    return "\n".join((
        "SET client_min_messages = warning;",
        "SET password_encryption = 'scram-sha-256';",
        f"CREATE ROLE {migration} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION PASSWORD {_quote_literal(credentials['migration'])};",
        f"CREATE ROLE {runtime} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION PASSWORD {_quote_literal(credentials['runtime'])};",
        f"CREATE DATABASE {target_database} OWNER {migration} TEMPLATE template0 ENCODING 'UTF8';",
        f"REVOKE ALL ON DATABASE {target_database} FROM PUBLIC;",
        f"GRANT CONNECT, TEMPORARY ON DATABASE {target_database} TO {migration};",
        f"GRANT CONNECT ON DATABASE {target_database} TO {runtime};",
        "",
    ))


def _database_permissions_sql(roles: Mapping[str, str]) -> str:
    migration = _quote_identifier(roles["migration"])
    runtime = _quote_identifier(roles["runtime"])
    return "\n".join((
        "SET client_min_messages = warning;",
        "REVOKE CREATE ON SCHEMA public FROM PUBLIC;",
        f"GRANT ALL ON SCHEMA public TO {migration};",
        f"GRANT USAGE ON SCHEMA public TO {runtime};",
        "",
    ))


def _readback_sql(database: str, roles: Mapping[str, str]) -> str:
    database_literal = _quote_literal(database)
    migration_literal = _quote_literal(roles["migration"])
    runtime_literal = _quote_literal(roles["runtime"])
    database_query = (
        "SELECT 'bootstrap_readback|' || d.datname || '|' || r.rolname "
        "FROM pg_database d JOIN pg_roles r ON r.oid = d.datdba "
        f"WHERE d.datname = {database_literal};"
    )
    roles_query = (
        "SELECT 'role|' || rolname || '|' || rolcanlogin::text || '|' || "
        "rolsuper::text || '|' || rolcreatedb::text || '|' || "
        "rolcreaterole::text || '|' || rolreplication::text FROM pg_roles "
        f"WHERE rolname IN ({migration_literal}, {runtime_literal}) ORDER BY rolname;"
    )
    return "\n".join((database_query, roles_query, ""))


def _verify_database_readback(stdout: str, database: str, roles: Mapping[str, str]) -> None:
    expected = {
        f"bootstrap_readback|{database}|{roles['migration']}",
        f"role|{roles['migration']}|true|false|false|false|false",
        f"role|{roles['runtime']}|true|false|false|false|false",
    }
    if any(marker not in stdout for marker in expected):
        raise BootstrapError("database_readback_failed")


def _dpapi_protect(
    plaintext: str,
    *,
    source: Mapping[str, str] | None = None,
    runner: Callable = _run_process,
) -> str:
    source = os.environ if source is None else source
    powershell = _powershell_executable(source)
    environment = child_environment(powershell.parent, source)
    script = r"""
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security
$value = [Console]::In.ReadToEnd()
$bytes = [System.Text.Encoding]::UTF8.GetBytes($value)
$entropy = [System.Text.Encoding]::UTF8.GetBytes('sli-local-postgres-18-profile-v1')
$sealed = [System.Security.Cryptography.ProtectedData]::Protect(
    $bytes, $entropy,
    [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
[Console]::Out.Write([Convert]::ToBase64String($sealed))
""".strip()
    result = _run_checked(
        runner,
        _powershell_command(powershell, script),
        env=environment,
        input_text=plaintext,
    )
    protected = (result.stdout or "").strip()
    try:
        decoded = base64.b64decode(protected, validate=True)
    except (ValueError, TypeError) as exc:
        raise BootstrapError("dpapi_protection_failed") from exc
    if not decoded:
        raise BootstrapError("dpapi_protection_failed")
    return protected


def _candidate(role_kind: str, role: str, sid: str, protected: str) -> dict:
    return {
        "active": False,
        "candidate_version": 1,
        "identity_sid": sid,
        "kind": role_kind,
        "payload": protected,
        "protection": "windows-dpapi-current-user",
        "role": role,
    }


def apply_bootstrap(
    opts,
    paths,
    identity,
    tools,
    confirmation_sha256: str,
    *,
    runner: Callable = _run_process,
    password_factory: Callable[[str], str] = _password,
    protector: Callable[[str], str] = _dpapi_protect,
    directory_creator: Callable[[Path, str], None] = create_private_directory,
    directory_verifier: Callable[[Path, str], bool] = verify_private_directory,
    source: Mapping[str, str] | None = None,
) -> Path:
    source = os.environ if source is None else source
    expected_paths = validate_paths(opts)
    if any(expected_paths[name] != paths[name] for name in expected_paths):
        raise BootstrapError("plan_changed")
    current_plan = build_plan(opts, paths, identity, tools)
    expected_confirmation = plan_confirmation(current_plan)
    if not hmac.compare_digest(confirmation_sha256 or "", expected_confirmation):
        raise BootstrapError("confirmation_mismatch")

    sid = identity["sid"]
    directory_creator(paths["profiles"], sid)
    if not directory_verifier(paths["profiles"], sid):
        raise BootstrapError("acl_verification_failed")

    receipt_path = paths["profiles"] / "receipt.json"
    receipt = {
        "confirmation_sha256": confirmation_sha256,
        "contract_version": 1,
        "database": opts.database,
        "data_dir": str(paths["data"]),
        "error_code": None,
        "identity_sid": sid,
        "last_completed_stage": "profile_directory_created",
        "roles": current_plan["roles"],
        "status": "in_progress",
    }
    _write_json_atomic(receipt_path, receipt)

    def checkpoint(stage: str) -> None:
        receipt["last_completed_stage"] = stage
        _write_json_atomic(receipt_path, receipt)

    try:
        directory_creator(paths["data"], sid)
        if not directory_verifier(paths["data"], sid):
            raise BootstrapError("acl_verification_failed")
        checkpoint("private_directories_created")

        credentials = {
            "superuser": password_factory("superuser"),
            "migration": password_factory("migration"),
            "runtime": password_factory("runtime"),
        }
        if any(not isinstance(value, str) or len(value) < 16 for value in credentials.values()):
            raise BootstrapError("credential_generation_failed")

        base_environment = child_environment(paths["bin"], source)
        initdb_command = [
            tools["initdb"]["path"],
            "-D",
            str(paths["data"]),
            "--username=postgres",
            "--auth-host=reject",
            "--auth-local=reject",
            "--encoding=UTF8",
        ]
        _run_checked(
            runner,
            initdb_command,
            env=base_environment,
        )
        checkpoint("cluster_initialized")

        postgres = tools["postgres"]["path"]
        _run_checked(
            runner,
            _single_user_command(postgres, paths["data"], "postgres"),
            env=base_environment,
            input_text=_superuser_password_sql(credentials["superuser"]),
        )
        checkpoint("superuser_password_set")

        _run_checked(
            runner,
            _single_user_command(postgres, paths["data"], "postgres"),
            env=base_environment,
            input_text=_create_database_sql(
                opts.database, current_plan["roles"], credentials),
        )
        _run_checked(
            runner,
            _single_user_command(postgres, paths["data"], opts.database),
            env=base_environment,
            input_text=_database_permissions_sql(current_plan["roles"]),
        )
        checkpoint("database_and_roles_created")

        readback = _run_checked(
            runner,
            _single_user_command(postgres, paths["data"], "postgres"),
            env=base_environment,
            input_text=_readback_sql(opts.database, current_plan["roles"]),
        )
        _verify_database_readback(
            "\n".join(filter(None, (readback.stdout, readback.stderr))),
            opts.database,
            current_plan["roles"],
        )
        checkpoint("database_readback_verified")

        _append_cluster_configuration(paths["data"], opts.port)
        checkpoint("loopback_configuration_written")

        _run_checked(
            runner,
            [
                tools["pg_ctl"]["path"],
                "-D",
                str(paths["data"]),
                "-l",
                str(paths["data"] / "bootstrap-postgres.log"),
                "-w",
                "start",
            ],
            env=base_environment,
            capture_output=False,
        )
        checkpoint("server_started")

        for role_kind in ("migration", "runtime"):
            role = current_plan["roles"][role_kind]
            credential = quote(credentials[role_kind], safe="")
            connection = urlunparse(
                (
                    "postgresql",
                    f"{role}:{credential}@127.0.0.1:{opts.port}",
                    f"/{opts.database}",
                    "",
                    "",
                    "",
                )
            )
            protected = protector(connection)
            candidate_path = paths["profiles"] / f"{role_kind}.candidate.json"
            _write_json_atomic(
                candidate_path,
                _candidate(role_kind, role, sid, protected),
                must_be_new=True,
            )
        checkpoint("profiles_written")
        receipt["status"] = "complete"
        _write_json_atomic(receipt_path, receipt)
        return receipt_path
    except BootstrapError as exc:
        receipt["status"] = "partial_failure"
        receipt["error_code"] = _safe_error_code(exc)
        try:
            _write_json_atomic(receipt_path, receipt)
        except BootstrapError:
            pass
        raise BootstrapError("bootstrap_partial_failure") from None
    except Exception:
        receipt["status"] = "partial_failure"
        receipt["error_code"] = "internal_error"
        try:
            _write_json_atomic(receipt_path, receipt)
        except BootstrapError:
            pass
        raise BootstrapError("bootstrap_partial_failure") from None


def main(argv=None) -> int:
    try:
        opts = parse_args(argv)
        paths = validate_paths(opts)
        identity = local_identity()
        tools = validate_postgres_tools(paths["bin"])
        plan = build_plan(opts, paths, identity, tools)
        confirmation = plan_confirmation(plan)
        if not opts.apply:
            print(canonical_json(plan_envelope(plan)))
            return 0
        if not hmac.compare_digest(opts.confirm_new_cluster or "", confirmation):
            raise BootstrapError("confirmation_mismatch")
        receipt = apply_bootstrap(
            opts, paths, identity, tools, confirmation)
        print(canonical_json({
            "confirmation_sha256": confirmation,
            "mode": "apply",
            "receipt": str(receipt),
            "status": "complete",
        }))
        return 0
    except BootstrapError as exc:
        print(canonical_json({
            "code": _safe_error_code(exc),
            "status": "error",
        }), file=sys.stderr)
        return 2
    except Exception:
        print(canonical_json({
            "code": "internal_error",
            "status": "error",
        }), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

"""Bootstrap the SLI schema in an existing loopback PostgreSQL 18 cluster."""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
import getpass
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import sys
from typing import Callable, Mapping, Sequence
from urllib.parse import quote, urlunparse
import secrets
from datetime import datetime, timezone


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


_FORWARD_NAME = re.compile(r"^(\d{3})_([a-z0-9_]+)\.sql$")
_ROLLBACK_NAME = re.compile(r"(?:\.|_)rollback\.sql$")
_IDENTIFIER = re.compile(r"[a-z_][a-z0-9_]{0,62}")
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
from deploy.linux.release_package import MIGRATION_MARKER as _MARKER

_BASE_MARKER_BLOCK = re.compile(
    r"insert\s+into\s+(?:public\.)?schema_migrations\s*"
    r"\(\s*version\s*,\s*name\s*\)\s*values(?P<body>.*?)"
    r"on\s+conflict\s*\(\s*version\s*\)",
    re.IGNORECASE | re.DOTALL,
)
_MARKER_TUPLE = re.compile(r"\(\s*(\d+)\s*,\s*'([^']+)'\s*\)")
EMPTY_DATABASE_V2_ROUTE_SQL = (
    "update public.storage_v2_cutover_state "
    "set read_mode='v2', write_mode='v2', shadow_sample_rate=0 "
    "where singleton=true"
)
RUNTIME_SCHEMA_BOOTSTRAP_GRANT_SQL = (
    "GRANT USAGE, CREATE ON SCHEMA public TO adlog_user"
)
PGCRYPTO_BOOTSTRAP_SQL = "CREATE EXTENSION IF NOT EXISTS pgcrypto"
RUNTIME_SCHEMA_CREATE_REVOKE_SQL = (
    "REVOKE CREATE ON SCHEMA public FROM adlog_user"
)
_ADMIN_CREDENTIAL_PURPOSE = "sli-existing-postgres-admin-v1"
_PLATFORM_OWNER_CREDENTIAL_PURPOSE = "sli-platform-owner-password-v1"
_ADMIN_MIGRATION_VERSIONS = frozenset(
    {
        # Migration 020 creates indexes on both adlog_user-owned legacy tables
        # and adlog_storage_owner-owned v2 tables in one autocommit session.
        20,
        # These migrations have source-owned maintenance controllers whose
        # apply/rollback paths explicitly require the local PostgreSQL admin.
        43,
        44,
        45,
        47,
        48,
        49,
        77,
        111,
        113,
        114,
        115,
        118,
        119,
        120,
        121,
        122,
        123,
        124,
        125,
        127,
        128,
        129,
        130,
    }
)
_ADMIN_CREDENTIAL_RELATIVE_PATH = (
    Path("data") / "runtime" / "local-postgres-admin" / "postgres-admin.dpapi.json"
)
_DPAPI_UI_FORBIDDEN = 1


class BootstrapError(RuntimeError):
    """Expose only fixed diagnostic codes at the command boundary."""


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        del message
        raise BootstrapError("invalid_arguments")


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    path: Path
    sha256: str


@dataclass(frozen=True)
class ClusterSnapshot:
    server_version_num: int
    data_directory: Path
    server_address: str
    server_port: int
    database_exists: bool
    runtime_role_exists: bool
    current_user: str = "postgres"
    admin_is_superuser: bool = True


def forward_migration_inventory(root: Path) -> tuple[Migration, ...]:
    migrations: list[Migration] = []
    for path in sorted(root.glob("*.sql"), key=lambda item: item.name):
        if _ROLLBACK_NAME.search(path.name):
            continue
        filename = _FORWARD_NAME.fullmatch(path.name)
        if filename is None:
            continue
        sql = path.read_text(encoding="utf-8")
        markers = _MARKER.findall(sql)
        if not markers:
            raise BootstrapError("migration_marker_missing")
        marker_version, marker_name = markers[-1]
        version = int(filename.group(1))
        if int(marker_version) != version:
            raise BootstrapError("migration_marker_mismatch")
        migrations.append(
            Migration(
                version=version,
                name=marker_name,
                path=path,
                sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            )
        )
    versions = [item.version for item in migrations]
    if len(versions) != len(set(versions)):
        raise BootstrapError("migration_version_duplicate")
    return tuple(migrations)


def base_schema_markers(schema_path: Path) -> tuple[tuple[int, str], ...]:
    sql = schema_path.read_text(encoding="utf-8")
    blocks = _BASE_MARKER_BLOCK.findall(sql)
    if not blocks:
        raise BootstrapError("base_schema_markers_missing")
    markers = tuple(
        (int(version), name) for version, name in _MARKER_TUPLE.findall(blocks[-1])
    )
    if not markers or len({version for version, _name in markers}) != len(markers):
        raise BootstrapError("base_schema_markers_invalid")
    return markers


def configured_source_domain(config_path: Path) -> str:
    """Derive one source-owned DNS domain from the controller inventory."""
    try:
        payload = json.loads(config_path.read_text(encoding="utf-8"))
        controllers = payload["domain_controllers"]
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise BootstrapError("source_domain_config_invalid") from exc
    if not isinstance(controllers, list) or not controllers:
        raise BootstrapError("source_domain_config_invalid")
    domains: set[str] = set()
    for controller in controllers:
        if not isinstance(controller, dict):
            raise BootstrapError("source_domain_config_invalid")
        address = str(controller.get("connect_address") or "").strip().lower()
        labels = address.split(".")
        if (
            len(labels) < 3
            or len(address) > 253
            or any(_DNS_LABEL.fullmatch(label) is None for label in labels)
        ):
            raise BootstrapError("source_domain_config_invalid")
        domains.add(".".join(labels[1:]))
    if len(domains) != 1:
        raise BootstrapError("source_domain_ambiguous")
    return next(iter(domains))


def seed_source_domain(execute: Callable[..., object], domain_fqdn: str) -> None:
    """Create the source identity required by domain-bound report migrations."""
    domain = str(domain_fqdn or "").strip().lower()
    labels = domain.split(".")
    if (
        len(labels) < 2
        or len(domain) > 253
        or any(_DNS_LABEL.fullmatch(label) is None for label in labels)
    ):
        raise BootstrapError("source_domain_config_invalid")
    forest_row = execute(
        """
        insert into public.forests(name) values (%s)
        on conflict(name) do update set name=excluded.name
        returning id
        """,
        (domain,),
    ).fetchone()
    if forest_row is None:
        raise BootstrapError("source_domain_seed_failed")
    domain_row = execute(
        """
        insert into public.domains(forest_id,fqdn)
        values (%s,%s)
        on conflict(forest_id,fqdn) do update set fqdn=excluded.fqdn
        returning id
        """,
        (int(forest_row[0]), domain),
    ).fetchone()
    if domain_row is None:
        raise BootstrapError("source_domain_seed_failed")
    count_row = execute(
        "select count(*) from public.domains where lower(fqdn)=lower(%s)",
        (domain,),
    ).fetchone()
    if count_row is None or int(count_row[0]) != 1:
        raise BootstrapError("source_domain_seed_failed")


def build_plan(
    *,
    database: str,
    expected_data_directory: Path,
    snapshot: ClusterSnapshot,
    schema_sha256: str,
    roles_sha256: str,
    migrations: tuple[Migration, ...],
) -> dict[str, object]:
    return {
        "contract_version": 1,
        "operation": "bootstrap_existing_postgresql_18",
        "database": database,
        "roles": {"migration": "postgres", "runtime": "adlog_user"},
        "cluster": {
            "server_version_num": snapshot.server_version_num,
            "data_directory": str(expected_data_directory),
            "server_address": snapshot.server_address,
            "server_port": snapshot.server_port,
            "database_exists": snapshot.database_exists,
            "runtime_role_exists": snapshot.runtime_role_exists,
            "current_user": snapshot.current_user,
            "admin_is_superuser": snapshot.admin_is_superuser,
        },
        "schema_sha256": schema_sha256,
        "roles_sha256": roles_sha256,
        "migrations": [
            {
                "version": item.version,
                "name": item.name,
                "path": item.path.name,
                "sha256": item.sha256,
            }
            for item in migrations
        ],
    }


def plan_confirmation(plan: dict[str, object]) -> str:
    payload = json.dumps(
        plan, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _path_key(path: Path) -> str:
    return os.path.normcase(os.path.abspath(os.path.normpath(os.fspath(path))))


def _quote_identifier(value: str) -> str:
    if _IDENTIFIER.fullmatch(value) is None:
        raise BootstrapError("invalid_identifier")
    return f'"{value}"'


def validate_cluster_identity(
    snapshot: ClusterSnapshot,
    *,
    expected_data_directory: Path,
    expected_port: int,
) -> None:
    if snapshot.server_version_num // 10000 != 18:
        raise BootstrapError("postgresql_18_required")
    if snapshot.current_user != "postgres" or not snapshot.admin_is_superuser:
        raise BootstrapError("postgres_admin_required")
    try:
        # PostgreSQL's ``inet`` text representation may include the address
        # family mask (for example ``127.0.0.1/32``).  Validate the host part
        # while preserving the loopback-only boundary.
        address = ipaddress.ip_interface(snapshot.server_address).ip
    except ValueError as exc:
        raise BootstrapError("loopback_required") from exc
    mapped = getattr(address, "ipv4_mapped", None)
    if not address.is_loopback and not (mapped is not None and mapped.is_loopback):
        raise BootstrapError("loopback_required")
    if (
        snapshot.server_port != expected_port
        or _path_key(snapshot.data_directory)
        != _path_key(expected_data_directory)
    ):
        raise BootstrapError("cluster_identity_mismatch")


def validate_new_target(
    snapshot: ClusterSnapshot,
    *,
    expected_data_directory: Path,
    expected_port: int,
) -> None:
    validate_cluster_identity(
        snapshot,
        expected_data_directory=expected_data_directory,
        expected_port=expected_port,
    )
    if snapshot.database_exists:
        raise BootstrapError("target_database_exists")
    if snapshot.runtime_role_exists:
        raise BootstrapError("runtime_role_exists")


def read_cluster_snapshot(connection, *, database: str) -> ClusterSnapshot:
    row = connection.execute(
        """
        select
          current_setting('server_version_num')::integer,
          current_setting('data_directory'),
          inet_server_addr()::text,
          inet_server_port(),
          exists(select 1 from pg_database where datname=%s),
          exists(select 1 from pg_roles where rolname=%s),
          current_user,
          coalesce((select rolsuper from pg_roles where rolname=current_user), false)
        """,
        (database, "adlog_user"),
    ).fetchone()
    if row is None or len(row) != 8:
        raise BootstrapError("cluster_readback_failed")
    return ClusterSnapshot(
        server_version_num=int(row[0]),
        data_directory=Path(str(row[1])),
        server_address=str(row[2]),
        server_port=int(row[3]),
        database_exists=bool(row[4]),
        runtime_role_exists=bool(row[5]),
        current_user=str(row[6]),
        admin_is_superuser=bool(row[7]),
    )


def validate_report_domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    labels = domain.split(".")
    if len(labels) < 2 or len(domain) > 253 or any(not _DNS_LABEL.fullmatch(label) for label in labels):
        raise ValueError("value_must_be_dns_name")
    return domain


def _child_environment(
    psql: Path,
    password: str,
    source: Mapping[str, str],
) -> dict[str, str]:
    folded = {str(key).upper(): str(value) for key, value in source.items()}
    result = {
        key: folded[key]
        for key in ("SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP")
        if folded.get(key)
    }
    result["PATH"] = str(psql.parent)
    result["PGPASSWORD"] = password
    domain = folded.get("ADLOG_REPORT_DOMAIN_FQDN", "").strip()
    if domain:
        domain = validate_report_domain(domain)
        result["PGOPTIONS"] = f"-c sli.report_domain_fqdn={domain}"
    return result


def _subprocess_runner(command: Sequence[str], **kwargs):
    return subprocess.run(list(command), check=False, **kwargs)


def run_psql_file(
    *,
    psql: Path,
    host: str,
    port: int,
    user: str,
    database: str,
    sql_path: Path,
    password: str,
    runner: Callable = _subprocess_runner,
    source: Mapping[str, str] | None = None,
) -> dict[str, str]:
    environment = _child_environment(psql, password, source or os.environ)
    command = [
        str(psql),
        "-X",
        "--host",
        host,
        "--port",
        str(port),
        "--username",
        user,
        "--dbname",
        database,
        "--no-password",
        "--set",
        "ON_ERROR_STOP=1",
        "--file",
        str(sql_path),
    ]
    result = runner(
        command,
        env=environment,
        input=None,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        raise BootstrapError("migration_apply_failed")
    return {"status": "ok"}


def verify_exact_ledger(
    actual: Sequence[tuple[int, str]],
    expected: Sequence[tuple[int, str]],
) -> None:
    if tuple(actual) != tuple(expected):
        raise BootstrapError("migration_ledger_mismatch")


def create_platform_owner(connection, password: str) -> None:
    """Create the exact product owner after the versioned auth schema exists."""
    if (
        not isinstance(password, str)
        or len(password) < 12
        or len(password) > 4096
        or "\x00" in password
    ):
        raise BootstrapError("platform_owner_password_invalid")
    from deploy.linux.sli_core.auth import PASSWORD_HASHER

    password_hash = PASSWORD_HASHER.hash(password)
    connection.execute(
        """
        insert into public.auth_users(username, password_hash, role)
        select %s, %s, %s
        where not exists(
          select 1 from public.auth_users where lower(username)='platform-owner'
        )
        """,
        ("platform-owner", password_hash, "admin"),
    )


def migration_requires_admin(migration: Migration) -> bool:
    """Choose the session identity that preserves the SQL-owned role model."""
    # Includes 150: mixed storage/runtime ownership and view ACL restoration.
    if migration.version >= 89 or migration.version in _ADMIN_MIGRATION_VERSIONS:
        return True
    sql = migration.path.read_text(encoding="utf-8")
    elevated_patterns = (
        r"\bset\s+local\s+role\b",
        r"\bpg_has_role\s*\(\s*session_user\b",
        r"\b(?:create|alter)\s+role\b",
        r"\bowner\s+to\b",
    )
    return any(re.search(pattern, sql, re.IGNORECASE) for pattern in elevated_patterns)


def apply_schema_sequence(
    *,
    schema_path: Path,
    roles_path: Path,
    migrations: Sequence[Migration],
    psql: Path,
    host: str,
    port: int,
    database: str,
    admin_password: str,
    runtime_password: str,
    platform_owner_password: str,
    admin_execute: Callable[..., object],
    source_domain: str | None = None,
    runner: Callable = _subprocess_runner,
    source: Mapping[str, str] | None = None,
) -> None:
    common = {
        "psql": psql,
        "host": host,
        "port": port,
        "database": database,
        "runner": runner,
        "source": source or os.environ,
    }
    admin_execute(PGCRYPTO_BOOTSTRAP_SQL)
    admin_execute(RUNTIME_SCHEMA_BOOTSTRAP_GRANT_SQL)
    run_psql_file(
        **common,
        user="adlog_user",
        sql_path=schema_path,
        password=runtime_password,
    )
    if source_domain is not None:
        seed_source_domain(admin_execute, source_domain)
    run_psql_file(
        **common,
        user="postgres",
        sql_path=roles_path,
        password=admin_password,
    )
    for migration in migrations:
        if migration.version == 89:
            admin_execute(RUNTIME_SCHEMA_CREATE_REVOKE_SQL)
        if migration.version == 12:
            admin_execute(EMPTY_DATABASE_V2_ROUTE_SQL)
        elevated = migration_requires_admin(migration)
        run_psql_file(
            **common,
            user="postgres" if elevated else "adlog_user",
            sql_path=migration.path,
            password=admin_password if elevated else runtime_password,
        )
        if migration.version == 14:
            class _AdminExecutor:
                def execute(self, statement, parameters=None):
                    return admin_execute(statement, parameters)

            create_platform_owner(_AdminExecutor(), platform_owner_password)


BASELINE_DOMAIN_PLACEHOLDER = "__SLI_REPORT_DOMAIN__"


def normalized_sha256(path: Path) -> str:
    """SHA-256 of a text file with CRLF folded to LF (checkout line endings vary)."""
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


@dataclass(frozen=True)
class Baseline:
    version: int
    roles_path: Path
    schema_path: Path


def load_baseline(baseline_dir: Path, migrations: Sequence[Migration]) -> Baseline:
    """Verified clean-install baseline (plan 6.6, ``build_postgres_baseline.py``).

    The manifest pins the hash of each baseline file and of every migration
    the baseline covers; a covered migration edited afterwards invalidates
    the baseline instead of silently diverging from it.
    """
    try:
        manifest = json.loads((baseline_dir / "manifest.json").read_text(encoding="utf-8"))
        version = int(manifest["baseline_version"])
        files = dict(manifest["files"])
        covered = {int(key): str(value) for key, value in dict(manifest["migrations"]).items()}
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise BootstrapError("baseline_manifest_invalid") from exc
    if manifest.get("domain_placeholder") != BASELINE_DOMAIN_PLACEHOLDER:
        raise BootstrapError("baseline_manifest_invalid")
    for name in ("roles.sql", "baseline.sql"):
        path = baseline_dir / name
        if not path.is_file() or normalized_sha256(path) != files.get(name):
            raise BootstrapError("baseline_file_mismatch")
    current = {item.version: normalized_sha256(item.path) for item in migrations if item.version <= version}
    if current != covered:
        raise BootstrapError("baseline_migrations_mismatch")
    return Baseline(version=version, roles_path=baseline_dir / "roles.sql", schema_path=baseline_dir / "baseline.sql")


def render_baseline_schema(
    baseline: Baseline, domain_fqdn: str, target: Path, *, seed_report_domain: bool = False,
) -> Path:
    """Render the installation domain; Linux may seed its DB setting at bootstrap."""
    domain = str(domain_fqdn or "").strip().lower()
    labels = domain.split(".")
    if len(labels) < 2 or len(domain) > 253 or any(_DNS_LABEL.fullmatch(label) is None for label in labels):
        raise BootstrapError("source_domain_config_invalid")
    sql = baseline.schema_path.read_text(encoding="utf-8")
    if domain == "example.invalid" and not seed_report_domain:
        # Native owner setup learns its directory from the first DC. Remove
        # only the baseline directory seed rows, leaving the schema intact.
        sql = re.sub(
            r"(?m)^(COPY public\.(?:domains|forests) \([^\n]*\) FROM stdin;\n)"
            rf"[0-9]+\t(?:[0-9]+\t)?{BASELINE_DOMAIN_PLACEHOLDER}\t[^\n]+\n",
            r"\1", sql,
        )
    sql = sql.replace(BASELINE_DOMAIN_PLACEHOLDER, domain)
    if seed_report_domain:
        # DNS validation above makes the literal safe. Linux runs this in the
        # baseline transaction, never on an existing installation or request.
        sql += (
            "\nINSERT INTO public.platform_settings (key, value, updated_by) "
            f"VALUES ('reports.domain_fqdn', '{domain}', 'installer') "
            "ON CONFLICT (key) DO NOTHING;\n"
        )
    target.write_text(sql, encoding="utf-8", newline="\n")
    return target


def apply_baseline_sequence(
    *,
    baseline: Baseline,
    rendered_schema_path: Path,
    migrations: Sequence[Migration],
    psql: Path,
    host: str,
    port: int,
    database: str,
    admin_password: str,
    runtime_password: str,
    platform_owner_password: str,
    admin_execute: Callable[..., object],
    runner: Callable = _subprocess_runner,
    source: Mapping[str, str] | None = None,
) -> None:
    """Clean install from the baseline, then migrations newer than it."""
    common = {
        "psql": psql,
        "host": host,
        "port": port,
        "database": database,
        "runner": runner,
        "source": source or os.environ,
    }
    run_psql_file(**common, user="postgres", sql_path=baseline.roles_path, password=admin_password)
    run_psql_file(**common, user="postgres", sql_path=rendered_schema_path, password=admin_password)

    class _AdminExecutor:
        def execute(self, statement, parameters=None):
            return admin_execute(statement, parameters)

    create_platform_owner(_AdminExecutor(), platform_owner_password)
    for migration in migrations:
        if migration.version <= baseline.version:
            continue
        elevated = migration_requires_admin(migration)
        run_psql_file(
            **common,
            user="postgres" if elevated else "adlog_user",
            sql_path=migration.path,
            password=admin_password if elevated else runtime_password,
        )


def create_target_database(
    connection,
    *,
    database: str,
    runtime_password: str,
) -> None:
    target = _quote_identifier(database)
    runtime = _quote_identifier("adlog_user")
    connection.execute("SET password_encryption = 'scram-sha-256'")
    connection.execute(
        "CREATE ROLE \"adlog_user\" LOGIN NOSUPERUSER NOCREATEDB "
        "NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION"
    )
    connection.execute(
        "select set_config('sli.bootstrap_runtime_password', %s, false)",
        (runtime_password,),
    )
    try:
        connection.execute(
            """
            do $bootstrap$
            begin
              execute format(
                'alter role "adlog_user" password %L',
                current_setting('sli.bootstrap_runtime_password')
              );
            end
            $bootstrap$
            """
        )
    finally:
        connection.execute("reset sli.bootstrap_runtime_password")
    connection.execute(
        f'CREATE DATABASE {target} OWNER "postgres" TEMPLATE template0 ENCODING \'UTF8\''
    )
    connection.execute(f"REVOKE ALL ON DATABASE {target} FROM PUBLIC")
    connection.execute(
        f"GRANT CONNECT, TEMPORARY ON DATABASE {target} TO {runtime}"
    )


def write_runtime_candidate(
    *,
    profile_dir: Path,
    database: str,
    host: str,
    port: int,
    runtime_password: str,
    identity_sid: str,
    protector: Callable[[str], str],
) -> Path:
    from scripts.maintenance.local_postgres_bootstrap import _write_json_atomic

    if profile_dir.exists():
        if not profile_dir.is_dir() or any(profile_dir.iterdir()):
            raise BootstrapError("profile_target_exists")
    else:
        profile_dir.mkdir(parents=True, exist_ok=False)
    credential = quote(runtime_password, safe="")
    dsn = urlunparse(
        ("postgresql", f"adlog_user:{credential}@{host}:{port}", f"/{database}", "", "", "")
    )
    payload = {
        "active": False,
        "candidate_version": 1,
        "identity_sid": identity_sid,
        "kind": "runtime",
        "payload": protector(dsn),
        "protection": "windows-dpapi-current-user",
        "role": "adlog_user",
    }
    path = profile_dir / "runtime.candidate.json"
    _write_json_atomic(path, payload, must_be_new=True)
    return path


def write_admin_credential(
    *,
    path: Path,
    password: str,
    identity_sid: str,
    protector: Callable[[str], str],
) -> Path:
    """Persist only a CurrentUser-DPAPI envelope for the PostgreSQL admin."""
    from scripts.maintenance.local_postgres_bootstrap import _write_json_atomic

    if path.exists():
        raise BootstrapError("admin_credential_exists")
    if not password or len(password) > 4096 or "\x00" in password:
        raise BootstrapError("postgres_admin_password_invalid")
    protected = protector(password)
    if not isinstance(protected, str) or not protected:
        raise BootstrapError("admin_credential_protection_failed")
    payload = {
        "credential_version": 1,
        "identity_sid": identity_sid,
        "kind": "postgresql-administrator",
        "payload": protected,
        "protection": "windows-dpapi-current-user",
        "purpose": _ADMIN_CREDENTIAL_PURPOSE,
        "role": "postgres",
    }
    try:
        _write_json_atomic(path, payload, must_be_new=True)
    except Exception as exc:
        if str(exc) == "target_exists":
            raise BootstrapError("admin_credential_exists") from None
        raise
    return path


def read_admin_credential(
    *,
    path: Path,
    identity_sid: str,
    unprotector: Callable[[str], str],
) -> str:
    """Load a validated admin secret without returning it in metadata."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BootstrapError("admin_credential_unavailable") from exc
    expected_keys = {
        "credential_version",
        "identity_sid",
        "kind",
        "payload",
        "protection",
        "purpose",
        "role",
    }
    if not isinstance(payload, dict) or set(payload) != expected_keys:
        raise BootstrapError("admin_credential_invalid")
    if payload.get("identity_sid") != identity_sid:
        raise BootstrapError("admin_credential_owner_mismatch")
    if (
        payload.get("credential_version") != 1
        or payload.get("kind") != "postgresql-administrator"
        or payload.get("protection") != "windows-dpapi-current-user"
        or payload.get("purpose") != _ADMIN_CREDENTIAL_PURPOSE
        or payload.get("role") != "postgres"
        or not isinstance(payload.get("payload"), str)
        or not payload["payload"]
    ):
        raise BootstrapError("admin_credential_invalid")
    try:
        password = unprotector(payload["payload"])
    except Exception as exc:
        raise BootstrapError("admin_credential_decryption_failed") from exc
    if not isinstance(password, str) or not password or len(password) > 4096 or "\x00" in password:
        raise BootstrapError("admin_credential_invalid")
    return password


def write_platform_owner_credential(
    *,
    path: Path,
    password: str,
    identity_sid: str,
    protector: Callable[[str], str],
) -> Path:
    from scripts.maintenance.local_postgres_bootstrap import _write_json_atomic

    if path.exists():
        raise BootstrapError("platform_owner_credential_exists")
    if not isinstance(password, str) or len(password) < 12 or len(password) > 4096 or "\x00" in password:
        raise BootstrapError("platform_owner_password_invalid")
    protected = protector(password)
    if not isinstance(protected, str) or not protected:
        raise BootstrapError("platform_owner_credential_protection_failed")
    payload = {
        "credential_version": 1,
        "identity_sid": identity_sid,
        "kind": "sli-platform-owner",
        "payload": protected,
        "protection": "windows-dpapi-current-user",
        "purpose": _PLATFORM_OWNER_CREDENTIAL_PURPOSE,
        "role": "platform-owner",
    }
    try:
        _write_json_atomic(path, payload, must_be_new=True)
    except Exception as exc:
        if str(exc) == "target_exists":
            raise BootstrapError("platform_owner_credential_exists") from None
        raise
    return path


def read_platform_owner_credential(
    *,
    path: Path,
    identity_sid: str,
    unprotector: Callable[[str], str],
) -> str:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BootstrapError("platform_owner_credential_unavailable") from exc
    expected = {
        "credential_version": 1,
        "identity_sid": identity_sid,
        "kind": "sli-platform-owner",
        "protection": "windows-dpapi-current-user",
        "purpose": _PLATFORM_OWNER_CREDENTIAL_PURPOSE,
        "role": "platform-owner",
    }
    if (
        not isinstance(payload, dict)
        or set(payload) != {*expected, "payload"}
        or any(payload.get(key) != value for key, value in expected.items())
        or not isinstance(payload.get("payload"), str)
        or not payload["payload"]
    ):
        if isinstance(payload, dict) and payload.get("identity_sid") != identity_sid:
            raise BootstrapError("platform_owner_credential_owner_mismatch")
        raise BootstrapError("platform_owner_credential_invalid")
    try:
        password = unprotector(payload["payload"])
    except Exception as exc:
        raise BootstrapError("platform_owner_credential_decryption_failed") from exc
    if not isinstance(password, str) or len(password) < 12 or len(password) > 4096 or "\x00" in password:
        raise BootstrapError("platform_owner_credential_invalid")
    return password


def _protect_admin_password(password: str) -> str:
    if os.name != "nt":
        raise BootstrapError("windows_dpapi_required")
    try:
        import win32crypt  # type: ignore

        sealed = win32crypt.CryptProtectData(
            password.encode("utf-8"),
            _ADMIN_CREDENTIAL_PURPOSE,
            _ADMIN_CREDENTIAL_PURPOSE.encode("ascii"),
            None,
            None,
            _DPAPI_UI_FORBIDDEN,
        )
    except Exception as exc:
        raise BootstrapError("admin_credential_protection_failed") from exc
    return base64.b64encode(bytes(sealed)).decode("ascii")


def _unprotect_admin_password(protected: str) -> str:
    if os.name != "nt":
        raise BootstrapError("windows_dpapi_required")
    try:
        import win32crypt  # type: ignore

        sealed = base64.b64decode(protected, validate=True)
        description, clear = win32crypt.CryptUnprotectData(
            sealed,
            _ADMIN_CREDENTIAL_PURPOSE.encode("ascii"),
            None,
            None,
            _DPAPI_UI_FORBIDDEN,
        )
        password = bytes(clear).decode("utf-8")
    except Exception as exc:
        raise BootstrapError("admin_credential_decryption_failed") from exc
    if description != _ADMIN_CREDENTIAL_PURPOSE:
        raise BootstrapError("admin_credential_invalid")
    return password


def _protect_platform_owner_password(password: str) -> str:
    if os.name != "nt":
        raise BootstrapError("windows_dpapi_required")
    try:
        import win32crypt  # type: ignore

        sealed = win32crypt.CryptProtectData(
            password.encode("utf-8"),
            _PLATFORM_OWNER_CREDENTIAL_PURPOSE,
            _PLATFORM_OWNER_CREDENTIAL_PURPOSE.encode("ascii"),
            None,
            None,
            _DPAPI_UI_FORBIDDEN,
        )
    except Exception as exc:
        raise BootstrapError("platform_owner_credential_protection_failed") from exc
    return base64.b64encode(bytes(sealed)).decode("ascii")


def _unprotect_platform_owner_password(protected: str) -> str:
    if os.name != "nt":
        raise BootstrapError("windows_dpapi_required")
    try:
        import win32crypt  # type: ignore

        sealed = base64.b64decode(protected, validate=True)
        description, clear = win32crypt.CryptUnprotectData(
            sealed,
            _PLATFORM_OWNER_CREDENTIAL_PURPOSE.encode("ascii"),
            None,
            None,
            _DPAPI_UI_FORBIDDEN,
        )
        password = bytes(clear).decode("utf-8")
    except Exception as exc:
        raise BootstrapError("platform_owner_credential_decryption_failed") from exc
    if description != _PLATFORM_OWNER_CREDENTIAL_PURPOSE:
        raise BootstrapError("platform_owner_credential_invalid")
    return password


def save_admin_password(app_root: Path, password: str) -> Path:
    from scripts.maintenance.local_postgres_bootstrap import (
        create_private_directory,
        local_identity,
        verify_private_directory,
    )

    root = Path(app_root) / _ADMIN_CREDENTIAL_RELATIVE_PATH.parent
    identity = local_identity()
    if root.exists():
        if not verify_private_directory(root, identity["sid"]):
            raise BootstrapError("admin_credential_acl_invalid")
    else:
        create_private_directory(root, identity["sid"])
        if not verify_private_directory(root, identity["sid"]):
            raise BootstrapError("admin_credential_acl_invalid")
    return write_admin_credential(
        path=root / _ADMIN_CREDENTIAL_RELATIVE_PATH.name,
        password=password,
        identity_sid=identity["sid"],
        protector=_protect_admin_password,
    )


def load_saved_admin_password(app_root: Path) -> str:
    from scripts.maintenance.local_postgres_bootstrap import (
        local_identity,
        verify_private_directory,
    )

    root = Path(app_root) / _ADMIN_CREDENTIAL_RELATIVE_PATH.parent
    identity = local_identity()
    if not verify_private_directory(root, identity["sid"]):
        raise BootstrapError("admin_credential_acl_invalid")
    return read_admin_credential(
        path=root / _ADMIN_CREDENTIAL_RELATIVE_PATH.name,
        identity_sid=identity["sid"],
        unprotector=_unprotect_admin_password,
    )


def save_platform_owner_password(app_root: Path, password: str) -> Path:
    from scripts.maintenance.local_postgres_bootstrap import (
        local_identity,
        verify_private_directory,
    )

    root = Path(app_root) / _ADMIN_CREDENTIAL_RELATIVE_PATH.parent
    identity = local_identity()
    if not verify_private_directory(root, identity["sid"]):
        raise BootstrapError("platform_owner_credential_acl_invalid")
    return write_platform_owner_credential(
        path=root / "platform-owner.dpapi.json",
        password=password,
        identity_sid=identity["sid"],
        protector=_protect_platform_owner_password,
    )


def load_saved_platform_owner_password(app_root: Path) -> str:
    from scripts.maintenance.local_postgres_bootstrap import (
        local_identity,
        verify_private_directory,
    )

    root = Path(app_root) / _ADMIN_CREDENTIAL_RELATIVE_PATH.parent
    identity = local_identity()
    if not verify_private_directory(root, identity["sid"]):
        raise BootstrapError("platform_owner_credential_acl_invalid")
    return read_platform_owner_credential(
        path=root / "platform-owner.dpapi.json",
        identity_sid=identity["sid"],
        unprotector=_unprotect_platform_owner_password,
    )


def parse_args(argv=None):
    parser = SafeParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--app-root", required=True, type=Path)
    parser.add_argument("--bin-dir", required=True, type=Path)
    parser.add_argument("--data-dir", required=True, type=Path)
    parser.add_argument("--database", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=55433, type=int)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--apply-after-plan", action="store_true")
    parser.add_argument("--confirm-plan")
    parser.add_argument("--status-file", type=Path)
    parser.add_argument("--admin-password-stdin", action="store_true")
    parser.add_argument("--save-admin-password", action="store_true")
    parser.add_argument("--use-saved-admin-password", action="store_true")
    parser.add_argument("--platform-owner-password-stdin", action="store_true")
    parser.add_argument("--save-platform-owner-password", action="store_true")
    parser.add_argument("--use-saved-platform-owner-password", action="store_true")
    opts = parser.parse_args(argv)
    if _IDENTIFIER.fullmatch(opts.database) is None or not opts.database.startswith("sli_"):
        raise BootstrapError("invalid_database")
    if opts.host != "127.0.0.1":
        raise BootstrapError("loopback_required")
    if not 1024 <= opts.port <= 65535:
        raise BootstrapError("invalid_port")
    if opts.apply_after_plan and (opts.apply or opts.confirm_plan):
        raise BootstrapError("invalid_arguments")
    if opts.use_saved_admin_password and (
        opts.admin_password_stdin or opts.save_admin_password
    ):
        raise BootstrapError("invalid_arguments")
    if opts.use_saved_platform_owner_password and (
        opts.platform_owner_password_stdin or opts.save_platform_owner_password
    ):
        raise BootstrapError("invalid_arguments")
    if not opts.apply_after_plan and opts.apply != bool(opts.confirm_plan):
        raise BootstrapError("confirmation_required")
    return opts


def _canonical_existing_directory(path: Path) -> Path:
    if not path.is_absolute():
        raise BootstrapError("unsafe_path")
    canonical = Path(os.path.abspath(os.path.normpath(os.fspath(path))))
    if not canonical.is_dir():
        raise BootstrapError("required_path_missing")
    return canonical


def _connect_postgres(*, host: str, port: int, database: str, password: str):
    try:
        import psycopg
    except ImportError as exc:
        raise BootstrapError("psycopg_required") from exc
    try:
        return psycopg.connect(
            host=host,
            port=port,
            dbname=database,
            user="postgres",
            password=password,
            connect_timeout=5,
            application_name="sli_existing_postgres_bootstrap",
            autocommit=True,
        )
    except Exception as exc:
        raise BootstrapError("postgres_admin_connection_failed") from exc


def validate_admin_credentials(opts, password: str) -> None:
    """Authenticate and bind a credential to the expected local PG18 cluster."""
    data_dir = _canonical_existing_directory(opts.data_dir)
    with _connect_postgres(
        host=opts.host,
        port=opts.port,
        database="postgres",
        password=password,
    ) as connection:
        snapshot = read_cluster_snapshot(connection, database=opts.database)
    validate_cluster_identity(
        snapshot,
        expected_data_directory=data_dir,
        expected_port=opts.port,
    )


def prepare_live_plan(opts, password: str) -> dict[str, object]:
    app_root = _canonical_existing_directory(opts.app_root)
    bin_dir = _canonical_existing_directory(opts.bin_dir)
    data_dir = _canonical_existing_directory(opts.data_dir)
    psql = bin_dir / "psql.exe"
    schema = app_root / "config" / "postgres_schema_v8.sql"
    controllers = app_root / "config" / "domain_controllers.json"
    roles = app_root / "config" / "postgres_migrations" / "storage_v2_roles.sql"
    migrations_root = app_root / "config" / "postgres_migrations"
    if (
        not psql.is_file()
        or not schema.is_file()
        or not roles.is_file()
        or not controllers.is_file()
    ):
        raise BootstrapError("required_path_missing")
    version = subprocess.run(
        [str(psql), "--version"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if version.returncode != 0 or re.search(r"PostgreSQL\) 18(?:\.\d+)*", version.stdout or "") is None:
        raise BootstrapError("postgresql_18_required")
    migrations = forward_migration_inventory(migrations_root)
    markers = base_schema_markers(schema)
    source_domain = configured_source_domain(controllers)
    with _connect_postgres(
        host=opts.host,
        port=opts.port,
        database="postgres",
        password=password,
    ) as connection:
        snapshot = read_cluster_snapshot(connection, database=opts.database)
    validate_new_target(
        snapshot,
        expected_data_directory=data_dir,
        expected_port=opts.port,
    )
    profile_dir = app_root / "data" / "runtime" / "local-postgres-18-official"
    if profile_dir.exists():
        raise BootstrapError("profile_target_exists")
    plan = build_plan(
        database=opts.database,
        expected_data_directory=data_dir,
        snapshot=snapshot,
        schema_sha256=hashlib.sha256(schema.read_bytes()).hexdigest(),
        roles_sha256=hashlib.sha256(roles.read_bytes()).hexdigest(),
        migrations=migrations,
    )
    plan.update(
        {
            "paths": {
                "app_root": str(app_root),
                "psql": str(psql),
                "profile_dir": str(
                    profile_dir
                ),
            },
            "isolated_rehearsal_required": True,
            "source_identity": {
                "domain_fqdn": source_domain,
                "forest_fqdn": source_domain,
                "domain_sid": None,
                "basis": "domain_controllers",
            },
            "base_markers": [
                {"version": version, "name": name} for version, name in markers
            ],
            "expected_marker_count": len(markers) + len(migrations),
            "planned_actions": [
                "create_runtime_login_role",
                "create_runtime_owned_database",
                "apply_base_schema",
                "seed_configured_source_domain",
                "apply_role_bootstrap",
                "apply_exact_forward_inventory",
                "verify_exact_marker_name_ledger",
                "require_separate_isolated_cluster_rehearsal",
                "write_inactive_dpapi_runtime_candidate",
                "write_sanitized_receipt",
            ],
            "excluded_actions": [
                "source_contact",
                "worker_start",
                "report_start",
                "cursor_change",
                "existing_database_change",
                "plaintext_secret_storage",
            ],
        }
    )
    return plan


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _safe_code(exc: BaseException) -> str:
    value = str(exc)
    return value if re.fullmatch(r"[a-z][a-z0-9_]{0,63}", value) else "internal_error"


def _write_status_file(path: Path | None, payload: Mapping[str, object]) -> None:
    if path is None:
        return
    from scripts.maintenance.local_postgres_bootstrap import _write_json_atomic

    if not path.is_absolute():
        raise BootstrapError("unsafe_status_path")
    path.parent.mkdir(parents=True, exist_ok=True)
    _write_json_atomic(path, dict(payload))


def _disposable_database_name(database: str) -> str:
    suffix = hashlib.sha256(database.encode("ascii")).hexdigest()[:12]
    return f"sli_test_bootstrap_{suffix}"


def _create_database_for_runtime(connection, database: str) -> None:
    target = _quote_identifier(database)
    connection.execute(
        f'CREATE DATABASE {target} OWNER "postgres" TEMPLATE template0 ENCODING \'UTF8\''
    )
    connection.execute(f"REVOKE ALL ON DATABASE {target} FROM PUBLIC")
    connection.execute(
        f'GRANT CONNECT, TEMPORARY ON DATABASE {target} TO "adlog_user"'
    )


def _read_ledger(connection) -> tuple[tuple[int, str], ...]:
    rows = connection.execute(
        "select version, name from public.schema_migrations order by version"
    ).fetchall()
    return tuple((int(version), str(name)) for version, name in rows)


def _expected_ledger(plan: Mapping[str, object]) -> tuple[tuple[int, str], ...]:
    base = plan.get("base_markers")
    forward = plan.get("migrations")
    if not isinstance(base, list) or not isinstance(forward, list):
        raise BootstrapError("plan_invalid")
    try:
        rows = [
            (int(item["version"]), str(item["name"]))
            for item in [*base, *forward]
        ]
    except (KeyError, TypeError, ValueError) as exc:
        raise BootstrapError("plan_invalid") from exc
    return tuple(sorted(rows))


def _verify_target_readback(connection, expected_marker_count: int) -> None:
    row = connection.execute(
        """
        select
          current_database(),
          pg_get_userbyid(database_row.datdba),
          runtime.rolcanlogin,
          runtime.rolsuper,
          runtime.rolcreatedb,
          runtime.rolcreaterole,
          runtime.rolbypassrls,
          (select count(*) from public.schema_migrations)
        from pg_database database_row
        join pg_roles runtime on runtime.rolname='adlog_user'
        where database_row.datname=current_database()
        """
    ).fetchone()
    if row is None or tuple(row[1:7]) != (
        "postgres",
        True,
        False,
        False,
        False,
        False,
    ) or int(row[7]) != expected_marker_count:
        raise BootstrapError("target_readback_failed")


def _apply_database_schema(
    *,
    opts,
    database: str,
    admin_password: str,
    runtime_password: str,
    platform_owner_password: str,
    plan: Mapping[str, object],
) -> None:
    app_root = Path(str(plan["paths"]["app_root"]))
    psql = Path(str(plan["paths"]["psql"]))
    schema = app_root / "config" / "postgres_schema_v8.sql"
    roles = app_root / "config" / "postgres_migrations" / "storage_v2_roles.sql"
    migrations = forward_migration_inventory(
        app_root / "config" / "postgres_migrations"
    )
    source_identity = plan.get("source_identity")
    if not isinstance(source_identity, dict):
        raise BootstrapError("plan_invalid")
    source_domain = source_identity.get("domain_fqdn")
    if not isinstance(source_domain, str):
        raise BootstrapError("plan_invalid")
    baseline_dir = app_root / "config" / "postgres_baseline"
    with _connect_postgres(
        host=opts.host,
        port=opts.port,
        database=database,
        password=admin_password,
    ) as admin_connection:
        if (baseline_dir / "manifest.json").is_file():
            # Clean install from the baseline (plan 6.6); the ledger check
            # below is the same as for the migration-by-migration path.
            baseline = load_baseline(baseline_dir, migrations)
            with tempfile.TemporaryDirectory(prefix="sli-baseline-") as temporary:
                apply_baseline_sequence(
                    baseline=baseline,
                    rendered_schema_path=render_baseline_schema(
                        baseline, source_domain, Path(temporary) / "baseline.sql",
                    ),
                    migrations=migrations,
                    psql=psql,
                    host=opts.host,
                    port=opts.port,
                    database=database,
                    admin_password=admin_password,
                    runtime_password=runtime_password,
                    platform_owner_password=platform_owner_password,
                    admin_execute=admin_connection.execute,
                )
            expected = _expected_ledger(plan)
            verify_exact_ledger(_read_ledger(admin_connection), expected)
            _verify_target_readback(admin_connection, len(expected))
            return
        apply_schema_sequence(
            schema_path=schema,
            roles_path=roles,
            migrations=migrations,
            psql=psql,
            host=opts.host,
            port=opts.port,
            database=database,
            admin_password=admin_password,
            runtime_password=runtime_password,
            platform_owner_password=platform_owner_password,
            admin_execute=admin_connection.execute,
            source_domain=source_domain,
        )
        expected = _expected_ledger(plan)
        verify_exact_ledger(_read_ledger(admin_connection), expected)
        _verify_target_readback(admin_connection, len(expected))


def perform_apply(
    opts,
    password: str,
    platform_owner_password: str,
    plan: dict[str, object],
    confirmation: str,
) -> Path:
    from scripts.maintenance.local_postgres_bootstrap import (
        _dpapi_protect,
        _write_json_atomic,
        create_private_directory,
        local_identity,
        verify_private_directory,
    )

    app_root = Path(str(plan["paths"]["app_root"]))
    profile_dir = Path(str(plan["paths"]["profile_dir"]))
    receipt_path = (
        app_root / "artifacts" / "operations" /
        "existing-postgres-bootstrap-latest.json"
    )
    identity = local_identity()
    receipt: dict[str, object] = {
        "contract_version": 1,
        "operation": "bootstrap_existing_postgresql_18",
        "status": "in_progress",
        "confirmation_sha256": confirmation,
        "database": opts.database,
        "isolated_rehearsal_required": True,
        "runtime_role": "adlog_user",
        "migration_role": "postgres",
        "expected_marker_count": plan["expected_marker_count"],
        "last_completed_stage": "plan_revalidated",
        "error_code": None,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "credential_values_exposed": False,
    }
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    _write_json_atomic(receipt_path, receipt)

    def checkpoint(stage: str) -> None:
        receipt["last_completed_stage"] = stage
        _write_json_atomic(receipt_path, receipt)

    try:
        runtime_password = secrets.token_urlsafe(36)
        with _connect_postgres(
            host=opts.host,
            port=opts.port,
            database="postgres",
            password=password,
        ) as admin_connection:
            create_target_database(
                admin_connection,
                database=opts.database,
                runtime_password=runtime_password,
            )
        checkpoint("target_database_and_runtime_role_created")

        _apply_database_schema(
            opts=opts,
            database=opts.database,
            admin_password=password,
            runtime_password=runtime_password,
            platform_owner_password=platform_owner_password,
            plan=plan,
        )
        checkpoint("target_schema_and_exact_ledger_verified")

        create_private_directory(profile_dir, identity["sid"])
        if not verify_private_directory(profile_dir, identity["sid"]):
            raise BootstrapError("acl_verification_failed")
        candidate = write_runtime_candidate(
            profile_dir=profile_dir,
            database=opts.database,
            host=opts.host,
            port=opts.port,
            runtime_password=runtime_password,
            identity_sid=identity["sid"],
            protector=_dpapi_protect,
        )
        receipt["runtime_candidate"] = str(candidate)
        receipt["status"] = "complete"
        checkpoint("runtime_candidate_written")
        return receipt_path
    except BootstrapError as exc:
        receipt["status"] = "partial_failure"
        receipt["error_code"] = _safe_code(exc)
        _write_json_atomic(receipt_path, receipt)
        raise
    except Exception as exc:
        receipt["status"] = "partial_failure"
        receipt["error_code"] = "internal_error"
        _write_json_atomic(receipt_path, receipt)
        raise BootstrapError("bootstrap_partial_failure") from exc


def main(argv=None) -> int:
    opts = None
    try:
        opts = parse_args(argv)
        if opts.use_saved_admin_password:
            password = load_saved_admin_password(opts.app_root)
        elif opts.admin_password_stdin:
            password = sys.stdin.readline(4097).rstrip("\r\n")
            if len(password) > 4096:
                raise BootstrapError("postgres_admin_password_invalid")
        else:
            password = getpass.getpass("PostgreSQL administrator password: ")
        if not password:
            raise BootstrapError("postgres_admin_password_required")

        platform_owner_password = None
        if opts.apply or opts.apply_after_plan:
            if opts.use_saved_platform_owner_password:
                platform_owner_password = load_saved_platform_owner_password(
                    opts.app_root
                )
            elif opts.platform_owner_password_stdin:
                platform_owner_password = sys.stdin.readline(4097).rstrip("\r\n")
                if len(platform_owner_password) > 4096:
                    raise BootstrapError("platform_owner_password_invalid")
            else:
                platform_owner_password = getpass.getpass(
                    "New platform-owner password: "
                )
            if len(platform_owner_password) < 12:
                raise BootstrapError("platform_owner_password_invalid")

        # When the caller explicitly requests DPAPI persistence, seal both
        # inputs immediately after authenticating them against the expected
        # local cluster.  Plan-level failures must not force another prompt.
        if opts.save_admin_password or opts.save_platform_owner_password:
            validate_admin_credentials(opts, password)
        if opts.save_admin_password:
            save_admin_password(opts.app_root, password)
        if opts.save_platform_owner_password:
            if platform_owner_password is None:
                raise BootstrapError("invalid_arguments")
            save_platform_owner_password(opts.app_root, platform_owner_password)

        plan = prepare_live_plan(opts, password)
        confirmation = plan_confirmation(plan)
        if not opts.apply and not opts.apply_after_plan:
            envelope = {
                "confirmation_sha256": confirmation,
                "mode": "plan",
                "plan": plan,
            }
            print(_json(envelope))
            _write_status_file(opts.status_file, {
                "status": "planned",
                "confirmation_sha256": confirmation,
            })
            return 0
        if platform_owner_password is None:
            raise BootstrapError("platform_owner_password_required")
        if opts.apply and not hmac.compare_digest(opts.confirm_plan or "", confirmation):
            raise BootstrapError("confirmation_mismatch")
        receipt = perform_apply(
            opts,
            password,
            platform_owner_password,
            plan,
            confirmation,
        )
        envelope = {
            "confirmation_sha256": confirmation,
            "mode": "apply",
            "receipt": str(receipt),
            "status": "complete",
        }
        print(_json(envelope))
        _write_status_file(opts.status_file, envelope)
        return 0
    except BootstrapError as exc:
        envelope = {"status": "error", "code": _safe_code(exc)}
        try:
            _write_status_file(getattr(opts, "status_file", None), envelope)
        except BootstrapError:
            pass
        print(_json(envelope), file=sys.stderr)
        return 2
    except Exception:
        envelope = {"status": "error", "code": "internal_error"}
        try:
            _write_status_file(getattr(opts, "status_file", None), envelope)
        except BootstrapError:
            pass
        print(_json(envelope), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

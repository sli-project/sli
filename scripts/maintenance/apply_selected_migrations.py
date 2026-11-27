"""Apply explicitly selected PostgreSQL migrations to the configured database.

Only the versions named on the command line are applied, in ascending order;
the working ledger may intentionally lack other versions (prepared but not
admitted migrations), so "apply everything pending" is never offered.

    plan   read-only: target identity, ledger state of each selected version
    apply  runs each not-yet-applied file with ``psql -f`` as the PostgreSQL
           administrator, then re-reads the ledger; requires
           ``--confirm APPLY-MIGRATIONS-<v1>-<v2>...``

Credentials come from the environment (``ADLOG_PG_DSN``,
``ADLOG_PG_ADMIN_USER``, ``ADLOG_PG_ADMIN_PASSWORD``).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from collections.abc import Mapping
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.maintenance.existing_postgres_bootstrap import (
    forward_migration_inventory, validate_report_domain,  # noqa: E402
)

MIGRATIONS_DIR = ROOT / "config" / "postgres_migrations"
DEFAULT_BIN_DIR = Path(r"D:\PostgreSQL\18\bin")


def confirmation_token(versions: list[int]) -> str:
    return "APPLY-MIGRATIONS-" + "-".join(str(version) for version in versions)


def migration_environment(source: Mapping[str, str]) -> dict[str, str]:
    """Pass a configured report domain to SQL that predates platform_settings."""
    environment = dict(source, PGCLIENTENCODING="UTF8")
    domain = source.get("ADLOG_REPORT_DOMAIN_FQDN", "").strip()
    if domain:
        domain = validate_report_domain(domain)
        environment["PGOPTIONS"] = (
            environment.get("PGOPTIONS", "") + f" -c sli.report_domain_fqdn={domain}"
        ).strip()
    return environment


def _admin_parts() -> dict[str, str]:
    from psycopg.conninfo import conninfo_to_dict

    from deploy.linux.sli_core.secret_files import secret_value

    parts = conninfo_to_dict(secret_value("ADLOG_PG_DSN") or "")
    user = os.getenv("ADLOG_PG_ADMIN_USER", "").strip()
    password = os.getenv("ADLOG_PG_ADMIN_PASSWORD", "")
    if not (parts.get("dbname") or parts.get("service") or os.getenv("PGSERVICE")) or not user or not password:
        raise SystemExit("PostgreSQL DSN and administrator credentials are required")
    parts.update(user=user, password=password, client_encoding="UTF8")
    return parts


# Include physical cluster, database, role and endpoint identity. A restart or
# failover requires a fresh plan rather than silently accepting another target.
TARGET_IDENTITY_SQL = """md5(jsonb_build_array(
    (select system_identifier::text from pg_control_system()),
    (select oid::text from pg_database where datname = current_database()),
    current_database(), current_user, inet_server_addr()::text,
    inet_server_port(), pg_postmaster_start_time()::text, pg_is_in_recovery()
)::text)"""
SERVICE_NAME = "sli_selected_migrations"


class MigrationConnectionError(Exception):
    """Only fixed, credential-free diagnostics may cross the CLI boundary."""


def _connect_timeout(parts: dict[str, str]) -> str:
    """Use libpq's service-before-environment precedence before our fallback."""
    from psycopg import pq

    if "connect_timeout" in parts:
        return parts["connect_timeout"]
    previous_service = os.environ.get("PGSERVICE")
    try:
        if "service" in parts:
            os.environ["PGSERVICE"] = parts["service"]
        for item in pq.Conninfo.get_defaults():
            if item.keyword == b"connect_timeout" and item.val is not None:
                return item.val.decode("utf-8")
        return "5"
    finally:
        if previous_service is None:
            os.environ.pop("PGSERVICE", None)
        else:
            os.environ["PGSERVICE"] = previous_service


@contextmanager
def _connection_contract(parts: dict[str, str]):
    """Freeze libpq-resolved service/environment defaults for every operation.

    The resolution connection executes no application or migration SQL. libpq's own effective options
    include service entries, hostaddr, TLS and options without PG* equivalents.
    A private service file then supplies precisely these options to BOTH clients.
    Unknown options in an older psql/libpq fail closed when it reads the file.
    """
    import psycopg

    with psycopg.connect(**dict(parts, connect_timeout=_connect_timeout(parts))) as conn:
        resolved = {
            item.keyword.decode("ascii"): item.val.decode("utf-8")
            for item in conn.pgconn.info
            if item.val is not None and item.keyword != b"service"
        }
    # Preserve arbitrary passwords (including whitespace/newlines) in the same
    # child-only environment transport as before, never in argv or diagnostics.
    password = resolved.pop("password", parts["password"])
    environment_options = migration_environment({
        "PGOPTIONS": resolved.get("options", ""),
        "ADLOG_REPORT_DOMAIN_FQDN": os.getenv("ADLOG_REPORT_DOMAIN_FQDN", ""),
    })
    resolved["options"] = environment_options["PGOPTIONS"]
    resolved["client_encoding"] = "UTF8"
    resolved.setdefault("application_name", resolved.get("fallback_application_name") or SERVICE_NAME)
    lines = [f"[{SERVICE_NAME}]\n"]
    for key, value in resolved.items():
        line = f"{key}={value}\n"
        # libpq service files use literal, unquoted values, trim trailing space,
        # and limit a line to 1022 bytes. Never truncate, quote or reinterpret.
        if (any(char in value for char in "\r\n\0") or value != value.rstrip()
                or len(line.encode("utf-8")) >= 1023):
            raise MigrationConnectionError(f"connection_option_not_service_representable:{key}")
        lines.append(line)
    previous = {key: value for key, value in os.environ.items() if key.startswith("PG")}
    with tempfile.TemporaryDirectory(prefix="sli-migration-") as directory:
        service_path = Path(directory) / "pg_service.conf"
        with service_path.open("x", encoding="utf-8", newline="\n") as service_file:
            os.chmod(service_path, 0o600)
            service_file.writelines(lines)
        # This CLI is single-threaded. Scope all libpq environment defaults,
        # including service lookup, identically for psycopg and psql, then restore.
        try:
            for key in previous:
                del os.environ[key]
            # These libpq startup GUCs are not PQconninfo options. Preserve
            # them too; connection selectors/security defaults come from the file.
            os.environ.update({key: previous[key] for key in ("PGDATESTYLE", "PGTZ", "PGGEQO")
                               if key in previous})
            os.environ.update(PGSERVICE=SERVICE_NAME, PGSERVICEFILE=str(service_path),
                              PGPASSWORD=password)
            yield {"service": SERVICE_NAME}
        finally:
            for key in list(os.environ):
                if key.startswith("PG"):
                    del os.environ[key]
            os.environ.update(previous)


def _ledger(parts: dict[str, str], versions: list[int]) -> dict[str, object]:
    import psycopg

    with psycopg.connect(**parts) as conn, conn.cursor() as cur:
        cur.execute("set transaction read only")
        cur.execute(f"select {TARGET_IDENTITY_SQL}")
        identity = cur.fetchone()[0]
        cur.execute("select current_database(), inet_server_port(), max(version) from schema_migrations")
        database, port, max_version = cur.fetchone()
        cur.execute("select version, name from schema_migrations where version = any(%s)", (versions,))
        applied = {int(version): name for version, name in cur.fetchall()}
    return {"database": database, "port": port, "ledger_max_version": max_version,
            "applied": applied, "target_identity": identity}


def _target_guard(identity: str) -> str:
    import re

    if not re.fullmatch(r"[0-9a-f]{32}", identity):
        raise MigrationConnectionError("invalid_target_identity")
    return ("DO $sli_target_guard$ BEGIN IF " + TARGET_IDENTITY_SQL
            + " IS DISTINCT FROM '" + identity + "' THEN "
            "RAISE EXCEPTION 'selected_migration_target_mismatch'; "
            "END IF; END $sli_target_guard$;")


def _run_selected(args, versions, inventory, parts) -> int:
    before = _ledger(parts, versions)
    result: dict[str, object] = {"action": args.action, "versions": versions, "before": before}
    if args.action == "apply":
        psql = args.bin_dir / ("psql.exe" if os.name == "nt" else "psql")
        applied_now = []
        for version in versions:
            if version in before["applied"]:
                continue
            migration = inventory[version]
            command = [
                str(psql), "--no-psqlrc", "--no-password",
                "--set", "ON_ERROR_STOP=1", "--quiet",
                "--command", _target_guard(before["target_identity"]),
                "--file", str(migration.path),
            ]
            # -c and -f run in order on the SAME session; -X prevents a startup
            # file from reconnecting/mutating before the guard. No wrapping
            # transaction is imposed on migrations with their own transactions.
            completed = subprocess.run(command, env=dict(os.environ), capture_output=True, text=True,
                                       encoding="utf-8", errors="replace", check=False)
            if completed.returncode != 0:
                # Server/libpq errors can contain DSNs, passwords or SQL values.
                # Never echo captured output, even if a simple redactor looks safe.
                result["failed"] = {"version": version, "psql_exit_code": completed.returncode,
                                    "reason": "psql_connection_guard_or_migration_failed"}
                print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
                return 1
            applied_now.append(version)
        result["applied_now"] = applied_now
        result["after"] = _ledger(parts, versions)
        if result["after"]["target_identity"] != before["target_identity"]:
            raise MigrationConnectionError("readback_target_mismatch")
        missing = [version for version in versions if version not in result["after"]["applied"]]
        if missing:
            result["missing_after_apply"] = missing
            print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
            return 1
    print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("action", choices=("plan", "apply"))
    parser.add_argument("--versions", required=True, help="comma-separated versions, e.g. 144,145")
    parser.add_argument("--confirm")
    parser.add_argument("--bin-dir", type=Path, default=DEFAULT_BIN_DIR)
    args = parser.parse_args(argv)
    versions = sorted({int(item) for item in args.versions.split(",") if item.strip()})
    inventory = {item.version: item for item in forward_migration_inventory(MIGRATIONS_DIR)}
    unknown = [version for version in versions if version not in inventory]
    if not versions or unknown:
        raise SystemExit(f"unknown migration versions: {unknown or 'none given'}")
    if args.action == "apply" and args.confirm != confirmation_token(versions):
        raise SystemExit(f"apply requires --confirm {confirmation_token(versions)}")
    import psycopg

    try:
        parts = _admin_parts()
        with _connection_contract(parts) as connection:
            return _run_selected(args, versions, inventory, connection)
    except MigrationConnectionError as exc:
        print(json.dumps({"error": str(exc)}))
    except (psycopg.Error, OSError, ValueError):
        # Exceptions may embed credentials or the full original conninfo.
        print(json.dumps({"error": "migration_connection_or_configuration_failed"}))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

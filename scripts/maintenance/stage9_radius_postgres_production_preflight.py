#!/usr/bin/env python3
from __future__ import annotations

"""Read-only production preflight for the exact Stage 9 migration 058."""

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.ops.worker_supervisor_secrets import (  # noqa: E402
    load_supervisor_environment,
)


FORWARD = (
    ROOT
    / "config/postgres_migrations/"
    "058_radius_accounting_transaction_foundation.sql"
)
ROLLBACK = (
    ROOT
    / "config/postgres_migrations/"
    "058_radius_accounting_transaction_foundation.rollback.sql"
)
RESULT = (
    ROOT
    / "artifacts/stage9/evidence/"
    "radius-accounting-postgres58-production-preflight.json"
)
FOUNDATION_TABLES = (
    "acquisition_source_instances",
    "acquisition_stream_cursors",
    "acquisition_consumer_subscriptions",
    "core_evidence_manifests",
    "radius_accounting_session_observations",
    "acquisition_delivery_outbox",
    "radius_accounting_class_cache",
)


def _load_environment() -> None:
    if not (
        os.getenv("ADLOG_PG_ADMIN_USER", "").strip()
        and os.getenv("ADLOG_PG_ADMIN_PASSWORD", "")
        and os.getenv("ADLOG_PG_DSN", "").strip()
    ):
        load_supervisor_environment()


def _admin_dsn() -> str:
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    source = os.getenv("ADLOG_PG_DSN", "").strip()
    user = os.getenv("ADLOG_PG_ADMIN_USER", "").strip()
    password = os.getenv("ADLOG_PG_ADMIN_PASSWORD", "")
    if not source or not user or not password:
        raise RuntimeError(
            "protected PostgreSQL migration credentials are required"
        )
    values = conninfo_to_dict(source)
    values.update(user=user, password=password)
    return make_conninfo(**values)


def _connect():
    import psycopg
    from psycopg.rows import dict_row

    return psycopg.connect(
        _admin_dsn(),
        autocommit=False,
        row_factory=dict_row,
        connect_timeout=5,
        application_name="sli_stage9_radius58_production_preflight",
        options="-c statement_timeout=15000 -c lock_timeout=3000",
    )


def inspect() -> dict[str, Any]:
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("set transaction read only")
        cur.execute(
            """
            select current_database() as database,
                   current_user as login_role,
                   current_role as active_role,
                   current_setting('server_version_num')::integer
                     as server_version_num,
                   current_setting('server_encoding') as encoding,
                   pg_is_in_recovery() as in_recovery
            """
        )
        identity = dict(cur.fetchone())
        cur.execute(
            """
            select version,name from schema_migrations
            where version=any(%s)
            order by version
            """,
            ([55, 56, 57, 58],),
        )
        markers = [
            {"version": int(row["version"]), "name": str(row["name"])}
            for row in cur.fetchall()
        ]
        cur.execute(
            """
            select coalesce(max(version),0) as maximum
            from schema_migrations
            """
        )
        maximum_marker = int(cur.fetchone()["maximum"])
        cur.execute(
            """
            select rolname,rolsuper,rolcreaterole
            from pg_roles
            where rolname=any(%s)
            order by rolname
            """,
            (
                [
                    str(identity["login_role"]),
                    "adlog_storage_owner",
                    "adlog_radius_accounting_worker",
                ],
            ),
        )
        roles = {
            str(row["rolname"]): {
                "superuser": bool(row["rolsuper"]),
                "createrole": bool(row["rolcreaterole"]),
            }
            for row in cur.fetchall()
        }
        cur.execute(
            """
            select pg_has_role(
                     current_user,'adlog_storage_owner','MEMBER'
                   ) as storage_owner_member,
                   has_schema_privilege(
                     current_user,'public','USAGE'
                   ) as public_schema_usage
            """
        )
        privileges = dict(cur.fetchone())
        cur.execute(
            """
            select relname from pg_class
            where relnamespace=current_schema()::regnamespace
              and relname=any(%s)
            order by relname
            """,
            (list(FOUNDATION_TABLES),),
        )
        conflicts = [str(row["relname"]) for row in cur.fetchall()]
        conn.rollback()

    marker_by_version = {
        item["version"]: item["name"] for item in markers
    }
    login = roles.get(str(identity["login_role"]), {})
    blockers = []
    if identity["encoding"] != "UTF8":
        blockers.append("database_encoding_is_not_utf8")
    if int(identity["server_version_num"]) < 160000:
        blockers.append("postgresql_version_below_16")
    if marker_by_version.get(55) != "semantic_finding_publication":
        blockers.append("required_marker_55_missing_or_mismatched")
    if 58 in marker_by_version:
        blockers.append("migration_58_already_present")
    if "adlog_radius_accounting_worker" in roles:
        blockers.append("worker_role_name_conflict")
    if conflicts:
        blockers.append("foundation_table_name_conflict")
    if not bool(privileges["storage_owner_member"]):
        blockers.append("admin_is_not_storage_owner_member")
    if not (bool(login.get("superuser")) or bool(login.get("createrole"))):
        blockers.append("admin_cannot_create_least_privilege_role")

    return {
        "status": "ready" if not blockers else "blocked",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "identity": {
            "database": str(identity["database"]),
            "login_role": str(identity["login_role"]),
            "active_role": str(identity["active_role"]),
            "server_version_num": int(identity["server_version_num"]),
            "encoding": str(identity["encoding"]),
            "in_recovery": bool(identity["in_recovery"]),
        },
        "schema": {
            "maximum_marker": maximum_marker,
            "relevant_markers": markers,
            "foundation_table_conflicts": conflicts,
            "radius_worker_role_exists": (
                "adlog_radius_accounting_worker" in roles
            ),
        },
        "privileges": {
            "storage_owner_member": bool(
                privileges["storage_owner_member"]
            ),
            "public_schema_usage": bool(
                privileges["public_schema_usage"]
            ),
            "can_create_role": bool(
                login.get("superuser") or login.get("createrole")
            ),
        },
        "migration": {
            "version": 58,
            "forward_sha256": sha256(FORWARD.read_bytes()).hexdigest(),
            "rollback_sha256": sha256(ROLLBACK.read_bytes()).hexdigest(),
            "execution_contract": "single_file_058_only",
            "excluded_from_automatic_sequence": [56, 57],
        },
        "blockers": blockers,
        "production_database_changed": False,
        "radius_source_contacted": False,
        "runtime_enabled": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--load-supervisor-environment",
        action="store_true",
    )
    parser.add_argument("--output", default=str(RESULT))
    args = parser.parse_args()
    output = Path(args.output).resolve()
    if not output.is_relative_to(ROOT):
        print(
            json.dumps(
                {
                    "status": "failed",
                    "error": "output must stay inside the project",
                }
            )
        )
        return 1
    if output.exists():
        print(
            json.dumps(
                {
                    "status": "failed",
                    "error": "preflight evidence already exists",
                    "output": str(output),
                }
            )
        )
        return 1
    try:
        if args.load_supervisor_environment:
            _load_environment()
        result = inspect()
    except Exception as exc:  # noqa: BLE001
        result = {
            "status": "failed",
            "error_type": type(exc).__name__,
            "error": str(exc),
            "production_database_changed": False,
            "radius_source_contacted": False,
            "runtime_enabled": False,
        }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result.get("status") == "ready" else 1


if __name__ == "__main__":
    raise SystemExit(main())

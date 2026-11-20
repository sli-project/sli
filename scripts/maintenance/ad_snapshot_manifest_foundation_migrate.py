#!/usr/bin/env python3
"""Bounded plan/apply/verify/rollback controller for migration 121 only."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.core.app_config import load_config, redact_dsn

VERSION = 121
NAME = "ad_snapshot_manifest_foundation"
FORWARD = ROOT / "config/postgres_migrations/121_ad_snapshot_manifest_foundation.sql"
ROLLBACK = ROOT / "config/postgres_migrations/121_ad_snapshot_manifest_foundation.rollback.sql"
APPLY_TOKEN = "APPLY-AD-SNAPSHOT-MANIFEST-FOUNDATION-121"
ROLLBACK_TOKEN = "ROLLBACK-AD-SNAPSHOT-MANIFEST-FOUNDATION-121"
TABLES = ("ad_snapshot_manifests", "ad_snapshot_manifest_sources", "ad_snapshot_projection_receipts")


def _dsn(*, admin: bool) -> str:
    from psycopg.conninfo import conninfo_to_dict, make_conninfo
    value = os.getenv("ADLOG_PG_DSN") or load_config().postgres_dsn
    if not value:
        raise RuntimeError("PostgreSQL DSN is not configured")
    if not admin:
        return str(value)
    user = os.getenv("ADLOG_PG_ADMIN_USER", "").strip()
    password = os.getenv("ADLOG_PG_ADMIN_PASSWORD", "")
    if not user or not password:
        raise RuntimeError("local PostgreSQL admin credentials are required")
    parts = conninfo_to_dict(str(value))
    parts.update(user=user, password=password)
    return make_conninfo(**parts)


def _connect(dsn: str):
    import psycopg
    from psycopg.rows import dict_row
    return psycopg.connect(dsn, row_factory=dict_row, connect_timeout=5,
        application_name="sli_ad_snapshot_manifest_foundation_v121",
        options="-c statement_timeout=30000 -c lock_timeout=5000")


def _status(cur: Any) -> dict[str, object]:
    cur.execute("select name from schema_migrations where version=%s", (VERSION,))
    marker_row = cur.fetchone()
    marker_name = str(marker_row["name"]) if marker_row else None
    cur.execute(
        """
        select
          (select count(*)::integer from pg_class where oid in (
             to_regclass('ad_snapshot_manifests'),to_regclass('ad_snapshot_manifest_sources'),
             to_regclass('ad_snapshot_projection_receipts')) and relkind='r') as table_count,
          (select count(*)::integer from pg_trigger where not tgisinternal and tgname in (
             'trg_ad_snapshot_manifests_immutable','trg_ad_snapshot_manifest_sources_immutable')) as immutable_trigger_count,
          exists(select 1 from pg_proc where proname='ad_snapshot_manifest_reject_mutation') as immutable_function,
          exists(select 1 from pg_constraint where conrelid=to_regclass('ad_snapshot_manifests')
             and contype='u' and pg_get_constraintdef(oid) like '%domain_id, slot_start_utc, contract_version%') as unique_domain_slot_contract,
          exists(select 1 from pg_indexes where indexname='idx_ad_snapshot_manifests_slot') as manifest_slot_index,
          exists(select 1 from pg_indexes where indexname='idx_ad_snapshot_projection_receipts_claim') as projection_claim_index,
          (select count(*)::integer from information_schema.role_table_grants
             where table_name in ('ad_snapshot_manifests','ad_snapshot_manifest_sources')
               and grantee='PUBLIC') as public_manifest_grants,
          (select count(*)::integer from information_schema.role_table_grants
             where table_name='ad_snapshot_projection_receipts' and grantee='PUBLIC') as public_receipt_grants,
          (select count(*)::integer
             from information_schema.role_table_grants grants
             join pg_catalog.pg_tables tables
               on tables.schemaname=grants.table_schema
              and tables.tablename=grants.table_name
            where grants.table_name in ('ad_snapshot_manifests','ad_snapshot_manifest_sources')
              and grants.privilege_type in ('UPDATE','DELETE','TRUNCATE')
              and grants.grantee<>tables.tableowner) as mutable_manifest_grants,
          exists(select 1 from pg_roles where rolname='adlog_context_worker') as worker_role_exists,
          (select count(*)::integer from information_schema.role_table_grants
             where grantee='adlog_context_worker'
               and table_name in ('ad_snapshot_manifests','ad_snapshot_manifest_sources')
               and privilege_type in ('SELECT','INSERT')) as worker_manifest_grants,
          (select count(*)::integer from information_schema.role_table_grants
             where grantee='adlog_context_worker' and table_name='ad_snapshot_projection_receipts'
               and privilege_type in ('SELECT','INSERT','UPDATE')) as worker_receipt_grants,
          (select count(*)::integer from information_schema.role_table_grants
             where grantee='adlog_context_worker'
               and table_name in ('ad_snapshot_manifests','ad_snapshot_manifest_sources','ad_snapshot_projection_receipts')
               and privilege_type in ('DELETE','TRUNCATE')) as worker_forbidden_grants
        """
    )
    return {
        "marker": marker_name == NAME,
        "marker_name": marker_name,
        "marker_version": VERSION if marker_row else None,
        **dict(cur.fetchone()),
    }


def _verify_applied(result: dict[str, object]) -> None:
    expected = {
        "marker": True, "marker_name": NAME, "marker_version": VERSION,
        "table_count": 3, "immutable_trigger_count": 2, "immutable_function": True,
        "unique_domain_slot_contract": True, "manifest_slot_index": True,
        "projection_claim_index": True, "public_manifest_grants": 0,
        "public_receipt_grants": 0, "mutable_manifest_grants": 0,
    }
    for key, value in expected.items():
        if result.get(key) != value:
            raise RuntimeError(f"migration 121 readback failed: {key}")
    if result.get("worker_role_exists"):
        for key, value in {"worker_manifest_grants": 4, "worker_receipt_grants": 3, "worker_forbidden_grants": 0}.items():
            if result.get(key) != value:
                raise RuntimeError(f"migration 121 restrictive grant readback failed: {key}")


def run(*, action: str, confirmation: str | None) -> dict[str, object]:
    if action not in {"plan", "apply", "verify", "rollback"}:
        raise ValueError("unsupported action")
    if action == "apply" and confirmation != APPLY_TOKEN:
        raise RuntimeError(f"apply requires --confirm {APPLY_TOKEN}")
    if action == "rollback" and confirmation != ROLLBACK_TOKEN:
        raise RuntimeError(f"rollback requires --confirm {ROLLBACK_TOKEN}")
    dsn = _dsn(admin=action in {"apply", "verify", "rollback"})
    result: dict[str, object] = {
        "status": "ok", "action": action, "migration_version": VERSION,
        "migration_name": NAME, "dsn": redact_dsn(dsn),
        "surveyed_systems_contacted": False, "report_rows_modified": False,
    }
    with _connect(dsn) as connection, connection.cursor() as cursor:
        if action in {"plan", "verify"}:
            cursor.execute("set transaction read only")
            result.update(_status(cursor))
            if action == "verify":
                _verify_applied(result)
            return result
        cursor.execute((FORWARD if action == "apply" else ROLLBACK).read_text(encoding="utf-8"))
        result.update(_status(cursor))
        if action == "apply":
            _verify_applied(result)
        elif result.get("marker") or result.get("table_count") != 0:
            raise RuntimeError("migration 121 rollback readback failed")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--apply", action="store_true")
    group.add_argument("--rollback", action="store_true")
    group.add_argument("--verify", action="store_true")
    parser.add_argument("--confirm")
    parser.add_argument("--load-supervisor-environment", action="store_true")
    args = parser.parse_args()
    if args.load_supervisor_environment and not (os.getenv("ADLOG_PG_ADMIN_USER", "").strip() and os.getenv("ADLOG_PG_ADMIN_PASSWORD", "")):
        from server.sli.ops.worker_supervisor_secrets import load_supervisor_environment
        load_supervisor_environment()
    action = "apply" if args.apply else "rollback" if args.rollback else "verify" if args.verify else "plan"
    try:
        result = run(action=action, confirmation=args.confirm)
    except Exception as exc:
        result = {"status": "error", "action": action, "error_type": type(exc).__name__, "error": str(exc)}
    print(json.dumps(result, ensure_ascii=False, default=str))
    return 0 if result["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())

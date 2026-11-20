#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from server.sli.core.app_config import load_config, redact_dsn  # noqa: E402
from server.sli.ops.postgres_schema_guard import OPS_STABILITY_SCHEMA_VERSION, clear_schema_guard_cache  # noqa: E402

MIGRATION_NAME = "ops_stability1_runtime_contracts"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _columns(cur, table: str) -> list[str]:
    cur.execute(
        """
        select column_name
        from information_schema.columns
        where table_schema=current_schema() and table_name=%s
        order by ordinal_position
        """,
        (table,),
    )
    return [str(row["column_name"]) for row in cur.fetchall()]


def run_migration() -> dict[str, Any]:
    cfg = load_config()
    if (cfg.db_backend or "").strip().lower() != "postgres":
        raise RuntimeError("OPS-STABILITY migration requires PostgreSQL-only runtime")
    if not (cfg.postgres_dsn or "").strip():
        raise RuntimeError("PostgreSQL DSN is not configured")

    from server.sli.core.postgres_runtime_pipeline import connect

    started = time.monotonic()
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("select pg_advisory_xact_lock(hashtext('ad_log_reports_ops_stability1'))")
            cur.execute("select to_regclass('post_collection_jobs') as post_jobs, to_regclass('storage_lifecycle_snapshots') as snapshots")
            tables = cur.fetchone() or {}
            if not tables.get("post_jobs") or not tables.get("snapshots"):
                raise RuntimeError(f"Required tables are missing: {tables}")

            cur.execute("alter table post_collection_jobs add column if not exists durable_job_id text")
            cur.execute("alter table post_collection_jobs add column if not exists worker_lease_until timestamptz null")
            cur.execute(
                "update post_collection_jobs set durable_job_id='legacy-' || id::text where durable_job_id is null or durable_job_id=''"
            )
            cur.execute("alter table post_collection_jobs alter column durable_job_id set not null")
            cur.execute(
                """
                do $$
                declare item record;
                begin
                    for item in
                        select c.conname
                        from pg_constraint c
                        join pg_class t on t.oid=c.conrelid
                        join pg_namespace n on n.oid=t.relnamespace
                        where n.nspname=current_schema()
                          and t.relname='post_collection_jobs'
                          and c.contype='u'
                          and c.conkey = array[(select attnum from pg_attribute where attrelid=t.oid and attname='source_job_id')]
                    loop
                        execute format('alter table post_collection_jobs drop constraint %I', item.conname);
                    end loop;
                end $$
                """
            )
            cur.execute("create unique index if not exists uq_post_collection_jobs_durable_job_id on post_collection_jobs(durable_job_id)")
            cur.execute("create index if not exists idx_post_collection_jobs_source_job_id on post_collection_jobs(source_job_id)")
            cur.execute("create index if not exists idx_post_collection_jobs_lease on post_collection_jobs(status, worker_lease_until)")

            cur.execute("alter table storage_lifecycle_snapshots add column if not exists source_run_id text null")
            cur.execute(
                """
                do $$
                declare item record;
                begin
                    for item in
                        select c.conname
                        from pg_constraint c
                        join pg_class t on t.oid=c.conrelid
                        join pg_namespace n on n.oid=t.relnamespace
                        where n.nspname=current_schema()
                          and t.relname='storage_lifecycle_snapshots'
                          and c.contype='u'
                          and c.conkey = array[(select attnum from pg_attribute where attrelid=t.oid and attname='source_job_id')]
                    loop
                        execute format('alter table storage_lifecycle_snapshots drop constraint %I', item.conname);
                    end loop;
                end $$
                """
            )
            cur.execute(
                "create unique index if not exists uq_storage_lifecycle_snapshots_source_run_id "
                "on storage_lifecycle_snapshots(source_run_id)"
            )
            cur.execute(
                "create index if not exists idx_storage_lifecycle_snapshots_source_job_id "
                "on storage_lifecycle_snapshots(source_job_id)"
            )

            cur.execute(
                """
                insert into schema_migrations(version, name)
                values (%s, %s)
                on conflict(version) do update set name=excluded.name
                """,
                (OPS_STABILITY_SCHEMA_VERSION, MIGRATION_NAME),
            )
            cur.execute("select coalesce(max(version),0)::integer as version from schema_migrations")
            version = int((cur.fetchone() or {}).get("version") or 0)
            cur.execute("select count(*)::integer as legacy_rows from post_collection_jobs where durable_job_id like 'legacy-%'")
            legacy_rows = int((cur.fetchone() or {}).get("legacy_rows") or 0)
            result = {
                "post_collection_columns": _columns(cur, "post_collection_jobs"),
                "storage_snapshot_columns": _columns(cur, "storage_lifecycle_snapshots"),
                "schema_version": version,
                "legacy_post_collection_rows": legacy_rows,
            }
    clear_schema_guard_cache()
    return {
        "package_type": "OPS_STABILITY1_SCHEMA_MIGRATION",
        "status": "ok",
        "generated_at_utc": _utc_now(),
        "duration_ms": int((time.monotonic() - started) * 1000),
        "backend": "postgres",
        "dsn": redact_dsn(cfg.postgres_dsn),
        "migration_version": OPS_STABILITY_SCHEMA_VERSION,
        "migration_name": MIGRATION_NAME,
        **result,
        "safety": {
            "event_rows_modified": False,
            "collection_state_modified": False,
            "legacy_jobs_executed": False,
            "ddl_scope": ["post_collection_jobs", "storage_lifecycle_snapshots", "schema_migrations"],
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Apply OPS-STABILITY-1 PostgreSQL runtime contracts")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--output")
    args = parser.parse_args()
    try:
        payload = run_migration()
        code = 0
    except Exception as exc:
        payload = {
            "package_type": "OPS_STABILITY1_SCHEMA_MIGRATION",
            "status": "failed",
            "generated_at_utc": _utc_now(),
            "error_type": type(exc).__name__,
            "error": str(exc),
        }
        code = 1
    text = json.dumps(payload, ensure_ascii=False, indent=2, default=str)
    if args.output:
        from pathlib import Path
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    if args.json or not args.output:
        print(text)
    return code


if __name__ == "__main__":
    raise SystemExit(main())

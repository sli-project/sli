#!/usr/bin/env python3
"""READ-ONLY inventory of the SLI runtime: collection blocks, cursors, heartbeats.

Opens one short-lived autocommit PostgreSQL connection with a bounded statement
timeout, runs only SELECTs, and prints a human-readable report.  No DDL, no DML,
no process control.  Intended to be run BEFORE starting anything, so an operator
never launches a duplicate worker or a second listener.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.core.app_config import load_config, redact_dsn  # noqa: E402

QUERIES: tuple[tuple[str, str], ...] = (
    ("schema marker", "select max(version) as version from schema_migrations"),
    (
        # `runtime_collection_blocks` is a SINGLETON table (migration 038):
        # singleton_id, active, reason_code, source_server, first/last_seen_at,
        # last_probe_at/result, cleared_at.  There is no server_hostname column.
        "durable-блокировка сбора",
        """
        select active, reason_code, source_server, source_worker_id,
               observed_count, first_seen_at, last_seen_at,
               last_probe_at, last_probe_result, cleared_at, operator_action
        from runtime_collection_blocks
        where singleton_id = 1
        """,
    ),
    (
        # `last_successful_collection_utc` is TEXT (ISO-8601), so a direct
        # timestamptz subtraction fails.  ISO-8601 sorts correctly as text, so we
        # order on the raw column and cast only for display — this also honours
        # the project rule against casting production time columns in recurring
        # index-backed queries.
        "курсоры каналов (самые отставшие сверху)",
        """
        select server_hostname, channel, last_event_record_id,
               last_successful_collection_utc,
               round(extract(epoch from (
                   now() - nullif(last_successful_collection_utc, '')::timestamptz
               )) / 60) as min_ago
        from collection_channel_state
        order by last_successful_collection_utc nulls first
        limit 10
        """,
    ),
    (
        "Security cursors",
        """
        select server_hostname, channel, last_event_record_id,
               last_successful_collection_utc,
               round(extract(epoch from (
                   now() - nullif(last_successful_collection_utc, '')::timestamptz
               )) / 60) as min_ago
        from collection_channel_state
        where channel = 'Security'
        order by server_hostname
        """,
    ),
    (
        # migration 032: the column is `heartbeat_at`, not `last_heartbeat_utc`.
        "heartbeat'ы worker'ов",
        """
        select worker_name, worker_id, process_pid, status, phase,
               expected_interval_seconds,
               heartbeat_at,
               round(extract(epoch from (now() - heartbeat_at)) / 60) as min_ago
        from runtime_worker_heartbeats
        order by heartbeat_at desc nulls last
        limit 12
        """,
    ),
    (
        # Use row JSON for the migration-047 fields so the inventory remains
        # usable during a fail-closed preflight against an older schema.
        "последние результаты каналов",
        """
        select r.server, r.channel, r.status, r.inserted, r.skipped, r.limit_used,
               to_jsonb(r)->>'partial_kind' as partial_kind,
               to_jsonb(r)->>'failure_stage' as failure_stage,
               to_jsonb(r)->>'cursor_commit_allowed' as cursor_commit_allowed,
               r.created_at
        from collector_channel_runs r
        order by r.id desc
        limit 12
        """,
    ),
    (
        "долгие транзакции (> 1 мин)",
        """
        select pid, state, application_name,
               round(extract(epoch from (clock_timestamp() - xact_start))) as xact_seconds
        from pg_stat_activity
        where datname = current_database()
          and pid <> pg_backend_pid()
          and xact_start is not null
          and clock_timestamp() - xact_start > interval '1 minute'
        order by xact_start
        limit 10
        """,
    ),
)


def main() -> int:
    dsn = os.getenv("ADLOG_PG_DSN") or load_config().postgres_dsn
    if not dsn:
        print("ADLOG_PG_DSN не настроен")
        return 1
    print(f"dsn: {redact_dsn(str(dsn))}")

    try:
        import psycopg
    except Exception as exc:  # pragma: no cover - environment dependent
        print(f"psycopg недоступен: {exc}")
        return 1

    failures = 0
    with psycopg.connect(
        str(dsn), autocommit=True, connect_timeout=5,
        application_name="sli_inventory_readonly",
    ) as conn:
        with conn.cursor() as cur:
            cur.execute("set statement_timeout = 15000")
            cur.execute("set lock_timeout = 3000")
            # Belt and braces: this session must never write.
            cur.execute("set default_transaction_read_only = on")
            for title, sql in QUERIES:
                print(f"\n  [{title}]")
                try:
                    cur.execute(sql)
                    rows = cur.fetchall()
                    if not rows:
                        print("    (пусто)")
                        continue
                    names = [str(desc[0]) for desc in (cur.description or [])]
                    print("    " + " | ".join(names))
                    for row in rows:
                        print("    " + " | ".join("" if value is None else str(value) for value in row))
                except Exception as exc:
                    failures += 1
                    print(f"    ОШИБКА: {type(exc).__name__}: {exc}")
    return 0 if failures == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())

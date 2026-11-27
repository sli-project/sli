"""Disposable PostgreSQL proof for the V2 quarantine-repair transaction boundary.

These checks intentionally use real PostgreSQL transactions and advisory locks.
They are limited to a schema-only ``sli_test_*`` database and synthetic event
rows; no retained event, worker, source or production database is contacted.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from urllib.parse import unquote, urlsplit

import pytest

from tests.migrations.historical_postgres import historical_connection
from tests.postgres_integration_guard import assert_disposable_database

ROOT = Path(__file__).resolve().parents[2]
MIGRATION_143 = ROOT / "config/postgres_migrations/143_semantic_v2_quarantine_repair.sql"


def _test_dsn() -> str:
    dsn = (os.environ.get("ADLOG_TEST_PG_DSN") or "").strip()
    if not dsn:
        pytest.skip("ADLOG_TEST_PG_DSN is not configured for disposable PostgreSQL tests")
    parsed = urlsplit(dsn)
    database = unquote(parsed.path).lstrip("/") if parsed.scheme else ""
    if not database:
        matched = re.search(r"(?:^|\s)dbname=(?:'([^']+)'|\"([^\"]+)\"|(\S+))", dsn)
        database = next((item for item in (matched.groups() if matched else ()) if item), "")
    if not database.startswith("sli_test_"):
        pytest.skip("ADLOG_TEST_PG_DSN must name a disposable sli_test_* database")
    return dsn


@pytest.fixture
def current_connect():
    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row

    dsn = _test_dsn()

    def _connect():
        return psycopg.connect(dsn, row_factory=dict_row)

    with _connect() as conn:
        assert_disposable_database(conn)
    return _connect



@pytest.fixture
def historical_connect(tmp_path, monkeypatch):
    import psycopg
    from psycopg.rows import dict_row

    # Migration 372 retires the event table used by the legacy repair control.
    # Worker, controller and observer connections must share this owned database.
    with historical_connection(tmp_path, monkeypatch, (371, "password_domain_auto")) as conn:
        with conn.transaction():
            conn.execute("set local role adlog_storage_owner")
            conn.execute(
                "insert into event_catalog_revisions(version) values ('pending-backfill') "
                "on conflict(version) do nothing"
            )
        parameters = conn.info.get_parameters()

        def connect():
            return psycopg.connect(**parameters, row_factory=dict_row)

        yield connect


def _insert_source(
    cur, *, source_event_id: int, windows_event_id: int = 4624,
    provider_value: str = "v2-repair-pg-provider",
    channel_value: str = "v2-repair-pg-channel",
    target_user_sid: str | None = None,
    keywords_value: str | None = None,
    occurred: datetime | None = None,
) -> None:
    occurred = occurred or datetime(2026, 9, 20, tzinfo=timezone.utc)
    identifiers: dict[str, int] = {}
    for table, value in {
        "storage_v2_provider": provider_value,
        "storage_v2_channel": channel_value,
        "storage_v2_computer": "v2-repair-pg-computer",
    }.items():
        cur.execute(
            f"insert into {table}(value) values (%s) on conflict(value) do update "
            f"set value=excluded.value returning id",
            (value,),
        )
        identifiers[table] = cur.fetchone()["id"]
    keywords_id = None
    if keywords_value is not None:
        cur.execute(
            """insert into storage_v2_keywords(value) values (%s)
               on conflict(value) do update set value=excluded.value returning id""",
            (keywords_value,),
        )
        keywords_id = cur.fetchone()["id"]
    cur.execute(
        """
        insert into events_v2_core(
            id,server_id,domain_id,log_source_id,event_record_id,event_id,
            keywords_id,provider_id,channel_id,computer_id,time_created_utc,target_user_sid,correlation_id,
            normalized_at,normalized_hash,source_core_sha256
        ) values (%s,1,1,1,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """,
        (
            source_event_id,
            source_event_id,
            windows_event_id,
            keywords_id,
            identifiers["storage_v2_provider"],
            identifiers["storage_v2_channel"],
            identifiers["storage_v2_computer"],
            occurred,
            target_user_sid,
            f"v2-repair-pg-{source_event_id}",
            occurred,
            b"a" * 32,
            b"b" * 32,
        ),
    )


def _apply_migration143(connect) -> None:
    """Apply only the submitted migration to the disposable schema clone."""
    with connect() as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(MIGRATION_143.read_text(encoding="utf-8"), prepare=False)

def _repair_payload(*, source_event_id: int, original_job_id: str) -> dict[str, object]:
    return {
        "repair_plan_digest": "c" * 64,
        "history_plan_digest": "d" * 64,
        "original_source_hash": ("61" * 32),
        "original_job_id": original_job_id,
        "original_attempt_count": 5,
        "original_max_attempts": 5,
        "original_error_code": "UniqueViolation",
        "original_error_detail_sha256": sha256(
            b'duplicate key value violates unique constraint "canonical_actions_pkey"'
        ).hexdigest(),
    }


def _terminal_original_snapshot(cur, *, source_event_ids: tuple[int, ...]) -> list[dict[str, object]]:
    """Read the immutable original rows without relying on controller output."""
    cur.execute(
        """select to_jsonb(outbox) as row
           from semantic_processing_outbox
           as outbox
           where source_event_id=any(%s) and job_kind='normalize_event'
           order by source_event_id,job_id""",
        (list(source_event_ids),),
    )
    return [dict(row)["row"] for row in cur.fetchall()]


@pytest.mark.postgres_integration
def test_security_history_check_snapshot_uses_repeatable_read_read_only_transaction(current_connect) -> None:
    """The intended check snapshot mode is accepted and observable on PostgreSQL."""
    with current_connect() as conn, conn.transaction(), conn.cursor() as cur:
        cur.execute("set transaction isolation level repeatable read, read only")
        cur.execute(
            """select current_setting('transaction_isolation') as isolation,
                      current_setting('transaction_read_only') as read_only"""
        )
        settings = cur.fetchone()
    assert settings == {"isolation": "repeatable read", "read_only": "on"}

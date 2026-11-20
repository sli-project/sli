"""PostgreSQL-only regression for the archive-start candidate type boundary."""
from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest


def test_archive_start_candidate_query_unions_timestamps_before_text_serialization() -> None:
    """A cast inside one UNION branch would raise DatatypeMismatch before RPC."""
    dsn = os.environ.get("SLITEST_PG_DSN", "").strip()
    if not dsn:
        pytest.skip("SLITEST_PG_DSN is not configured for the local read-only PostgreSQL regression")

    import psycopg
    from server.sli.core.postgres_runtime_pipeline import ARCHIVE_START_CANDIDATE_QUERY

    with psycopg.connect(dsn, autocommit=False, connect_timeout=5) as conn:
        with conn.cursor() as cur:
            cur.execute("set transaction read only")
            cur.execute("set local statement_timeout = '5s'")
            cur.execute(
                """
                with collection_runs(run_started_at) as (
                    values ('2026-09-10 00:30:00+01'::timestamptz)
                ), events_v2_core(time_created_utc) as (
                    values ('2026-09-09 23:45:00+00'::timestamptz)
                )
                """
                + ARCHIVE_START_CANDIDATE_QUERY
            )
            row = cur.fetchone()
            cur.execute(
                """
                with collection_runs(run_started_at) as (
                    values (null::timestamptz)
                ), events_v2_core(time_created_utc) as (
                    values (null::timestamptz)
                )
                """
                + ARCHIVE_START_CANDIDATE_QUERY
            )
            empty_row = cur.fetchone()

    assert row is not None
    assert datetime.fromisoformat(str(row[0])).astimezone(timezone.utc) == datetime(
        2026, 9, 9, 23, 30, tzinfo=timezone.utc
    )
    assert empty_row == (None,)

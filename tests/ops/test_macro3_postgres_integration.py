from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest


@pytest.mark.postgres_integration
def test_postgres_text_time_cutoff_and_source_run_conflict_contract() -> None:
    dsn = (os.environ.get("ADLOG_TEST_PG_DSN") or "").strip()
    if not dsn:
        pytest.skip("ADLOG_TEST_PG_DSN is not configured for isolated PostgreSQL integration tests")

    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("create temporary table events(time_created_utc text not null)")
            now = datetime.now(timezone.utc)
            old = (now - timedelta(days=2)).isoformat(timespec="microseconds")
            recent = (now - timedelta(hours=1)).isoformat(timespec="microseconds")
            cutoff = (now - timedelta(hours=24)).isoformat(timespec="microseconds")
            cur.execute("insert into events(time_created_utc) values (%s), (%s)", (old, recent))
            cur.execute(
                "select count(*) from events where time_created_utc >= %s",
                (cutoff,),
            )
            assert cur.fetchone()[0] == 1

            cur.execute(
                "create temporary table snapshots(source_run_id text unique, payload integer not null)"
            )
            cur.execute(
                "insert into snapshots(source_run_id, payload) values (%s, 1) "
                "on conflict(source_run_id) do nothing returning payload",
                ("run-1",),
            )
            assert cur.fetchone()[0] == 1
            cur.execute(
                "insert into snapshots(source_run_id, payload) values (%s, 2) "
                "on conflict(source_run_id) do nothing returning payload",
                ("run-1",),
            )
            assert cur.fetchone() is None

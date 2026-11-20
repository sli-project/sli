"""Compile the production health reads with the migrated API role in CI."""
import json
import os

import pytest

from server.sli.agents.collection_health import _AGENTS_SQL, _STREAMS_SQL
from server.sli.core.database import _pg_sql
from tests.postgres_integration_guard import assert_disposable_database

pytestmark = pytest.mark.postgres_integration


def test_collection_health_reads_use_existing_runtime_grants():
    psycopg = pytest.importorskip("psycopg")
    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("Disposable migrated PostgreSQL required")
    with psycopg.connect(dsn) as conn, conn.transaction(force_rollback=True):
        assert_disposable_database(conn)
        conn.execute("set local role adlog_user")
        conn.execute("set local search_path=pg_catalog,public")
        conn.execute("set local statement_timeout='3s'")
        conn.execute(_pg_sql(_AGENTS_SQL)).fetchall()
        assert conn.execute(_pg_sql(_STREAMS_SQL), (json.dumps([]),)).fetchall() == []

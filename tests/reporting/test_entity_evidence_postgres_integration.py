from __future__ import annotations

import os

import pytest

from tests.postgres_integration_guard import assert_disposable_database


@pytest.mark.postgres_integration
@pytest.mark.postgres_historical(371, "password_domain_auto")
def test_entity_evidence_id_preflight_query_prepares_on_postgresql(monkeypatch) -> None:
    """Run the legacy id-only query through planning on its last schema.

    The unit contract keeps ``time_created_utc`` out of the returned candidate
    DTO.  PostgreSQL, unlike SQLite, rejects ``SELECT DISTINCT`` when its
    ``ORDER BY`` expression is not selected, so this isolated integration check
    catches that syntax/plan boundary without reading production data.
    """
    dsn = (os.environ.get("ADLOG_TEST_PG_DSN") or "").strip()
    if not dsn:
        pytest.skip("ADLOG_TEST_PG_DSN is not configured for isolated PostgreSQL integration tests")

    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row
    from server.sli.reporting import ui_workspace
    from server.sli.core.database import _pg_sql

    captured: dict[str, object] = {}
    monkeypatch.setattr(ui_workspace, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(
        ui_workspace,
        "query_rows_bounded",
        lambda sql, params, **_kwargs: captured.update(sql=sql, params=params) or [],
    )
    ui_workspace._get_entity_evidence_event_rows(
        entity_id=1,
        limit=31,
        before_time_utc=None,
        before_event_db_id=None,
        id_only=True,
    )

    with psycopg.connect(dsn, row_factory=dict_row) as conn, conn.cursor() as cur:
        assert_disposable_database(conn)
        cur.execute("explain " + _pg_sql(str(captured["sql"])), captured["params"])
        assert cur.fetchall()

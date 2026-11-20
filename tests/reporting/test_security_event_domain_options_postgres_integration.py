"""Exercise the declaration's real metadata SQL without any event store."""
from __future__ import annotations

import os

import pytest

from tests.postgres_integration_guard import assert_disposable_database
from tests.reporting.test_reporting_v2 import FakeHandler
from tests.reporting.test_security_event_reporting import _report_access


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_security_action_declaration_reads_only_authorized_metadata(monkeypatch):
    dsn = str(os.environ.get("ADLOG_TEST_PG_DSN") or "").strip()
    if not dsn:
        pytest.skip("ADLOG_TEST_PG_DSN is required for disposable PostgreSQL coverage")
    psycopg = pytest.importorskip("psycopg")
    from server.api.routes import reports_v2 as routes
    from server.sli.reporting.v2.reports import security_events

    with psycopg.connect(dsn) as conn:
        assert_disposable_database(conn)
        conn.execute("create table domains (id bigint primary key, fqdn text not null)")
        conn.execute("insert into domains values (7, 'active.example.test'), "
                     "(8, 'archive.example.test'), (9, 'hidden.example.test')")
        # An event-table probe would fail in this schema. The route must use
        # real PostgreSQL metadata, without depending on retained event rows.
        assert conn.execute("select to_regclass('events_v2_core')").fetchone()[0] is None

    # Select the real report definition; leave its options, SQL, connection,
    # report grant and domain/capability decisions unpatched.
    monkeypatch.setattr(routes, "get_report", lambda _key: security_events.REPORT)
    monkeypatch.setattr(routes, "report_plugin_state", lambda _key: None)
    access = _report_access()
    access["reports"][0]["grants"][0]["scope"]["ids"] = [7, 8]
    handler = FakeHandler(access)
    assert routes.try_handle_get(handler, "/api/v2/reports/security.events.chains", {})
    payload, status = handler.sent[-1]
    assert status == 200
    assert payload["filter_options"]["domain"] == [
        {"value": "7", "label": "active.example.test"},
        {"value": "8", "label": "archive.example.test"},
    ]
    access["capabilities"] = []
    assert security_events._domain_options(access) == []

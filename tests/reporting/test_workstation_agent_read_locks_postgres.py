"""UI agent reads and lifecycle writes coexist on the migrated runtime role.

Two live transactions deliberately overlap; no timing sleeps or fake cursor
results substitute for PostgreSQL row locks. Only the connection is injected.
"""

from contextlib import nullcontext
import os
from uuid import uuid4

import pytest

from server.sli.plugins.workstations import agent_read, scope
from server.sli.plugins.workstations.reports import FIELDS
from tests.postgres_integration_guard import assert_disposable_database

pytestmark = pytest.mark.postgres_integration


@pytest.fixture
def agent_database():
    # The existing autouse fixture clones a migrated sli_test_* database.
    dsn = (os.environ.get("ADLOG_TEST_PG_DSN") or "").strip()
    if not dsn:
        pytest.skip("CI-owned disposable migrated PostgreSQL required")
    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row

    agent = str(uuid4())

    def connect():
        return psycopg.connect(
            dsn, row_factory=dict_row,
            options="-c role=adlog_user -c lock_timeout=500ms -c statement_timeout=5s",
        )

    with connect() as conn:
        assert_disposable_database(conn)
        assert conn.execute("select current_user as role").fetchone()["role"] == "adlog_user"
        conn.execute("insert into sli_agents(id,host_id,key_fingerprint,assigned_modules) "
                     "values(%s,%s,%s,%s::jsonb)",
                     (agent, str(uuid4()), "a" * 64, '[{"module_id":"sli.workstations"}]'))
    return connect, agent


def _read(conn, agent, reader, monkeypatch):
    access = {"capabilities": ["workstations.read"], "reports": [{
        "report_key": "workstations.overview", "allowed": True,
        "allowed_actions": ["view"], "grants": [{
            "scope": {"kind": "all"} if reader == "scope_all" else {"kind": "agent", "ids": [agent]},
            "allowed_actions": ["view"], "field_categories": sorted(FIELDS),
        }],
    }]}
    if reader.startswith("scope_"):
        # Keep the real reader's transaction open for the reverse-lock check.
        monkeypatch.setattr(scope, "connect", lambda: nullcontext(conn))
        keys = scope.WorkstationScopeAdapter().agent_keys(access, "workstations.overview", "view", FIELDS)
        assert agent in keys
        if reader == "scope_agent":
            assert keys == (agent,)
        return None
    with conn.cursor() as cur:
        result = agent_read.read_agents(cur, access, {} if reader == "agent_list" else {"agent_key": [agent]})
    assert len(result["items"]) == 1
    assert result["items"][0]["agent_key"] == agent
    assert result["has_more"] is False
    assert result["next_cursor"] is None
    return result["items"][0]["status"]


@pytest.mark.parametrize("reader", ["scope_all", "scope_agent", "agent_list", "agent_status"])
def test_ui_read_completes_while_agent_writer_holds_row(agent_database, monkeypatch, reader):
    connect, agent = agent_database
    with connect() as writer, connect() as reader_conn:
        writer.execute("update sli_agents set status='disabled' where id=%s", (agent,))
        # The update's row lock is held until explicit commit below. A locking
        # read would fail at lock_timeout, not be rescued by early release.
        status = _read(reader_conn, agent, reader, monkeypatch)
        if reader.startswith("agent_"):
            assert status == "active"  # Last committed state, not dirty data.
        writer.commit()
        status = _read(reader_conn, agent, reader, monkeypatch)
        if reader.startswith("agent_"):
            assert status == "disabled"  # READ COMMITTED observes the change.
        assert reader_conn.execute("select status from sli_agents where id=%s", (agent,)).fetchone()["status"] == "disabled"


@pytest.mark.parametrize("reader", ["scope_all", "scope_agent", "agent_list", "agent_status"])
def test_ui_read_transaction_does_not_hold_agent_row(agent_database, monkeypatch, reader):
    connect, agent = agent_database
    with connect() as reader_conn, connect() as writer:
        _read(reader_conn, agent, reader, monkeypatch)
        # No reader commit/rollback yet: a row lock taken by the actual adapter
        # would block this independent lifecycle update and fail in 500 ms.
        writer.execute("update sli_agents set status='disabled' where id=%s", (agent,))
        writer.commit()
        assert reader_conn.execute("select status from sli_agents where id=%s", (agent,)).fetchone()["status"] == "disabled"

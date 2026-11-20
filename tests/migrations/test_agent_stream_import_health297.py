"""Migration 297: exact transactional import facts, including late replay."""
import os
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from server.sli.sources.collection_packet_import import consume_agent_packets
from tests.reporting.test_agent_collection_query_plan_postgres import (
    AGENT,
    MIGRATION,
    WANTED,
    migrate,
    read,
)
from tests.reporting.test_agent_collection_query_plan_postgres import (
    database as database,  # noqa: PLC0414 -- pytest fixture registration
)

pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]

ROLLBACK = MIGRATION.with_suffix(".rollback.sql")


def test_apply_pending_accepts_health_migration_after_applied_296(database):
    import psycopg

    from deploy.linux.migrate import apply_pending
    from scripts.maintenance.existing_postgres_bootstrap import (
        forward_migration_inventory,
    )

    database.execute("insert into schema_migrations values(296,'agent_runtime_switch')")
    seed(database, 1, imported="2026-01-03")
    migration = next(item for item in forward_migration_inventory(MIGRATION.parent)
                     if item.name == "agent_stream_import_health")
    expected = {286: "sigma_rule_labels", 296: "agent_runtime_switch",
                migration.version: "agent_stream_import_health"}
    with psycopg.connect(os.environ["ADLOG_TEST_PG_DSN"], autocommit=True) as connection:
        def execute(paths):
            for path in paths:
                connection.execute(path.read_text(encoding="utf-8"))

        apply_pending(connection, [migration], expected, execute, baseline_version=296)
        assert connection.execute("select version,name from schema_migrations order by version").fetchall() == [
            (286, "sigma_rule_labels"), (296, "agent_runtime_switch"), (297, "agent_stream_import_health")]
    assert read(database, [WANTED])[0]["last_import_at"] == datetime(2026, 1, 3, tzinfo=UTC)
    database.execute(ROLLBACK.read_text(encoding="utf-8"))
    assert database.execute("select name from schema_migrations where version=296").fetchone()["name"] == "agent_runtime_switch"
    assert database.execute("select count(*) as n from sli_agent_packet_inbox").fetchone()["n"] == 1


@pytest.mark.parametrize("predecessors", [(), (287,), (287, 288), (287, 288, 289), (296,)])
def test_forward_rollback_and_reapply_preserve_intervening_markers(database, predecessors):
    # Isolate 297's ledger admission from the unrelated PRs' schema changes.
    # Never apply the whole migration directory: it will grow in main.
    for version in predecessors:
        database.execute("insert into schema_migrations values(%s,'synthetic_predecessor')", (version,))
    before = database.execute("select * from schema_migrations order by version").fetchall()
    packet = seed(database, 1, imported="2026-01-03")
    migrate(database)
    assert read(database, [WANTED])[0]["last_import_at"] == datetime(2026, 1, 3, tzinfo=UTC)
    database.execute(ROLLBACK.read_text(encoding="utf-8"))
    assert database.execute("select to_regclass('public.sli_agent_stream_import_health') as name").fetchone()["name"] is None
    assert database.execute("select to_regprocedure('public.record_agent_stream_import_v297()') as name").fetchone()["name"] is None
    assert database.execute("select count(*) as n from pg_trigger where tgname='sli_agent_stream_import_health_write'").fetchone()["n"] == 0
    assert database.execute("select * from schema_migrations order by version").fetchall() == before
    # Inbox/history survive rollback; writes and reapplication still work.
    database.execute("update sli_agent_packet_inbox set imported_at='2026-01-04' where packet_id=%s", (packet,))
    migrate(database)
    assert read(database, [WANTED])[0]["last_import_at"] == datetime(2026, 1, 4, tzinfo=UTC)


@pytest.mark.parametrize("change", ["missing", "wrong_name", "future", "runtime"])
def test_rollback_rejects_invalid_ledger_or_caller_without_dropping_objects(database, change):
    import psycopg

    seed(database, 1, imported="2026-01-03")
    migrate(database)
    if change == "missing":
        database.execute("delete from schema_migrations where version=297")
    elif change == "wrong_name":
        database.execute("update schema_migrations set name='foreign_marker' where version=297")
    elif change == "future":
        database.execute("insert into schema_migrations values(298,'synthetic_future')")
    before = database.execute("select * from schema_migrations order by version").fetchall()
    rollback_sql = ROLLBACK.read_text(encoding="utf-8")
    try:
        if change == "runtime":
            # Reach the membership guard even if an installation exposes ledger reads.
            database.execute("grant select on schema_migrations to adlog_user")
            # session_user, not just current_role, must be unprivileged.
            database.execute("set session authorization adlog_user")
        with pytest.raises(psycopg.errors.RaiseException, match="migration 297 rollback prerequisites failed"):
            database.execute(rollback_sql)
    finally:
        database.execute("rollback")
        database.execute("reset session authorization")
    assert database.execute("select * from schema_migrations order by version").fetchall() == before
    # The trigger and its function must remain usable after rejection.
    seed(database, 2, imported="2026-01-04")
    assert read(database, [WANTED])[0]["last_import_at"] == datetime(2026, 1, 4, tzinfo=UTC)


def seed(database, sequence, *, revision="2", channel="Security", imported=None):
    packet = uuid4()
    database.execute("insert into sli_agent_receipts values(%s,%s,%s,%s,'2025-01-01'::timestamptz+%s*interval '1 second')",
                     (AGENT, WANTED["module_id"], sequence, packet, sequence))
    database.execute("""insert into sli_agent_packet_inbox
        (packet_id,imported_at,collection_revision,collection_channel,collection_read_error,packet,received_at)
        values(%s,%s,%s,%s,false,'{}','2025-01-01'::timestamptz+%s*interval '1 second')""",
                     (packet, imported, revision, channel, sequence))
    return packet


def test_backfill_keeps_exact_maximum_and_null_channels_separate(database):
    seed(database, 1, imported="2026-01-03")
    seed(database, 2, imported="2026-01-02")  # receipt order != import order
    seed(database, 3, channel=None, imported="2026-01-04")
    seed(database, 4, revision="old", imported="2026-01-05")
    seed(database, 5)
    rows = read(database, [WANTED, {**WANTED, "channel": None}])
    assert {row["channel"]: row["last_import_at"] for row in rows} == {
        "Security": datetime(2026, 1, 3, tzinfo=UTC),
        None: datetime(2026, 1, 4, tzinfo=UTC)}
    assert database.execute("select count(*) as n from sli_agent_stream_import_health").fetchone()["n"] == 3
    seed(database, 6, channel=None, imported="2026-01-02")
    assert database.execute("select count(*) as n from sli_agent_stream_import_health").fetchone()["n"] == 3
    assert read(database, [{**WANTED, "channel": None}])[0]["last_import_at"] == datetime(2026, 1, 4, tzinfo=UTC)


def test_importer_late_replay_and_rollback_update_fact_atomically(database):
    old = seed(database, 1)
    seed(database, 2, imported="2026-01-02")
    migrate(database)
    # These columns are real importer inputs, unnecessary for the health reads.
    database.execute("""alter table sli_agent_packet_inbox
        add column envelope jsonb not null default '{}',
        add column event_rows jsonb not null default '[]'""")
    with pytest.raises(RuntimeError, match="sink rollback"), database.transaction():
        assert consume_agent_packets(database, import_rows=lambda *a, **kw: None) == 1
        progress = database.execute("select imported_at from sli_agent_packet_inbox where packet_id=%s", (old,)).fetchone()["imported_at"]
        assert read(database, [WANTED])[0]["last_import_at"] == progress
        raise RuntimeError("sink rollback")
    assert read(database, [WANTED])[0]["last_import_at"] == datetime(2026, 1, 2, tzinfo=UTC)
    assert database.execute("select imported_at from sli_agent_packet_inbox where packet_id=%s", (old,)).fetchone()["imported_at"] is None
    # Deferred old input imported long after newer receipts must advance the exact fact.
    assert consume_agent_packets(database, import_rows=lambda *a, **kw: None) == 1
    imported = database.execute("select imported_at from sli_agent_packet_inbox where packet_id=%s", (old,)).fetchone()["imported_at"]
    assert read(database, [WANTED])[0]["last_import_at"] == imported
    # A later writer with an earlier timestamp cannot move the maximum backwards.
    seed(database, 3, imported="2026-01-01")
    assert read(database, [WANTED])[0]["last_import_at"] == imported


def test_runtime_can_read_and_import_but_cannot_forge_summary(database):
    packet = seed(database, 1, channel=None)
    migrate(database)
    database.execute("set role adlog_user")
    try:
        database.execute("update sli_agent_packet_inbox set imported_at='2026-01-06' where packet_id=%s", (packet,))
        result = database.execute("select last_import_at from sli_agent_stream_import_health").fetchone()
        assert result["last_import_at"] == datetime(2026, 1, 6, tzinfo=UTC)
        psycopg = pytest.importorskip("psycopg")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            database.execute("update sli_agent_stream_import_health set last_import_at=now()")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            database.execute("select public.record_agent_stream_import_v297()")
    finally:
        database.execute("reset role")


def test_bounded_read_jit_option_is_local_and_connection_is_closed(database, monkeypatch):
    import psycopg
    from psycopg.rows import dict_row

    from server.sli.core import postgres_runtime_pipeline
    from server.sli.core.database import query_rows_bounded

    opened = []

    def connect():
        connection = psycopg.connect(os.environ["ADLOG_TEST_PG_DSN"], row_factory=dict_row, options="-c jit=on")
        opened.append(connection)
        return connection

    monkeypatch.setattr(postgres_runtime_pipeline, "connect", connect)
    assert query_rows_bounded("select current_setting('jit') as jit", jit=False) == [{"jit": "off"}]
    assert query_rows_bounded("select current_setting('jit') as jit") == [{"jit": "on"}]
    assert all(connection.closed for connection in opened)


def test_concurrent_imports_of_same_null_channel_preserve_maximum(database):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    import psycopg

    packets = [seed(database, n, channel=None) for n in (1, 2)]
    migrate(database)
    ready = Barrier(2)

    def import_one(packet, timestamp):
        with psycopg.connect(os.environ["ADLOG_TEST_PG_DSN"]) as connection:
            connection.execute("set local role adlog_user")
            connection.execute("set local lock_timeout='5s'")
            ready.wait(timeout=5)
            connection.execute("update sli_agent_packet_inbox set imported_at=%s where packet_id=%s", (timestamp, packet))

    with ThreadPoolExecutor(max_workers=2) as workers:
        futures = [workers.submit(import_one, packet, timestamp) for packet, timestamp in
                   zip(packets, ("2026-01-03T00:00:00Z", "2026-01-01T00:00:00Z"), strict=True)]
        for future in futures:
            future.result(timeout=10)
    assert read(database, [{**WANTED, "channel": None}])[0]["last_import_at"] == datetime(2026, 1, 3, tzinfo=UTC)
    assert database.execute("select count(*) as n from sli_agent_stream_import_health").fetchone()["n"] == 1

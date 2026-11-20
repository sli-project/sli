"""Requested stream SQL on disposable PostgreSQL; no stand latency claim."""
import json
import os
from datetime import datetime
from pathlib import Path
from uuid import uuid4

import pytest

from server.sli.agents.collection_health import _STREAMS_SQL
from server.sli.core.database import _pg_sql
from tests.postgres_integration_guard import assert_disposable_database

pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]
AGENT = "00000000-0000-4000-8000-000000000001"
WANTED = {"agent_id": AGENT, "module_id": "sli.windows.ad-dc", "revision": "2",
          "channel": "Security", "snapshot": False}
MIGRATION = Path(__file__).resolve().parents[2] / "config/postgres_migrations/297_agent_stream_import_health.sql"


def migrate(database):
    if database.execute("select to_regclass('public.sli_agent_stream_import_health') as name").fetchone()["name"] is None:
        database.execute(MIGRATION.read_text(encoding="utf-8"))


@pytest.fixture
def database():
    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row
    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("Disposable PostgreSQL required")
    with psycopg.connect(dsn, autocommit=True, row_factory=dict_row) as conn:
        assert_disposable_database(conn)
        conn.execute("set timezone='UTC'")
        conn.execute("set statement_timeout='120s'")
        conn.execute("""
            grant usage,create on schema public to adlog_storage_owner;
            set role adlog_storage_owner;
            create table schema_migrations(version integer primary key,name text);
            insert into schema_migrations values(286,'sigma_rule_labels');
            create table sli_agent_receipts(
                agent_id uuid not null,module_id text not null,sequence bigint not null,
                packet_id uuid not null unique,received_at timestamptz not null,
                primary key(agent_id,module_id,sequence));
            create table sli_agent_packet_inbox(
                packet_id uuid primary key,imported_at timestamptz,collection_revision text,
                collection_channel text,collection_read_error boolean,packet jsonb,
                received_at timestamptz not null default now());
            create table sli_agent_packet_quarantine(
                packet_id uuid primary key,reason_code text not null,quarantined_at timestamptz not null);
            create table sli_agent_snapshot_cycles(
                agent_id uuid,module_id text,policy jsonb,created_at timestamptz,
                completed_at timestamptz,published_at timestamptz,publication_state text);
            create index sli_agent_receipts_collection_health
                on sli_agent_receipts(agent_id,received_at desc) include(packet_id,module_id,sequence);
            create index sli_agent_receipts_module_received
                on sli_agent_receipts(module_id,received_at desc) include(packet_id);
            create index sli_agent_inbox_collection_health on sli_agent_packet_inbox(packet_id)
                include(collection_revision,collection_channel,collection_read_error,imported_at);
            create index sli_agent_inbox_imported_prefix
                on sli_agent_packet_inbox(imported_at desc,packet_id) where imported_at is not null;
            create index sli_agent_packet_inbox_pending
                on sli_agent_packet_inbox(received_at,packet_id) where imported_at is null;
            grant select,insert on sli_agent_receipts,sli_agent_packet_inbox to adlog_user;
            grant update(imported_at) on sli_agent_packet_inbox to adlog_user;
            reset role;
        """)
        yield conn


def read(database, requested):
    migrate(database)
    return database.execute(_pg_sql(_STREAMS_SQL), (json.dumps(requested),)).fetchall()


@pytest.mark.parametrize("samples,expected", [
    ([("1960-01-01T00:00:00.000001+00:00", 1, True),
      ("1960-01-01T00:00:00.000002+00:00", 2, False)], False),
    ([("2026-01-01T00:00:00+00:00", 9223372036854775806, True),
      ("2026-01-01T00:00:00+00:00", 9223372036854775807, False)], False),
    ([("2026-01-01T00:00:00+00:00", 1, True),
      ("2026-01-01T00:00:00+00:00", 2, None)], None),
])
def test_latest_receipt_keeps_microsecond_bigint_and_nullable_flag_order(database, samples, expected):
    for received, sequence, flag in samples:
        packet = uuid4()
        database.execute("insert into sli_agent_receipts values(%s,'sli.windows.ad-dc',%s,%s,%s)",
                         (AGENT, sequence, packet, datetime.fromisoformat(received)))
        database.execute("insert into sli_agent_packet_inbox values(%s,%s,'2','Security',%s,'{}')",
                         (packet, datetime.fromisoformat(received), flag))
    rows = read(database, [WANTED])
    assert len(rows) == 1 and rows[0]["read_error"] is expected
    assert rows[0]["last_packet_at"] == datetime.fromisoformat(samples[-1][0])
    assert rows[0]["pending_since"] is None


def test_current_revisions_keep_old_live_backlog_and_terminal_conflicts_separate(database):
    database.execute("""
        insert into sli_agent_receipts
        select '00000000-0000-4000-8000-000000000001'::uuid,'sli.windows.ad-dc',n,md5(n::text)::uuid,
               now() - case n when 2 then interval '30 days' when 3 then interval '40 days'
                              else interval '1 minute' end
        from generate_series(1,5) n;
        insert into sli_agent_packet_inbox
        select packet_id,case when sequence in (2,3) then null else received_at end,
               case when sequence=4 then '9' else '2' end,
               case when sequence=5 then 'System' else 'Security' end,
               sequence in (4,5),'{}'::jsonb from sli_agent_receipts;
        insert into sli_agent_packet_quarantine
        select packet_id,'source_event_allocation_hash_mismatch',received_at
        from sli_agent_receipts where sequence=3;
        insert into sli_agent_snapshot_cycles values
            ('00000000-0000-4000-8000-000000000001','sli.ad-snapshot','{"policy_revision":"1"}',
             '2025-01-01',null,null,'pending'),
            ('00000000-0000-4000-8000-000000000001','sli.ad-snapshot','{"policy_revision":"2"}',
             '2025-02-01','2025-02-02','2025-02-03','published');
    """)
    snapshot = {**WANTED, "module_id": "sli.ad-snapshot", "channel": None, "snapshot": True}
    rows = read(database, [WANTED, snapshot])
    assert len(rows) == 2 and all(row["revision"] == "2" for row in rows)
    event = next(row for row in rows if row["module_id"] == "sli.windows.ad-dc")
    pending = database.execute("select received_at from sli_agent_receipts where sequence=2").fetchone()
    assert event["pending_since"] == pending["received_at"]
    assert event["historical_unimported_packets"] == 1 and event["historical_error_at"] is not None
    assert event["read_error"] is False
    snap = next(row for row in rows if row["module_id"] == "sli.ad-snapshot")
    assert snap["pending_since"] is None and snap["last_import_at"] is not None
    empty = read(database, [{**WANTED, "revision": "missing"}])[0]
    assert empty["last_packet_at"] is empty["last_import_at"] is empty["pending_since"] is None


def test_unassigned_history_does_not_expand_the_requested_result(database):
    database.execute("""
        insert into sli_agent_receipts
        select '00000000-0000-4000-8000-000000000002'::uuid,'sli.windows.ad-dc',n,
               md5(n::text)::uuid,'2025-01-01'::timestamptz+n*interval '1 second'
        from generate_series(1,40000) n;
        insert into sli_agent_packet_inbox
        select packet_id,received_at,'1','Security',false,'{}'::jsonb from sli_agent_receipts;
        analyze sli_agent_receipts;
        analyze sli_agent_packet_inbox;
    """)
    rows = read(database, [WANTED])
    assert len(rows) == 1 and rows[0]["agent_id"] == AGENT and rows[0]["last_packet_at"] is None
    plan = database.execute("explain (analyze,buffers,format json) " + _pg_sql(_STREAMS_SQL),
                             (json.dumps([WANTED]),)).fetchone()["QUERY PLAN"][0]
    assert plan["Plan"]["Actual Rows"] == 1
    print("T092 requested stream query: " + json.dumps({"unassigned_history": 40000,
          "requested_streams": 1, "execution_ms": plan["Execution Time"], "scope": "synthetic, not stand latency"}))


def _nodes(node):
    yield node
    for child in node.get("Plans", []):
        yield from _nodes(child)


@pytest.mark.parametrize("analyze", [False, True], ids=["stale-statistics", "analyzed"])
def test_large_history_preserves_stream_facts_without_global_import_scan(database, analyze):
    # Four agent/module pairs, 265k receipts EACH, matching the stand skew.
    # The first sample supplies stale column statistics for the second batch.
    for start, end in ((1, 30000), (30001, 1060000)):
        database.execute("""
            insert into sli_agent_receipts
            select md5('agent-' || (n %% 2)::text)::uuid,
                   (array['sli.windows.ad-dc','sli.file-audit'])[1 + (n / 2) %% 2],
                   n,md5('history-' || n::text)::uuid,'2026-01-01'::timestamptz + n * interval '1 second'
            from generate_series(%s::integer,%s::integer) n
        """, (start, end))
        database.execute("""
            insert into sli_agent_packet_inbox
            select packet_id,received_at,'old','Security',false,'{}'::jsonb from sli_agent_receipts
            where sequence between %s and %s
        """, (start, end))
        if start == 1:
            database.execute("analyze sli_agent_receipts")
            database.execute("analyze sli_agent_packet_inbox")
    agents = [str(database.execute("select md5('agent-' || %s::text)::uuid as id", (n,)).fetchone()["id"])
              for n in range(2)]
    requested = [{**WANTED, "agent_id": agent, "module_id": module}
                 for agent in agents
                 for module in ("sli.windows.ad-dc", "sli.file-audit")]
    # Multiple requested channels share the same agent/module receipt history.
    requested = [{**wanted, "channel": channel} for wanted in requested
                 for channel in ("Security", "System", "Application", None)]
    requested += [{**WANTED, "agent_id": agent, "module_id": "sli.ad-snapshot", "channel": None, "snapshot": True}
                  for agent in agents]
    for number, wanted in enumerate(requested[:-2]):
        for sequence, age, imported_age, flag in (
            (2000001, "30 days", None, False),  # historical terminal quarantine
            (2000002, "20 days", None, False),  # live backlog: never truncate history
            (2000003, "1 minute", "2 hours", False),
            (2000004, "2 minutes", "1 hour", True),  # latest import != latest receipt
            (2000005, "10 days", None, False),  # non-terminal quarantine
            (2000006, "6 days", None, False),  # recent terminal still blocks import
        ):
            packet = uuid4()
            database.execute("""insert into sli_agent_receipts values(%s,%s,%s,%s,now()-%s::interval)""",
                             (wanted["agent_id"], wanted["module_id"], sequence + number * 10, packet, age))
            database.execute("""insert into sli_agent_packet_inbox values(
                %s,now()-%s::interval,%s,%s,%s,'{"context":{"read_error":"file_audit_read_failed"}}')""",
                             (packet, imported_age, wanted["revision"], wanted["channel"], flag))
            if sequence in (2000001, 2000005, 2000006):
                reason = "other" if sequence == 2000005 else (
                    "source_event_allocation_hash_mismatch" if number % 2 else "published_source_event_hash_mismatch")
                database.execute("insert into sli_agent_packet_quarantine values(%s,%s,now()-%s::interval)",
                                 (packet, reason, age))
    database.execute("""insert into sli_agent_snapshot_cycles values
        (%s,'sli.ad-snapshot','{"policy_revision":"2"}','2025-01-01',null,null,'pending'),
        (%s,'sli.ad-snapshot','{"policy_revision":"2"}','2025-02-01','2025-02-02','2025-02-03','published')
    """, (agents[0], agents[0]))
    migrate(database)  # real migration backfills the full history once, outside the read
    # Retain column statistics from the first 30k rows, then also test fresh
    # statistics. VACUUM updates visibility/row counts, but not column statistics.
    for table in ("sli_agent_receipts", "sli_agent_packet_inbox", "sli_agent_packet_quarantine"):
        database.execute(f"vacuum {table}")
        if analyze:
            database.execute(f"analyze {table}")
    baseline = Path(__file__).with_name("sql").joinpath("agent_collection_streams_before_t108.sql").read_text(encoding="utf-8")
    params = (json.dumps(requested),)
    with database.transaction():
        # Stable now() for both complete result sets, including quarantine age.
        database.execute("set local statement_timeout='120s'")
        database.execute("set local jit=off")
        expected = database.execute(_pg_sql(baseline), params).fetchall()
        database.execute("set local statement_timeout='3s'")
        actual = read(database, requested)
        sort_key = lambda row: tuple(str(row[key]) for key in ("agent_id", "module_id", "revision", "channel"))
        assert sorted(actual, key=sort_key) == sorted(expected, key=sort_key)
        assert len(actual) == 18
        event = next(row for row in actual if row["agent_id"] == agents[0]
                     and row["module_id"] == "sli.windows.ad-dc" and row["channel"] == "Security")
        # An older receipt imported later must supply last_import_at.
        imported = database.execute("""select i.imported_at from sli_agent_packet_inbox i
            join sli_agent_receipts r using(packet_id) where r.agent_id=%s
            and r.module_id='sli.windows.ad-dc' and r.sequence=2000004""", (agents[0],)).fetchone()
        assert event["last_import_at"] == imported["imported_at"]
        assert event["historical_unimported_packets"] == 1
        assert event["pending_since"] < event["last_packet_at"]
        plan = database.execute("explain (analyze,buffers,format json) " + _pg_sql(_STREAMS_SQL),
                                params).fetchone()["QUERY PLAN"][0]
    nodes = list(_nodes(plan["Plan"]))
    assert not any(node.get("Index Name") == "sli_agent_inbox_imported_prefix" for node in nodes)
    assert not any(node.get("Alias") in ("import_packet", "import_receipt") for node in nodes)
    assert any(node.get("Relation Name") == "sli_agent_stream_import_health" for node in nodes)
    # All receipt reads (latest and pending included) must stay far below history size.
    for node in nodes:
        if node.get("Relation Name") in ("sli_agent_receipts", "sli_agent_packet_inbox"):
            examined = node["Actual Rows"] + node.get("Rows Removed by Filter", 0)
            assert examined * node["Actual Loops"] < 5000, node
    assert "JIT" not in plan
    assert plan["Execution Time"] < 300
    buffers = sum(plan["Plan"].get(key, 0) for key in (
        "Shared Hit Blocks", "Shared Read Blocks", "Local Hit Blocks", "Local Read Blocks"))
    assert buffers < 20000
    print("T108 stream imports: " + json.dumps({
        "history_rows": 1060000, "receipts_per_pair": 265000,
        "streams": len(requested), "analyzed": analyze,
        "execution_ms": plan["Execution Time"], "buffers": buffers,
        "scope": "synthetic, not stand latency",
    }))



def test_legacy_station_name_uses_four_indexed_lookups_not_observation_scan(database):
    from server.sli.plugins.workstations.reports import _EVENT_NAMES_SQL
    database.execute("""
        create schema sli_plugin_workstations;
        create table sli_plugin_workstations.observations(
            id text primary key,agent_key text,family text,observed_at timestamptz,source_xml text);
        create index workstation_report_window
            on sli_plugin_workstations.observations(agent_key,family,observed_at,id);
        insert into sli_plugin_workstations.observations
        select md5(n::text||family),'fixture-agent',family,
               '2026-01-01'::timestamptz+n*interval '1 second','<Event/>'
        from generate_series(1,40000) n
        cross join (values ('logons'),('processes'),('usb'),('protection')) f(family);
        analyze sli_plugin_workstations.observations;
    """)
    rows = database.execute(_EVENT_NAMES_SQL, (["fixture-agent"],)).fetchall()
    assert len(rows) == 4
    plan = database.execute("explain (analyze,buffers,format json) " + _EVENT_NAMES_SQL,
                            (["fixture-agent"],)).fetchone()["QUERY PLAN"][0]
    lookups = [node for node in _nodes(plan["Plan"]) if node.get("Relation Name") == "observations"]
    assert lookups and all(node["Index Name"] == "workstation_report_window" for node in lookups)
    assert sum(node["Actual Rows"] * node["Actual Loops"] for node in lookups) == 4
    print("T114e station names: " + json.dumps({"history_rows": 160000,
          "event_rows_read": 4, "execution_ms": plan["Execution Time"], "scope": "synthetic"}))

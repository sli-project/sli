"""Actual PostgreSQL discovery boundaries, empty packets and migration guards."""
import json
from pathlib import Path
from uuid import uuid4

import pytest

from tests.migrations.test_qw_finding_notifications_migration229 import publication_pg as publication_pg

from tests.migrations.test_default_native_detections_migration262 import defaults_pg as defaults_pg
from tests.migrations.test_qw_semantic_input_migration228 import pg as pg

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "config/postgres_migrations/263_native_source_lookup_index.sql"
AGENT = "00000000-0000-0000-0000-000000000003"
OTHER_AGENT = "00000000-0000-0000-0000-000000000007"
MODULE = "sli.windows.ad-dc"


@pytest.fixture
def discovery_pg(defaults_pg):
    import psycopg
    from psycopg import sql

    login = "sli_discovery_" + uuid4().hex
    with psycopg.connect(defaults_pg, autocommit=True) as conn:
        # Missing migration deliberately leaves 262 installed for the RED run.
        if MIGRATION.exists():
            conn.execute(MIGRATION.read_text("utf-8"))
        conn.execute(sql.SQL("create role {} login").format(sql.Identifier(login)))
        conn.execute(sql.SQL("grant adlog_semantic_worker to {}").format(sql.Identifier(login)))
        conn.execute("insert into sli_agents values(%s,'active',%s::jsonb)",
                     (AGENT, json.dumps([{"module_id": MODULE, "enabled": True}])))
        conn.execute("insert into sli_agent_module_bindings values(%s,%s,'fixture-source')", (AGENT, MODULE))
    yield defaults_pg, login
    with psycopg.connect(defaults_pg, autocommit=True) as conn:
        conn.execute(sql.SQL("drop role {}").format(sql.Identifier(login)))


def packet(conn, sequence, *, generation="generation-1", source="fixture-source", agent=AGENT,
           module=MODULE, event=True, committed=True, imported=True, tampered=False,
           channel="Security", log_source_id=3):
    packet_id = str(uuid4())
    envelope = {"source_instance_id": source, "generation": generation}
    inbox_envelope = envelope | ({"tampered": True} if tampered else {})
    conn.execute("insert into sli_agent_receipts values(%s,%s,%s,%s::jsonb,%s::jsonb,%s)",
                 (packet_id, agent, module, json.dumps(envelope),
                  json.dumps({"status": "committed" if committed else "pending"}), sequence))
    conn.execute("insert into sli_agent_packet_inbox values(%s,%s::jsonb,%s::jsonb,%s::jsonb,%s)",
                 (packet_id, json.dumps(inbox_envelope), json.dumps({"header": {"channel": channel}}), json.dumps([{}] if event else []),
                  "2026-10-01T00:00:00Z" if imported else None))
    if event:
        event_id = conn.execute("select coalesce(max(id),0)+1 from events_v2_core").fetchone()[0]
        conn.execute("insert into raw_log_files values(%s,%s)", (event_id, "agent-packet:" + packet_id))
        conn.execute("insert into events_v2_core(id,log_source_id,raw_log_file_id) values(%s,%s,%s)",
                     (event_id, log_source_id, event_id))


def sources(conn, login):
    from psycopg import sql

    conn.execute(sql.SQL("set session authorization {}").format(sql.Identifier(login)))
    try:
        conn.execute("set role adlog_semantic_worker")
        return [row[0] for row in conn.execute("select source from default_detection_sources()")]
    finally:
        conn.execute("reset session authorization; reset role")


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_latest_empty_does_not_hide_same_generation_core_source(discovery_pg):
    import psycopg

    dsn, login = discovery_pg
    with psycopg.connect(dsn, autocommit=True) as conn:
        packet(conn, 1)
        packet(conn, 2, event=False)
        found = sources(conn, login)
        assert len(found) == 1
        assert found[0]["scope"]["source_generation"] == "generation-1"
        assert sources(conn, login) == found


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
@pytest.mark.parametrize("bad_witness", [
    {"generation": "generation-old"}, {"source": "other-source"}, {"agent": OTHER_AGENT},
    {"module": "sli.vpn-nps"}, {"committed": False}, {"imported": False}, {"tampered": True},
])
def test_witness_cannot_cross_scope_or_receipt_attestation(discovery_pg, bad_witness):
    import psycopg

    dsn, login = discovery_pg
    with psycopg.connect(dsn, autocommit=True) as conn:
        packet(conn, 1, **bad_witness)
        packet(conn, 2, event=False)
        assert sources(conn, login) == []
        assert conn.execute("select count(*) from finding_evidence_source_bindings").fetchone()[0] == 0


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
@pytest.mark.parametrize("transition", ["generation", "source_instance"])
def test_old_binding_not_returned_after_scope_transition(discovery_pg, transition):
    import psycopg

    dsn, login = discovery_pg
    with psycopg.connect(dsn, autocommit=True) as conn:
        packet(conn, 1)
        assert len(sources(conn, login)) == 1
        if transition == "generation":
            packet(conn, 2, generation="generation-2", event=False)
        else:
            conn.execute("update sli_agent_module_bindings set source_instance_id='replacement-source'")
            packet(conn, 2, source="replacement-source", event=False)
        assert sources(conn, login) == []
        # Historical binding is retained, but no longer grants live discovery.
        assert conn.execute("select count(*) from finding_evidence_source_bindings").fetchone()[0] == 1


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_witness_outside_receipt_bound_fails_closed(discovery_pg):
    import psycopg

    dsn, login = discovery_pg
    with psycopg.connect(dsn, autocommit=True) as conn:
        packet(conn, 1)
        for sequence in range(2, 130):
            packet(conn, sequence, event=False)
        assert sources(conn, login) == []
        packet(conn, 130)
        assert len(sources(conn, login)) == 1


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_migration_creates_packet_lookup_index_and_preserves_worker_acl(discovery_pg):
    import psycopg
    from psycopg import sql

    dsn, login = discovery_pg
    with psycopg.connect(dsn, autocommit=True) as conn:
        assert conn.execute("select name from schema_migrations where version=263").fetchone() == ("native_source_lookup_index",)
        assert conn.execute("select indexdef from pg_indexes where indexname='events_v2_core_raw_packet_lookup'").fetchone()[0].endswith(
            "USING btree (raw_log_file_id, id) INCLUDE (log_source_id)")
        with pytest.raises(psycopg.errors.RaiseException, match="migration 263 prerequisites failed"):
            conn.execute(MIGRATION.read_text("utf-8"))
        conn.execute("rollback")
        conn.execute(sql.SQL("set session authorization {}").format(sql.Identifier(login)))
        try:
            conn.execute("set role adlog_semantic_worker")
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute("update semantic_policy_admission set enabled=false")
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute("select * from finding_evidence_source_bindings")
        finally:
            conn.execute("reset session authorization; reset role")


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_wrong_predecessor_rejects_without_index_or_function_changes(defaults_pg):
    import psycopg

    assert MIGRATION.exists()
    with psycopg.connect(defaults_pg, autocommit=True) as conn:
        before = conn.execute("select pg_get_functiondef('public.default_detection_sources()'::regprocedure)").fetchone()[0]
        conn.execute("update schema_migrations set name='wrong-predecessor' where version=262")
        with pytest.raises(psycopg.errors.RaiseException, match="migration 263 prerequisites failed"):
            conn.execute(MIGRATION.read_text("utf-8"))
        conn.execute("rollback")
        assert conn.execute("select to_regclass('public.events_v2_core_raw_packet_lookup')").fetchone()[0] is None
        assert conn.execute("select pg_get_functiondef('public.default_detection_sources()'::regprocedure)").fetchone()[0] == before

@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_packet_lookup_uses_covering_index_without_core_history_sort(discovery_pg):
    import psycopg

    dsn, _ = discovery_pg
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute("insert into events_v2_core(id,raw_log_file_id,log_source_id) select n,n,3 from generate_series(1,10000) n")
        conn.execute("analyze events_v2_core")
        result = conn.execute("select log_source_id from events_v2_core where raw_log_file_id=9999 order by id limit 1").fetchone()
        assert result == (3,)
        plan = conn.execute("explain(format json) select log_source_id from events_v2_core where raw_log_file_id=9999 order by id limit 1").fetchone()[0]
        nodes = [plan[0]["Plan"]]
        indexes = []
        while nodes:
            node = nodes.pop()
            assert node["Node Type"] != "Sort"
            if "Index Name" in node:
                indexes.append(node["Index Name"])
            nodes.extend(node.get("Plans", []))
        assert indexes == ["events_v2_core_raw_packet_lookup"]


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_same_generation_channel_rotation_keeps_existing_security_source(discovery_pg):
    import psycopg

    dsn, login = discovery_pg
    with psycopg.connect(dsn, autocommit=True) as conn:
        packet(conn, 1)
        initial = sources(conn, login)
        assert len(initial) == 1
        packet(conn, 2, channel="Directory Service", log_source_id=4)
        assert sources(conn, login) == initial
        assert conn.execute("select log_source_id from finding_evidence_source_bindings").fetchall() == [(3,)]


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_initial_selection_uses_security_even_when_latest_event_is_another_channel(discovery_pg):
    import psycopg

    dsn, login = discovery_pg
    with psycopg.connect(dsn, autocommit=True) as conn:
        packet(conn, 1)
        packet(conn, 2, channel="Directory Service", log_source_id=4)
        assert len(sources(conn, login)) == 1
        assert conn.execute("select log_source_id from finding_evidence_source_bindings").fetchall() == [(3,)]


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
@pytest.mark.parametrize("channel", ["Directory Service", "System", None])
def test_unsupported_or_missing_native_channel_cannot_create_security_binding(discovery_pg, channel):
    import psycopg

    dsn, login = discovery_pg
    with psycopg.connect(dsn, autocommit=True) as conn:
        packet(conn, 1, channel=channel, log_source_id=4)
        assert sources(conn, login) == []
        assert conn.execute("select count(*) from finding_evidence_source_bindings").fetchone()[0] == 0


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_retained_binding_requires_its_own_security_witness_inside_tail(discovery_pg):
    import psycopg

    dsn, login = discovery_pg
    with psycopg.connect(dsn, autocommit=True) as conn:
        packet(conn, 1)
        assert len(sources(conn, login)) == 1
        for sequence in range(2, 130):
            packet(conn, sequence, channel="Directory Service", log_source_id=4)
        assert sources(conn, login) == []
        assert conn.execute("select log_source_id from finding_evidence_source_bindings").fetchall() == [(3,)]


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_unsupported_historical_binding_is_never_rewritten_to_security(discovery_pg):
    import psycopg

    dsn, login = discovery_pg
    with psycopg.connect(dsn, autocommit=True) as conn:
        packet(conn, 1)
        assert len(sources(conn, login)) == 1
        # Simulate an older installation's unsupported channel binding.
        conn.execute("update finding_evidence_source_bindings set log_source_id=4")
        packet(conn, 2, channel="Directory Service", log_source_id=4)
        assert sources(conn, login) == []
        assert conn.execute("select log_source_id from finding_evidence_source_bindings").fetchall() == [(4,)]

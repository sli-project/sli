"""Immutable replay uses an admitted count-only read on disposable PostgreSQL."""
from pathlib import Path

import pytest

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory
from tests.migrations.historical_postgres import historical_connection
from tests.migrations.test_file_audit_catalog_revision_migration206 import (
    accepted_file_packet,
    store_historical_file_packet,
)

PATH = Path(__file__).resolve().parents[2] / "config/postgres_migrations/208_file_audit_collection_replay.sql"


def test_replay_migration_is_next_unique_version():
    pairs = [(m.version, m.name) for m in forward_migration_inventory(PATH.parent)]
    position = pairs.index((208, "file_audit_collection_replay"))
    assert pairs[position - 1] == (207, "agent_packet_projection_recovery")
    assert len(pairs) == len({version for version, _ in pairs})


@pytest.mark.postgres_integration
@pytest.mark.postgres_owned_cluster
def test_replay_keeps_native_publication_and_denies_unadmitted_reads(tmp_path, monkeypatch):
    import psycopg
    from psycopg.rows import dict_row
    from psycopg.types.json import Jsonb

    from tools.e2e.scenario import file_cohort_action_ids, file_cohort_evidence_counts

    with historical_connection(tmp_path, monkeypatch, (207, "agent_packet_projection_recovery")) as conn:
        conn.row_factory = dict_row
        missing = "select to_regprocedure('sli_plugin_file_audit.collection_replay(uuid,uuid)') as routine"
        assert conn.execute(missing).fetchone()["routine"] is None
        conn.execute(PATH.read_text("utf-8"))
        assert conn.execute("select name from schema_migrations where version=208").fetchone()["name"] == "file_audit_collection_replay"
        packet = accepted_file_packet(conn)
        identity = packet["agent"], packet["id"]
        replay_sql = "select sli_plugin_file_audit.collection_replay(%s,%s) as data"
        with conn.transaction():
            conn.execute("set local role adlog_user")
            assert conn.execute(replay_sql, identity).fetchone()["data"] is None
        store_historical_file_packet(conn, packet)

        conn.execute("create schema sli_e2e")
        conn.execute("""create table sli_e2e.cohort as select 'file-audit'::text as family,envelope,event_rows
                        from sli_agent_packet_inbox where packet_id=%s""", (packet["id"],))
        assert file_cohort_evidence_counts(conn, "file-audit") == {"facts": 1, "projection": 1}
        action_ids = file_cohort_action_ids(conn, "file-audit")
        assert len(action_ids) == 1
        with conn.transaction(force_rollback=True):
            conn.execute("update sli_e2e.cohort set event_rows='[{\"record_id\":0}]'::jsonb")
            assert file_cohort_evidence_counts(conn, "file-audit") == {"facts": 0, "projection": 0}
            assert file_cohort_action_ids(conn, "file-audit") == set()

        publications_sql = "select * from sli_plugin_file_audit.collection_publications"
        actions_sql = "select * from sli_plugin_file_audit.actions"
        observations_sql = "select normalized from sli_plugin_file_audit.observations"
        published = conn.execute(publications_sql).fetchall()
        actions = conn.execute(actions_sql).fetchall()
        observations = conn.execute(observations_sql).fetchall()
        assert len(published) == len(actions) == len(observations) == 1
        conn.execute("update sli_agent_packet_inbox set imported_at=null where packet_id=%s", (packet["id"],))
        with conn.transaction():
            conn.execute("set local role adlog_user")
            assert conn.execute(replay_sql, identity).fetchone()["data"] == {"observed": 1, "actions": 1}
            with pytest.raises(psycopg.errors.RaiseException, match="file_audit_collection_not_admitted"):
                with conn.transaction():
                    conn.execute(replay_sql, ("00000000-0000-4000-8000-000000000099", packet["id"]))
            conn.execute("select sli_plugin_file_audit.store_collection(%s,%s,%s)",
                         (*identity, Jsonb(packet["projection"])))
            conn.execute("update sli_agent_packet_inbox set imported_at=now() where packet_id=%s", (packet["id"],))

        assert conn.execute(publications_sql).fetchall() == published
        assert conn.execute(actions_sql).fetchall() == actions
        assert conn.execute(observations_sql).fetchall() == observations
        assert file_cohort_action_ids(conn, "file-audit") == action_ids
        assert conn.execute("select has_table_privilege('adlog_user',"
                            "'sli_plugin_file_audit.collection_publications','SELECT') as allowed").fetchone()["allowed"] is False
        with pytest.raises(psycopg.errors.RaiseException, match="file_audit_collection_not_admitted"):
            with conn.transaction():
                conn.execute("set local role adlog_user")
                conn.execute(replay_sql, identity)

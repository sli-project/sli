"""Register file catalogue metadata without bypassing the core trigger."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

import pytest

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory
from tests.migrations.historical_postgres import historical_connection

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/206_file_audit_catalog_revision.sql"


def store_historical_file_packet(conn, packet):
    """The historical transaction writes through the storage trigger and actual projection entry point."""
    from psycopg.types.json import Jsonb

    source = conn.execute("""select r.server_id,s.domain_id,r.log_source_id,c.id as channel_id
                             from raw_log_files r join servers s on s.id=r.server_id
                             join storage_v2_channel c on c.value='Security' where r.id=99001""").fetchone()
    with conn.transaction():
        conn.execute("set local role adlog_storage_worker")
        conn.execute("""insert into events_v2_core(id,raw_log_file_id,server_id,domain_id,log_source_id,
                        event_id,event_record_id,channel_id,time_created_utc,normalized_at,normalized_hash,
                        source_core_sha256,noise_class,noise_catalog_version)
                        values(99001,99001,%s,%s,%s,4663,1,%s,%s,now(),%s,%s,%s,%s)""",
                     (source["server_id"], source["domain_id"], source["log_source_id"], source["channel_id"],
                      packet["stamp"], packet["hash"], packet["hash"], packet["classification"], packet["revision"]))
        conn.execute("set local role adlog_user")
        conn.execute("select sli_plugin_file_audit.store_collection(%s,%s,%s)",
                     (packet["agent"], packet["id"], Jsonb(packet["projection"])))
        conn.execute("update sli_agent_packet_inbox set imported_at=now() where packet_id=%s", (packet["id"],))


def test_catalogue_migration_follows_predecessor_and_versions_are_unique():
    inventory = forward_migration_inventory(PATH.parent)
    pairs = [(item.version, item.name) for item in inventory]
    position = pairs.index((206, "file_audit_catalog_revision"))
    assert position > 0
    assert pairs[position - 1] == (205, "security_event_identity_category")
    assert max(version for version, _ in pairs[:position]) + 1 == 206
    assert len(pairs) == len({version for version, _ in pairs})
    assert inventory[position].path == PATH
    assert list(PATH.parent.glob("206_*.sql")) == [PATH]
    sql = PATH.read_text("utf-8")
    assert "version=205 and name='security_event_identity_category'" in sql
    assert "where version>=206" in sql
    assert "values(206,'file_audit_catalog_revision')" in sql


@pytest.fixture
def predecessor205(tmp_path, monkeypatch):
    from psycopg.rows import dict_row

    with historical_connection(tmp_path, monkeypatch, (205, "security_event_identity_category")) as conn:
        conn.row_factory = dict_row
        yield conn


@pytest.mark.postgres_integration
@pytest.mark.postgres_owned_cluster
def test_registration_preserves_an_existing_catalogue_identity(predecessor205):
    conn = predecessor205
    conn.execute("insert into event_catalog_revisions(version) values('1.0.0')")
    before = conn.execute("select * from event_catalog_revisions order by id").fetchall()
    conn.execute(PATH.read_text("utf-8"))
    assert conn.execute("select * from event_catalog_revisions order by id").fetchall() == before


@pytest.mark.postgres_integration
@pytest.mark.postgres_owned_cluster
def test_registration_refuses_a_missing_admission_trigger(predecessor205):
    import psycopg

    conn = predecessor205
    conn.execute("drop trigger events_v2_core_catalog_revision on events_v2_core")
    with pytest.raises(psycopg.errors.RaiseException, match="migration 206 requires the catalog revision trigger"):
        conn.execute(PATH.read_text("utf-8"))
    conn.rollback()
    assert conn.execute("select count(*) as n from schema_migrations where version=206").fetchone()["n"] == 0

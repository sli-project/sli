import json
import os
from datetime import timedelta
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

import pytest

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory
from server.sli.semantic.semantic_processing import normalize_semantic_source_payload
from server.sli.semantic.semantic_processing_repository import (
    load_semantic_source_event,
)
from server.sli.storage.storage_v2_archive import (
    ArchiveReader,
    InMemoryArchiveManifestStore,
)
from tests.postgres_integration_guard import assert_disposable_database
from tests.semantic.test_semantic_agent_source import evidence

MIGRATION = Path(__file__).resolve().parents[2] / "config/postgres_migrations/190_agent_semantic_source.sql"


def test_migration_has_exact_predecessor_and_unique_version():
    inventory = forward_migration_inventory(MIGRATION.parent)
    pairs = [(item.version, item.name) for item in inventory]
    position = pairs.index((190, "agent_semantic_source"))
    assert pairs[position - 1:position + 1] == [
        (189, "agent_snapshot_publication_health"), (190, "agent_semantic_source"),
    ]
    assert max(version for version, _ in pairs[:position]) + 1 == 190
    assert len(pairs) == len({version for version, _ in pairs})
    assert inventory[position].path == MIGRATION
    assert list(MIGRATION.parent.glob("190_*.sql")) == [MIGRATION]
    sql = MIGRATION.read_text("utf-8")
    assert "version=189 and name='agent_snapshot_publication_health'" in sql
    assert "version>=190" in sql
    assert "values(190,'agent_semantic_source')" in sql


def test_file_source_upgrade_follows_200_without_rewriting_190():
    pairs = [(item.version, item.name) for item in forward_migration_inventory(MIGRATION.parent)]
    index = pairs.index((201, 'file_audit_semantic_source'))
    assert pairs[index - 1] == (200, 'agent_gpo_change_history')


def test_timestamp_precision_upgrade_has_exact_predecessor_and_unique_version():
    inventory = forward_migration_inventory(MIGRATION.parent)
    pairs = [(item.version, item.name) for item in inventory]
    index = pairs.index((203, 'agent_semantic_timestamp_precision'))
    assert pairs[index - 1] == (202, 'agent_gpo_history_expiry_fence')
    assert len(pairs) == len({version for version, _ in pairs})


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
@pytest.mark.parametrize('source_version', [190, 201, 203])
def test_migration_reads_exact_imported_evidence_with_worker_authority(source_version):
    psycopg = pytest.importorskip("psycopg")
    from psycopg import sql
    from psycopg.conninfo import conninfo_to_dict
    from psycopg.rows import dict_row

    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("isolated PostgreSQL DSN is required")
    database = "sli_test_agent_semantic_" + uuid4().hex
    with psycopg.connect(dsn, autocommit=True) as admin:
        assert_disposable_database(admin)
        admin.execute(sql.SQL("create database {}").format(sql.Identifier(database)))
        try:
            parts = conninfo_to_dict(dsn)
            parts["dbname"] = database
            with psycopg.connect(**parts, autocommit=True, row_factory=dict_row) as conn:
                conn.execute("""do $$ begin
                    if to_regrole('adlog_storage_owner') is null then create role adlog_storage_owner nologin; end if;
                    if to_regrole('adlog_semantic_worker') is null then create role adlog_semantic_worker nologin; end if;
                    end $$;
                    grant usage,create on schema public to adlog_storage_owner;
                    set role adlog_storage_owner;
                    create table schema_migrations(version int primary key,name text);
                    insert into schema_migrations values(189,'agent_snapshot_publication_health');
                    create table events_v2_core(id bigint primary key,raw_log_file_id bigint,
                        server_id int,domain_id int,log_source_id int,event_id int,event_record_id bigint,
                        time_created_utc timestamptz,normalized_hash bytea);
                    create table sli_agent_packet_inbox(packet_id uuid primary key,envelope jsonb,
                        packet jsonb,event_rows jsonb,imported_at timestamptz);
                    create table sli_agent_receipts(packet_id uuid primary key,module_id text,
                        envelope jsonb,receipt jsonb);
                    reset role;
                    create table raw_log_files(id bigint primary key,file_path text);""")
                conn.execute(MIGRATION.read_text("utf-8"))
                if source_version >= 201:
                    conn.execute("insert into schema_migrations values(200,'agent_gpo_change_history')")
                    conn.execute((MIGRATION.parent / '201_file_audit_semantic_source.sql').read_text('utf-8'))
                if source_version >= 203:
                    conn.execute("insert into schema_migrations values(202,'agent_gpo_history_expiry_fence')")
                    conn.execute((MIGRATION.parent / '203_agent_semantic_timestamp_precision.sql').read_text('utf-8'))
                core, row = evidence()
                packet_id = str(uuid4())
                conn.execute("insert into events_v2_core values(7,1,1,2,3,4625,42,%s,%s)",
                             (core["time_created_utc"], core["normalized_hash"]))
                conn.execute("insert into raw_log_files values(1,%s)", ("agent-packet:" + packet_id,))
                packet = {"header": {"source": "fixture-dc", "channel": "Security"}}
                other = {**row, "record_id": 43}
                conn.execute("insert into sli_agent_packet_inbox values(%s,'{}',%s,%s,now())",
                             (packet_id, json.dumps(packet), json.dumps([other, row])))
                conn.execute("insert into sli_agent_receipts values(%s,'sli.windows.ad-dc','{}','{\"status\":\"committed\"}')",
                             (packet_id,))
                assert conn.execute("select has_function_privilege('public','read_agent_semantic_source_v190(bigint)','EXECUTE') as allowed").fetchone()["allowed"] is False
                conn.execute("set role adlog_semantic_worker")
                assert conn.execute("select has_table_privilege(current_user,'sli_agent_packet_inbox','SELECT') as allowed").fetchone()["allowed"] is False
                with conn.cursor() as cur:
                    source = load_semantic_source_event(cur, source_event_id=7, source_identity=core,
                                                        archive=ArchiveReader(InMemoryArchiveManifestStore()))
                assert normalize_semantic_source_payload(source).semantic_type == "authentication.session.failed"
                assert conn.execute("select read_agent_semantic_source_v190(8) as source").fetchone()["source"] is None
                conn.execute("reset role")
                if source_version >= 203:
                    for difference_us, allowed in [(-1, True), (1, True), (-2, False), (2, False)]:
                        timestamp = core['time_created_utc'] + timedelta(microseconds=difference_us)
                        conn.execute('update events_v2_core set time_created_utc=%s', (timestamp,))
                        conn.execute('set role adlog_semantic_worker')
                        assert (conn.execute('select read_agent_semantic_source_v190(7) as source').fetchone()['source'] is not None) is allowed
                        if allowed:
                            with conn.cursor() as cur:
                                source = load_semantic_source_event(cur, source_event_id=7,
                                    source_identity={**core, 'time_created_utc': timestamp},
                                    archive=ArchiveReader(InMemoryArchiveManifestStore()))
                            assert normalize_semantic_source_payload(source).semantic_type == 'authentication.session.failed'
                        conn.execute('reset role')
                    conn.execute('update events_v2_core set time_created_utc=%s', (core['time_created_utc'],))
                    precise_row = {**row, 'time_created': '2026-10-09T00:00:00.502957500Z'}
                    precise_hash = sha256(json.dumps(precise_row, sort_keys=True, ensure_ascii=False).encode()).digest()
                    precise_time = core['time_created_utc'].replace(microsecond=502958)
                    conn.execute('update events_v2_core set time_created_utc=%s,normalized_hash=%s',
                        (precise_time, precise_hash))
                    conn.execute('update sli_agent_packet_inbox set event_rows=%s', (json.dumps([precise_row]),))
                    conn.execute('set role adlog_semantic_worker')
                    with conn.cursor() as cur:
                        source = load_semantic_source_event(cur, source_event_id=7,
                            source_identity={**core, 'time_created_utc': precise_time, 'normalized_hash': precise_hash},
                            archive=ArchiveReader(InMemoryArchiveManifestStore()))
                    assert source['source_event_sha256'] == precise_hash
                    conn.execute('reset role')
                    conn.execute('update events_v2_core set time_created_utc=%s,normalized_hash=%s',
                        (core['time_created_utc'], core['normalized_hash']))
                    conn.execute('update sli_agent_packet_inbox set event_rows=%s', (json.dumps([other, row]),))
                if source_version >= 201:
                    conn.execute("update sli_agent_receipts set module_id='sli.file-audit'")
                    conn.execute('set role adlog_semantic_worker')
                    with conn.cursor() as cur:
                        source = load_semantic_source_event(cur, source_event_id=7, source_identity=core,
                            archive=ArchiveReader(InMemoryArchiveManifestStore()))
                    assert normalize_semantic_source_payload(source).semantic_type == 'authentication.session.failed'
                    conn.execute('reset role')
                    for event_id, channel, allowed in [(4663, 'Security', True), (4728, 'Security', False), (4625, 'System', False)]:
                        conn.execute('update events_v2_core set event_id=%s', (event_id,))
                        changed = {**row, 'event_id': event_id, 'channel': channel}
                        conn.execute('update sli_agent_packet_inbox set event_rows=%s,packet=%s',
                            (json.dumps([changed]), json.dumps({'header': {'source': 'fixture-dc', 'channel': channel}})))
                        conn.execute('set role adlog_semantic_worker')
                        assert (conn.execute('select read_agent_semantic_source_v190(7) as source').fetchone()['source'] is not None) is allowed
                        conn.execute('reset role')
                    conn.execute('update events_v2_core set event_id=4625')
                    conn.execute('update sli_agent_packet_inbox set packet=%s', (json.dumps(packet),))
                    conn.execute("update sli_agent_receipts set module_id='sli.windows.ad-dc'")
                conn.execute("update sli_agent_packet_inbox set event_rows=%s", (json.dumps([row, row]),))
                conn.execute("set role adlog_semantic_worker")
                assert conn.execute("select read_agent_semantic_source_v190(7) as source").fetchone()["source"] is None
                conn.execute("reset role")
                conn.execute("update sli_agent_packet_inbox set event_rows=%s", (json.dumps([other, row]),))
                for change in (
                    "update sli_agent_packet_inbox set imported_at=null",
                    "update sli_agent_packet_inbox set imported_at=now(),envelope='{\"changed\":true}'",
                    "update sli_agent_packet_inbox set envelope='{}'; update sli_agent_receipts set receipt='{\"status\":\"pending\"}'",
                    "update sli_agent_receipts set receipt='{\"status\":\"committed\"}',module_id='other-module'",
                ):
                    conn.execute(change)
                    conn.execute("set role adlog_semantic_worker")
                    assert conn.execute("select read_agent_semantic_source_v190(7) as source").fetchone()["source"] is None
                    conn.execute("reset role")
                assert conn.execute("select name from schema_migrations where version=190").fetchone()["name"] == "agent_semantic_source"
        finally:
            admin.execute(sql.SQL("drop database {} with (force)").format(sql.Identifier(database)))

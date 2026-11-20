import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory
from server.sli.storage import ad_snapshot_change_history as history
from tests.migrations.test_ad_snapshot_history_composition_migration195 import (
    history_database as history_database,  # noqa: PLC0414 -- register shared pytest fixture
)

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / 'config/postgres_migrations/200_agent_gpo_change_history.sql'


def test_forward_inventory_follows_exact_199():
    items = [(x.version, x.name) for x in forward_migration_inventory(PATH.parent)]
    n = items.index((200, 'agent_gpo_change_history'))
    assert items[n - 1] == (199, 'bundled_plugin_defaults')


@pytest.fixture
def gpo_database(history_database):
    c = history_database
    c.execute("""alter table public.gpo_report_v2_source_snapshots
        add column payload_sha256 bytea,add column import_status text default 'completed',add column payload_json jsonb;
        create table public.sli_agent_snapshot_cycles(cycle_id uuid primary key,agent_id uuid,module_id text,
            slot_start_utc timestamptz,policy jsonb,publication_state text,gpo_source_run_id uuid,domain_sid text default 'synthetic');
        create table public.domains(id bigint primary key,domain_sid text,fqdn text);
        insert into public.domains values(1,'synthetic','synthetic.invalid'),(2,'other','other.invalid');
        grant select on public.sli_agent_snapshot_cycles,public.gpo_report_v2_source_snapshots,public.domains to adlog_user;
        insert into public.schema_migrations values(199,'bundled_plugin_defaults');""")
    c.execute(PATH.read_text('utf-8'))
    return c


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_independent_gpo_history_is_guarded_idempotent_and_preserves_gaps(gpo_database, monkeypatch):
    import psycopg
    from psycopg.conninfo import make_conninfo
    from psycopg.rows import dict_row
    from psycopg.types.json import Jsonb

    c = gpo_database
    agent = str(uuid4())
    now = datetime(2026, 10, 11, tzinfo=timezone.utc)
    policy = {'source_instance_id': 'synthetic', 'domain_sid': 'synthetic', 'domain_dns': 'synthetic.invalid', 'scope': 'domain'}
    cycles = []
    for n, state in enumerate(('published', 'published', 'pending', 'published', 'published')):
        cycle, source = str(uuid4()), str(uuid4())
        payload = {'collection_status': 'complete', 'gpos': [], 'links': [
            {'id': 'synthetic-link', 'enabled': bool(n % 2)}]}
        digest = history.canonical_output_sha256(payload)
        selected = policy if n != 4 else {**policy, 'source_instance_id': 'different'}
        # A colliding source UUID in another domain must never be loaded.
        other = {'collection_status':'complete','gpos':[], 'links':[]}
        c.execute('insert into public.gpo_report_v2_source_snapshots values(%s,2,%s,%s,\'completed\',%s)',
                  (source, now + timedelta(hours=n), bytes.fromhex(history.canonical_output_sha256(other)), Jsonb(other)))
        c.execute('insert into public.gpo_report_v2_source_snapshots values(%s,1,%s,%s,\'completed\',%s)',
                  (source, now + timedelta(hours=n), bytes.fromhex(digest), Jsonb(payload)))
        c.execute('insert into public.sli_agent_snapshot_cycles values(%s,%s,\'sli.gpo-snapshot\',%s,%s,%s,%s)',
                  (cycle, agent, now + timedelta(hours=n), Jsonb(selected), state, source))
        cycles.append(cycle)
    batches = []
    monkeypatch.setattr(history, 'publish_batch', lambda port, batch: batches.append(batch))
    dsn = make_conninfo(os.environ['ADLOG_TEST_PG_DSN'], user='adlog_user')
    from server.sli.core import postgres_runtime_pipeline
    monkeypatch.setattr(postgres_runtime_pipeline, 'connect', lambda: psycopg.connect(dsn, row_factory=dict_row))
    monkeypatch.setattr(history, 'ensure_schema', lambda *a: None)
    with pytest.raises(RuntimeError, match='^snapshot_history_migration_required$'):
        history.run_cycle(port=8123, apply_retention=False, now=now, max_manifests=1)
    c.execute("insert into schema_migrations values(201,'file_audit_semantic_source'),"
              "(202,'agent_gpo_history_expiry_fence')")
    c.execute("insert into schema_migrations values(203,'agent_semantic_timestamp_precision')")
    c.execute((PATH.parent / '204_agent_gpo_history_slot_timestamp.sql').read_text('utf-8'))
    result = history.run_cycle(port=8123, apply_retention=False, now=now, max_manifests=1)
    assert result['gpo_cycles_published'] == 1 and result['status'] == 'partial'
    with psycopg.connect(dsn, row_factory=dict_row) as runtime:
        assert history.publish_agent_gpo_cycle(runtime, 8123, cycles[0])['records_published'] == 0
        assert history.publish_agent_gpo_cycle(runtime, 8123, cycles[1])['records_published'] == 1
        assert history.publish_agent_gpo_cycle(runtime, 8123, cycles[1])['records_published'] == 0
        assert len(batches) == 2
        with pytest.raises(ValueError, match='gpo_cycle_missing'):
            history.publish_agent_gpo_cycle(runtime, 8123, cycles[2])
        for cycle in cycles[3:]:
            assert history.publish_agent_gpo_cycle(runtime, 8123, cycle)['records_published'] == 0
        runtime.commit()
    assert history.run_cycle(port=8123, apply_retention=False, now=now)['gpo_cycles_published'] == 0
    for sql in ["update public.ad_snapshot_history_confirmations set record_count=2",
                "delete from public.ad_snapshot_history_confirmations"]:
        with pytest.raises(psycopg.Error, match='immutable'): c.execute(sql)
    rows = c.execute("select * from public.ad_snapshot_history_confirmations order by observed_at").fetchall()
    assert len(rows) == 4 and str(rows[1]['previous_manifest_id']) == cycles[0]
    assert rows[1]['coverage_state'] == 'complete'
    assert all(r['previous_manifest_id'] is None and r['coverage_state'] == 'partial' for r in rows[2:])
    # The guard rejects forged domain/time/hash/source even with INSERT permission.
    for field, value in [('domain_id', 2), ('source_sha256', 'f' * 64), ('observed_at', now + timedelta(minutes=1))]:
        row = dict(rows[0]); row[field] = value
        # New synthetic cycle has the same published source but no confirmation.
        fake = str(uuid4())
        c.execute('insert into public.sli_agent_snapshot_cycles select %s,agent_id,module_id,slot_start_utc,policy,publication_state,gpo_source_run_id from public.sli_agent_snapshot_cycles where cycle_id=%s', (fake, cycles[0]))
        row['manifest_id'] = fake
        row['batch_id'] = fake.replace('-', '') + '0' * 32
        with psycopg.connect(dsn) as runtime, pytest.raises(psycopg.Error, match='source mismatch'):
            runtime.execute("""insert into public.ad_snapshot_history_confirmations
                (manifest_id,family,domain_id,previous_manifest_id,source_sha256,previous_sha256,batch_id,
                 records_sha256,record_count,observed_at,coverage_state)
                values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                tuple(row[k] for k in ('manifest_id','family','domain_id','previous_manifest_id','source_sha256',
                    'previous_sha256','batch_id','records_sha256','record_count','observed_at','coverage_state')))


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_source_hash_failure_prevents_confirmation(gpo_database, monkeypatch):
    import psycopg
    from psycopg.conninfo import make_conninfo
    from psycopg.rows import dict_row
    from psycopg.types.json import Jsonb
    c = gpo_database
    cycle, source, agent = (str(uuid4()) for _ in range(3))
    c.execute("insert into public.gpo_report_v2_source_snapshots values(%s,1,now(),%s,'completed','{}')", (source, b'a' * 32))
    c.execute("insert into public.sli_agent_snapshot_cycles values(%s,%s,'sli.gpo-snapshot',now(),%s,'published',%s)",
              (cycle, agent, Jsonb({'domain_sid':'synthetic','domain_dns':'synthetic.invalid'}), source))
    monkeypatch.setattr(history, 'publish_batch', lambda *a: pytest.fail('corrupt source published'))
    with (
        psycopg.connect(make_conninfo(os.environ['ADLOG_TEST_PG_DSN'], user='adlog_user'), row_factory=dict_row) as runtime,
        pytest.raises(RuntimeError, match='source_hash_mismatch'),
    ):
        history.publish_agent_gpo_cycle(runtime, 8123, cycle)
    assert c.execute('select count(*) as n from public.ad_snapshot_history_confirmations').fetchone()['n'] == 0

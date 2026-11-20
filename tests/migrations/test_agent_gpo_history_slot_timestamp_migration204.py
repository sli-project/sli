import os
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory
from server.sli.storage import ad_snapshot_change_history as history
from tests.migrations.test_ad_snapshot_history_composition_migration195 import (
    history_database as history_database,  # noqa: PLC0414 -- register shared pytest fixture
)
from tests.migrations.test_agent_gpo_change_history_migration200 import (
    gpo_database as gpo_database,  # noqa: PLC0414 -- register shared pytest fixture
)

PATH = Path(__file__).resolve().parents[2] / 'config/postgres_migrations/204_agent_gpo_history_slot_timestamp.sql'
NOW = datetime(2026, 10, 11, tzinfo=timezone.utc)


def test_slot_repair_follows_exact_203():
    pairs = [(x.version, x.name) for x in forward_migration_inventory(PATH.parent)]
    assert pairs[pairs.index((204, 'agent_gpo_history_slot_timestamp')) - 1] == (
        203, 'agent_semantic_timestamp_precision')


@pytest.fixture
def text_slot_database(gpo_database):
    # Match migration 170 and the installed DB, not the old test's timestamptz.
    gpo_database.execute('alter table sli_agent_snapshot_cycles alter column slot_start_utc type text')
    return gpo_database


def seed_cycles(connection):
    from psycopg.types.json import Jsonb

    agent = str(uuid4())
    cycles = []
    for index in range(2):
        cycle, source = str(uuid4()), str(uuid4())
        payload = {'collection_status': 'complete', 'gpos': [], 'links': [
            {'id': 'synthetic-link', 'enabled': bool(index)}]}
        digest = history.canonical_output_sha256(payload)
        stamp = NOW + timedelta(hours=index)
        connection.execute("insert into gpo_report_v2_source_snapshots values(%s,1,%s,%s,'completed',%s)",
                           (source, stamp, bytes.fromhex(digest), Jsonb(payload)))
        connection.execute("insert into sli_agent_snapshot_cycles values(%s,%s,'sli.gpo-snapshot',%s,%s,'published',%s)",
                           (cycle, agent, stamp.isoformat(), Jsonb({
                               'domain_sid': 'synthetic', 'domain_dns': 'synthetic.invalid',
                               'source_instance_id': 'synthetic', 'scope': 'domain'}), source))
        cycles.append(cycle)
    return cycles


def runtime_connection():
    import psycopg
    from psycopg.conninfo import make_conninfo
    from psycopg.rows import dict_row

    return psycopg.connect(make_conninfo(os.environ['ADLOG_TEST_PG_DSN'], user='adlog_user'), row_factory=dict_row)


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_text_slots_confirm_only_after_repair_and_keep_source_guard(text_slot_database, monkeypatch):
    import psycopg

    admin = text_slot_database
    cycles = seed_cycles(admin)
    monkeypatch.setattr(history, 'publish_batch', lambda *a: None)
    # Reproduce the exact installed failure with the original migration 200.
    with runtime_connection() as runtime, pytest.raises(psycopg.Error) as failure:
        history.publish_agent_gpo_cycle(runtime, 8123, cycles[0])
    assert failure.value.sqlstate == '42883'
    assert admin.execute('select count(*) as n from ad_snapshot_history_confirmations').fetchone()['n'] == 0

    admin.execute("insert into schema_migrations values(201,'file_audit_semantic_source'),"
                  "(202,'agent_gpo_history_expiry_fence'),(203,'agent_semantic_timestamp_precision')")
    admin.execute(PATH.read_text('utf-8'))
    with runtime_connection() as runtime:
        assert history.publish_agent_gpo_cycle(runtime, 8123, cycles[0])['records_published'] == 0
        assert history.publish_agent_gpo_cycle(runtime, 8123, cycles[1])['records_published'] == 1
    rows = admin.execute('select * from ad_snapshot_history_confirmations order by observed_at').fetchall()
    assert [r['observed_at'] for r in rows] == [NOW, NOW + timedelta(hours=1)]
    assert rows[0]['coverage_state'] == 'partial' and rows[0]['previous_manifest_id'] is None
    assert rows[1]['coverage_state'] == 'complete' and str(rows[1]['previous_manifest_id']) == cycles[0]
    # Repairing the type comparison must not relax the exact timestamp guard.
    with runtime_connection() as runtime, pytest.raises(psycopg.Error, match='source mismatch'):
        runtime.execute("""insert into ad_snapshot_history_confirmations
            (manifest_id,family,domain_id,source_sha256,batch_id,records_sha256,record_count,observed_at,coverage_state)
            values(%s,'gpo_v2',1,%s,%s,%s,0,%s,'partial')""",
            (cycles[0], rows[0]['source_sha256'], 'f' * 64, 'e' * 64, NOW + timedelta(minutes=1)))


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_unrepaired_gpo_schema_blocks_deletion_but_worker_and_health_are_warning(
    text_slot_database, monkeypatch, tmp_path, capsys,
):
    import psycopg

    from deploy.linux import healthcheck
    from scripts.runtime import storage_lifecycle_worker as worker
    from server.sli.core import postgres_runtime_pipeline
    from server.sli.storage import permanent_history_lifecycle as lifecycle

    seed_cycles(text_slot_database)
    monkeypatch.setattr(postgres_runtime_pipeline, 'connect', runtime_connection)
    monkeypatch.setattr(history, 'ensure_schema', lambda *a: pytest.fail('schema write before repair'))
    monkeypatch.setattr(history, 'publish_agent_gpo_cycle', lambda *a: pytest.fail('publication before repair'))
    monkeypatch.setattr(history, 'purge_history', lambda *a, **kw: pytest.fail('history deletion before repair'))
    monkeypatch.setattr(lifecycle.history, 'primary_read_enabled', lambda: True)
    monkeypatch.setattr(lifecycle.history, 'configured_read_port', lambda: 8123)
    monkeypatch.setattr(lifecycle.history, 'next_after_id', lambda *a: pytest.fail('copy after blocked AD'))
    monkeypatch.setattr(lifecycle, '_retain', lambda **kw: pytest.fail('hot deletion before repair'))
    monkeypatch.setattr(worker, 'lifecycle_lock', lambda: nullcontext(True))
    monkeypatch.setattr(worker, '_capacity_evidence', dict)
    monkeypatch.setattr(worker, '_prior_successful_watermark', lambda: ('prior-watermark', 'prior-timestamp'))
    monkeypatch.setattr(worker, 'LAST_RESULT', tmp_path / 'result.json')
    results, heartbeats = [], []

    def run_cycle(**kwargs):
        result = lifecycle.run_cycle(apply_retention=True, now=NOW)
        results.append(result)
        return result

    monkeypatch.setattr(worker, 'run_cycle', run_cycle)
    monkeypatch.setattr(worker, 'record_worker_heartbeat', lambda **kw: heartbeats.append(kw))
    assert worker.run(once=True, interval_seconds=900) == 2
    result = results[0]
    assert result['status'] == 'blocked' and result['reason'] == 'snapshot_history_migration_required'
    assert result['blocked_phase'] == 'ad_snapshot_history' and result['deleted_rows'] == 0
    assert result['copy_only_no_delete'] is True and result['delete_execution_admitted'] is False
    heartbeat = heartbeats[-1]
    assert heartbeat['status'] == 'warning'
    assert heartbeat['details']['last_cycle_status'] == 'blocked'
    assert heartbeat['details']['last_successful_watermark'] == 'prior-watermark'
    assert text_slot_database.execute('select count(*) as n from ad_snapshot_history_confirmations').fetchone()['n'] == 0

    row = (heartbeat['status'], heartbeat['details']['last_cycle_reason'])
    probe = SimpleNamespace(execute=lambda *a: SimpleNamespace(fetchone=lambda: row))
    monkeypatch.setattr(healthcheck, 'load_config', lambda: SimpleNamespace(postgres_dsn='synthetic'))
    monkeypatch.setattr(psycopg, 'connect', lambda *a, **kw: nullcontext(probe))
    assert healthcheck.healthy('storage_lifecycle')
    assert 'warning: storage_lifecycle: snapshot_history_migration_required' in capsys.readouterr().out

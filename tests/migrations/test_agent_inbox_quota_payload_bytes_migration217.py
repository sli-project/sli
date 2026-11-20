"""Quota byte accounting stays exact without rewriting retained event payloads."""
from pathlib import Path

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / 'config/postgres_migrations/217_agent_inbox_quota_payload_bytes.sql'
SQL = PATH.read_text('utf-8')


def test_quota_column_backfills_only_pending_rows_without_rewriting_evidence():
    assert 'add column quota_payload_bytes bigint' in SQL
    assert 'where imported_at is null;' in SQL
    update = SQL.split('update public.sli_agent_packet_inbox', 1)[1].split(';', 1)[0]
    assert update.split('set ', 1)[1].startswith('quota_payload_bytes=1024')
    for field in ('envelope', 'packet', 'event_rows'):
        assert f'octet_length({field}::text)' in update
    assert 'generated always' not in SQL
    assert 'delete from' not in SQL
    assert 'disable trigger' not in SQL


def test_quota_trigger_cannot_be_forged_and_import_ack_does_not_recompute_payload():
    assert 'security invoker set search_path=pg_catalog,pg_temp' in SQL
    assert 'before insert or update of envelope,packet,event_rows,quota_payload_bytes' in SQL
    trigger = SQL.split('create trigger agent_inbox_payload_bytes_v217', 1)[1]
    assert 'imported_at' not in trigger
    for field in ('envelope', 'packet', 'event_rows'):
        assert f'octet_length(new.{field}::text)' in SQL
    assert 'revoke all on function public.agent_inbox_payload_bytes_v217() from public;' in SQL


def test_quota_migration_requires_exact_predecessor_and_storage_owner():
    pairs = [(m.version, m.name) for m in forward_migration_inventory(PATH.parent)]
    assert pairs[pairs.index((217, 'agent_inbox_quota_payload_bytes')) - 1] == (216, 'semantic_quarantine_requeue')
    assert list(PATH.parent.glob('217_*.sql')) == [PATH]
    assert len(pairs) == len({version for version, _ in pairs})
    assert "version=216 and name='semantic_quarantine_requeue'" in SQL
    assert 'where version>=217' in SQL
    assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in SQL
    assert 'set local role adlog_storage_owner;' in SQL
    assert SQL.strip().endswith('commit;')

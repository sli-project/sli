"""D01-D03 SQL admission and reference contracts; no database connection."""
from pathlib import Path

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/247_decoy_delivery_context.sql"
SQL = PATH.read_text("utf-8")
ENQUEUE = SQL.split("create or replace function public.enqueue_qw_finding_notifications", 1)[1]


def test_new_number_and_transaction_preserve_immutable_predecessor(tmp_path):
    (tmp_path / PATH.name).write_text(SQL, encoding="utf-8")
    inventory = [(item.version, item.name) for item in forward_migration_inventory(tmp_path)]
    assert inventory.count((247, "decoy_delivery_context")) == 1
    assert "version=245 and name='file_decoy'" in SQL and "where version>=247" in SQL
    assert "values(247,'decoy_delivery_context')" in SQL
    assert SQL.splitlines()[1] == "begin;" and SQL.strip().endswith("commit;")


def test_decoy_delay_enqueues_instead_of_using_the_threshold_age_suppression():
    decoy = ENQUEUE.split("if decoy then", 1)[1].split("elsif exists", 1)[0]
    assert "'processing_mode','live')" in decoy
    assert "reason='live' and event_at<clock_timestamp()-interval '15 minutes'" in decoy
    assert "reason := 'pipeline_delay'" in decoy
    assert "extract(epoch from (clock_timestamp()-event_at))/60" in decoy
    assert "return 0" not in decoy
    assert "scenario_kind='qw.nps-denials'" in ENQUEUE
    assert "scenario_kind in ('qw.nps-denials','qw.account-decoy','qw.file-decoy')" not in ENQUEUE


def test_history_import_and_replay_create_terminal_journal_rows_without_dispatch():
    assert "bool_and(coalesce(signal.document_json->>'processing_mode','live')='history_import')" in ENQUEUE
    assert "in ('historical_replay','history_import'))" in ENQUEUE
    assert "case when reason in ('historical_replay','history_import') then 'cancelled' else 'pending' end" in ENQUEUE
    assert "case when reason in ('historical_replay','history_import') then reason else null end" in ENQUEUE
    assert "delivery_reason,delay_minutes,state,result_code" in ENQUEUE
    assert "delivery_key := delivery_key || ':' || reason" in ENQUEUE
    assert "on conflict(object_kind,object_id,recipient_user_id,channel,change_key) do nothing" in ENQUEUE
    assert "reason not in ('historical_replay','history_import') and required+" in ENQUEUE


def test_admission_and_native_evidence_guards_remain_in_place():
    assert "job.source_kind='qw_signal' and admission.enabled is true" in ENQUEUE
    assert "public.qw_signal_evidence_allowed(signal.document_json,true) is not true" in ENQUEUE
    assert "scenario.evidence_state='ready'" in ENQUEUE
    assert "pg_advisory_xact_lock(hashtext('notification_outbox_admission'))" in ENQUEUE
    assert "where enabled order by id for share" in ENQUEUE


def test_queue_bridge_reads_immutable_signal_versions_and_exposes_only_references():
    bridge = SQL.split("create function public.finding_decoy_context", 1)[1].split("$$;", 1)[0]
    assert "semantic_finding_publications publication" in bridge
    assert "semantic_scenario_steps step using(scenario_id)" in bridge
    assert "signal.document_json->'decoy_context'" in bridge
    assert "signal.document_json->'file_decoy_context'" in bridge
    assert "context->>'label_id'" in bridge and "context->'label_revision'" in bridge
    assert "decoy_label_versions" not in bridge
    assert "security definer set search_path=pg_catalog,pg_temp" in bridge
    assert "revoke all on function public.finding_decoy_context(bigint) from public" in SQL
    assert "grant execute on function public.finding_decoy_context(bigint) to adlog_user" in SQL

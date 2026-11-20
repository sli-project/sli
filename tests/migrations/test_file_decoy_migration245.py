"""D03 additive schema, bounded capability readers and unchanged admission."""
from pathlib import Path

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory

ROOT = Path(__file__).resolve().parents[2]
SQL = (ROOT / "config/postgres_migrations/245_file_decoy.sql").read_text("utf-8")


def test_d03_follows_main_and_is_dormant():
    pairs = [(item.version, item.name) for item in forward_migration_inventory(ROOT / "config/postgres_migrations")]
    assert pairs[pairs.index((245, "file_decoy"))-1] == (244, "account_decoy")
    assert "version=244 and name='account_decoy'" in SQL and "where version>=245" in SQL
    assert "values(245,'file_decoy')" in SQL and SQL.strip().endswith("commit;")
    for table in ("finding_evidence_source_bindings", "semantic_risk_policies", "semantic_policy_admission",
                  "notification_channels", "notification_subscriptions"):
        assert "insert into public." + table not in SQL


def test_capability_reader_is_exact_scoped_and_uses_native_observations_before_action_filters():
    reader = SQL.split("create function public.read_file_decoy_observations", 1)[1].split("end $$;", 1)[0]
    assert "stable security definer set search_path=pg_catalog,pg_temp" in reader
    assert "public.file_ransom_scope_allowed(s,p_agent) is not true" in reader
    assert "o.generation=s->>'source_generation'" in reader
    assert "o.event_id in (4656,5145,4663,4660,4670)" in reader
    assert "coalesce(p.policy->>'source_kind','server')='server'" in reader
    assert "d.device_id=p_agent::text" in reader and "d.collection_scope_id=s->>'collection_scope_id'" in reader
    assert "d.active_from<=o.observed_at and (d.active_to is null or o.observed_at<d.active_to)" in reader
    assert "public.resolve_finding_evidence_ref(" in reader
    assert "activity_findings" not in reader and "service_account_exclusions" not in reader and "rule_results" not in reader
    assert "p_native is not null and o.evidence_key=p_native" in reader
    assert "order by o.observed_at,o.evidence_key limit 128" in reader and "limit 129" in reader
    assert "grant select on sli_plugin_file_audit.observations to adlog_semantic_worker" not in SQL
    assert "alter table public.semantic_file_decoy_checks enable row level security" in SQL


def test_technical_delete_requires_bounded_exact_handle_context_and_native_hashes():
    assert "c.generation=o.generation" in SQL and "c.policy_revision=o.policy_revision" in SQL
    assert "interval '300 seconds'" in SQL and "jsonb_array_length(items)<=128" in SQL
    for field in ("subject_user_sid", "logon_id_numeric", "server_process_id", "handle_id"):
        assert f"c.normalized#>'{{facts,{field}}}'=o.normalized#>'{{facts,{field}}}'" in SQL
    assert "o.event_id=4660 and o.normalized#>>'{facts,outcome}'='success'" in SQL
    assert "where c->>'path' is null" in SQL
    assert "o.normalized->>'payload_sha256'=p_sha256" in SQL
    assert "or public.file_decoy_evidence_in_root(b.agent_id,p_source,p_generation,p_collection,p_native)" in SQL


def test_history_is_bounded_and_loss_is_read_from_committed_receipts():
    assert "d.id=p_label and d.revision=p_revision and d.kind='file'" in SQL
    assert "order by q.signal_id limit 101" in SQL
    assert "ref->>'native_id'=o.evidence_key and ref->>'sha256'=o.payload_sha256" in SQL
    assert "r.receipt->>'status'='committed'" in SQL and "i.envelope=r.envelope" in SQL
    assert "r.envelope->>'continuity_state'" in SQL and "r.envelope->>'lost_count'" in SQL


def test_shared_atomic_outbox_and_both_channels_keep_admission_and_replay_guards():
    assert "('qw.nps-denials','qw.account-decoy','qw.file-decoy')" in SQL
    assert "job.source_kind='qw_signal' and admission.enabled is true" in SQL
    assert "public.qw_signal_evidence_allowed(signal.document_json,true) is not true" in SQL
    assert "select distinct on(recipient_user_id,channel)" in SQL
    assert "on conflict(object_kind,object_id,recipient_user_id,channel,change_key) do nothing" in SQL

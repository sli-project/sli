"""D02 migration contract; no database or source connections."""
from pathlib import Path

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory

SQL = (Path(__file__).resolve().parents[2] / "config/postgres_migrations/244_account_decoy.sql").read_text("utf-8")


def test_registry_prerequisite_is_shipped_before_the_detector():
    migrations = Path(__file__).resolve().parents[2] / "config/postgres_migrations"
    pairs = [(item.version, item.name) for item in forward_migration_inventory(migrations)]
    index = pairs.index((244, "account_decoy"))
    assert pairs[index - 2:index] == [(242, "gpo_plan_credentials"), (243, "decoy_registry")]
    assert len(pairs) == len({version for version, _ in pairs})


def test_additive_migration_depends_on_registry_and_does_not_activate_anything():
    assert "version=243 and name='decoy_registry'" in SQL
    assert "where version>=244" in SQL and "values(244,'account_decoy')" in SQL
    assert SQL.splitlines()[1] == "begin;" and SQL.strip().endswith("commit;")
    for table in ("finding_evidence_source_bindings", "semantic_risk_policies", "semantic_policy_admission",
                  "notification_channels", "notification_subscriptions"):
        assert "insert into public." + table not in SQL


def test_reader_requires_bound_native_scope_and_grants_no_underlying_reads():
    assert "stable security definer set search_path=pg_catalog,pg_temp" in SQL
    assert "p_plugin is distinct from 'sli.windows.ad-dc'" in SQL
    assert "public.finding_evidence_scope_allowed(p_installation,p_plugin,p_source,p_generation,'','core_event') is not true" in SQL
    assert "public.resolve_finding_evidence_ref(p_installation,p_plugin,p_source,p_generation,'','core_event'," in SQL
    assert "encode(e.normalized_hash,'hex')" in SQL
    assert "n.source_event_sha256=e.normalized_hash and n.occurred_at_utc=e.time_created_utc" in SQL
    assert "grant select on public.normalized_events" not in SQL
    assert "grant select on public.decoy_label_versions" not in SQL
    assert "revoke all on function public.read_account_decoy_events(uuid,text,text,text,text,uuid) from public" in SQL
    assert "alter table public.semantic_account_decoy_checks enable row level security" in SQL
    assert "grant select(id,fqdn,netbios_name) on public.domains to adlog_storage_owner" in SQL
    assert "on public.ad_context_entity_versions to adlog_storage_owner" in SQL


def test_reader_uses_authentication_and_event_time_versions_not_current_names_or_inventory():
    assert "e.event_id in (4624,4625,4768,4769,4771,4776)" in SQL
    assert "n.normalizer_id='windows.named-eventdata'" in SQL and "n.processing_status='normalized'" in SQL
    assert "n.semantic_contract_version=1" in SQL
    assert "d.active_from<=e.occurred_at_utc and (d.active_to is null or e.occurred_at_utc<d.active_to)" in SQL
    assert "v.valid_from_utc<=e.occurred_at_utc and (v.valid_to_utc is null or e.occurred_at_utc<v.valid_to_utc)" in SQL
    assert "r.domain_id=e.domain_id" in SQL and "d.collection_scope_id='ad-domain:'||e.domain_id" in SQL
    assert "'sid',v.attributes_json#>>'{identity,object_sid}'" in SQL
    assert "'guid',lower(v.attributes_json#>>'{identity,object_guid}')" in SQL
    assert "e.event_id=4625" in SQL and "lower(domain.fqdn)" in SQL and "lower(domain.netbios_name)" in SQL
    assert "source_section='directory_accounts'" in SQL and "r.status='completed'" in SQL
    assert "label.collection_scope_id='ad-domain:'||e.domain_id" in SQL
    assert "label.active_from<=n.occurred_at_utc" in SQL


def test_checkpoints_are_bounded_and_do_not_skip_late_normalization_or_publication_rechecks():
    assert "primary key(checkpoint_key,normalized_event_id)" in SQL
    assert "p_normalized is not null and n.normalized_event_id=p_normalized" in SQL
    assert "c.checkpoint_key=p_checkpoint and c.normalized_event_id=n.normalized_event_id" in SQL
    assert "order by n.normalized_at,n.normalized_event_id limit 128" in SQL
    assert "limit 129" in SQL and "limit 257" in SQL
    assert "now()-interval" not in SQL


def test_decoy_outbox_keeps_shared_admission_channels_and_historical_suppression():
    assert "scenario_kind in ('qw.nps-denials','qw.account-decoy') and last_seen_utc<clock_timestamp()-interval '15 minutes'" in SQL
    assert "job.source_kind='qw_signal' and admission.enabled is true" in SQL
    assert "signal.document_json->>'conclusion_state' is distinct from 'observed'" in SQL
    assert "public.qw_signal_evidence_allowed(signal.document_json,true) is not true" in SQL
    assert "select distinct on(recipient_user_id,channel)" in SQL
    assert "on conflict(object_kind,object_id,recipient_user_id,channel,change_key) do nothing" in SQL
    assert "notification_queue_full" in SQL

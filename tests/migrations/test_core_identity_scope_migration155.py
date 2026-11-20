from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SQL = (ROOT / "config/postgres_migrations/155_core_identity_scope.sql").read_text(encoding="utf-8")


def test_predecessor_owner_and_shared_identity_prerequisites():
    assert "version=154 and name='core_job_queue'" in SQL
    assert "migration 155 requires exact migration 154 core_job_queue" in SQL
    assert "version=153" not in SQL and "semantic_governance" not in SQL
    assert "version=34 and name='ad_context_entities_v2'" in SQL
    assert "version=45 and name='ad_context_shared_entity_identity'" in SQL
    assert "version=90 and name='storage_v2_direct_identity'" in SQL
    assert "pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER')" in SQL
    assert "version=155" in SQL and "migration 155 already applied" in SQL
    assert "values(155,'core_identity_scope')" in SQL


def test_versioned_lock_and_trigger_use_the_renumbered_migration():
    assert "hashtext('ad_log_core_identity_scope_v155')" in SQL
    assert "create function core_identity_immutable_v155() returns trigger" in SQL
    assert SQL.count("execute function core_identity_immutable_v155()") == 3
    assert "revoke all on function core_identity_immutable_v155() from public" in SQL
    assert "v154" not in SQL
    assert not (ROOT / "config/postgres_migrations/154_core_identity_scope.sql").exists()


def test_references_are_granted_before_owner_switch_and_no_existing_ids_change():
    assert SQL.index("grant references on entities_v2,auth_users to adlog_storage_owner") < SQL.index("set local role adlog_storage_owner")
    assert "references entities_v2(id) on delete restrict" in SQL
    assert "update entities_v2" not in SQL.lower()
    assert "alter table entities_v2" not in SQL.lower()
    assert "setval" not in SQL.lower()
    assert "access_report_assignments" not in SQL


def test_identifiers_are_scoped_aliases_do_not_claim_uniqueness():
    assert "on core_entity_identifiers(entity_kind,namespace,scope_id,value) where strength='stable'" in SQL
    assert "strength in ('stable','alias')" in SQL
    assert "entity_kind in ('principal','device','group')" in SQL


def test_observations_and_associations_preserve_evidence_and_ambiguity():
    assert "source_instance_id text not null" in SQL
    assert "plugin_id text not null" in SQL
    assert "resolution in ('resolved','provisional','unresolved','ambiguous')" in SQL
    assert "resolution<>'ambiguous' or cardinality(candidate_ids)>1" in SQL
    assert "actor_id bigint not null references auth_users(id)" in SQL
    assert "cardinality(evidence_refs) between 1 and 64" in SQL
    assert "source_entity_id<>target_entity_id" in SQL


def test_runtime_has_append_only_history_and_no_automatic_grants():
    assert "revoke all on core_entity_identifiers,core_entity_observations,core_entity_associations from public,adlog_user" in SQL
    assert "grant select,insert on core_entity_identifiers,core_entity_observations to adlog_storage_worker,adlog_context_worker" in SQL
    assert "grant select,insert on core_entity_associations to adlog_user" in SQL
    assert "grant update" not in SQL.lower() and "grant delete" not in SQL.lower()
    assert "insert into access_" not in SQL.lower()


def test_scope_reader_uses_provenance_view_without_raw_identity_and_evidence_access():
    view = SQL.split("create view core_entity_scope_resources")[1].split("create function")[0]
    assert "security_barrier=true" in view
    assert "plugin_id" in view and "source_instance_id" in view and "collection_scope_id" in view
    assert "identifiers_json" not in view and "evidence_refs" not in view
    assert "grant select on core_entity_scope_resources to adlog_user" in SQL
    assert "grant select on core_entity_identifiers,core_entity_observations to adlog_user" not in SQL
    assert SQL.index("grant select(id,entity_type_id,display_name,natural_key,domain_id) on entities_v2 to adlog_storage_owner") < SQL.index("set local role adlog_storage_owner")


def test_identity_history_rejects_mutation_even_by_a_table_owner():
    for table in ("core_entity_identifiers", "core_entity_observations", "core_entity_associations"):
        assert f"before update or delete on {table}" in SQL
    assert "core identity evidence is append-only" in SQL

"""Source contracts for widening internal event identities, without a live DB."""

import re
from pathlib import Path

import pytest

from scripts.maintenance import existing_postgres_bootstrap as bootstrap

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "config/postgres_migrations/150_storage_v2_event_bigint.sql"
BASELINE = ROOT / "config/postgres_baseline/baseline.sql"
WIDENED = {
    "events_v2_core": {"id": "bigint"},
    "storage_v2_event_identity_allocations": {"id": "bigint"},
    "event_facts_v2": {"event_id": "bigint"},
    "event_entity_link_blocks_v2": {
        "first_event_id": "bigint", "last_event_id": "bigint", "event_ids": "bigint[]",
    },
    "entity_state_current": {"source_event_db_id": "bigint"},
    "entity_state_projection_jobs": {"source_event_db_id": "bigint"},
    "normalized_events": {"source_event_id": "bigint"},
    "semantic_processing_outbox": {"source_event_id": "bigint"},
    "entity_identity_merge_events_v2": {"source_event_id": "bigint"},
    "entity_identity_semantic_replays_v2": {"source_event_id": "bigint"},
}


def test_migration_preserves_dependencies_privileges_and_sequence_position() -> None:
    sql = MIGRATION.read_text(encoding="utf-8").lower()
    assert sql.strip().startswith("-- migration 150")
    assert "pg_advisory_xact_lock" in sql
    assert "version = 149 and name = 'investigation_finding_links'" in sql
    assert "name is distinct from 'storage_v2_event_bigint'" in sql
    assert "pg_has_role(session_user, 'adlog_storage_owner', 'member')" in sql
    assert "pg_has_role(session_user, 'adlog_user', 'member')" in sql
    assert "pg_get_constraintdef" in sql and "confrelid" in sql and "convalidated" in sql
    assert "drop constraint %i" in sql and "add constraint %i %s" in sql
    assert "drop view public.event_entity_links_v2" in sql
    assert "create view public.event_entity_links_v2" in sql
    assert "aclexplode" in sql and "is_grantable" in sql
    assert "acldefault('r', rel.relowner)" in sql
    assert "alter sequence public.storage_v2_event_id_seq as bigint no maxvalue" in sql
    assert "9223372036854775807" in sql and "last_value" in sql
    assert "setval(" not in sql
    assert "access exclusive" in sql and "lock_timeout" in sql
    assert "pg_total_relation_size" in sql and "minutes" in sql
    assert "pg_get_functiondef" in sql
    assert "seqtypid = 'bigint'::regtype and seqmax = 9223372036854775807" in sql
    assert "return;" in sql
    assert "(item.value->>'source_event_id')::bigint" in sql
    for table, columns in WIDENED.items():
        for column, dtype in columns.items():
            assert f"('{table}', '{column}', '{dtype}')" in sql
    inventory = bootstrap.forward_migration_inventory(MIGRATION.parent)
    migration = next(item for item in inventory if item.version == 150)
    assert migration.name == "storage_v2_event_bigint"
    assert bootstrap.migration_requires_admin(migration)


@pytest.mark.parametrize("table,columns", WIDENED.items())
def test_baseline_widens_every_int32_event_reference(table, columns) -> None:
    sql = BASELINE.read_text(encoding="utf-8")
    body = re.search(rf"CREATE TABLE public\.{table} \((.*?)\n\);", sql, re.DOTALL)[1]
    for column, dtype in columns.items():
        assert re.search(rf"^    {column} {re.escape(dtype)}(?!\w)", body, re.MULTILINE)
    if table == "events_v2_core":
        assert "event_id integer NOT NULL" in body  # Windows Event ID stays int32.


def test_bigint_capacity_gate_covers_sequence_core_and_unpublished_reservations() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    assert "greatest_event_id >= 9223372036854775807" in sql
    assert "select last_value into sequence_position from public.storage_v2_event_id_seq" in sql
    assert "coalesce((select max(id) from public.events_v2_core), 0)" in sql
    assert "coalesce((select max(id) from public.storage_v2_event_identity_allocations), 0)" in sql
    assert sql.index("greatest_event_id >= 9223372036854775807") < sql.index("return;")


def test_historical_direct_identity_migration_keeps_its_original_checksum() -> None:
    # Original clean-install manifest pin: migration 090 is already applied.
    path = MIGRATION.parent / "090_storage_v2_direct_identity.sql"
    assert bootstrap.normalized_sha256(path) == (
        "b978a1220f63b39a77215afd67fccd76ee51efe06a0053f3c9d50a821a496d33"
    )


def test_clickhouse_internal_event_references_are_already_64_bit() -> None:
    sql = (ROOT / "config/clickhouse/002_permanent_fact_history.sql").read_text(encoding="utf-8")
    assert sql.count("event_db_id UInt64") == 4
    assert "event_key UInt32" in sql  # Windows Event ID, not the internal key.


def test_baseline_fk_event_keys_and_non_fk_evidence_are_64_bit() -> None:
    sql = BASELINE.read_text(encoding="utf-8")
    tables = dict(re.findall(r"CREATE TABLE public\.(\w+) \((.*?)\n\);", sql, re.DOTALL))
    fks = re.findall(
        r"ALTER TABLE ONLY public\.(\w+)\s+ADD CONSTRAINT \w+ FOREIGN KEY \((\w+)\) "
        r"REFERENCES public\.events_v2_core\(id\)", sql,
    )
    assert len(fks) == 7
    for table, column in fks:
        assert re.search(rf"^    {column} bigint\b", tables[table], re.MULTILINE)
    migration = MIGRATION.read_text(encoding="utf-8")
    # Check the complete declared identity inventory, including bigint no-ops.
    for table, column, dtype in re.findall(r"\('([^']+)', '([^']+)', '(bigint(?:\[\])?)'\)", migration):
        assert re.search(rf"^    {column} {re.escape(dtype)}(?!\w)", tables[table], re.MULTILINE)
    assert "unnest(fk.conkey, fk.confkey)" in migration
    assert "on conflict do nothing" in migration
    assert "col.atttypid <> target.target_type::regtype" in migration
    assert "string_agg" in migration  # One rewrite per table with multiple changed columns.


def test_process_evidence_writer_and_baseline_use_bigint_source_cast() -> None:
    sql = BASELINE.read_text(encoding="utf-8")
    assert "source.id=(item.value->>'source_event_id')::bigint" in sql
    assert "source.id=(item.value->>'source_event_id')::integer" not in sql
    migration = MIGRATION.read_text(encoding="utf-8")
    assert "'public.write_process_episode_revision_v89(jsonb)'::regprocedure" in migration
    assert "(item.value->>''source_event_id'')::bigint" in migration


def test_baseline_contains_the_contracts_between_previous_snapshot_and_150() -> None:
    sql = BASELINE.read_text(encoding="utf-8")
    baseline = bootstrap.load_baseline(BASELINE.parent, bootstrap.forward_migration_inventory(MIGRATION.parent))
    assert baseline.version == 152
    for table in ("platform_settings", "domain_controller_targets", "investigation_finding_links"):
        assert f"CREATE TABLE public.{table} (" in sql
        assert f"ALTER TABLE public.{table} OWNER TO adlog_user;" in sql
    assert "GRANT UPDATE(domain_sid) ON TABLE public.domains TO adlog_context_worker;" in sql
    for column in ("id", "fqdn"):
        assert f"GRANT SELECT({column}) ON TABLE public.domains TO adlog_vpn_session_reader_owner;" in sql
    assert re.search(r"^\d+\t150\tstorage_v2_event_bigint\t", sql, re.MULTILINE)

from pathlib import Path

import pytest



ROOT = Path(__file__).resolve().parents[2]
FORWARD = (ROOT / "config/postgres_migrations/068_entity_identity_merge_r7.sql").read_text(encoding="utf-8").lower()
ROLLBACK = (ROOT / "config/postgres_migrations/068_entity_identity_merge_r7.rollback.sql").read_text(encoding="utf-8").lower()
REPAIR = (ROOT / "config/postgres_migrations/069_entity_identity_runtime_repair.sql").read_text(encoding="utf-8").lower()
REPAIR_ROLLBACK = (ROOT / "config/postgres_migrations/069_entity_identity_runtime_repair.rollback.sql").read_text(encoding="utf-8").lower()
BOUNDED_LOOKUP = (ROOT / "config/postgres_migrations/070_entity_identity_bounded_lookup.sql").read_text(encoding="utf-8").lower()
BOUNDED_LOOKUP_ROLLBACK = (ROOT / "config/postgres_migrations/070_entity_identity_bounded_lookup.rollback.sql").read_text(encoding="utf-8").lower()


def test_migration_68_is_append_only_and_blocks_source_resurrection() -> None:
    assert "entity_identity_merges_v2" in FORWARD
    assert "entity_identity_merge_events_v2" in FORWARD
    assert "entity_identity_semantic_replays_v2" in FORWARD
    assert "before update or delete" in FORWARD
    assert "reject_merged_entity_link_block" in FORWARD
    assert "resolve_entity_identity_v2" in FORWARD
    assert "entities_v2_active" in FORWARD
    assert "entity_identity_finding_supersessions_v2" in FORWARD
    assert "findings_active" in FORWARD
    assert "merged_observation.first_seen_utc" in FORWARD
    assert "merged_observation.last_seen_utc" in FORWARD
    assert "rollback blocked by immutable r7 evidence" in ROLLBACK




def test_migration_69_repairs_the_view_without_exposing_merge_evidence() -> None:
    assert "security definer" in REPAIR
    assert "set search_path=pg_catalog,public" in REPAIR
    assert "public.entity_identity_merges_v2" in REPAIR
    assert "grant select on entity_identity_merges_v2 to adlog_storage_worker" not in REPAIR
    assert "left join lateral" not in REPAIR
    assert "group by merged.target_entity_id" in REPAIR
    assert "values(69,'entity_identity_runtime_repair')" in REPAIR
    assert "rollback 069 is forbidden" in REPAIR_ROLLBACK
    assert "security definer" in REPAIR
    assert "reject_merged_entity_link_block" in REPAIR
    assert "grant select on entity_identity_merges_v2 to adlog_storage_worker" not in REPAIR




def test_migration_70_exposes_only_a_bounded_active_decision() -> None:
    assert "security definer" in BOUNDED_LOOKUP
    assert "set search_path=pg_catalog,public" in BOUNDED_LOOKUP
    assert "returns boolean" in BOUNDED_LOOKUP
    assert "grant execute on function entity_v2_is_active(bigint) to adlog_user" in BOUNDED_LOOKUP
    assert "grant select on entity_identity_merges_v2 to adlog_user" not in BOUNDED_LOOKUP
    assert "values(70,'entity_identity_bounded_lookup')" in BOUNDED_LOOKUP
    assert "rollback 070 is forbidden" in BOUNDED_LOOKUP_ROLLBACK

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FORWARD = (
    ROOT
    / "config/postgres_migrations/071_semantic_source_retention_decoupling.sql"
).read_text(encoding="utf-8").lower()
ROLLBACK = (
    ROOT
    / "config/postgres_migrations/071_semantic_source_retention_decoupling.rollback.sql"
).read_text(encoding="utf-8").lower()


def test_migration_71_preserves_identity_without_raw_payload() -> None:
    assert "source_identity_json" in FORWARD
    assert "source_event_sha256" in FORWARD
    assert "source_occurred_at_utc" in FORWARD
    assert "event_data_json" in FORWARD  # explicitly forbidden by constraints
    assert "jsonb_build_object" in FORWARD
    assert "migration 071 source identity backfill is incomplete" in FORWARD
    assert "lock table entity_identity_merge_events_v2" in FORWARD
    assert "disable trigger trg_entity_identity_merge_events_immutable" in FORWARD
    assert "enable trigger trg_entity_identity_merge_events_immutable" in FORWARD
    assert "failed to restore r7 immutability triggers" in FORWARD


def test_migration_71_removes_only_stage8_hot_core_foreign_keys() -> None:
    for table in (
        "semantic_processing_outbox",
        "normalized_events",
        "entity_identity_merge_events_v2",
        "entity_identity_semantic_replays_v2",
    ):
        assert f"'{table}'::regclass" in FORWARD
    assert "confrelid='events_v2_core'::regclass" in FORWARD
    assert "event_facts_v2" not in FORWARD
    assert "finding_evidence" not in FORWARD
    assert "values(71,'semantic_source_retention_decoupling')" in FORWARD


def test_migration_71_is_forward_only_after_hot_expiry() -> None:
    assert "rollback 071 is forbidden after retention decoupling" in ROLLBACK

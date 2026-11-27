from __future__ import annotations

from pathlib import Path

import pytest



def test_gpo_migration_republishes_evidence_contract_and_controlled_export() -> None:
    root = Path(__file__).resolve().parents[2]
    migration = (root / "config/postgres_migrations/104_gpo_evidence_first_v1.sql").read_text(encoding="utf-8")
    rollback = (root / "config/postgres_migrations/104_gpo_evidence_first_v1.rollback.sql").read_text(encoding="utf-8")

    for field in (
        "security_filtering_sids", "scheduled_task_count", "modified_utc",
        "has_executable_components",
    ):
        assert field in migration
    assert "'{export_policy}'" in migration
    assert "'\"controlled\"'::jsonb" in migration
    assert "allowed_actions || array['export']" in migration
    assert "priority" not in migration
    assert "review_reason" not in migration
    assert "array_remove(allowed_actions,'export')" in rollback


def test_gpo_settings_migration_publishes_nested_evidence_without_new_grants() -> None:
    root = Path(__file__).resolve().parents[2]
    migration = (root / "config/postgres_migrations/105_gpo_settings_evidence_v2.sql").read_text(encoding="utf-8")
    rollback = (root / "config/postgres_migrations/105_gpo_settings_evidence_v2.rollback.sql").read_text(encoding="utf-8")

    assert '"key":"settings"' in migration
    assert '"category":"security"' in migration
    assert "access_package_reports" not in migration
    assert "access_subject_report_grants" not in migration
    assert "updated_at_utc" not in migration
    assert "updated_at_utc" not in rollback
    assert "report_registry_v4" in migration
    assert "report_definitions_v4" not in migration
    assert "applied_at_utc" not in migration
    assert "105_gpo_settings_evidence_v2" in migration
    assert "field->>'key' <> 'settings'" in rollback

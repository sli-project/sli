from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = (
    ROOT
    / "scripts/maintenance/"
    "storage_capacity_profile_disposable_acceptance.py"
).read_text(encoding="utf-8")


def test_disposable_acceptance_is_loopback_bounded_and_cleans_up() -> None:
    assert '"postgres:18-alpine"' in SCRIPT
    assert '"127.0.0.1:0:5432"' in SCRIPT
    assert '"--pull", "never"' in SCRIPT
    assert "DISPOSABLE_CONTAINER" in SCRIPT
    assert "_remove_cluster" in SCRIPT


def test_disposable_acceptance_proves_mixed_candidate_retention_and_control_safety() -> None:
    assert "dry_run_mutates_nothing" in SCRIPT
    assert "mixed_candidates_delete_only_eligible" in SCRIPT
    assert "held_by_relationship_horizon" in SCRIPT
    assert "held_by_archive_gap" in SCRIPT
    assert "held_by_other_dependency" in SCRIPT
    assert "2026-07-21T00:00:00Z" in SCRIPT
    assert "control_state_preserved" in SCRIPT
    assert "production_database_changed\": False" in SCRIPT

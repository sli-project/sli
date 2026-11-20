from __future__ import annotations

from pathlib import Path

from server.sli.storage.tier_retention_delete_plan_runtime import GateInputs, assemble_gate
from server.sli.storage.storage_policy import StoragePolicy


ROOT = Path(__file__).resolve().parents[2]


def _inputs(**overrides) -> GateInputs:
    values = {
        "candidate_count": 0,
        "candidates_truncated": False,
        "backup_valid": True,
        "warm_available": True,
        "warm_missing": 0,
        "warm_hash_mismatches": 0,
        "archive_paths_missing": 0,
        "restrictive_reference_rows": 0,
    }
    values.update(overrides)
    return GateInputs(**values)


def test_no_old_rows_is_a_clean_no_work_plan() -> None:
    plan = assemble_gate(StoragePolicy(), _inputs())

    assert plan["status"] == "no_candidates"
    assert plan["technical_gate_passed"] is True
    assert plan["authorization"]["granted"] is False
    assert plan["authorization"]["delete_performed"] is False


def test_verified_candidates_still_require_separate_owner_authorization() -> None:
    plan = assemble_gate(
        StoragePolicy(),
        _inputs(candidate_count=25),
    )

    assert plan["status"] == "ready_for_owner_authorization"
    assert plan["technical_gate_passed"] is True
    assert plan["authorization"] == {
        "required": True,
        "granted": False,
        "delete_performed": False,
    }


def test_live_evidence_reference_blocks_candidate_deletion() -> None:
    plan = assemble_gate(
        StoragePolicy(),
        _inputs(candidate_count=25, restrictive_reference_rows=3),
    )

    assert plan["status"] == "blocked"
    assert plan["technical_gate_passed"] is False
    assert "candidate_rows_are_still_referenced_as_live_evidence" in plan["blockers"]


def test_plan_source_contains_no_mutating_storage_statement() -> None:
    source = (
        ROOT / "scripts" / "maintenance" / "tier_retention_delete_plan.py"
    ).read_text(encoding="utf-8").lower()

    assert "delete from events_v2_core" not in source
    assert "update events_v2_core" not in source
    assert "truncate events_v2_core" not in source
    assert "drop table" not in source

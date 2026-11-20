from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from server.sli.sources.ad_snapshot_retention import (
    REQUIRED_AD_RETENTION_RELATIONS,
    plan_ad_snapshot_retention,
)


NOW = datetime(2026, 9, 1, 12, tzinfo=timezone.utc)


def _safe_inventory(*, candidate_count: int = 0) -> dict[str, dict[str, object]]:
    return {
        relation: {
            "candidate_count": candidate_count,
            "root_mapping_proven": True,
            "anchor_proven": True,
            "owner_admitted": True,
            "shared_source": False,
            "dependency_state": "safe",
            "independent_legacy_cleaner": False,
            "whole_unit_admitted": candidate_count == 0,
        }
        for relation in REQUIRED_AD_RETENTION_RELATIONS
    }


def test_zero_eligible_plan_proves_completed_non_destructive_path() -> None:
    result = plan_ad_snapshot_retention(now=NOW, inventory=_safe_inventory())

    assert result["status"] == "completed"
    assert result["policy_horizon_days"] == 7
    assert result["eligible_before"] == 0
    assert result["eligible_after"] == 0
    assert tuple(result["relations"]) == REQUIRED_AD_RETENTION_RELATIONS
    assert all(row["candidate_count"] == 0 for row in result["relations"].values())
    assert all(row["classification_counts"] == {"eligible": 0} for row in result["relations"].values())


def test_nonzero_or_ambiguous_relation_never_infers_admission() -> None:
    nonzero = _safe_inventory()
    nonzero["ad_snapshot_manifests"]["candidate_count"] = 3
    nonzero["ad_snapshot_manifests"]["whole_unit_admitted"] = False

    blocked = plan_ad_snapshot_retention(now=NOW, inventory=nonzero)

    assert blocked["status"] == "blocked"
    assert blocked["eligible_before"] == 3
    assert blocked["eligible_after"] == 0
    assert blocked["relations"]["ad_snapshot_manifests"]["classification_counts"] == {
        "blocked_unapproved_whole_unit": 3
    }

    ambiguous = _safe_inventory()
    ambiguous["gpo_report_v2_source_snapshots"]["candidate_count"] = None
    result = plan_ad_snapshot_retention(now=NOW, inventory=ambiguous)
    assert result["status"] == "blocked"
    assert result["eligible_before"] is None
    assert result["relations"]["gpo_report_v2_source_snapshots"]["classification_counts"] == {
        "blocked_unknown_candidate_count": 1
    }


def test_missing_ownership_anchor_dependency_or_legacy_cleaner_is_blocked() -> None:
    inventory = _safe_inventory()
    inventory["ad_snapshot_projection_outputs"]["root_mapping_proven"] = False
    inventory["users_report_v2_snapshots"]["owner_admitted"] = False
    inventory["computers_v6_source_snapshots"]["shared_source"] = True
    inventory["gpo_report_v2_source_snapshots"]["dependency_state"] = "unknown"
    inventory["ad_snapshot_projection_receipts"]["independent_legacy_cleaner"] = True

    result = plan_ad_snapshot_retention(now=NOW, inventory=inventory)

    assert result["status"] == "blocked"
    assert result["relations"]["ad_snapshot_projection_outputs"]["classification_counts"] == {
        "blocked_missing_root_mapping": 0
    }
    assert result["relations"]["users_report_v2_snapshots"]["classification_counts"] == {
        "blocked_missing_owner_admission": 0
    }
    assert result["relations"]["computers_v6_source_snapshots"]["classification_counts"] == {
        "blocked_shared_source": 0
    }
    assert result["relations"]["gpo_report_v2_source_snapshots"]["classification_counts"] == {
        "blocked_dependency_unknown": 0
    }
    assert result["relations"]["ad_snapshot_projection_receipts"]["classification_counts"] == {
        "blocked_independent_legacy_cleaner": 0
    }


def test_safe_not_due_plan_is_explicit_and_fixed_to_7_days() -> None:
    result = plan_ad_snapshot_retention(now=NOW, inventory=_safe_inventory(), due=False)

    assert result["status"] == "not_due"
    assert result["policy_horizon_days"] == 7
    assert result["eligible_before"] == 0
    assert result["eligible_after"] == 0


def test_retention_module_has_no_mutation_dml_or_apply_entrypoint() -> None:
    import server.sli.sources.ad_snapshot_retention as retention

    source = Path(retention.__file__).read_text(encoding="utf-8").casefold()
    for forbidden in (
        "delete from ",
        "truncate ",
        "insert into ",
        "update ",
        "def apply",
    ):
        assert forbidden not in source

from __future__ import annotations

"""Bounded, read-only AD retention admission planning."""

from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Any


POLICY_HORIZON_DAYS = 7
REQUIRED_AD_RETENTION_RELATIONS = (
    "ad_snapshot_manifests",
    "ad_snapshot_manifest_sources",
    "ad_snapshot_projection_receipts",
    "ad_snapshot_projection_outputs",
    "users_report_v2_snapshots",
    "computers_v6_source_snapshots",
    "gpo_report_v2_source_snapshots",
)
EXCLUDED_AD_RETENTION_RELATIONS = frozenset({"ad_context_runs"})


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _unknown_root() -> dict[str, object]:
    return {
        "candidate_count": None,
        "root_mapping_proven": False,
        "anchor_proven": False,
        "owner_admitted": False,
        "shared_source": False,
        "dependency_state": "unknown",
        "independent_legacy_cleaner": False,
        "whole_unit_admitted": False,
    }


def _candidate_count(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("candidate_count must be a non-negative integer or null")
    return value


def _classification(
    value: Mapping[str, object], *, candidate_count: int | None, compatibility: bool
) -> str:
    if compatibility and value.get("compatibility_ownership_proven") is not True:
        return "blocked_compatibility_ownership"
    if value.get("root_mapping_proven") is not True:
        return "blocked_missing_root_mapping"
    if value.get("anchor_proven") is not True:
        return "blocked_missing_anchor"
    if value.get("owner_admitted") is not True:
        return "blocked_missing_owner_admission"
    if value.get("shared_source") is True:
        return "blocked_shared_source"
    if value.get("independent_legacy_cleaner") is True:
        return "blocked_independent_legacy_cleaner"
    dependency_state = str(value.get("dependency_state") or "unknown")
    if dependency_state != "safe":
        if dependency_state == "restrictive":
            return "blocked_dependency_restrictive"
        return "blocked_dependency_unknown"
    if candidate_count is None:
        return "blocked_unknown_candidate_count"
    if candidate_count and value.get("whole_unit_admitted") is not True:
        return "blocked_unapproved_whole_unit"
    return "eligible"


def _failed_plan(now: datetime, error: Exception) -> dict[str, Any]:
    return {
        "status": "failed",
        "policy_horizon_days": POLICY_HORIZON_DAYS,
        "horizon_before_utc": _utc_text(now - timedelta(days=POLICY_HORIZON_DAYS)),
        "eligible_before": None,
        "eligible_after": 0,
        "relations": {},
        "error": f"{type(error).__name__}:{error}",
    }


def plan_ad_snapshot_retention(
    _connection: Any | None = None,
    *,
    now: datetime,
    inventory: Mapping[str, Mapping[str, object]] | None = None,
    due: bool = True,
    policy_horizon_days: int = POLICY_HORIZON_DAYS,
) -> dict[str, Any]:
    """Classify an AD retention unit without changing rows or admitting unknown roots.

    Callers provide a bounded, exact inventory readback when one has been proven.
    The conservative default deliberately blocks every physical root rather than
    inferring ownership, anchors, dependencies, or whole-unit admission.
    """
    if policy_horizon_days != POLICY_HORIZON_DAYS:
        raise ValueError("policy_horizon_days is fixed at 7")
    if not isinstance(due, bool):
        return _failed_plan(now, ValueError("due must be boolean"))
    try:
        raw_inventory: Mapping[str, Mapping[str, object]] = inventory or {}
        relation_values: list[tuple[str, Mapping[str, object], bool]] = []
        for relation in REQUIRED_AD_RETENTION_RELATIONS:
            value = raw_inventory.get(relation, _unknown_root())
            if not isinstance(value, Mapping):
                raise ValueError(f"inventory for {relation} must be a mapping")
            relation_values.append((relation, value, False))

        compatibility_roots = raw_inventory.get("compatibility_roots", {})
        if not isinstance(compatibility_roots, Mapping):
            raise ValueError("compatibility_roots must be a mapping")
        for relation in sorted(compatibility_roots):
            if relation in EXCLUDED_AD_RETENTION_RELATIONS:
                raise ValueError(f"{relation} is outside the AD snapshot retention scope")
            if relation in REQUIRED_AD_RETENTION_RELATIONS:
                raise ValueError("compatibility root duplicates a canonical relation")
            value = compatibility_roots[relation]
            if not isinstance(value, Mapping):
                raise ValueError(f"inventory for {relation} must be a mapping")
            relation_values.append((str(relation), value, True))

        relations: dict[str, dict[str, Any]] = {}
        known_candidate_counts: list[int] = []
        has_unknown_candidate_count = False
        eligible_after = 0
        blocked = False
        for relation, value, compatibility in relation_values:
            candidate_count = _candidate_count(value.get("candidate_count"))
            classification = _classification(
                value,
                candidate_count=candidate_count,
                compatibility=compatibility,
            )
            classification_count = candidate_count
            if classification == "blocked_unknown_candidate_count":
                classification_count = 1
                has_unknown_candidate_count = True
            elif candidate_count is not None:
                known_candidate_counts.append(candidate_count)
            if classification.startswith("blocked_"):
                blocked = True
            elif candidate_count is not None:
                eligible_after += candidate_count
            relations[relation] = {
                "candidate_count": candidate_count,
                "classification_counts": {classification: classification_count},
                "eligible_before": candidate_count,
                "eligible_after": candidate_count if classification == "eligible" else 0,
            }

        eligible_before = (
            None if has_unknown_candidate_count else sum(known_candidate_counts)
        )
        status = "blocked" if blocked else "not_due" if not due else "completed"
        return {
            "status": status,
            "policy_horizon_days": POLICY_HORIZON_DAYS,
            "horizon_before_utc": _utc_text(
                now - timedelta(days=POLICY_HORIZON_DAYS)
            ),
            "eligible_before": eligible_before,
            "eligible_after": eligible_after if not blocked else 0,
            "relations": relations,
        }
    except (TypeError, ValueError) as exc:
        return _failed_plan(now, exc)

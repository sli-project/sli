from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any, Literal, Mapping


@dataclass(frozen=True)
class ResolvedRetentionPeriod:
    days: int
    source: Literal["catalogue", "configuration"]
    defaulted: bool
    policy_field: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


_PROMOTION_FIELDS = (
    "version",
    "archive_requirement",
    "post_promotion_disposition",
    "read_representation",
    "high_volume",
    "semantic_role",
    "hot_need",
    "warm_value",
    "executable_lifecycle",
    "budget",
)


_PROMOTION_BUDGET_FIELDS = (
    "events_per_day_upper",
    "source_bytes_per_event_upper",
    "derived_bytes_per_object_upper",
    "calibration",
)


_SAFE_LEGACY_PROMOTION = {
    "version": "legacy-safe-default",
    "archive_requirement": "archive_required",
    "post_promotion_disposition": "preserve_source",
    "read_representation": "archived_atomic",
    "high_volume": False,
    "semantic_role": None,
    "hot_need": None,
    "warm_value": None,
    "executable_lifecycle": None,
    "budget": None,
}


def _resolve_lifecycle_promotion(lifecycle: Mapping[str, Any]) -> dict[str, Any]:
    declared = lifecycle.get("promotion")
    if declared is None:
        return dict(_SAFE_LEGACY_PROMOTION)
    if not isinstance(declared, Mapping):
        raise ValueError("lifecycle promotion must be an object")
    missing = [field for field in _PROMOTION_FIELDS if field not in declared]
    if missing:
        raise ValueError(f"lifecycle promotion fields missing: {', '.join(missing)}")
    promotion = {field: declared[field] for field in _PROMOTION_FIELDS}
    if promotion["version"] != "descriptor-lifecycle-v2":
        raise ValueError("unsupported lifecycle promotion version")
    if promotion["archive_requirement"] not in {"archive_required", "no_archive"}:
        raise ValueError("lifecycle archive requirement is invalid")
    if promotion["post_promotion_disposition"] != "delete_source":
        raise ValueError("unsupported post-promotion disposition")
    if promotion["read_representation"] not in {"archived_atomic", "derived_only"}:
        raise ValueError("lifecycle read representation is invalid")
    if not isinstance(promotion["high_volume"], bool):
        raise ValueError("lifecycle high_volume must be boolean")
    if any(not isinstance(promotion[field], str) or not promotion[field].strip()
           for field in ("semantic_role", "hot_need", "warm_value")):
        raise ValueError("lifecycle promotion semantic terms must be non-empty strings")
    if promotion["executable_lifecycle"] not in {
        "existing_warm_then_retention_executor",
        "semantic_then_direct_retention_executor",
    }:
        raise ValueError("unsupported executable lifecycle")
    if (
        promotion["executable_lifecycle"] == "semantic_then_direct_retention_executor"
        and promotion["archive_requirement"] != "no_archive"
    ):
        raise ValueError("direct retention requires no_archive")
    budget = promotion["budget"]
    if not isinstance(budget, Mapping):
        raise ValueError("lifecycle promotion budget must be an object")
    missing_budget = [field for field in _PROMOTION_BUDGET_FIELDS if field not in budget]
    if missing_budget:
        raise ValueError(f"lifecycle promotion budget fields missing: {', '.join(missing_budget)}")
    for field in _PROMOTION_BUDGET_FIELDS[:-1]:
        value = budget[field]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"lifecycle promotion budget {field} must be a non-negative integer")
    if promotion["high_volume"] and any(int(budget[field]) <= 0 for field in _PROMOTION_BUDGET_FIELDS[:-1]):
        raise ValueError("high-volume lifecycle budget bounds must be positive")
    if budget["calibration"] not in {"representative", "production"}:
        raise ValueError("lifecycle promotion budget calibration is invalid")
    if promotion["archive_requirement"] == "no_archive":
        if promotion["read_representation"] != "derived_only":
            raise ValueError("no-archive lifecycle must use derived-only reads")
    elif promotion["read_representation"] != "archived_atomic":
        raise ValueError("archive-required lifecycle must use archived atomic reads")
    promotion["budget"] = {field: budget[field] for field in _PROMOTION_BUDGET_FIELDS}
    return promotion


def _retention_policy_fingerprint(
    *,
    raw_payload: ResolvedRetentionPeriod,
    record: ResolvedRetentionPeriod,
    warm_record: ResolvedRetentionPeriod,
    rollup: str | None,
    rollup_role: str | None,
    promotion: Mapping[str, Any],
) -> str:
    payload = {
        "raw_payload": raw_payload.to_dict(),
        "record": record.to_dict(),
        "warm_record": warm_record.to_dict(),
        "rollup": rollup,
        "rollup_role": rollup_role,
        "promotion": promotion,
    }
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

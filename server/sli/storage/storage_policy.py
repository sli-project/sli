from __future__ import annotations

import json
import os
import re
import shutil
import time
import zipfile
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal, Mapping, Sequence

from server.sli.core.app_config import AdLogConfig, load_config
from server.sli.events.event_catalog import lookup_event_catalog, lookup_event_descriptor
from server.sli.core.paths import DATA_DIR, DB_PATH, LOG_DIR, REPORTS_DIR, ROOT
from server.sli.ops.postgres_operations import get_postgres_operations_status
from server.sli.core.database import active_backend
from server.sli.storage.operations_storage import load_operations_storage_snapshot
from server.sli.storage.storage_policy_format import (
    _iso,
    _now_utc,
    fmt_bytes,
)
from server.sli.storage.storage_policy_read_types import (
    StorageReadAvailability,
    StorageReadPlan,
    StorageReadQueryKind,
    StorageReadRepresentation,
    StorageReadSegment,
    StorageReadTier,
    _require_utc_aware,
)
from server.sli.storage.storage_policy_catalog import (
    ResolvedRetentionPeriod,
    _PROMOTION_BUDGET_FIELDS,  # noqa: F401
    _PROMOTION_FIELDS,  # noqa: F401
    _SAFE_LEGACY_PROMOTION,
    _resolve_lifecycle_promotion,
    _retention_policy_fingerprint,
)
from server.sli.storage.storage_policy_capacity import (
    StorageCapacityProfile,
    _capacity_state,
    _growth_bytes_per_day,
    _load_storage_capacity_snapshots,
    _operator_guidance,
    _project_scan_warning,
    _snapshot_at,
    _snapshot_total_for_recommendation,
)
from server.sli.storage.storage_policy_fs import (
    ACTIVE_LOG_NAMES,  # noqa: F401
    PROTECTED_RAW_HINTS,
    PYTEST_RUN_NAME_RE,
    _action,
    _bounded_dir_size,
    _build_age_delete_actions,
    _file_age_days,
    _iter_files,
    _path_is_link_like,
    _pytest_active_marker,
    _raw_path_variants,
    _safe_stat,
    _scan_pytest_run_tree,
    _unique,
)

DEFAULT_DATA_DIR = DATA_DIR
MAINTENANCE_DIR = DATA_DIR / "maintenance"
STORAGE_CLEANUP_LAST = MAINTENANCE_DIR / "storage_cleanup_last.json"
RAW_ARCHIVE_DIR = DATA_DIR / "raw_archive"

# All retention defaults live here. Configuration only reports explicit raw
# overrides, and every consumer receives a resolved policy from this module.
DEFAULT_RAW_RETENTION_DAYS = 2
DEFAULT_DB_RETENTION_DAYS = 7
DEFAULT_WARM_RETENTION_DAYS = 365
DEFAULT_BACKUP_RETENTION_DAYS = 7
DEFAULT_LOG_RETENTION_DAYS = 14
DEFAULT_ARTIFACT_RETENTION_DAYS = 30
DEFAULT_POST_COLLECTION_RETENTION_DAYS = 30
DEFAULT_PYTEST_RUN_MIN_AGE_HOURS = 24
PYTEST_RUNS_DIR = DATA_DIR / "tmp" / "pytest-runs"












@dataclass(frozen=True)
class StoragePolicy:
    raw_retention_days: int = DEFAULT_RAW_RETENTION_DAYS
    raw_archive_enabled: bool = True
    raw_archive_compress: bool = True
    db_retention_days: int = DEFAULT_DB_RETENTION_DAYS
    relationship_retention_days: int = 30
    warm_retention_days: int = DEFAULT_WARM_RETENTION_DAYS
    backup_retention_days: int = DEFAULT_BACKUP_RETENTION_DAYS
    log_retention_days: int = DEFAULT_LOG_RETENTION_DAYS
    artifact_retention_days: int = DEFAULT_ARTIFACT_RETENTION_DAYS
    post_collection_retention_days: int = DEFAULT_POST_COLLECTION_RETENTION_DAYS
    archive_auto_delete_enabled: bool = False
    min_free_disk_percent: int = 15
    stop_collection_if_free_disk_percent_below: int = 10
    stop_collection_if_free_disk_bytes_below: int = 10 * 1024**3
    critical_free_disk_percent: int = 5
    cleanup_candidate_limit: int = 1000

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)




def resolve_storage_capacity_profile(
    selected_profile: StorageCapacityProfile | str | None,
    *,
    base_policy: StoragePolicy,
    overrides: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Resolve an explicitly selected capacity profile into the single policy.

    The function is intentionally pure: recommendations may call it for an
    explanation, but neither they nor a disk check can change the selected
    profile.  Per-field overrides are shown in the result rather than hidden
    in consumer-specific branches.
    """
    if selected_profile not in (None, "economy", "extended"):
        raise ValueError("storage_capacity_profile must be economy or extended")
    explicit = dict(overrides or {})
    unknown = set(explicit).difference(StoragePolicy.__dataclass_fields__)
    if unknown:
        raise ValueError(f"unknown storage policy override fields: {sorted(unknown)}")
    if selected_profile == "economy":
        policy = replace(base_policy, raw_archive_enabled=False, raw_archive_compress=False)
    else:
        policy = base_policy
    if explicit:
        policy = replace(policy, **explicit)
    if policy.raw_archive_enabled and int(policy.warm_retention_days) <= 0:
        raise ValueError("persistent raw archive requires a positive warm_retention_days boundary")
    return {
        "selected_profile": selected_profile,
        "effective_policy": policy.to_dict(),
        "overrides": explicit,
        "profile_state": "not_selected" if selected_profile is None else "confirmed_by_admin_config",
        "persistent_raw_archive": {
            "enabled": policy.raw_archive_enabled,
            "retention_days": policy.warm_retention_days if policy.raw_archive_enabled else None,
            "enforceable": (not policy.raw_archive_enabled) or int(policy.warm_retention_days) > 0,
        },
    }






def recommend_storage_capacity_profile(
    snapshots: Sequence[Mapping[str, Any]],
    *,
    selected_profile: StorageCapacityProfile | str | None,
    effective_policy: StoragePolicy,
) -> dict[str, Any]:
    """Make a read-only, explainable profile recommendation from stored facts."""
    valid = sorted(
        ((at, row) for row in snapshots if (at := _snapshot_at(row.get("captured_at"))) is not None),
        key=lambda item: item[0],
    )
    reset_after = 0
    positive: list[tuple[int, float]] = []
    for index in range(1, len(valid)):
        previous_at, previous = valid[index - 1]
        current_at, current = valid[index]
        elapsed_days = (current_at - previous_at).total_seconds() / 86400.0
        if elapsed_days <= 0:
            continue
        delta = _snapshot_total_for_recommendation(current) - _snapshot_total_for_recommendation(previous)
        if delta <= 0:
            reset_after = index
            positive.clear()
            continue
        if index >= reset_after:
            positive.append((delta, elapsed_days))
    if not valid or not positive:
        return {
            "selected_profile": selected_profile,
            "recommended_profile": "economy",
            "recommendation_changes_selection": False,
            "reason": "insufficient_growth_evidence",
            "inputs": {"valid_snapshots": len(valid), "positive_intervals_after_reset": 0},
            "growth_bytes_per_day": None,
            "required_capacity_bytes": None,
            "reserve_bytes": None,
        }
    growth = int(round(sum(delta for delta, _days in positive) / sum(days for _delta, days in positive)))
    latest = valid[-1][1]
    total = int(latest.get("disk_total_bytes") or 0)
    free = int(latest.get("disk_free_bytes") or 0)
    stop_percent = max(0, int(effective_policy.stop_collection_if_free_disk_percent_below))
    reserve = max(
        int(effective_policy.stop_collection_if_free_disk_bytes_below),
        int(total * stop_percent / 100.0),
    )
    bounded_days = max(
        int(effective_policy.db_retention_days),
        int(effective_policy.raw_retention_days),
        int(effective_policy.warm_retention_days) if effective_policy.raw_archive_enabled else 0,
    )
    required = growth * bounded_days
    usable = max(0, free - reserve)
    extended = usable >= required and growth > 0
    return {
        "selected_profile": selected_profile,
        "recommended_profile": "extended" if extended else "economy",
        "recommendation_changes_selection": False,
        "reason": "extended_capacity_sufficient" if extended else "bounded_lifecycle_exceeds_usable_capacity",
        "inputs": {
            "valid_snapshots": len(valid),
            "positive_intervals_after_reset": len(positive),
            "current_disk_free_bytes": free,
            "current_disk_total_bytes": total,
            "bounded_lifecycle_days": bounded_days,
        },
        "growth_bytes_per_day": growth,
        "required_capacity_bytes": required,
        "reserve_bytes": reserve,
        "usable_capacity_bytes": usable,
    }




@dataclass(frozen=True)
class EventRetentionResolution:
    raw_payload: ResolvedRetentionPeriod
    record: ResolvedRetentionPeriod
    warm_record: ResolvedRetentionPeriod
    rollup: str | None
    rollup_role: str | None
    catalogue_entry_found: bool
    promotion: Mapping[str, Any]
    policy_fingerprint: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw_payload": self.raw_payload.to_dict(),
            "record": self.record.to_dict(),
            "warm_record": self.warm_record.to_dict(),
            "rollup": self.rollup,
            "rollup_role": self.rollup_role,
            "catalogue_entry_found": self.catalogue_entry_found,
            "promotion": dict(self.promotion),
            "policy_fingerprint": self.policy_fingerprint,
        }










def plan_storage_read(
    *,
    query_kind: StorageReadQueryKind,
    time_from_utc: datetime,
    time_to_utc: datetime,
    now_utc: datetime,
    policy: StoragePolicy | None = None,
    warm_read_enabled: bool = False,
    warm_available: bool = False,
    archive_available: bool = False,
    descriptor_source: str | None = None,
    descriptor_stream: str | None = None,
    descriptor_event_key: str | None = None,
) -> StorageReadPlan:
    """Plan a tiered read without executing or enabling any storage route.

    The warm tier contains session analytics, not complete evidence. Atomic
    evidence outside the hot PostgreSQL window therefore always requires the
    canonical archive. Availability is explicit and fail-closed so a research
    ClickHouse instance cannot become a production reader by accident.
    """

    if query_kind not in ("session_analytics", "atomic_evidence"):
        raise ValueError(f"unknown storage read query kind: {query_kind!r}")
    descriptor_fields = (
        descriptor_source,
        descriptor_stream,
        descriptor_event_key,
    )
    if any(value is not None for value in descriptor_fields) and not all(descriptor_fields):
        raise ValueError("descriptor_source_stream_and_event_key_must_be_supplied_together")

    start = _require_utc_aware(time_from_utc, "time_from_utc")
    end = _require_utc_aware(time_to_utc, "time_to_utc")
    now = _require_utc_aware(now_utc, "now_utc")
    if start > end:
        raise ValueError("time_from_utc must not be after time_to_utc")
    if start == end:
        return StorageReadPlan(query_kind=query_kind, segments=(), complete=True, blockers=())

    resolved_policy = policy or StoragePolicy()
    descriptor_resolution = (
        resolve_descriptor_retention(
            descriptor_source,
            descriptor_stream,
            descriptor_event_key,
            policy=resolved_policy,
        )
        if all(descriptor_fields) else None
    )
    no_archive_descriptor = bool(
        descriptor_resolution is not None
        and descriptor_resolution.promotion.get("archive_requirement") == "no_archive"
        and descriptor_resolution.promotion.get("read_representation") == "derived_only"
    )
    hot_days = int(resolved_policy.db_retention_days)
    warm_days = int(resolved_policy.warm_retention_days)
    if hot_days <= 0:
        raise ValueError("db_retention_days must be positive")
    if warm_days <= hot_days:
        raise ValueError("warm_retention_days must be greater than db_retention_days")

    hot_cutoff = now - timedelta(days=hot_days)
    warm_cutoff = now - timedelta(days=warm_days)
    segments: list[StorageReadSegment] = []

    def append_segment(
        tier: StorageReadTier,
        segment_start: datetime,
        segment_end: datetime,
        representation: StorageReadRepresentation,
        ready: bool,
        blocker: str | None = None,
        availability: StorageReadAvailability = "data_unavailable",
    ) -> None:
        if segment_start < segment_end:
            segments.append(
                StorageReadSegment(
                    tier=tier,
                    time_from_utc=segment_start,
                    time_to_utc=segment_end,
                    representation=representation,
                    ready=ready,
                    blocker=blocker,
                    availability=availability,
                    source_link=None,
                )
            )

    archive_end = min(end, hot_cutoff)
    if start < archive_end:
        if no_archive_descriptor:
            cold_end = min(archive_end, warm_cutoff)
            append_segment(
                "clickhouse_warm",
                start,
                cold_end,
                "session",
                False,
                "data_unavailable",
                "data_unavailable",
            )
            warm_start = max(start, warm_cutoff)
            warm_ready = warm_read_enabled and warm_available
            if query_kind == "atomic_evidence":
                append_segment(
                    "clickhouse_warm",
                    warm_start,
                    archive_end,
                    "session",
                    False,
                    "atomic_evidence_unavailable_derived_only",
                    "derived_only_available",
                )
            else:
                warm_blocker = None
                if not warm_read_enabled:
                    warm_blocker = "warm_read_disabled"
                elif not warm_available:
                    warm_blocker = "warm_tier_unavailable"
                append_segment(
                    "clickhouse_warm",
                    warm_start,
                    archive_end,
                    "session",
                    warm_ready,
                    warm_blocker,
                    "derived_only_available" if warm_ready else "data_unavailable",
                )
        elif query_kind == "session_analytics":
            cold_end = min(archive_end, warm_cutoff)
            append_segment(
                "canonical_archive",
                start,
                cold_end,
                "full_payload",
                archive_available,
                None if archive_available else "canonical_archive_unavailable",
                "source_archived" if archive_available else "data_unavailable",
            )
            warm_start = max(start, warm_cutoff)
            warm_ready = warm_read_enabled and warm_available
            warm_blocker = None
            if not warm_read_enabled:
                warm_blocker = "warm_read_disabled"
            elif not warm_available:
                warm_blocker = "warm_tier_unavailable"
            append_segment(
                "clickhouse_warm",
                warm_start,
                archive_end,
                "session",
                warm_ready,
                warm_blocker,
                "derived_only_available" if warm_ready else "data_unavailable",
            )
        else:
            append_segment(
                "canonical_archive",
                start,
                archive_end,
                "full_payload",
                archive_available,
                None if archive_available else "canonical_archive_unavailable",
                "source_archived" if archive_available else "data_unavailable",
            )

    append_segment(
        "postgres_hot",
        max(start, hot_cutoff),
        end,
        "atomic_event",
        True,
        availability="atomic_evidence_available",
    )

    blockers = tuple(
        dict.fromkeys(
            segment.blocker
            for segment in segments
            if segment.blocker is not None
        )
    )
    return StorageReadPlan(
        query_kind=query_kind,
        segments=tuple(segments),
        complete=not blockers,
        blockers=blockers,
    )


def _configured_period(value: int | None, default: int) -> int:
    return int(default if value is None else value)


def _base_storage_policy(cfg: AdLogConfig) -> StoragePolicy:
    return StoragePolicy(
        raw_retention_days=_configured_period(cfg.raw_retention_days, DEFAULT_RAW_RETENTION_DAYS),
        raw_archive_enabled=bool(cfg.raw_archive_enabled),
        raw_archive_compress=bool(cfg.raw_archive_compress),
        db_retention_days=_configured_period(cfg.db_retention_days, DEFAULT_DB_RETENTION_DAYS),
        warm_retention_days=_configured_period(cfg.warm_retention_days, DEFAULT_WARM_RETENTION_DAYS),
        backup_retention_days=_configured_period(cfg.backup_retention_days, DEFAULT_BACKUP_RETENTION_DAYS),
        log_retention_days=_configured_period(cfg.log_retention_days, DEFAULT_LOG_RETENTION_DAYS),
        artifact_retention_days=_configured_period(cfg.artifact_retention_days, DEFAULT_ARTIFACT_RETENTION_DAYS),
        post_collection_retention_days=_configured_period(
            cfg.post_collection_retention_days,
            DEFAULT_POST_COLLECTION_RETENTION_DAYS,
        ),
        archive_auto_delete_enabled=bool(
            False if cfg.archive_auto_delete_enabled is None else cfg.archive_auto_delete_enabled
        ),
        min_free_disk_percent=int(cfg.min_free_disk_percent),
        stop_collection_if_free_disk_percent_below=int(cfg.stop_collection_if_free_disk_percent_below),
        stop_collection_if_free_disk_bytes_below=int(cfg.stop_collection_if_free_disk_bytes_below),
        critical_free_disk_percent=int(cfg.critical_free_disk_percent),
        cleanup_candidate_limit=_storage_cleanup_limit(),
    )


def get_storage_capacity_profile_resolution(config: AdLogConfig | None = None) -> dict[str, Any]:
    """Expose selected profile, effective policy, and explicit overrides."""
    cfg = config or load_config()
    configured_policy = _base_storage_policy(cfg)
    selected = getattr(cfg, "storage_capacity_profile", None)
    override_fields = tuple(
        getattr(cfg, "storage_capacity_profile_overrides", ())
        or getattr(cfg, "storage_policy_override_fields", ())
        or ()
    )
    base_policy = StoragePolicy(
        cleanup_candidate_limit=configured_policy.cleanup_candidate_limit,
    ) if selected is not None else configured_policy
    overrides = {field: getattr(configured_policy, field) for field in override_fields}
    return resolve_storage_capacity_profile(
        selected,
        base_policy=base_policy,
        overrides=overrides,
    )


def load_storage_policy(config: AdLogConfig | None = None) -> StoragePolicy:
    resolution = get_storage_capacity_profile_resolution(config)
    return StoragePolicy(**resolution["effective_policy"])


def _storage_cleanup_limit() -> int:
    raw = os.getenv("ADLOG_STORAGE_CLEANUP_LIMIT")
    if raw in (None, ""):
        return 1000
    try:
        return int(raw)
    except ValueError:
        return 1000


def _predicate_matches(actual: Any, operator: str, expected: Any) -> bool:
    expected_values = expected if isinstance(expected, list) else [expected]
    if operator == "equals":
        return any(actual == value or str(actual) == str(value) for value in expected_values)
    if operator == "one_of":
        return any(actual == value or str(actual) == str(value) for value in expected_values)

    actual_text = str(actual or "")
    if operator == "prefix":
        return any(actual_text.startswith(str(value)) for value in expected_values)
    if operator == "suffix":
        return any(actual_text.endswith(str(value)) for value in expected_values)
    if operator == "contains":
        return any(str(value) in actual_text for value in expected_values)
    if operator == "regex":
        return any(re.search(str(value), actual_text) is not None for value in expected_values)
    raise ValueError(f"unsupported lifecycle predicate operator: {operator!r}")


def _resolve_catalogue_days(value: Any, event: Mapping[str, Any]) -> int:
    if isinstance(value, bool):
        raise ValueError("lifecycle period must be an integer, not bool")
    if isinstance(value, int):
        return value
    if not isinstance(value, Mapping) or "default" not in value:
        raise ValueError("lifecycle period must be an integer or predicate with default")
    selected = value["default"]
    for rule in value.get("rules") or []:
        if not isinstance(rule, Mapping):
            raise ValueError("lifecycle predicate rule must be an object")
        field = str(rule.get("field") or "")
        operator = str(rule.get("op") or "")
        if _predicate_matches(event.get(field), operator, rule.get("value")):
            selected = rule.get("then")
            break
    if isinstance(selected, bool) or not isinstance(selected, int):
        raise ValueError("lifecycle predicate must resolve to an integer")
    return selected








def resolve_catalogue_retention(
    entry: Mapping[str, Any] | None,
    *,
    event: Mapping[str, Any] | None = None,
    policy: StoragePolicy | None = None,
) -> EventRetentionResolution:
    """Resolve catalogue lifecycle first and make every fallback explicit."""
    resolved_policy = policy or load_storage_policy()
    lifecycle = entry.get("lifecycle") if entry else None
    if not isinstance(lifecycle, Mapping):
        raw_payload = ResolvedRetentionPeriod(
            resolved_policy.raw_retention_days,
            "configuration",
            True,
            "raw_retention_days",
        )
        record = ResolvedRetentionPeriod(
            resolved_policy.db_retention_days,
            "configuration",
            True,
            "db_retention_days",
        )
        warm_record = ResolvedRetentionPeriod(
            resolved_policy.warm_retention_days,
            "configuration",
            True,
            "warm_retention_days",
        )
        promotion = dict(_SAFE_LEGACY_PROMOTION)
        return EventRetentionResolution(
            raw_payload=raw_payload,
            record=record,
            warm_record=warm_record,
            rollup=None,
            rollup_role=None,
            catalogue_entry_found=entry is not None,
            promotion=promotion,
            policy_fingerprint=_retention_policy_fingerprint(
                raw_payload=raw_payload,
                record=record,
                warm_record=warm_record,
                rollup=None,
                rollup_role=None,
                promotion=promotion,
            ),
        )

    event_payload = event or {}
    raw_days = _resolve_catalogue_days(lifecycle.get("raw_payload_days"), event_payload)
    record_days = _resolve_catalogue_days(lifecycle.get("record_days"), event_payload)
    warm_value = lifecycle.get("warm_record_days")
    warm_record = (
        ResolvedRetentionPeriod(
            _resolve_catalogue_days(warm_value, event_payload),
            "catalogue",
            False,
        )
        if warm_value is not None
        else ResolvedRetentionPeriod(
            resolved_policy.warm_retention_days,
            "configuration",
            True,
            "warm_retention_days",
        )
    )
    rollup = lifecycle.get("rollup")
    if rollup is not None and not isinstance(rollup, str):
        raise ValueError("lifecycle rollup must be a string or null")
    rollup_role = lifecycle.get("rollup_role")
    if rollup_role is not None and rollup_role not in {"open", "close", "boot_scope"}:
        raise ValueError("lifecycle rollup_role is invalid")
    promotion = _resolve_lifecycle_promotion(lifecycle)
    if promotion["high_volume"] and (rollup is None or rollup_role is None):
        raise ValueError("high-volume lifecycle requires rollup and rollup_role")
    raw_payload = ResolvedRetentionPeriod(raw_days, "catalogue", False)
    record = ResolvedRetentionPeriod(record_days, "catalogue", False)
    return EventRetentionResolution(
        raw_payload=raw_payload,
        record=record,
        warm_record=warm_record,
        rollup=rollup,
        rollup_role=rollup_role,
        catalogue_entry_found=True,
        promotion=promotion,
        policy_fingerprint=_retention_policy_fingerprint(
            raw_payload=raw_payload,
            record=record,
            warm_record=warm_record,
            rollup=rollup,
            rollup_role=rollup_role,
            promotion=promotion,
        ),
    )


def resolve_event_retention(
    event_id: int,
    *,
    channel: str | None = None,
    provider_name: str | None = None,
    event: Mapping[str, Any] | None = None,
    policy: StoragePolicy | None = None,
) -> EventRetentionResolution:
    entry = lookup_event_catalog(event_id, channel, provider_name)
    return resolve_catalogue_retention(entry, event=event, policy=policy)


def resolve_descriptor_retention(
    source: str,
    stream: str,
    event_key: str,
    *,
    event: Mapping[str, Any] | None = None,
    policy: StoragePolicy | None = None,
) -> EventRetentionResolution:
    entry = lookup_event_descriptor(source, stream, event_key)
    return resolve_catalogue_retention(entry, event=event, policy=policy)


def resolve_operational_retention(
    kind: Literal["post_collection_jobs"],
    *,
    policy: StoragePolicy | None = None,
) -> ResolvedRetentionPeriod:
    resolved_policy = policy or load_storage_policy()
    if kind == "post_collection_jobs":
        return ResolvedRetentionPeriod(
            resolved_policy.post_collection_retention_days,
            "configuration",
            False,
            "post_collection_retention_days",
        )
    raise ValueError(f"unknown operational retention kind: {kind!r}")


def disk_info(path: Path = ROOT) -> dict[str, Any]:
    usage = shutil.disk_usage(path)
    free_percent = round((usage.free / usage.total) * 100, 2) if usage.total else 0.0
    return {
        "path": str(path),
        "total_bytes": usage.total,
        "used_bytes": usage.used,
        "free_bytes": usage.free,
        "free_percent": free_percent,
        "total_human": fmt_bytes(usage.total),
        "used_human": fmt_bytes(usage.used),
        "free_human": fmt_bytes(usage.free),
    }


def disk_pressure_status(path: Path = ROOT, policy: StoragePolicy | None = None) -> dict[str, Any]:
    policy = policy or load_storage_policy()
    from server.sli.storage.storage_lifecycle import validate_storage_thresholds

    validation = validate_storage_thresholds(policy)
    effective = validation["effective"]
    warn_threshold = int(effective["warn_free_percent"])
    stop_threshold_percent = int(effective["stop_free_percent"])
    stop_threshold_bytes = max(
        1, int(policy.stop_collection_if_free_disk_bytes_below)
    )
    disk = disk_info(path)
    free = float(disk.get("free_percent") or 0)
    free_bytes = int(disk.get("free_bytes") or 0)
    status = "ok"
    collection_allowed = True
    reason = None
    if free_bytes < stop_threshold_bytes or free < stop_threshold_percent:
        status = "blocked"
        collection_allowed = False
        if free_bytes < stop_threshold_bytes and free < stop_threshold_percent:
            reason = (
                "Свободное место ниже обоих порогов остановки сбора: "
                f"{fmt_bytes(free_bytes)} < {fmt_bytes(stop_threshold_bytes)}; "
                f"{free}% < {stop_threshold_percent}%"
            )
            blocking_condition = "free_bytes_and_percent_below_stop"
        elif free_bytes < stop_threshold_bytes:
            reason = (
                "Свободное место ниже фиксированного порога сбора: "
                f"{fmt_bytes(free_bytes)} < {fmt_bytes(stop_threshold_bytes)}"
            )
            blocking_condition = "free_bytes_below_stop"
        else:
            reason = (
                "Свободное место ниже процентного порога остановки сбора: "
                f"{free}% < {stop_threshold_percent}%"
            )
            blocking_condition = "free_percent_below_stop"
    elif free < warn_threshold:
        status = "warn"
        reason = (
            f"Свободное место ниже рекомендованного уровня: "
            f"{free}% < {warn_threshold}%; сбор разрешён, "
            f"пороги остановки — {fmt_bytes(stop_threshold_bytes)} "
            f"или {stop_threshold_percent}%."
        )
        blocking_condition = "warning_only"
    else:
        blocking_condition = "none"
    if validation.get("status") != "ok" and reason is None:
        reason = "Некорректные storage thresholds; применены безопасные значения 15/10/5."
        status = "warn"
    return {
        "status": status,
        "collection_allowed": collection_allowed,
        "reason": reason,
        "disk": disk,
        "policy": policy.to_dict(),
        "blocking_threshold": {
            "mode": "free_bytes_or_percent",
            "condition": blocking_condition,
            "free_bytes": stop_threshold_bytes,
            "free_human": fmt_bytes(stop_threshold_bytes),
            "free_percent": stop_threshold_percent,
        },
        "threshold_validation": validation,
    }




def get_storage_runtime_capacity_evidence(
    *,
    snapshots: Sequence[Mapping[str, Any]] | None = None,
    now_utc: datetime | None = None,
    path: Path = ROOT,
    policy: StoragePolicy | None = None,
    history_limit: int = 120,
) -> dict[str, Any]:
    """Report measured 72-hour capacity evidence without changing runtime state."""
    effective_policy = policy or load_storage_policy()
    pressure = disk_pressure_status(path, effective_policy)
    disk = dict(pressure.get("disk") or {})
    threshold = dict(pressure.get("blocking_threshold") or {})
    disk_free_bytes = int(disk.get("free_bytes") or 0)
    disk_free_percent = float(disk.get("free_percent") or 0.0)
    disk_total_bytes = int(disk.get("total_bytes") or 0)
    stop_bytes = int(threshold.get("free_bytes") or 0)
    stop_percent = float(threshold.get("free_percent") or 0.0)
    effective_reserve = max(stop_bytes, int(disk_total_bytes * stop_percent / 100.0))
    snapshot_error: dict[str, str] | None = None
    if snapshots is None:
        try:
            rows = _load_storage_capacity_snapshots(limit=history_limit)
        except Exception as exc:
            rows = []
            snapshot_error = {"error_type": type(exc).__name__, "error": str(exc)}
    else:
        rows = [dict(row) for row in snapshots]

    now = (now_utc or _now_utc()).astimezone(timezone.utc)
    valid = sorted(
        ((at, row) for row in rows if (at := _snapshot_at(row.get("captured_at"))) is not None and at <= now),
        key=lambda item: item[0],
    )
    latest_at, latest = valid[-1] if valid else (None, None)
    baseline: tuple[datetime, dict[str, Any]] | None = None
    if latest_at is not None:
        eligible = [
            (at, row)
            for at, row in valid[:-1]
            if 72.0 <= (latest_at - at).total_seconds() / 3600.0 <= 96.0
        ]
        if eligible:
            baseline = min(
                eligible,
                key=lambda item: abs((latest_at - item[0]).total_seconds() / 3600.0 - 72.0),
            )

    measured: dict[str, Any] = {"quality": "unknown", "reason": "eligible_72_to_96_hour_baseline_required"}
    if baseline is not None and latest is not None and latest_at is not None:
        baseline_at, baseline_row = baseline
        elapsed_hours = (latest_at - baseline_at).total_seconds() / 3600.0
        elapsed_days = elapsed_hours / 24.0
        database_per_day = int(round((int(latest.get("database_bytes") or 0) - int(baseline_row.get("database_bytes") or 0)) / elapsed_days))
        disk_used_per_day = int(round((int(latest.get("disk_used_bytes") or 0) - int(baseline_row.get("disk_used_bytes") or 0)) / elapsed_days))
        operational_fields = ("database_bytes", "raw_bytes", "raw_archive_bytes", "logs_bytes", "reports_bytes")
        operational_per_day = int(round(sum(
            int(latest.get(field) or 0) - int(baseline_row.get(field) or 0)
            for field in operational_fields
        ) / elapsed_days))
        measured = {
            "quality": "measured_72h",
            "from": _iso(baseline_at),
            "to": _iso(latest_at),
            "elapsed_hours": round(elapsed_hours, 2),
            "database_bytes_per_day": database_per_day,
            "disk_used_bytes_per_day": disk_used_per_day,
            "operational_bytes_per_day": operational_per_day,
        }

    if not pressure.get("collection_allowed"):
        forecast = {"status": "already_at_or_below_stop", "estimated_days_to_stop": 0.0}
        status = "already_at_or_below_stop"
    elif measured["quality"] == "unknown":
        forecast = {"status": "unknown", "estimated_days_to_stop": None}
        status = "unknown"
    else:
        growth_rate = max(
            0,
            int(measured["operational_bytes_per_day"]),
            int(measured["database_bytes_per_day"]),
            int(measured["disk_used_bytes_per_day"]),
        )
        if growth_rate <= 0:
            forecast = {"status": "stable_or_nonpositive_growth", "estimated_days_to_stop": None}
        else:
            forecast = {
                "status": "ok",
                "estimated_days_to_stop": round(max(0, disk_free_bytes - effective_reserve) / growth_rate, 2),
                "growth_bytes_per_day_used": growth_rate,
            }
        status = "ok"
    return {
        "status": status,
        "read_only": True,
        "disk_free_bytes": disk_free_bytes,
        "disk_free_percent": disk_free_percent,
        "stop_threshold": {
            "mode": "free_bytes_or_percent",
            "condition": threshold.get("condition"),
            "free_bytes": stop_bytes,
            "free_percent": stop_percent,
            "effective_reserve_bytes": effective_reserve,
        },
        "measured_growth": measured,
        "forecast": forecast,
        "snapshot_count": len(valid),
        "snapshot_read_error": snapshot_error,
    }


def can_start_collection(path: Path = ROOT, policy: StoragePolicy | None = None) -> dict[str, Any]:
    return disk_pressure_status(path, policy)


def _read_last_cleanup() -> dict[str, Any] | None:
    path = (
        DATA_DIR / "maintenance" / "storage_cleanup_last.json"
        if DATA_DIR != DEFAULT_DATA_DIR
        else STORAGE_CLEANUP_LAST
    )
    try:
        return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None
    except (OSError, json.JSONDecodeError):
        return None


def _write_last_cleanup(result: dict[str, Any]) -> None:
    path = (
        DATA_DIR / "maintenance" / "storage_cleanup_last.json"
        if DATA_DIR != DEFAULT_DATA_DIR
        else STORAGE_CLEANUP_LAST
    )
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(result, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    except OSError:
        return


def _is_protected_raw(path: Path) -> tuple[bool, str | None]:
    # Protection hints must be evaluated only inside data/raw.  Looking at the
    # absolute path makes a project directory such as ``adlog_findings_work``
    # accidentally protect every raw file below it.
    try:
        lowered = path.resolve().relative_to((DATA_DIR / "raw").resolve()).as_posix().lower()
    except (OSError, ValueError):
        lowered = path.name.lower()
    if path.with_suffix(path.suffix + ".keep").exists() or path.with_suffix(path.suffix + ".evidence").exists():
        return True, "sidecar keep/evidence marker"
    for hint in PROTECTED_RAW_HINTS:
        if hint in lowered:
            return True, f"protected raw hint: {hint}"
    return False, None




def _confirmed_imported_raw_paths(paths: list[Path]) -> tuple[set[str] | None, dict[str, Any]]:
    """Return raw paths registered by a completed PostgreSQL import.

    ``None`` means the confirmation query was unavailable.  In PostgreSQL mode
    that is fail-safe: raw files remain in place instead of being archived on an
    assumption.  SQLite compatibility keeps the legacy file-age behavior for
    offline tests and historical tools.
    """
    if active_backend() != "postgres":
        return None, {"status": "not_required", "backend": active_backend()}
    variants: set[str] = set()
    for path in paths:
        variants.update(_raw_path_variants(path))
    if not variants:
        return set(), {"status": "ok", "backend": "postgres", "checked": 0, "confirmed": 0}
    try:
        from server.sli.core.postgres_runtime_pipeline import connect

        with connect() as conn:
            with conn.cursor() as cur:
                normalized_variants = sorted({item.lower() for item in variants})
                cur.execute(
                    "select file_path from raw_log_files where lower(file_path) = any(%s)",
                    (normalized_variants,),
                )
                confirmed = {str(row["file_path"]) for row in cur.fetchall()}
    except Exception as exc:
        return None, {
            "status": "unavailable",
            "backend": "postgres",
            "checked": len(variants),
            "error_type": type(exc).__name__,
            "error": str(exc),
        }
    normalized = set(confirmed)
    if os.name == "nt":
        normalized.update(item.lower() for item in confirmed)
    return normalized, {
        "status": "ok",
        "backend": "postgres",
        "checked": len(variants),
        "confirmed": len(confirmed),
    }


def _is_protected_artifact(path: Path) -> tuple[bool, str | None]:
    try:
        lowered = path.resolve().relative_to((ROOT / "artifacts").resolve()).as_posix().lower()
    except (OSError, ValueError):
        lowered = path.name.lower()
    if path.with_suffix(path.suffix + ".keep").exists() or path.with_suffix(path.suffix + ".evidence").exists():
        return True, "sidecar keep/evidence marker"
    for hint in ("acceptance", "evidence", "baseline", "handoff", "incident", "investigation"):
        if hint in lowered:
            return True, f"protected artifact hint: {hint}"
    return False, None














def build_pytest_run_cleanup_plan(
    *,
    min_age_hours: float = DEFAULT_PYTEST_RUN_MIN_AGE_HOURS,
    limit: int = 200,
) -> dict[str, Any]:
    """Plan removal of stale generated pytest trees and nothing else."""
    started = time.monotonic()
    root = PYTEST_RUNS_DIR.resolve()
    minimum_age = max(1.0, float(min_age_hours))
    candidate_limit = max(1, min(int(limit), 1000))
    now = _now_utc()
    actions: list[dict[str, Any]] = []
    excluded = {
        "recent": 0,
        "active_marker": 0,
        "invalid_name": 0,
        "top_level_link": 0,
        "scan_error": 0,
        "over_limit": 0,
    }
    scanned = 0
    if root.is_dir():
        for path in sorted(root.iterdir(), key=lambda item: item.name):
            if not path.is_dir():
                continue
            scanned += 1
            if _path_is_link_like(path):
                excluded["top_level_link"] += 1
                continue
            if not PYTEST_RUN_NAME_RE.fullmatch(path.name):
                excluded["invalid_name"] += 1
                continue
            if _pytest_active_marker(root, path.name).exists():
                excluded["active_marker"] += 1
                continue
            metrics = _scan_pytest_run_tree(path)
            if metrics["errors"]:
                excluded["scan_error"] += 1
                continue
            newest = datetime.fromtimestamp(
                float(metrics["newest_mtime"]), tz=timezone.utc
            )
            age_hours = max(0.0, (now - newest).total_seconds() / 3600)
            if age_hours < minimum_age:
                excluded["recent"] += 1
                continue
            if len(actions) >= candidate_limit:
                excluded["over_limit"] += 1
                continue
            actions.append({
                "category": "pytest_runs",
                "action": "delete_tree",
                "path": str(path.resolve()),
                "reason": f"generated pytest run inactive for at least {minimum_age:g} hours",
                "size_bytes": int(metrics["bytes"]),
                "size_human": fmt_bytes(int(metrics["bytes"])),
                "files": int(metrics["files"]),
                "directories": int(metrics["directories"]),
                "links_not_followed": int(metrics["links_not_followed"]),
                "newest_modified_utc": _iso(newest),
                "age_hours": round(age_hours, 2),
            })
    total = sum(int(item["size_bytes"]) for item in actions)
    return {
        "status": "ok",
        "mode": "dry-run",
        "category": "pytest_runs",
        "generated_at_utc": _iso(),
        "duration_ms": int((time.monotonic() - started) * 1000),
        "root": str(root),
        "min_age_hours": minimum_age,
        "limit": candidate_limit,
        "actions": actions,
        "total_candidates": len(actions),
        "total_bytes": total,
        "total_human": fmt_bytes(total),
        "scan": {
            "directories_seen": scanned,
            "excluded": {key: value for key, value in excluded.items() if value},
        },
        "safety": {
            "dry_run_default": True,
            "apply_requires_confirm_apply": True,
            "exact_generated_root_required": True,
            "immediate_children_only": True,
            "generated_name_required": True,
            "active_marker_preserved": True,
            "top_level_symbolic_links_rejected": True,
            "internal_links_not_followed": True,
            "production_runtime_data_touched": False,
        },
    }


def apply_pytest_run_cleanup_plan(
    plan: dict[str, Any],
    *,
    apply: bool = False,
    confirm_apply: bool = False,
) -> dict[str, Any]:
    """Apply a previously built pytest-only plan with path revalidation."""
    started = time.monotonic()
    result = dict(plan)
    result["mode"] = "apply" if apply else "dry-run"
    result["applied"] = []
    result["errors"] = []
    if not apply:
        return result
    if not confirm_apply:
        result["status"] = "failed"
        result["errors"].append({"error": "--apply requires --confirm-apply"})
        return result

    expected_root = PYTEST_RUNS_DIR.resolve()
    try:
        plan_root = Path(str(plan.get("root") or "")).resolve()
    except OSError as exc:
        result["status"] = "failed"
        result["errors"].append({
            "error_type": type(exc).__name__,
            "error": str(exc),
        })
        return result
    if plan_root != expected_root:
        result["status"] = "failed"
        result["errors"].append({
            "error": "pytest cleanup root mismatch",
            "expected": str(expected_root),
            "actual": str(plan_root),
        })
        return result

    for item in plan.get("actions") or []:
        path = Path(str(item.get("path") or ""))
        try:
            if item.get("action") != "delete_tree":
                raise ValueError("unsupported pytest cleanup action")
            if path.parent.resolve() != expected_root:
                raise ValueError("candidate is outside the pytest-runs root")
            if not PYTEST_RUN_NAME_RE.fullmatch(path.name):
                raise ValueError("candidate does not have a generated pytest name")
            if _pytest_active_marker(expected_root, path.name).exists():
                raise ValueError("candidate has an active-run marker")
            if _path_is_link_like(path):
                raise ValueError("candidate is a symbolic link or junction")
            if not path.exists():
                result["errors"].append({
                    "path": str(path),
                    "error": "candidate missing",
                })
                continue
            if not path.is_dir():
                raise ValueError("candidate is not a directory")
            metrics = _scan_pytest_run_tree(path)
            if metrics["errors"]:
                raise ValueError("candidate failed safe recursive revalidation")
            newest = datetime.fromtimestamp(
                float(metrics["newest_mtime"]), tz=timezone.utc
            )
            age_hours = max(0.0, (_now_utc() - newest).total_seconds() / 3600)
            if age_hours < float(plan.get("min_age_hours") or 0):
                raise ValueError("candidate became newer than the accepted age boundary")
            shutil.rmtree(path)
            if path.exists():
                raise OSError("candidate still exists after recursive cleanup")
            result["applied"].append({
                "action": "delete_tree",
                "path": str(path),
                "size_bytes": int(metrics["bytes"]),
                "files": int(metrics["files"]),
                "directories": int(metrics["directories"]),
                "links_not_followed": int(metrics["links_not_followed"]),
            })
        except (OSError, ValueError) as exc:
            result["errors"].append({
                "path": str(path),
                "error_type": type(exc).__name__,
                "error": str(exc),
            })
    result["applied_count"] = len(result["applied"])
    result["applied_bytes"] = sum(
        int(item.get("size_bytes") or 0) for item in result["applied"]
    )
    result["applied_human"] = fmt_bytes(result["applied_bytes"])
    result["status"] = "warn" if result["errors"] else "ok"
    result["duration_ms"] = int((time.monotonic() - started) * 1000)
    return result


def _build_raw_actions(policy: StoragePolicy, *, limit: int, deep: bool) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    raw_dir = DATA_DIR / "raw"
    files, scan = _iter_files(raw_dir, max_entries=(20000 if deep else 5000), max_seconds=(10.0 if deep else 2.5))
    cutoff_days = max(0, int(policy.raw_retention_days))
    confirmed_paths, import_check = _confirmed_imported_raw_paths(files)
    actions: list[dict[str, Any]] = []
    excluded = {
        "recent": 0,
        "protected": 0,
        "not_confirmed_imported": 0,
        "import_confirmation_unavailable": 0,
        "archive_disabled": 0,
        "over_limit": 0,
        "stat_error": 0,
    }
    for path in sorted(files):
        st = _safe_stat(path)
        if not st:
            excluded["stat_error"] += 1
            continue
        age = _file_age_days(path)
        if age is None or age < cutoff_days:
            excluded["recent"] += 1
            continue
        protected, _protected_reason = _is_protected_raw(path)
        if protected:
            excluded["protected"] += 1
            continue
        if active_backend() == "postgres":
            if confirmed_paths is None:
                excluded["import_confirmation_unavailable"] += 1
                continue
            variants = _raw_path_variants(path)
            if not any(item in confirmed_paths for item in variants):
                excluded["not_confirmed_imported"] += 1
                continue
        if len(actions) >= limit:
            excluded["over_limit"] += 1
            continue
        rel = path.relative_to(raw_dir) if raw_dir in path.parents else Path(path.name)
        if not policy.raw_archive_enabled:
            actions.append(_action(path, "delete_file", f"raw older than {cutoff_days} days with confirmed successful import and archive disabled", "raw"))
        elif policy.raw_archive_compress:
            target = RAW_ARCHIVE_DIR / f"raw_archive_{_now_utc().strftime('%Y%m%d_%H%M%S')}.zip"
            actions.append(_action(path, "archive_zip", f"raw older than {cutoff_days} days with confirmed successful import", "raw", target))
        else:
            actions.append(_action(path, "archive_move", f"raw older than {cutoff_days} days with confirmed successful import", "raw", RAW_ARCHIVE_DIR / rel))
    scan["import_confirmation"] = import_check
    scan["excluded"] = {k: v for k, v in excluded.items() if v}
    return actions, scan



def _build_technical_artifact_actions(policy: StoragePolicy, *, limit: int, deep: bool) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    root = ROOT / "artifacts"
    files, scan = _iter_files(root, max_entries=(10000 if deep else 3000), max_seconds=(5.0 if deep else 1.5))
    days = max(1, int(policy.artifact_retention_days))
    actions: list[dict[str, Any]] = []
    excluded = {"recent": 0, "protected": 0, "over_limit": 0, "stat_error": 0}
    for path in sorted(files):
        st = _safe_stat(path)
        if not st:
            excluded["stat_error"] += 1
            continue
        age = _file_age_days(path)
        if age is None or age < days:
            excluded["recent"] += 1
            continue
        protected, _reason = _is_protected_artifact(path)
        if protected:
            excluded["protected"] += 1
            continue
        if len(actions) >= limit:
            excluded["over_limit"] += 1
            continue
        actions.append(_action(path, "delete_file", f"technical artifact older than {days} days", "technical_artifacts"))
    scan["excluded"] = {k: v for k, v in excluded.items() if v}
    return actions, scan


def build_storage_cleanup_plan(
    *,
    deep: bool = False,
    limit: int | None = None,
    policy: StoragePolicy | None = None,
) -> dict[str, Any]:
    policy = policy or load_storage_policy()
    candidate_limit = int(limit if limit is not None else policy.cleanup_candidate_limit)
    started = time.monotonic()
    raw_actions, raw_scan = _build_raw_actions(policy, limit=candidate_limit, deep=deep)
    remaining = max(0, candidate_limit - len(raw_actions))
    raw_archive_actions: list[dict[str, Any]] = []
    raw_archive_scan: dict[str, Any] = {"status": "not_applicable"}
    if policy.raw_archive_enabled:
        raw_archive_actions, raw_archive_scan = _build_age_delete_actions(
            RAW_ARCHIVE_DIR,
            days=policy.warm_retention_days,
            category="raw_archive",
            limit=remaining,
            deep=deep,
        )
    remaining = max(0, remaining - len(raw_archive_actions))
    backup_actions, backup_scan = _build_age_delete_actions(DATA_DIR / "backups", days=policy.backup_retention_days, category="backups", limit=remaining, deep=deep)
    remaining = max(0, remaining - len(backup_actions))
    legacy_backup_actions, legacy_backup_scan = _build_age_delete_actions(ROOT / "backups", days=policy.backup_retention_days, category="legacy_backups", limit=remaining, deep=deep)
    remaining = max(0, remaining - len(legacy_backup_actions))
    log_actions, log_scan = _build_age_delete_actions(LOG_DIR, days=policy.log_retention_days, category="logs", limit=remaining, deep=deep)
    remaining = max(0, remaining - len(log_actions))
    artifact_actions, artifact_scan = _build_technical_artifact_actions(policy, limit=remaining, deep=deep)
    actions = raw_actions + raw_archive_actions + backup_actions + legacy_backup_actions + log_actions + artifact_actions
    # The runtime database is PostgreSQL; a leftover SQLite file is not read here.
    sqlite_plan = {"status": "not_applicable", "reason": "runtime database is PostgreSQL; SQLite retention is not part of the product"}
    total = sum(int(item.get("size_bytes") or 0) for item in actions)
    return {
        "status": "ok",
        "mode": "dry-run",
        "generated_at_utc": _iso(),
        "duration_ms": int((time.monotonic() - started) * 1000),
        "policy": policy.to_dict(),
        "deep": deep,
        "limit": candidate_limit,
        "actions": actions,
        "total_candidates": len(actions),
        "total_bytes": total,
        "total_human": fmt_bytes(total),
        "sqlite_retention": sqlite_plan,
        "scan": {"raw": raw_scan, "raw_archive": raw_archive_scan, "backups": backup_scan, "legacy_backups": legacy_backup_scan, "logs": log_scan, "technical_artifacts": artifact_scan},
        "safety": {
            "dry_run_default": True,
            "failed_partial_raw_preserved": True,
            "evidence_raw_preserved": True,
            "vacuum_automatic": False,
            "apply_requires_confirm_apply": True,
            "raw_delete_automatic": False,
            "archive_verified_before_source_remove": True,
            "raw_requires_confirmed_postgres_import": active_backend() == "postgres",
            "acceptance_evidence_artifacts_preserved": True,
        },
    }




def apply_storage_cleanup_plan(plan: dict[str, Any], *, apply: bool = False, confirm_apply: bool = False) -> dict[str, Any]:
    started = time.monotonic()
    result = dict(plan)
    result["mode"] = "apply" if apply else "dry-run"
    result["applied"] = []
    result["errors"] = []
    if not apply:
        _write_last_cleanup(result)
        return result
    if not confirm_apply:
        result["status"] = "failed"
        result["errors"].append({"error": "--apply requires --confirm-apply"})
        _write_last_cleanup(result)
        return result
    zip_groups: dict[str, list[dict[str, Any]]] = {}
    for item in plan.get("actions") or []:
        action = item.get("action")
        path = Path(str(item.get("path") or ""))
        try:
            if action == "archive_zip":
                zip_groups.setdefault(str(item.get("target") or RAW_ARCHIVE_DIR / f"raw_archive_{_now_utc().strftime('%Y%m%d_%H%M%S')}.zip"), []).append(item)
                continue
            if action == "archive_move":
                target = _unique(Path(str(item.get("target"))))
                if not path.exists() or not path.is_file():
                    result["errors"].append({"path": str(path), "error": "source missing"})
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(path), str(target))
                result["applied"].append({"action": action, "from": str(path), "to": str(target), "size_bytes": item.get("size_bytes")})
            elif action == "delete_file":
                if path.exists() and path.is_file():
                    path.unlink()
                    result["applied"].append({"action": action, "path": str(path), "size_bytes": item.get("size_bytes")})
        except OSError as exc:
            result["errors"].append({"path": str(path), "error_type": type(exc).__name__, "error": str(exc)})
    for target_text, items in zip_groups.items():
        zip_path = _unique(Path(target_text))
        staged: list[tuple[Path, str, int]] = []
        try:
            zip_path.parent.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
                for item in items:
                    src = Path(str(item.get("path")))
                    if not src.exists() or not src.is_file():
                        result["errors"].append({"path": str(src), "error": "source missing"})
                        continue
                    rel = src.relative_to(DATA_DIR / "raw").as_posix() if DATA_DIR / "raw" in src.parents else src.name
                    source_size = int(src.stat().st_size)
                    zf.write(src, rel)
                    staged.append((src, rel, source_size))
            verification_errors: list[dict[str, Any]] = []
            with zipfile.ZipFile(zip_path, "r") as zf:
                bad_member = zf.testzip()
                if bad_member:
                    verification_errors.append({"path": str(zip_path), "error": f"zip CRC verification failed: {bad_member}"})
                members = {info.filename: info for info in zf.infolist()}
                for src, rel, source_size in staged:
                    info = members.get(rel)
                    if info is None:
                        verification_errors.append({"path": str(src), "error": f"archive member missing: {rel}"})
                    elif int(info.file_size) != source_size:
                        verification_errors.append({"path": str(src), "error": f"archive size mismatch: {rel}"})
            if verification_errors:
                result["errors"].extend(verification_errors)
                result.setdefault("archive_verification", []).append({"zip": str(zip_path), "status": "failed", "files": len(staged)})
                continue
            result.setdefault("archive_verification", []).append({"zip": str(zip_path), "status": "verified", "files": len(staged)})
            for src, rel, source_size in staged:
                try:
                    src.unlink()
                    result["applied"].append({"action": "archive_zip", "from": str(src), "zip": str(zip_path), "archive_name": rel, "size_bytes": source_size, "verified": True})
                except OSError as exc:
                    result["errors"].append({"path": str(src), "error_type": type(exc).__name__, "error": str(exc)})
        except (OSError, zipfile.BadZipFile) as exc:
            result["errors"].append({"path": str(zip_path), "error_type": type(exc).__name__, "error": str(exc)})
    result["status"] = "warn" if result["errors"] else "ok"
    result["duration_ms"] = int((time.monotonic() - started) * 1000)
    _write_last_cleanup(result)
    return result




def get_capacity_plan(policy: StoragePolicy | None = None) -> dict[str, Any]:
    policy = policy or load_storage_policy()
    disk = disk_info(ROOT)
    growth = _growth_bytes_per_day([DATA_DIR / "raw", DATA_DIR / "processed", DATA_DIR / "logs"], lookback_hours=24)
    gb_per_day = float(growth.get("gb_per_day") or 0)
    days_until_full = None if gb_per_day <= 0 else round((int(disk["free_bytes"]) / 1024**3) / gb_per_day, 1)
    current_servers = int(os.getenv("ADLOG_CAPACITY_CURRENT_SERVERS", "2") or "2")
    model = []
    for servers in (2, 5, 10):
        multiplier = servers / max(1, current_servers)
        projected = gb_per_day * multiplier
        model.append({"servers": servers, "projected_gb_per_day": round(projected, 2), "projected_days_until_full": None if projected <= 0 else round((int(disk["free_bytes"]) / 1024**3) / projected, 1)})
    return {"disk": disk, "observed_growth": growth, "days_until_full": days_until_full, "server_model": model, "policy": policy.to_dict()}


def _legacy_sqlite_lifecycle() -> dict[str, Any]:
    backend = active_backend()
    st = _safe_stat(DB_PATH)
    return {
        "active_backend": backend,
        "path": str(DB_PATH),
        "exists": bool(st),
        "bytes": int(st.st_size) if st else 0,
        "human": fmt_bytes(int(st.st_size) if st else 0),
        "runtime_access_allowed": backend != "postgres",
        "policy": "frozen_rollback_copy" if backend == "postgres" else "active_runtime_database",
        "automatic_delete": False,
        "operator_decision_required": backend == "postgres",
        "note": "Legacy SQLite is retained as a rollback/evidence copy and is not an automatic cleanup target." if backend == "postgres" else "SQLite is the active runtime backend.",
    }






def get_storage_health(*, deep: bool = False) -> dict[str, Any]:
    from server.sli.storage.purge_audit import last_purge_runs
    policy = load_storage_policy()
    sizes = {
        "raw": _bounded_dir_size(DATA_DIR / "raw", max_entries=20000 if deep else 5000, max_seconds=8.0 if deep else 2.0),
        "raw_archive": _bounded_dir_size(RAW_ARCHIVE_DIR, max_entries=5000 if deep else 1000, max_seconds=3.0 if deep else 1.0),
        "processed": _bounded_dir_size(DATA_DIR / "processed", max_entries=3000, max_seconds=2.0),
        "sqlite": _bounded_dir_size(DB_PATH, max_entries=1, max_seconds=0.1),
        "backups": _bounded_dir_size(DATA_DIR / "backups", max_entries=3000, max_seconds=2.0),
        "legacy_backups": _bounded_dir_size(ROOT / "backups", max_entries=3000, max_seconds=2.0),
        "logs": _bounded_dir_size(LOG_DIR, max_entries=3000, max_seconds=1.5),
        "reports": _bounded_dir_size(REPORTS_DIR, max_entries=3000, max_seconds=1.5),
        "diagnostics": _bounded_dir_size(DATA_DIR / "diagnostics", max_entries=1000, max_seconds=1.0),
        "handoff": _bounded_dir_size(DATA_DIR / "handoff", max_entries=1000, max_seconds=1.0),
        "artifacts": _bounded_dir_size(ROOT / "artifacts", max_entries=3000, max_seconds=1.5),
    }
    pressure = disk_pressure_status(ROOT, policy)
    cleanup_plan = build_storage_cleanup_plan(deep=False, limit=100)
    capacity = get_capacity_plan(policy)
    capacity_state = _capacity_state(capacity)
    legacy_sqlite = _legacy_sqlite_lifecycle()
    postgres_operations = get_postgres_operations_status(table_limit=30 if deep else 15)
    try:
        from server.sli.storage.storage_lifecycle import get_storage_lifecycle_status

        storage_lifecycle = get_storage_lifecycle_status(history_limit=72 if deep else 48, include_estimate=True) if active_backend() == "postgres" else {"status": "not_applicable", "backend": active_backend()}
    except Exception as exc:
        storage_lifecycle = {"status": "unavailable", "error_type": type(exc).__name__, "error": str(exc)}
    # One complete project scan provides an honest headline number.  PostgreSQL
    # keeps its data outside the repository tree, so add it separately instead
    # of pretending the on-disk project folder is the whole system.
    try:
        from server.sli.storage.runtime_storage import get_runtime_storage_summary

        project_files = get_runtime_storage_summary(ROOT)
        project_file_bytes = int(((project_files.get("sizes") or {}).get("project") or {}).get("bytes") or 0)
        database_bytes = int(((postgres_operations.get("database") or {}).get("database_bytes")) or 0)
        growth = storage_lifecycle.get("measured_growth") or storage_lifecycle.get("fallback_estimate") or {}
        forecast = storage_lifecycle.get("forecast") or {}
        previous_database_bytes = int(((storage_lifecycle.get("latest_snapshot") or {}).get("database_bytes")) or 0)
        # A major migration/reclaim makes an older rate mathematically true but
        # operationally irrelevant. Wait for a new baseline instead.
        growth_ready = not previous_database_bytes or not database_bytes or abs(previous_database_bytes - database_bytes) / max(previous_database_bytes, database_bytes) < 0.25
        project_overview = {
            "project_files_bytes": project_file_bytes,
            "project_files_human": fmt_bytes(project_file_bytes),
            "database_bytes": database_bytes,
            "database_human": fmt_bytes(database_bytes),
            "total_bytes": project_file_bytes + database_bytes,
            "total_human": fmt_bytes(project_file_bytes + database_bytes),
            "growth_bytes_per_day": int(growth.get("operational_bytes_per_day") or growth.get("managed_bytes_per_day") or growth.get("estimated_managed_bytes_per_day") or 0) if growth_ready else 0,
            "growth_human_per_day": (growth.get("operational_per_day_human") or growth.get("managed_per_day_human") or growth.get("estimated_managed_per_day_human") or "пока недостаточно наблюдений") if growth_ready else "измерение начинается",
            "growth_quality": (growth.get("quality") or "pending") if growth_ready else "baseline_changed",
            "forecast": forecast if growth_ready else {},
            "scan": project_files.get("scan") or {},
        }
    except Exception as exc:
        project_overview = {"status": "unavailable", "reason": type(exc).__name__}
    warnings: list[str] = []
    if pressure["status"] in {"warn", "blocked", "critical"}:
        warnings.append(str(pressure.get("reason") or "disk pressure"))
    if int(sizes["raw"].get("bytes") or 0) > 1024**3:
        warnings.append(f"data/raw is larger than 1 GB: {sizes['raw'].get('human')}")
    if int(sizes["processed"].get("bytes") or 0) > 5 * 1024**3:
        label = "legacy SQLite/processed" if active_backend() == "postgres" else "processed/SQLite"
        warnings.append(f"{label} is larger than 5 GB: {sizes['processed'].get('human')}")
    if capacity_state.get("status") in {"critical", "high", "warn"}:
        warnings.append(f"capacity forecast: {capacity_state.get('days_until_full')} days until full at observed growth")
    if cleanup_plan.get("total_candidates"):
        warnings.append(f"cleanup candidates available: {cleanup_plan.get('total_candidates')} files / {cleanup_plan.get('total_human')}")
    if postgres_operations.get("status") == "failed":
        warnings.append("PostgreSQL operations metrics are unavailable")
    warnings.extend(str(item) for item in (postgres_operations.get("warnings") or []))
    if storage_lifecycle.get("status") in {"warn", "unavailable"}:
        warnings.append("Storage lifecycle status requires operator attention")
    project_scan_warning = _project_scan_warning(project_overview)
    if project_scan_warning:
        warnings.append(project_scan_warning)
    return {
        "generated_at_utc": _iso(),
        "status": "critical" if pressure["status"] == "critical" else ("warn" if warnings or pressure["status"] in {"warn", "blocked"} else "ok"),
        "warnings": warnings,
        "policy": policy.to_dict(),
        "disk_pressure": pressure,
        "sizes": sizes,
        "cleanup_preview": {k: cleanup_plan.get(k) for k in ("mode", "total_candidates", "total_bytes", "total_human", "safety", "sqlite_retention")},
        "last_cleanup": _read_last_cleanup(),
        "capacity_plan": capacity,
        "capacity_state": capacity_state,
        "legacy_sqlite_lifecycle": legacy_sqlite,
        "postgres_operations": postgres_operations,
        "storage_lifecycle": storage_lifecycle,
        "purge_runs": last_purge_runs(),
        "project_overview": project_overview,
        "operator_guidance": _operator_guidance(pressure, cleanup_plan, postgres_operations, storage_lifecycle),
    }


def get_operations_storage_summary(postgres_operations: dict[str, Any]) -> dict[str, Any]:
    """Return a fast, honest storage summary for the frequently refreshed operations UI.

    The full storage-health endpoint performs bounded filesystem inventories,
    cleanup planning and lifecycle forecasting.  Repeating that work every 30
    seconds blocks the operations page and duplicates PostgreSQL metrics.  This
    summary reuses the PostgreSQL size already read for this request and reads
    the latest operator-generated complete footprint snapshot.  It never runs
    filesystem traversal or Docker commands in the HTTP request path.
    """
    policy = load_storage_policy()
    pressure = disk_pressure_status(ROOT, policy)
    database = dict(postgres_operations.get("database") or {})
    database_bytes = int(database.get("database_bytes") or 0)
    footprint = load_operations_storage_snapshot()
    totals = dict(footprint.get("totals") or {})
    warnings: list[str] = []
    if pressure.get("status") in {"warn", "blocked", "critical"}:
        warnings.append(str(pressure.get("reason") or "disk pressure"))
    if postgres_operations.get("available") is False:
        warnings.append("PostgreSQL database size is unavailable.")
    if footprint.get("status") in {"partial", "stale", "unavailable"}:
        warnings.extend(str(item) for item in (footprint.get("warnings") or []))
    status = "critical" if pressure.get("status") == "critical" else ("warn" if warnings else "ok")
    return {
        "generated_at_utc": _iso(),
        "status": status,
        "warnings": warnings,
        "disk_pressure": pressure,
        "project_overview": {
            "database_bytes": database_bytes or None,
            "database_human": database.get("database_human"),
            "total_bytes": totals.get("accounted_bytes"),
            "total_human": totals.get("accounted_human"),
            "scope": "deduplicated_known_project_footprint",
            "complete": footprint.get("status") == "ok",
        },
        "footprint": footprint,
        "limitations": [
            "PostgreSQL is represented by pg_database_size rather than a measured physical data directory.",
            "Docker image raw sizes are shown separately and excluded from the total because layers may be shared.",
            "Refresh the footprint with scripts/maintenance/operations_storage_snapshot.py; the HTTP endpoint never starts a scan.",
        ],
        "read_only": True,
    }



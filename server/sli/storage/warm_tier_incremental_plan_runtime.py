#!/usr/bin/env python3
# ruff: noqa: F401 -- re-export hub (plan 7.2b): split-out modules read these
# names through ``warm_tier_incremental_plan_runtime`` at call time.
"""Plan one exact gap-safe warm-tier batch without changing any storage.

The planner never treats ``max(event_id)`` as a copy cursor: source IDs follow
ingestion order while event timestamps can arrive out of order.  It scans the
bounded time interval that has matured out of the seven-day hot window, asks
ClickHouse which exact source IDs are already present, and freezes only the
missing IDs.  A legacy recovery anchor covers batches published by the former
max-ID planner.

It does not copy rows, start workers, change routing, or authorize deletion.

The real implementation lives here (production-grade module, shared by
``server.sli.storage.warm_tier_incremental_copy_runtime``'s ``drain_warm_tier_backlog``).
``scripts/maintenance/warm_tier_incremental_plan.py`` is a thin CLI wrapper
kept for manual/acceptance use and backward compatibility; it holds no logic
of its own.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.sources.source_capture_continuity import (
    BOOT_EVENT_KEY,  # noqa: E402
    RANGE_CONTRACT_ID,
    CaptureContinuityError,
    prepare_descriptor_range,
)
from server.sli.storage.postgres_profile_retention import (
    direct_no_archive_descriptors,  # noqa: E402
)
from server.sli.storage.storage_lifecycle_io import (  # noqa: E402
    CONTAINER,
    DATABASE,
    _connect,
    _container_port,
    _http_query,
)
from server.sli.storage.storage_policy import (  # noqa: E402
    StoragePolicy,
    load_storage_policy,
    resolve_descriptor_retention,
)

DEFAULT_BATCH_LIMIT = 10_000
MAX_BATCH_LIMIT = 10_000
MAX_DURABLE_DECLARATION_SCAN = 10_000
MAX_DECLARATION_MEMBERS = 10_000
MAX_DECLARATION_IDS = 10_000
MAX_SOURCE_REFERENCES = 10_000
DEFAULT_SCAN_LIMIT = 500_000
MAX_SCAN_LIMIT = 2_000_000
SCAN_PAGE_ROWS = 10_000
SELECTION_MODE = "missing_placement_time_window_v2"
LEGACY_SELECTION_MODE = "legacy_max_event_id_v1"
CURSOR_OVERLAP = timedelta(minutes=5)
DEFAULT_OUTPUT = (
    ROOT / "artifacts" / "stage7" / "evidence"
    / "warm-tier-incremental-plan.json"
)


@dataclass(frozen=True)
class IncrementalInputs:
    warm_available: bool
    warm_rows: int
    warm_max_event_id: int
    source_rows: int
    source_max_event_id: int
    appended_rows: int
    eligible_rows: int
    planned_rows: int
    archive_missing: int
    batch_truncated: bool
    reconciliation_anchor_available: bool = True
    candidate_scan_complete: bool = True
    scanned_rows: int = 0
    already_present_rows: int = 0
    gap_rows_at_or_below_warm_max: int = 0
    batch_filled: bool = False








def assess_incremental(
    policy: StoragePolicy,
    inputs: IncrementalInputs,
) -> dict[str, Any]:
    blockers: list[str] = []
    if policy.db_retention_days != 7:
        blockers.append("hot_window_is_not_owner_approved_7_days")
    if policy.warm_retention_days != 365:
        blockers.append("warm_window_is_not_owner_approved_365_days")
    if policy.archive_auto_delete_enabled:
        blockers.append("archive_auto_delete_must_remain_disabled")
    if not inputs.warm_available:
        blockers.append("isolated_warm_tier_unavailable")
    if inputs.warm_rows <= 0 or inputs.warm_max_event_id <= 0:
        blockers.append("warm_baseline_is_empty")
    if inputs.source_max_event_id < inputs.warm_max_event_id:
        blockers.append("source_high_watermark_precedes_warm_baseline")
    if not inputs.reconciliation_anchor_available:
        blockers.append("warm_reconciliation_anchor_missing")
    if (
        not inputs.candidate_scan_complete
        and not inputs.batch_filled
    ):
        blockers.append("candidate_scan_limit_exceeded_before_exact_result")
    if inputs.planned_rows > inputs.eligible_rows:
        blockers.append("planned_batch_exceeds_candidate_rows")
    if inputs.archive_missing:
        blockers.append("planned_rows_missing_published_archive_coverage")

    if blockers:
        status = "blocked"
    elif inputs.planned_rows == 0:
        status = "waiting_for_data_accumulation"
    else:
        status = "ready_for_manual_bounded_copy"

    return {
        "status": status,
        "mode": "read_only_plan",
        "policy": {
            "hot_days": policy.db_retention_days,
            "warm_days": policy.warm_retention_days,
            "archive_auto_delete_enabled": policy.archive_auto_delete_enabled,
        },
        "technical_gate_passed": not blockers,
        "blockers": blockers,
        "measurements": asdict(inputs),
        "manual_action": {
            "required": inputs.planned_rows > 0 and not blockers,
            "authorized_by_this_plan": False,
            "copy_performed": False,
            "routing_changed": False,
            "delete_performed": False,
        },
    }


# Bounds applied to every read-only metadata query below, via ClickHouse
# HTTP query parameters -- the exact equivalent of the
# ``--readonly 1 --max_execution_time 30 --max_memory_usage 536870912
# --max_threads 2`` flags the previous ``docker exec clickhouse-client``
# invocation passed on its command line.
_READONLY_QUERY_SETTINGS = {
    "readonly": "1",
    "max_execution_time": "30",
    "max_memory_usage": "536870912",
    "max_threads": "2",
}






def _parse_utc(value: Any) -> datetime:
    text = str(value or "").strip().replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)




def _effective_selection_lower(
    anchor: datetime,
    planned: list[dict[str, Any]],
) -> datetime:
    return min(
        (anchor, *(row["time_created_utc"] for row in planned)),
    )




def select_missing_rows(
    rows: list[dict[str, Any]],
    present_ids: set[int],
    *,
    limit: int,
) -> list[dict[str, Any]]:
    """Pure exact set-difference used by the live planner and regression tests."""
    return [row for row in rows if int(row["id"]) not in present_ids][:limit]


def _direct_no_archive_exclusion() -> tuple[
    list[str], list[int], list[str], list[str],
]:
    descriptors = direct_no_archive_descriptors(load_storage_policy())
    return (
        [str(item["source"]) for item in descriptors],
        [int(item["event_key"]) for item in descriptors],
        [str(item["stream"]) for item in descriptors],
        [str(item["provider_name"]) for item in descriptors],
    )


















def build_plan(
    batch_limit: int = DEFAULT_BATCH_LIMIT,
    scan_limit: int = DEFAULT_SCAN_LIMIT,
    *,
    port: int | None = None,
    declaration_after_id: int = 0,
    processed_declaration_ids: set[int] | None = None,
) -> dict[str, Any]:
    if batch_limit < 1 or batch_limit > MAX_BATCH_LIMIT:
        raise ValueError(f"batch_limit must be between 1 and {MAX_BATCH_LIMIT}")
    if scan_limit < batch_limit or scan_limit > MAX_SCAN_LIMIT:
        raise ValueError(
            f"scan_limit must be between batch_limit and {MAX_SCAN_LIMIT}"
        )
    policy = load_storage_policy()
    # ``docker port`` is a single, cheap-but-real OS process launch. A
    # caller draining many batches in one loop (``drain_warm_tier_backlog``)
    # resolves it once for the whole drain cycle and passes it in here, so
    # the number of ``docker port`` launches does not grow with batch
    # count. A standalone caller (CLI, single-shot callers) leaves ``port``
    # unset and this function resolves it itself, same as before.
    if port is None:
        port = _container_port(CONTAINER)
    warm = _warm_state(port)
    selection_lower, anchor_kind = _selection_lower(
        warm, policy.db_retention_days
    )
    if not warm["available"] or selection_lower is None:
        inputs = IncrementalInputs(
            warm_available=bool(warm["available"]),
            warm_rows=int(warm["rows"]),
            warm_max_event_id=int(warm["max_event_id"]),
            source_rows=0,
            source_max_event_id=0,
            appended_rows=0,
            eligible_rows=0,
            planned_rows=0,
            archive_missing=0,
            batch_truncated=False,
            reconciliation_anchor_available=selection_lower is not None,
        )
        result = assess_incremental(policy, inputs)
        result["warm"] = warm
        result["selection"] = {
            "mode": SELECTION_MODE,
            "anchor_kind": anchor_kind,
        }
        result["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
        return result

    with _connect() as conn:
        conn.execute("begin transaction isolation level repeatable read read only")
        with conn.cursor() as cur:
            cur.execute("select now() as checked_at_utc")
            checked_at = cur.fetchone()["checked_at_utc"]
        hot_cutoff = checked_at - timedelta(days=policy.db_retention_days)
        warm_cutoff = checked_at - timedelta(days=policy.warm_retention_days)
        source = _source_summary(
            conn,
            warm_max_event_id=int(warm["max_event_id"]),
            selection_lower_utc=selection_lower,
            hot_cutoff_utc=hot_cutoff,
            warm_cutoff_utc=warm_cutoff,
        )
        planned, scan = _scan_missing(
            conn,
            warm_max_event_id=int(warm["max_event_id"]),
            selection_lower_utc=selection_lower,
            hot_cutoff_utc=hot_cutoff,
            warm_cutoff_utc=warm_cutoff,
            batch_limit=batch_limit,
            scan_limit=scan_limit,
            port=port,
        )
        durable_descriptor = _next_durable_descriptor_batch(
            conn,
            batch_limit=batch_limit,
            hot_cutoff_utc=hot_cutoff,
            warm_cutoff_utc=warm_cutoff,
            port=port,
            declaration_after_id=declaration_after_id,
            processed_declaration_ids=processed_declaration_ids,
        )
        descriptor_selection: dict[str, Any] | None = None
        if durable_descriptor is not None:
            descriptor_rows, descriptor_selection = durable_descriptor
            planned = [
                {
                    "id": int(row["id"]),
                    "normalized_hash_hex": str(row["normalized_hash"]).lower(),
                    "time_created_utc": row["time_created_utc"],
                }
                for row in descriptor_rows
            ]
        scan["candidate_scan_complete"] = bool(
            scan["candidate_scan_complete"]
            or int(scan["scanned_rows"]) >= int(source.get("eligible_rows") or 0)
        )
        scan["scan_limit_reached"] = bool(
            scan["scan_limit_reached"]
            and not scan["candidate_scan_complete"]
        )
        descriptor_requires_archive = bool(
            descriptor_selection is not None
            and str(resolve_descriptor_retention(
                "sli.windows.ad-dc", "Security",
                str((descriptor_selection.get("event_keys") or [""])[0]),
            ).promotion.get("archive_requirement")) == "archive_required"
        )
        coverage = (
            _archive_coverage(conn, [int(row["id"]) for row in planned])
            if descriptor_selection is None or descriptor_requires_archive
            else {"missing": 0, "missing_ids": []}
        )

    eligible_rows = int(source.get("eligible_rows") or 0)
    effective_selection_lower = _effective_selection_lower(selection_lower, planned)
    gap_rows = sum(
        int(row["id"]) <= int(warm["max_event_id"]) for row in planned
    )
    inputs = IncrementalInputs(
        warm_available=True,
        warm_rows=int(warm["rows"]),
        warm_max_event_id=int(warm["max_event_id"]),
        source_rows=int(source.get("source_rows") or 0),
        source_max_event_id=int(source.get("source_max_event_id") or 0),
        appended_rows=int(source.get("appended_rows") or 0),
        eligible_rows=eligible_rows,
        planned_rows=len(planned),
        archive_missing=int(coverage["missing"]),
        batch_truncated=(len(planned) == batch_limit and eligible_rows > len(planned)),
        reconciliation_anchor_available=True,
        candidate_scan_complete=bool(scan["candidate_scan_complete"]),
        scanned_rows=int(scan["scanned_rows"]),
        already_present_rows=int(scan["already_present_rows"]),
        gap_rows_at_or_below_warm_max=gap_rows,
        batch_filled=len(planned) == batch_limit,
    )
    result = assess_incremental(policy, inputs)
    result.update(
        {
            "package_type": "WARM_TIER_INCREMENTAL_PLAN",
            "contract_version": 2,
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "warm": warm,
            "source": source,
            "selection": {
                "mode": SELECTION_MODE,
                "legacy_mode_retired": LEGACY_SELECTION_MODE,
                "anchor_kind": anchor_kind,
                "lower_utc": effective_selection_lower,
                "eligibility_upper_utc": hot_cutoff,
                "checkpoint_upper_utc": scan["checkpoint_upper_utc"],
                "warm_cutoff_utc": warm_cutoff,
                "source_order": "time_created_utc,event_id",
                "exact_set_difference": True,
                "scan_limit": scan_limit,
                **scan,
            },
            "planned_batch": {
                "limit": batch_limit,
                "rows": len(planned),
                "event_ids": [int(row["id"]) for row in planned],
                "first_event_id": int(planned[0]["id"]) if planned else None,
                "last_event_id": int(planned[-1]["id"]) if planned else None,
                "first_event_utc": min(
                    (row["time_created_utc"] for row in planned), default=None
                ),
                "last_event_utc": max(
                    (row["time_created_utc"] for row in planned), default=None
                ),
                "identity_sha256": _batch_identity(planned),
                "archive_coverage": coverage,
            },
            "safety": {
                "postgres_repeatable_read_only": True,
                "clickhouse_read_only": True,
                "working_data_changed": False,
                "workers_started": False,
                "production_routing_changed": False,
                "delete_performed": False,
            },
        }
    )
    if descriptor_selection is not None:
        apply_durable_descriptor_selection(result, planned, descriptor_selection)
        result["selection"]["durable_source_capture"] = {
            "scope_identity": descriptor_selection["declaration_scope_identity"],
            "declaration_sha256": descriptor_selection["declaration_sha256"],
            "full_scope_verified_before_selection": True,
        }
    return result


def plan_and_record(
    batch_limit: int,
    scan_limit: int,
    *,
    output_path: Path,
    port: int | None = None,
    declaration_after_id: int = 0,
    processed_declaration_ids: set[int] | None = None,
) -> dict[str, Any]:
    """Build one warm-tier plan and record it as evidence, in-process.

    Shared by the CLI (``main``) and by ``storage_lifecycle_worker.py``,
    which previously launched this whole module as a subprocess once per
    warm batch instead of calling this function directly. ``port`` lets a
    multi-batch drain loop pass in an already-resolved container port
    instead of this function re-resolving it via a fresh ``docker port``
    launch on every batch.
    """
    result = build_plan(
        batch_limit, scan_limit, port=port,
        declaration_after_id=declaration_after_id,
        processed_declaration_ids=processed_declaration_ids,
    )
    # Normalize exactly as the previous JSON-file round trip did (datetimes
    # become strings via ``default=str``), so callers see identical shapes
    # whether they read the evidence file or use the returned dict.
    normalized = json.loads(json.dumps(result, ensure_ascii=False, default=str))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(normalized, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return normalized


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch-limit", type=int, default=DEFAULT_BATCH_LIMIT)
    parser.add_argument("--scan-limit", type=int, default=DEFAULT_SCAN_LIMIT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--descriptor-after-id", type=int, default=0)
    args = parser.parse_args()

    output = args.output.resolve()
    evidence_root = (ROOT / "artifacts" / "stage7" / "evidence").resolve()
    if output.parent != evidence_root:
        parser.error(f"output must be directly inside {evidence_root}")
    result = plan_and_record(
        args.batch_limit, args.scan_limit, output_path=output,
        declaration_after_id=args.descriptor_after_id,
    )
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["status"] != "blocked" else 2


if __name__ == "__main__":
    import sys as _sys

    _sys.modules.setdefault("server.sli.storage.warm_tier_incremental_plan_runtime", _sys.modules[__name__])
from server.sli.storage.warm_tier_incremental_plan_runtime_descriptors import (
    _batch_identity,
    _build_declaration_progress,
    _declaration_source_rows,
    _durable_derived_publication_is_verified,
    _freeze_descriptor_lifecycle,
    _next_durable_descriptor_batch,
    apply_durable_descriptor_selection,
)
from server.sli.storage.warm_tier_incremental_plan_runtime_scan import (
    _archive_coverage,
    _candidate_page,
    _json_row,
    _scan_missing,
    _selection_lower,
    _source_summary,
    _warm_present_ids,
    _warm_state,
)

if __name__ == "__main__":
    raise SystemExit(main())

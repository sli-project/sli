"""Split out of ``server.sli.storage.warm_tier_incremental_copy_runtime`` (plan 7.2b).

Module-level names of ``warm_tier_incremental_copy_runtime`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import server.sli.storage.warm_tier_incremental_copy_runtime as _src


def validate_plan(plan: dict[str, _src.Any]) -> dict[str, _src.Any]:
    if plan.get("package_type") != "WARM_TIER_INCREMENTAL_PLAN":
        raise ValueError("unexpected_plan_package_type")
    if plan.get("status") != "ready_for_manual_bounded_copy":
        raise ValueError("plan_is_not_ready_for_manual_bounded_copy")
    if plan.get("technical_gate_passed") is not True:
        raise ValueError("plan_technical_gate_did_not_pass")
    batch = dict(plan.get("planned_batch") or {})
    selection = dict(plan.get("selection") or {})
    if int(plan.get("contract_version") or 0) != 2:
        raise ValueError("gap_safe_plan_contract_v2_is_required")
    if selection.get("mode") != _src.SELECTION_MODE:
        raise ValueError("gap_safe_selection_mode_is_required")
    if selection.get("exact_set_difference") is not True:
        raise ValueError("exact_warm_set_difference_is_required")
    rows = int(batch.get("rows") or 0)
    limit = int(batch.get("limit") or 0)
    first_event_id = int(batch.get("first_event_id") or 0)
    last_event_id = int(batch.get("last_event_id") or 0)
    identity = str(batch.get("identity_sha256") or "").lower()
    event_ids = [int(value) for value in (batch.get("event_ids") or [])]
    coverage = dict(batch.get("archive_coverage") or {})
    if not 1 <= rows <= _src.MAX_BATCH_ROWS:
        raise ValueError("planned_rows_out_of_bounds")
    if not rows <= limit <= _src.MAX_BATCH_ROWS:
        raise ValueError("plan_limit_must_cover_the_bounded_batch")
    if first_event_id <= 0 or last_event_id < first_event_id:
        raise ValueError("invalid_plan_event_bounds")
    if (
        len(event_ids) != rows
        or event_ids != sorted(set(event_ids))
        or event_ids[0] != first_event_id
        or event_ids[-1] != last_event_id
    ):
        raise ValueError("planned_event_ids_are_not_exact_ordered_bounds")
    if not _src.HEX64.fullmatch(identity):
        raise ValueError("invalid_plan_identity")
    if int(coverage.get("missing") or 0) != 0:
        raise ValueError("plan_archive_coverage_is_incomplete")
    policy = dict(plan.get("policy") or {})
    if (
        int(policy.get("hot_days") or 0) != 7
        or int(policy.get("warm_days") or 0) != 365
        or policy.get("archive_auto_delete_enabled") is not False
    ):
        raise ValueError("plan_storage_policy_is_not_owner_approved")
    source = dict(plan.get("source") or {})
    checked_at = _src._parse_utc(source.get("checked_at_utc"))
    generated_at = _src._parse_utc(plan.get("generated_at_utc"))
    selection_lower = _src._parse_utc(selection.get("lower_utc"))
    eligibility_upper = _src._parse_utc(selection.get("eligibility_upper_utc"))
    checkpoint_upper = _src._parse_utc(selection.get("checkpoint_upper_utc"))
    warm_cutoff = _src._parse_utc(selection.get("warm_cutoff_utc"))
    if not warm_cutoff < eligibility_upper:
        raise ValueError("invalid_plan_retention_window")
    if not selection_lower < checkpoint_upper <= eligibility_upper:
        raise ValueError("invalid_plan_selection_window")
    if generated_at < checked_at - _src.timedelta(minutes=5):
        raise ValueError("plan_generated_before_source_snapshot")
    frozen = {
        "rows": rows,
        "event_ids": event_ids,
        "first_event_id": first_event_id,
        "last_event_id": last_event_id,
        "identity_sha256": identity,
        "warm_max_event_id": int(
            (plan.get("measurements") or {}).get("warm_max_event_id") or 0
        ),
        "checked_at_utc": checked_at,
        "generated_at_utc": generated_at,
        "selection_mode": _src.SELECTION_MODE,
        "selection_lower_utc": selection_lower,
        "eligibility_upper_utc": eligibility_upper,
        "checkpoint_upper_utc": checkpoint_upper,
        "warm_cutoff_utc": warm_cutoff,
    }
    lifecycle = plan.get("descriptor_lifecycle")
    if lifecycle is None:
        frozen["descriptor_lifecycle"] = None
        frozen["descriptor_context"] = None
        return frozen
    if not isinstance(lifecycle, dict):
        raise ValueError("descriptor_lifecycle_must_be_an_object")
    members_value = lifecycle.get("continuity_declaration_members") or ()
    if not isinstance(members_value, (list, tuple)) or len(members_value) > _src.MAX_DECLARATION_MEMBERS:
        raise ValueError("continuity_declaration_member_count_out_of_bounds")
    progress_value = lifecycle.get("declaration_progress")
    if isinstance(progress_value, dict):
        declaration_ids = progress_value.get("declaration_ids")
        if not isinstance(declaration_ids, list) or len(declaration_ids) > _src.MAX_DECLARATION_IDS:
            raise ValueError("declaration_progress_id_count_out_of_bounds")
    expected = _src._freeze_descriptor_lifecycle(
        source=str(lifecycle.get("source") or ""),
        stream=str(lifecycle.get("stream") or ""),
        event_keys=tuple(str(value) for value in lifecycle.get("event_keys") or ()),
        candidate_ids=tuple(event_ids),
        continuity_declaration_scope_identity=(
            str(lifecycle["continuity_declaration_scope_identity"])
            if lifecycle.get("continuity_declaration_scope_identity") is not None else None
        ),
        continuity_declaration_sha256=(
            str(lifecycle["continuity_declaration_sha256"])
            if lifecycle.get("continuity_declaration_sha256") is not None else None
        ),
        continuity_declaration_members=tuple(
            dict(value)
            for value in lifecycle.get("continuity_declaration_members") or ()
        ),
        supplemental_context_ids=tuple(
            int(value) for value in lifecycle.get("supplemental_context_ids") or ()
        ),
        declaration_progress=(
            dict(lifecycle["declaration_progress"])
            if lifecycle.get("declaration_progress") is not None else None
        ),
    )
    if lifecycle != expected:
        raise ValueError("frozen_descriptor_lifecycle_mismatch")
    frozen["descriptor_lifecycle"] = expected
    frozen["descriptor_context"] = None
    return frozen


def classify_existing(
    expected: list[dict[str, _src.Any]],
    actual: list[dict[str, _src.Any]],
    manifests: list[dict[str, _src.Any]],
    identity: str,
    *,
    frozen: dict[str, _src.Any] | None = None,
    archive: dict[str, _src.Any] | None = None,
) -> str:
    if len(manifests) > 1:
        raise RuntimeError("duplicate_incremental_manifest")
    if manifests and (frozen is None or archive is None):
        raise RuntimeError("incremental_manifest_contract_unavailable")
    if manifests:
        _src._validate_manifest_contract(manifests, frozen, archive)
    if not actual:
        if manifests:
            raise RuntimeError("manifest_exists_without_batch_rows")
        return "new"
    expected_by_id = {int(row["id"]): row for row in expected}
    if len(expected_by_id) != len(expected):
        raise RuntimeError("duplicate_expected_batch_event_id")
    actual_by_id = {int(row["id"]): row for row in actual}
    if len(actual_by_id) != len(actual):
        raise RuntimeError("duplicate_warm_batch_event_id")
    if not set(actual_by_id).issubset(expected_by_id):
        raise RuntimeError("warm_batch_id_set_mismatch")
    complete = set(actual_by_id) == set(expected_by_id)
    if not complete and manifests:
        raise RuntimeError("partial_or_overlapping_warm_batch")
    for event_id, target in actual_by_id.items():
        source = expected_by_id[event_id]
        if (
            str(target.get("normalized_hash") or "").lower()
            != str(source["normalized_hash"]).lower()
            or str(target.get("archive_file") or "")
            != str(source["archive_file"])
            or int(target.get("archive_line") or 0)
            != int(source["archive_line"])
            or str(target.get("placement") or "") != "unclassified"
        ):
            raise RuntimeError(f"warm_batch_content_mismatch:{event_id}")
    if _src._identity(expected) != identity:
        raise RuntimeError("expected_batch_identity_mismatch")
    if not complete:
        return "recover_placements"
    return "published" if manifests else "recover_manifest"


def _write_manifest(
    port: int,
    frozen: dict[str, _src.Any],
    archive: dict[str, _src.Any],
) -> None:
    _src._ensure_incremental_manifest_schema(port)
    current = _src._manifest_rows(port, frozen["identity_sha256"])
    if current:
        _src._validate_manifest_contract(current, frozen, archive)
        return
    inserted, interrupted = _src._http_insert_json_rows(
        port,
        f"{_src.DATABASE}.incremental_copy_manifest",
        [
            {
                "batch_identity": frozen["identity_sha256"],
                "plan_generated_at_utc": frozen["generated_at_utc"].strftime(
                    "%Y-%m-%d %H:%M:%S.%f"
                ),
                "planned_rows": frozen["rows"],
                "first_event_id": frozen["first_event_id"],
                "last_event_id": frozen["last_event_id"],
                "archive_identity_sha256": archive[
                    "block_sha256_sequence"
                ],
                "selection_mode": frozen["selection_mode"],
                "selection_lower_utc": frozen[
                    "selection_lower_utc"
                ].strftime("%Y-%m-%d %H:%M:%S.%f"),
                "selection_upper_utc": frozen[
                    "checkpoint_upper_utc"
                ].strftime("%Y-%m-%d %H:%M:%S.%f"),
                "published_at_utc": _src.datetime.now(_src.timezone.utc).strftime(
                    "%Y-%m-%d %H:%M:%S.%f"
                ),
            }
        ],
    )
    if interrupted or inserted != 1:
        raise RuntimeError("manifest_insert_incomplete")

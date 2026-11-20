"""Split out of ``scripts.runtime.storage_lifecycle_worker`` (plan 7.2b).

Module-level names of ``storage_lifecycle_worker`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import scripts.runtime.storage_lifecycle_worker as _src


def run_cycle(
    *,
    max_warm_batches: int = _src.DEFAULT_WARM_BATCH_BUDGET,
    warm_batch_size: int = 10_000,
    warm_scan_limit: int = 2_000_000,
    delete_batch_size: int = 10_000,
    on_wait: _src.Callable[[], None] | None = None,
    invoke: _src.Callable[..., dict[str, object]] = _src._invoke,
    now: _src.Callable[[], _src.datetime] = lambda: _src.datetime.now(_src.timezone.utc),
) -> dict[str, object]:
    warm_archive_admitted = _src.warm_automation_admitted()
    direct_no_archive_admitted = _src.no_archive_automation_admitted()
    delete_execution_allowed = _src.delete_execution_admitted()
    hot_delete_allowed = _src.automation_admitted() and delete_execution_allowed
    if not warm_archive_admitted and not direct_no_archive_admitted:
        return {"status": "disabled", "reason": "one_time_storage_admission_missing"}
    config = _src.load_config()
    profile_resolution = _src.get_storage_capacity_profile_resolution(config)
    policy = _src.load_storage_policy(config)
    if _src.os.environ.get("ADLOG_HISTORY_READ_MODE", "disabled").strip() == "primary":
        if policy.db_retention_days != 7 or policy.archive_auto_delete_enabled:
            return {"status": "blocked", "reason": "owner_storage_policy_changed"}
        return _src._run_history_cycle(
            max_batches=max_warm_batches,
            delete_batch_size=delete_batch_size,
            delete_allowed=direct_no_archive_admitted and delete_execution_allowed,
            on_wait=on_wait,
            invoke=invoke,
        )
    if profile_resolution["selected_profile"] == "economy":
        if not warm_archive_admitted:
            return {"status": "disabled", "reason": "one_time_storage_admission_missing"}
        if not delete_execution_allowed:
            return {
                "status": "disabled",
                "reason": "delete_execution_gate_missing",
                "profile": "economy",
                "deleted_rows": 0,
                "delete_execution_admitted": False,
                "copy_only_no_delete": True,
                "physical_reclaim_performed": False,
                "archive_delete_performed": False,
            }
        if not config.retention_apply_by_default:
            return {"status": "disabled", "reason": "economy_retention_apply_by_default_disabled"}
        file_plan = _src.build_storage_cleanup_plan(policy=policy)
        file_result = _src.apply_storage_cleanup_plan(
            file_plan, apply=True, confirm_apply=True,
        )
        with _src.connect() as connection:
            postgres_result = _src.execute_configured_postgres_profile_retention(
                connection, config=config, apply=True,
            )
        return {
            "status": "ok" if postgres_result.get("status") == "ok" else "blocked",
            "profile": "economy",
            "postgres_retention": postgres_result,
            "file_cleanup": file_result,
            "physical_reclaim_performed": False,
            "archive_delete_performed": False,
        }
    if (
        policy.db_retention_days != 7
        or policy.warm_retention_days != 365
        or policy.archive_auto_delete_enabled
    ):
        return {"status": "blocked", "reason": "owner_storage_policy_changed"}

    started = now().astimezone(_src.timezone.utc)
    cycle_id = started.strftime("%Y%m%dT%H%M%S%fZ")
    frozen_cutoff = _src._frozen_no_archive_cutoff(
        started,
        retention_days=policy.db_retention_days,
    )
    if direct_no_archive_admitted and delete_execution_allowed:
        no_archive = _src._run_no_archive_cycle(
            frozen_cutoff=frozen_cutoff,
            delete_batch_size=delete_batch_size,
        )
    elif direct_no_archive_admitted:
        no_archive = {
            "status": "disabled",
            "reason": "delete_execution_gate_missing",
            "deleted_count": 0,
        }
    else:
        no_archive = {
            "status": "disabled",
            "reason": "direct_no_archive_admission_missing",
        }
    no_archive_status = str(no_archive["status"])
    if not warm_archive_admitted:
        result = {
            "status": (
                "blocked" if no_archive_status == "blocked"
                else "partial" if no_archive_status == "partial" else "ok"
            ),
            "cycle_id": cycle_id,
            "cutoff_utc": frozen_cutoff.isoformat(),
            "no_archive_retention": no_archive,
            "archive_lane": {
                "status": "disabled",
                "reason": "warm_archive_admission_missing",
            },
            "deleted_rows": int(no_archive.get("deleted_count") or 0),
            "delete_execution_admitted": delete_execution_allowed,
            "copy_only_no_delete": not delete_execution_allowed,
            "verified_delete_candidates": int(no_archive.get("selected_count") or 0),
            "archive_delete_performed": False,
            "archive_write_performed": False,
            "dc_mutated": False,
            "physical_reclaim_performed": False,
        }
        if no_archive_status == "blocked":
            result["reason"] = str(
                no_archive.get("reason") or "direct_no_archive_retention_blocked"
            )
        _src._atomic_json(_src.LAST_RESULT, result)
        return result
    _src._processed_declaration_ids()  # validate the independent monotonic ledger
    warm_batch_budget = max(1, min(max_warm_batches, 500))
    # A single subprocess launch drains the whole warm-tier backlog for this
    # cycle: warm_tier_incremental_copy.py loops over batches in-process
    # inside that one child instead of a new Python child process being
    # launched per warm batch (which could reach hundreds across a large
    # backlog). A single bad item inside one batch fails only that batch --
    # batches already committed before it are not retried or undone.
    drain = invoke(
        [
            "-m", "server.sli.storage.warm_tier_incremental_copy_runtime",
            "--drain-backlog",
            "--batch-limit", str(max(1, min(warm_batch_size, 10_000))),
            "--scan-limit", str(max(10_000, min(warm_scan_limit, 5_000_000))),
            "--max-batches", str(warm_batch_budget),
            "--processed-package-ledger", str(_src.PROCESSED_PACKAGES),
            "--confirmation", _src.WARM_CONFIRMATION,
        ],
        timeout_seconds=7200,
        on_wait=on_wait,
    )
    warm_batches = int(drain.get("batches") or 0)
    copied_rows = int(drain.get("copied_rows") or 0)
    drain_status = str(drain.get("status") or "")
    if drain_status not in {"drained", "partial"}:
        raise RuntimeError(f"warm_drain_unexpected_status:{drain_status}")
    warm_cycle_receipt = (
        _src._record_warm_cycle_receipt(
            cycle_id=cycle_id,
            started_at=started,
            drain=drain,
            max_warm_batches=warm_batch_budget,
        )
        if not delete_execution_allowed else None
    )
    completed_packages = [
        dict(value) for value in drain.get("completed_packages") or ()
        if isinstance(value, dict)
        and str(value.get("promotion_evidence_path") or "").strip()
    ]
    if not completed_packages:
        completed_packages = [
            {"promotion_evidence_path": str(value), "declaration_frontier_id": 0}
            for value in drain.get("completed_copy_paths") or () if str(value).strip()
        ]
    candidates = 0
    deleted = 0
    plan_paths: list[str] = []
    execution_paths: list[str] = []
    for package_index, package in enumerate(completed_packages, start=1):
        if not hot_delete_allowed:
            continue
        promotion_evidence_path = str(package.get("promotion_evidence_path") or "").strip()
        package_progress = package.get("declaration_progress")
        promotion_output_identity = str(package.get("promotion_output_identity") or "")
        if package_progress is not None:
            package_progress = _src._validated_declaration_progress(package_progress)
        if not promotion_evidence_path:
            raise RuntimeError("retention_package_evidence_identity_invalid")
        plan_path = _src.EVIDENCE / (
            f"tier-retention-delete-plan-{cycle_id}-{package_index:04d}.json"
        )
        manifest_path = _src.EVIDENCE / (
            f"tier-retention-delete-candidates-{cycle_id}-{package_index:04d}.bin"
        )
        plan_args = [
            "-m", "server.sli.storage.tier_retention_delete_plan_runtime",
            "--full", "--candidate-manifest", str(manifest_path),
            "--out", str(plan_path),
        ]
        plan_args.extend(["--promotion-evidence", promotion_evidence_path])
        plan = invoke(
            plan_args,
            timeout_seconds=3600,
            on_wait=on_wait,
        )
        plan_status = str(plan.get("status") or "")
        package_candidates = int(plan.get("candidate_count") or 0)
        if plan_status == "no_candidates" and package_candidates == 0:
            checkpoint = plan.get("processed_package_checkpoint")
            if package_progress is None or not isinstance(checkpoint, dict) or (
                checkpoint.get("progress_digest") != package_progress["digest"]
                or checkpoint.get("promotion_output_identity") != promotion_output_identity
            ):
                raise RuntimeError("retention_no_candidates_package_mismatch")
            _src._commit_processed_package(
                package_progress, promotion_output_identity=promotion_output_identity,
            )
            continue
        if plan_status != "ready_for_owner_authorization" or package_candidates <= 0:
            raise RuntimeError(f"retention_plan_not_ready:{plan_status}")
        execution_path = _src.EVIDENCE / (
            f"tier-retention-delete-execution-{cycle_id}-{package_index:04d}.json"
        )
        execution = invoke(
            [
                "-m", "server.sli.storage.tier_retention_delete_executor_runtime",
                "--plan", str(plan_path),
                "--output", str(execution_path),
                "--batch-size", str(max(1, min(delete_batch_size, 10_000))),
                "--execute", "--confirmation", _src.DELETE_CONFIRMATION,
            ],
            timeout_seconds=7200,
            on_wait=on_wait,
        )
        if str(execution.get("status") or "") != "complete":
            raise RuntimeError("hot_retention_delete_not_complete")
        candidates += package_candidates
        deleted += int(execution.get("deleted_rows") or 0)
        plan_paths.append(str(plan_path))
        execution_paths.append(str(execution_path))
        if package_progress is not None:
            expected_binding = plan.get("processed_package_binding")
            executed_binding = execution.get("executed_package_binding")
            if (
                not isinstance(expected_binding, dict)
                or expected_binding.get("progress_digest") != package_progress["digest"]
                or expected_binding.get("promotion_output_identity") != promotion_output_identity
                or expected_binding.get("candidate_identity_sha256")
                != package_progress["candidate_identity_sha256"]
                or executed_binding != expected_binding
            ):
                raise RuntimeError("executed_retention_package_mismatch")
            _src._commit_processed_package(
                package_progress, promotion_output_identity=promotion_output_identity,
            )
    direct_partial = no_archive_status == "partial"
    direct_blocked = no_archive_status == "blocked"
    copy_only_bounded_work_unit_completed = (
        not delete_execution_allowed
        and warm_cycle_receipt is not None
        and drain_status == "partial"
    )
    result: dict[str, object] = {
        "status": (
            "blocked" if direct_blocked
            else "partial" if direct_partial
            else "ok" if copy_only_bounded_work_unit_completed
            else "partial" if drain_status == "partial" else "ok"
        ),
        "cycle_id": cycle_id,
        "policy": {"hot_days": 7, "warm_days": 365, "archive_auto_delete": False},
        "cutoff_utc": frozen_cutoff.isoformat(),
        "warm_batch_budget": warm_batch_budget,
        "warm_batches": warm_batches,
        "warm_rows_copied": copied_rows,
        "warm_backlog_remaining": drain_status == "partial",
        "verified_delete_candidates": candidates + int(no_archive.get("selected_count") or 0),
        "deleted_rows": deleted + int(no_archive.get("deleted_count") or 0),
        "delete_execution_admitted": delete_execution_allowed,
        "copy_only_no_delete": not delete_execution_allowed,
        "warm_cycle_receipt": warm_cycle_receipt,
        "no_archive_retention": no_archive,
        "plan_paths": plan_paths,
        "execution_paths": execution_paths,
        "processed_declaration_count": len(_src._processed_declaration_ids()),
        "physical_reclaim_performed": False,
        "archive_delete_performed": False,
        "finished_at_utc": now().astimezone(_src.timezone.utc).isoformat(),
    }
    if direct_blocked:
        result.update({
            "reason": str(no_archive.get("reason") or "direct_no_archive_retention_blocked"),
        })
    elif direct_partial:
        result.update({
            "reason": "direct_no_archive_backlog_remaining",
            "next_retry_seconds": _src.BACKLOG_RETRY_SECONDS,
        })
    elif drain_status == "partial":
        result.update({
            "reason": "warm_backlog_remaining",
            "next_planned_rows": int(drain.get("next_planned_rows") or 0),
            "next_retry_seconds": _src.BACKLOG_RETRY_SECONDS,
        })
    _src._atomic_json(_src.LAST_RESULT, result)
    return result

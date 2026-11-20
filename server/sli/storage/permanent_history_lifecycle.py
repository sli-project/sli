"""Bounded history publication followed by verified seven-day hot retention."""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, timezone

from server.sli.core.paths import DATA_DIR

from server.sli.storage import permanent_fact_history as history
from server.sli.storage import ad_snapshot_change_history as ad_history
from server.sli.plugins.file_audit import retention as file_retention
from server.sli.storage.permanent_history_retention import retain_batch
from server.sli.storage.purge_audit import failure_reason
from server.sli.ops.postgres_session_lock import session_advisory_lock
from server.sli.storage.tier_retention_delete_executor_runtime import _connect_write

PROGRESS = DATA_DIR / "runtime/storage-history-retention-progress.json"


def _retain(*, port: int, cutoff: datetime, batch_size: int) -> dict:
    after_id = 0
    sweep_held = 0
    if PROGRESS.exists():
        progress = json.loads(PROGRESS.read_text(encoding="utf-8"))
        if progress.get("contract") != "sli.history-retention-progress.v1":
            raise RuntimeError("history_retention_progress_invalid")
        after_id = int(progress["last_scanned_id"])
        sweep_held = int(progress.get("sweep_held_count", 0))
        if after_id < 0:
            raise RuntimeError("history_retention_progress_invalid")
    with _connect_write() as connection:
        result = retain_batch(
            connection, cutoff=cutoff, after_id=after_id, batch_size=batch_size,
            preservation_check=lambda candidates: history.verify_preserved_candidates(
                port, candidates,
            ),
        )
    if result["status"] in {"partial", "complete"}:
        from scripts.runtime.storage_lifecycle_worker import _atomic_json
        sweep_held += int(result.get("held_count", 0))
        _atomic_json(PROGRESS, {
            "contract": "sli.history-retention-progress.v1",
            "last_scanned_id": result["last_scanned_id"],
            "cutoff_utc": cutoff.isoformat(),
            "sweep_held_count": 0 if result["status"] == "complete" else sweep_held,
        })
        result["sweep_held_count"] = sweep_held
        if result["status"] == "complete" and sweep_held:
            result.update(status="blocked", reason="source_rows_held_for_processing_or_evidence")
    return result


def run_cycle(
    *, max_batches: int = 50, delete_batch_size: int = 1_000,
    apply_retention: bool = False, now: datetime | None = None,
) -> dict:
    result = {"deleted_rows": 0, "_phase": "configuration"}
    try:
        outcome = _run_cycle(result=result, max_batches=max_batches,
                             delete_batch_size=delete_batch_size,
                             apply_retention=apply_retention, now=now)
    except Exception as error:
        outcome = {**result, "status": "blocked", "reason": failure_reason(error),
                   "error_type": type(error).__name__,
                   "delete_execution_admitted": False, "copy_only_no_delete": True}
    if outcome.get("status") == "blocked":
        outcome["blocked_phase"] = result["_phase"]
    outcome.pop("_phase", None)
    return outcome


def _run_cycle(
    *, result: dict, max_batches: int, delete_batch_size: int,
    apply_retention: bool, now: datetime | None,
) -> dict:
    if not history.primary_read_enabled():
        return {"status": "blocked", "reason": "history_primary_read_required"}
    port = history.configured_read_port()
    if port is None:
        return {"status": "blocked", "reason": "history_clickhouse_port_missing"}
    started = now or datetime.now(timezone.utc)
    cutoff = started - timedelta(days=7)
    result.update({
        "status": "partial", "cycle_id": started.strftime("%Y%m%dT%H%M%S%fZ"),
        "policy": {"hot_days": 7, "facts_and_links": "permanent"},
        "cutoff_utc": cutoff.isoformat(),
        "history_batches": 0, "history_rows_copied": 0,
        "history_links_copied": 0, "deleted_rows": 0,
        "delete_execution_admitted": apply_retention,
        "copy_only_no_delete": not apply_retention,
        "archive_lane": {"status": "disabled", "reason": "clickhouse_history_primary"},
        "archive_delete_performed": False, "physical_reclaim_performed": False,
    })
    result["_phase"] = "ad_snapshot_history"
    try:
        result["ad_snapshot_history"] = ad_history.run_cycle(
            port=port, apply_retention=apply_retention, now=started,
            max_manifests=max(1, min(int(max_batches), 16)),
        )
    except Exception as error:
        # The AD connection context has rolled back unconfirmed publications.
        # Do not expose exception text containing sources or connection details.
        result["ad_snapshot_history"] = {"status": "blocked", "reason": failure_reason(error)}
    if result["ad_snapshot_history"].get("status") not in {"ok", "partial"}:
        return {**result, "status": "blocked",
                "reason": result["ad_snapshot_history"].get("reason", "ad_snapshot_history_unavailable"),
                "delete_execution_admitted": False, "copy_only_no_delete": True}
    # Share the manual copier's lock and durable publication frontier. Holding
    # it through retention prevents source deletion during a concurrent copy.
    result["_phase"] = "copy_lock"
    with session_advisory_lock(history._connect, history.LOCK_NAME) as acquired:
        if not acquired:
            return {**result, "reason": "fact_history_copy_lock_held"}
        try:
            result["_phase"] = "event_history_publication"
            after_id = history.next_after_id(port)
            for _ in range(max(1, min(int(max_batches), 500))):
                copied = history.copy_one_batch(
                    port, after_id=after_id, limit=history.MAX_BATCH_EVENTS, apply=True,
                )
                if copied["status"] == "complete":
                    result["status"] = "ok"
                    break
                if copied["status"] not in {"published", "already_published"}:
                    raise RuntimeError("history_publication_not_verified")
                frontier = int(copied["last_event_db_id"])
                if frontier <= after_id:
                    raise RuntimeError("history_publication_frontier_did_not_advance")
                after_id = frontier
                result["history_batches"] += 1
                result["history_rows_copied"] += int(copied["event_count"])
                result["history_links_copied"] += int(copied["link_count"])
        except Exception as error:
            return {**result, "status": "blocked", "reason": failure_reason(error),
                    "delete_execution_admitted": False, "copy_only_no_delete": True}
        result["history_last_event_id"] = after_id
        if result["status"] == "partial":
            return {**result, "reason": "history_publication_backlog_remaining"}
        if apply_retention:
            if file_retention.cleanup_enabled():
                result["_phase"] = "file_audit_retention"
                try:
                    file_result = file_retention.run_batch(port=port, now=started)
                except Exception as error:
                    file_result = {"status": "blocked", "reason": failure_reason(error)}
                result["file_audit_retention"] = file_result
                if file_result["status"] != "complete":
                    return {**result, "status": file_result["status"],
                            "reason": file_result.get("reason", "file_audit_retention_backlog_remaining")}
            result["retention_batches"] = 0
            result["_phase"] = "event_retention"
            result["retention_rows_scanned"] = 0
            result["retention_rows_held"] = 0
            for _ in range(max(1, min(int(max_batches), 500))):
                try:
                    retained = _retain(
                        port=port, cutoff=cutoff,
                        batch_size=max(1, min(int(delete_batch_size), history.MAX_BATCH_EVENTS)),
                    )
                except Exception as error:
                    retained = {"status": "blocked", "reason": failure_reason(error)}
                result["retention_batches"] += 1
                result["retention_rows_scanned"] += int(retained.get("selected_count", 0))
                result["retention_rows_held"] += int(retained.get("held_count", 0))
                result["deleted_rows"] += int(retained.get("deleted_count") or 0)
                if retained["status"] != "partial":
                    break
            result["no_archive_retention"] = retained
            status = retained.get("status")
            if status not in {"complete", "partial", "blocked"}:
                raise RuntimeError("history_retention_unexpected_status")
            result["status"] = "ok" if status == "complete" else status
            if retained.get("reason"):
                result["reason"] = retained["reason"]
    if result["status"] == "ok" and result["ad_snapshot_history"]["status"] == "partial":
        result.update(status="partial", reason="ad_snapshot_history_backlog_remaining")
    if result["ad_snapshot_history"].get("coverage_state") == "partial":
        result["warning_reason"] = "ad_snapshot_history_coverage_partial"
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-batches", type=int, default=50)
    parser.add_argument("--delete-batch-size", type=int, default=1_000)
    parser.add_argument("--apply-retention", action="store_true")
    args = parser.parse_args()
    if args.apply_retention:
        from scripts.runtime.storage_lifecycle_worker import (
            delete_execution_admitted,
            no_archive_automation_admitted,
        )
        if not delete_execution_admitted() or not no_archive_automation_admitted():
            raise RuntimeError("history_retention_admission_missing")
    result = run_cycle(
        max_batches=args.max_batches, delete_batch_size=args.delete_batch_size,
        apply_retention=args.apply_retention,
    )
    # A blocked safety gate is a cycle result, not a crashed subprocess.
    print(json.dumps(result, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

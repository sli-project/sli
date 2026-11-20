"""Split out of ``scripts.runtime.storage_lifecycle_worker`` (plan 7.2b).

Module-level names of ``storage_lifecycle_worker`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import scripts.runtime.storage_lifecycle_worker as _src


def _bound_warm_copy_evidence(path_value: object) -> dict[str, object]:
    """Read one verified copy record that is local to lifecycle evidence."""
    if not isinstance(path_value, str) or not path_value.strip():
        raise RuntimeError("warm_cycle_copy_evidence_path_invalid")
    evidence_root = _src.EVIDENCE.resolve()
    path = _src.Path(path_value).resolve()
    if path.parent != evidence_root:
        raise RuntimeError("warm_cycle_copy_evidence_path_invalid")
    try:
        if not path.is_file():
            raise FileNotFoundError(path)
        if path.stat().st_size > _src.MAX_WARM_CYCLE_COPY_EVIDENCE_BYTES:
            raise RuntimeError("warm_cycle_copy_evidence_too_large")
        evidence = _src.json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimeError("warm_cycle_copy_evidence_missing") from exc
    except (OSError, UnicodeDecodeError, ValueError, _src.json.JSONDecodeError) as exc:
        raise RuntimeError("warm_cycle_copy_evidence_invalid") from exc
    if not isinstance(evidence, dict):
        raise RuntimeError("warm_cycle_copy_evidence_invalid")
    plan = evidence.get("plan")
    source = evidence.get("source")
    safety = evidence.get("safety")
    batch_identity = plan.get("batch_identity") if isinstance(plan, dict) else None
    rows = plan.get("rows") if isinstance(plan, dict) else None
    if (
        evidence.get("status") not in {"copied_and_verified", "already_published"}
        or not _src._is_sha256(batch_identity)
        or not isinstance(rows, int) or isinstance(rows, bool) or not 0 < rows <= 10_000
        or path.name != f"warm-tier-incremental-copy-{batch_identity[:16]}.json"
        or not isinstance(source, dict)
        or source.get("postgres_transaction") != "REPEATABLE READ, READ ONLY"
        or not isinstance(safety, dict)
        or safety.get("postgres_mutated") is not False
        or safety.get("delete_performed") is not False
    ):
        raise RuntimeError("warm_cycle_copy_evidence_invalid")
    return {
        "batch_identity": batch_identity,
        "copy_evidence_path": path.name,
        "copy_evidence_sha256": _src._sha256_file(path),
        "rows": rows,
        "status": evidence["status"],
    }


def _record_warm_cycle_receipt(
    *,
    cycle_id: str,
    started_at: _src.datetime,
    drain: dict[str, object],
    max_warm_batches: int,
) -> dict[str, str]:
    """Exclusively create and read back the evidence for one copy-only cycle."""
    if not cycle_id or any(character not in "0123456789TZ" for character in cycle_id):
        raise RuntimeError("warm_cycle_receipt_cycle_id_invalid")
    drain_status = str(drain.get("status") or "")
    batches = drain.get("batches")
    copied_rows = drain.get("copied_rows")
    paths = drain.get("completed_copy_paths")
    next_planned_rows = drain.get("next_planned_rows", 0)
    if (
        not isinstance(max_warm_batches, int) or isinstance(max_warm_batches, bool)
        or not 1 <= max_warm_batches <= 500
        or drain_status not in {"drained", "partial"}
        or not isinstance(batches, int) or isinstance(batches, bool)
        or not 0 <= batches <= max_warm_batches
        or not isinstance(copied_rows, int) or isinstance(copied_rows, bool) or copied_rows < 0
        or not isinstance(paths, list) or len(paths) != batches
        or not isinstance(next_planned_rows, int) or isinstance(next_planned_rows, bool)
        or not 0 <= next_planned_rows <= 10_000
        or (drain_status == "drained" and next_planned_rows != 0)
        or (drain_status == "partial" and (
            batches != max_warm_batches or next_planned_rows <= 0
        ))
    ):
        raise RuntimeError("warm_cycle_receipt_drain_invalid")
    copies = [_src._bound_warm_copy_evidence(path) for path in paths]
    if (
        len({str(item["batch_identity"]) for item in copies}) != len(copies)
        or len({str(item["copy_evidence_path"]) for item in copies}) != len(copies)
        or sum(int(item["rows"]) for item in copies) != copied_rows
    ):
        raise RuntimeError("warm_cycle_receipt_copy_set_invalid")
    receipt: dict[str, object] = {
        "contract": _src.WARM_CYCLE_RECEIPT_CONTRACT,
        "cycle_id": cycle_id,
        "cycle_started_at_utc": started_at.astimezone(_src.timezone.utc).isoformat(),
        "drain_status": drain_status,
        "max_warm_batches": max_warm_batches,
        "warm_batches": batches,
        "warm_rows_copied": copied_rows,
        "backlog_remaining": drain_status == "partial",
        "next_planned_rows": next_planned_rows,
        "lifecycle_work_unit_status": "completed",
        "drain_completed": drain_status == "drained",
        "copy_only_no_delete": True,
        "delete_execution_admitted": False,
        "copies": copies,
    }
    receipt["receipt_digest"] = _src._warm_cycle_receipt_digest(receipt)
    receipt_path = _src.EVIDENCE.resolve() / f"warm-cycle-receipt-{cycle_id}.json"
    serialized = _src.json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    try:
        with receipt_path.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(serialized)
    except FileExistsError as exc:
        raise RuntimeError("warm_cycle_receipt_exists") from exc
    try:
        readback = _src.json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, _src.json.JSONDecodeError) as exc:
        raise RuntimeError("warm_cycle_receipt_readback_invalid") from exc
    if (
        readback != receipt
        or not isinstance(readback, dict)
        or readback.get("receipt_digest") != _src._warm_cycle_receipt_digest(readback)
    ):
        raise RuntimeError("warm_cycle_receipt_readback_invalid")
    return {"path": str(receipt_path), "digest": str(receipt["receipt_digest"])}


def _prior_successful_watermark() -> tuple[str | None, str | None]:
    try:
        value = _src.json.loads(_src.LAST_RESULT.read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError, _src.json.JSONDecodeError):
        return None, None
    if not isinstance(value, dict):
        return None, None
    watermark = value.get("last_successful_watermark")
    watermark_updated_at = value.get("watermark_updated_at")
    return (
        str(watermark) if isinstance(watermark, str) and watermark else None,
        str(watermark_updated_at) if isinstance(watermark_updated_at, str) else None,
    )


def _persist_lifecycle_result(
    result: dict[str, object],
    *,
    started_at: _src.datetime,
    ended_at: _src.datetime,
    phase: str,
    error: Exception | None,
    prior_successful_watermark: str | None,
    prior_watermark_updated_at: str | None,
) -> dict[str, object]:
    persisted = dict(result)
    cycle_watermark = persisted.get("cycle_id") if phase == "completed" else None
    if not isinstance(cycle_watermark, str) or not cycle_watermark:
        cycle_watermark = prior_successful_watermark
    watermark_updated_at = (
        ended_at.astimezone(_src.timezone.utc).isoformat()
        if phase == "completed" and cycle_watermark != prior_successful_watermark
        else prior_watermark_updated_at
    )
    persisted.update({
        "contract": "sli.storage-lifecycle-result.v1",
        "started_at_utc": started_at.astimezone(_src.timezone.utc).isoformat(),
        "ended_at_utc": ended_at.astimezone(_src.timezone.utc).isoformat(),
        "phase": phase,
        "cutoff_utc": persisted.get("cutoff_utc"),
        "error": _src.failure_reason(error) if error is not None else None,
        "error_type": type(error).__name__ if error is not None else None,
        "last_successful_watermark": cycle_watermark,
        "watermark_updated_at": watermark_updated_at,
    })
    persisted["result_digest"] = _src._lifecycle_result_digest(persisted)
    _src._atomic_json(_src.LAST_RESULT, persisted)
    return persisted


def _lifecycle_heartbeat_details(
    *,
    cycle_evidence: dict[str, object],
    capacity_evidence: dict[str, object],
    process_status: str,
    lifecycle_phase: str,
    now: _src.datetime,
) -> dict[str, object]:
    completed_at = cycle_evidence.get("last_cycle_completed_at")
    if not isinstance(completed_at, _src.datetime):
        completed_at = None
    details: dict[str, object] = {
        "policy": (
            "7/permanent_facts_and_links/no_file_archive"
            if _src.os.environ.get("ADLOG_HISTORY_READ_MODE") == "primary"
            else "7/365/no_archive_delete"
        ),
        "process_status": process_status,
        "last_cycle_status": cycle_evidence["last_cycle_status"],
        "last_cycle_reason": cycle_evidence.get("last_cycle_reason"),
        "last_cycle_started_at": (
            cycle_evidence["last_cycle_started_at"].isoformat()
            if isinstance(cycle_evidence.get("last_cycle_started_at"), _src.datetime) else None
        ),
        "last_cycle_completed_at": completed_at.isoformat() if completed_at else None,
        "last_success_at": (
            cycle_evidence["last_success_at"].isoformat()
            if isinstance(cycle_evidence.get("last_success_at"), _src.datetime) else None
        ),
        "last_error_type": cycle_evidence["last_error_type"],
        "result_age_seconds": _src._heartbeat_result_age(completed_at, now=now),
        "last_result_digest": cycle_evidence["last_result_digest"],
        "last_result_phase": cycle_evidence["last_result_phase"],
        "last_successful_watermark": cycle_evidence["last_successful_watermark"],
        "watermark_updated_at": cycle_evidence["watermark_updated_at"],
        "copy_only_no_delete": cycle_evidence["copy_only_no_delete"],
        "delete_execution_admitted": cycle_evidence["delete_execution_admitted"],
        "deleted_rows": cycle_evidence["deleted_rows"],
        "lifecycle_phase": lifecycle_phase,
        "capacity_evidence": capacity_evidence,
    }
    return details

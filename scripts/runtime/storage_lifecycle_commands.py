"""Split out of ``scripts.runtime.storage_lifecycle_worker`` (plan 7.2b).

Module-level names of ``storage_lifecycle_worker`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import scripts.runtime.storage_lifecycle_worker as _src


def _run_command(
    command: list[str],
    *,
    timeout_seconds: int,
    on_wait: _src.Callable[[], None] | None = None,
) -> _src.subprocess.CompletedProcess[str]:
    flags = (
        getattr(_src.subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        | getattr(_src.subprocess, "CREATE_NO_WINDOW", 0)
        if _src.os.name == "nt"
        else 0
    )
    process = _src.subprocess.Popen(
        command,
        cwd=str(_src.ROOT),
        stdout=_src.subprocess.PIPE,
        stderr=_src.subprocess.PIPE,
        text=True,
        creationflags=flags,
    )
    job_handle = _src._start_job_protected(process.pid)
    try:
        deadline = _src.time.monotonic() + max(1, timeout_seconds)
        while True:
            remaining = deadline - _src.time.monotonic()
            try:
                stdout, stderr = process.communicate(timeout=max(0.1, min(30, remaining)))
                return _src.subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
            except _src.subprocess.TimeoutExpired as exc:
                if _src.time.monotonic() < deadline:
                    if on_wait is not None:
                        on_wait()
                    continue
                if job_handle is not None:
                    _src._terminate_job(job_handle)
                if _src.os.name == "nt":
                    try:
                        _src.subprocess.run(
                            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                            stdout=_src.subprocess.DEVNULL,
                            stderr=_src.subprocess.DEVNULL,
                            timeout=10,
                            check=False,
                            creationflags=getattr(_src.subprocess, "CREATE_NO_WINDOW", 0),
                        )
                    except Exception:
                        # Cleanup is secondary evidence; never replace the
                        # child command's authoritative timeout with taskkill's.
                        pass
                    # Job assignment can fail (or taskkill can hang).  This
                    # bounded fallback still guarantees the direct child gets
                    # a terminate request; confirmed Job ownership covers its
                    # descendants when available.
                    try:
                        process.kill()
                    except Exception:
                        pass
                else:
                    process.kill()
                try:
                    stdout, stderr = process.communicate(
                        timeout=_src._POST_KILL_DRAIN_SECONDS
                    )
                except _src.subprocess.TimeoutExpired:
                    stdout, stderr = "", ""
                raise _src.subprocess.TimeoutExpired(
                    command, timeout_seconds, output=stdout, stderr=stderr
                ) from exc
    finally:
        if job_handle is not None:
            _src._close_job(job_handle)


def _invoke(
    args: list[str],
    *,
    timeout_seconds: int,
    on_wait: _src.Callable[[], None] | None,
) -> dict[str, object]:
    result = _src._run_command(
        [_src.sys.executable, *args],
        timeout_seconds=timeout_seconds,
        on_wait=on_wait,
    )
    try:
        payload = _src.json.loads(result.stdout or "{}")
    except _src.json.JSONDecodeError as exc:
        raise RuntimeError("storage_lifecycle_command_output_invalid") from exc
    if result.returncode != 0:
        reason = str(payload.get("status") or "command_failed")
        # A drain result can end in thousands of event IDs. Preserve the bounded
        # structured cause instead of replacing it with that unrelated JSON tail.
        detail = ":".join(
            str(payload[key]) for key in ("reason", "error") if payload.get(key)
        ) or (result.stderr or result.stdout or "")[-1000:]
        raise RuntimeError(f"{reason}:{detail}"[:1000])
    return dict(payload)


def _run_no_archive_cycle(
    *,
    frozen_cutoff: _src.datetime,
    delete_batch_size: int,
) -> dict[str, object]:
    port = _src.configured_read_port()
    # The regular runtime role can read V2 but cannot lock or delete it. Use
    # the established maintenance-only connection for this admitted operation.
    with _src.retention_write_connect() as connection:
        result = _src.execute_no_archive_retention(
            connection,
            cutoff=frozen_cutoff,
            apply=True,
            admitted=True,
            batch_size=max(1, min(delete_batch_size, 1_000)),
            preservation_check=(
                (lambda candidates: _src.verify_preserved_candidates(port, candidates))
                if port is not None else None
            ),
        )
    status = str(result.get("status") or "")
    if status not in {"blocked", "complete", "partial"}:
        raise RuntimeError(f"direct_no_archive_unexpected_status:{status}")
    if str(result.get("cutoff_utc") or "") != frozen_cutoff.isoformat():
        raise RuntimeError("direct_no_archive_cutoff_mismatch")
    if int(result.get("archive_rows_written") or 0):
        raise RuntimeError("direct_no_archive_wrote_archive_rows")
    _src._atomic_json(_src.NO_ARCHIVE_PROGRESS, {
        "contract": "sli.storage-no-archive-progress.v2",
        "status": status,
        "reason": str(result.get("reason") or "") or None,
        "cutoff_utc": frozen_cutoff.isoformat(),
        "descriptor_identities": list(result.get("descriptor_identities") or ()),
        "expired_total_count": int(result.get("expired_total_count") or 0),
        "covered_by_continuity_count": int(result.get("covered_by_continuity_count") or 0),
        "blocked_without_continuity_count": int(result.get("blocked_without_continuity_count") or 0),
        "blocked_by_relationship_count": int(result.get("blocked_by_relationship_count") or 0),
        "blocked_by_archive_gap_count": int(result.get("blocked_by_archive_gap_count") or 0),
        "blocked_by_restrictive_reference_count": int(result.get("blocked_by_restrictive_reference_count") or 0),
        "selected_count": int(result.get("selected_count") or 0),
        "eligible_count": int(result.get("eligible_count") or 0),
        "held_count": int(result.get("held_count") or 0),
        "deleted_count": int(result.get("deleted_count") or 0),
        "remaining_count": int(result.get("remaining_count") or 0),
        "batches_committed": int(result.get("batches_committed") or 0),
        "resume_strategy": "exact_predicate_rescan",
        "delete_performed": bool(result.get("delete_performed")),
        "archive_write_performed": bool(result.get("archive_write_performed")),
        "dc_mutated": bool(result.get("dc_mutated")),
        "event_log_mutated": False,
        "physical_reclaim_performed": False,
    })
    return result


def _run_history_cycle(
    *, max_batches: int, delete_batch_size: int, delete_allowed: bool,
    on_wait: _src.Callable[[], None] | None, invoke: _src.Callable[..., dict[str, object]],
) -> dict[str, object]:
    arguments = [
        "-m", "server.sli.storage.permanent_history_lifecycle",
        "--max-batches", str(max(1, min(max_batches, 500))),
        "--delete-batch-size", str(max(1, min(delete_batch_size, 1_000))),
    ]
    if delete_allowed:
        arguments.append("--apply-retention")
    return invoke(arguments, timeout_seconds=7200, on_wait=on_wait)

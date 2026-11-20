from __future__ import annotations

import json
from contextlib import nullcontext
from datetime import datetime, timezone
from pathlib import Path
from subprocess import CompletedProcess

import pytest

from scripts.runtime import storage_lifecycle_worker as worker


def test_primary_history_cycle_never_enters_legacy_archive_lane(monkeypatch):
    monkeypatch.setenv(worker.ENABLE_ENV, "1")
    monkeypatch.setenv(worker.WARM_ADMISSION_ENV, worker.WARM_CONFIRMATION)
    monkeypatch.setenv("ADLOG_HISTORY_READ_MODE", "primary")
    expected = {"status": "ok", "history_rows_copied": 0, "deleted_rows": 0}
    monkeypatch.setattr(worker, "_run_history_cycle", lambda **kw: expected, raising=False)
    assert worker.run_cycle(
        invoke=lambda *a, **kw: pytest.fail("legacy archive lane invoked"),
    ) == expected


def test_history_configuration_survives_supervisor_environment_filter():
    from server.sli.ops.worker_supervisor_secrets import WORKER_ENV_ALLOWLIST

    assert {
        "ADLOG_HISTORY_READ_MODE", "ADLOG_HISTORY_CLICKHOUSE_PORT",
        "ADLOG_HISTORY_CLICKHOUSE_USER", "ADLOG_HISTORY_CLICKHOUSE_PASSWORD",
    } <= WORKER_ENV_ALLOWLIST


def test_failed_cycle_schedules_prompt_retry(monkeypatch):
    heartbeats = []
    monkeypatch.setattr(worker, "lifecycle_lock", lambda: nullcontext(True))
    monkeypatch.setattr(worker, "record_worker_heartbeat", lambda **kw: heartbeats.append(kw))
    monkeypatch.setattr(worker, "_capacity_evidence", dict)

    def fail(**kw):
        raise ConnectionError("dependency unavailable")

    monkeypatch.setattr(worker, "run_cycle", fail)
    assert worker.run(once=True, interval_seconds=21600) == 2
    assert heartbeats[-1]["expected_interval_seconds"] == worker.BACKLOG_RETRY_SECONDS


def test_command_failure_preserves_structured_cause_not_payload_tail(monkeypatch) -> None:
    payload = {
        "status": "blocked", "reason": "warm_copy_not_verified:blocked",
        "error": "archive_event_duplicate:175754910",
        "final_plan": {"event_ids": list(range(10000))},
    }
    monkeypatch.setattr(worker, "_run_command", lambda *_args, **_kwargs: CompletedProcess(
        [], 2, stdout=json.dumps(payload), stderr="unrelated warning",
    ))
    with pytest.raises(RuntimeError) as error:
        worker._invoke(["-m", "test"], timeout_seconds=1, on_wait=None)
    assert str(error.value) == (
        "blocked:warm_copy_not_verified:blocked:archive_event_duplicate:175754910"
    )


def test_command_child_is_job_owned_before_communication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[object] = []

    class FakeProcess:
        pid = 42
        returncode = 0

        def communicate(self, *, timeout):
            events.append(("communicate", timeout))
            assert events[0] == ("protected", 42)
            return "ok", ""

    monkeypatch.setattr(worker.subprocess, "Popen", lambda *_args, **_kwargs: FakeProcess())
    monkeypatch.setattr(
        worker,
        "_start_job_protected",
        lambda pid: events.append(("protected", pid)) or 77,
    )
    monkeypatch.setattr(
        worker,
        "_close_job",
        lambda handle: events.append(("closed", handle)),
    )

    result = worker._run_command(["child"], timeout_seconds=5)

    assert result.stdout == "ok"
    assert events[-1] == ("closed", 77)


def test_command_hides_windows_child_console_and_keeps_process_group(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process_group = 0x00000200
    no_window = 0x08000000
    calls: list[dict[str, object]] = []

    class FakeProcess:
        pid = 42
        returncode = 0

        def communicate(self, *, timeout):
            return "ok", ""

    def launch(*_args, **kwargs):
        calls.append(kwargs)
        return FakeProcess()

    monkeypatch.setattr(worker.os, "name", "nt")
    monkeypatch.setattr(worker.subprocess, "CREATE_NEW_PROCESS_GROUP", process_group, raising=False)
    monkeypatch.setattr(worker.subprocess, "CREATE_NO_WINDOW", no_window, raising=False)
    monkeypatch.setattr(worker.subprocess, "Popen", launch)
    monkeypatch.setattr(worker, "_start_job_protected", lambda _pid: None)

    result = worker._run_command(["child"], timeout_seconds=5)

    assert result.stdout == "ok"
    assert calls[0]["creationflags"] & process_group
    assert calls[0]["creationflags"] & no_window


def test_job_protection_is_active_only_after_confirmed_assignment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed: list[int] = []
    monkeypatch.setattr(worker, "_create_kill_on_close_job", lambda: 88)
    monkeypatch.setattr(worker, "_assign_process_to_job", lambda _handle, _pid: False)
    monkeypatch.setattr(worker, "_close_job", closed.append)

    assert worker._start_job_protected(44) is None
    assert closed == [88]

    monkeypatch.setattr(worker, "_assign_process_to_job", lambda _handle, _pid: True)
    assert worker._start_job_protected(44) == 88


def test_command_timeout_preserves_original_when_taskkill_hangs_and_kills_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[object] = []

    class FakeProcess:
        pid = 43
        returncode = None
        communicate_calls = 0

        def communicate(self, *, timeout):
            self.communicate_calls += 1
            events.append(("communicate", timeout))
            if self.communicate_calls == 1:
                raise worker.subprocess.TimeoutExpired(["child"], 1)
            return "partial output", "partial error"

        def kill(self):
            events.append("direct-child-killed")

    process = FakeProcess()
    monotonic = iter((0.0, 2.0, 2.0))
    monkeypatch.setattr(worker.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(worker.time, "monotonic", lambda: next(monotonic))
    monkeypatch.setattr(worker, "_start_job_protected", lambda _pid: None)
    monkeypatch.setattr(worker.os, "name", "nt")

    def hung_taskkill(*_args, **_kwargs):
        events.append("taskkill-hung")
        raise worker.subprocess.TimeoutExpired(["taskkill"], 10)

    monkeypatch.setattr(worker.subprocess, "run", hung_taskkill)

    with pytest.raises(worker.subprocess.TimeoutExpired) as error:
        worker._run_command(["child"], timeout_seconds=1)

    assert error.value.cmd == ["child"]
    assert error.value.timeout == 1
    assert "taskkill-hung" in events
    assert "direct-child-killed" in events
    assert events[-1] == ("communicate", worker._POST_KILL_DRAIN_SECONDS)


@pytest.fixture(autouse=True)
def _completed_empty_no_archive_stage(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    monkeypatch.setattr(worker, "NO_ARCHIVE_PROGRESS", tmp_path / "no-archive-progress.json")
    monkeypatch.setattr(worker, "LAST_RESULT", tmp_path / "storage-lifecycle-last.json")
    monkeypatch.setenv(
        worker.NO_ARCHIVE_ADMISSION_ENV, worker.NO_ARCHIVE_DELETE_CONFIRMATION,
    )
    monkeypatch.setenv(worker.DELETE_EXECUTION_ENV, "1")
    monkeypatch.setattr(worker, "connect", lambda: nullcontext(object()))
    monkeypatch.setattr(worker, "retention_write_connect", lambda: nullcontext(object()))
    monkeypatch.setattr(
        worker,
        "execute_no_archive_retention",
        lambda _connection, **kwargs: {
            "status": "complete",
            "cutoff_utc": kwargs["cutoff"].isoformat(),
            "selected_count": 0,
            "deleted_count": 0,
            "remaining_count": 0,
            "archive_rows_written": 0,
        },
        raising=False,
    )


def test_admission_requires_enable_and_exact_delete_contract() -> None:
    assert not worker.automation_admitted({})
    assert not worker.automation_admitted({worker.ENABLE_ENV: "1"})
    assert not worker.automation_admitted({
        worker.ENABLE_ENV: "1",
        worker.ADMISSION_ENV: "wrong",
    })
    assert worker.automation_admitted({
        worker.ENABLE_ENV: "true",
        worker.ADMISSION_ENV: worker.DELETE_CONFIRMATION,
    })


def test_warm_copy_admission_does_not_authorize_direct_no_archive_delete() -> None:
    admitted = getattr(worker, "no_archive_automation_admitted", lambda _env: True)
    assert not admitted({
        worker.ENABLE_ENV: "1",
        worker.ADMISSION_ENV: worker.DELETE_CONFIRMATION,
    })
    assert admitted({
        worker.ENABLE_ENV: "1",
        "ADLOG_STORAGE_NO_ARCHIVE_DELETE_CONFIRMATION": (
            "DELETE_EXPLICIT_NO_ARCHIVE_ROWS_AFTER_SEMANTIC_COMPLETION"
        ),
    })


def test_direct_only_admission_never_invokes_warm_or_archive_lane(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(worker.ENABLE_ENV, "1")
    monkeypatch.delenv(worker.ADMISSION_ENV, raising=False)

    result = worker.run_cycle(
        invoke=lambda *_args, **_kwargs: pytest.fail("warm/archive lane invoked"),
        now=lambda: datetime(2026, 8, 3, tzinfo=timezone.utc),
    )

    assert result["status"] == "ok"
    assert result["no_archive_retention"]["status"] == "complete"
    assert result["archive_lane"] == {
        "status": "disabled",
        "reason": "warm_archive_admission_missing",
    }


def test_warm_only_admission_never_invokes_direct_no_archive_delete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(worker.ENABLE_ENV, "1")
    monkeypatch.setenv(worker.ADMISSION_ENV, worker.DELETE_CONFIRMATION)
    monkeypatch.delenv(worker.NO_ARCHIVE_ADMISSION_ENV, raising=False)
    monkeypatch.setattr(
        worker,
        "execute_no_archive_retention",
        lambda *_args, **_kwargs: pytest.fail("direct no-archive lane invoked"),
    )

    result = worker.run_cycle(
        invoke=lambda *_args, **_kwargs: {
            "status": "drained", "batches": 0, "copied_rows": 0,
        },
        now=lambda: datetime(2026, 8, 3, tzinfo=timezone.utc),
    )

    assert result["status"] == "ok"
    assert result["no_archive_retention"] == {
        "status": "disabled",
        "reason": "direct_no_archive_admission_missing",
    }


def test_copy_only_mode_runs_warm_copy_without_any_retention_delete(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.setenv(worker.ENABLE_ENV, "1")
    monkeypatch.setenv(worker.ADMISSION_ENV, "0")
    monkeypatch.setenv(worker.WARM_ADMISSION_ENV, worker.WARM_CONFIRMATION)
    monkeypatch.setenv(worker.NO_ARCHIVE_ADMISSION_ENV, worker.NO_ARCHIVE_DELETE_CONFIRMATION)
    monkeypatch.delenv(worker.DELETE_EXECUTION_ENV, raising=False)
    monkeypatch.setattr(worker, "EVIDENCE", tmp_path)
    batch_identity = "a" * 64
    copy_path = tmp_path / f"warm-tier-incremental-copy-{batch_identity[:16]}.json"
    copy_path.write_text(json.dumps({
        "status": "copied_and_verified",
        "plan": {"batch_identity": batch_identity, "rows": 10_000},
        "source": {"postgres_transaction": "REPEATABLE READ, READ ONLY"},
        "safety": {"postgres_mutated": False, "delete_performed": False},
    }), encoding="utf-8")
    monkeypatch.setattr(
        worker,
        "execute_no_archive_retention",
        lambda *_args, **_kwargs: pytest.fail("direct no-archive DELETE invoked"),
    )
    calls: list[str] = []

    def invoke(args, **_kwargs):
        calls.append(args[1])
        if args[1].endswith("warm_tier_incremental_copy_runtime"):
            return {
                "status": "drained",
                "batches": 1,
                "copied_rows": 10_000,
                "completed_copy_paths": [str(copy_path)],
            }
        pytest.fail(f"retention subprocess invoked: {args[1]}")

    result = worker.run_cycle(
        invoke=invoke,
        now=lambda: datetime(2026, 8, 3, tzinfo=timezone.utc),
    )

    assert calls == ["server.sli.storage.warm_tier_incremental_copy_runtime"]
    assert result["warm_rows_copied"] == 10_000
    assert result["deleted_rows"] == 0
    assert result["delete_execution_admitted"] is False
    assert result["copy_only_no_delete"] is True
    assert result["no_archive_retention"] == {
        "status": "disabled",
        "reason": "delete_execution_gate_missing",
        "deleted_count": 0,
    }


def test_copy_only_cycle_records_an_immutable_bound_warm_receipt(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """P1-C3 accepts a copy-only cycle only with its own immutable receipt."""
    monkeypatch.setenv(worker.ENABLE_ENV, "1")
    monkeypatch.setenv(worker.ADMISSION_ENV, "0")
    monkeypatch.setenv(worker.WARM_ADMISSION_ENV, worker.WARM_CONFIRMATION)
    monkeypatch.delenv(worker.DELETE_EXECUTION_ENV, raising=False)
    monkeypatch.setattr(worker, "EVIDENCE", tmp_path)
    batch_identity = "a" * 64
    copy_path = tmp_path / f"warm-tier-incremental-copy-{batch_identity[:16]}.json"
    copy_path.write_text(json.dumps({
        "status": "copied_and_verified",
        "plan": {"batch_identity": batch_identity, "rows": 2},
        "source": {"postgres_transaction": "REPEATABLE READ, READ ONLY"},
        "safety": {"postgres_mutated": False, "delete_performed": False},
    }), encoding="utf-8")

    def invoke(args, **_kwargs):
        assert args[1].endswith("warm_tier_incremental_copy_runtime")
        return {
            "status": "drained", "batches": 1, "copied_rows": 2,
            "completed_copy_paths": [str(copy_path)],
        }

    now = lambda: datetime(2026, 9, 3, 1, 2, 3, 4, tzinfo=timezone.utc)
    result = worker.run_cycle(invoke=invoke, now=now)

    receipt_path = tmp_path / "warm-cycle-receipt-20260903T010203000004Z.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert result["warm_cycle_receipt"] == {
        "path": str(receipt_path), "digest": receipt["receipt_digest"],
    }
    assert receipt["contract"] == "sli.storage-lifecycle-warm-cycle-receipt.v1"
    assert receipt["cycle_id"] == result["cycle_id"]
    assert receipt["drain_status"] == "drained"
    assert receipt["copy_only_no_delete"] is True
    assert receipt["delete_execution_admitted"] is False
    assert receipt["copies"] == [{
        "batch_identity": batch_identity,
        "copy_evidence_path": copy_path.name,
        "copy_evidence_sha256": worker._sha256_file(copy_path),
        "rows": 2,
        "status": "copied_and_verified",
    }]
    assert receipt["receipt_digest"] == worker._warm_cycle_receipt_digest(receipt)

    with pytest.raises(RuntimeError, match="warm_cycle_receipt_exists"):
        worker.run_cycle(invoke=invoke, now=now)


def test_copy_only_cycle_fails_closed_when_warm_evidence_cannot_be_bound(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.setenv(worker.ENABLE_ENV, "1")
    monkeypatch.setenv(worker.ADMISSION_ENV, "0")
    monkeypatch.setenv(worker.WARM_ADMISSION_ENV, worker.WARM_CONFIRMATION)
    monkeypatch.delenv(worker.DELETE_EXECUTION_ENV, raising=False)
    monkeypatch.setattr(worker, "EVIDENCE", tmp_path)

    with pytest.raises(RuntimeError, match="warm_cycle_copy_evidence_missing"):
        worker.run_cycle(
            invoke=lambda *_args, **_kwargs: {
                "status": "drained", "batches": 1, "copied_rows": 2,
                "completed_copy_paths": [str(tmp_path / "missing.json")],
            },
            now=lambda: datetime(2026, 9, 3, tzinfo=timezone.utc),
        )


def test_copy_only_max_batch_completion_advances_successful_watermark(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """A fully evidenced copy-only work unit completes despite bounded backlog."""
    monkeypatch.setenv(worker.ENABLE_ENV, "1")
    monkeypatch.setenv(worker.ADMISSION_ENV, "0")
    monkeypatch.setenv(worker.WARM_ADMISSION_ENV, worker.WARM_CONFIRMATION)
    monkeypatch.delenv(worker.DELETE_EXECUTION_ENV, raising=False)
    monkeypatch.setattr(worker, "EVIDENCE", tmp_path)
    result_path = tmp_path / "storage-lifecycle-last.json"
    monkeypatch.setattr(worker, "LAST_RESULT", result_path)
    batch_identity = "b" * 64
    copy_path = tmp_path / f"warm-tier-incremental-copy-{batch_identity[:16]}.json"
    copy_path.write_text(json.dumps({
        "status": "copied_and_verified",
        "plan": {"batch_identity": batch_identity, "rows": 2},
        "source": {"postgres_transaction": "REPEATABLE READ, READ ONLY"},
        "safety": {"postgres_mutated": False, "delete_performed": False},
    }), encoding="utf-8")
    calls: list[str] = []

    def invoke(args, **_kwargs):
        calls.append(args[1])
        assert args[args.index("--max-batches") + 1] == "1"
        return {
            "status": "partial", "batches": 1, "copied_rows": 2,
            "next_planned_rows": 2, "completed_copy_paths": [str(copy_path)],
        }

    result = worker.run_cycle(
        max_warm_batches=1,
        invoke=invoke,
        now=lambda: datetime(2026, 9, 3, 1, 2, 3, 5, tzinfo=timezone.utc),
    )

    receipt = json.loads((
        tmp_path / "warm-cycle-receipt-20260903T010203000005Z.json"
    ).read_text(encoding="utf-8"))
    assert calls == ["server.sli.storage.warm_tier_incremental_copy_runtime"]
    assert result["status"] == "ok"
    assert result["warm_backlog_remaining"] is True
    assert result["warm_batch_budget"] == 1
    assert result["warm_batches"] == 1
    assert result["warm_rows_copied"] == 2
    assert result["next_planned_rows"] == 2
    assert result["next_retry_seconds"] == worker.BACKLOG_RETRY_SECONDS
    assert result["deleted_rows"] == 0
    assert result["copy_only_no_delete"] is True
    assert receipt["drain_status"] == "partial"
    assert receipt["lifecycle_work_unit_status"] == "completed"
    assert receipt["drain_completed"] is False
    assert receipt["max_warm_batches"] == 1
    assert receipt["backlog_remaining"] is True
    assert receipt["next_planned_rows"] == 2
    assert receipt["copies"][0]["batch_identity"] == batch_identity
    assert receipt["receipt_digest"] == worker._warm_cycle_receipt_digest(receipt)

    heartbeats: list[dict[str, object]] = []
    monkeypatch.setattr(worker, "lifecycle_lock", lambda: nullcontext(True))
    monkeypatch.setattr(
        worker, "record_worker_heartbeat", lambda **kwargs: heartbeats.append(kwargs),
    )
    monkeypatch.setattr(worker, "run_cycle", lambda *, on_wait: result)

    assert worker.run(once=True, interval_seconds=900) == 0
    persisted = json.loads(result_path.read_text(encoding="utf-8"))
    assert persisted["phase"] == "completed"
    assert persisted["last_successful_watermark"] == result["cycle_id"]
    assert heartbeats[-1]["status"] == "idle"
    assert heartbeats[-1]["expected_interval_seconds"] == worker.BACKLOG_RETRY_SECONDS


def test_copy_only_partial_without_explicit_backlog_evidence_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.setenv(worker.ENABLE_ENV, "1")
    monkeypatch.setenv(worker.ADMISSION_ENV, "0")
    monkeypatch.setenv(worker.WARM_ADMISSION_ENV, worker.WARM_CONFIRMATION)
    monkeypatch.delenv(worker.DELETE_EXECUTION_ENV, raising=False)
    monkeypatch.setattr(worker, "EVIDENCE", tmp_path)
    batch_identity = "c" * 64
    copy_path = tmp_path / f"warm-tier-incremental-copy-{batch_identity[:16]}.json"
    copy_path.write_text(json.dumps({
        "status": "copied_and_verified",
        "plan": {"batch_identity": batch_identity, "rows": 2},
        "source": {"postgres_transaction": "REPEATABLE READ, READ ONLY"},
        "safety": {"postgres_mutated": False, "delete_performed": False},
    }), encoding="utf-8")

    with pytest.raises(RuntimeError, match="warm_cycle_receipt_drain_invalid"):
        worker.run_cycle(
            max_warm_batches=1,
            invoke=lambda *_args, **_kwargs: {
                "status": "partial", "batches": 1, "copied_rows": 2,
                "completed_copy_paths": [str(copy_path)],
            },
            now=lambda: datetime(2026, 9, 3, tzinfo=timezone.utc),
        )


def test_economy_retention_requires_existing_admission_and_apply_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from server.sli.core.app_config import AdLogConfig

    config = AdLogConfig(
        reports_dir="data/reports",
        log_dir="data/logs",
        storage_capacity_profile="economy",
        retention_apply_by_default=False,
    )
    monkeypatch.setattr(worker, "load_config", lambda: config)
    monkeypatch.setattr(worker, "_atomic_json", lambda *_: None)
    assert worker.run_cycle()["reason"] == "one_time_storage_admission_missing"

    monkeypatch.setenv(worker.ENABLE_ENV, "1")
    monkeypatch.setenv(worker.ADMISSION_ENV, worker.DELETE_CONFIRMATION)
    enabled = worker.run_cycle()
    assert enabled["reason"] == "economy_retention_apply_by_default_disabled"


def test_economy_delete_gate_blocks_both_destructive_helpers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from server.sli.core.app_config import AdLogConfig

    config = AdLogConfig(
        reports_dir="data/reports",
        log_dir="data/logs",
        storage_capacity_profile="economy",
        retention_apply_by_default=True,
    )
    monkeypatch.setenv(worker.ENABLE_ENV, "1")
    monkeypatch.setenv(worker.ADMISSION_ENV, worker.DELETE_CONFIRMATION)
    monkeypatch.delenv(worker.DELETE_EXECUTION_ENV, raising=False)
    monkeypatch.setattr(worker, "load_config", lambda: config)
    calls: list[str] = []
    monkeypatch.setattr(
        worker,
        "apply_storage_cleanup_plan",
        lambda *_args, **_kwargs: calls.append("file_cleanup") or {"status": "ok"},
    )
    monkeypatch.setattr(
        worker,
        "execute_configured_postgres_profile_retention",
        lambda *_args, **_kwargs: calls.append("postgres_retention") or {"status": "ok"},
    )

    result = worker.run_cycle()

    assert calls == []
    assert result == {
        "status": "disabled",
        "reason": "delete_execution_gate_missing",
        "profile": "economy",
        "deleted_rows": 0,
        "delete_execution_admitted": False,
        "copy_only_no_delete": True,
        "physical_reclaim_performed": False,
        "archive_delete_performed": False,
    }

def test_economy_path_reuses_existing_worker_cleanup_and_retention_entry_points(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from server.sli.core.app_config import AdLogConfig

    config = AdLogConfig(
        reports_dir="data/reports",
        log_dir="data/logs",
        storage_capacity_profile="economy",
        retention_apply_by_default=True,
    )
    monkeypatch.setenv(worker.ENABLE_ENV, "1")
    monkeypatch.setenv(worker.ADMISSION_ENV, worker.DELETE_CONFIRMATION)
    monkeypatch.setattr(worker, "load_config", lambda: config)
    monkeypatch.setattr(worker, "build_storage_cleanup_plan", lambda **_kwargs: {"actions": []})
    monkeypatch.setattr(worker, "apply_storage_cleanup_plan", lambda *args, **kwargs: {"status": "ok", "reused": True})
    monkeypatch.setattr(worker, "connect", lambda: nullcontext(object()))
    monkeypatch.setattr(worker, "execute_configured_postgres_profile_retention", lambda *_args, **kwargs: {"status": "ok", "apply": kwargs["apply"]})

    result = worker.run_cycle()

    assert result["status"] == "ok"
    assert result["profile"] == "economy"
    assert result["file_cleanup"] == {"status": "ok", "reused": True}
    assert result["postgres_retention"] == {"status": "ok", "apply": True}


def test_default_warm_batch_budget_is_bounded_for_partial_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(worker.ENABLE_ENV, "1")
    monkeypatch.setenv(worker.ADMISSION_ENV, worker.DELETE_CONFIRMATION)
    monkeypatch.setattr(worker, "_atomic_json", lambda *_args: None)
    warm_args: list[str] = []

    def fake_invoke(args, **_kwargs):
        warm_args.extend(args)
        return {
            "status": "partial",
            "batches": 50,
            "copied_rows": 500_000,
            "next_planned_rows": 10_000,
        }

    result = worker.run_cycle(
        invoke=fake_invoke,
        now=lambda: datetime(2026, 8, 3, tzinfo=timezone.utc),
    )

    assert warm_args[warm_args.index("--max-batches") + 1] == "50"
    assert result["status"] == "partial"
    assert result["reason"] == "warm_backlog_remaining"
    assert result["next_retry_seconds"] == worker.BACKLOG_RETRY_SECONDS


def test_cycle_copies_then_freezes_then_deletes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(worker.ENABLE_ENV, "1")
    monkeypatch.setenv(worker.ADMISSION_ENV, worker.DELETE_CONFIRMATION)
    monkeypatch.setattr(worker, "_atomic_json", lambda *_: None)
    calls: list[list[str]] = []

    def fake_invoke(args, **_kwargs):
        calls.append(args)
        assert args[0] == "-m"
        module = args[1]
        if module.endswith("warm_tier_incremental_copy_runtime"):
            assert "--drain-backlog" in args
            assert args[args.index("--confirmation") + 1] == worker.WARM_CONFIRMATION
            return {
                "status": "drained",
                "batches": 1,
                "copied_rows": 3,
                "completed_copy_paths": ["C:/evidence/warm-tier-incremental-copy-one.json"],
                "final_plan": {
                    "selection": {"eligibility_upper_utc": "2026-07-27T00:00:00+00:00"},
                },
            }
        if module.endswith("tier_retention_delete_plan_runtime"):
            assert args[args.index("--promotion-evidence") + 1].endswith("copy-one.json")
            return {"status": "ready_for_owner_authorization", "candidate_count": 3}
        if module.endswith("tier_retention_delete_executor_runtime"):
            assert worker.DELETE_CONFIRMATION in args
            return {"status": "complete", "deleted_rows": 3}
        raise AssertionError(module)

    result = worker.run_cycle(
        invoke=fake_invoke,
        now=lambda: datetime(2026, 8, 3, tzinfo=timezone.utc),
    )
    assert result["status"] == "ok"
    assert result["warm_rows_copied"] == 3
    assert result["deleted_rows"] == 3
    # The whole warm-tier backlog is drained by one subprocess launch (which
    # loops over batches internally), not one launch per batch.
    assert [call[1] for call in calls] == [
        "server.sli.storage.warm_tier_incremental_copy_runtime",
        "server.sli.storage.tier_retention_delete_plan_runtime",
        "server.sli.storage.tier_retention_delete_executor_runtime",
    ]


def test_cycle_runs_direct_no_archive_before_warm_with_one_frozen_cutoff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(worker.ENABLE_ENV, "1")
    monkeypatch.setenv(worker.ADMISSION_ENV, worker.DELETE_CONFIRMATION)
    monkeypatch.setattr(worker, "_atomic_json", lambda *_: None)
    monkeypatch.setattr(worker, "connect", lambda: nullcontext(object()))
    order: list[str] = []
    expected_cutoff = datetime(2026, 7, 27, tzinfo=timezone.utc)

    def fake_direct(_connection, **kwargs):
        order.append("direct")
        assert kwargs == {
            "cutoff": expected_cutoff,
            "apply": True,
            "admitted": True,
            "batch_size": 1_000,
            "preservation_check": None,
        }
        return {
            "status": "complete",
            "cutoff_utc": expected_cutoff.isoformat(),
            "selected_count": 0,
            "deleted_count": 0,
            "remaining_count": 0,
            "archive_rows_written": 0,
        }

    def fake_invoke(args, **_kwargs):
        order.append("warm")
        assert args[1].endswith("warm_tier_incremental_copy_runtime")
        return {"status": "drained", "batches": 0, "copied_rows": 0}

    monkeypatch.setattr(
        worker,
        "execute_no_archive_retention",
        fake_direct,
        raising=False,
    )
    result = worker.run_cycle(
        invoke=fake_invoke,
        now=lambda: datetime(2026, 8, 3, tzinfo=timezone.utc),
    )

    assert order == ["direct", "warm"]
    assert result["cutoff_utc"] == expected_cutoff.isoformat()
    assert result["no_archive_retention"]["status"] == "complete"


def test_limit_stopped_direct_no_archive_cycle_remains_partial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(worker.ENABLE_ENV, "1")
    monkeypatch.setenv(worker.ADMISSION_ENV, worker.DELETE_CONFIRMATION)
    monkeypatch.setattr(worker, "_atomic_json", lambda *_: None)
    monkeypatch.setattr(
        worker,
        "execute_no_archive_retention",
        lambda _connection, **kwargs: {
            "status": "partial",
            "cutoff_utc": kwargs["cutoff"].isoformat(),
            "selected_count": 10_000,
            "deleted_count": 10_000,
            "remaining_count": 1,
            "archive_rows_written": 0,
        },
    )

    result = worker.run_cycle(
        invoke=lambda *_args, **_kwargs: {
            "status": "drained", "batches": 0, "copied_rows": 0,
        },
        now=lambda: datetime(2026, 8, 3, tzinfo=timezone.utc),
    )

    assert result["status"] == "partial"
    assert result["reason"] == "direct_no_archive_backlog_remaining"
    assert result["no_archive_retention"]["remaining_count"] == 1


def test_direct_no_archive_continuity_block_is_persisted_and_returned_as_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(worker.ENABLE_ENV, "1")
    monkeypatch.setenv(worker.ADMISSION_ENV, worker.DELETE_CONFIRMATION)
    writes: list[tuple[Path, dict[str, object]]] = []
    monkeypatch.setattr(
        worker,
        "_atomic_json",
        lambda path, payload: writes.append((path, dict(payload))),
    )
    monkeypatch.setattr(
        worker,
        "execute_no_archive_retention",
        lambda _connection, **kwargs: {
            "status": "blocked",
            "reason": "expired_rows_without_continuity_declarations",
            "cutoff_utc": kwargs["cutoff"].isoformat(),
            "expired_total_count": 100,
            "covered_by_continuity_count": 0,
            "blocked_without_continuity_count": 100,
            "blocked_by_relationship_count": 0,
            "blocked_by_archive_gap_count": 0,
            "blocked_by_restrictive_reference_count": 0,
            "eligible_count": 0,
            "remaining_count": 100,
            "deleted_count": 0,
        },
    )

    result = worker.run_cycle(
        invoke=lambda *_args, **_kwargs: {
            "status": "drained", "batches": 0, "copied_rows": 0,
        },
        now=lambda: datetime(2026, 8, 3, tzinfo=timezone.utc),
    )

    assert result["status"] == "blocked"
    assert result["reason"] == "expired_rows_without_continuity_declarations"
    assert result["no_archive_retention"]["remaining_count"] == 100
    progress = next(payload for path, payload in writes if path == worker.NO_ARCHIVE_PROGRESS)
    assert progress["contract"] == "sli.storage-no-archive-progress.v2"
    assert progress["expired_total_count"] == 100
    assert progress["blocked_without_continuity_count"] == 100
    assert progress["remaining_count"] == 100


def test_partial_no_archive_progress_reuses_frozen_cutoff_after_restart(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    progress = tmp_path / "no-archive-progress.json"
    progress.write_text(json.dumps({
        "contract": "sli.storage-no-archive-progress.v1",
        "status": "partial",
        "cutoff_utc": "2026-07-27T00:00:00+00:00",
        "descriptor_identities": [
            {"source": "sli.windows.ad-dc", "stream": "Security", "event_key": event_key}
            for event_key in ("4624", "4634")
        ],
    }), encoding="utf-8")
    monkeypatch.setattr(worker, "NO_ARCHIVE_PROGRESS", progress, raising=False)

    cutoff = worker._frozen_no_archive_cutoff(
        datetime(2026, 8, 4, tzinfo=timezone.utc),
        retention_days=7,
    )

    assert cutoff == datetime(2026, 7, 27, tzinfo=timezone.utc)


def test_partial_no_archive_progress_rejects_changed_descriptor_predicate(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    progress = tmp_path / "no-archive-progress.json"
    progress.write_text(json.dumps({
        "contract": "sli.storage-no-archive-progress.v1",
        "status": "partial",
        "cutoff_utc": "2026-07-27T00:00:00+00:00",
        "descriptor_identities": [{
            "source": "sli.windows.ad-dc",
            "stream": "Security",
            "event_key": "4672",
        }],
    }), encoding="utf-8")
    monkeypatch.setattr(worker, "NO_ARCHIVE_PROGRESS", progress)

    with pytest.raises(RuntimeError, match="no_archive_progress_invalid"):
        worker._frozen_no_archive_cutoff(
            datetime(2026, 8, 4, tzinfo=timezone.utc),
            retention_days=7,
        )


def test_direct_no_archive_checkpoint_is_persisted_before_warm_lane(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(worker.ENABLE_ENV, "1")
    monkeypatch.setenv(worker.ADMISSION_ENV, worker.DELETE_CONFIRMATION)
    writes: list[tuple[Path, dict[str, object]]] = []
    monkeypatch.setattr(
        worker,
        "_atomic_json",
        lambda path, payload: writes.append((path, dict(payload))),
    )
    monkeypatch.setattr(
        worker,
        "execute_no_archive_retention",
        lambda _connection, **kwargs: {
            "status": "partial",
            "cutoff_utc": kwargs["cutoff"].isoformat(),
            "descriptor_identities": [{
                "source": "sli.windows.ad-dc",
                "stream": "Security",
                "event_key": "4624",
            }],
            "selected_count": 1,
            "deleted_count": 1,
            "remaining_count": 1,
            "archive_rows_written": 0,
            "delete_performed": True,
            "archive_write_performed": False,
            "dc_mutated": False,
        },
    )

    worker.run_cycle(
        invoke=lambda *_args, **_kwargs: {
            "status": "drained", "batches": 0, "copied_rows": 0,
        },
        now=lambda: datetime(2026, 8, 3, tzinfo=timezone.utc),
    )

    assert writes[0][0] == worker.NO_ARCHIVE_PROGRESS
    assert writes[0][1]["contract"] == "sli.storage-no-archive-progress.v2"
    assert writes[0][1]["status"] == "partial"
    assert writes[0][1]["archive_write_performed"] is False
    assert writes[0][1]["dc_mutated"] is False
    assert writes[-1][0] == worker.LAST_RESULT


def test_cycle_binds_each_delete_package_to_its_published_copy_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A lifecycle cycle may delete several bounded, independently promoted packages."""
    monkeypatch.setenv(worker.ENABLE_ENV, "1")
    monkeypatch.setenv(worker.ADMISSION_ENV, worker.DELETE_CONFIRMATION)
    monkeypatch.setattr(worker, "_atomic_json", lambda *_: None)
    calls: list[list[str]] = []

    def fake_invoke(args, **_kwargs):
        calls.append(args)
        module = args[1]
        if module.endswith("warm_tier_incremental_copy_runtime"):
            return {
                "status": "drained",
                "batches": 2,
                "copied_rows": 3,
                "completed_copy_paths": [
                    "C:/evidence/warm-tier-incremental-copy-first.json",
                    "C:/evidence/warm-tier-incremental-copy-second.json",
                ],
                "final_plan": {
                    "selection": {"eligibility_upper_utc": "2026-07-27T00:00:00+00:00"},
                },
            }
        if module.endswith("tier_retention_delete_plan_runtime"):
            evidence = args[args.index("--promotion-evidence") + 1]
            return {
                "status": "ready_for_owner_authorization",
                "candidate_count": 1,
                "promotion_gate": {"output_identity": evidence},
            }
        if module.endswith("tier_retention_delete_executor_runtime"):
            return {"status": "complete", "deleted_rows": 1}
        raise AssertionError(module)

    result = worker.run_cycle(
        invoke=fake_invoke,
        now=lambda: datetime(2026, 8, 3, tzinfo=timezone.utc),
    )

    planner_calls = [
        call for call in calls
        if call[1].endswith("tier_retention_delete_plan_runtime")
    ]
    assert [
        call[call.index("--promotion-evidence") + 1]
        for call in planner_calls
    ] == [
        "C:/evidence/warm-tier-incremental-copy-first.json",
        "C:/evidence/warm-tier-incremental-copy-second.json",
    ]
    assert result["verified_delete_candidates"] == 2
    assert result["deleted_rows"] == 2


def test_cycle_binds_archive_required_copy_to_the_canonical_promotion_planner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(worker.ENABLE_ENV, "1")
    monkeypatch.setenv(worker.ADMISSION_ENV, worker.DELETE_CONFIRMATION)
    monkeypatch.setattr(worker, "_atomic_json", lambda *_: None)

    def fake_invoke(args, **_kwargs):
        module = args[1]
        if module.endswith("warm_tier_incremental_copy_runtime"):
            return {
                "status": "drained",
                "batches": 1,
                "copied_rows": 2,
                "completed_packages": [{
                    "promotion_evidence_path": "C:/evidence/archive-promotion.json",
                    "declaration_frontier_id": 0,
                }],
            }
        if module.endswith("tier_retention_delete_plan_runtime"):
            assert args[args.index("--promotion-evidence") + 1].endswith(
                "archive-promotion.json"
            )
            assert "--copy-evidence" not in args
            return {"status": "ready_for_owner_authorization", "candidate_count": 2}
        if module.endswith("tier_retention_delete_executor_runtime"):
            return {"status": "complete", "deleted_rows": 2}
        raise AssertionError(module)

    result = worker.run_cycle(
        invoke=fake_invoke,
        now=lambda: datetime(2026, 8, 3, tzinfo=timezone.utc),
    )

    assert result["deleted_rows"] == 2
    assert result["verified_delete_candidates"] == 2


def test_cycle_does_not_persist_descriptor_frontier_before_completed_disposition(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.setenv(worker.ENABLE_ENV, "1")
    monkeypatch.setenv(worker.ADMISSION_ENV, worker.DELETE_CONFIRMATION)
    state = tmp_path / "storage-lifecycle-last.json"
    state.write_text('{"descriptor_frontier_id": 7}\n', encoding="utf-8")
    monkeypatch.setattr(worker, "LAST_RESULT", state)
    writes: list[tuple[Path, dict[str, object]]] = []
    monkeypatch.setattr(
        worker, "_atomic_json", lambda path, value: writes.append((path, value)),
    )

    def fake_invoke(args, **_kwargs):
        module = args[1]
        if module.endswith("warm_tier_incremental_copy_runtime"):
            assert args[args.index("--processed-package-ledger") + 1] == str(worker.PROCESSED_PACKAGES)
            return {
                "status": "drained", "batches": 1, "copied_rows": 1,
                "completed_packages": [{
                    "promotion_evidence_path": "C:/evidence/descriptor.json",
                    "declaration_frontier_id": 8,
                }],
            }
        if module.endswith("tier_retention_delete_plan_runtime"):
            return {"status": "ready_for_owner_authorization", "candidate_count": 1}
        if module.endswith("tier_retention_delete_executor_runtime"):
            return {"status": "blocked", "deleted_rows": 0}
        raise AssertionError(module)

    with pytest.raises(RuntimeError, match="hot_retention_delete_not_complete"):
        worker.run_cycle(
            invoke=fake_invoke,
            now=lambda: datetime(2026, 8, 3, tzinfo=timezone.utc),
        )

    assert [value for path, value in writes if path == worker.LAST_RESULT] == []
    assert len([value for path, value in writes if path == worker.NO_ARCHIVE_PROGRESS]) == 1


def test_cycle_resumes_descriptor_frontier_only_after_completed_delete(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.setenv(worker.ENABLE_ENV, "1")
    monkeypatch.setenv(worker.ADMISSION_ENV, worker.DELETE_CONFIRMATION)
    state = tmp_path / "storage-lifecycle-last.json"
    state.write_text('{"descriptor_frontier_id": 7}\n', encoding="utf-8")
    monkeypatch.setattr(worker, "LAST_RESULT", state)
    writes: list[tuple[Path, dict[str, object]]] = []
    monkeypatch.setattr(
        worker, "_atomic_json", lambda path, value: writes.append((path, value)),
    )

    def fake_invoke(args, **_kwargs):
        module = args[1]
        if module.endswith("warm_tier_incremental_copy_runtime"):
            assert args[args.index("--processed-package-ledger") + 1] == str(worker.PROCESSED_PACKAGES)
            return {
                "status": "drained", "batches": 2, "copied_rows": 2,
                "completed_packages": [
                    {"promotion_evidence_path": "C:/evidence/one.json", "declaration_frontier_id": 8},
                    {"promotion_evidence_path": "C:/evidence/two.json", "declaration_frontier_id": 9},
                ],
            }
        if module.endswith("tier_retention_delete_plan_runtime"):
            return {"status": "ready_for_owner_authorization", "candidate_count": 1}
        if module.endswith("tier_retention_delete_executor_runtime"):
            return {"status": "complete", "deleted_rows": 1}
        raise AssertionError(module)

    result = worker.run_cycle(
        invoke=fake_invoke,
        now=lambda: datetime(2026, 8, 3, tzinfo=timezone.utc),
    )

    assert result["processed_declaration_count"] == 0
    assert len([value for path, value in writes if path == worker.NO_ARCHIVE_PROGRESS]) == 1
    last_results = [value for path, value in writes if path == worker.LAST_RESULT]
    assert len(last_results) == 1
    assert "descriptor_frontier_id" not in last_results[0]


def test_partial_drain_commits_already_verified_descriptor_package_before_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A cycle boundary cannot strand a published exact package until drain completion."""
    monkeypatch.setenv(worker.ENABLE_ENV, "1")
    monkeypatch.setenv(worker.ADMISSION_ENV, worker.DELETE_CONFIRMATION)
    writes: list[dict[str, object]] = []
    monkeypatch.setattr(worker, "_atomic_json", lambda _path, payload: writes.append(payload))
    calls: list[str] = []

    def fake_invoke(args, **_kwargs):
        calls.append(args[1])
        if args[1].endswith("warm_tier_incremental_copy_runtime"):
            return {
                "status": "partial",
                "batches": 1,
                "copied_rows": 3,
                "next_planned_rows": 3,
                "completed_packages": [{
                    "promotion_evidence_path": "C:/evidence/descriptor-copy.json",
                    "declaration_frontier_id": 8,
                }],
            }
        if args[1].endswith("tier_retention_delete_plan_runtime"):
            assert args[args.index("--promotion-evidence") + 1].endswith(
                "descriptor-copy.json"
            )
            return {"status": "ready_for_owner_authorization", "candidate_count": 3}
        if args[1].endswith("tier_retention_delete_executor_runtime"):
            return {"status": "complete", "deleted_rows": 3}
        raise AssertionError(args[1])

    result = worker.run_cycle(
        max_warm_batches=1,
        invoke=fake_invoke,
        now=lambda: datetime(2026, 8, 3, tzinfo=timezone.utc),
    )

    assert result["status"] == "partial"
    assert result["deleted_rows"] == 3
    assert result["processed_declaration_count"] == 0
    assert calls == [
        "server.sli.storage.warm_tier_incremental_copy_runtime",
        "server.sli.storage.tier_retention_delete_plan_runtime",
        "server.sli.storage.tier_retention_delete_executor_runtime",
    ]
    assert all("descriptor_frontier_id" not in payload for payload in writes)


def test_cycle_never_deletes_when_full_verification_is_not_clean(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(worker.ENABLE_ENV, "1")
    monkeypatch.setenv(worker.ADMISSION_ENV, worker.DELETE_CONFIRMATION)
    monkeypatch.setattr(worker, "_atomic_json", lambda *_: None)
    calls: list[str] = []

    def fake_invoke(args, **_kwargs):
        calls.append(args[1])
        if args[1].endswith("warm_tier_incremental_copy_runtime"):
            return {
                "status": "drained",
                "batches": 0,
                "copied_rows": 0,
                "completed_copy_paths": ["C:/evidence/warm-tier-incremental-copy-one.json"],
                "final_plan": {
                    "selection": {"eligibility_upper_utc": "2026-07-27T00:00:00+00:00"},
                },
            }
        return {"status": "blocked", "candidate_count": 3}

    with pytest.raises(RuntimeError, match="retention_plan_not_ready"):
        worker.run_cycle(invoke=fake_invoke)
    assert not any(path.endswith("tier_retention_delete_executor_runtime") for path in calls)


def test_warm_tier_backlog_uses_a_single_subprocess_launch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R51/R52: the whole warm-tier backlog for a cycle is drained by a
    single subprocess launch (which loops over batches internally), not one
    launch per batch -- so OS process launches per cycle are bounded by a
    constant and do not grow with the number of warm batches processed."""
    monkeypatch.setenv(worker.ENABLE_ENV, "1")
    monkeypatch.setenv(worker.ADMISSION_ENV, worker.DELETE_CONFIRMATION)
    monkeypatch.setattr(worker, "_atomic_json", lambda *_: None)
    invoke_calls: list[str] = []

    def fake_invoke(args, **_kwargs):
        invoke_calls.append(args[1])
        if args[1].endswith("warm_tier_incremental_copy_runtime"):
            return {
                "status": "drained",
                "batches": 50,
                "copied_rows": 500_000,
                "final_plan": {
                    "selection": {"eligibility_upper_utc": "2026-07-27T00:00:00+00:00"},
                },
            }
        if args[1].endswith("tier_retention_delete_plan_runtime"):
            return {"status": "no_candidates", "candidate_count": 0}
        raise AssertionError(f"unexpected subprocess launch: {args[1]}")

    result = worker.run_cycle(
        invoke=fake_invoke,
        now=lambda: datetime(2026, 8, 3, tzinfo=timezone.utc),
    )

    assert result["status"] == "ok"
    assert result["warm_batches"] == 50
    assert result["warm_rows_copied"] == 500_000
    # Archive/ordinary warm batches do not receive an invented promotion
    # gate, so this remains a single warm-tier subprocess launch.
    assert len(invoke_calls) == 1
    assert invoke_calls[0].endswith("warm_tier_incremental_copy_runtime")


def test_cycle_fails_when_warm_drain_reports_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R57: a blocked warm-tier drain (e.g. one bad item in one batch)
    fails the cycle -- it is never reported as overall success, and the
    retention step never runs."""
    monkeypatch.setenv(worker.ENABLE_ENV, "1")
    monkeypatch.setenv(worker.ADMISSION_ENV, worker.DELETE_CONFIRMATION)
    calls: list[str] = []

    def fake_invoke(args, **_kwargs):
        calls.append(args[1])
        if args[1].endswith("warm_tier_incremental_copy_runtime"):
            return {
                "status": "blocked",
                "reason": "warm_copy_not_verified:blocked",
                "batches": 1,
                "copied_rows": 10_000,
                "error": "archive_event_hash_mismatch:99",
            }
        raise AssertionError(f"unexpected subprocess launch: {args[1]}")

    with pytest.raises(RuntimeError, match="warm_drain_unexpected_status:blocked"):
        worker.run_cycle(invoke=fake_invoke)
    assert not any(
        path.endswith("tier_retention_delete_plan_runtime") for path in calls
    )


def test_failed_result_cannot_erase_committed_package_ledger(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    ledger = tmp_path / "storage-lifecycle-processed-packages.jsonl"
    monkeypatch.setattr(worker, "PROCESSED_PACKAGES", ledger)
    progress = {
        "contract": "sli.storage-lifecycle-declaration-progress.v1",
        "declaration_ids": [7, 11],
        "scope_identity": "scope-a",
        "declaration_sha256": "a" * 64,
        "candidate_identity_sha256": "b" * 64,
    }
    progress["digest"] = worker._declaration_progress_digest(progress)

    worker._commit_processed_package(progress, promotion_output_identity="c" * 64)
    worker._atomic_json(tmp_path / "last.json", {"status": "failed"})

    assert worker._processed_declaration_ids() == {7, 11}
    assert json.loads(ledger.read_text(encoding="utf-8"))["progress_digest"] == progress["digest"]


def test_exact_clean_no_candidates_checkpoints_only_matching_bound_package(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.setenv(worker.ENABLE_ENV, "1")
    monkeypatch.setenv(worker.ADMISSION_ENV, worker.DELETE_CONFIRMATION)
    monkeypatch.setattr(worker, "PROCESSED_PACKAGES", tmp_path / "ledger.jsonl")
    monkeypatch.setattr(worker, "_atomic_json", lambda *_args: None)
    progress = {
        "contract": "sli.storage-lifecycle-declaration-progress.v1",
        "declaration_ids": [3, 9],
        "scope_identity": "scope-a",
        "declaration_sha256": "a" * 64,
        "candidate_identity_sha256": "b" * 64,
    }
    progress["digest"] = worker._declaration_progress_digest(progress)

    def invoke(args, **_kwargs):
        if args[1].endswith("warm_tier_incremental_copy_runtime"):
            return {"status": "drained", "batches": 1, "copied_rows": 2,
                    "completed_packages": [{
                        "promotion_evidence_path": "C:/evidence/package.json",
                        "promotion_output_identity": "c" * 64,
                        "declaration_progress": progress,
                    }]}
        if args[1].endswith("tier_retention_delete_plan_runtime"):
            return {"status": "no_candidates", "candidate_count": 0,
                    "processed_package_checkpoint": {
                        "progress_digest": progress["digest"],
                        "promotion_output_identity": "c" * 64,
                    }}
        raise AssertionError(args)

    result = worker.run_cycle(invoke=invoke)

    assert result["status"] == "ok"
    assert worker._processed_declaration_ids() == {3, 9}


def test_no_candidates_rejects_swapped_progress_evidence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.setenv(worker.ENABLE_ENV, "1")
    monkeypatch.setenv(worker.ADMISSION_ENV, worker.DELETE_CONFIRMATION)
    monkeypatch.setattr(worker, "PROCESSED_PACKAGES", tmp_path / "ledger.jsonl")
    monkeypatch.setattr(worker, "_atomic_json", lambda *_args: None)
    progress = {
        "contract": "sli.storage-lifecycle-declaration-progress.v1",
        "declaration_ids": [4], "scope_identity": "scope-a",
        "declaration_sha256": "a" * 64,
        "candidate_identity_sha256": "b" * 64,
    }
    progress["digest"] = worker._declaration_progress_digest(progress)

    def invoke(args, **_kwargs):
        if args[1].endswith("warm_tier_incremental_copy_runtime"):
            return {"status": "drained", "batches": 1, "copied_rows": 1,
                    "completed_packages": [{
                        "promotion_evidence_path": "C:/evidence/package.json",
                        "promotion_output_identity": "c" * 64,
                        "declaration_progress": progress,
                    }]}
        return {"status": "no_candidates", "candidate_count": 0,
                "processed_package_checkpoint": {
                    "progress_digest": "d" * 64,
                    "promotion_output_identity": "c" * 64,
                }}

    with pytest.raises(RuntimeError, match="retention_no_candidates_package_mismatch"):
        worker.run_cycle(invoke=invoke)
    assert not (tmp_path / "ledger.jsonl").exists()


def test_completed_delete_rejects_substituted_executed_package_before_checkpoint(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.setenv(worker.ENABLE_ENV, "1")
    monkeypatch.setenv(worker.ADMISSION_ENV, worker.DELETE_CONFIRMATION)
    monkeypatch.setattr(worker, "PROCESSED_PACKAGES", tmp_path / "ledger.jsonl")
    monkeypatch.setattr(worker, "_atomic_json", lambda *_args: None)
    progress = {
        "contract": "sli.storage-lifecycle-declaration-progress.v1",
        "declaration_ids": [4], "scope_identity": "scope-a",
        "declaration_sha256": "a" * 64,
        "candidate_identity_sha256": "b" * 64,
    }
    progress["digest"] = worker._declaration_progress_digest(progress)
    expected = {
        "promotion_output_identity": "c" * 64,
        "progress_digest": progress["digest"],
        "candidate_identity_sha256": "b" * 64,
        "source_reference_digest": "d" * 64,
        "manifest_digest": "e" * 64,
        "candidate_manifest_sha256": "f" * 64,
        "candidate_manifest_rows": 1,
    }

    def invoke(args, **_kwargs):
        if args[1].endswith("warm_tier_incremental_copy_runtime"):
            return {"status": "drained", "batches": 1, "copied_rows": 1,
                    "completed_packages": [{
                        "promotion_evidence_path": "C:/evidence/package.json",
                        "promotion_output_identity": "c" * 64,
                        "declaration_progress": progress,
                    }]}
        if args[1].endswith("tier_retention_delete_plan_runtime"):
            return {"status": "ready_for_owner_authorization", "candidate_count": 1,
                    "processed_package_binding": expected}
        return {"status": "complete", "deleted_rows": 1,
                "executed_package_binding": {**expected, "manifest_digest": "9" * 64}}

    with pytest.raises(RuntimeError, match="executed_retention_package_mismatch"):
        worker.run_cycle(invoke=invoke)
    assert not (tmp_path / "ledger.jsonl").exists()


def test_processed_package_ledger_rejects_oversized_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_bytes(b" " * (worker.MAX_PROCESSED_LEDGER_BYTES + 1))
    monkeypatch.setattr(worker, "PROCESSED_PACKAGES", ledger)

    with pytest.raises(RuntimeError, match="processed_package_ledger_too_large"):
        worker._processed_declaration_ids()


def test_run_records_startup_before_entering_the_lifecycle_cycle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    heartbeats: list[dict[str, object]] = []

    monkeypatch.setattr(worker, "lifecycle_lock", lambda: nullcontext(True))
    monkeypatch.setattr(
        worker,
        "record_worker_heartbeat",
        lambda **kwargs: heartbeats.append(kwargs),
    )

    def run_once(*, on_wait):
        assert [
            (item["status"], item["phase"])
            for item in heartbeats
        ] == [("starting", "startup"), ("running", "processing")]
        return {"status": "ok"}

    monkeypatch.setattr(worker, "run_cycle", run_once)

    assert worker.run(once=True, interval_seconds=900) == 0


def test_run_refreshes_active_work_then_reports_idle_after_a_clean_cycle(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    heartbeats: list[dict[str, object]] = []
    result_path = tmp_path / "storage-lifecycle-last.json"

    monkeypatch.setattr(worker, "lifecycle_lock", lambda: nullcontext(True))
    monkeypatch.setattr(worker, "LAST_RESULT", result_path)
    monkeypatch.setattr(
        worker,
        "record_worker_heartbeat",
        lambda **kwargs: heartbeats.append(kwargs),
    )

    def run_once(*, on_wait):
        on_wait()
        return {
            "status": "ok",
            "deleted_rows": 0,
            "copy_only_no_delete": True,
            "delete_execution_admitted": False,
        }

    monkeypatch.setattr(worker, "run_cycle", run_once)

    assert worker.run(once=True, interval_seconds=900) == 0
    assert [
        (item["status"], item["phase"])
        for item in heartbeats
    ] == [
        ("starting", "startup"),
        ("running", "processing"),
        ("running", "processing"),
        ("idle", "sleep"),
    ]
    details = heartbeats[-1]["details"]
    persisted = json.loads(result_path.read_text(encoding="utf-8"))
    assert persisted["deleted_rows"] == 0
    assert persisted["phase"] == "completed"
    assert details["last_result_digest"] == persisted["result_digest"]
    assert details["last_result_phase"] == "completed"
    assert details["copy_only_no_delete"] is True
    assert details["delete_execution_admitted"] is False
    assert details["deleted_rows"] == 0
    assert "last_result" not in details
    assert details["last_cycle_status"] == "success"
    assert details["last_success_at"] == details["last_cycle_completed_at"]
    assert details["last_error_type"] is None


@pytest.mark.parametrize("result,expected_status,expected_phase,expected_exit", [
    ({"status": "blocked", "reason": "snapshot_history_migration_required"}, "warning", "blocked", 2),
    ({"status": "blocked", "reason": "source_rows_held_for_processing_or_evidence"}, "warning", "blocked", 2),
    ({"status": "blocked", "reason": "history_source_link_details_missing"}, "warning", "blocked", 2),
    ({"status": "blocked", "reason": "history_source_archive_unavailable"}, "warning", "blocked", 2),
    ({"status": "blocked", "reason": "history_clickhouse_unavailable"}, "warning", "blocked", 2),
    ({"status": "blocked", "reason": "file_audit_semantic_pending"}, "warning", "blocked", 2),
    ({"status": "blocked", "reason": "history_source_link_role_mismatch"}, "blocked", "blocked", 2),
    ({"status": "blocked", "reason": "snapshot_history_source_hash_mismatch"}, "blocked", "blocked", 2),
    ({"status": "blocked", "reason": "purge_verification_or_io_failed"}, "blocked", "blocked", 2),
    ({"status": "ok", "warning_reason": "ad_snapshot_history_coverage_partial"}, "warning", "completed", 0),
])
def test_run_distinguishes_expected_wait_from_failed_preservation(
    result, expected_status, expected_phase, expected_exit, monkeypatch, tmp_path,
):
    heartbeats = []
    monkeypatch.setattr(worker, "lifecycle_lock", lambda: nullcontext(True))
    monkeypatch.setattr(worker, "LAST_RESULT", tmp_path / "result.json")
    monkeypatch.setattr(worker, "record_worker_heartbeat", lambda **kw: heartbeats.append(kw))
    monkeypatch.setattr(worker, "run_cycle", lambda **kw: {**result, "cycle_id": "synthetic"})
    assert worker.run(once=True, interval_seconds=900) == expected_exit
    assert heartbeats[-1]["status"] == expected_status
    details = heartbeats[-1]["details"]
    assert details["last_result_phase"] == expected_phase
    assert details["last_cycle_reason"] == result.get("reason", result.get("warning_reason"))
    assert details["last_cycle_status"] == ("blocked" if expected_phase == "blocked" else "success")
    assert details["last_successful_watermark"] == (None if expected_phase == "blocked" else "synthetic")


def test_run_reports_cycle_exceptions_as_failed_error_heartbeats(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    heartbeats: list[dict[str, object]] = []
    result_path = tmp_path / "storage-lifecycle-last.json"

    monkeypatch.setattr(worker, "lifecycle_lock", lambda: nullcontext(True))
    monkeypatch.setattr(worker, "LAST_RESULT", result_path)
    monkeypatch.setattr(
        worker,
        "record_worker_heartbeat",
        lambda **kwargs: heartbeats.append(kwargs),
    )

    def raise_cycle(*, on_wait):
        raise RuntimeError("injected lifecycle failure")

    monkeypatch.setattr(worker, "run_cycle", raise_cycle)

    assert worker.run(once=True, interval_seconds=900) == 2
    assert [
        (item["status"], item["phase"])
        for item in heartbeats
    ] == [
        ("starting", "startup"),
        ("running", "processing"),
        ("failed", "error"),
    ]
    persisted = json.loads(result_path.read_text(encoding="utf-8"))
    details = heartbeats[-1]["details"]
    assert persisted["phase"] == "failed"
    assert details["last_result_digest"] == persisted["result_digest"]
    assert details["last_result_phase"] == "failed"
    assert details["last_error_type"] == "RuntimeError"
    assert "last_result" not in details


def test_run_persists_terminal_cycle_evidence_during_processing_and_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    heartbeats: list[dict[str, object]] = []
    cycle_count = 0
    sleeps = 0

    monkeypatch.setattr(worker, "lifecycle_lock", lambda: nullcontext(True))
    monkeypatch.setattr(
        worker,
        "record_worker_heartbeat",
        lambda **kwargs: heartbeats.append(kwargs),
    )
    monkeypatch.setattr(
        worker,
        "get_storage_runtime_capacity_evidence",
        lambda: {"status": "ok", "read_only": True, "disk_free_bytes": 42},
    )

    def run_two_cycles(*, on_wait):
        nonlocal cycle_count
        cycle_count += 1
        if cycle_count == 1:
            return {"status": "ok", "deleted_rows": 0}
        active = heartbeats[-1]["details"]
        assert active["process_status"] == "running"
        assert active["last_cycle_status"] == "success"
        assert active["last_cycle_completed_at"] is not None
        assert isinstance(active["result_age_seconds"], int)
        raise RuntimeError("injected lifecycle failure")

    def stop_after_second_cycle(_seconds: int) -> None:
        nonlocal sleeps
        sleeps += 1
        if sleeps == 2:
            raise KeyboardInterrupt

    monkeypatch.setattr(worker, "run_cycle", run_two_cycles)
    monkeypatch.setattr(worker.time, "sleep", stop_after_second_cycle)

    with pytest.raises(KeyboardInterrupt):
        worker.run(once=False, interval_seconds=900)

    completed = [item for item in heartbeats if item["status"] in {"idle", "failed"}]
    successful, failed = completed
    startup = heartbeats[0]["details"]
    success_details = successful["details"]
    failed_details = failed["details"]
    assert startup["process_status"] == "starting"
    assert startup["result_age_seconds"] is None
    assert success_details["process_status"] == "running"
    assert success_details["last_cycle_status"] == "success"
    assert success_details["last_cycle_started_at"] is not None
    assert success_details["last_cycle_completed_at"] is not None
    assert success_details["last_success_at"] == success_details["last_cycle_completed_at"]
    assert success_details["last_error_type"] is None
    assert isinstance(success_details["result_age_seconds"], int)
    assert success_details["capacity_evidence"]["disk_free_bytes"] == 42
    assert failed_details["last_cycle_status"] == "failed"
    assert failed_details["last_cycle_completed_at"] is not None
    assert failed_details["last_success_at"] == success_details["last_success_at"]
    assert failed_details["last_error_type"] == "RuntimeError"
    assert failed_details["process_status"] == "running"
    assert isinstance(failed_details["result_age_seconds"], int)


def test_run_records_partial_result_and_refreshes_terminal_capacity_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    heartbeats: list[dict[str, object]] = []
    cycle_count = 0
    sleeps = 0
    capacity_values = iter((100, 90, 80, 70, 60))

    monkeypatch.setattr(worker, "lifecycle_lock", lambda: nullcontext(True))
    monkeypatch.setattr(worker, "_atomic_json", lambda *_args: None)
    monkeypatch.setattr(
        worker,
        "record_worker_heartbeat",
        lambda **kwargs: heartbeats.append(kwargs),
    )
    monkeypatch.setattr(
        worker,
        "get_storage_runtime_capacity_evidence",
        lambda: {"status": "ok", "disk_free_bytes": next(capacity_values)},
    )

    def run_two_cycles(*, on_wait):
        nonlocal cycle_count
        cycle_count += 1
        if cycle_count == 1:
            raise RuntimeError("injected lifecycle failure")
        return {"status": "partial", "next_retry_seconds": 300}

    def stop_after_partial_cycle(_seconds: int) -> None:
        nonlocal sleeps
        sleeps += 1
        if sleeps == 2:
            raise KeyboardInterrupt

    monkeypatch.setattr(worker, "run_cycle", run_two_cycles)
    monkeypatch.setattr(worker.time, "sleep", stop_after_partial_cycle)

    with pytest.raises(KeyboardInterrupt):
        worker.run(once=False, interval_seconds=900)

    second_active = heartbeats[-2]["details"]
    terminal = heartbeats[-1]["details"]
    assert heartbeats[-1]["status"] == "warning"
    assert terminal["last_cycle_status"] == "partial"
    assert terminal["last_cycle_reason"] == "history_publication_backlog_remaining"
    assert terminal["last_success_at"] is None
    assert terminal["last_error_type"] is None
    assert terminal["capacity_evidence"]["disk_free_bytes"] == 60
    assert terminal["capacity_evidence"] != second_active["capacity_evidence"]


def test_run_persists_digest_backed_lifecycle_result_and_success_watermark(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    heartbeats: list[dict[str, object]] = []
    result_path = tmp_path / "storage-lifecycle-last.json"
    monkeypatch.setattr(worker, "LAST_RESULT", result_path)
    monkeypatch.setattr(worker, "lifecycle_lock", lambda: nullcontext(True))
    monkeypatch.setattr(
        worker,
        "record_worker_heartbeat",
        lambda **kwargs: heartbeats.append(kwargs),
    )
    monkeypatch.setattr(
        worker,
        "run_cycle",
        lambda *, on_wait: {
            "status": "ok",
            "cycle_id": "20260903T010203000000Z",
            "cutoff_utc": "2026-08-27T01:02:03+00:00",
        },
    )

    assert worker.run(once=True, interval_seconds=900) == 0

    persisted = json.loads(result_path.read_text(encoding="utf-8"))
    assert persisted["started_at_utc"]
    assert persisted["ended_at_utc"]
    assert persisted["phase"] == "completed"
    assert persisted["cutoff_utc"] == "2026-08-27T01:02:03+00:00"
    assert persisted["error"] is None
    assert persisted["last_successful_watermark"] == "20260903T010203000000Z"
    assert persisted["result_digest"] == worker._lifecycle_result_digest(persisted)
    terminal_details = heartbeats[-1]["details"]
    assert terminal_details["last_result_digest"] == persisted["result_digest"]
    assert terminal_details["last_successful_watermark"] == persisted["last_successful_watermark"]
    assert "last_result" not in terminal_details


def test_run_does_not_disclose_private_failure_text(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys,
) -> None:
    result_path = tmp_path / "storage-lifecycle-last.json"
    error_text = "x" * 1_001
    monkeypatch.setattr(worker, "LAST_RESULT", result_path)
    monkeypatch.setattr(worker, "lifecycle_lock", lambda: nullcontext(True))
    monkeypatch.setattr(worker, "record_worker_heartbeat", lambda **_kwargs: None)

    def fail(*, on_wait) -> None:
        raise RuntimeError(error_text)

    monkeypatch.setattr(worker, "run_cycle", fail)

    assert worker.run(once=True, interval_seconds=900) == 2
    persisted = json.loads(result_path.read_text(encoding="utf-8"))
    assert persisted["phase"] == "failed"
    assert persisted["error"] == "purge_verification_or_io_failed"
    assert error_text not in capsys.readouterr().out
    assert persisted["cutoff_utc"] is None


def test_main_does_not_disclose_startup_or_result_io_errors(monkeypatch, capsys):
    monkeypatch.setattr(worker.sys, "argv", ["storage-lifecycle", "--once"])

    def fail(**kwargs):
        raise OSError("synthetic private startup connection or result path")

    monkeypatch.setattr(worker, "run", fail)
    assert worker.main() == 2
    output = json.loads(capsys.readouterr().out)
    assert output == {"status": "failed", "reason": "purge_verification_or_io_failed", "error_type": "OSError"}

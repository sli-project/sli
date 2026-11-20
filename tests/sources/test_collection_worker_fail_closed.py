from __future__ import annotations

from contextlib import contextmanager
import importlib
import json
import os
import subprocess
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.core


def test_invalid_windows_security_context_is_non_retryable() -> None:
    from server.sli.sources.collection_failure_policy import classify_collection_failure

    decision = classify_collection_failure([
        "DC2: (1749, 'EvtOpenSession', 'Неправильный контекст безопасности.')"
    ])

    assert decision.blocked is True
    assert decision.code == "windows_security_context_invalid"
    assert decision.phase == "security_context_invalid"
    assert "Автоматический повтор отключён" in str(decision.operator_action)


def test_machine_readable_security_context_code_is_non_retryable() -> None:
    from server.sli.sources.collection_failure_policy import classify_collection_failure

    decision = classify_collection_failure([
        "DC1: код возврата 74; Collection blocked before backend fallback/import/cursor update: windows_security_context_invalid"
    ])
    assert decision.blocked is True
    assert decision.code == "windows_security_context_invalid"


def test_preflight_reads_one_remote_event_instead_of_only_opening_session(
    monkeypatch,
) -> None:
    from server.sli.sources import windows_event_probe as module
    from scripts.collect import collect_windows_events

    session = object()
    observed: dict[str, object] = {}
    monkeypatch.setattr(
        collect_windows_events,
        "open_remote_session",
        lambda server: observed.setdefault("server", server) and session,
    )
    monkeypatch.setattr(
        collect_windows_events,
        "probe_latest_record_id",
        lambda actual_session, channel, timeout_ms: observed.update(
            session=actual_session,
            channel=channel,
            timeout_ms=timeout_ms,
        ) or 123,
    )
    monkeypatch.setattr(module, "_close_evt_handle", lambda handle: None)

    result = module.probe_windows_event_context("DC2")

    assert result["status"] == "ok"
    assert result["query_access"] == "verified"
    assert result["event_observed"] is True
    assert observed["server"] == "DC2"
    assert observed["session"] is session
    assert observed["channel"] == "Security"


def test_preflight_classifies_evtquery_access_denied(monkeypatch) -> None:
    from server.sli.sources import windows_event_probe as module
    from scripts.collect import collect_windows_events

    class AccessDenied(Exception):
        winerror = 5

    monkeypatch.setattr(
        collect_windows_events,
        "open_remote_session",
        lambda server: object(),
    )
    monkeypatch.setattr(
        collect_windows_events,
        "probe_latest_record_id",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AccessDenied("EvtQuery access denied")
        ),
    )
    monkeypatch.setattr(module, "_close_evt_handle", lambda handle: None)

    result = module.probe_windows_event_context("DC2")

    assert result["status"] == "failed"
    assert result["failure_code"] == "windows_event_log_access_denied"
    assert result["winerror"] == 5


def test_unrelated_collection_error_remains_retryable() -> None:
    from server.sli.sources.collection_failure_policy import classify_collection_failure

    assert classify_collection_failure(["bounded channel timeout"]).blocked is False


def test_numeric_winerror_and_hresult_are_classified_without_localized_text() -> None:
    from server.sli.sources.collection_failure_policy import classify_collection_failure

    class NativeError(Exception):
        winerror = 1749

    class HResultError(Exception):
        hresult = 0x800706D5

    assert classify_collection_failure([NativeError("localized")]).blocked is True
    assert classify_collection_failure([HResultError("localized")]).blocked is True


def test_pilot_blocks_partial_batch_before_import(tmp_path) -> None:
    from scripts.run_dc_log_pilot import summarize_channel_status, write_collection_block_marker

    summary = {
        "started_at": "2026-07-22T00:00:00+00:00",
        "channels": [
            {"channel": "Security", "status": "completed", "count": 5},
            {"channel": "System", "status": "failed", "count": 0,
             "error": "(1749, 'EvtOpenSession', 'The security context has expired.')"},
        ],
    }
    status = summarize_channel_status(summary)

    assert status["terminal_block"] is True
    assert status["import_allowed"] is False
    marker = write_collection_block_marker(tmp_path, summary, status, server="DC2")
    payload = __import__("json").loads(marker.read_text(encoding="utf-8"))
    assert payload["pipeline_disposition"] == "blocked_pre_import"
    assert payload["import_attempted"] is False
    assert payload["cursor_advanced"] is False


def test_run_cycle_persists_security_context_block(monkeypatch) -> None:
    from scripts.runtime import collection_worker as module

    @contextmanager
    def acquired_lock():
        yield True

    updates: list[dict[str, object]] = []
    monkeypatch.setattr(module, "load_config", lambda: SimpleNamespace(db_backend="postgres"))
    monkeypatch.setattr(module, "get_active_collection_block", lambda: None)
    monkeypatch.setattr(module, "collection_worker_lock", acquired_lock)
    monkeypatch.setattr(module, "start_runtime_collection_run", lambda **kwargs: None)
    monkeypatch.setattr(module, "update_runtime_collection_run", lambda run_id, **kwargs: updates.append(kwargs))
    monkeypatch.setattr(module, "create_collect_job", lambda **kwargs: {"id": 7, "servers": ["DC2"]})
    monkeypatch.setattr(module, "get_job", lambda job_id: {
        "status": "failed", "phase": "done", "duration_ms": 3123,
        "errors": ["(1749, 'EvtOpenSession', 'Неправильный контекст безопасности.')"],
    })

    result = module.run_cycle(hours=1, max_events=10, wait_seconds=1, worker_id="test-worker")

    assert result["status"] == "blocked"
    assert result["reason"] == "windows_security_context_invalid"
    assert result["phase"] == "security_context_invalid"
    assert updates[-1]["status"] == "blocked"
    assert updates[-1]["phase"] == "security_context_invalid"


def test_run_cycle_rechecks_durable_block_before_classifying_terminal_job(monkeypatch) -> None:
    from scripts.runtime import collection_worker as module

    @contextmanager
    def acquired_lock():
        yield True

    blocks = iter([None, {
        "reason_code": "windows_security_context_invalid",
        "operator_action": "operator recovery required",
    }])
    updates: list[dict[str, object]] = []
    monkeypatch.setattr(module, "load_config", lambda: SimpleNamespace(db_backend="postgres"))
    monkeypatch.setattr(module, "get_active_collection_block", lambda: next(blocks))
    monkeypatch.setattr(module, "collection_worker_lock", acquired_lock)
    monkeypatch.setattr(module, "start_runtime_collection_run", lambda **kwargs: None)
    monkeypatch.setattr(module, "update_runtime_collection_run", lambda run_id, **kwargs: updates.append(kwargs))
    monkeypatch.setattr(module, "create_collect_job", lambda **kwargs: {"id": 9, "servers": ["DC1"]})
    monkeypatch.setattr(module, "get_job", lambda job_id: {
        "status": "failed", "phase": "done", "duration_ms": 100,
        "errors": ["localized collector failure without stable text"],
    })

    result = module.run_cycle(hours=1, max_events=10, wait_seconds=1, worker_id="test-worker")

    assert result["status"] == "blocked"
    assert result["reason"] == "windows_security_context_invalid"
    assert result["operator_action"] == "operator recovery required"
    assert updates[-1]["status"] == "blocked"


def test_running_cycle_refreshes_heartbeat_without_waiting_for_terminal_job(monkeypatch) -> None:
    from scripts.runtime import collection_worker as module

    @contextmanager
    def acquired_lock():
        yield True

    jobs = iter([
        {"status": "running", "phase": "collection"},
        {"status": "completed", "phase": "done", "duration_ms": 100, "errors": []},
    ])
    monotonic = iter([0.0, 31.0])
    heartbeats: list[dict[str, object]] = []
    monkeypatch.setattr(module, "load_config", lambda: SimpleNamespace(db_backend="postgres"))
    monkeypatch.setattr(module, "get_active_collection_block", lambda: None)
    monkeypatch.setattr(module, "collection_worker_lock", acquired_lock)
    monkeypatch.setattr(module, "start_runtime_collection_run", lambda **kwargs: None)
    monkeypatch.setattr(module, "update_runtime_collection_run", lambda *args, **kwargs: None)
    monkeypatch.setattr(module, "create_collect_job", lambda **kwargs: {"id": 11, "servers": ["DC1"]})
    monkeypatch.setattr(module, "get_job", lambda job_id: next(jobs))
    monkeypatch.setattr(module.time, "monotonic", lambda: next(monotonic))
    monkeypatch.setattr(module.time, "sleep", lambda seconds: None)

    result = module.run_cycle(
        hours=1,
        max_events=50_000,
        wait_seconds=1,
        worker_id="test-worker",
        heartbeat_callback=heartbeats.append,
    )

    assert result["status"] == "completed"
    assert heartbeats == [{"job_id": 11, "status": "running", "phase": "collection"}]


def test_continuous_worker_exits_without_sleep_after_block(monkeypatch) -> None:
    from scripts.runtime import collection_worker as module

    heartbeats: list[dict[str, object]] = []
    @contextmanager
    def process_lock():
        yield True
    monkeypatch.setattr(module, "collection_process_lock", process_lock)
    monkeypatch.setattr(module.sys, "argv", ["collection_worker.py", "--preflight-server", "DC2"])
    monkeypatch.setattr(module, "preflight_windows_collection_context", lambda **kwargs: {"status": "ok", "server": "DC2"})
    monkeypatch.setattr(module, "clear_matching_block_after_successful_preflight", lambda **kwargs: None)
    monkeypatch.setattr(module, "run_cycle", lambda **kwargs: {
        "status": "blocked", "phase": "security_context_invalid",
        "reason": "windows_security_context_invalid", "operator_action": "operator action",
    })
    monkeypatch.setattr(module, "record_worker_heartbeat", lambda **kwargs: heartbeats.append(kwargs))
    monkeypatch.setattr(module, "log_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(module.time, "sleep", lambda seconds: (_ for _ in ()).throw(AssertionError("retry sleep")))

    assert module.main() == 2
    assert heartbeats[-1]["status"] == "blocked"
    assert heartbeats[-1]["phase"] == "security_context_invalid"


def test_worker_requires_context_preflight_before_run_cycle(monkeypatch) -> None:
    from scripts.runtime import collection_worker as module

    monkeypatch.setattr(module.sys, "argv", ["collection_worker.py", "--once"])
    @contextmanager
    def process_lock():
        yield True
    monkeypatch.setattr(module, "collection_process_lock", process_lock)
    monkeypatch.setattr(
        module,
        "run_cycle",
        lambda **kwargs: (_ for _ in ()).throw(AssertionError("collection must not start")),
    )

    assert module.main() == 2


def test_successful_worker_preflight_reuses_probe_to_clear_matching_block(monkeypatch) -> None:
    from scripts.runtime import collection_worker as module

    calls: list[dict[str, object]] = []
    monkeypatch.setattr(module, "get_active_collection_block", lambda: {
        "reason_code": "windows_security_context_invalid",
    })
    monkeypatch.setattr(
        module,
        "record_probe_and_clear",
        lambda **kwargs: calls.append(kwargs) or {"active": False},
    )
    monkeypatch.setattr(module.getpass, "getuser", lambda: "operator")

    result = module.clear_matching_block_after_successful_preflight(server="DC2")

    assert result == {"active": False}
    assert calls == [{
        "probe_server": "DC2",
        "cleared_by": "worker-preflight:operator",
    }]


def test_invalid_exact_worker_identity_activates_durable_block(monkeypatch) -> None:
    from scripts.runtime import collection_worker as module
    from server.sli.sources import windows_runtime_identity

    activated: list[dict[str, object]] = []
    monkeypatch.setattr(
        windows_runtime_identity,
        "verify_collection_identity",
        lambda: {
            "status": "failed",
            "reason": "windows_collection_identity_invalid",
            "reasons": ["sid_mismatch"],
        },
    )
    monkeypatch.setattr(
        module,
        "activate_collection_block",
        lambda **kwargs: activated.append(kwargs) or {
            "operator_action": kwargs["operator_action"]
        },
    )
    monkeypatch.setattr(module, "log_event", lambda *args, **kwargs: None)

    result = module.preflight_windows_collection_context(
        server="DC2", worker_id="worker-test"
    )

    assert result["status"] == "failed"
    assert result["failure_code"] == "windows_security_context_invalid"
    assert activated[0]["source_worker_id"] == "worker-test"
    assert activated[0]["evidence"]["identity_reasons"] == ["sid_mismatch"]


def test_successful_worker_preflight_does_not_clear_unrelated_block(monkeypatch) -> None:
    from scripts.runtime import collection_worker as module

    monkeypatch.setattr(module, "get_active_collection_block", lambda: {
        "reason_code": "disk_pressure_stop",
    })
    monkeypatch.setattr(
        module,
        "record_probe_and_clear",
        lambda **kwargs: (_ for _ in ()).throw(AssertionError("must not clear")),
    )

    with pytest.raises(RuntimeError, match="cannot be cleared"):
        module.clear_matching_block_after_successful_preflight(server="DC2")


def test_continuous_worker_default_is_normal_50k_profile(monkeypatch) -> None:
    from scripts.runtime import collection_worker as module

    monkeypatch.setenv("ADLOG_EXTERNAL_STORAGE_V2_OUTBOX_WORKER", "test-original")
    monkeypatch.setenv("ADLOG_EXTERNAL_POST_COLLECTION_WORKER", "test-original")
    captured: dict[str, object] = {}
    @contextmanager
    def process_lock():
        yield True
    monkeypatch.setattr(module, "collection_process_lock", process_lock)
    monkeypatch.setattr(module.sys, "argv", [
        "collection_worker.py", "--once", "--preflight-server", "DC2",
    ])
    monkeypatch.setattr(
        module,
        "preflight_windows_collection_context",
        lambda **kwargs: {"status": "ok", "server": "DC2"},
    )
    monkeypatch.setattr(module, "clear_matching_block_after_successful_preflight", lambda **kwargs: None)
    monkeypatch.setattr(
        module,
        "run_cycle",
        lambda **kwargs: captured.update(kwargs) or {"status": "completed"},
    )
    monkeypatch.setattr(module, "record_worker_heartbeat", lambda **kwargs: None)
    monkeypatch.setattr(module, "log_event", lambda *args, **kwargs: None)

    assert module.main() == 0
    assert captured["max_events"] == 50_000
    assert os.environ["ADLOG_EXTERNAL_STORAGE_V2_OUTBOX_WORKER"] == "1"
    assert os.environ["ADLOG_EXTERNAL_POST_COLLECTION_WORKER"] == "1"


def test_worker_stops_before_run_cycle_when_context_preflight_fails(monkeypatch) -> None:
    from scripts.runtime import collection_worker as module

    heartbeats: list[dict[str, object]] = []
    @contextmanager
    def process_lock():
        yield True
    monkeypatch.setattr(module, "collection_process_lock", process_lock)
    monkeypatch.setattr(module.sys, "argv", ["collection_worker.py", "--once", "--preflight-server", "DC2"])
    monkeypatch.setattr(module, "preflight_windows_collection_context", lambda **kwargs: {
        "status": "failed",
        "server": "DC2",
        "reason": "windows_security_context_invalid",
        "operator_action": "interactive token required",
    })
    monkeypatch.setattr(module, "record_worker_heartbeat", lambda **kwargs: heartbeats.append(kwargs))
    monkeypatch.setattr(
        module,
        "run_cycle",
        lambda **kwargs: (_ for _ in ()).throw(AssertionError("collection must not start")),
    )

    assert module.main() == 2
    assert heartbeats[-1]["phase"] == "security_context_preflight"


def test_postgres_importer_rejects_quarantined_batch_before_db_connect(tmp_path, monkeypatch) -> None:
    module = importlib.import_module("scripts.import.import_event_jsonl_to_postgres")

    (tmp_path / "Security.jsonl").write_text("{}\n", encoding="utf-8")
    (tmp_path / "collection-blocked.json").write_text(
        '{"failure_code":"windows_security_context_invalid","pipeline_disposition":"blocked_pre_import"}',
        encoding="utf-8",
    )
    monkeypatch.setattr(module.sys, "argv", [
        "import_event_jsonl_to_postgres.py", "--input-dir", str(tmp_path), "--server", "DC2",
    ])
    monkeypatch.setattr(module, "connect", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("DB connect")))
    monkeypatch.setattr(module, "log_event", lambda *args, **kwargs: None)

    assert module.main() == 74


def test_durable_security_block_is_visible_even_when_collection_env_is_disabled(monkeypatch) -> None:
    from server.sli.sources import collection_runtime_block
    from server.jobs import collector

    monkeypatch.setattr(collector, "_runtime_db_backend", lambda: "postgres")
    monkeypatch.setattr(collector, "_env_truthy", lambda name: name == "ADLOG_DISABLE_COLLECTION")
    monkeypatch.setattr(collector, "_postgres_collection_enabled", lambda: True)
    monkeypatch.setattr(collection_runtime_block, "get_active_collection_block", lambda: {
        "reason_code": "windows_security_context_invalid"
    })

    assert collector._collection_block_reason() == "windows_security_context_invalid"


def test_worker_requested_limit_is_absolute_over_adaptive_recovery(monkeypatch) -> None:
    from server.jobs import collector

    captured: dict[str, object] = {}
    monkeypatch.setattr(
        collector,
        "_scheduler_canary_config",
        lambda: {"enabled": False, "archive_enabled": False},
    )
    monkeypatch.setattr(
        collector,
        "get_adaptive_plan_for_server",
        lambda server: SimpleNamespace(
            channels=["Security"],
            channel_limits={"Security": 50_000},
            channel_timeouts={"Security": 900},
            recovery_mode=True,
            reason="test_recovery",
        ),
    )
    monkeypatch.setattr(collector, "resolve_domain_controller_connect_address", lambda server: "127.0.0.1")
    monkeypatch.setattr(collector, "log_event", lambda *args, **kwargs: captured.setdefault("log", kwargs))

    def fake_run(command, timeout_seconds, **kwargs):
        captured["command"] = command
        captured["timeout_seconds"] = timeout_seconds
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(collector, "_run_subprocess_live", fake_run)

    collector._run_single_server_collection("DC1", 1, 5_000, job_id=7)

    command = list(captured["command"])
    limits = json.loads(command[command.index("--channel-limits-json") + 1])
    assert limits == {"Security": 5_000}
    assert command[command.index("--max-events-per-channel") + 1] == "5000"
    assert captured["log"]["adaptive_limits_capped"] is True


def test_collect_now_and_scheduler_subprocess_forces_storage_v2_external_owner(monkeypatch) -> None:
    """Manual "Collect Now" and the in-process scheduler both reach the
    run_dc_log_pilot.py subprocess through _run_single_server_collection.
    Neither sets ADLOG_EXTERNAL_STORAGE_V2_OUTBOX_WORKER for themselves (only
    scripts/runtime/collection_worker.py does, for its own process), so
    without forcing it at spawn time the child would inherit whatever the
    parent process happens to have -- commonly unset -- letting the pilot's
    own compat-drain race scripts/runtime/storage_v2_outbox_worker.py for the
    same outbox row. This asserts the forced value at the actual subprocess
    spawn call, not just by reading the source.
    """
    from server.jobs import collector

    monkeypatch.delenv("ADLOG_EXTERNAL_STORAGE_V2_OUTBOX_WORKER", raising=False)
    monkeypatch.setattr(collector, "_scheduler_canary_config", lambda: {"enabled": False, "archive_enabled": False})
    monkeypatch.setattr(
        collector,
        "get_adaptive_plan_for_server",
        lambda server: SimpleNamespace(
            channels=["Security"],
            channel_limits={"Security": 5},
            channel_timeouts={"Security": 5},
            recovery_mode=False,
            reason="test",
        ),
    )
    monkeypatch.setattr(collector, "resolve_domain_controller_connect_address", lambda server: "127.0.0.1")
    monkeypatch.setattr(collector, "log_event", lambda *args, **kwargs: None)

    captured: dict[str, object] = {}

    class FakeProcess:
        pid = 999
        returncode = 0
        stdout = iter(())

        def poll(self):
            return 0

    def fake_popen(command, *, cwd, text, stdout, stderr, bufsize, env, **kwargs):
        captured["env"] = env
        return FakeProcess()

    monkeypatch.setattr(collector.subprocess, "Popen", fake_popen)

    collector._run_single_server_collection("DC1", 1, 5, job_id=None)

    assert "env" in captured and captured["env"] is not None
    assert captured["env"]["ADLOG_EXTERNAL_STORAGE_V2_OUTBOX_WORKER"] == "1"
    assert "ADLOG_EXTERNAL_STORAGE_V2_OUTBOX_WORKER" not in os.environ


def test_pre_spawn_contract_rejects_limit_above_requested_ceiling() -> None:
    from server.jobs import collector

    with pytest.raises(RuntimeError, match="exceeds requested ceiling"):
        collector._validate_requested_channel_ceiling(
            requested_max_events=5_000,
            channels=["Security"],
            channel_limits={"Security": 50_000},
        )


def test_pre_spawn_contract_rejects_missing_channel_limit() -> None:
    from server.jobs import collector

    with pytest.raises(RuntimeError, match="missing"):
        collector._validate_requested_channel_ceiling(
            requested_max_events=5_000,
            channels=["Security", "System"],
            channel_limits={"Security": 5_000},
        )


def test_below_threshold_admission_does_not_persist_job_or_start_thread(monkeypatch) -> None:
    from server.jobs import collector

    started_threads: list[dict[str, object]] = []

    class CapturingThread:
        def __init__(self, *args, **kwargs) -> None:
            self.kwargs = kwargs

        def start(self) -> None:
            started_threads.append(self.kwargs)

    monkeypatch.setattr(collector, "_collection_block_reason", lambda: None)
    monkeypatch.setattr(
        collector,
        "can_start_collection",
        lambda: {
            "collection_allowed": False,
            "status": "blocked",
            "reason": "disk_pressure_threshold",
        },
    )
    monkeypatch.setattr(collector.threading, "Thread", CapturingThread)
    monkeypatch.setattr(collector, "log_audit_action", lambda *args, **kwargs: None)
    monkeypatch.setattr(collector, "log_event", lambda *args, **kwargs: None)
    with collector._lock:
        before_jobs = dict(collector._jobs)

    try:
        result = collector.create_collect_job(
            servers=["DC1"],
            hours=1,
            max_events_per_channel=321,
            reason="external_worker",
        )

        assert result["status"] == "skipped"
        assert result["reason"] == "disk_pressure_threshold"
        assert "id" not in result
        assert started_threads == []
        with collector._lock:
            assert collector._jobs == before_jobs
    finally:
        with collector._lock:
            collector._jobs.clear()
            collector._jobs.update(before_jobs)


def test_guard_read_exception_blocks_before_source_or_subprocess(monkeypatch) -> None:
    from server.jobs import collector

    source_calls: list[bool] = []
    batch_calls: list[tuple[object, ...]] = []
    started_threads: list[dict[str, object]] = []

    class CapturingThread:
        def __init__(self, *args, **kwargs) -> None:
            self.kwargs = kwargs

        def start(self) -> None:
            started_threads.append(self.kwargs)

    def guard_read_error() -> dict:
        raise OSError("disk status unavailable")

    monkeypatch.setattr(collector, "_collection_block_reason", lambda: None)
    monkeypatch.setattr(collector, "can_start_collection", guard_read_error)
    monkeypatch.setattr(
        collector,
        "discover_domain_controllers",
        lambda: source_calls.append(True) or ["DC1"],
    )
    monkeypatch.setattr(
        collector,
        "_collect_servers_parallel",
        lambda *args, **kwargs: batch_calls.append(args) or [],
    )
    monkeypatch.setattr(collector.threading, "Thread", CapturingThread)
    monkeypatch.setattr(collector, "log_audit_action", lambda *args, **kwargs: None)
    monkeypatch.setattr(collector, "log_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(collector, "log_internal_error", lambda *args, **kwargs: "guard-error")
    with collector._lock:
        before_jobs = dict(collector._jobs)

    try:
        result = collector.create_collect_job(
            hours=1,
            max_events_per_channel=321,
            reason="external_worker",
        )

        assert result["status"] == "blocked"
        assert result["reason"] == "collection_guard_error"
        assert result.get("error_type") == "OSError"
        assert "id" not in result
        assert source_calls == []
        assert batch_calls == []
        assert started_threads == []
        with collector._lock:
            assert collector._jobs == before_jobs
    finally:
        with collector._lock:
            collector._jobs.clear()
            collector._jobs.update(before_jobs)


def test_allowed_admission_starts_thread_with_requested_event_ceiling(monkeypatch) -> None:
    from server.jobs import collector

    started_threads: list[dict[str, object]] = []

    class CapturingThread:
        def __init__(self, *args, **kwargs) -> None:
            self.kwargs = kwargs

        def start(self) -> None:
            started_threads.append(self.kwargs)

    monkeypatch.setattr(collector, "_collection_block_reason", lambda: None)
    monkeypatch.setattr(
        collector,
        "can_start_collection",
        lambda: {"collection_allowed": True, "status": "ok"},
    )
    monkeypatch.setattr(collector.threading, "Thread", CapturingThread)
    monkeypatch.setattr(collector, "log_audit_action", lambda *args, **kwargs: None)
    monkeypatch.setattr(collector, "log_event", lambda *args, **kwargs: None)
    with collector._lock:
        before_jobs = dict(collector._jobs)

    try:
        result = collector.create_collect_job(
            servers=["DC1"],
            hours=2,
            max_events_per_channel=321,
            reason="external_worker",
        )

        assert result["status"] == "queued"
        assert result["max_events_per_channel"] == 321
        assert result["id"] in collector._jobs
        assert started_threads == [{
            "target": collector._run_collect_job,
            "args": (result["id"], "external_worker"),
            "daemon": True,
        }]
    finally:
        with collector._lock:
            collector._jobs.clear()
            collector._jobs.update(before_jobs)


def test_queued_job_rechecks_admission_before_collection_batch(monkeypatch) -> None:
    from server.jobs import collector

    guard_results = iter([
        {"collection_allowed": True, "status": "ok"},
        {
            "collection_allowed": False,
            "status": "blocked",
            "reason": "disk_pressure_threshold",
        },
    ])
    batch_calls: list[tuple[object, ...]] = []

    class CapturingThread:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def start(self) -> None:
            pass

    monkeypatch.setattr(collector, "_collection_block_reason", lambda: None)
    monkeypatch.setattr(collector, "can_start_collection", lambda: next(guard_results))
    monkeypatch.setattr(collector.threading, "Thread", CapturingThread)
    monkeypatch.setattr(collector, "CONTINUOUS_RECOVERY_ENABLED", False)
    monkeypatch.setattr(
        collector,
        "_collect_servers_parallel",
        lambda *args, **kwargs: batch_calls.append(args) or [],
    )
    monkeypatch.setattr(collector, "_scheduler_skip_report_enabled", lambda: True)
    monkeypatch.setattr(collector, "log_audit_action", lambda *args, **kwargs: None)
    monkeypatch.setattr(collector, "log_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(collector, "log_performance_stage", lambda *args, **kwargs: None)
    monkeypatch.setattr(collector, "log_internal_error", lambda *args, **kwargs: "collect-error")
    with collector._lock:
        before_jobs = dict(collector._jobs)

    try:
        created = collector.create_collect_job(
            servers=["DC1"],
            hours=1,
            max_events_per_channel=321,
            reason="external_worker",
        )
        collector._run_collect_job_body(int(created["id"]))
        result = collector.get_job(int(created["id"]))

        assert batch_calls == []
        assert result is not None
        assert result["status"] == "skipped"
        assert result["skipped_reason"] == "disk_pressure_threshold"
    finally:
        with collector._lock:
            collector._jobs.clear()
            collector._jobs.update(before_jobs)


def test_run_cycle_persists_guard_error_without_job_id(monkeypatch) -> None:
    from scripts.runtime import collection_worker as module

    @contextmanager
    def acquired_lock():
        yield True

    updates: list[dict[str, object]] = []
    monkeypatch.setattr(module, "load_config", lambda: SimpleNamespace(db_backend="postgres"))
    monkeypatch.setattr(module, "get_active_collection_block", lambda: None)
    monkeypatch.setattr(module, "collection_worker_lock", acquired_lock)
    monkeypatch.setattr(module, "start_runtime_collection_run", lambda **kwargs: None)
    monkeypatch.setattr(
        module,
        "update_runtime_collection_run",
        lambda run_id, **kwargs: updates.append(kwargs),
    )
    monkeypatch.setattr(
        module,
        "create_collect_job",
        lambda **kwargs: {
            "status": "blocked",
            "phase": "admission",
            "reason": "collection_guard_error",
            "collection_allowed": False,
            "error_type": "OSError",
        },
    )
    monkeypatch.setattr(
        module,
        "get_job",
        lambda job_id: (_ for _ in ()).throw(AssertionError("job must not be read")),
    )

    result = module.run_cycle(hours=1, max_events=321, wait_seconds=1, worker_id="test-worker")

    assert result["status"] == "blocked"
    assert result["phase"] == "admission"
    assert result["reason"] == "collection_guard_error"
    assert "job_id" not in result
    assert updates[-1]["status"] == "blocked"
    assert updates[-1]["phase"] == "admission"
    assert updates[-1]["errors"] == ["collection_guard_error"]

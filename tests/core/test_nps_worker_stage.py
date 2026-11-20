"""NPS is serial supplemental work inside, never beside, collection_worker."""
from __future__ import annotations

from contextlib import nullcontext
from types import SimpleNamespace

import pytest


def test_nps_stage_is_off_by_default_without_route_or_database_access(monkeypatch):
    from scripts.runtime import collection_worker as worker

    monkeypatch.delenv("ADLOG_NPS_EVENTLOG_ENABLED", raising=False)
    monkeypatch.setattr(worker, "load_config", lambda: (_ for _ in ()).throw(AssertionError("unexpected")))

    assert worker.run_nps_stage(dc_servers=["DC1"], max_events=50000, heartbeat_callback=None) == {"status": "disabled"}


def test_nps_invalid_enable_value_fails_closed(monkeypatch):
    from scripts.runtime import collection_worker as worker

    monkeypatch.setenv("ADLOG_NPS_EVENTLOG_ENABLED", "true")
    with pytest.raises(RuntimeError, match="nps_eventlog_enabled_value_invalid"):
        worker.run_nps_stage(dc_servers=[], max_events=1, heartbeat_callback=None)


def test_nps_stage_uses_exact_pilot_contract_and_heartbeats_while_waiting(monkeypatch):
    from scripts.runtime import collection_worker as worker
    from scripts import run_dc_log_pilot as pilot
    from server.sli.core import postgres_runtime_pipeline as pipeline
    from server.source_packs.radius import collection_routes as routes

    monkeypatch.setenv("ADLOG_NPS_EVENTLOG_ENABLED", "1")
    monkeypatch.setattr(routes, "load_radius_collection_routes", lambda: {
        "source_name": "nps.example.test", "source_instance_id": "nps.example.test",
        "owner_confirmed_ip": "10.0.0.4", "event_log_ready": True,
        "event_log_adapter": "windows-eventlog-pywin32",
    })
    monkeypatch.setattr(pipeline, "get_collection_plan_for_server_pg", lambda server, channels: {
        "Security": {"start_time_utc": "2026-09-10T00:00:00+00:00"}
    })
    monkeypatch.setattr(pilot, "postgres_import_timeout_seconds", lambda: 1800)
    received: dict[str, object] = {}
    complete = SimpleNamespace(returncode=0, stdout='collection_result={"status":"completed"}\n', stderr="")
    class Future:
        calls = 0
        def result(self, timeout):
            self.calls += 1
            if self.calls == 1:
                raise worker.TimeoutError()
            return complete
    class Executor:
        def __init__(self, **kwargs):
            received["executor"] = kwargs
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def submit(self, fn, command, *, timeout_seconds):
            received["command"] = command
            received["timeout"] = timeout_seconds
            return Future()
    monkeypatch.setattr(worker, "ThreadPoolExecutor", Executor)
    heartbeats: list[dict[str, object]] = []

    result = worker.run_nps_stage(dc_servers=["DC1"], max_events=90000, heartbeat_callback=heartbeats.append)

    command = received["command"]
    assert command[2:] == [
        "--nps-continuous", "--server", "nps.example.test", "--connect-address", "nps.example.test",
        "--channels", "Security", "--archive", "--use-record-id-cursor", "true",
        "--adaptive-state-mode", "observe", "--collect-message", "false",
        "--max-events-per-channel", "50000", "--channel-timeout-seconds", "60",
        "--command-timeout-seconds", "90", "--collector-backend", "python",
        "--ad-source-credential-mode", "dpapi_current_user", "--event-ids-json", "[6272,6273]",
        "--start-time-utc", "2026-09-10T00:00:00+00:00", "--end-time-utc", command[-2],
        "--no-technical-report",
    ]
    assert received["timeout"] == 1950
    assert heartbeats == [{"status": "running", "phase": "nps", "source": "nps.example.test"}]
    assert result["status"] == "completed"


def _cycle_mocks(monkeypatch, *, dc_status: str, nps_result=None):
    from scripts.runtime import collection_worker as worker
    monkeypatch.setattr(worker, "load_config", lambda: SimpleNamespace(db_backend="postgres"))
    monkeypatch.setattr(worker, "get_active_collection_block", lambda: None)
    monkeypatch.setattr(worker, "collection_worker_lock", lambda: nullcontext(True))
    monkeypatch.setattr(worker, "start_runtime_collection_run", lambda **_: None)
    updates: list[dict[str, object]] = []
    monkeypatch.setattr(worker, "update_runtime_collection_run", lambda *args, **kwargs: updates.append(kwargs))
    monkeypatch.setattr(worker, "create_collect_job", lambda **_: {"id": 7, "servers": ["DC1"]})
    monkeypatch.setattr(worker, "get_job", lambda _: {"status": dc_status, "phase": "done", "errors": [], "warnings": []})
    if nps_result is not None:
        monkeypatch.setattr(worker, "run_nps_stage", lambda **_: nps_result)
    return worker, updates


def test_failed_dc_job_never_starts_nps(monkeypatch):
    worker, _updates = _cycle_mocks(monkeypatch, dc_status="failed")
    monkeypatch.setattr(worker, "run_nps_stage", lambda **_: (_ for _ in ()).throw(AssertionError("nps started")))

    result = worker.run_cycle(hours=1, max_events=50000, wait_seconds=1)

    assert result["status"] == "failed"
    assert "nps" not in result


def test_nps_failure_is_recorded_separately_from_completed_dc_job(monkeypatch):
    worker, updates = _cycle_mocks(monkeypatch, dc_status="completed", nps_result={"status": "failed", "reason": "nps_access_denied", "phase": "nps", "output_tail": "safe"})
    monkeypatch.setenv("ADLOG_NPS_EVENTLOG_ENABLED", "1")
    order: list[str] = []
    monkeypatch.setattr(worker, "update_runtime_collection_run", lambda *args, **kwargs: order.append("history") or updates.append(kwargs))
    monkeypatch.setattr(worker, "run_nps_stage", lambda **_: order.append("nps") or {"status": "failed", "reason": "nps_access_denied", "phase": "nps", "output_tail": "safe"})

    result = worker.run_cycle(hours=1, max_events=50000, wait_seconds=1)

    assert result["status"] == "failed"
    assert result["phase"] == "nps"
    assert result["dc_status"] == "completed"
    assert result["nps"]["reason"] == "nps_access_denied"
    assert updates[-1]["phase"] == "nps"
    assert order == ["history", "nps", "history"]


def test_nps_partial_makes_the_cycle_partial_and_includes_its_duration(monkeypatch):
    worker, updates = _cycle_mocks(monkeypatch, dc_status="completed", nps_result={"status": "partial", "phase": "nps", "duration_ms": 40})
    monkeypatch.setenv("ADLOG_NPS_EVENTLOG_ENABLED", "1")
    monkeypatch.setattr(worker, "get_job", lambda _: {"status": "completed", "phase": "done", "duration_ms": 60, "errors": [], "warnings": []})

    result = worker.run_cycle(hours=1, max_events=50000, wait_seconds=1)

    assert result["status"] == "partial"
    assert result["phase"] == "nps"
    assert result["dc_status"] == "completed"
    assert result["duration_ms"] == 100
    assert updates[-1]["status"] == "partial"


def test_safe_partial_dc_runs_nps_but_remains_partial_when_nps_completes(monkeypatch):
    worker, updates = _cycle_mocks(monkeypatch, dc_status="partial", nps_result={"status": "completed", "phase": "nps", "duration_ms": 4})
    monkeypatch.setenv("ADLOG_NPS_EVENTLOG_ENABLED", "1")
    monkeypatch.setattr(worker, "get_job", lambda _: {"status": "partial", "phase": "collection", "duration_ms": 6, "errors": [], "warnings": []})

    result = worker.run_cycle(hours=1, max_events=50000, wait_seconds=1)

    assert result["status"] == "partial"
    assert result["phase"] == "nps"
    assert result["dc_status"] == "partial"
    assert result["nps"]["status"] == "completed"
    assert result["duration_ms"] == 10
    assert updates[-1]["status"] == "partial"


def test_terminal_nps_classifier_persists_the_canonical_collection_block(monkeypatch):
    worker, updates = _cycle_mocks(monkeypatch, dc_status="completed", nps_result={
        "status": "failed", "phase": "nps", "reason": "windows_event_log_authentication_failed",
        "blocked": True, "operator_action": "repair credential", "source": "nps.example.test", "duration_ms": 1,
    })
    monkeypatch.setenv("ADLOG_NPS_EVENTLOG_ENABLED", "1")
    persisted: dict[str, object] = {}
    monkeypatch.setattr(worker, "activate_collection_block", lambda **kwargs: persisted.update(kwargs) or {
        "reason_code": kwargs["reason_code"], "operator_action": kwargs["operator_action"],
    })

    result = worker.run_cycle(hours=1, max_events=50000, wait_seconds=1, worker_id="worker-1")

    assert result["status"] == "blocked"
    assert result["dc_status"] == "completed"
    assert persisted["source_worker_id"] == "worker-1"
    assert persisted["source_job_id"] == 7
    assert persisted["source_server"] == "nps.example.test"
    assert updates[-1]["status"] == "blocked"

from __future__ import annotations

import subprocess
from datetime import datetime, timedelta, timezone
from typing import Any


def test_postgres_adaptive_plan_never_opens_sqlite(monkeypatch) -> None:
    from server.sli.sources import collector_adaptive
    from server.sli.core import postgres_runtime_pipeline

    monkeypatch.setattr(collector_adaptive, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(
        postgres_runtime_pipeline,
        "get_adaptive_plan_state_pg",
        lambda *args, **kwargs: {
            "backend": "postgres",
            "security_lag_minutes": 180,
            "adaptive_state": {
                "current_limit": 500,
                "consecutive_completed": 0,
                "recovery_mode": False,
            },
            "fairness_channels": ["System"],
        },
    )
    assert not hasattr(collector_adaptive, "sqlite3"), "adaptive planning must not import sqlite3"

    plan = collector_adaptive.get_adaptive_plan_for_server("DC1")

    assert plan.recovery_mode is True
    assert plan.channels[0] == "Security"
    assert "System" in plan.channels
    assert "backend=postgres_runtime" in plan.reason


def test_fixed_scheduler_canary_skips_adaptive_planner(monkeypatch) -> None:
    from server.jobs import collector

    # Unit tests must not write synthetic canary activity into the operational
    # collection log consumed by the Operations screen.
    monkeypatch.setattr(collector, "log_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(collector, "resolve_domain_controller_connect_address", lambda server: "192.0.2.19")
    monkeypatch.setattr(
        collector,
        "get_adaptive_plan_for_server",
        lambda server: (_ for _ in ()).throw(AssertionError("fixed canary must not call adaptive planner")),
    )
    monkeypatch.setattr(
        collector,
        "_scheduler_canary_config",
        lambda: {
            "enabled": True,
            "profile": "archive-watermark-security-1000",
            "channels": ["Security"],
            "max_events_per_channel": 1000,
            "requested_max_events_per_channel": 1000,
            "hours": 1,
            "channel_timeout_seconds": 300,
            "command_timeout_seconds": 600,
            "collection_mode": "current",
            "archive_enabled": True,
            "max_events_cap": 1000,
            "max_events_capped": False,
        },
    )
    monkeypatch.setattr(collector, "_scheduler_skip_report_enabled", lambda: True)
    captured: dict[str, Any] = {}

    def fake_run(command: list[str], timeout_seconds: int, *, server: str, job_id: int | None, env: dict[str, str] | None = None):
        captured["command"] = command
        captured["timeout_seconds"] = timeout_seconds
        return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

    monkeypatch.setattr(collector, "_run_subprocess_live", fake_run)

    result = collector._run_single_server_collection("DC1", 1, 500, job_id=7)

    assert result.returncode == 0
    assert "--max-events-per-channel" in captured["command"]
    assert "1000" in captured["command"]
    assert "--archive" in captured["command"]
    mode_index = captured["command"].index("--adaptive-state-mode")
    assert captured["command"][mode_index + 1] == "observe"


class _FakeCursor:
    def __init__(self) -> None:
        self.executed: list[tuple[str, tuple[Any, ...] | None]] = []
        self._row: dict[str, Any] | None = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, sql: str, params: tuple[Any, ...] | None = None) -> None:
        normalized = " ".join(sql.split()).lower()
        self.executed.append((normalized, params))
        if "from events_v2_core e" in normalized and "order by e.time_created_utc desc" in normalized:
            self._row = {
                "time_created_utc": (datetime.now(timezone.utc) - timedelta(minutes=180)).isoformat(),
                "event_record_id": 100,
            }
        elif "from collector_channel_runs" in normalized and "order by id desc" in normalized:
            self._row = None
        elif "from collector_adaptive_state" in normalized:
            self._row = {
                "server": "DC1",
                "channel": "Security",
                "current_limit": 500,
                "consecutive_completed": 0,
                "recovery_mode": False,
                "last_status": "completed",
                "last_lag_minutes": 10,
                "last_action": None,
                "updated_at": datetime.now(timezone.utc),
            }
        else:
            self._row = None

    def fetchone(self):
        return self._row


class _FakeConnection:
    def __init__(self, cursor: _FakeCursor) -> None:
        self._cursor = cursor

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def cursor(self) -> _FakeCursor:
        return self._cursor


def test_postgres_channel_history_updates_adaptive_state(monkeypatch) -> None:
    from server.sli.sources import collector_adaptive
    from server.sli.core import postgres_runtime_pipeline

    cursor = _FakeCursor()
    monkeypatch.setattr(postgres_runtime_pipeline, "connect", lambda: _FakeConnection(cursor))
    monkeypatch.setattr(postgres_runtime_pipeline, "log_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(collector_adaptive, "log_event", lambda *args, **kwargs: None)

    postgres_runtime_pipeline.record_collector_channel_runs_pg(
        server="DC1",
        summary={
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "collection_mode": "recovery",
            "requested_collection_mode": "auto",
            "collector_backend": "python",
            "channels": [
                {
                    "channel": "Security",
                    "status": "partial_timeout",
                    "count": 100,
                    "max_events": 500,
                    "timeout_seconds": 900,
                    "duration_seconds": 10,
                    "started_at": datetime.now(timezone.utc).isoformat(),
                }
            ],
        },
        import_stats={"Security": {"inserted": 100, "skipped": 0}},
        job_id=10,
        import_duration_ms=50,
    )

    adaptive_upserts = [item for item in cursor.executed if "insert into collector_adaptive_state" in item[0]]
    run_inserts = [item for item in cursor.executed if "insert into collector_channel_runs" in item[0]]

    assert len(adaptive_upserts) == 1
    assert adaptive_upserts[0][1] is not None
    assert adaptive_upserts[0][1][2] == 250
    assert adaptive_upserts[0][1][4] is True
    assert "partial_timeout" in str(adaptive_upserts[0][1][7])
    assert len(run_inserts) == 1
    assert "partial_timeout" in str(run_inserts[0][1][14])
    assert int(run_inserts[0][1][11]) >= 179


def test_baseline_snapshot_routes_postgres_without_sqlite(monkeypatch) -> None:
    from scripts.maintenance import baseline_snapshot

    monkeypatch.setattr(baseline_snapshot, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(
        baseline_snapshot,
        "_postgres_schema_state",
        lambda: {"backend": "postgres", "exists": True, "events_total": 42},
    )

    result = baseline_snapshot._db_schema_state()

    assert result["backend"] == "postgres"
    assert result["events_total"] == 42


def test_baseline_snapshot_reports_non_postgres_backend_explicitly(monkeypatch) -> None:
    from scripts.maintenance import baseline_snapshot

    monkeypatch.setattr(baseline_snapshot, "is_postgres_runtime_db", lambda: False)
    monkeypatch.setattr(baseline_snapshot, "active_backend", lambda: "sqlite")

    result = baseline_snapshot._db_schema_state()

    assert result["exists"] is False
    assert result["probe_error"]["error_type"] == "UnsupportedBackend"
    assert "events_total" not in result


def test_diagnostics_snapshot_routes_postgres_without_sqlite(monkeypatch) -> None:
    from scripts.maintenance import collect_diagnostics

    monkeypatch.setattr(collect_diagnostics, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(
        collect_diagnostics,
        "_postgres_db_snapshot",
        lambda **kwargs: {"backend": "postgres", "exists": True, "events_total": 42},
    )

    result = collect_diagnostics._db_snapshot()

    assert result["backend"] == "postgres"
    assert result["events_total"] == 42


def test_diagnostics_snapshot_reports_non_postgres_backend_explicitly(monkeypatch) -> None:
    from scripts.maintenance import collect_diagnostics

    monkeypatch.setattr(collect_diagnostics, "is_postgres_runtime_db", lambda: False)
    monkeypatch.setattr(collect_diagnostics, "active_backend", lambda: "sqlite")

    result = collect_diagnostics._db_snapshot()

    assert result["exists"] is False
    assert result["db_probe_error"]["error_type"] == "UnsupportedBackend"
    assert "events_total" not in result


def test_maintenance_snapshots_select_v2_after_physical_v1_drop() -> None:
    from scripts.maintenance import baseline_snapshot, collect_diagnostics

    class Cursor:
        def execute(self, _sql, _params=()):
            return None

        def fetchone(self):
            return {"v1_available": False, "v2_available": True}

    assert baseline_snapshot._physical_event_relation(Cursor()) == "events_v2_core"
    assert collect_diagnostics._physical_event_relation(Cursor()) == "events_v2_core"


def test_postgres_canary_observe_mode_records_run_without_state_mutation(monkeypatch) -> None:
    from server.sli.sources import collector_adaptive
    from server.sli.core import postgres_runtime_pipeline

    cursor = _FakeCursor()
    monkeypatch.setattr(postgres_runtime_pipeline, "connect", lambda: _FakeConnection(cursor))
    monkeypatch.setattr(postgres_runtime_pipeline, "log_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(collector_adaptive, "log_event", lambda *args, **kwargs: None)

    postgres_runtime_pipeline.record_collector_channel_runs_pg(
        server="DC1",
        summary={
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "collection_mode": "current",
            "requested_collection_mode": "current",
            "collector_backend": "python",
            "channels": [
                {
                    "channel": "Security",
                    "status": "completed",
                    "count": 1000,
                    "max_events": 1000,
                    "timeout_seconds": 300,
                    "duration_seconds": 10,
                    "started_at": datetime.now(timezone.utc).isoformat(),
                }
            ],
        },
        import_stats={"Security": {"inserted": 1000, "skipped": 0}},
        job_id=11,
        import_duration_ms=50,
        adaptive_state_mode="observe",
    )

    state_reads = [item for item in cursor.executed if "from collector_adaptive_state" in item[0]]
    state_upserts = [item for item in cursor.executed if "insert into collector_adaptive_state" in item[0]]
    run_inserts = [item for item in cursor.executed if "insert into collector_channel_runs" in item[0]]

    assert state_reads == []
    assert state_upserts == []
    assert len(run_inserts) == 1
    assert run_inserts[0][1] is not None
    assert run_inserts[0][1][14] == "observe_only:state_unchanged"

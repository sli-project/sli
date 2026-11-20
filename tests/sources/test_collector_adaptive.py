from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from server.sli.sources.collector_adaptive import (
    compute_non_security_adaptive_transition,
    compute_security_adaptive_transition,
    get_adaptive_plan_for_server,
)


class _FakeCursor:
    """PostgreSQL cursor double: Security is 180 minutes behind, no saved adaptive state."""

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


def _record_runs_pg(monkeypatch, channel_item: dict[str, Any], *, inserted: int, job_id: int) -> _FakeCursor:
    from server.sli.sources import collector_adaptive
    from server.sli.core import postgres_runtime_pipeline

    cursor = _FakeCursor()
    monkeypatch.setattr(postgres_runtime_pipeline, "connect", lambda: _FakeConnection(cursor))
    monkeypatch.setattr(postgres_runtime_pipeline, "log_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(collector_adaptive, "log_event", lambda *args, **kwargs: None)
    postgres_runtime_pipeline.record_collector_channel_runs_pg(
        server="DC1",
        summary={"finished_at": datetime.now(timezone.utc).isoformat(), "channels": [channel_item]},
        import_stats={channel_item["channel"]: {"inserted": inserted, "skipped": 0}},
        job_id=job_id,
    )
    return cursor


def _plan_from_pg_state(monkeypatch, **source: Any):
    from server.sli.sources import collector_adaptive
    from server.sli.core import postgres_runtime_pipeline

    monkeypatch.setattr(collector_adaptive, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(
        postgres_runtime_pipeline,
        "get_adaptive_plan_state_pg",
        lambda *args, **kwargs: {"backend": "postgres", **source},
    )
    return get_adaptive_plan_for_server("DC1")


def test_adaptive_plan_rejects_non_postgres_backend(monkeypatch) -> None:
    import pytest

    from server.sli.sources import collector_adaptive

    monkeypatch.setattr(collector_adaptive, "is_postgres_runtime_db", lambda: False)
    with pytest.raises(RuntimeError, match="PostgreSQL-only"):
        get_adaptive_plan_for_server("DC1")


def test_adaptive_security_limit_does_not_decrease_for_duplicate_events() -> None:
    transition = compute_security_adaptive_transition(
        state={
            "current_limit": 50_000,
            "consecutive_completed": 0,
            "recovery_mode": False,
        },
        status="completed",
        inserted=0,
        skipped=50_000,
        lag_minutes=2,
        previous_limit=50_000,
    )

    assert transition["current_limit"] == 50_000
    assert transition["action"] == "keep"
    assert transition["reason"] in {"completed_streak", "completed_fast_recovery"}


def test_adaptive_security_limit_does_not_decrease_for_functional_failure() -> None:
    transition = compute_security_adaptive_transition(
        state={
            "current_limit": 50_000,
            "consecutive_completed": 0,
            "recovery_mode": False,
        },
        status="failed",
        inserted=0,
        skipped=0,
        lag_minutes=2,
        previous_limit=50_000,
    )

    assert transition["current_limit"] == 50_000
    assert transition["action"] == "keep"
    assert transition["reason"] == "functional_failure"


def test_adaptive_security_limit_still_decreases_after_timeout() -> None:
    transition = compute_security_adaptive_transition(
        state={
            "current_limit": 50_000,
            "consecutive_completed": 0,
            "recovery_mode": False,
        },
        status="timeout",
        inserted=0,
        skipped=0,
        lag_minutes=2,
        previous_limit=50_000,
    )

    assert transition["current_limit"] == 25_000
    assert transition["action"] == "decrease_limit"
    assert transition["reason"] == "timeout"


def test_adaptive_security_limit_does_not_decrease_for_partial_functional_failure(monkeypatch) -> None:
    cursor = _record_runs_pg(
        monkeypatch,
        {
            "channel": "Security",
            "status": "partial_timeout",
            "partial_kind": "failure",
            "failure_stage": "query",
            "cursor_commit_allowed": False,
            "count": 100,
            "max_events": 500,
            "timeout_seconds": 900,
            "started_at": datetime.now(timezone.utc).isoformat(),
        },
        inserted=100,
        job_id=11,
    )

    upserts = [params for sql, params in cursor.executed if "insert into collector_adaptive_state" in sql]
    runs = [params for sql, params in cursor.executed if "insert into collector_channel_runs" in sql]

    assert len(upserts) == 1
    assert upserts[0][2] == 500
    assert "keep:functional_partial_failure" in upserts[0][7]
    assert len(runs) == 1
    assert runs[0][2] == "Security"
    assert runs[0][-3:] == ("failure", "query", False)


def test_recovery_plan_collects_security_only_when_lag_is_high(monkeypatch) -> None:
    plan = _plan_from_pg_state(
        monkeypatch,
        security_lag_minutes=180,
        adaptive_state=None,
        fairness_channels=[],
    )

    assert plan.recovery_mode is True
    assert plan.channels == ["Security"]
    assert plan.channel_limits["Security"] >= 100
    assert plan.channel_timeouts["Security"] >= 600


def test_truncated_non_security_channel_becomes_bounded_recovery_target(monkeypatch) -> None:
    cursor = _record_runs_pg(
        monkeypatch,
        {
            "channel": "System",
            "status": "completed",
            "count": 100,
            "max_events": 100,
            "continuity": {
                "contract": "sli.source-capture-continuity.v1",
                "status": "not_proven",
                "truncated": True,
            },
        },
        inserted=100,
        job_id=12,
    )
    upserts = [params for sql, params in cursor.executed if "insert into collector_adaptive_state" in sql]
    assert len(upserts) == 1
    saved = {
        "channel": "System",
        "current_limit": upserts[0][2],
        "consecutive_completed": upserts[0][3],
        "recovery_mode": upserts[0][4],
    }

    plan = _plan_from_pg_state(
        monkeypatch,
        security_lag_minutes=180,
        adaptive_state=None,
        fairness_channels=[],
        adaptive_states={"System": saved},
    )

    assert "System" in plan.recovery_channels
    assert plan.channel_limits["System"] > 100
    assert plan.channel_limits["System"] <= 50_000


def test_complete_non_security_boundary_exits_recovery() -> None:
    transition = compute_non_security_adaptive_transition(
        state={"current_limit": 5_000, "recovery_mode": True},
        status="completed",
        previous_limit=5_000,
        truncated=False,
    )

    assert transition["recovery_mode"] is False
    assert transition["current_limit"] == 500

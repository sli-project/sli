from __future__ import annotations

import json
from contextlib import contextmanager

import pytest


@pytest.mark.parametrize(
    ("options", "limit", "poll_seconds"),
    [([], 16, 30), (["--limit", "100", "--poll-seconds", "1000"], 16, 300),
     (["--limit", "0", "--poll-seconds", "0"], 1, 1)],
)
def test_runtime_worker_cli_passes_bounded_options(monkeypatch, options, limit, poll_seconds):
    from scripts.runtime import entity_state_worker

    calls = []
    monkeypatch.setattr(entity_state_worker, "run", lambda **kwargs: calls.append(kwargs) or 0)

    assert entity_state_worker.main(["--once", *options]) == 0
    assert calls == [{"once": True, "limit": limit, "poll_seconds": poll_seconds}]


def test_runtime_worker_once_processes_one_bounded_iteration(monkeypatch, capsys) -> None:
    from scripts.runtime import entity_state_worker

    @contextmanager
    def acquired_lock():
        yield True

    calls: list[int] = []
    monkeypatch.setattr(entity_state_worker, "entity_state_worker_lock", acquired_lock)
    monkeypatch.setattr(entity_state_worker, "run_once", lambda *, limit: calls.append(limit) or {
        "status": "ok", "claimed": 4, "completed": 4, "failed": 0,
    })
    monkeypatch.setattr(entity_state_worker, "log_event", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(entity_state_worker, "record_worker_heartbeat", lambda **_kwargs: {"status": "ok"})

    assert entity_state_worker.run(once=True, poll_seconds=30, limit=16) == 0
    assert calls == [16]
    assert json.loads(capsys.readouterr().out)["completed"] == 4


def test_runtime_worker_exits_cleanly_when_singleton_lock_is_held(monkeypatch, capsys) -> None:
    from scripts.runtime import entity_state_worker

    @contextmanager
    def rejected_lock(connect, name):
        assert connect is entity_state_worker._connect
        assert name == "ad_log_reports_runtime_entity_state_worker"
        yield False

    monkeypatch.setattr(entity_state_worker, "session_advisory_lock", rejected_lock)
    monkeypatch.setattr(entity_state_worker, "run_once", lambda **kwargs: pytest.fail("worker did not own the lock"))
    monkeypatch.setattr(entity_state_worker, "log_event", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(entity_state_worker, "record_worker_heartbeat", lambda **_kwargs: {"status": "ok"})

    assert entity_state_worker.run(once=False, poll_seconds=30, limit=16) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["status"] == "skipped"
    assert status["reason"] == "entity_state_worker_lock_held"

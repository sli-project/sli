from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path


def test_runtime_worker_entrypoint_has_project_bootstrap_and_bounded_cli() -> None:
    source = Path("scripts/runtime/entity_state_worker.py").read_text(encoding="utf-8")

    assert "Path(__file__).resolve().parents[2]" in source
    assert 'LOCK_NAME = "ad_log_reports_runtime_entity_state_worker"' in source
    assert "session_advisory_lock" in source
    assert 'parser.add_argument("--limit", type=int, default=16' in source
    assert 'parser.add_argument("--poll-seconds", type=int, default=30' in source


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
    assert '"completed": 4' in capsys.readouterr().out


def test_runtime_worker_exits_cleanly_when_singleton_lock_is_held(monkeypatch, capsys) -> None:
    from scripts.runtime import entity_state_worker

    @contextmanager
    def rejected_lock():
        yield False

    monkeypatch.setattr(entity_state_worker, "entity_state_worker_lock", rejected_lock)
    monkeypatch.setattr(entity_state_worker, "log_event", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(entity_state_worker, "record_worker_heartbeat", lambda **_kwargs: {"status": "ok"})

    assert entity_state_worker.run(once=False, poll_seconds=30, limit=16) == 0
    assert "entity_state_worker_lock_held" in capsys.readouterr().out

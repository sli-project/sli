from __future__ import annotations

from pathlib import Path

import pytest

from server.sli.sources import postgres_import_queue as module


def test_queue_acquires_and_reports_wait(monkeypatch, tmp_path):
    lock_path = tmp_path / "pg-import.lock"
    monkeypatch.setenv("ADLOG_POSTGRES_IMPORT_QUEUE_LOCK", str(lock_path))
    with module.postgres_import_queue(server="DC1", timeout_seconds=1) as info:
        assert info.lock_path == lock_path
        assert info.wait_ms >= 0
        assert lock_path.exists()

    # Windows msvcrt locking can deny concurrent reads while the byte-range
    # lock is held. Validate queue metadata after the context releases and
    # closes the lock handle; this also verifies clean lock release.
    assert "server=DC1" in lock_path.read_text(encoding="utf-8")


def test_queue_timeout_is_bounded(monkeypatch, tmp_path):
    lock_path = tmp_path / "pg-import.lock"
    monkeypatch.setenv("ADLOG_POSTGRES_IMPORT_QUEUE_LOCK", str(lock_path))
    monkeypatch.setattr(module, "postgres_import_queue_poll_seconds", lambda: 0.01)
    monkeypatch.setattr(module, "_try_lock", lambda _handle: (_ for _ in ()).throw(BlockingIOError("busy")))
    with pytest.raises(module.PostgresImportQueueTimeout) as error:
        with module.postgres_import_queue(server="DC2", timeout_seconds=0):
            pass
    assert error.value.lock_path == lock_path
    assert error.value.wait_ms >= 0

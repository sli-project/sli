from __future__ import annotations

import contextlib
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from server.sli.ops.logging_config import log_event
from server.sli.core.paths import DATA_DIR
from server.sli.ops.performance import monotonic_ms


@dataclass(frozen=True)
class PostgresImportQueueInfo:
    lock_path: Path
    wait_ms: int
    timeout_seconds: int


class PostgresImportQueueTimeout(TimeoutError):
    def __init__(self, message: str, *, wait_ms: int, lock_path: Path) -> None:
        super().__init__(message)
        self.wait_ms = int(wait_ms)
        self.lock_path = Path(lock_path)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default


def postgres_import_queue_timeout_seconds() -> int:
    return max(1, _env_int("ADLOG_POSTGRES_IMPORT_QUEUE_TIMEOUT_SECONDS", 900))


def postgres_import_queue_poll_seconds() -> float:
    raw = os.environ.get("ADLOG_POSTGRES_IMPORT_QUEUE_POLL_SECONDS", "0.2")
    try:
        value = float(raw)
    except (TypeError, ValueError):
        value = 0.2
    return max(0.05, min(value, 5.0))


def postgres_import_queue_path() -> Path:
    configured = os.environ.get("ADLOG_POSTGRES_IMPORT_QUEUE_LOCK")
    path = Path(configured) if configured else DATA_DIR / "maintenance" / "postgres-import.queue.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


@contextlib.contextmanager
def postgres_import_queue(
    *,
    trace_id: str | None = None,
    job_id: int | None = None,
    server: str | None = None,
    timeout_seconds: int | None = None,
) -> Iterator[PostgresImportQueueInfo]:
    """Serialize PostgreSQL event importers across collector processes.

    DC reads may run in parallel. The expensive entity/link write phase is kept
    to one importer at a time so PostgreSQL receives bounded load and the wait
    becomes an explicit backpressure metric instead of hidden contention.
    """

    timeout = timeout_seconds if timeout_seconds is not None else postgres_import_queue_timeout_seconds()
    lock_path = postgres_import_queue_path()
    started_ms = monotonic_ms()
    acquired = False
    handle = lock_path.open("a+", encoding="utf-8")
    try:
        while True:
            try:
                _try_lock(handle)
                acquired = True
                break
            except BlockingIOError:
                wait_ms = monotonic_ms() - started_ms
                if wait_ms >= timeout * 1000:
                    log_event(
                        "postgres_import_queue",
                        "queue_timeout",
                        "PostgreSQL import queue wait timed out.",
                        level=logging.ERROR,
                        trace_id=trace_id,
                        job_id=job_id,
                        server=server,
                        lock_path=str(lock_path),
                        wait_ms=wait_ms,
                        timeout_seconds=timeout,
                    )
                    raise PostgresImportQueueTimeout(
                        f"PostgreSQL import queue timeout after {timeout}s: {lock_path}",
                        wait_ms=wait_ms,
                        lock_path=lock_path,
                    )
                time.sleep(postgres_import_queue_poll_seconds())

        wait_ms = monotonic_ms() - started_ms
        handle.seek(0)
        handle.truncate()
        handle.write(f"pid={os.getpid()} job_id={job_id} server={server} trace_id={trace_id}\n")
        handle.flush()
        log_event(
            "postgres_import_queue",
            "queue_acquired",
            "PostgreSQL import queue acquired.",
            trace_id=trace_id,
            job_id=job_id,
            server=server,
            lock_path=str(lock_path),
            wait_ms=wait_ms,
        )
        yield PostgresImportQueueInfo(lock_path=lock_path, wait_ms=wait_ms, timeout_seconds=timeout)
    finally:
        if acquired:
            try:
                _unlock(handle)
            finally:
                log_event(
                    "postgres_import_queue",
                    "queue_released",
                    "PostgreSQL import queue released.",
                    trace_id=trace_id,
                    job_id=job_id,
                    server=server,
                    lock_path=str(lock_path),
                )
        handle.close()


def _try_lock(handle) -> None:
    if os.name == "nt":  # pragma: no cover - production Windows branch
        import msvcrt

        try:
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError as exc:
            raise BlockingIOError(str(exc)) from exc
        return

    import fcntl  # pragma: no cover - platform branch covered indirectly

    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        raise BlockingIOError(str(exc)) from exc


def _unlock(handle) -> None:
    if os.name == "nt":  # pragma: no cover - production Windows branch
        import msvcrt

        handle.seek(0)
        try:
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
        return

    import fcntl  # pragma: no cover - platform branch covered indirectly

    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    except OSError:
        pass

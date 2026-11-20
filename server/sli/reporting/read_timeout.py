"""One configurable PostgreSQL read budget for an HTTP report request."""
from __future__ import annotations

import os
from contextlib import contextmanager
from contextvars import ContextVar
from threading import Timer
from time import monotonic

_deadline: ContextVar[float | None] = ContextVar("report_read_deadline", default=None)
_watchdogs: ContextVar[list | None] = ContextVar("report_read_watchdogs", default=None)
DEFAULT_READ_TIMEOUT_MS = 8_000


def read_timeout_ms() -> int:
    try:
        value = int(os.getenv("ADLOG_REPORT_READ_TIMEOUT_MS", str(DEFAULT_READ_TIMEOUT_MS)))
    except ValueError:
        return DEFAULT_READ_TIMEOUT_MS
    return value if value >= 100 else DEFAULT_READ_TIMEOUT_MS


def remaining_read_ms() -> int | None:
    deadline = _deadline.get()
    if deadline is None:
        return None
    remaining = int((deadline - monotonic()) * 1000)
    if remaining <= 0:
        from server.sli.core.database import QueryTimeoutError

        raise QueryTimeoutError("Report read budget exhausted", timeout_ms=read_timeout_ms())
    return max(1, remaining)


def watch_read_connection(connection) -> None:
    """Also bound readers using a driver cursor directly instead of query_rows."""
    watchdogs = _watchdogs.get()
    if watchdogs is None:
        return
    remaining = remaining_read_ms()

    def cancel():
        try:
            connection.cancel()
        except Exception:  # noqa: BLE001 - cancellation is best effort on a closed driver connection
            return  # The reader still owns and closes the connection.

    timer = Timer(remaining / 1000, cancel)
    timer.daemon = True
    watchdogs.append(timer)
    timer.start()


@contextmanager
def report_read_budget(*, timeout_ms: int | None = None):
    """Share read deadlines; an explicit cap can only shorten the budget.

    Calls without a cap retain the existing nested-context behavior. A capped
    nested scope restores the original absolute deadline on exit, not a fresh
    interval, and owns/cleans up only its newly registered watchdogs.
    """
    if timeout_ms is not None and (type(timeout_ms) is not int or timeout_ms <= 0):
        raise ValueError("invalid_read_timeout_cap")
    outer = _deadline.get()
    if outer is not None and timeout_ms is None:
        yield
        return
    duration = read_timeout_ms()
    if timeout_ms is not None:
        duration = min(duration, timeout_ms)
    deadline = monotonic() + duration / 1000
    token = _deadline.set(min(outer, deadline) if outer is not None else deadline)
    watchdog_token = _watchdogs.set([])
    try:
        yield
    finally:
        for timer in _watchdogs.get():
            timer.cancel()
        _watchdogs.reset(watchdog_token)
        _deadline.reset(token)

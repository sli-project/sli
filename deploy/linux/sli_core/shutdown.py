"""Cooperative Linux service shutdown at durable worker batch boundaries."""
from __future__ import annotations

from contextlib import contextmanager
import signal
from threading import Event

_STOP = Event()
_installed = False


def requested() -> bool:
    return _STOP.is_set()


def wait(seconds, *, sleep):
    if _installed:
        _STOP.wait(seconds)
    else:
        sleep(seconds)


@contextmanager
def graceful_shutdown():
    global _installed
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
    _STOP.clear()
    _installed = True
    for sig in previous:
        signal.signal(sig, lambda *_: _STOP.set())
    try:
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        _installed = False
        _STOP.clear()

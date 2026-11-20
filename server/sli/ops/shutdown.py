"""Cooperative Linux service shutdown at durable worker batch boundaries."""
from __future__ import annotations

from contextlib import contextmanager
import os
import signal
from threading import Event, Thread, current_thread, main_thread

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


@contextmanager
def http_shutdown(server):
    """Close HTTP admission on SIGTERM and join accepted request threads."""
    if os.name == "nt" or current_thread() is not main_thread():
        yield
        return
    previous = signal.getsignal(signal.SIGTERM)
    server.daemon_threads = False
    server.sli_stopping = False

    def stop(*_):
        server.sli_stopping = True

        def drain():
            begin = getattr(server, "begin_shutdown", None)
            if begin is not None:
                begin()
            server.shutdown()

        Thread(target=drain, daemon=True).start()

    # BaseServer.shutdown cannot run in the serve_forever thread itself.
    signal.signal(signal.SIGTERM, stop)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)

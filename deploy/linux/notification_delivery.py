"""Persistent bounded notification queue worker with a local, value-free health heartbeat."""
import json
import os
from pathlib import Path
import signal
import threading
import time

from server.sli.core.notification_outbox import process_one

STATUS = Path("/tmp/notification-delivery.json")


def healthy(*, process_pid=1, started_at=None, status_path=None):
    try:
        row = json.loads((status_path or STATUS).read_text())
        age = time.time() - row["at"]
        return (row["pid"] == process_pid and 0 <= age <= 90
                and (started_at is None or row["at"] >= started_at.timestamp()))
    except (OSError, ValueError, KeyError, TypeError):
        return False


def main():
    status = Path(os.environ.get("SLI_NOTIFICATION_STATUS_FILE", str(STATUS)))
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    while not stop.is_set():
        try:
            worked = process_one(telegram=True, smtp=True, notification_only=True, include_reports=True)
            temporary = status.with_suffix(".tmp")
            temporary.write_text(json.dumps({"pid": os.getpid(), "at": time.time()}))
            temporary.replace(status)
        except Exception:
            # A failed DB cycle must eventually fail health; never print values.
            worked = False
        if not worked:
            stop.wait(3)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


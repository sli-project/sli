"""Local health probes for the notification socket and delivery heartbeat."""
import json
from pathlib import Path
import socket
import sys
import time

DELIVERY_STATUS = Path("/tmp/notification-delivery.json")


def delivery_healthy(*, process_pid=1, started_at=None, status_path=None):
    try:
        row = json.loads((status_path or DELIVERY_STATUS).read_text())
        age = time.time() - row["at"]
        return (row["pid"] == process_pid and 0 <= age <= 90
                and (started_at is None or row["at"] >= started_at.timestamp()))
    except (OSError, ValueError, KeyError, TypeError):
        return False


def healthy(kind, *, status_path=None):
    if kind == "delivery":
        return delivery_healthy()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(2)
            client.connect(str(status_path or "/run/notification-setup/control.sock"))
        return True
    except OSError:
        return False


if __name__ == "__main__":
    raise SystemExit(0 if healthy(sys.argv[1]) else 1)

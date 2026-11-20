"""Local health probes; no network, secret reads or database mutations."""
import socket
import sys


def healthy(kind, *, status_path=None):
    if kind == "delivery":
        from deploy.linux.notification_delivery import healthy as delivery_healthy
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

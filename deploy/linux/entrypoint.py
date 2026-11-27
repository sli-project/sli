"""Run the shared API/worker code without the Windows service supervisor."""

from __future__ import annotations

import argparse
import importlib
import signal
import subprocess
import sys
import time

# Accepted requests and executor joins can outlive a 20-second CLI stop poll.
# The updater waits for PID 1 separately and still rejects forced exits.
API_SHUTDOWN_SECONDS = 300


def run_api(arguments: list[str]) -> int:
    """Bound the whole API process, including request and executor thread joins."""
    deadline = None

    def stop(*_):
        nonlocal deadline
        if deadline is None:
            deadline = time.monotonic() + API_SHUTDOWN_SECONDS

    previous = {sig: signal.signal(sig, stop) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        with subprocess.Popen([sys.executable, "-m", "scripts.run_server", *arguments]) as child:
            signalled = False
            while True:
                if deadline is not None and not signalled:
                    child.terminate()
                    signalled = True
                try:
                    code = child.wait(timeout=0.1)
                    return code if code >= 0 else 1
                except subprocess.TimeoutExpired:
                    if deadline is not None and time.monotonic() >= deadline:
                        # PostgreSQL rolls back uncommitted connections; no ACK
                        # is invented for an interrupted agent request.
                        print("api_shutdown_timeout", file=sys.stderr, flush=True)
                        child.kill()
                        child.wait()
                        return 1
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)

WORKERS = {
    "post-collection": "scripts.runtime.post_collection_worker",
    "what-where-when": "scripts.runtime.what_where_when_projection_worker",
    "semantic": "scripts.runtime.semantic_production_worker",
    "entity-state": "scripts.runtime.entity_state_worker",
    "storage-lifecycle": "scripts.runtime.storage_lifecycle_worker",
    "ad-snapshot-manifest-coordinator": "scripts.runtime.ad_snapshot_manifest_coordinator_worker",
    "remote-access": "scripts.runtime.remote_access_plugin_host",
}
NOTIFICATION_WORKERS = {"notification-delivery": "deploy.linux.notification_delivery",
                        "notification-setup": "deploy.linux.telegram_setup"}



def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("service", choices=("api", "migrate", "restore", "executor", *WORKERS, *NOTIFICATION_WORKERS))
    args, remaining = parser.parse_known_args()
    if args.service in {"migrate", "restore"}:
        from deploy.linux.migrate import migrate

        try:
            if args.service == "restore":
                from deploy.linux.restore_existing import main as restore

                return restore(remaining)
            migrate()
        except Exception as error:  # noqa: BLE001 - never disclose SQL/connection errors at the CLI boundary
            # SQL errors may include source rows, connection strings or secrets.
            from deploy.linux.operation_wait import OperationTimeout
            print(error.code if isinstance(error, OperationTimeout) else "linux_migration_failed", file=sys.stderr)
            return 1
        return 0
    from deploy.linux.legacy_runtime import run_service

    return run_service(args.service, remaining, WORKERS, NOTIFICATION_WORKERS, run_api, importlib.import_module)


if __name__ == "__main__":
    raise SystemExit(main())

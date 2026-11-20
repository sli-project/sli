"""Bounded readiness checks with fixed diagnostics and no secret output."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import ssl
from datetime import datetime, timezone
from urllib.request import urlopen

from server.sli.core.app_config import load_config
from server.sli.sources.plugin_runtime_heartbeat import read_plugin_heartbeat
from server.sli.storage.lifecycle_health import safe_warning_reason

WORKER_MAX_AGES = {
    "post_collection": 120,
    "what_where_when_projection": 120,
    "semantic": 120,
    "entity_state": 120,
    "storage_lifecycle": 43230,
    "ad_snapshot_manifest_coordinator": 630,
}


def healthy(service: str, *, process_pid: int = 1, started_at: datetime | None = None,
            status_path: Path | None = None) -> bool:
    """Docker defaults stay unchanged; native callers supply the current identity."""
    try:
        if service == "notification-delivery":
            from deploy.linux.notification_delivery import healthy as delivery_healthy
            return delivery_healthy(process_pid=process_pid, started_at=started_at, status_path=status_path)
        if service == "notification-setup":
            from deploy.linux.notification_health import healthy as setup_healthy
            return setup_healthy("setup", status_path=status_path)
        if service.startswith("executor-"):
            import json
            profile = service.removeprefix("executor-")
            row = json.loads((status_path or Path(f"/tmp/sli-executor-{profile}.json")).read_text("utf-8"))
            stamp = datetime.fromisoformat(row["at_utc"])
            age = (datetime.now(timezone.utc) - stamp).total_seconds()
            return (row["profile"] == profile and row["pid"] == process_pid and 0 <= age <= 120
                    and (started_at is None or stamp >= started_at))
        if service == "api":
            context = ssl.create_default_context(cafile=os.environ["SLI_TLS_CA_FILE"])
            with urlopen(os.environ["SLI_HEALTH_URL"], context=context, timeout=5) as response:
                return response.status == 200
        if service == "radius-session-observation":
            from server.sli.core.job_executor import pilot_enabled

            if started_at is None and pilot_enabled():
                return True  # Legacy service exits without claiming when the pilot is selected.
            if status_path is None:
                row = read_plugin_heartbeat(service)
            else:
                import json

                row = json.loads(status_path.read_text("utf-8"))
            if not row or row.get("component_id") != service or row.get("plugin_id") != "sli.remote-access":
                return False
            stamp = datetime.fromisoformat(row["heartbeat_at_utc"])
            if stamp.tzinfo is None:
                return False
            age = (datetime.now(timezone.utc) - stamp).total_seconds()
            return (row.get("process_pid") == process_pid and row.get("status") in {"running", "idle"}
                    and 0 <= age <= 120 and (started_at is None or stamp >= started_at))
        max_age = WORKER_MAX_AGES[service]
        import psycopg

        with psycopg.connect(load_config().postgres_dsn, connect_timeout=3,
                             options="-c statement_timeout=3000") as connection:
            if service == "storage_lifecycle":
                row = connection.execute(
                    """SELECT status, details_json->>'last_cycle_reason'
                        FROM public.runtime_worker_heartbeats
                        WHERE worker_name = %s
                          AND heartbeat_at > now() - make_interval(secs =>
                              LEAST(%s, GREATEST(120, expected_interval_seconds * 2 + 30)))
                          AND heartbeat_at <= now() AND process_pid = %s
                          AND (%s::timestamptz IS NULL OR heartbeat_at >= %s)
                    """, (service, max_age, process_pid, started_at, started_at),
                ).fetchone()
                if not row or row[0] not in {"running", "idle", "warning"}:
                    return False
                if row[0] == "warning":
                    print(f"warning: storage_lifecycle: {safe_warning_reason(row[1])}")
                return True
            row = connection.execute(
                """SELECT EXISTS (
                    SELECT 1 FROM public.runtime_worker_heartbeats
                    WHERE worker_name = %s AND status IN ('running', 'idle', 'warning')
                      AND heartbeat_at > now() - make_interval(secs =>
                          LEAST(%s, GREATEST(120, expected_interval_seconds * 2 + 30)))
                      AND heartbeat_at <= now()
                      AND process_pid = %s
                      AND (%s::timestamptz IS NULL OR heartbeat_at >= %s)
                )""", (service, max_age, process_pid, started_at, started_at),
            ).fetchone()
            return bool(row and row[0])
    except Exception:  # noqa: BLE001 - health probes expose only success/failure
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("service", choices=("api", *WORKER_MAX_AGES, "radius-session-observation",
                                           "executor-light", "executor-heavy", "executor-long"))
    return 0 if healthy(parser.parse_args().service) else 1


if __name__ == "__main__":
    raise SystemExit(main())

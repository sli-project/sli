"""Bounded readiness checks with fixed diagnostics and no secret output."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import ssl
from datetime import datetime, timezone
from urllib.request import urlopen

WORKER_MAX_AGES = {
    "post_collection": 120,
    "what_where_when_projection": 120,
    "semantic": 120,
    "entity_state": 120,
    "storage_lifecycle": 43230,
    "ad_snapshot_manifest_coordinator": 630,
}


WARNING_REASONS = frozenset({
    "snapshot_history_migration_required",
    "source_rows_held_for_processing_or_evidence",
    "owner_storage_policy_changed",
    "history_source_link_details_missing",
    "history_source_archive_unavailable",
    "history_clickhouse_unavailable",
    "published_history_event_batch_incomplete",
    "retention_candidate_history_incomplete",
    "retention_candidate_history_not_published",
    "file_audit_history_unavailable",
    "file_audit_payload_held_or_unresolved",
    "file_audit_semantic_pending",
    "file_audit_evidence_held",
    "purge_lock_unavailable",
    "purge_statement_timeout",
    "ad_snapshot_history_coverage_partial",
    "ad_snapshot_history_backlog_remaining",
    "history_publication_backlog_remaining",
    "fact_history_copy_lock_held",
    "file_audit_retention_backlog_remaining",
    "warm_backlog_remaining",
})


def native_postgres_dsn():
    from psycopg.conninfo import make_conninfo

    from deploy.linux.native_credentials import secret_value

    dsn = secret_value("ADLOG_PG_DSN")
    if not dsn:
        raise ValueError("native_health_dsn_required")
    password = secret_value("ADLOG_PG_PASSWORD")
    return make_conninfo(dsn, password=password) if password is not None else dsn


def native_healthy(service: str, *, process_pid: int, started_at: datetime, status_path: Path | None = None) -> bool:
    return _healthy(service, process_pid=process_pid, started_at=started_at, status_path=status_path,
                    postgres_dsn=native_postgres_dsn)


def load_config():
    from deploy.linux.legacy_runtime import load_config as legacy_config

    return legacy_config()


def read_plugin_heartbeat(service):
    from deploy.linux.legacy_runtime import read_plugin_heartbeat as legacy_heartbeat

    return legacy_heartbeat(service)


def healthy(service: str, *, process_pid: int = 1, started_at: datetime | None = None,
            status_path: Path | None = None) -> bool:
    """Compose health checks retain their existing configuration and pilot defaults."""
    try:
        if service == "radius-session-observation" and started_at is None:
            from deploy.linux.legacy_runtime import pilot_enabled

            if pilot_enabled():
                return True  # The legacy service exits without claiming.
        if service == "radius-session-observation" and status_path is None:
            return radius_healthy(read_plugin_heartbeat(service), service, process_pid, started_at)
    except Exception:  # noqa: BLE001 - health probes expose only success/failure
        return False
    return _healthy(service, process_pid=process_pid, started_at=started_at, status_path=status_path,
                    postgres_dsn=lambda: load_config().postgres_dsn)


def radius_healthy(row, service, process_pid, started_at):
    if not row or row.get("component_id") != service or row.get("plugin_id") != "sli.remote-access":
        return False
    stamp = datetime.fromisoformat(row["heartbeat_at_utc"])
    if stamp.tzinfo is None:
        return False
    age = (datetime.now(timezone.utc) - stamp).total_seconds()
    return (row.get("process_pid") == process_pid and row.get("status") in {"running", "idle"}
            and 0 <= age <= 120 and (started_at is None or stamp >= started_at))


def _healthy(service, *, process_pid, started_at, status_path, postgres_dsn):
    try:
        if service == "notification-delivery":
            from deploy.linux.notification_health import delivery_healthy

            return delivery_healthy(process_pid=process_pid, started_at=started_at, status_path=status_path)
        if service == "notification-setup":
            from deploy.linux.notification_health import healthy as setup_healthy

            return setup_healthy("setup", status_path=status_path)
        if service.startswith("executor-"):
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
            return status_path is not None and radius_healthy(
                json.loads(status_path.read_text("utf-8")), service, process_pid, started_at)
        max_age = WORKER_MAX_AGES[service]
        import psycopg

        with psycopg.connect(postgres_dsn(), connect_timeout=3,
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
                    reason = row[1] if isinstance(row[1], str) and row[1] in WARNING_REASONS else (
                        "storage_lifecycle_condition_pending")
                    print(f"warning: storage_lifecycle: {reason}")
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

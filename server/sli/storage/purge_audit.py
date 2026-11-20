"""Bounded, source-free receipts for destructive storage work.

A running receipt survives a crash. PostgreSQL row deletion does not prove
physical disk reclamation; logical row bytes are reported separately.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from time import monotonic
from uuid import uuid4

from server.sli.core.paths import DATA_DIR
from server.sli.storage.lifecycle_health import EXPECTED_BLOCK_REASONS

AUDIT_DIR = DATA_DIR / "runtime" / "purge-runs"
MAX_RUNS = 50
SAFE_REASONS = EXPECTED_BLOCK_REASONS | frozenset({
    "history_clickhouse_credentials_missing", "history_clickhouse_port_missing",
    "history_clickhouse_port_invalid", "history_read_mode_invalid", "history_primary_read_required",
    "history_source_link_role_mismatch", "history_source_link_detail_duplicate",
    "history_source_link_duplicate", "history_source_archive_permission_denied",
    "clickhouse_batch_manifest_duplicate", "clickhouse_batch_manifest_mismatch",
    "clickhouse_batch_publication_incomplete",
    "postgres_dsn_not_configured", "protected_postgres_admin_credentials_required",
    "protected_read_only_admin_credentials_required",
    "unknown_event_dependency", "direct_no_archive_descriptors_missing",
    "snapshot_history_migration_required",
    "snapshot_history_source_family_missing", "snapshot_history_source_hash_mismatch",
    "snapshot_history_manifest_missing", "snapshot_history_clickhouse_readback_mismatch",
    "snapshot_history_clickhouse_identity_readback_mismatch", "snapshot_history_retention_readback_failed",
    "history_publication_not_verified", "history_publication_frontier_did_not_advance",
    "history_retention_source_changed", "history_retention_semantic_state_changed",
    "history_retention_delete_mismatch", "history_retention_evidence_changed",
    "retention_candidate_source_hash_changed", "retention_candidate_history_incomplete",
    "retention_candidate_history_not_published", "retention_candidate_source_count_mismatch",
    "clickhouse_fact_history_readback_mismatch", "clickhouse_fact_history_readback_incomplete",
    "clickhouse_event_duplicate_or_mismatch", "clickhouse_link_duplicate_or_mismatch",
    "history_retention_delete_readback_mismatch",
    "workstation_observation_hash_mismatch", "workstation_source_hash_mismatch",
    "workstation_history_receipt_mismatch", "workstation_delete_count_mismatch",
    "workstation_history_unavailable",
    "workstation_history_durability_unverified",
    "workstation_retention_plan_changed",
    "workstation_delete_readback_mismatch", "exact_source_event_missing",
    "link_detail_set_mismatch", "history_retention_progress_invalid",
    "file_audit_retention_source_changed", "file_audit_retention_delete_mismatch",
    "file_audit_retention_readback_mismatch",
})


def failure_reason(error: Exception) -> str:
    # Never publish an exception containing SQL, payloads or connection details.
    database_reasons = {
        "57014": "purge_statement_timeout", "55P03": "purge_lock_unavailable",
        "42501": "purge_permission_denied", "23503": "purge_dependency_changed",
        "42P01": "purge_schema_missing", "42703": "purge_schema_incompatible",
        "28P01": "postgres_authentication_failed",
    }
    sqlstate = getattr(error, "sqlstate", None)
    if sqlstate in database_reasons:
        return database_reasons[sqlstate]
    reason = str(error)
    return reason if reason in SAFE_REASONS else "purge_verification_or_io_failed"


def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(payload, stream)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


class PurgeRun:
    def __init__(self, lane: str):
        tables = {
            "event_history": ("events_v2_core", "event_facts_v2"),
            "file_audit": ("sli_agent_packet_inbox", "sli_plugin_file_audit.access_snapshots"),
        }.get(lane, ("sli_plugin_workstations.observations",))
        self.started = monotonic()
        self.payload = {
            "contract": "sli.purge-run.v1", "lane": lane,
            "started_at_utc": datetime.now(timezone.utc).isoformat(),
            "status": "running", "tables": {
                name: {"selected_count": 0, "deleted_count": 0,
                       "logical_bytes_deleted": 0, "partitions": []} for name in tables
            }, "duration_ms": 0,
            "bytes_reclaimed": 0, "logical_bytes_deleted": 0,
            "physical_reclaim_performed": False,
        }
        self.path = AUDIT_DIR / f"{datetime.now(timezone.utc):%Y%m%dT%H%M%S%fZ}-{uuid4().hex}.json"
        # Failure to write the initial receipt prevents destructive work.
        _write(self.path, self.payload)

    def checkpoint(self, result: dict) -> None:
        self.payload.update(result)
        _write(self.path, self.payload)

    def finish(self, result: dict) -> None:
        self.payload.update(
            finished_at_utc=datetime.now(timezone.utc).isoformat(),
            duration_ms=round((monotonic() - self.started) * 1000, 3),
        )
        self.checkpoint(result)
        for path in sorted(AUDIT_DIR.glob("*.json"), reverse=True)[MAX_RUNS:]:
            path.unlink(missing_ok=True)


def last_purge_runs() -> dict:
    try:
        rows = [json.loads(path.read_text(encoding="utf-8"))
                for path in sorted(AUDIT_DIR.glob("*.json"), reverse=True)[:MAX_RUNS]]
        if any(row.get("contract") != "sli.purge-run.v1" for row in rows):
            raise ValueError("invalid receipt")
        return {"status": "ok", "runs": rows, "limit": MAX_RUNS}
    except (OSError, ValueError, TypeError, AttributeError):
        return {"status": "unavailable", "reason": "purge_receipts_unreadable", "runs": []}

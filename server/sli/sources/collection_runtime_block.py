"""Durable fail-closed circuit breaker for non-retryable collection failures."""
from __future__ import annotations

import json
from typing import Any


REASON_WINDOWS_SECURITY_CONTEXT = "windows_security_context_invalid"
REASON_WINDOWS_EVENT_LOG_ACCESS_DENIED = "windows_event_log_access_denied"
RETRY_OPERATOR_RECOVERY = "operator_recovery_required"


def _ensure_schema() -> None:
    from server.sli.ops.postgres_schema_guard import require_table_columns

    require_table_columns(
        "runtime_collection_blocks",
        (
            "singleton_id", "active", "reason_code", "retry_policy", "operator_action",
            "source_worker_id", "source_job_id", "source_server", "evidence_json",
            "observed_count", "first_seen_at", "last_seen_at", "last_probe_at",
            "last_probe_result", "cleared_at", "cleared_by", "updated_at",
        ),
        minimum_schema_version=38,
    )


def get_active_collection_block() -> dict[str, Any] | None:
    _ensure_schema()
    from server.sli.core.postgres_runtime_pipeline import connect

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("select * from runtime_collection_blocks where singleton_id=1 and active=true")
            row = cur.fetchone()
            return dict(row) if row else None


def activate_collection_block(
    *,
    reason_code: str,
    operator_action: str,
    source_worker_id: str | None = None,
    source_job_id: int | None = None,
    source_server: str | None = None,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    _ensure_schema()
    from server.sli.core.postgres_runtime_pipeline import connect

    safe_evidence = {
        str(key): value for key, value in (evidence or {}).items()
        if str(key) in {"failure_code", "failure_scope", "collector_backend", "marker"}
    }
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                insert into runtime_collection_blocks(
                    singleton_id,active,reason_code,retry_policy,operator_action,
                    source_worker_id,source_job_id,source_server,evidence_json
                ) values (1,true,%s,%s,%s,%s,%s,%s,%s::jsonb)
                on conflict(singleton_id) do update set
                    active=true,reason_code=excluded.reason_code,retry_policy=excluded.retry_policy,
                    operator_action=excluded.operator_action,source_worker_id=excluded.source_worker_id,
                    source_job_id=excluded.source_job_id,source_server=excluded.source_server,
                    evidence_json=excluded.evidence_json,
                    observed_count=runtime_collection_blocks.observed_count+1,
                    last_seen_at=now(),cleared_at=null,cleared_by=null,updated_at=now()
                returning *
                """,
                (
                    reason_code, RETRY_OPERATOR_RECOVERY, operator_action, source_worker_id,
                    source_job_id, source_server, json.dumps(safe_evidence, ensure_ascii=False),
                ),
            )
            return dict(cur.fetchone() or {})


def record_probe_and_clear(*, probe_server: str, cleared_by: str) -> dict[str, Any]:
    """Clear only after the caller has completed one successful explicit probe."""
    _ensure_schema()
    from server.sli.core.postgres_runtime_pipeline import connect

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                update runtime_collection_blocks
                set active=false,last_probe_at=now(),last_probe_result='success',
                    cleared_at=now(),cleared_by=%s,updated_at=now(),
                    evidence_json=evidence_json || jsonb_build_object('successful_probe_server', %s::text)
                where singleton_id=1 and active=true
                returning *
                """,
                (str(cleared_by), str(probe_server)),
            )
            row = cur.fetchone()
            if not row:
                # A successful operator probe and the collection worker
                # preflight can race legitimately.  If the same singleton is
                # already inactive, recovery has reached the required state
                # and must be reported idempotently instead of as a failure.
                cur.execute(
                    "select * from runtime_collection_blocks where singleton_id=1"
                )
                existing = cur.fetchone()
                if existing and not bool(existing.get("active")):
                    result = dict(existing)
                    result["clear_outcome"] = "already_clear"
                    return result
                raise RuntimeError("active collection block was not found")
            result = dict(row)
            result["clear_outcome"] = "cleared"
            return result

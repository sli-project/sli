"""Durable Storage V2 entity-state projection with bounded leases and retries."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable

from server.sli.entities.entity_state_model import resolve_current

JOB_SCHEMA_VERSION = 1
MAX_CANDIDATES_PER_EVENT = 64
MAX_CLAIM = 16


def _row_dict(row: Any) -> dict[str, Any]:
    if isinstance(row, dict):
        return dict(row)
    try:
        return dict(row)
    except (TypeError, ValueError):
        return {}


def _canonical_candidates(candidates: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    ordered = sorted(
        (dict(item) for item in candidates),
        key=lambda item: (int(item["entity_id"]), str(item["state_type"]), str(item["rule_id"])),
    )
    if not 1 <= len(ordered) <= MAX_CANDIDATES_PER_EVENT:
        raise ValueError("entity-state job candidate count must be between 1 and 64")
    required = {
        "entity_id", "state_type", "severity", "status", "observed_at_utc",
        "summary", "source_event_db_id", "rule_id", "rule_version",
    }
    for item in ordered:
        missing = sorted(required.difference(item))
        if missing:
            raise ValueError(f"entity-state candidate is missing fields: {', '.join(missing)}")
    return ordered


def enqueue_projection_job(cur: Any, *, source_event_db_id: int, candidates: Iterable[dict[str, Any]]) -> str:
    """Enqueue in the caller's import transaction; replay is identity-safe."""
    normalized = _canonical_candidates(candidates)
    if any(int(item["source_event_db_id"]) != int(source_event_db_id) for item in normalized):
        raise ValueError("candidate source_event_db_id differs from job identity")
    payload = json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    job_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"adlog:entity-state:v1:event:{int(source_event_db_id)}"))
    cur.execute(
        """
        insert into entity_state_projection_jobs(
            job_id,job_schema_version,source_event_db_id,candidate_states
        ) values (%s,%s,%s,%s::jsonb)
        on conflict(source_event_db_id) do nothing
        """,
        (job_id, JOB_SCHEMA_VERSION, int(source_event_db_id), payload),
    )
    cur.execute(
        "select job_id,candidate_states from entity_state_projection_jobs where source_event_db_id=%s",
        (int(source_event_db_id),),
    )
    existing = _row_dict(cur.fetchone())
    existing_payload = existing.get("candidate_states")
    if isinstance(existing_payload, str):
        existing_payload = json.loads(existing_payload)
    if existing_payload != normalized:
        raise RuntimeError("entity-state job replay payload conflict")
    return str(existing.get("job_id") or job_id)


def claim_projection_jobs(cur: Any, *, worker_id: str, limit: int = 1, lease_seconds: int = 300) -> list[dict[str, Any]]:
    """Claim only supported jobs whose V2 event and every V2 entity exist."""
    requested = max(1, min(int(limit), MAX_CLAIM))
    lease = max(60, min(int(lease_seconds), 3600))
    token = str(uuid.uuid4())
    cur.execute(
        """
        with candidates as (
            select job.job_id
            from entity_state_projection_jobs job
            where job.job_schema_version=%s
              and job.attempt_count < job.max_attempts
              and job.available_at <= now()
              and (job.status in ('queued','failed') or (job.status='running' and job.lease_until < now()))
              and exists (select 1 from events_v2_core event where event.id=job.source_event_db_id)
              and not exists (
                  select 1
                  from jsonb_array_elements(job.candidate_states) candidate
                  left join entities_v2_active entity
                    on entity.id=resolve_entity_identity_v2((candidate->>'entity_id')::integer)
                  where entity.id is null
              )
            order by job.source_event_db_id
            for update skip locked
            limit %s
        )
        update entity_state_projection_jobs job
        set status='running', attempt_count=job.attempt_count+1, lease_token=%s,
            lease_until=now() + (%s * interval '1 second'), heartbeat_at=now(),
            last_error=null, updated_at=now()
        from candidates
        where job.job_id=candidates.job_id
        returning job.*
        """,
        (JOB_SCHEMA_VERSION, requested, token, lease),
    )
    rows = [_row_dict(row) for row in (cur.fetchall() or [])]
    for row in rows:
        row["worker_id"] = worker_id
        row["lease_token"] = str(row.get("lease_token") or token)
    return rows


def heartbeat_projection_job(cur: Any, *, job_id: str, lease_token: str, lease_seconds: int = 300) -> bool:
    lease = max(60, min(int(lease_seconds), 3600))
    cur.execute(
        """
        update entity_state_projection_jobs
        set heartbeat_at=now(), lease_until=now() + (%s * interval '1 second'), updated_at=now()
        where job_id=%s and status='running' and lease_token=%s
        returning job_id
        """,
        (lease, job_id, lease_token),
    )
    return cur.fetchone() is not None


def _apply_candidate(cur: Any, candidate: dict[str, Any]) -> str:
    cur.execute(
        "select resolve_entity_identity_v2(%s) as entity_id",
        (int(candidate["entity_id"]),),
    )
    resolved = _row_dict(cur.fetchone())
    if not resolved:
        raise RuntimeError("entity identity resolver returned no row")
    candidate = {**candidate, "entity_id": int(resolved["entity_id"])}
    cur.execute(
        """
        insert into entity_states(
            entity_id,state_type,severity,status,observed_at_utc,summary,evidence_event_id,details_json
        ) values (%s,%s,%s,%s,%s,%s,%s,%s)
        on conflict(entity_id,state_type,evidence_event_id) do nothing
        """,
        (
            int(candidate["entity_id"]), str(candidate["state_type"]), str(candidate["severity"]),
            str(candidate["status"]), str(candidate["observed_at_utc"]), str(candidate["summary"]),
            int(candidate["source_event_db_id"]),
            json.dumps({
                **dict(candidate.get("details") or {}),
                "rule_id": candidate["rule_id"], "rule_version": candidate["rule_version"],
                "projection_status": candidate.get("projection_status", "normal"),
            }, ensure_ascii=False, sort_keys=True),
        ),
    )
    cur.execute(
        """
        select entity_id,state_type,status,projection_status,observed_at,
               source_event_db_id,rule_id,rule_version,details_json
        from entity_state_current where entity_id=%s and state_type=%s for update
        """,
        (int(candidate["entity_id"]), str(candidate["state_type"])),
    )
    current = _row_dict(cur.fetchone()) or None
    if current and isinstance(current.get("observed_at"), datetime):
        current["observed_at_utc"] = current["observed_at"].astimezone(timezone.utc).isoformat()
    action, result = resolve_current(current, candidate)
    if action == "older" or action == "same":
        return action
    details = dict(result.get("details") or {})
    if result.get("conflict_statuses"):
        details["conflict_statuses"] = result["conflict_statuses"]
    cur.execute(
        """
        insert into entity_state_current(
            entity_id,state_type,status,projection_status,observed_at,source_event_db_id,
            rule_id,rule_version,details_json
        ) values (%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
        on conflict(entity_id,state_type) do update set
            status=excluded.status, projection_status=excluded.projection_status,
            observed_at=excluded.observed_at, source_event_db_id=excluded.source_event_db_id,
            rule_id=excluded.rule_id, rule_version=excluded.rule_version,
            details_json=excluded.details_json, updated_at=now()
        """,
        (
            int(result["entity_id"]), str(result["state_type"]), str(result["status"]),
            str(result.get("projection_status") or "normal"), str(result["observed_at_utc"]),
            int(result["source_event_db_id"]), str(result["rule_id"]), str(result["rule_version"]),
            json.dumps(details, ensure_ascii=False, sort_keys=True),
        ),
    )
    return action


def complete_projection_job(cur: Any, job: dict[str, Any]) -> dict[str, int]:
    payload = job.get("candidate_states")
    if isinstance(payload, str):
        payload = json.loads(payload)
    if not isinstance(payload, list) or not 1 <= len(payload) <= MAX_CANDIDATES_PER_EVENT:
        raise ValueError("invalid entity-state job payload")
    counters = {"insert": 0, "replace": 0, "same": 0, "older": 0, "conflict": 0}
    for candidate in payload:
        counters[_apply_candidate(cur, dict(candidate))] += 1
    cur.execute(
        """
        update entity_state_projection_jobs
        set status='completed', completed_at=now(), lease_token=null, lease_until=null,
            heartbeat_at=now(), updated_at=now()
        where job_id=%s and status='running' and lease_token=%s
        returning job_id
        """,
        (str(job["job_id"]), str(job["lease_token"])),
    )
    if cur.fetchone() is None:
        raise RuntimeError("entity-state projection lease was lost")
    return counters


def fail_projection_job(cur: Any, job: dict[str, Any], error: BaseException) -> str:
    attempt = int(job.get("attempt_count") or 1)
    terminal = attempt >= int(job.get("max_attempts") or 5)
    state = "quarantined" if terminal else "failed"
    retry_seconds = min(3600, 30 * (2 ** min(attempt - 1, 7)))
    cur.execute(
        """
        update entity_state_projection_jobs
        set status=%s, available_at=now() + (%s * interval '1 second'),
            lease_token=null, lease_until=null, last_error=%s, updated_at=now()
        where job_id=%s and status='running' and lease_token=%s
        returning status
        """,
        (state, retry_seconds, str(error)[:1000], str(job["job_id"]), str(job["lease_token"])),
    )
    if cur.fetchone() is None:
        raise RuntimeError("entity-state projection lease was lost while recording failure")
    return state

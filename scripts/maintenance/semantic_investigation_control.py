#!/usr/bin/env python3
"""Control accepted investigation rules and their retained-facts backfill.

The backfill reads only the frozen exact version of ``normalized_events`` and
uses the existing semantic dispatch queue.  It does not publish source jobs,
poll collectors, move collection cursors, evaluate risk, or create findings.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.maintenance.semantic_l1_shadow_control import (  # noqa: E402
    _connect_admin,
    _load_environment,
)
from scripts.maintenance.semantic_production_control import (  # noqa: E402
    _archive_reader,
    _facts_check_environment,
)
from server.sli.ops.postgres_session_lock import session_advisory_lock  # noqa: E402
from server.sli.semantic.semantic_investigation_backfill import (  # noqa: E402
    BACKFILL_BATCH_MAX,
    INVESTIGATION_SOURCE_WINDOWS_EVENT_IDS,
    INVESTIGATION_CONTEXT_WINDOWS_EVENT_IDS,
    FACTS_PHASE_ANCHORS,
    FACTS_PHASE_CONTEXT,
    INVESTIGATION_RULE_IDS,
    activate_investigation_rules,
    enqueue_investigation_targets,
    investigation_rule_semantic_types,
    investigation_rule_identities,
    investigation_rule_identity_tuples,
    investigation_quarantine_recovery_candidates,
    investigation_quarantine_recovery_digest,
    investigation_rules_fingerprint,
    new_investigation_facts_checkpoint,
    new_investigation_checkpoint,
    select_investigation_fact_targets,
    select_investigation_targets,
    recover_investigation_quarantined_dispatch_jobs,
    validate_investigation_checkpoint,
    validate_investigation_facts_checkpoint,
)
from server.sli.semantic.semantic_processing import (  # noqa: E402
    NORMALIZER_ID,
    NORMALIZER_VERSION,
    SEMANTIC_CONTRACT_VERSION,
    SemanticFeatureSettings,
)
from server.sli.semantic.semantic_processing_repository import (  # noqa: E402
    PROCESSOR_ID,
    PROCESSOR_VERSION,
)
from server.sli.semantic.semantic_production_runtime import (  # noqa: E402
    INVESTIGATION_MODE,
    PRODUCTION_WORKER_LOCK_NAME,
    prepare_production_connection,
    run_once as run_production_once,
    validate_semantic_runtime_settings,
)
from server.sli.semantic.semantic_producer import publish_semantic_candidates  # noqa: E402
from server.sli.semantic.semantic_worker_connection import connect_semantic_worker  # noqa: E402
from server.sli.semantic.semantic_production_credentials import (  # noqa: E402
    ephemeral_worker_environment,
)
from server.sli.semantic.semantic_worker_runtime import process_semantic_dispatch  # noqa: E402
from server.sli.ops.worker_supervisor_secrets import load_supervisor_environment  # noqa: E402


ACTIVATE_CONFIRM = "ACTIVATE-INVESTIGATION-RELATIONS-SHADOW"
FACTS_POLL_CONFIRM = "POLL-RETAINED-INVESTIGATION-FACTS"
POLL_CONFIRM = "POLL-RETAINED-INVESTIGATION-RELATIONS"
RECOVERY_CONFIRM_PREFIX = "RECOVER-INVESTIGATION-DISPATCH-"
LOCK_NAME = "semantic_retained_investigation_relations_controller_v1"
FACTS_LOCK_NAME = "semantic_retained_investigation_facts_controller_v1"
CHECKPOINT_PATH = ROOT / "artifacts/stage8/evidence/semantic-investigation-relations-checkpoint.json"
FACTS_CHECKPOINT_PATH = ROOT / "artifacts/stage8/evidence/semantic-investigation-facts-checkpoint.json"
SEMANTIC_FLAG_NAMES = (
    "ADLOG_SEMANTIC_PRODUCTION_ENABLED",
    "ADLOG_SEMANTIC_RUNTIME_MODE",
    "ADLOG_SEMANTIC_NORMALIZATION_ENABLED",
    "ADLOG_SEMANTIC_ASSEMBLY_ENABLED",
    "ADLOG_SEMANTIC_DIRECTORY_STATE_ENABLED",
    "ADLOG_SEMANTIC_CORRELATION_ENABLED",
    "ADLOG_SEMANTIC_RISK_ENGINE_ENABLED",
    "ADLOG_SEMANTIC_FINDING_CREATION_ENABLED",
)


def _settings() -> SemanticFeatureSettings:
    settings = SemanticFeatureSettings(
        normalization_enabled=True,
        assembly_enabled=True,
        directory_state_enabled=False,
        correlation_enabled=True,
        risk_engine_enabled=False,
        finding_creation_enabled=False,
    )
    validate_semantic_runtime_settings(
        INVESTIGATION_MODE,
        settings,
        environ={"ADLOG_SEMANTIC_RUNTIME_MODE": INVESTIGATION_MODE},
    )
    return settings


def _database_identity(cur: Any) -> dict[str, str]:
    cur.execute(
        "select coalesce(inet_server_addr()::text,'local') as host,current_database() as database,current_user as role"
    )
    row = dict(cur.fetchone() or {})
    identity = {name: str(row.get(name) or "") for name in ("host", "database", "role")}
    if not all(identity.values()):
        raise RuntimeError("investigation database identity is unavailable")
    return identity


def _snapshot(cur: Any, *, frozen_normalized_at: str | None = None) -> dict[str, Any]:
    boundary = frozen_normalized_at or datetime.now(timezone.utc).isoformat()
    semantic_types = list(investigation_rule_semantic_types())
    cur.execute(
        """
        select exists(
                 select 1 from schema_migrations
                 where version=135 and name='semantic_cross_dc_partitions'
               ) as schema_ready,
               coalesce(max(source_event_id) filter (
                 where processing_status='normalized'
                   and semantic_contract_version=%s
                   and normalizer_id=%s and normalizer_version=%s
                   and normalized_at<=%s and semantic_type=any(%s)
               ),0) as high_watermark,
               count(*) filter (
                 where processing_status='normalized'
                   and semantic_contract_version=%s
                   and normalizer_id=%s and normalizer_version=%s
                   and normalized_at<=%s and semantic_type=any(%s)
               ) as normalized_targets
        from normalized_events
        """,
        (
            SEMANTIC_CONTRACT_VERSION, NORMALIZER_ID, NORMALIZER_VERSION,
            boundary, semantic_types,
            SEMANTIC_CONTRACT_VERSION, NORMALIZER_ID, NORMALIZER_VERSION,
            boundary, semantic_types,
        ),
    )
    summary = dict(cur.fetchone() or {})
    cur.execute(
        """
        select coalesce((select max(id) from events_v2_core),0) as high_watermark,
               count(*) as target_count
        from events_v2_core
        where event_id=any(%s)
        """,
        (list(INVESTIGATION_SOURCE_WINDOWS_EVENT_IDS),),
    )
    raw_summary = dict(cur.fetchone() or {})
    cur.execute(
        """
        select rule_id,rule_version,lifecycle_status,encode(definition_sha256,'hex') as definition_sha256
        from semantic_correlation_rules
        where rule_id=any(%s)
        order by rule_id,rule_version
        """,
        (list(INVESTIGATION_RULE_IDS),),
    )
    rules = [dict(row) for row in (cur.fetchall() or [])]
    database_identity = _database_identity(cur)
    return {
        "database_identity": database_identity,
        "schema_ready": bool(summary.get("schema_ready")),
        "frozen_normalized_at": boundary,
        "high_watermark_source_event_id": int(summary.get("high_watermark") or 0),
        "normalized_targets": int(summary.get("normalized_targets") or 0),
        "retained_anchor_fact_targets": int(raw_summary.get("target_count") or 0),
        "retained_fact_high_watermark_event_id": int(raw_summary.get("high_watermark") or 0),
        "facts_contract": {
            "semantic_contract_version": SEMANTIC_CONTRACT_VERSION,
            "normalizer_id": NORMALIZER_ID,
            "normalizer_version": NORMALIZER_VERSION,
        },
        "rule_ids": list(INVESTIGATION_RULE_IDS),
        "rules": rules,
        "rules_fingerprint": investigation_rules_fingerprint(),
    }


def _read_checkpoint() -> dict[str, Any] | None:
    if not CHECKPOINT_PATH.exists():
        return None
    try:
        payload = json.loads(CHECKPOINT_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("investigation checkpoint is invalid") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("investigation checkpoint is invalid")
    return payload


def _read_facts_checkpoint() -> dict[str, Any] | None:
    if not FACTS_CHECKPOINT_PATH.exists():
        return None
    try:
        payload = json.loads(FACTS_CHECKPOINT_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("investigation facts checkpoint is invalid") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("investigation facts checkpoint is invalid")
    return payload


def _rules_ready(snapshot: dict[str, Any]) -> bool:
    expected = investigation_rule_identities()
    rows = [dict(row) for row in snapshot.get("rules", [])]
    for rule_id, identity in expected.items():
        exact = [
            row for row in rows
            if str(row.get("rule_id")) == rule_id
            and int(row.get("rule_version") or 0) == int(identity["rule_version"])
            and str(row.get("definition_sha256") or "") == str(identity["definition_sha256"])
        ]
        if len(exact) != 1 or exact[0].get("lifecycle_status") != "shadow":
            return False
        if any(
            row not in exact
            and str(row.get("rule_id")) == rule_id
            and row.get("lifecycle_status") in {"test", "shadow", "enabled"}
            for row in rows
        ):
            return False
    return True


def _write_checkpoint(payload: dict[str, Any]) -> None:
    CHECKPOINT_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = CHECKPOINT_PATH.with_name(f".{CHECKPOINT_PATH.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temporary, CHECKPOINT_PATH)


def _write_facts_checkpoint(payload: dict[str, Any]) -> None:
    FACTS_CHECKPOINT_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = FACTS_CHECKPOINT_PATH.with_name(
        f".{FACTS_CHECKPOINT_PATH.name}.{os.getpid()}.tmp"
    )
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8",
    )
    os.replace(temporary, FACTS_CHECKPOINT_PATH)


def _completed_ranges(
    checkpoint: dict[str, Any], *, start_key: str, high_key: str,
) -> list[dict[str, int]]:
    ranges = [
        {"start": int(item["start"]), "end": int(item["end"])}
        for item in checkpoint.get("completed_ranges", [])
    ]
    completed = {
        "start": int(checkpoint[start_key]),
        "end": int(checkpoint[high_key]),
    }
    if not ranges or ranges[-1] != completed:
        ranges.append(completed)
    return ranges


def _resume_facts_checkpoint_for_snapshot(
    checkpoint: dict[str, Any], *, snapshot: dict[str, Any], fingerprint: str,
) -> dict[str, Any]:
    """Open one new frozen range after a completed retained-facts pass."""
    if checkpoint.get("status") != "complete":
        return checkpoint
    previous_high = int(checkpoint["frozen_high_watermark_event_id"])
    observed_high = int(snapshot["retained_fact_high_watermark_event_id"])
    if observed_high <= previous_high:
        return checkpoint
    resumed = new_investigation_facts_checkpoint(
        high_watermark=observed_high,
        fingerprint=fingerprint,
        range_start=previous_high + 1,
    )
    resumed["database_identity"] = snapshot["database_identity"]
    resumed["completed_ranges"] = _completed_ranges(
        checkpoint,
        start_key="range_start_event_id",
        high_key="frozen_high_watermark_event_id",
    )
    return resumed


def _resume_relation_checkpoint_for_snapshot(
    checkpoint: dict[str, Any], *, snapshot: dict[str, Any], fingerprint: str,
) -> dict[str, Any]:
    """Open one new frozen normalized range after a completed relation pass."""
    if checkpoint.get("status") != "complete":
        return checkpoint
    previous_high = int(checkpoint["frozen_high_watermark_source_event_id"])
    observed_high = int(snapshot["high_watermark_source_event_id"])
    if observed_high <= previous_high:
        return checkpoint
    resumed = new_investigation_checkpoint(
        high_watermark=observed_high,
        fingerprint=fingerprint,
        frozen_normalized_at=str(snapshot["frozen_normalized_at"]),
        range_start=previous_high + 1,
    )
    resumed["database_identity"] = snapshot["database_identity"]
    resumed["completed_ranges"] = _completed_ranges(
        checkpoint,
        start_key="range_start_source_event_id",
        high_key="frozen_high_watermark_source_event_id",
    )
    return resumed


def plan() -> dict[str, Any]:
    _load_environment()
    _settings()
    with _connect_admin() as conn, conn.cursor() as cur:
        cur.execute("set transaction read only")
        snapshot = _snapshot(cur)
    checkpoint = _read_checkpoint()
    if checkpoint is not None:
        validate_investigation_checkpoint(
            checkpoint, fingerprint=str(snapshot["rules_fingerprint"]),
        )
        if checkpoint.get("database_identity") != snapshot["database_identity"]:
            raise RuntimeError("investigation checkpoint database identity mismatch")
    relation_state = "not_started"
    if checkpoint is not None:
        relation_state = str(checkpoint.get("status") or "active")
        if (
            relation_state == "complete"
            and int(snapshot["high_watermark_source_event_id"])
            > int(checkpoint["frozen_high_watermark_source_event_id"])
        ):
            relation_state = "next_range_ready"
    return {
        "status": (
            "ready" if snapshot["schema_ready"] and _rules_ready(snapshot)
            else "rules_not_ready" if snapshot["schema_ready"]
            else "schema_not_ready"
        ),
        "snapshot": snapshot,
        "checkpoint": checkpoint,
        "backfill_state": relation_state,
        "checkpoint_path": str(CHECKPOINT_PATH),
        "source_contacted": False,
        "collection_cursors_changed": False,
        "risk_evaluated": False,
        "findings_created": 0,
    }


def facts_plan() -> dict[str, Any]:
    """Preview the exact retained event subset without changing any queue."""
    _load_environment()
    fingerprint = investigation_rules_fingerprint()
    with _connect_admin() as conn, conn.cursor() as cur:
        cur.execute("set transaction read only")
        snapshot = _snapshot(cur)
    checkpoint = _read_facts_checkpoint()
    if checkpoint is not None:
        validate_investigation_facts_checkpoint(
            checkpoint, fingerprint=fingerprint,
        )
        if checkpoint.get("database_identity") != snapshot["database_identity"]:
            raise RuntimeError("investigation facts checkpoint database identity mismatch")
    facts_state = "facts_plan_ready"
    if checkpoint is not None:
        facts_state = "resume_ready"
        if checkpoint.get("status") == "complete":
            facts_state = (
                "next_range_ready"
                if int(snapshot["retained_fact_high_watermark_event_id"])
                > int(checkpoint["frozen_high_watermark_event_id"])
                else "complete"
            )
    return {
        "status": facts_state,
        "database_identity": snapshot["database_identity"],
        "windows_event_ids": list(INVESTIGATION_SOURCE_WINDOWS_EVENT_IDS),
        "context_windows_event_ids": list(INVESTIGATION_CONTEXT_WINDOWS_EVENT_IDS),
        "anchor_target_events": snapshot["retained_anchor_fact_targets"],
        "context_target_events": {
            "state": "deferred_until_anchor_normalization",
            "event_ids": list(INVESTIGATION_CONTEXT_WINDOWS_EVENT_IDS),
            "selection": "exact_sid_successful_reset_then_logon_within_1h",
        },
        "observed_high_watermark_event_id": snapshot["retained_fact_high_watermark_event_id"],
        "rules_fingerprint": fingerprint,
        "checkpoint": checkpoint,
        "checkpoint_path": str(FACTS_CHECKPOINT_PATH),
        "source_contacted": False,
        "collection_cursors_changed": False,
        "risk_evaluated": False,
        "findings_created": 0,
    }


def _recovery_checkpoint() -> dict[str, Any]:
    checkpoint = _read_checkpoint()
    if checkpoint is None:
        raise RuntimeError("investigation relation checkpoint is required for recovery")
    validate_investigation_checkpoint(
        checkpoint, fingerprint=investigation_rules_fingerprint(),
    )
    return checkpoint


def _recovery_bounds(checkpoint: dict[str, Any]) -> tuple[str, int]:
    return (
        str(checkpoint["frozen_normalized_at"]),
        int(checkpoint["frozen_high_watermark_source_event_id"]),
    )


def _recovery_confirmation(plan_digest: str) -> str:
    digest = str(plan_digest or "").casefold()
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise ValueError("investigation recovery plan digest is invalid")
    return RECOVERY_CONFIRM_PREFIX + digest[:16].upper()


def _assert_semantic_production_disabled(
    environ: dict[str, str] | None = None,
) -> None:
    values = os.environ if environ is None else environ
    disabled = {"0", "false", "no", "off"}
    if str(values.get("ADLOG_SEMANTIC_PRODUCTION_ENABLED", "")).strip().casefold() not in disabled:
        raise RuntimeError("semantic production must be disabled before quarantine recovery")
    if str(values.get("ADLOG_SEMANTIC_RUNTIME_MODE", "")).strip() != "disabled":
        raise RuntimeError("semantic production must be disabled before quarantine recovery")
    for name in SEMANTIC_FLAG_NAMES[2:]:
        if str(values.get(name, "")).strip().casefold() not in disabled:
            raise RuntimeError("semantic production must be disabled before quarantine recovery")


@contextmanager
def _investigation_recovery_environment():
    """Admit one process-owned semantic login without changing the sealed profile."""
    previous = {name: os.environ.get(name) for name in SEMANTIC_FLAG_NAMES}
    try:
        os.environ.update({
            "ADLOG_SEMANTIC_PRODUCTION_ENABLED": "1",
            "ADLOG_SEMANTIC_RUNTIME_MODE": INVESTIGATION_MODE,
            "ADLOG_SEMANTIC_NORMALIZATION_ENABLED": "1",
            "ADLOG_SEMANTIC_ASSEMBLY_ENABLED": "1",
            "ADLOG_SEMANTIC_DIRECTORY_STATE_ENABLED": "0",
            "ADLOG_SEMANTIC_CORRELATION_ENABLED": "1",
            "ADLOG_SEMANTIC_RISK_ENGINE_ENABLED": "0",
            "ADLOG_SEMANTIC_FINDING_CREATION_ENABLED": "0",
        })
        with ephemeral_worker_environment():
            yield
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def quarantine_recovery_plan() -> dict[str, Any]:
    """Read-only exact recovery preview for terminal ACL failures."""
    _load_environment()
    checkpoint = _recovery_checkpoint()
    boundary, high = _recovery_bounds(checkpoint)
    with _connect_admin() as conn, conn.cursor() as cur:
        cur.execute("set transaction read only")
        database_identity = _database_identity(cur)
        if checkpoint.get("database_identity") != database_identity:
            raise RuntimeError("investigation checkpoint database identity mismatch")
        candidates = investigation_quarantine_recovery_candidates(
            cur,
            frozen_normalized_at=boundary,
            high_watermark_source_event_id=high,
        )
    digest = investigation_quarantine_recovery_digest(
        candidates,
        database_identity=database_identity,
        frozen_normalized_at=boundary,
        high_watermark_source_event_id=high,
    )
    jobs = [{
        "job_id": str(row["job_id"]),
        "source_event_id": int(row["source_event_id"]),
        "rule_id": str(row["rule_id"]),
        "rule_version": int(row["rule_version"]),
        "definition_sha256": str(row["definition_sha256"]),
        "attempt_count": int(row["attempt_count"]),
        "max_attempts": int(row["max_attempts"]),
        "error_code": str(row["last_error_code"]),
    } for row in candidates]
    return {
        "status": "recovery_required" if jobs else "nothing_to_recover",
        "database_identity": database_identity,
        "frozen_normalized_at": boundary,
        "high_watermark_source_event_id": high,
        "candidate_count": len(jobs),
        "jobs": jobs,
        "plan_digest": digest,
        "required_confirmation": _recovery_confirmation(digest),
        "source_contacted": False,
        "collection_cursors_changed": False,
        "risk_evaluated": False,
        "findings_created": 0,
    }


def _dispatch_recovered_jobs(
    *, conn: Any, settings: SemanticFeatureSettings,
    job_ids: tuple[str, ...], frozen_normalized_at: str,
) -> dict[str, Any]:
    aggregate = {"completed": 0, "failed": 0, "relations": 0}
    if not job_ids:
        return aggregate
    boundary = datetime.fromisoformat(frozen_normalized_at.replace("Z", "+00:00"))
    for _offset in range(0, len(job_ids), 16):
        cycle = process_semantic_dispatch(
            conn,
            archive=None,
            settings=settings,
            limit=16,
            allowed_rule_identities=investigation_rule_identity_tuples(),
            allowed_job_ids=job_ids,
            normalized_before=boundary,
        )
        for key in aggregate:
            aggregate[key] += int(cycle[key])
        if int(cycle["failed"]):
            break
        if int(cycle["completed"]) == 0:
            break
    return aggregate


def _recovered_job_states(job_ids: tuple[str, ...]) -> list[dict[str, Any]]:
    if not job_ids:
        return []
    with _connect_admin() as conn, conn.cursor() as cur:
        cur.execute("set transaction read only")
        cur.execute(
            """
            select job_id::text as job_id,dispatch_status,attempt_count,max_attempts,
                   last_error_code
            from semantic_correlation_dispatch_jobs
            where job_id=any(%s::uuid[])
            order by job_id
            """,
            (list(job_ids),),
        )
        return [dict(row) for row in (cur.fetchall() or ())]


def quarantine_recover(*, plan_digest: str, confirmation: str) -> dict[str, Any]:
    """Recover and dispatch only one unchanged, plan-bound ACL failure set."""
    digest = str(plan_digest or "").casefold()
    if confirmation != _recovery_confirmation(digest):
        raise RuntimeError("exact investigation quarantine recovery confirmation required")
    _load_environment()
    _assert_semantic_production_disabled()
    with session_advisory_lock(_connect_admin, LOCK_NAME) as controller_acquired:
        if not controller_acquired:
            raise RuntimeError("investigation backfill lock is busy")
        with session_advisory_lock(
            _connect_admin, PRODUCTION_WORKER_LOCK_NAME,
        ) as worker_acquired:
            if not worker_acquired:
                raise RuntimeError("semantic production worker lock is busy")
            checkpoint = _recovery_checkpoint()
            boundary, high = _recovery_bounds(checkpoint)
            with _investigation_recovery_environment():
                with connect_semantic_worker() as semantic_conn:
                    settings = prepare_production_connection(
                        semantic_conn, runtime_mode=INVESTIGATION_MODE,
                    )
                    with _connect_admin() as conn:
                        with conn.transaction(), conn.cursor() as cur:
                            database_identity = _database_identity(cur)
                            if checkpoint.get("database_identity") != database_identity:
                                raise RuntimeError("investigation checkpoint database identity mismatch")
                            cur.execute("set local role adlog_storage_worker")
                            recovered = recover_investigation_quarantined_dispatch_jobs(
                                cur,
                                expected_digest=digest,
                                database_identity=database_identity,
                                frozen_normalized_at=boundary,
                                high_watermark_source_event_id=high,
                            )
                    dispatch = _dispatch_recovered_jobs(
                        conn=semantic_conn,
                        settings=settings,
                        job_ids=recovered,
                        frozen_normalized_at=boundary,
                    )
                    states = _recovered_job_states(recovered)
    completed = bool(recovered) and len(states) == len(recovered) and all(
        str(row.get("dispatch_status") or "") == "completed" for row in states
    )
    return {
        "status": (
            "complete" if completed else
            "nothing_to_recover" if not recovered else
            "blocked_batch"
        ),
        "plan_digest": digest,
        "recovered_job_ids": list(recovered),
        "dispatch": dispatch,
        "job_states": states,
        "source_contacted": False,
        "collection_cursors_changed": False,
        "risk_evaluated": False,
        "findings_created": 0,
    }


def _facts_completion_state(
    cur: Any,
    event_ids: tuple[int, ...],
) -> dict[str, Any]:
    """Prove that every exact source has the current fact and completed job."""
    requested = tuple(sorted({int(value) for value in event_ids}))
    if not requested:
        return {
            "state": "processed",
            "requested": 0,
            "completed": 0,
            "queued": 0,
            "leased": 0,
            "failed": 0,
            "quarantined": 0,
            "not_enqueued": 0,
            "inconsistent_completed": 0,
            "unresolved_event_ids": [],
        }
    cur.execute(
        """
        select requested.source_event_id,
               fact.processing_status,
               job.status as outbox_status
        from unnest(%s::bigint[]) requested(source_event_id)
        left join normalized_events fact
          on fact.source_event_id=requested.source_event_id
         and fact.semantic_contract_version=%s
         and fact.normalizer_id=%s
         and fact.normalizer_version=%s
        left join semantic_processing_outbox job
          on job.source_event_id=requested.source_event_id
         and job.job_kind='normalize_event'
         and job.semantic_contract_version=%s
         and job.processor_id=%s
         and job.processor_version=%s
        order by requested.source_event_id
        """,
        (
            list(requested),
            SEMANTIC_CONTRACT_VERSION,
            NORMALIZER_ID,
            NORMALIZER_VERSION,
            SEMANTIC_CONTRACT_VERSION,
            PROCESSOR_ID,
            PROCESSOR_VERSION,
        ),
    )
    rows = [dict(row) for row in (cur.fetchall() or [])]
    by_id = {int(row["source_event_id"]): row for row in rows}
    counters = {
        "queued": 0,
        "leased": 0,
        "failed": 0,
        "quarantined": 0,
        "not_enqueued": 0,
        "inconsistent_completed": 0,
    }
    completed = 0
    unresolved: list[int] = []
    for source_event_id in requested:
        row = by_id.get(source_event_id, {})
        fact_status = str(row.get("processing_status") or "")
        outbox_status = str(row.get("outbox_status") or "")
        if fact_status in {"normalized", "ignored"} and outbox_status == "completed":
            completed += 1
            continue
        unresolved.append(source_event_id)
        if outbox_status in {"queued", "leased", "failed", "quarantined"}:
            counters[outbox_status] += 1
        elif outbox_status == "completed":
            counters["inconsistent_completed"] += 1
        else:
            counters["not_enqueued"] += 1
    state = "processed" if completed == len(requested) else (
        "no_admitted_events"
        if counters["not_enqueued"] == len(requested)
        else "pending"
    )
    return {
        "state": state,
        "requested": len(requested),
        "completed": completed,
        **counters,
        "unresolved_event_ids": unresolved,
    }


def _verify_exact_facts(event_ids: tuple[int, ...]) -> dict[str, Any]:
    with _connect_admin() as conn, conn.cursor() as cur:
        cur.execute("set transaction read only")
        return _facts_completion_state(cur, event_ids)


def _process_exact_facts(event_ids: tuple[int, ...]) -> dict[str, Any]:
    """Publish and consume one exact retained batch under the facts-only lock."""
    if not event_ids or len(event_ids) > BACKFILL_BATCH_MAX:
        raise ValueError("investigation facts batch is invalid")
    with _facts_check_environment():
        with session_advisory_lock(
            connect_semantic_worker,
            PRODUCTION_WORKER_LOCK_NAME,
            prepare=prepare_production_connection,
        ) as acquired:
            if not acquired:
                return {"status": "blocked", "reason": "semantic_production_worker_lock_held"}
            with _connect_admin() as conn:
                with conn.transaction(), conn.cursor() as cur:
                    cur.execute("set local role adlog_storage_worker")
                    producer = publish_semantic_candidates(
                        cur, event_ids, include_context=True,
                    )
            aggregate = {
                "completed": 0, "failed": 0, "normalized": 0, "actions": 0,
            }
            archive = _archive_reader()
            for offset in range(0, len(event_ids), 16):
                chunk = event_ids[offset:offset + 16]
                cycle = run_production_once(
                    limit=len(chunk),
                    connect_factory=connect_semantic_worker,
                    archive=archive,
                    source_event_ids=chunk,
                )
                processing = dict(cycle.get("processing") or {})
                for key in aggregate:
                    aggregate[key] += int(processing.get(key) or 0)
                if int(cycle.get("failed") or 0):
                    break
            verification = _verify_exact_facts(event_ids)
            return {
                "status": verification["state"],
                "producer": producer,
                "processing": aggregate,
                "verification": verification,
            }


def _advance_facts_checkpoint(
    checkpoint: dict[str, Any],
    *,
    phase: str,
    targets: tuple[int, ...],
    high_watermark: int,
) -> None:
    next_committed = int(targets[-1]) if targets else int(high_watermark)
    checkpoint["last_committed_event_id"] = next_committed
    if next_committed >= high_watermark and phase == FACTS_PHASE_ANCHORS:
        checkpoint["phase"] = FACTS_PHASE_CONTEXT
        checkpoint["last_committed_event_id"] = (
            int(checkpoint.get("range_start_event_id", 1)) - 1
        )
        checkpoint["status"] = "active"
    else:
        checkpoint["status"] = (
            "complete" if next_committed >= high_watermark else "active"
        )
    checkpoint["updated_at_utc"] = datetime.now(timezone.utc).isoformat()


def facts_backfill_poll() -> dict[str, Any]:
    """Process one checkpointed retained batch without remote source contact."""
    _load_environment()
    fingerprint = investigation_rules_fingerprint()
    with session_advisory_lock(_connect_admin, FACTS_LOCK_NAME) as acquired:
        if not acquired:
            raise RuntimeError("investigation facts backfill lock is busy")
        checkpoint = _read_facts_checkpoint()
        with _connect_admin() as conn, conn.cursor() as cur:
            cur.execute("set transaction read only")
            snapshot = _snapshot(cur)
            if checkpoint is None:
                checkpoint = new_investigation_facts_checkpoint(
                    high_watermark=int(snapshot["retained_fact_high_watermark_event_id"]),
                    fingerprint=fingerprint,
                )
                checkpoint["database_identity"] = snapshot["database_identity"]
                _write_facts_checkpoint(checkpoint)
            else:
                validate_investigation_facts_checkpoint(
                    checkpoint, fingerprint=fingerprint,
                )
                if checkpoint.get("database_identity") != snapshot["database_identity"]:
                    raise RuntimeError("investigation facts checkpoint database identity mismatch")
                resumed = _resume_facts_checkpoint_for_snapshot(
                    checkpoint, snapshot=snapshot, fingerprint=fingerprint,
                )
                if resumed is not checkpoint:
                    checkpoint = resumed
                    _write_facts_checkpoint(checkpoint)
            committed = int(checkpoint["last_committed_event_id"])
            high = int(checkpoint["frozen_high_watermark_event_id"])
            phase = str(checkpoint["phase"])
            targets = select_investigation_fact_targets(
                cur,
                after_id=committed,
                high_watermark=high,
                limit=BACKFILL_BATCH_MAX,
                phase=phase,
            )
        processing = _process_exact_facts(targets) if targets else {
            "status": "processed",
            "producer": {"scanned": 0, "queued": 0},
            "processing": {"completed": 0, "failed": 0, "normalized": 0, "actions": 0},
        }
        if processing.get("status") != "processed":
            return {
                "status": "blocked_batch",
                "checkpoint": checkpoint,
                "target_events": len(targets),
                "processing": processing,
                "source_contacted": False,
                "collection_cursors_changed": False,
                "risk_evaluated": False,
                "findings_created": 0,
            }
        _advance_facts_checkpoint(
            checkpoint,
            phase=phase,
            targets=targets,
            high_watermark=high,
        )
        _write_facts_checkpoint(checkpoint)
    return {
        "status": checkpoint["status"],
        "checkpoint": checkpoint,
        "target_events": len(targets),
        "processing": processing,
        "source_contacted": False,
        "collection_cursors_changed": False,
        "risk_evaluated": False,
        "findings_created": 0,
    }


def activate() -> dict[str, Any]:
    _load_environment()
    _settings()
    with _connect_admin() as conn:
        with conn.transaction(), conn.cursor() as cur:
            cur.execute(
                "select exists(select 1 from schema_migrations where version=138 and name='normalized_event_versioned_identity') as ready"
            )
            if not bool(dict(cur.fetchone() or {}).get("ready")):
                raise RuntimeError("migration 138 is required before investigation activation")
            cur.execute("set local role adlog_storage_worker")
            statuses = activate_investigation_rules(cur)
    return {
        "status": "investigation_rules_shadow",
        "rules": statuses,
        "worker_started": False,
        "risk_evaluated": False,
        "findings_created": 0,
    }


def backfill_poll() -> dict[str, Any]:
    _load_environment()
    settings = _settings()
    fingerprint = investigation_rules_fingerprint()
    with session_advisory_lock(_connect_admin, LOCK_NAME) as acquired:
        if not acquired:
            raise RuntimeError("investigation backfill lock is busy")
        checkpoint = _read_checkpoint()
        with _connect_admin() as conn, conn.cursor() as cur:
            cur.execute("set transaction read only")
            if checkpoint is None:
                snapshot = _snapshot(cur)
                if not snapshot["schema_ready"]:
                    raise RuntimeError("migration 135 is required before investigation backfill")
                if not _rules_ready(snapshot):
                    raise RuntimeError("exact investigation rules must be in shadow before backfill")
                checkpoint = new_investigation_checkpoint(
                    high_watermark=int(snapshot["high_watermark_source_event_id"]),
                    fingerprint=fingerprint,
                    frozen_normalized_at=str(snapshot["frozen_normalized_at"]),
                )
                checkpoint["database_identity"] = snapshot["database_identity"]
                _write_checkpoint(checkpoint)
            else:
                validate_investigation_checkpoint(checkpoint, fingerprint=fingerprint)
                if checkpoint.get("database_identity") != _database_identity(cur):
                    raise RuntimeError("investigation checkpoint database identity mismatch")
                live_snapshot = _snapshot(cur)
                resumed = _resume_relation_checkpoint_for_snapshot(
                    checkpoint, snapshot=live_snapshot, fingerprint=fingerprint,
                )
                if resumed is not checkpoint:
                    checkpoint = resumed
                    _write_checkpoint(checkpoint)
                current = _snapshot(cur, frozen_normalized_at=str(checkpoint["frozen_normalized_at"]))
                if not _rules_ready(current):
                    raise RuntimeError("investigation rules changed during backfill")
        committed = int(checkpoint["last_committed_source_event_id"])
        high = int(checkpoint["frozen_high_watermark_source_event_id"])
        with _connect_admin() as conn:
            with conn.transaction(), conn.cursor() as cur:
                cur.execute("set local role adlog_storage_worker")
                targets = select_investigation_targets(
                    cur,
                    after_id=committed,
                    high_watermark=high,
                    limit=BACKFILL_BATCH_MAX,
                    frozen_normalized_at=str(checkpoint["frozen_normalized_at"]),
                )
                job_ids = enqueue_investigation_targets(cur, targets)

            dispatch = {"completed": 0, "failed": 0, "relations": 0}
            with conn.cursor() as cur:
                cur.execute("set role adlog_storage_worker")
            frozen_normalized_at = datetime.fromisoformat(
                str(checkpoint["frozen_normalized_at"]).replace("Z", "+00:00")
            )
            if job_ids:
                for _ in range(BACKFILL_BATCH_MAX // 16 + 2):
                    cycle = process_semantic_dispatch(
                        conn,
                        archive=None,
                        settings=settings,
                        limit=16,
                        allowed_rule_identities=investigation_rule_identity_tuples(),
                        allowed_job_ids=job_ids,
                        normalized_before=frozen_normalized_at,
                    )
                    for key in dispatch:
                        dispatch[key] += int(cycle[key])
                    if int(cycle["completed"]) + int(cycle["failed"]) == 0:
                        break
            pending: list[dict[str, Any]] = []
            if job_ids:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        select job_id,dispatch_status,last_error_code
                        from semantic_correlation_dispatch_jobs
                        where job_id=any(%s) and dispatch_status<>'completed'
                        order by job_id
                        """,
                        (list(job_ids),),
                    )
                    pending = [dict(row) for row in (cur.fetchall() or [])]
        if not pending and int(dispatch["failed"]) == 0:
            next_committed = int(targets[-1]["source_event_id"]) if targets else high
            checkpoint["last_committed_source_event_id"] = next_committed
            checkpoint["status"] = "complete" if next_committed >= high else "active"
            checkpoint["updated_at_utc"] = datetime.now(timezone.utc).isoformat()
            _write_checkpoint(checkpoint)
        return {
            "status": "complete" if checkpoint["status"] == "complete" else ("blocked_batch" if pending or dispatch["failed"] else "batch_complete"),
            "checkpoint": checkpoint,
            "targets": len(targets),
            "jobs": len(job_ids),
            "dispatch": dispatch,
            "pending_jobs": pending,
            "source_contacted": False,
            "collection_cursors_changed": False,
            "risk_evaluated": False,
            "findings_created": 0,
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=(
            "plan", "facts-plan", "facts-backfill-poll", "activate",
            "backfill-poll", "quarantine-plan", "quarantine-recover",
        ),
    )
    parser.add_argument("--confirm", default="")
    parser.add_argument(
        "--plan-digest",
        default="",
        help="Exact digest printed by quarantine-plan; required for quarantine-recover.",
    )
    parser.add_argument(
        "--max-polls",
        type=int,
        default=1,
        help="Run up to this many checkpointed batches (1..20); stop on completion or a blocked batch.",
    )
    parser.add_argument(
        "--environment-file",
        type=Path,
        help="CurrentUser DPAPI runtime-environment profile; secret values are never printed.",
    )
    args = parser.parse_args()
    try:
        if not 1 <= args.max_polls <= 20:
            raise RuntimeError("max polls must be between 1 and 20")
        if args.max_polls != 1 and args.action not in {"facts-backfill-poll", "backfill-poll"}:
            raise RuntimeError("multiple polls are only valid for checkpointed backfill actions")
        if args.environment_file is not None and not load_supervisor_environment(
            path=args.environment_file,
            override_existing=True,
        ):
            raise RuntimeError("protected runtime environment could not be loaded")
        if args.action == "plan":
            payload = plan()
        elif args.action == "facts-plan":
            payload = facts_plan()
        elif args.action == "quarantine-plan":
            payload = quarantine_recovery_plan()
        elif args.action == "quarantine-recover":
            payload = quarantine_recover(
                plan_digest=args.plan_digest,
                confirmation=args.confirm,
            )
        elif args.action == "facts-backfill-poll":
            if args.confirm != FACTS_POLL_CONFIRM:
                raise RuntimeError("exact investigation facts confirmation required")
            poll_results = []
            for _index in range(args.max_polls):
                payload = facts_backfill_poll()
                poll_results.append({
                    "status": payload.get("status"),
                    "targets": payload.get("target_events", 0),
                    "phase": (payload.get("checkpoint") or {}).get("phase"),
                    "last_committed": (payload.get("checkpoint") or {}).get("last_committed_event_id"),
                })
                if payload.get("status") in {"complete", "blocked_batch"}:
                    break
            payload["polls_executed"] = len(poll_results)
            payload["poll_summaries"] = poll_results
        elif args.action == "activate":
            if args.confirm != ACTIVATE_CONFIRM:
                raise RuntimeError("exact investigation activation confirmation required")
            payload = activate()
        else:
            if args.confirm != POLL_CONFIRM:
                raise RuntimeError("exact investigation backfill confirmation required")
            poll_results = []
            for _index in range(args.max_polls):
                payload = backfill_poll()
                poll_results.append({
                    "status": payload.get("status"),
                    "targets": payload.get("targets", 0),
                    "last_committed": (payload.get("checkpoint") or {}).get("last_committed_source_event_id"),
                })
                if payload.get("status") in {"complete", "blocked_batch"}:
                    break
            payload["polls_executed"] = len(poll_results)
            payload["poll_summaries"] = poll_results
        print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
        return 0
    except Exception as exc:
        print(json.dumps({"status": "blocked", "error_type": type(exc).__name__, "error": str(exc)}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

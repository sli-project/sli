"""Bounded normalization/assembly stage for the semantic worker."""
from __future__ import annotations

from datetime import datetime
from hashlib import sha256
import re
from typing import Any, Callable, Mapping, Sequence
from uuid import UUID

from server.sli.ops import shutdown
from server.sli.semantic.semantic_processing import (
    SemanticFeatureSettings,
    apply_identity_role_overrides,
    assemble_canonical_actions,
    normalize_semantic_source_payload,
)
from server.sli.semantic.semantic_processing_repository import (
    INVESTIGATION_CONTEXT_JOB_KIND,
    SEMANTIC_REPAIR_JOB_KIND,
    SEMANTIC_V2_QUARANTINE_REPAIR_JOB_KIND,
    claim_semantic_jobs,
    complete_semantic_job,
    defer_semantic_job,
    enqueue_semantic_job,
    fail_semantic_job,
    load_semantic_source_event,
    load_retained_normalized_event,
    load_identity_role_overrides,
    lock_semantic_source,
    prior_identity_normalized_events,
    persist_canonical_actions,
    persist_normalized_event,
    record_identity_semantic_replay,
    semantic_source_identity,
)
from server.sli.semantic.semantic_producer import (
    MAX_CONTEXT_EXPANSION_BATCH,
    select_investigation_context_expansion_ids,
)
from server.sli.semantic.semantic_processing import NORMALIZER_ID, NORMALIZER_VERSION
from server.sli.semantic.semantic_dispatch import match_compiled_rule
from server.sli.semantic.semantic_dispatch_repository import (
    claim_dispatch_jobs,
    complete_dispatch_job,
    enqueue_dispatch_jobs,
    fail_dispatch_job,
    load_dispatch_work_item,
    persist_dispatched_relation,
)

MAX_SEMANTIC_BATCH = 128
MAX_SEMANTIC_RECOVERY_BATCH = 16


def semantic_cycle_has_work(result: Mapping[str, Any]) -> bool:
    """Poll again after activity; only an empty cycle earns the idle delay.

    Claimed context-expansion jobs may defer without completing or failing.
    Failed jobs retain their repository retry delay, so polling again does not
    bypass backoff. Exceptions outside a completed cycle still use the delay.
    """
    return any(int(result.get(key) or 0) > 0 for key in ("completed", "failed", "risk_queued")) or any(
        int((result.get(stage) or {}).get("claimed") or 0) > 0
        for stage in ("processing", "dispatch")
    )


def _validate_semantic_repair_job(cur: Any, job: Mapping[str, Any], payload: Mapping[str, Any]) -> None:
    """Bind a repair to its immutable source identity and approved plan digest."""
    plan_digest = str(payload.get("repair_plan_digest") or "").casefold()
    history_plan_digest = str(payload.get("history_plan_digest") or "").casefold()
    source_hash = str(payload.get("original_source_hash") or "").casefold()
    original_job_id = str(payload.get("original_job_id") or "").strip()
    if (
        len(plan_digest) != 64
        or len(history_plan_digest) != 64
        or len(source_hash) != 64
        or any(value not in "0123456789abcdef" for value in plan_digest + history_plan_digest + source_hash)
        or not original_job_id
    ):
        raise RuntimeError("semantic repair payload is invalid")
    try:
        UUID(original_job_id)
    except ValueError as exc:
        raise RuntimeError("semantic repair original job id is invalid") from exc
    identity = semantic_source_identity(job.get("source_identity_json") or {})
    if identity["normalized_hash"] != source_hash:
        raise RuntimeError("semantic repair source hash differs from immutable job identity")
    cur.execute(
        """
        select source_event_id,job_kind,status,processor_id,processor_version,
               source_identity_json->>'normalized_hash' as source_hash
        from semantic_processing_outbox where job_id=%s
        """,
        (original_job_id,),
    )
    original = dict(cur.fetchone() or {})
    if (
        int(original.get("source_event_id") or 0) != int(job["source_event_id"])
        or original.get("job_kind") != "normalize_event"
        or original.get("status") != "completed"
        or original.get("processor_id") != job.get("processor_id")
        or original.get("processor_version") != job.get("processor_version")
        or str(original.get("source_hash") or "").casefold() != source_hash
    ):
        raise RuntimeError("semantic repair original job no longer matches approved source")


_LOWER_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CANONICAL_ACTIONS_PRIMARY_KEY_DETAIL = re.compile(r"['\"]canonical_actions_pkey['\"]")


def _validate_semantic_v2_quarantine_repair_job(
    cur: Any, job: Mapping[str, Any], payload: Mapping[str, Any]
) -> None:
    """Fail closed before archive I/O for one terminal v2 repair candidate."""
    required_digests = (
        "repair_plan_digest", "history_plan_digest", "original_source_hash",
        "original_error_detail_sha256",
    )
    values = {field: str(payload.get(field) or "") for field in required_digests}
    if any(_LOWER_SHA256.fullmatch(value) is None for value in values.values()):
        raise RuntimeError("semantic v2 quarantine repair payload digest is invalid")
    original_job_id = str(payload.get("original_job_id") or "")
    try:
        if str(UUID(original_job_id)) != original_job_id:
            raise ValueError("not canonical")
    except ValueError as exc:
        raise RuntimeError("semantic v2 quarantine repair original job id is invalid") from exc
    original_attempt_count = payload.get("original_attempt_count")
    original_max_attempts = payload.get("original_max_attempts")
    if type(original_attempt_count) is not int or type(original_max_attempts) is not int:
        raise RuntimeError("semantic v2 quarantine repair attempts are invalid")
    original_attempt_count = int(original_attempt_count)
    original_max_attempts = int(original_max_attempts)
    if (
        original_attempt_count <= 0
        or original_max_attempts <= 0
        or original_attempt_count != original_max_attempts
        or payload.get("original_error_code") != "UniqueViolation"
    ):
        raise RuntimeError("semantic v2 quarantine repair terminal evidence is invalid")
    identity = semantic_source_identity(job.get("source_identity_json") or {})
    if identity["normalized_hash"] != values["original_source_hash"]:
        raise RuntimeError("semantic v2 quarantine repair source hash differs from immutable identity")
    cur.execute(
        """
        select source_event_id,job_kind,status,semantic_contract_version,
               processor_id,processor_version,
               source_identity_json->>'normalized_hash' as source_hash,
               attempt_count,max_attempts,last_error_code,last_error_detail
        from semantic_processing_outbox where job_id=%s
        """,
        (original_job_id,),
    )
    original = dict(cur.fetchone() or {})
    detail = str(original.get("last_error_detail") or "")
    if (
        int(original.get("source_event_id") or 0) != int(job["source_event_id"])
        or original.get("job_kind") != "normalize_event"
        or original.get("status") != "quarantined"
        or int(original.get("semantic_contract_version") or 0) != int(job.get("semantic_contract_version") or 0)
        or original.get("processor_id") != job.get("processor_id")
        or original.get("processor_version") != job.get("processor_version")
        or str(original.get("source_hash") or "") != values["original_source_hash"]
        or int(original.get("attempt_count") or 0) != original_attempt_count
        or int(original.get("max_attempts") or 0) != original_max_attempts
        or original.get("last_error_code") != "UniqueViolation"
        or sha256(detail.encode("utf-8")).hexdigest() != values["original_error_detail_sha256"]
        or _CANONICAL_ACTIONS_PRIMARY_KEY_DETAIL.search(detail) is None
    ):
        raise RuntimeError("semantic v2 quarantine repair original job no longer matches terminal evidence")
    cur.execute(
        """select exists(
              select 1 from normalized_events
              where source_event_id=%s and semantic_contract_version=%s
                and normalizer_id=%s and normalizer_version=%s
            ) as exists""",
        (int(job["source_event_id"]), int(job["semantic_contract_version"]), NORMALIZER_ID, NORMALIZER_VERSION),
    )
    if bool(dict(cur.fetchone() or {}).get("exists")):
        raise RuntimeError("semantic v2 quarantine repair source is already normalized")


def process_semantic_outbox(
    conn: Any,
    *,
    archive: Any,
    settings: SemanticFeatureSettings,
    limit: int,
    source_event_ids: Sequence[int] | None = None,
    allowed_rule_identities: Sequence[tuple[str, int, bytes | str]] | None = None,
    repair_plan_digest: str | None = None,
) -> dict[str, int]:
    """Process identity-only jobs; every job owns one bounded transaction."""
    if not settings.normalization_enabled:
        return {"completed": 0, "failed": 0, "normalized": 0, "actions": 0, "claimed": 0}
    recovery_digest = str(repair_plan_digest or "").strip()
    if recovery_digest and (
        len(recovery_digest) != 64
        or any(char not in "0123456789abcdef" for char in recovery_digest)
    ):
        raise ValueError("semantic v2 quarantine repair digest is invalid")
    batch_limit = MAX_SEMANTIC_RECOVERY_BATCH if recovery_digest else MAX_SEMANTIC_BATCH
    requested = max(1, min(int(limit), batch_limit))
    completed = failed = normalized_count = action_count = claimed_count = 0
    # Claim just before processing, in repository order. Pre-leasing a whole
    # batch could expire later jobs' leases while earlier jobs are still running.
    for _ in range(requested):
        if shutdown.requested():
            break
        with conn.transaction(), conn.cursor() as cur:
            claim_kwargs: dict[str, Any] = {"limit": 1}
            if source_event_ids is not None:
                claim_kwargs["source_event_ids"] = source_event_ids
            if recovery_digest:
                claim_kwargs["repair_plan_digest"] = recovery_digest
            jobs = claim_semantic_jobs(cur, **claim_kwargs)
        if not jobs:
            break
        job = jobs[0]
        claimed_count += 1
        try:
            job_kind = str(job.get("job_kind") or "")
            if recovery_digest and job_kind != SEMANTIC_V2_QUARANTINE_REPAIR_JOB_KIND:
                raise RuntimeError("recovery-only semantic worker claimed an unscoped job")
            if not recovery_digest and job_kind == SEMANTIC_V2_QUARANTINE_REPAIR_JOB_KIND:
                raise RuntimeError("ordinary semantic worker must not process v2 quarantine repair")
            if job_kind not in {
                "normalize_event",
                "semantic_replay",
                INVESTIGATION_CONTEXT_JOB_KIND,
                SEMANTIC_REPAIR_JOB_KIND,
                SEMANTIC_V2_QUARANTINE_REPAIR_JOB_KIND,
            }:
                raise RuntimeError("unsupported semantic worker job kind")
            payload = job.get("payload_json") or {}
            if isinstance(payload, str):
                import json
                payload = json.loads(payload)
            if not isinstance(payload, Mapping):
                raise RuntimeError("semantic job payload must be an object")
            if (
                recovery_digest
                and str(payload.get("repair_plan_digest") or "") != recovery_digest
            ):
                raise RuntimeError("recovery-only semantic worker repair digest differs")
            if job_kind == INVESTIGATION_CONTEXT_JOB_KIND:
                with conn.transaction(), conn.cursor() as cur:
                    context_ids, has_more = select_investigation_context_expansion_ids(
                        cur,
                        reset_source_event_id=int(job["source_event_id"]),
                        limit=MAX_CONTEXT_EXPANSION_BATCH,
                    )
                    for source_event_id in context_ids:
                        enqueue_semantic_job(
                            cur,
                            source_event_id=source_event_id,
                            payload={"selection_reason": "late_related_context"},
                        )
                    if has_more:
                        defer_semantic_job(
                            cur,
                            job_id=str(job["job_id"]),
                            lease_token=str(job["lease_token"]),
                        )
                    else:
                        complete_semantic_job(
                            cur,
                            job_id=str(job["job_id"]),
                            lease_token=str(job["lease_token"]),
                        )
                if not has_more:
                    completed += 1
                continue
            required_merge_id = (
                str(payload.get("identity_merge_id") or "").strip()
                if job_kind == "semantic_replay"
                else None
            )
            if job_kind == "semantic_replay" and not required_merge_id:
                raise RuntimeError("identity semantic replay requires merge id")
            persisted_actions = 0
            with conn.transaction(), conn.cursor() as cur:
                lock_semantic_source(cur, source_event_id=int(job["source_event_id"]))
                if job_kind == SEMANTIC_REPAIR_JOB_KIND:
                    _validate_semantic_repair_job(cur, job, payload)
                elif job_kind == SEMANTIC_V2_QUARANTINE_REPAIR_JOB_KIND:
                    _validate_semantic_v2_quarantine_repair_job(cur, job, payload)
                try:
                    source = load_semantic_source_event(
                        cur,
                        source_event_id=int(job["source_event_id"]),
                        archive=archive,
                        source_identity=job.get("source_identity_json"),
                    )
                except FileNotFoundError:
                    # A prior repair may have persisted this exact version's
                    # facts before its source archive became unavailable. Replays and
                    # scoped repairs still require the original evidence.
                    if job_kind != "normalize_event" or not job.get("source_identity_json"):
                        raise
                    normalized = load_retained_normalized_event(
                        cur, source_event_id=int(job["source_event_id"]),
                        source_identity=job["source_identity_json"],
                    )
                    if normalized is None:
                        raise
                else:
                    if not source:
                        raise RuntimeError("semantic source event missing")
                    normalized = normalize_semantic_source_payload(source)
                overrides = load_identity_role_overrides(
                    cur,
                    event=normalized,
                    required_merge_id=required_merge_id,
                )
                old_normalized_ids = (
                    prior_identity_normalized_events(
                        cur,
                        source_event_id=normalized.source_event_id,
                        source_keys=tuple(overrides),
                    )
                    if required_merge_id
                    else ()
                )
                normalized = apply_identity_role_overrides(normalized, overrides)
                normalizer_version = (
                    str(job["processor_version"])
                    if required_merge_id
                    else NORMALIZER_VERSION
                )
                normalized_id = (
                    persist_normalized_event(
                        cur,
                        event=normalized,
                        normalizer_version=normalizer_version,
                        source_identity=job.get("source_identity_json"),
                    )
                    if required_merge_id
                    else persist_normalized_event(
                        cur,
                        event=normalized,
                        source_identity=job.get("source_identity_json"),
                    )
                )
                if required_merge_id:
                    record_identity_semantic_replay(
                        cur,
                        merge_id=required_merge_id,
                        source_event_id=normalized.source_event_id,
                        old_normalized_event_ids=old_normalized_ids,
                        new_normalized_event_id=normalized_id,
                        replay_job_id=str(job["job_id"]),
                    )
                if settings.assembly_enabled:
                    actions = assemble_canonical_actions((normalized,))
                    if required_merge_id:
                        persist_canonical_actions(
                            cur,
                            actions=actions,
                            normalizer_version=normalizer_version,
                        )
                    else:
                        persist_canonical_actions(cur, actions=actions)
                    persisted_actions = len(actions)
                if settings.correlation_enabled and not recovery_digest:
                    enqueue_dispatch_jobs(
                        cur,
                        normalized_event_id=normalized_id,
                        allowed_rule_identities=allowed_rule_identities,
                    )
                complete_semantic_job(
                    cur,
                    job_id=str(job["job_id"]),
                    lease_token=str(job["lease_token"]),
                )
            normalized_count += 1
            action_count += persisted_actions
            completed += 1
        except Exception as exc:
            with conn.transaction(), conn.cursor() as cur:
                fail_semantic_job(
                    cur,
                    job_id=str(job["job_id"]),
                    lease_token=str(job["lease_token"]),
                    attempt_count=int(job["attempt_count"]),
                    max_attempts=int(job["max_attempts"]),
                    error_code=type(exc).__name__,
                    error_detail=str(exc),
                )
            failed += 1
    return {
        "completed": completed,
        "failed": failed,
        "normalized": normalized_count,
        "actions": action_count,
        "claimed": claimed_count,
    }


def process_semantic_dispatch(
    conn: Any,
    *,
    archive: Any,
    settings: SemanticFeatureSettings,
    limit: int,
    allowed_rule_ids: Sequence[str] | None = None,
    allowed_rule_identities: Sequence[tuple[str, int, bytes | str]] | None = None,
    allowed_job_ids: Sequence[str] | None = None,
    normalized_before: datetime | None = None,
    claim_jobs: Callable[..., list[dict[str, Any]]] | None = None,
    complete_job: Callable[..., None] | None = None,
) -> dict[str, int]:
    """Run the bounded correlation dispatcher after normalization."""
    if not settings.correlation_enabled:
        return {"completed": 0, "failed": 0, "relations": 0, "claimed": 0}
    requested = max(1, min(int(limit), MAX_SEMANTIC_BATCH))
    completed = failed = relation_count = claimed_count = 0
    claim = claim_jobs or claim_dispatch_jobs
    complete = complete_job or complete_dispatch_job
    for _ in range(requested):
        if shutdown.requested():
            break
        with conn.transaction(), conn.cursor() as cur:
            jobs = claim(
                cur,
                limit=1,
                allowed_rule_ids=allowed_rule_ids,
                allowed_rule_identities=allowed_rule_identities,
                allowed_job_ids=allowed_job_ids,
            )
        if not jobs:
            break
        job = jobs[0]
        claimed_count += 1
        try:
            persisted_relations = 0
            with conn.transaction(), conn.cursor() as cur:
                work = load_dispatch_work_item(
                    cur,
                    job_id=str(job["job_id"]),
                    lease_token=str(job["lease_token"]),
                    archive=archive,
                    normalized_before=normalized_before,
                )
                relations = match_compiled_rule(work.rule, work.events)
                for relation in relations:
                    late_ids = (
                        (work.trigger_source_event_id,)
                        if work.is_late
                        and work.trigger_source_event_id
                        in relation.source_event_ids
                        else ()
                    )
                    persist_dispatched_relation(
                        cur,
                        rule=work.rule,
                        relation=relation,
                        late_source_event_ids=late_ids,
                        evidence_contract=work.evidence_contract,
                    )
                complete(
                    cur,
                    job_id=str(job["job_id"]),
                    lease_token=str(job["lease_token"]),
                )
                persisted_relations = len(relations)
            relation_count += persisted_relations
            completed += 1
        except Exception as exc:
            with conn.transaction(), conn.cursor() as cur:
                fail_dispatch_job(
                    cur,
                    job_id=str(job["job_id"]),
                    lease_token=str(job["lease_token"]),
                    attempt_count=int(job["attempt_count"]),
                    max_attempts=int(job["max_attempts"]),
                    error_code=type(exc).__name__,
                    error_detail=str(exc),
                )
            failed += 1
    return {
        "completed": completed,
        "failed": failed,
        "relations": relation_count,
        "claimed": claimed_count,
    }

"""Split out of ``server.sli.semantic.semantic_investigation_backfill`` (plan 7.2b).

Module-level names of ``semantic_investigation_backfill`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import server.sli.semantic.semantic_investigation_backfill as _src


def read_security_history_v2_repair_rows(
    cur: _src.Any, pairs: _src.Sequence[tuple[int, str]],
) -> list[dict[str, object]]:
    """Read exact repair lineage and normalized proofs without loading source payloads."""
    if not pairs:
        return []
    source_ids = [int(source_id) for source_id, _ in pairs]
    source_hashes = [str(source_hash).casefold() for _, source_hash in pairs]
    cur.execute(
        """
        with selected(source_event_id,source_hash) as (
          select * from unnest(%s::bigint[],%s::text[])
        )
        select selected.source_event_id,selected.source_hash,
               original.original_job_count,original.original_job_id,original.original_status,
               original.original_attempt_count,original.original_max_attempts,
               original.original_error_code,original.original_error_detail,
               original.original_source_hash,
               repair.repair_job_count,repair.repair_status,repair.repair_processor_id,
               repair.repair_processor_version,repair.repair_source_hash,
               repair.repair_payload_source_hash,repair.repair_semantic_contract_version,
               repair.repair_original_job_id,repair.repair_history_plan_digest,
               repair.repair_plan_digest,repair.repair_original_attempt_count,
               repair.repair_original_max_attempts,repair.repair_original_error_code,
               repair.repair_original_error_detail_sha256,
               normalized.normalized_current_count,normalized.normalized_proof_count,
               normalized.normalized_proof_hash,normalized.normalized_action_count
        from selected
        left join lateral (
          select count(job.job_id)::integer as original_job_count,
                 min(job.job_id::text) as original_job_id,min(job.status) as original_status,
                 min(job.attempt_count)::integer as original_attempt_count,
                 min(job.max_attempts)::integer as original_max_attempts,
                 min(job.last_error_code) as original_error_code,
                 min(job.last_error_detail) as original_error_detail,
                 min(job.source_identity_json->>'normalized_hash') as original_source_hash
          from public.semantic_processing_outbox job
          where job.source_event_id=selected.source_event_id and job.job_kind='normalize_event'
            and job.semantic_contract_version=%s and job.processor_id=%s and job.processor_version=%s
        ) original on true
        left join lateral (
          select count(job.job_id)::integer as repair_job_count,
                 min(job.status) as repair_status,min(job.processor_id) as repair_processor_id,
                 min(job.processor_version) as repair_processor_version,
                 min(job.semantic_contract_version)::integer as repair_semantic_contract_version,
                 min(job.source_identity_json->>'normalized_hash') as repair_source_hash,
                 min(job.payload_json->>'original_source_hash') as repair_payload_source_hash,
                 min(job.payload_json->>'original_job_id') as repair_original_job_id,
                 min(job.payload_json->>'history_plan_digest') as repair_history_plan_digest,
                 min(job.payload_json->>'repair_plan_digest') as repair_plan_digest,
                 min(job.payload_json->>'original_attempt_count') as repair_original_attempt_count,
                 min(job.payload_json->>'original_max_attempts') as repair_original_max_attempts,
                 min(job.payload_json->>'original_error_code') as repair_original_error_code,
                 min(job.payload_json->>'original_error_detail_sha256') as repair_original_error_detail_sha256
          from public.semantic_processing_outbox job
          where job.source_event_id=selected.source_event_id
            and job.job_kind='semantic_v2_quarantine_repair'
        ) repair on true
        left join lateral (
          select count(normalized.normalized_event_id)::integer as normalized_current_count,
                 count(normalized.normalized_event_id) filter (
                   where normalized.processing_status='normalized'
                     and normalized.source_event_sha256=decode(selected.source_hash,'hex')
                     and normalized.semantic_type<>'event.unknown'
                 )::integer as normalized_proof_count,
                 min(encode(normalized.source_event_sha256,'hex')) filter (
                   where normalized.processing_status='normalized'
                     and normalized.source_event_sha256=decode(selected.source_hash,'hex')
                     and normalized.semantic_type<>'event.unknown'
                 ) as normalized_proof_hash,
                 count(distinct action_evidence.canonical_action_id) filter (
                   where normalized.processing_status='normalized'
                     and normalized.source_event_sha256=decode(selected.source_hash,'hex')
                     and normalized.semantic_type<>'event.unknown'
                 )::integer as normalized_action_count
          from public.normalized_events normalized
          left join public.canonical_action_evidence action_evidence
            on action_evidence.normalized_event_id=normalized.normalized_event_id
          where normalized.source_event_id=selected.source_event_id
            and normalized.semantic_contract_version=%s and normalized.normalizer_id=%s
            and normalized.normalizer_version=%s
        ) normalized on true
        order by selected.source_event_id
        """,
        (
            source_ids, source_hashes, _src.SEMANTIC_CONTRACT_VERSION, _src.PROCESSOR_ID, _src.PROCESSOR_VERSION,
            _src.SEMANTIC_CONTRACT_VERSION, _src.NORMALIZER_ID, _src.NORMALIZER_VERSION,
        ),
    )
    rows = [dict(row) for row in (cur.fetchall() or [])]
    for row in rows:
        detail = str(row.get("original_error_detail") or "")
        row["original_error_detail_sha256"] = _src.sha256(detail.encode("utf-8")).hexdigest()
    return rows


def classify_security_history_v2_repair_row(
    row: _src.Mapping[str, object], *, source_hash: str, history_plan_digest: str,
    repair_plan_digest: str | None = None,
) -> _src.SecurityHistoryV2RepairState:
    """Classify one selected 4624 context without hiding immutable quarantine.

    The original ``normalize_event`` remains immutable evidence.  It is only
    superseded for this exact source when one v2 repair binds its terminal
    proof and that repair has produced the current normalized proof.
    """
    original_valid = (
        int(row.get("original_job_count") or 0) == 1
        and str(row.get("original_status") or "") == "quarantined"
        and int(row.get("original_attempt_count") or 0) > 0
        and int(row.get("original_attempt_count") or 0) == int(row.get("original_max_attempts") or -1)
        and str(row.get("original_error_code") or "") == "UniqueViolation"
        and '"canonical_actions_pkey"' in str(row.get("original_error_detail") or "")
        and _src._is_lower_sha256(row.get("original_error_detail_sha256"))
        and str(row.get("original_source_hash") or "").casefold() == source_hash
        and bool(str(row.get("original_job_id") or "").strip())
    )
    repair_count = int(row.get("repair_job_count") or 0)
    if repair_count == 0:
        return "absent" if original_valid else "conflict"
    repair_status = str(row.get("repair_status") or "")
    repair_valid = (
        repair_count == 1
        and repair_status in {"queued", "leased", "completed", "failed", "quarantined"}
        and int(row.get("repair_semantic_contract_version") or 0) == _src.SEMANTIC_CONTRACT_VERSION
        and str(row.get("repair_source_hash") or "").casefold() == source_hash
        and str(row.get("repair_payload_source_hash") or "").casefold() == source_hash
        and str(row.get("repair_original_job_id") or "") == str(row.get("original_job_id") or "")
        and str(row.get("repair_history_plan_digest") or "").casefold() == history_plan_digest
        and _src._is_lower_sha256(row.get("repair_plan_digest"))
        and (
            repair_plan_digest is None
            or str(row.get("repair_plan_digest") or "").casefold()
            == repair_plan_digest.casefold()
        )
        and str(row.get("repair_original_error_detail_sha256") or "").casefold()
        == str(row.get("original_error_detail_sha256") or "").casefold()
        and int(row.get("repair_original_attempt_count") or -1) == int(row.get("original_attempt_count") or -2)
        and int(row.get("repair_original_max_attempts") or -1) == int(row.get("original_max_attempts") or -2)
        and str(row.get("repair_original_error_code") or "") == "UniqueViolation"
        and str(row.get("repair_processor_id") or "") == _src.PROCESSOR_ID
        and str(row.get("repair_processor_version") or "") == _src.PROCESSOR_VERSION
    )
    proof_count = int(row.get("normalized_proof_count") or 0)
    proof_valid = (
        int(row.get("normalized_current_count") or 0) == 1
        and proof_count == 1
        and int(row.get("normalized_action_count") or 0) == 1
        and str(row.get("normalized_proof_hash") or "").casefold() == source_hash
    )
    if not original_valid or not repair_valid:
        return "conflict"
    if repair_status == "completed":
        return "completed" if proof_valid else "conflict"
    if int(row.get("normalized_current_count") or 0):
        return "conflict"
    return repair_status  # type: ignore[return-value]


def reconcile_security_history_v2_context_event(
    cur: _src.Any, *, high_watermark: int, reset_high_watermark: int, history_plan_digest: str,
) -> _src.SecurityHistoryV2ContextReconciliation:
    """Reconcile the frozen v2 4624 context against its exact repair lineage.

    This intentionally does not reinterpret a quarantined original as success.
    Each source is accepted only through one matching v2 repair and one current
    normalized proof; all malformed or ambiguous lineages remain ``conflict``.
    ``normalized_events`` has no durable repair-job foreign key, so the
    completed-repair plus current-proof conclusion is an inference from the
    worker's one-transaction ordering, not a per-row causal database link.
    """
    pairs = list(_src._iter_security_history_context_pairs(
        cur, after_id=0, high_watermark=high_watermark,
        reset_high_watermark=reset_high_watermark,
    ))
    current = _src.reconcile_security_history_context_event(
        cur, high_watermark=high_watermark, reset_high_watermark=reset_high_watermark,
    )
    source_ids = [int(source_id) for source_id, _source_hash in pairs]
    states = {state: 0 for state in _src.SECURITY_HISTORY_V2_REPAIR_STATES}
    if not pairs:
        return _src.SecurityHistoryV2ContextReconciliation(current=current, repair_states=states)
    rows = _src.read_security_history_v2_repair_rows(cur, pairs)
    if len(rows) != len(pairs) or {int(row.get("source_event_id") or 0) for row in rows} != set(source_ids):
        raise RuntimeError("security history v2 repair reconciliation is incomplete")
    for row in rows:
        detail = str(row.get("original_error_detail") or "")
        row["original_error_detail_sha256"] = _src.sha256(detail.encode("utf-8")).hexdigest()
        state = _src.classify_security_history_v2_repair_row(
            row,
            source_hash=str(row["source_hash"]).casefold(),
            history_plan_digest=history_plan_digest.casefold(),
        )
        states[state] += 1
    if sum(states.values()) != len(pairs):
        raise RuntimeError("security history v2 repair reconciliation state is invalid")
    return _src.SecurityHistoryV2ContextReconciliation(current=current, repair_states=states)

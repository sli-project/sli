# ruff: noqa: F401 -- re-export hub (plan 7.2b): split-out modules read these
# names through ``semantic_investigation_backfill`` at call time.
"""Controlled historical dispatch for accepted investigation relations.

This module never reads collectors or remote sources.  The facts selector reads
only retained ``events_v2_core`` rows for the exact accepted rule inputs; the
relations selector then fans the matching exact normalized version into the
existing correlation queue.  Rules stay in SHADOW, so no finding is implied.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Literal, Mapping, Sequence
from uuid import UUID

from server.sli.semantic.semantic_chain_pack import (
    DEFAULT_PACK_PATH,
    load_dispatch_rule_pack,
)
from server.sli.semantic.semantic_correlation_repository import (
    CorrelationRuleDefinition,
    register_correlation_rule,
    transition_correlation_rule,
)
from server.sli.semantic.semantic_dispatch import compile_correlation_rule
from server.sli.semantic.semantic_dispatch_repository import (
    enqueue_dispatch_jobs,
    replace_rule_subscriptions,
)
from server.sli.semantic.semantic_identity import is_exact_domain_sid
from server.sli.semantic.semantic_processing import (
    ASSEMBLER_ID,
    ASSEMBLER_VERSION,
    NORMALIZER_ID,
    NORMALIZER_VERSION,
    SEMANTIC_CONTRACT_VERSION,
)
from server.sli.semantic.semantic_processing_repository import (
    PROCESSOR_ID,
    PROCESSOR_VERSION,
)
from server.sli.semantic.semantic_producer import MAX_PRODUCER_BATCH
from server.source_packs.windows_ad_dc import (
    SECURITY_RELATION_ANCHOR_EVENT_IDS,
    SECURITY_RELATION_CONTEXT_EVENT_IDS,
    SECURITY_RELATION_EVENT_IDS_BY_SEMANTIC_TYPE,
    security_audit_outcome,
)

INVESTIGATION_RULE_IDS = (
    "investigation.account.lockout.preceded-by-failures",
    "investigation.account.unlock.after-lock",
    "investigation.group.membership.removed-after-add",
    "investigation.account.created-then-group-add",
    "investigation.password.reset-then-logon",
)
INVESTIGATION_SOURCE_WINDOWS_EVENT_IDS = SECURITY_RELATION_ANCHOR_EVENT_IDS
INVESTIGATION_CONTEXT_WINDOWS_EVENT_IDS = SECURITY_RELATION_CONTEXT_EVENT_IDS
INVESTIGATION_PASSWORD_RESET_WINDOWS_EVENT_ID = (
    SECURITY_RELATION_EVENT_IDS_BY_SEMANTIC_TYPE["account.password.reset.succeeded"][0]
)
BACKFILL_BATCH_MAX = 100
QUARANTINE_RECOVERY_MAX = 1024
QUARANTINE_RECOVERY_ERROR_CODE = "InsufficientPrivilege"
QUARANTINE_RECOVERY_DETAIL_PATTERN = "%semantic_correlation_rules%"
FACTS_PHASE_ANCHORS = "anchors"
FACTS_PHASE_CONTEXT = "context"

# This is deliberately independent from the five relation-input sets above.
# Every member is retained as a versioned fact; only the existing rules may
# later consume their already-defined inputs.
SECURITY_HISTORY_EVENT_IDS = (
    4740, 4767, 4723, 4724, 4720, 4722, 4725, 4726, 4738, 4781,
    4728, 4729, 4732, 4733, 4756, 4757,
    4727, 4730, 4737, 4731, 4734, 4735, 4754, 4755, 4758, 4764,
    4624, 4625, 4771, 4776, 4719, 1102,
)
SECURITY_HISTORY_MANIFEST_TYPE_V1 = "retained_security_events_vocabulary_v1"
# Keep the old public name while v1 checkpoints are still repairable.  New
# superseding checkpoints use the explicit v2 constructor below.
SECURITY_HISTORY_MANIFEST_TYPE = SECURITY_HISTORY_MANIFEST_TYPE_V1
SECURITY_HISTORY_MANIFEST_TYPE_V2 = "retained_security_events_vocabulary_v2"
SECURITY_HISTORY_SUPERSEDE_REASON = "routine_logons_are_exact_context_only"
# Historical report vocabulary is independently bounded by the existing
# producer's maximum.  Relation backfill keeps its narrower 100-row bound.
SECURITY_HISTORY_BATCH_MAX = MAX_PRODUCER_BATCH
SECURITY_HISTORY_LOCK_NAME = "semantic_retained_security_history_vocabulary_controller"
SECURITY_HISTORY_COHORT_FETCH_SIZE = 256
SECURITY_HISTORY_PROGRESS_STATES = frozenset({"planned", "publishing", "queued", "processing"})
SECURITY_HISTORY_EXCEPTION_STATES = frozenset({
    "incomplete_original", "incomplete_normalization", "blocked", "failed", "quarantined",
})
SECURITY_HISTORY_TERMINAL_STATES = frozenset({
    "no_retained_events", "complete",
})
SECURITY_HISTORY_STATES = (
    SECURITY_HISTORY_PROGRESS_STATES
    | SECURITY_HISTORY_TERMINAL_STATES
    | SECURITY_HISTORY_EXCEPTION_STATES
)
SECURITY_HISTORY_EXACT_STATE_REASONS = {
    "no_retained_events": "no_retained_events",
    "complete": "current_version_normalized_hash_reconciled",
    "incomplete_original": "frozen_original_integrity_mismatch",
    "incomplete_normalization": "current_version_non_unknown_normalization_missing",
    "blocked": "operator_blocked_after_evidence",
    "failed": "failed_current_version_work",
    "quarantined": "quarantined_current_version_work",
}
SECURITY_HISTORY_V2_REPAIR_STATES = (
    "absent", "queued", "leased", "completed", "failed", "quarantined", "conflict",
)
SecurityHistoryV2RepairState = Literal[
    "absent", "queued", "leased", "completed", "failed", "quarantined", "conflict",
]


@dataclass(frozen=True)
class SecurityHistoryV2ContextReconciliation:
    """Current 4624 proof plus the append-only repair state for each selected row."""

    current: Mapping[str, int]
    repair_states: Mapping[SecurityHistoryV2RepairState, int]


def security_history_provider(event_id: int) -> str:
    """Return the frozen exact provider for one retained Security ID."""
    if int(event_id) not in SECURITY_HISTORY_EVENT_IDS:
        raise ValueError("security history event ID is outside the retained vocabulary")
    if int(event_id) == 1102:
        return "Microsoft-Windows-Eventlog"
    return "Microsoft-Windows-Security-Auditing"


def security_history_predicate(event_id: int) -> dict[str, object]:
    return {
        "channel": "Security",
        "provider": security_history_provider(event_id),
        "event_id": int(event_id),
    }


def _history_hash_text(value: object) -> str:
    if isinstance(value, memoryview):
        value = value.tobytes()
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).hex()
    text = str(value or "").casefold()
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise ValueError("security history normalized hash is invalid")
    return text


def security_history_cohort_digest(
    pairs: Sequence[tuple[int, object]],
) -> str:
    """Canonical streaming identity for one ordered, frozen retained cohort."""
    digest = sha256()
    previous = -1
    for source_event_id, normalized_hash in pairs:
        source_id = int(source_event_id)
        if source_id <= previous:
            raise ValueError("security history cohort pairs must be strictly ordered")
        previous = source_id
        digest.update(str(source_id).encode("ascii"))
        digest.update(b":")
        digest.update(_history_hash_text(normalized_hash).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def security_history_selection_fingerprint(
    *, batch_limit: int = SECURITY_HISTORY_BATCH_MAX,
) -> str:
    selected_limit = int(batch_limit)
    if not 1 <= selected_limit <= MAX_PRODUCER_BATCH:
        raise ValueError("security history batch limit is invalid")
    material = {
        "source": "events_v2_core",
        "runtime_mode": "investigation-v1",
        "semantic_contract_version": SEMANTIC_CONTRACT_VERSION,
        "normalizer": {"id": NORMALIZER_ID, "version": NORMALIZER_VERSION},
        "assembler": {"id": ASSEMBLER_ID, "version": ASSEMBLER_VERSION},
        "vocabulary": list(SECURITY_HISTORY_EVENT_IDS),
        "batch_limit": selected_limit,
        "moves_collection_cursors": False,
        "contacts_sources": False,
    }
    return sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def security_history_v2_selection_fingerprint(
    *, batch_limit: int = SECURITY_HISTORY_BATCH_MAX,
) -> str:
    """Identify the v2 policy that retains raw 4624 but normalizes only context."""
    material = {
        "v1_selection_fingerprint": security_history_selection_fingerprint(
            batch_limit=batch_limit,
        ),
        "manifest_type": SECURITY_HISTORY_MANIFEST_TYPE_V2,
        "logon_semantic_scope": "successful_password_reset_same_domain_sid_within_1h",
    }
    return sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()






def new_security_history_manifest_v1(
    *, database_identity: Mapping[str, str], plan_digest: str,
    cohorts: Mapping[int, Mapping[str, object]],
    batch_limit: int = SECURITY_HISTORY_BATCH_MAX,
) -> dict[str, object]:
    """Name the legacy constructor when a v1 checkpoint is being superseded."""
    return new_security_history_manifest(
        database_identity=database_identity,
        plan_digest=plan_digest,
        cohorts=cohorts,
        batch_limit=batch_limit,
    )




def select_security_history_targets(
    cur: Any, *, event_id: int, after_id: int, high_watermark: int,
    limit: int = SECURITY_HISTORY_BATCH_MAX,
) -> tuple[int, ...]:
    """Select one exact provider-bound cohort chunk and nothing outside its HWM."""
    requested = max(1, min(int(limit), MAX_PRODUCER_BATCH))
    predicate = security_history_predicate(event_id)
    cur.execute(
        """
        select core.id
        from events_v2_core core
        join storage_v2_channel channel on channel.id=core.channel_id
        join storage_v2_provider provider on provider.id=core.provider_id
        where channel.value='Security'
          and provider.value=%s
          and core.event_id=%s
          and core.id>%s and core.id<=%s
          and not exists (
              select 1 from normalized_events normalized
              where normalized.source_event_id=core.id
                and normalized.semantic_contract_version=%s
                and normalized.normalizer_id=%s and normalized.normalizer_version=%s
                and normalized.processing_status='normalized'
                and normalized.source_event_sha256=core.normalized_hash
                and normalized.semantic_type<>'event.unknown'
          )
        order by core.id
        limit %s
        """,
        (
            predicate["provider"], int(event_id), int(after_id), int(high_watermark),
            SEMANTIC_CONTRACT_VERSION, NORMALIZER_ID, NORMALIZER_VERSION, requested,
        ),
    )
    return tuple(int(row["id"]) for row in (cur.fetchall() or ()))


def _execute_security_history_context_candidates(
    cur: Any, *, after_id: int, high_watermark: int, reset_high_watermark: int,
    exclude_current_normalized: bool = False,
) -> None:
    """Select candidate evidence; Python applies the canonical audit outcome."""
    reset_ids = list(SECURITY_RELATION_EVENT_IDS_BY_SEMANTIC_TYPE[
        "account.password.reset.succeeded"
    ])
    normalized_clause = """
          and not exists (
            select 1 from normalized_events normalized
            where normalized.source_event_id=login.id
              and normalized.semantic_contract_version=%s
              and normalized.normalizer_id=%s and normalized.normalizer_version=%s
              and normalized.processing_status='normalized'
              and normalized.source_event_sha256=login.normalized_hash
              and normalized.semantic_type<>'event.unknown'
          )
    """ if exclude_current_normalized else ""
    parameters: list[object] = [
        "Security", "Microsoft-Windows-Security-Auditing", reset_ids,
        int(reset_high_watermark), "Security", "Microsoft-Windows-Security-Auditing",
        int(after_id), int(high_watermark),
    ]
    if exclude_current_normalized:
        parameters.extend((SEMANTIC_CONTRACT_VERSION, NORMALIZER_ID, NORMALIZER_VERSION))
    cur.execute(
        f"""
        select login.id as source_event_id,
               encode(login.normalized_hash,'hex') as normalized_hash,
               login.target_user_sid as login_target_user_sid,
               reset_event.target_user_sid as reset_target_user_sid,
               reset_keywords.value as reset_keywords
        from events_v2_core login
        join storage_v2_channel login_channel
          on login_channel.id=login.channel_id and login_channel.value=%s
        join storage_v2_provider login_provider
          on login_provider.id=login.provider_id and login_provider.value=%s
        join events_v2_core reset_event
          on reset_event.domain_id=login.domain_id
         and lower(nullif(btrim(reset_event.target_user_sid),''))=
             lower(nullif(btrim(login.target_user_sid),''))
         and reset_event.event_id=any(%s) and reset_event.id<=%s
         and login.time_created_utc>reset_event.time_created_utc
         and login.time_created_utc<=reset_event.time_created_utc+interval '1 hour'
        join storage_v2_channel reset_channel
          on reset_channel.id=reset_event.channel_id and reset_channel.value=%s
        join storage_v2_provider reset_provider
          on reset_provider.id=reset_event.provider_id and reset_provider.value=%s
        left join storage_v2_keywords reset_keywords
          on reset_keywords.id=reset_event.keywords_id
        where login.event_id=4624 and login.id>%s and login.id<=%s
          {normalized_clause}
        order by login.id,reset_event.time_created_utc,reset_event.id
        """,
        tuple(parameters),
    )


def _iter_security_history_context_pairs(
    cur: Any, *, after_id: int, high_watermark: int, reset_high_watermark: int,
    exclude_current_normalized: bool = False,
):
    """Yield exact context pairs in bounded pages using the publisher's outcome rule."""
    _execute_security_history_context_candidates(
        cur, after_id=after_id, high_watermark=high_watermark,
        reset_high_watermark=reset_high_watermark,
        exclude_current_normalized=exclude_current_normalized,
    )
    previous_id = -1
    selected_hash: str | None = None
    selected = False
    while page := cur.fetchmany(SECURITY_HISTORY_COHORT_FETCH_SIZE):
        for raw_row in page:
            row = dict(raw_row)
            source_event_id = int(row["source_event_id"])
            normalized_hash = _history_hash_text(row["normalized_hash"])
            if source_event_id < previous_id:
                raise RuntimeError("security history context cohort order is invalid")
            if source_event_id != previous_id:
                if selected_hash is not None and selected:
                    yield previous_id, selected_hash
                previous_id = source_event_id
                selected_hash = normalized_hash
                selected = False
            if (
                is_exact_domain_sid(row.get("login_target_user_sid"))
                and row.get("login_target_user_sid") == row.get("reset_target_user_sid")
                and security_audit_outcome(row.get("reset_keywords")) == "success"
            ):
                selected = True
    if selected_hash is not None and selected:
        yield previous_id, selected_hash


def _security_history_context_rows(
    cur: Any, *, after_id: int, high_watermark: int,
    reset_high_watermark: int, limit: int | None,
) -> tuple[tuple[int, str], ...]:
    """Bounded result page after canonical success filtering, never before it."""
    selected: list[tuple[int, str]] = []
    for pair in _iter_security_history_context_pairs(
        cur, after_id=after_id, high_watermark=high_watermark,
        reset_high_watermark=reset_high_watermark,
        exclude_current_normalized=True,
    ):
        selected.append(pair)
        if limit is not None and len(selected) >= max(1, min(int(limit), MAX_PRODUCER_BATCH)):
            break
    return tuple(selected)


def select_security_history_context_targets(
    cur: Any, *, after_id: int, high_watermark: int, reset_high_watermark: int,
    limit: int = SECURITY_HISTORY_BATCH_MAX,
) -> tuple[int, ...]:
    """Select only exact successful-reset 4624 context, never routine logons."""
    pairs = _security_history_context_rows(
        cur, after_id=after_id, high_watermark=high_watermark,
        reset_high_watermark=reset_high_watermark, limit=limit,
    )
    return tuple(sorted({source_event_id for source_event_id, _ in pairs}))


def security_history_context_cohort(
    cur: Any, *, high_watermark: int, reset_high_watermark: int,
) -> dict[str, object]:
    """Freeze the eligible 4624 context cohort separately from retained coverage."""
    count = 0
    digest = sha256()
    for source_event_id, normalized_hash in _iter_security_history_context_pairs(
        cur, after_id=0, high_watermark=high_watermark,
        reset_high_watermark=reset_high_watermark,
    ):
        digest.update(str(source_event_id).encode("ascii"))
        digest.update(b":")
        digest.update(normalized_hash.encode("ascii"))
        digest.update(b"\n")
        count += 1
    return {
        "count": count,
        "cohort_digest": digest.hexdigest(),
        "reset_high_watermark": int(reset_high_watermark),
    }








def reconcile_security_history_event(
    cur: Any, *, event_id: int, high_watermark: int,
) -> dict[str, int]:
    """Compare one frozen source cohort with current normalized/outbox evidence."""
    predicate = security_history_predicate(event_id)
    cur.execute(
        """
        select
          count(distinct core.id)::integer as retained_count,
          count(distinct normalized.normalized_event_id) filter (
            where normalized.processing_status='normalized'
              and normalized.source_event_sha256=core.normalized_hash
              and normalized.semantic_type<>'event.unknown'
          )::integer as normalized_count,
          count(distinct normalized.normalized_event_id) filter (
            where normalized.processing_status='failed'
          )::integer as normalization_failed,
          count(distinct normalized.normalized_event_id) filter (
            where normalized.processing_status='quarantined'
          )::integer as normalization_quarantined,
          count(distinct outbox.job_id) filter (where outbox.status='queued')::integer as outbox_queued,
          count(distinct outbox.job_id) filter (where outbox.status='leased')::integer as outbox_leased,
          count(distinct outbox.job_id) filter (where outbox.status='completed')::integer as outbox_completed,
          count(distinct outbox.job_id) filter (where outbox.status='failed')::integer as outbox_failed,
          count(distinct outbox.job_id) filter (where outbox.status='quarantined')::integer as outbox_quarantined,
          count(distinct action_evidence.normalized_event_id)::integer as action_evidence_count
        from events_v2_core core
        join storage_v2_channel channel on channel.id=core.channel_id
        join storage_v2_provider provider on provider.id=core.provider_id
        left join normalized_events normalized
          on normalized.source_event_id=core.id
         and normalized.semantic_contract_version=%s
         and normalized.normalizer_id=%s and normalized.normalizer_version=%s
        left join semantic_processing_outbox outbox
          on outbox.source_event_id=core.id
         and outbox.job_kind in ('normalize_event','semantic_repair')
         and outbox.semantic_contract_version=%s
         and outbox.processor_id=%s and outbox.processor_version=%s
        left join canonical_action_evidence action_evidence
          on action_evidence.normalized_event_id=normalized.normalized_event_id
        where channel.value='Security' and provider.value=%s and core.event_id=%s
          and core.id<=%s
        """,
        (
            SEMANTIC_CONTRACT_VERSION, NORMALIZER_ID, NORMALIZER_VERSION,
            SEMANTIC_CONTRACT_VERSION, PROCESSOR_ID, PROCESSOR_VERSION,
            predicate["provider"], int(event_id), int(high_watermark),
        ),
    )
    row = {key: int(value or 0) for key, value in dict(cur.fetchone() or {}).items()}
    expected = {
        "retained_count", "normalized_count", "normalization_failed", "normalization_quarantined",
        "outbox_queued", "outbox_leased", "outbox_completed", "outbox_failed",
        "outbox_quarantined", "action_evidence_count",
    }
    if set(row) != expected:
        raise RuntimeError("security history reconciliation row is invalid")
    return row


def reconcile_security_history_context_event(
    cur: Any, *, high_watermark: int, reset_high_watermark: int,
) -> dict[str, int]:
    """Reconcile only the frozen successful-reset 4624 context cohort.

    The retained 4624 count is intentionally *not* the semantic work count;
    raw coverage is verified separately by ``security_history_cohorts``.
    """
    expected = {
        "retained_count", "normalized_count", "normalization_failed", "normalization_quarantined",
        "outbox_queued", "outbox_leased", "outbox_completed", "outbox_failed",
        "outbox_quarantined", "action_evidence_count",
    }
    totals = {field: 0 for field in expected}
    # Finish this cursor's streaming result before issuing aggregate queries on
    # it; psycopg replaces an active result set when ``execute`` is called.
    selected_ids = [source_event_id for source_event_id, _normalized_hash in _iter_security_history_context_pairs(
        cur, after_id=0, high_watermark=high_watermark,
        reset_high_watermark=reset_high_watermark,
    )]
    for offset in range(0, len(selected_ids), MAX_PRODUCER_BATCH):
        _accumulate_security_history_context_reconciliation(
            cur, selected_ids[offset:offset + MAX_PRODUCER_BATCH], totals,
        )
    return totals


def _accumulate_security_history_context_reconciliation(
    cur: Any, source_event_ids: Sequence[int], totals: dict[str, int],
) -> None:
    """Aggregate a bounded, canonically-selected context page."""
    cur.execute(
        """
        select
          count(distinct core.id)::integer as retained_count,
          count(distinct normalized.normalized_event_id) filter (
            where normalized.processing_status='normalized'
              and normalized.source_event_sha256=core.normalized_hash
              and normalized.semantic_type<>'event.unknown'
          )::integer as normalized_count,
          count(distinct normalized.normalized_event_id) filter (
            where normalized.processing_status='failed'
          )::integer as normalization_failed,
          count(distinct normalized.normalized_event_id) filter (
            where normalized.processing_status='quarantined'
          )::integer as normalization_quarantined,
          count(distinct outbox.job_id) filter (where outbox.status='queued')::integer as outbox_queued,
          count(distinct outbox.job_id) filter (where outbox.status='leased')::integer as outbox_leased,
          count(distinct outbox.job_id) filter (where outbox.status='completed')::integer as outbox_completed,
          count(distinct outbox.job_id) filter (where outbox.status='failed')::integer as outbox_failed,
          count(distinct outbox.job_id) filter (where outbox.status='quarantined')::integer as outbox_quarantined,
          count(distinct action_evidence.normalized_event_id)::integer as action_evidence_count
        from events_v2_core core
        left join normalized_events normalized
          on normalized.source_event_id=core.id
         and normalized.semantic_contract_version=%s
         and normalized.normalizer_id=%s and normalized.normalizer_version=%s
        left join semantic_processing_outbox outbox
          on outbox.source_event_id=core.id
         and outbox.job_kind in ('normalize_event','semantic_repair')
         and outbox.semantic_contract_version=%s
         and outbox.processor_id=%s and outbox.processor_version=%s
        left join canonical_action_evidence action_evidence
          on action_evidence.normalized_event_id=normalized.normalized_event_id
        where core.id=any(%s)
        """,
        (
            SEMANTIC_CONTRACT_VERSION, NORMALIZER_ID, NORMALIZER_VERSION,
            SEMANTIC_CONTRACT_VERSION, PROCESSOR_ID, PROCESSOR_VERSION,
            list(source_event_ids),
        ),
    )
    row = {key: int(value or 0) for key, value in dict(cur.fetchone() or {}).items()}
    expected = {
        "retained_count", "normalized_count", "normalization_failed", "normalization_quarantined",
        "outbox_queued", "outbox_leased", "outbox_completed", "outbox_failed",
        "outbox_quarantined", "action_evidence_count",
    }
    if set(row) != expected:
        raise RuntimeError("security history context reconciliation row is invalid")
    for name, value in row.items():
        totals[name] += value


def _is_lower_sha256(value: object) -> bool:
    rendered = str(value or "")
    return len(rendered) == 64 and all(character in "0123456789abcdef" for character in rendered)








def selected_investigation_rules(
    path: Path = DEFAULT_PACK_PATH,
) -> tuple[CorrelationRuleDefinition, ...]:
    by_id = {rule.rule_id: rule for rule in load_dispatch_rule_pack(path)}
    if set(INVESTIGATION_RULE_IDS) - set(by_id):
        raise RuntimeError("investigation rule pack is incomplete")
    return tuple(by_id[rule_id] for rule_id in INVESTIGATION_RULE_IDS)


def investigation_rule_semantic_types(path: Path = DEFAULT_PACK_PATH) -> tuple[str, ...]:
    return tuple(sorted({
        semantic_type
        for rule in selected_investigation_rules(path)
        for semantic_type in compile_correlation_rule(rule).input_types
    }))


def investigation_source_contract() -> dict[str, list[int]]:
    return {
        semantic_type: [int(event_id) for event_id in event_ids]
        for semantic_type, event_ids in sorted(
            SECURITY_RELATION_EVENT_IDS_BY_SEMANTIC_TYPE.items()
        )
    }


def investigation_rules_fingerprint(path: Path = DEFAULT_PACK_PATH) -> str:
    contract: dict[str, Any] = {"facts_contract": {
        "semantic_contract_version": SEMANTIC_CONTRACT_VERSION,
        "normalizer_id": NORMALIZER_ID,
        "normalizer_version": NORMALIZER_VERSION,
    }, "source_event_ids_by_semantic_type": investigation_source_contract(), "rules": [{
        "rule_id": rule.rule_id,
        "rule_version": rule.rule_version,
        "rule_kind": rule.rule_kind,
        "definition": rule.definition,
    } for rule in selected_investigation_rules(path)]}
    encoded = json.dumps(contract, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256(encoded).hexdigest()


def investigation_rule_identities(path: Path = DEFAULT_PACK_PATH) -> dict[str, dict[str, Any]]:
    return {
        rule.rule_id: {
            "rule_version": rule.rule_version,
            "definition_sha256": compile_correlation_rule(rule).definition_sha256.hex(),
        }
        for rule in selected_investigation_rules(path)
    }


def investigation_rule_identity_tuples(
    path: Path = DEFAULT_PACK_PATH,
) -> tuple[tuple[str, int, bytes], ...]:
    return tuple(
        (
            rule.rule_id,
            int(rule.rule_version),
            compile_correlation_rule(rule).definition_sha256,
        )
        for rule in selected_investigation_rules(path)
    )


def _exact_job_ids(values: Sequence[str] | None) -> list[str] | None:
    if values is None:
        return None
    try:
        selected = sorted({str(UUID(str(value))) for value in values})
    except (TypeError, ValueError, AttributeError) as exc:
        raise ValueError("investigation recovery job IDs are invalid") from exc
    if not selected or len(selected) > QUARANTINE_RECOVERY_MAX:
        raise ValueError("investigation recovery job IDs are invalid")
    return selected


def _recovery_boundary(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        boundary = value
    else:
        try:
            boundary = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("investigation recovery frozen boundary is invalid") from exc
    if boundary.tzinfo is None:
        raise ValueError("investigation recovery frozen boundary is invalid")
    return boundary


def _definition_hex(value: Any) -> str:
    if isinstance(value, memoryview):
        value = value.tobytes()
    if isinstance(value, bytes):
        value = value.hex()
    text = str(value or "").casefold()
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise RuntimeError("investigation recovery rule definition hash is invalid")
    return text










def new_investigation_facts_checkpoint(
    *, high_watermark: int, fingerprint: str, range_start: int = 1,
) -> dict[str, Any]:
    if high_watermark < 0 or range_start < 1 or range_start > high_watermark + 1:
        raise ValueError("investigation facts high watermark is invalid")
    return {
        "checkpoint_type": "retained_semantic_investigation_facts_v1",
        "status": "active",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "source": "events_v2_core",
        "range_start_event_id": int(range_start),
        "frozen_high_watermark_event_id": int(high_watermark),
        "last_committed_event_id": int(range_start) - 1,
        "rules_fingerprint": str(fingerprint),
        "windows_event_ids": list(INVESTIGATION_SOURCE_WINDOWS_EVENT_IDS),
        "context_windows_event_ids": list(INVESTIGATION_CONTEXT_WINDOWS_EVENT_IDS),
        "source_event_ids_by_semantic_type": investigation_source_contract(),
        "phase": FACTS_PHASE_ANCHORS,
        "batch_limit": BACKFILL_BATCH_MAX,
        "moves_collection_cursors": False,
        "contacts_sources": False,
    }










def enqueue_investigation_targets(cur: Any, targets: list[Mapping[str, Any]]) -> tuple[str, ...]:
    jobs: list[str] = []
    for target in targets:
        jobs.extend(enqueue_dispatch_jobs(
            cur,
            normalized_event_id=str(target["normalized_event_id"]),
            allowed_rule_identities=investigation_rule_identity_tuples(),
        ))
    return tuple(dict.fromkeys(jobs))


def _rule_status(cur: Any, rule_id: str, rule_version: int) -> str | None:
    cur.execute(
        "select lifecycle_status from semantic_correlation_rules where rule_id=%s and rule_version=%s",
        (rule_id, int(rule_version)),
    )
    row = dict(cur.fetchone() or {})
    return str(row.get("lifecycle_status") or "") or None


def _verify_rule_subscriptions(cur: Any, rule) -> None:
    cur.execute(
        """
        select semantic_type,subscription_order,definition_sha256
        from semantic_correlation_subscriptions
        where rule_id=%s and rule_version=%s
        order by subscription_order
        """,
        (rule.rule_id, rule.rule_version),
    )
    observed = [dict(row) for row in (cur.fetchall() or [])]
    expected = [{
        "semantic_type": semantic_type,
        "subscription_order": order,
        "definition_sha256": rule.definition_sha256,
    } for order, semantic_type in enumerate(rule.input_types)]
    if observed != expected:
        raise RuntimeError("investigation rule subscriptions differ from accepted definition")






from server.sli.semantic.semantic_investigation_backfill_investigation import (
    activate_investigation_rules,
    new_investigation_checkpoint,
    retire_superseded_investigation_rule_versions,
    select_investigation_fact_targets,
    select_investigation_targets,
    validate_investigation_checkpoint,
    validate_investigation_facts_checkpoint,
)
from server.sli.semantic.semantic_investigation_backfill_manifest import (
    _history_cohort_entry,
    new_security_history_manifest,
    new_security_history_manifest_v2,
    security_history_cohort_mismatches,
    security_history_cohorts,
    validate_security_history_manifest,
)
from server.sli.semantic.semantic_investigation_backfill_quarantine import (
    investigation_quarantine_recovery_candidates,
    investigation_quarantine_recovery_digest,
    recover_investigation_quarantined_dispatch_jobs,
)
from server.sli.semantic.semantic_investigation_backfill_repair_v2 import (
    classify_security_history_v2_repair_row,
    read_security_history_v2_repair_rows,
    reconcile_security_history_v2_context_event,
)

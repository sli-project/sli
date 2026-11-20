"""Bounded pre-queue selection for the dormant semantic pipeline."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from math import ceil
from typing import Any, Mapping, Sequence

from server.sli.events.event_catalog import lookup_semantic_event_descriptor
from server.sli.semantic.semantic_processing_repository import (
    INVESTIGATION_CONTEXT_JOB_KIND,
    PROCESSOR_ID,
    PROCESSOR_VERSION,
    SEMANTIC_CONTRACT_VERSION,
    enqueue_semantic_job,
)
from server.sli.semantic.semantic_identity import is_exact_domain_sid
from server.source_packs.registry import resolve_source_pack
from server.source_packs.windows_ad_dc import (
    SECURITY_EVENTS_EVENTLOG_EVENT_ID,
    SECURITY_EVENTS_REPORT_AUDITING_PROVIDER,
    SECURITY_EVENTS_REPORT_EVENTLOG_PROVIDER,
    SECURITY_EVENTS_REPORT_EXPLICIT_QUERY_EVENT_IDS,
    SECURITY_RELATION_CONTEXT_EVENT_IDS,
    SECURITY_RELATION_EVENT_IDS_BY_SEMANTIC_TYPE,
    security_audit_outcome,
    security_event_report_provider,
)


MAX_PRODUCER_BATCH = 5_000
UNKNOWN_TASK_FRACTION = 0.05
MAX_UNKNOWN_TASKS_PER_BATCH = 32
MAX_CONTEXT_EXPANSION_BATCH = 100


@dataclass(frozen=True)
class SemanticQueueCandidate:
    source_event_id: int
    selection_reason: str


def select_semantic_queue_candidates(
    rows: Sequence[Mapping[str, Any]],
    *,
    include_context: bool = False,
    context_event_ids: Sequence[int] = (),
) -> tuple[tuple[SemanticQueueCandidate, ...], dict[str, int]]:
    """Select signal plus a bounded unknown sample before queue publication."""
    if len(rows) > MAX_PRODUCER_BATCH:
        raise ValueError("semantic producer batch exceeds 5000 events")
    signals: list[SemanticQueueCandidate] = []
    contexts: list[SemanticQueueCandidate] = []
    unknown: list[SemanticQueueCandidate] = []
    counters = {
        "scanned": len(rows),
        "signal_queued": 0,
        "unknown_queued": 0,
        "unknown_suppressed": 0,
        "context_skipped": 0,
        "noise_skipped": 0,
    }
    admitted_context_ids = {int(value) for value in context_event_ids}
    for source in rows:
        row = dict(source)
        source_event_id = int(row.get("source_event_id") or 0)
        if source_event_id <= 0:
            raise ValueError("semantic producer requires positive source_event_id")
        stream = str(row.get("stream") or "")
        provider = str(row.get("provider_name") or "")
        event_key = str(row.get("event_key") or "")
        pack = resolve_source_pack(stream, provider, event_key)
        descriptor = (
            lookup_semantic_event_descriptor(
                pack.pack_id,
                stream,
                event_key,
                provider,
            )
            if pack is not None
            else None
        )
        if descriptor is None and source_event_id in admitted_context_ids:
            contexts.append(
                SemanticQueueCandidate(source_event_id, "related_context")
            )
            continue
        if descriptor is None:
            unknown.append(
                SemanticQueueCandidate(source_event_id, "descriptor_missing")
            )
            continue
        noise_class = str(descriptor.get("noise_class") or "").strip().lower()
        if noise_class == "signal":
            signals.append(SemanticQueueCandidate(source_event_id, "signal"))
        elif noise_class == "context":
            if include_context or source_event_id in admitted_context_ids:
                contexts.append(
                    SemanticQueueCandidate(
                        source_event_id,
                        "explicit_context" if include_context else "related_context",
                    )
                )
            else:
                counters["context_skipped"] += 1
        elif noise_class == "noise":
            counters["noise_skipped"] += 1
        elif source_event_id in admitted_context_ids:
            # A caller that has already proved an exact retained source cohort
            # may opt this row into bounded context publication.  The ordinary
            # path keeps the former unknown-sampling behavior unchanged.
            contexts.append(
                SemanticQueueCandidate(source_event_id, "related_context")
            )
        else:
            unknown.append(
                SemanticQueueCandidate(source_event_id, "noise_class_not_classified")
            )

    unknown_limit = min(
        MAX_UNKNOWN_TASKS_PER_BATCH,
        max(1, ceil(len(rows) * UNKNOWN_TASK_FRACTION)) if rows else 0,
    )
    selected_unknown = unknown[:unknown_limit]
    counters["signal_queued"] = len(signals)
    counters["unknown_queued"] = len(selected_unknown)
    counters["unknown_suppressed"] = len(unknown) - len(selected_unknown)
    selected = tuple(
        sorted(
            (*signals, *contexts, *selected_unknown),
            key=lambda item: item.source_event_id,
        )
    )
    return selected, counters


def publish_semantic_candidates(
    cur: Any,
    event_ids: Sequence[int],
    *,
    include_context: bool = False,
    context_event_ids: Sequence[int] = (),
) -> dict[str, int]:
    """Publish selected identities using the caller's Storage V2 transaction."""
    ordered_ids = sorted({int(value) for value in event_ids})
    if not ordered_ids:
        return {
            "scanned": 0,
            "queued": 0,
            "signal_queued": 0,
            "unknown_queued": 0,
            "unknown_suppressed": 0,
            "context_skipped": 0,
            "noise_skipped": 0,
        }
    if len(ordered_ids) > MAX_PRODUCER_BATCH:
        raise ValueError("semantic producer batch exceeds 5000 events")
    cur.execute(
        """
        select core.id as source_event_id,
               core.event_id::text as event_key,
               channel.value as stream,
               coalesce(provider.value, '') as provider_name
        from events_v2_core core
        join storage_v2_channel channel on channel.id=core.channel_id
        left join storage_v2_provider provider on provider.id=core.provider_id
        where core.id=any(%s)
        order by core.id
        """,
        (ordered_ids,),
    )
    rows = [dict(row) for row in (cur.fetchall() or [])]
    if len(rows) != len(ordered_ids):
        present = {int(row["source_event_id"]) for row in rows}
        missing = sorted(set(ordered_ids) - present)
        raise RuntimeError(f"semantic producer source rows are missing: {missing[:10]}")
    selected, counters = select_semantic_queue_candidates(
        rows,
        include_context=include_context,
        context_event_ids=context_event_ids,
    )
    for candidate in selected:
        enqueue_semantic_job(
            cur,
            source_event_id=candidate.source_event_id,
            payload={"selection_reason": candidate.selection_reason},
        )
    return {**counters, "queued": len(selected)}


def _context_time(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _context_identity(value: Any) -> str | None:
    return value if is_exact_domain_sid(value) else None


def _eligible_investigation_report_source_event_ids(
    rows: Sequence[Mapping[str, Any]],
    *,
    requested_ids: Sequence[int],
) -> tuple[int, ...]:
    """Recheck the source-owned security-report boundary after SQL filtering."""
    requested = {int(value) for value in requested_ids}
    allowed_event_ids = (
        SECURITY_EVENTS_REPORT_EXPLICIT_QUERY_EVENT_IDS
        - set(SECURITY_RELATION_CONTEXT_EVENT_IDS)
    )
    eligible: set[int] = set()
    for source in rows:
        row = dict(source)
        source_event_id = int(row.get("source_event_id") or 0)
        try:
            event_id = int(row.get("event_key"))
        except (TypeError, ValueError):
            continue
        if (
            source_event_id in requested
            and event_id in allowed_event_ids
            and str(row.get("stream") or "") == "Security"
            and str(row.get("provider_name") or "")
            == security_event_report_provider(event_id)
        ):
            eligible.add(source_event_id)
    return tuple(sorted(eligible))


def _investigation_report_source_event_ids(
    cur: Any,
    event_ids: Sequence[int],
) -> tuple[int, ...]:
    """Select only events owned by the unified security-actions report."""
    ordered_ids = sorted({int(value) for value in event_ids})
    if not ordered_ids:
        return ()
    allowed_event_ids = sorted(
        SECURITY_EVENTS_REPORT_EXPLICIT_QUERY_EVENT_IDS
        - set(SECURITY_RELATION_CONTEXT_EVENT_IDS)
    )
    cur.execute(
        """
        select core.id as source_event_id,
               core.event_id::text as event_key,
               channel.value as stream,
               coalesce(provider.value, '') as provider_name
        from events_v2_core core
        join storage_v2_channel channel on channel.id=core.channel_id
        left join storage_v2_provider provider on provider.id=core.provider_id
        where core.id=any(%s)
          and core.event_id=any(%s)
          and channel.value=%s
          and (
              (core.event_id=%s and provider.value=%s)
              or (core.event_id<>%s and provider.value=%s)
          )
        order by core.id
        """,
        (
            ordered_ids,
            allowed_event_ids,
            "Security",
            SECURITY_EVENTS_EVENTLOG_EVENT_ID,
            SECURITY_EVENTS_REPORT_EVENTLOG_PROVIDER,
            SECURITY_EVENTS_EVENTLOG_EVENT_ID,
            SECURITY_EVENTS_REPORT_AUDITING_PROVIDER,
        ),
    )
    return _eligible_investigation_report_source_event_ids(
        cur.fetchall() or [],
        requested_ids=ordered_ids,
    )


def _eligible_investigation_context_ids(
    rows: Sequence[Mapping[str, Any]],
) -> tuple[int, ...]:
    """Recheck the exact relation boundary independently of SQL filtering."""
    eligible: set[int] = set()
    for source in rows:
        row = dict(source)
        login_sid = _context_identity(row.get("login_target_user_sid"))
        reset_sid = _context_identity(row.get("reset_target_user_sid"))
        login_at = _context_time(row.get("login_time_created_utc"))
        reset_at = _context_time(row.get("reset_time_created_utc"))
        if (
            not login_sid
            or login_sid != reset_sid
            or row.get("login_domain_id") != row.get("reset_domain_id")
            or login_at is None
            or reset_at is None
            or login_at <= reset_at
            or login_at > reset_at + timedelta(hours=1)
            or security_audit_outcome(row.get("reset_keywords")) != "success"
        ):
            continue
        source_event_id = int(row.get("source_event_id") or 0)
        if source_event_id > 0:
            eligible.add(source_event_id)
    return tuple(sorted(eligible))


def _investigation_context_event_ids(
    cur: Any,
    event_ids: Sequence[int],
) -> tuple[int, ...]:
    """Select only logons that can follow an exact successful password reset.

    Ordinary successful-logon events are high-volume context, not report
    signals.  The
    direct V2 writer therefore admits one only when retained source evidence
    already proves a same-domain, same-SID successful password reset during
    the preceding hour.  This also works when reset and logon are committed in
    one importer transaction; correlation still performs its own stricter
    semantic checks.
    """
    ordered_ids = sorted({int(value) for value in event_ids})
    if not ordered_ids:
        return ()
    context_ids = list(
        SECURITY_RELATION_EVENT_IDS_BY_SEMANTIC_TYPE[
            "authentication.session.created"
        ]
    )
    reset_ids = list(
        SECURITY_RELATION_EVENT_IDS_BY_SEMANTIC_TYPE[
            "account.password.reset.succeeded"
        ]
    )
    cur.execute(
        """
        select login.id as source_event_id,
               login.domain_id as login_domain_id,
               login.target_user_sid as login_target_user_sid,
               login.time_created_utc as login_time_created_utc,
               reset_event.domain_id as reset_domain_id,
               reset_event.target_user_sid as reset_target_user_sid,
               reset_event.time_created_utc as reset_time_created_utc,
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
         and reset_event.event_id=any(%s)
         and login.time_created_utc>reset_event.time_created_utc
         and login.time_created_utc<=reset_event.time_created_utc+interval '1 hour'
        join storage_v2_channel reset_channel
          on reset_channel.id=reset_event.channel_id and reset_channel.value=%s
        join storage_v2_provider reset_provider
          on reset_provider.id=reset_event.provider_id and reset_provider.value=%s
        left join storage_v2_keywords reset_keywords
          on reset_keywords.id=reset_event.keywords_id
        where login.id=any(%s) and login.event_id=any(%s)
        order by login.id,reset_event.time_created_utc,reset_event.id
        """,
        (
            "Security",
            "Microsoft-Windows-Security-Auditing",
            reset_ids,
            "Security",
            "Microsoft-Windows-Security-Auditing",
            ordered_ids,
            context_ids,
        ),
    )
    return _eligible_investigation_context_ids(cur.fetchall() or [])


def _investigation_context_expansion_anchor_ids(
    cur: Any,
    event_ids: Sequence[int],
) -> tuple[int, ...]:
    ordered_ids = sorted({int(value) for value in event_ids})
    if not ordered_ids:
        return ()
    reset_ids = list(
        SECURITY_RELATION_EVENT_IDS_BY_SEMANTIC_TYPE[
            "account.password.reset.succeeded"
        ]
    )
    cur.execute(
        """
        select candidate.id as source_event_id,keywords.value as keywords
        from events_v2_core candidate
        join storage_v2_channel channel
          on channel.id=candidate.channel_id and channel.value=%s
        join storage_v2_provider provider
          on provider.id=candidate.provider_id and provider.value=%s
        left join storage_v2_keywords keywords on keywords.id=candidate.keywords_id
        where candidate.id=any(%s) and candidate.event_id=any(%s)
        order by candidate.id
        """,
        (
            "Security",
            "Microsoft-Windows-Security-Auditing",
            ordered_ids,
            reset_ids,
        ),
    )
    return tuple(
        int(row["source_event_id"])
        for row in (cur.fetchall() or [])
        if security_audit_outcome(row.get("keywords")) == "success"
    )


def select_investigation_context_expansion_ids(
    cur: Any,
    *,
    reset_source_event_id: int,
    limit: int = MAX_CONTEXT_EXPANSION_BATCH,
) -> tuple[tuple[int, ...], bool]:
    """Return one durable page of retained logons made relevant by a late reset."""
    requested = max(1, min(int(limit), MAX_CONTEXT_EXPANSION_BATCH))
    reset_ids = list(
        SECURITY_RELATION_EVENT_IDS_BY_SEMANTIC_TYPE[
            "account.password.reset.succeeded"
        ]
    )
    context_ids = list(
        SECURITY_RELATION_EVENT_IDS_BY_SEMANTIC_TYPE[
            "authentication.session.created"
        ]
    )
    cur.execute(
        """
        select reset_event.domain_id,reset_event.target_user_sid,
               reset_event.time_created_utc,reset_event.event_id,
               channel.value as channel,provider.value as provider_name,
               keywords.value as keywords
        from events_v2_core reset_event
        join storage_v2_channel channel on channel.id=reset_event.channel_id
        join storage_v2_provider provider on provider.id=reset_event.provider_id
        left join storage_v2_keywords keywords on keywords.id=reset_event.keywords_id
        where reset_event.id=%s
        """,
        (int(reset_source_event_id),),
    )
    reset = dict(cur.fetchone() or {})
    reset_sid = _context_identity(reset.get("target_user_sid"))
    reset_at = _context_time(reset.get("time_created_utc"))
    if (
        int(reset.get("event_id") or 0) not in reset_ids
        or str(reset.get("channel") or "") != "Security"
        or str(reset.get("provider_name") or "")
        != "Microsoft-Windows-Security-Auditing"
        or security_audit_outcome(reset.get("keywords")) != "success"
        or reset.get("domain_id") is None
        or not reset_sid
        or reset_at is None
    ):
        return (), False
    cur.execute(
        """
        select login.id as source_event_id,login.target_user_sid as login_target_user_sid
        from events_v2_core login
        join storage_v2_channel channel
          on channel.id=login.channel_id and channel.value=%s
        join storage_v2_provider provider
          on provider.id=login.provider_id and provider.value=%s
        where login.domain_id=%s
          and login.target_user_sid=%s
          and login.event_id=any(%s)
          and login.time_created_utc>%s
          and login.time_created_utc<=%s+interval '1 hour'
          and not exists(
            select 1 from semantic_processing_outbox job
            where job.source_event_id=login.id and job.job_kind='normalize_event'
              and job.semantic_contract_version=%s
              and job.processor_id=%s and job.processor_version=%s
          )
        order by login.id
        limit %s
        """,
        (
            "Security",
            "Microsoft-Windows-Security-Auditing",
            int(reset["domain_id"]),
            reset_sid,
            context_ids,
            reset_at,
            reset_at,
            SEMANTIC_CONTRACT_VERSION,
            PROCESSOR_ID,
            PROCESSOR_VERSION,
            requested + 1,
        ),
    )
    rows = [
        int(row["source_event_id"])
        for row in (cur.fetchall() or [])
        if _context_identity(row.get("login_target_user_sid")) == reset_sid
    ]
    return tuple(rows[:requested]), len(rows) > requested


def publish_investigation_candidates(
    cur: Any,
    event_ids: Sequence[int],
) -> dict[str, int]:
    """Publish report-owned events plus relation-relevant authentication context.

    A late password-reset observation can make retained logons relevant.  A
    durable expansion job pages those logons later, outside the caller's V2
    transaction, so event arrival order cannot suppress the supported relation
    or create an unbounded collection transaction.
    """
    ordered_ids = sorted({int(value) for value in event_ids})
    if len(ordered_ids) > MAX_PRODUCER_BATCH:
        raise ValueError("semantic producer batch exceeds 5000 events")
    report_event_ids = _investigation_report_source_event_ids(cur, ordered_ids)
    related_context = _investigation_context_event_ids(cur, ordered_ids)
    for source_event_id in report_event_ids:
        enqueue_semantic_job(
            cur,
            source_event_id=source_event_id,
            payload={"selection_reason": "signal"},
        )
    report_ids = set(report_event_ids)
    context_only_ids = tuple(
        source_event_id
        for source_event_id in related_context
        if source_event_id not in report_ids
    )
    for source_event_id in context_only_ids:
        enqueue_semantic_job(
            cur,
            source_event_id=source_event_id,
            payload={"selection_reason": "related_context"},
        )
    admitted_ids = report_ids | set(context_only_ids)
    totals = {
        "scanned": len(ordered_ids),
        "queued": len(admitted_ids),
        "signal_queued": len(report_event_ids),
        "unknown_queued": 0,
        "unknown_suppressed": 0,
        "context_skipped": 0,
        "noise_skipped": len(set(ordered_ids) - admitted_ids),
    }
    expansion_anchors = _investigation_context_expansion_anchor_ids(
        cur, ordered_ids,
    )
    for source_event_id in expansion_anchors:
        enqueue_semantic_job(
            cur,
            source_event_id=source_event_id,
            job_kind=INVESTIGATION_CONTEXT_JOB_KIND,
            payload={"selection_reason": "late_context_expansion"},
        )
    totals["queued"] += len(expansion_anchors)
    return totals

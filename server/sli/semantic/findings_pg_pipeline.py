from __future__ import annotations

import json
import os
from collections import defaultdict
from datetime import datetime, timezone
from time import monotonic
from typing import Any, Callable, Mapping

from server.sli.storage.runtime_storage import StorageRouteConsumer, resolve_storage_route
from server.sli.storage.storage_v2_transition_controller import CutoverAuthorization

PIPELINE_NAME = "events_to_findings_v1"
DEFAULT_BATCH_LIMIT = 5000
MAX_BATCH_LIMIT = 20000
AUTO_REPEATABLE_STATUSES = frozenset({"new", "active", "repeated"})
MANUAL_PRESERVED_STATUSES = frozenset({"review", "confirmed", "false_positive", "closed"})
V2_FINDINGS_EVIDENCE_UNAVAILABLE = "storage_v2_findings_evidence_adapter_unavailable"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _clean_limit(limit: int | None) -> int:
    if limit is None:
        try:
            limit = int(os.getenv("ADLOG_FINDINGS_BATCH_SIZE", str(DEFAULT_BATCH_LIMIT)))
        except (TypeError, ValueError):
            limit = DEFAULT_BATCH_LIMIT
    return max(1, min(int(limit), MAX_BATCH_LIMIT))


def _json_payload(rows: list[dict[str, Any]]) -> str:
    return json.dumps(rows, ensure_ascii=False, default=str)


def _v2_findings_route_selected(
    authorization: CutoverAuthorization | None,
) -> bool:
    """Storage V2 is the only route (plan 6.5); this still rejects a bad authority."""
    resolve_storage_route(authorization=authorization, consumer=StorageRouteConsumer.FINDINGS)
    return True


def _findings_event_relation(
    authorization: object | None,
) -> str:
    _v2_findings_route_selected(authorization)
    return "events_v2_core"


def _v2_findings_evidence_unavailable() -> dict[str, Any]:
    return {
        "status": "unavailable",
        "backend": "storage_v2",
        "pipeline": PIPELINE_NAME,
        "reason": V2_FINDINGS_EVIDENCE_UNAVAILABLE,
        "limitations": [
            "Legacy Findings refresh is disabled for the Storage V2 route; no V2 findings evidence adapter is available."
        ],
        "generated_at_utc": _utc_now(),
    }


def ensure_findings_pg_schema(
    *,
    bootstrap_to_current: bool = False,
    authorization: CutoverAuthorization | None = None,
) -> dict[str, Any]:
    """Verify Findings schema and initialize only its durable watermark row.

    On the first runtime start after deployment, ``bootstrap_to_current=True`` seeds
    the watermark to the current maximum event id.  This deliberately avoids an
    implicit historical backfill.  Subsequent current cycles are processed
    incrementally.  A missing state row discovered outside startup is seeded to 0
    so events are never silently skipped.
    """
    from server.sli.core.postgres_runtime_pipeline import connect
    from server.sli.ops.postgres_schema_guard import require_table_columns

    event_relation = _findings_event_relation(authorization)

    require_table_columns(
        "findings_refresh_state",
        (
            "pipeline_name", "last_event_id", "bootstrap_event_id", "last_status",
            "last_started_at", "last_completed_at", "last_failed_at", "last_duration_ms",
            "last_scanned_events", "last_matched_events", "last_created_findings",
            "last_updated_findings", "last_evidence_added", "last_manual_status_preserved",
            "last_has_more", "last_error", "updated_at",
        ),
    )
    require_table_columns("findings", ("id", "last_repeat_detected_at"))

    with connect() as conn:
        with conn.cursor() as cur:
            if bootstrap_to_current:
                cur.execute(
                    f"""
                    insert into findings_refresh_state(
                        pipeline_name, last_event_id, bootstrap_event_id, last_status, updated_at
                    )
                    select %s, coalesce(max(id), 0), coalesce(max(id), 0), 'ready', now()
                    from {event_relation}
                    on conflict (pipeline_name) do nothing
                    """,
                    (PIPELINE_NAME,),
                )
                cur.execute(
                    f"""
                    update findings_refresh_state
                    set last_event_id=seed.max_event_id,
                        bootstrap_event_id=seed.max_event_id,
                        updated_at=now()
                    from (select coalesce(max(id),0) as max_event_id from {event_relation}) seed
                    where pipeline_name=%s
                      and last_event_id=0
                      and bootstrap_event_id=0
                      and last_completed_at is null
                      and last_failed_at is null
                    """,
                    (PIPELINE_NAME,),
                )
            else:
                cur.execute(
                    """
                    insert into findings_refresh_state(
                        pipeline_name, last_event_id, bootstrap_event_id, last_status, updated_at
                    ) values (%s, 0, 0, 'ready', now())
                    on conflict (pipeline_name) do nothing
                    """,
                    (PIPELINE_NAME,),
                )
            cur.execute(
                """
                select pipeline_name, last_event_id, bootstrap_event_id, last_status,
                       last_completed_at, last_failed_at, last_error
                from findings_refresh_state where pipeline_name=%s
                """,
                (PIPELINE_NAME,),
            )
            row = cur.fetchone()
            return dict(row or {})


def _event_candidate(
    row: Mapping[str, Any],
    *,
    rules: Mapping[int, tuple[str, str, str, str]],
    event_label: Callable[[Any], str],
    principal: Callable[[Any, Any], str | None],
    recommendation: Callable[[str], str],
) -> dict[str, Any] | None:
    try:
        numeric_event_id = int(row.get("event_id"))
    except (TypeError, ValueError):
        return None
    rule = rules.get(numeric_event_id)
    if rule is None:
        return None
    rule_code, title, severity, why = rule
    target = (
        principal(row.get("target_domain_name"), row.get("target_user_name"))
        or principal(row.get("subject_domain_name"), row.get("subject_user_name"))
        or "unknown"
    )
    actor = principal(row.get("subject_domain_name"), row.get("subject_user_name"))
    source = row.get("ip_address") or row.get("workstation_name") or row.get("computer") or row.get("hostname")
    hostname = str(row.get("hostname") or row.get("computer") or "unknown")
    fingerprint = f"{rule_code}|{target}|{hostname}|{numeric_event_id}"
    event_time = str(row.get("time_created_utc") or "")
    return {
        "event_db_id": int(row["id"]),
        "event_id": numeric_event_id,
        "event_note": event_label(numeric_event_id),
        "event_time": event_time,
        "fingerprint": fingerprint,
        "rule_code": rule_code,
        "title": title,
        "severity": severity,
        "actor": actor,
        "target": target,
        "source": str(source) if source else None,
        "hostname": hostname,
        "summary": f"{title}: {target} на {hostname} ({event_label(numeric_event_id)}).",
        "why_it_matters": why,
        "recommended_action": recommendation(rule_code),
        "entities": [
            {"entity_type": "account", "display_name": target if target != "unknown" else None, "entity_role": "target"},
            {"entity_type": "account", "display_name": actor, "entity_role": "actor"},
            {"entity_type": "ip", "display_name": row.get("ip_address"), "entity_role": "source"},
            {
                "entity_type": "host",
                "display_name": row.get("workstation_name") or row.get("computer") or row.get("hostname"),
                "entity_role": "source",
            },
        ],
    }


def _before_findings_refresh_commit(_result: dict[str, Any]) -> None:
    """Test hook.  Production intentionally performs no action here."""


def _require_qualified_findings(candidates: list[dict[str, Any]]) -> None:
    # Source-pack event hints have no admitted policy identity.
    # Only semantic_findings may publish a policy-qualified finding.
    if candidates:
        raise RuntimeError("event findings require an admitted semantic policy; legacy publication is disabled")


def _findings_event_batch_sql(authorization: object | None) -> str:
    _v2_findings_route_selected(authorization)
    return """
        select e.id, e.event_id, channel.value as channel, e.time_created_utc,
               e.subject_user_name, subject_domain.value as subject_domain_name,
               e.target_user_name, target_domain.value as target_domain_name,
               e.ip_address, e.workstation_name, computer.value as computer,
               facts.message_sample as message_text, s.hostname
        from events_v2_core e
        join servers s on s.id=e.server_id
        join storage_v2_channel channel on channel.id=e.channel_id
        left join storage_v2_domain_name subject_domain on subject_domain.id=e.subject_domain_id
        left join storage_v2_domain_name target_domain on target_domain.id=e.target_domain_id
        left join storage_v2_computer computer on computer.id=e.computer_id
        left join event_facts_v2 facts on facts.event_id=e.id
        where e.id > %s
        order by e.id asc
        limit %s
    """


def _record_failure(*, error: Exception, started_at: str, duration_ms: int) -> None:
    """Persist failure visibility without changing the committed watermark."""
    from server.sli.core.postgres_runtime_pipeline import connect

    try:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    update findings_refresh_state
                    set last_status='failed', last_started_at=%s, last_failed_at=now(),
                        last_duration_ms=%s, last_error=%s, updated_at=now()
                    where pipeline_name=%s
                    """,
                    (started_at, duration_ms, f"{type(error).__name__}: {error}"[:4000], PIPELINE_NAME),
                )
    except Exception:
        # The original refresh exception is more important than a secondary status-write failure.
        pass


def refresh_findings_postgres(
    *,
    rules: Mapping[int, tuple[str, str, str, str]],
    event_label: Callable[[Any], str],
    principal: Callable[[Any, Any], str | None],
    recommendation: Callable[[str], str],
    limit: int | None = None,
    authorization: CutoverAuthorization | None = None,
) -> dict[str, Any]:
    """Process one bounded PostgreSQL event slice transactionally.

    The watermark is the monotonically increasing ``events.id``.  It advances over
    every scanned event, including events that do not match a Finding rule.  All
    Findings, evidence, entity, lifecycle and watermark writes share one database
    transaction; an exception before commit rolls the entire batch back.
    """
    from server.sli.core.postgres_runtime_pipeline import connect

    if authorization is None:
        ensure_findings_pg_schema(bootstrap_to_current=False)
    else:
        ensure_findings_pg_schema(
            bootstrap_to_current=False,
            authorization=authorization,
        )
    clean_limit = _clean_limit(limit)
    started_at = _utc_now()
    started = monotonic()
    try:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select * from findings_refresh_state
                    where pipeline_name=%s
                    for update
                    """,
                    (PIPELINE_NAME,),
                )
                state = dict(cur.fetchone() or {})
                watermark_before = int(state.get("last_event_id") or 0)

                cur.execute(
                    _findings_event_batch_sql(authorization),
                    (watermark_before, clean_limit),
                )
                event_rows = [dict(row) for row in cur.fetchall()]
                watermark_after = max((int(row["id"]) for row in event_rows), default=watermark_before)
                candidates = [
                    item
                    for item in (
                        _event_candidate(
                            row,
                            rules=rules,
                            event_label=event_label,
                            principal=principal,
                            recommendation=recommendation,
                        )
                        for row in event_rows
                    )
                    if item is not None
                ]

                created_findings = 0
                updated_findings = 0
                evidence_added = 0
                manual_status_preserved = 0

                _require_qualified_findings(candidates)
                if candidates:
                    unique_findings: dict[str, dict[str, Any]] = {}
                    for item in candidates:
                        unique_findings.setdefault(item["fingerprint"], item)
                    finding_payload = [
                        {
                            "fingerprint": item["fingerprint"],
                            "rule_code": item["rule_code"],
                            "title": item["title"],
                            "severity": item["severity"],
                            "first_seen_utc": item["event_time"],
                            "last_seen_utc": item["event_time"],
                            "actor": item["actor"],
                            "target": item["target"],
                            "source": item["source"],
                            "summary": item["summary"],
                            "why_it_matters": item["why_it_matters"],
                            "recommended_action": item["recommended_action"],
                        }
                        for item in unique_findings.values()
                    ]
                    cur.execute(
                        """
                        with incoming as (
                            select * from jsonb_to_recordset(%s::jsonb) as x(
                                fingerprint text, rule_code text, title text, severity text,
                                first_seen_utc text, last_seen_utc text, actor text, target text,
                                source text, summary text, why_it_matters text,
                                recommended_action text
                            )
                        )
                        insert into findings(
                            fingerprint, rule_code, title, severity, confidence, status,
                            first_seen_utc, last_seen_utc, actor, target, source, summary,
                            why_it_matters, recommended_action, evidence_count, status_reason,
                            repeat_count, last_evidence_event_id
                        )
                        select fingerprint, rule_code, title, severity, 0.70, 'new',
                               first_seen_utc, last_seen_utc, actor, target, source, summary,
                               why_it_matters, recommended_action, 0, 'создано по событию', 0, null
                        from incoming
                        on conflict(fingerprint) do nothing
                        returning id, fingerprint
                        """,
                        (_json_payload(finding_payload),),
                    )
                    created_rows = [dict(row) for row in cur.fetchall()]
                    created_findings = len(created_rows)
                    if created_rows:
                        cur.execute(
                            """
                            with incoming as (
                                select * from jsonb_to_recordset(%s::jsonb)
                                as x(finding_id bigint)
                            )
                            insert into finding_status_history(
                                finding_id, old_status, new_status, changed_by, note
                            )
                            select finding_id, null, 'new', 'system', 'created from event'
                            from incoming
                            """,
                            (_json_payload([{"finding_id": row["id"]} for row in created_rows]),),
                        )

                    fingerprints = list(unique_findings)
                    cur.execute(
                        """
                        select id, fingerprint, status, evidence_count, status_reason,
                               assigned_to, closed_at, last_seen_utc, last_evidence_event_id
                        from findings where fingerprint = any(%s)
                        """,
                        (fingerprints,),
                    )
                    finding_by_fingerprint = {row["fingerprint"]: dict(row) for row in cur.fetchall()}

                    evidence_payload: list[dict[str, Any]] = []
                    candidate_by_event: dict[int, dict[str, Any]] = {}
                    entity_payload: list[dict[str, Any]] = []
                    seen_entities: set[tuple[int, str, str, str]] = set()
                    for item in candidates:
                        finding = finding_by_fingerprint[item["fingerprint"]]
                        finding_id = int(finding["id"])
                        event_db_id = int(item["event_db_id"])
                        candidate_by_event[event_db_id] = item
                        evidence_payload.append(
                            {
                                "finding_id": finding_id,
                                "event_id": event_db_id,
                                "evidence_role": "supporting_event",
                                "note": item["event_note"],
                            }
                        )
                        for entity in item["entities"]:
                            display_name = str(entity.get("display_name") or "").strip()
                            if not display_name:
                                continue
                            key = (finding_id, str(entity["entity_type"]), display_name.casefold(), str(entity["entity_role"]))
                            if key in seen_entities:
                                continue
                            seen_entities.add(key)
                            entity_payload.append(
                                {
                                    "finding_id": finding_id,
                                    "entity_type": entity["entity_type"],
                                    "display_name": display_name,
                                    "entity_role": entity["entity_role"],
                                }
                            )

                    cur.execute(
                        """
                        with incoming as (
                            select * from jsonb_to_recordset(%s::jsonb) as x(
                                finding_id bigint, event_id bigint,
                                evidence_role text, note text
                            )
                        )
                        insert into finding_evidence(finding_id, event_id, evidence_role, note)
                        select finding_id, event_id, evidence_role, note from incoming
                        on conflict(finding_id, event_id, evidence_role) do nothing
                        returning finding_id, event_id
                        """,
                        (_json_payload(evidence_payload),),
                    )
                    added_rows = [dict(row) for row in cur.fetchall()]
                    evidence_added = len(added_rows)

                    if entity_payload:
                        cur.execute(
                            """
                            with incoming as (
                                select * from jsonb_to_recordset(%s::jsonb) as x(
                                    finding_id bigint, entity_type text,
                                    display_name text, entity_role text
                                )
                            )
                            insert into finding_entities(
                                finding_id, entity_type, display_name, entity_role
                            )
                            select i.finding_id, i.entity_type, i.display_name, i.entity_role
                            from incoming i
                            where not exists (
                                select 1 from finding_entities fe
                                where fe.finding_id=i.finding_id
                                  and coalesce(fe.entity_type,'')=coalesce(i.entity_type,'')
                                  and coalesce(fe.display_name,'')=coalesce(i.display_name,'')
                                  and coalesce(fe.entity_role,'')=coalesce(i.entity_role,'')
                            )
                            """,
                            (_json_payload(entity_payload),),
                        )

                    deltas: dict[int, dict[str, Any]] = {}
                    for added in added_rows:
                        finding_id = int(added["finding_id"])
                        item = candidate_by_event[int(added["event_id"])]
                        current = deltas.setdefault(
                            finding_id,
                            {
                                "finding_id": finding_id,
                                "added_count": 0,
                                "min_time": item["event_time"],
                                "max_time": item["event_time"],
                                "latest_event_id": item["event_db_id"],
                                "actor": item["actor"],
                                "source": item["source"],
                            },
                        )
                        current["added_count"] += 1
                        if item["event_time"] < current["min_time"]:
                            current["min_time"] = item["event_time"]
                        if (item["event_time"], int(item["event_db_id"])) >= (
                            current["max_time"], int(current["latest_event_id"])
                        ):
                            current["max_time"] = item["event_time"]
                            current["latest_event_id"] = int(item["event_db_id"])
                            current["actor"] = item["actor"] or current["actor"]
                            current["source"] = item["source"] or current["source"]

                    transition_rows: list[dict[str, Any]] = []
                    if deltas:
                        cur.execute(
                            """
                            with delta as (
                                select * from jsonb_to_recordset(%s::jsonb) as x(
                                    finding_id bigint, added_count bigint,
                                    min_time text, max_time text, latest_event_id bigint,
                                    actor text, source text
                                )
                            ), targets as (
                                select f.id,
                                       f.status as old_status,
                                       case
                                           when f.evidence_count + d.added_count > 1
                                                and f.status in ('new','active','repeated')
                                           then 'repeated'
                                           else f.status
                                       end as new_status,
                                       f.evidence_count + d.added_count as new_evidence_count,
                                       d.*
                                from findings f join delta d on d.finding_id=f.id
                            ), updated as (
                                update findings f
                                set evidence_count=t.new_evidence_count,
                                    repeat_count=greatest(0, t.new_evidence_count - 1),
                                    first_seen_utc=case
                                        when f.first_seen_utc is null or t.min_time < f.first_seen_utc
                                        then t.min_time else f.first_seen_utc end,
                                    last_seen_utc=case
                                        when f.last_seen_utc is null or t.max_time > f.last_seen_utc
                                        then t.max_time else f.last_seen_utc end,
                                    actor=coalesce(f.actor, t.actor),
                                    source=coalesce(f.source, t.source),
                                    status=t.new_status,
                                    status_reason=case
                                        when f.status in ('new','active','repeated') then
                                            case when t.new_evidence_count > 1
                                                 then 'повторно обнаружено похожее событие'
                                                 else coalesce(f.status_reason, 'создано по событию') end
                                        else f.status_reason
                                    end,
                                    last_evidence_event_id=case
                                        when f.last_seen_utc is null or t.max_time >= f.last_seen_utc
                                        then t.latest_event_id else f.last_evidence_event_id end,
                                    last_repeat_detected_at=case
                                        when t.new_evidence_count > 1 then t.max_time
                                        else f.last_repeat_detected_at end,
                                    updated_at=now()
                                from targets t
                                where f.id=t.id
                                returning f.id, t.old_status, t.new_status,
                                          t.new_evidence_count
                            )
                            select * from updated
                            """,
                            (_json_payload(list(deltas.values())),),
                        )
                        update_rows = [dict(row) for row in cur.fetchall()]
                        updated_findings = len(update_rows)
                        transition_rows = [row for row in update_rows if row["old_status"] != row["new_status"]]
                        manual_status_preserved = sum(
                            1 for row in update_rows if str(row["old_status"]) in MANUAL_PRESERVED_STATUSES
                        )
                        if transition_rows:
                            cur.execute(
                                """
                                with incoming as (
                                    select * from jsonb_to_recordset(%s::jsonb) as x(
                                        finding_id bigint, old_status text, new_status text
                                    )
                                )
                                insert into finding_status_history(
                                    finding_id, old_status, new_status, changed_by, note
                                )
                                select finding_id, old_status, new_status,
                                       'system', 'repeat evidence added'
                                from incoming
                                """,
                                (
                                    _json_payload(
                                        [
                                            {
                                                "finding_id": row["id"],
                                                "old_status": row["old_status"],
                                                "new_status": row["new_status"],
                                            }
                                            for row in transition_rows
                                        ]
                                    ),
                                ),
                            )

                duration_ms = int((monotonic() - started) * 1000)
                result = {
                    "status": "ok",
                    "backend": "postgres",
                    "pipeline": PIPELINE_NAME,
                    "watermark_before": watermark_before,
                    "watermark_after": watermark_after,
                    "scanned_events": len(event_rows),
                    "matched_events": len(candidates),
                    "created_findings": created_findings,
                    "updated_findings": updated_findings,
                    "evidence_added": evidence_added,
                    "manual_status_preserved": manual_status_preserved,
                    "has_more": len(event_rows) >= clean_limit,
                    "batch_limit": clean_limit,
                    "duration_ms": duration_ms,
                    "generated_at_utc": _utc_now(),
                }
                cur.execute(
                    """
                    update findings_refresh_state
                    set last_event_id=%s, last_status='completed',
                        last_started_at=%s, last_completed_at=now(),
                        last_duration_ms=%s, last_scanned_events=%s,
                        last_matched_events=%s, last_created_findings=%s,
                        last_updated_findings=%s, last_evidence_added=%s,
                        last_manual_status_preserved=%s, last_has_more=%s,
                        last_error=null, updated_at=now()
                    where pipeline_name=%s
                    """,
                    (
                        watermark_after,
                        started_at,
                        duration_ms,
                        len(event_rows),
                        len(candidates),
                        created_findings,
                        updated_findings,
                        evidence_added,
                        manual_status_preserved,
                        len(event_rows) >= clean_limit,
                        PIPELINE_NAME,
                    ),
                )
                _before_findings_refresh_commit(result)
                return result
    except Exception as exc:
        duration_ms = int((monotonic() - started) * 1000)
        _record_failure(error=exc, started_at=started_at, duration_ms=duration_ms)
        raise


def get_findings_refresh_status(
    *, authorization: object | None = None
) -> dict[str, Any]:
    from server.sli.core.postgres_runtime_pipeline import connect

    try:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select * from findings_refresh_state where pipeline_name=%s
                    """,
                    (PIPELINE_NAME,),
                )
                state = dict(cur.fetchone() or {})
                relation = _findings_event_relation(authorization)
                cur.execute(f"select coalesce(max(id),0) as max_event_id from {relation}")
                max_event_id = int((cur.fetchone() or {}).get("max_event_id") or 0)
        last_event_id = int(state.get("last_event_id") or 0)
        state.update(
            {
                "status": "ok" if state.get("last_status") != "failed" else "limited",
                "backend": "postgres",
                "pipeline": PIPELINE_NAME,
                "max_event_id": max_event_id,
                "event_id_gap_estimate": max(0, max_event_id - last_event_id),
                "limitations": (
                    [f"последнее обновление Findings завершилось ошибкой: {state.get('last_error')}"]
                    if state.get("last_status") == "failed"
                    else []
                ),
            }
        )
        return state
    except Exception as exc:
        return {
            "status": "unavailable",
            "backend": "postgres",
            "pipeline": PIPELINE_NAME,
            "reason": f"{type(exc).__name__}: {exc}",
            "limitations": ["состояние инкрементального обновления Findings временно недоступно"],
            "generated_at_utc": _utc_now(),
        }

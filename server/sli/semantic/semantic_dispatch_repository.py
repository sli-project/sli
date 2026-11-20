"""Durable bounded dispatch primitives for migration 027.

Nothing in this module registers a worker or enables correlation. Callers own
transactions, feature gates and the decision to execute claimed work.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from typing import Any
import uuid

from server.sli.semantic.semantic_correlation import SemanticRelation
from server.sli.semantic.semantic_correlation_repository import (
    EXECUTABLE_RULE_STATES,
    CorrelationRuleDefinition,
    persist_correlation_candidate,
)
from server.sli.semantic.semantic_dispatch import (
    MAX_MATCH_EVENTS,
    CompiledCorrelationRule,
    compile_correlation_rule,
    relation_partition_key,
)
from server.sli.semantic.semantic_identity import parse_exact_domain_sid_partition
from server.sli.semantic.semantic_processing import NormalizedEvent
from server.sli.semantic.semantic_context import (
    MAX_CONTEXT_EVENTS_PER_IDENTITY,
    hydrate_dispatch_context,
)
from server.sli.storage.storage_v2_archive import ArchiveReader


MAX_DISPATCH_CLAIM = 16
MAX_LATE_AFTER = timedelta(hours=24)
MAX_RULE_FILTERS = 64
MAX_JOB_FILTERS = 1024


def _bounded_rule_ids(values: Sequence[str] | None) -> list[str] | None:
    if values is None:
        return None
    result = sorted({str(value).strip() for value in values if str(value).strip()})
    if not result or len(result) > 64 or any(len(value) > 200 for value in result):
        raise ValueError("allowed_rule_ids must contain bounded exact rule IDs")
    return result


def _bounded_rule_identities(
    values: Sequence[tuple[str, int, bytes | str]] | None,
) -> list[tuple[str, int, bytes]] | None:
    if values is None:
        return None
    result: set[tuple[str, int, bytes]] = set()
    for raw_rule_id, raw_version, raw_digest in values:
        rule_id = str(raw_rule_id).strip()
        try:
            version = int(raw_version)
            digest = (
                bytes.fromhex(raw_digest)
                if isinstance(raw_digest, str)
                else bytes(raw_digest)
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("allowed_rule_identities are invalid") from exc
        if not rule_id or len(rule_id) > 200 or version <= 0 or len(digest) != 32:
            raise ValueError("allowed_rule_identities are invalid")
        result.add((rule_id, version, digest))
    if not result or len(result) > MAX_RULE_FILTERS:
        raise ValueError("allowed_rule_identities are invalid")
    return sorted(result, key=lambda item: (item[0], item[1], item[2]))


def _bounded_job_ids(values: Sequence[str] | None) -> list[str] | None:
    if values is None:
        return None
    result: set[str] = set()
    try:
        for value in values:
            result.add(str(uuid.UUID(str(value))))
    except (TypeError, ValueError, AttributeError) as exc:
        raise ValueError("allowed_job_ids are invalid") from exc
    if len(result) > MAX_JOB_FILTERS:
        raise ValueError("allowed_job_ids are invalid")
    return sorted(result)


@dataclass(frozen=True, kw_only=True)
class DispatchWorkItem:
    job_id: str
    lease_token: str
    trigger_source_event_id: int
    is_late: bool
    rule: CompiledCorrelationRule
    events: tuple[NormalizedEvent, ...]
    evidence_contract: tuple[int, str, str] | None = None


@dataclass(frozen=True, kw_only=True)
class CandidateDispatchState:
    candidate_id: str
    candidate_status: str
    reopen_count: int
    late_evidence_count: int


def _json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    parsed = json.loads(str(value or "{}"))
    if not isinstance(parsed, Mapping):
        raise RuntimeError("semantic dispatch JSON must contain an object")
    return dict(parsed)


def _dispatch_identity(
    *, normalized_event_id: str, rule_id: str, rule_version: int, definition_sha256: bytes
) -> bytes:
    payload = json.dumps(
        {
            "normalized_event_id": normalized_event_id,
            "rule_id": rule_id,
            "rule_version": int(rule_version),
            "definition_sha256": definition_sha256.hex(),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return sha256(payload.encode("utf-8")).digest()


def _cross_dc_context_predicate(
    rule: CompiledCorrelationRule, partition_key: str,
) -> tuple[str, tuple[str, ...]]:
    """Build the non-empty exact-partition predicate for cross-DC context.

    JSONB containment of ``{}`` matches every object, so every predicate arm is
    constructed only from a closed-form partition component and is non-empty.
    """
    pieces = parse_exact_domain_sid_partition(partition_key)
    if pieces is None:
        raise RuntimeError("cross-DC dispatch partition is not an exact SID key")
    domain_filter = json.dumps(
        {"domain_id": int(pieces["domain"])}, sort_keys=True, separators=(",", ":")
    )
    if rule.partition_kind == "domain_account_sid":
        role_filter = json.dumps(
            {"affected_entity": f"sid:{pieces['account_sid']}"},
            sort_keys=True, separators=(",", ":"),
        )
        return "facts_json @> %s::jsonb and roles_json @> %s::jsonb", (
            domain_filter, role_filter,
        )
    if rule.partition_kind == "domain_member_group_sid":
        fact_filter = json.dumps(
            {
                "relation_member_sid": pieces["member_sid"],
                "relation_group_sid": pieces["group_sid"],
            },
            sort_keys=True, separators=(",", ":"),
        )
        return "facts_json @> %s::jsonb and facts_json @> %s::jsonb", (
            domain_filter, fact_filter,
        )
    if rule.partition_kind == "domain_account_member_sid":
        sid = pieces["account_member_sid"]
        role_filter = json.dumps(
            {"affected_entity": f"sid:{sid}"}, sort_keys=True, separators=(",", ":")
        )
        fact_filter = json.dumps(
            {"relation_member_sid": sid}, sort_keys=True, separators=(",", ":")
        )
        return (
            "facts_json @> %s::jsonb and "
            "(roles_json @> %s::jsonb or facts_json @> %s::jsonb)",
            (domain_filter, role_filter, fact_filter),
        )
    raise RuntimeError("cross-DC dispatch rule partition is unsupported")


def replace_rule_subscriptions(cur: Any, *, rule: CompiledCorrelationRule) -> None:
    """Replace subscriptions only while the exact rule version is in DRAFT."""
    cur.execute(
        """
        select lifecycle_status,definition_sha256
        from semantic_correlation_rules
        where rule_id=%s and rule_version=%s
        for update
        """,
        (rule.rule_id, rule.rule_version),
    )
    parent = dict(cur.fetchone() or {})
    if not parent:
        raise LookupError("correlation rule version not found")
    if parent.get("lifecycle_status") != "draft":
        raise RuntimeError("correlation subscriptions are mutable only in draft")
    if bytes(parent.get("definition_sha256") or b"") != rule.definition_sha256:
        raise RuntimeError("correlation subscription definition hash mismatch")
    cur.execute(
        """
        select semantic_type,subscription_order,definition_sha256
        from semantic_correlation_subscriptions
        where rule_id=%s and rule_version=%s
        order by subscription_order
        """,
        (rule.rule_id, rule.rule_version),
    )
    existing = [dict(item) for item in (cur.fetchall() or [])]
    expected = [
        {
            "semantic_type": semantic_type,
            "subscription_order": order,
            "definition_sha256": rule.definition_sha256,
        }
        for order, semantic_type in enumerate(rule.input_types)
    ]
    if existing == expected:
        return
    cur.execute(
        """
        delete from semantic_correlation_subscriptions
        where rule_id=%s and rule_version=%s
        """,
        (rule.rule_id, rule.rule_version),
    )
    for order, semantic_type in enumerate(rule.input_types):
        cur.execute(
            """
            insert into semantic_correlation_subscriptions(
                rule_id,rule_version,semantic_type,subscription_order,definition_sha256
            ) values (%s,%s,%s,%s,%s)
            """,
            (
                rule.rule_id,
                rule.rule_version,
                semantic_type,
                order,
                rule.definition_sha256,
            ),
        )


def enqueue_dispatch_jobs(
    cur: Any,
    *,
    normalized_event_id: str,
    late_after: timedelta = timedelta(minutes=5),
    allowed_rule_ids: Sequence[str] | None = None,
    allowed_rule_identities: Sequence[tuple[str, int, bytes | str]] | None = None,
) -> tuple[str, ...]:
    """Fan one normalized event out to exact executable rule subscriptions."""
    if late_after <= timedelta(0) or late_after > MAX_LATE_AFTER:
        raise ValueError("late_after must be within 24 hours")
    selected_rule_ids = _bounded_rule_ids(allowed_rule_ids)
    selected_rule_identities = _bounded_rule_identities(allowed_rule_identities)
    if selected_rule_ids is not None and selected_rule_identities is not None:
        raise ValueError("choose rule IDs or exact rule identities, not both")
    cur.execute(
        """
        select normalized_event_id,semantic_type,occurred_at_utc,
               source_ingested_at,roles_json,facts_json,quality_json
        from normalized_events
        where normalized_event_id=%s and processing_status='normalized'
        """,
        (normalized_event_id,),
    )
    event = dict(cur.fetchone() or {})
    if not event:
        raise LookupError("normalized dispatch source event not found")
    occurred_at = event["occurred_at_utc"]
    ingested_at = event["source_ingested_at"]
    is_late = ingested_at - occurred_at > late_after
    identity_filter = ""
    identity_parameters: list[Any] = []
    if selected_rule_identities is not None:
        identity_filter = "and (" + " or ".join(
            "(rule.rule_id=%s and rule.rule_version=%s and rule.definition_sha256=%s)"
            for _ in selected_rule_identities
        ) + ")"
        for rule_id, rule_version, definition_sha256 in selected_rule_identities:
            identity_parameters.extend((rule_id, rule_version, definition_sha256))
    cur.execute(
        f"""
        select subscription.rule_id,subscription.rule_version,
               subscription.definition_sha256,rule.rule_kind,rule.definition_json
        from semantic_correlation_subscriptions subscription
        join semantic_correlation_rules rule
          on rule.rule_id=subscription.rule_id
         and rule.rule_version=subscription.rule_version
         and rule.definition_sha256=subscription.definition_sha256
        where subscription.semantic_type=%s
          and rule.lifecycle_status=any(%s)
          and (%s::text[] is null or rule.rule_id=any(%s))
          {identity_filter}
        order by subscription.rule_id,subscription.rule_version
        """,
        tuple((
            event["semantic_type"], sorted(EXECUTABLE_RULE_STATES),
            selected_rule_ids, selected_rule_ids,
        ) + tuple(identity_parameters)),
    )
    subscriptions = [dict(item) for item in (cur.fetchall() or [])]
    normalized_event = NormalizedEvent(
        source_event_id=0,
        semantic_type=str(event["semantic_type"]),
        occurred_at_utc=occurred_at,
        roles=_json_object(event.get("roles_json")),
        facts=_json_object(event.get("facts_json")),
        quality=_json_object(event.get("quality_json")),
        semantic_sha256="",
    )
    job_ids: list[str] = []
    for subscription in subscriptions:
        rule_id = str(subscription["rule_id"])
        rule_version = int(subscription["rule_version"])
        definition_sha = bytes(subscription["definition_sha256"])
        source_rule = CorrelationRuleDefinition(
            rule_id=rule_id,
            rule_version=rule_version,
            rule_kind=str(subscription["rule_kind"]),
            definition=_json_object(subscription["definition_json"]),
        )
        rule = compile_correlation_rule(source_rule)
        if rule.definition_sha256 != definition_sha:
            raise RuntimeError("semantic dispatch subscription definition hash mismatch")
        partition_key = relation_partition_key(rule, normalized_event)
        if partition_key is None:
            continue
        if len(partition_key) > 512:
            raise RuntimeError("normalized dispatch event requires a bounded exact partition")
        identity = _dispatch_identity(
            normalized_event_id=str(event["normalized_event_id"]),
            rule_id=rule_id,
            rule_version=rule_version,
            definition_sha256=definition_sha,
        )
        job_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"adlog:semantic-dispatch:{identity.hex()}"))
        cur.execute(
            """
            insert into semantic_correlation_dispatch_jobs(
                job_id,normalized_event_id,rule_id,rule_version,idempotency_key,
                partition_key,occurred_at_utc,is_late
            ) values (%s,%s,%s,%s,%s,%s,%s,%s)
            on conflict(idempotency_key) do nothing
            """,
            (
                job_id,
                event["normalized_event_id"],
                rule_id,
                rule_version,
                identity,
                partition_key,
                occurred_at,
                is_late,
            ),
        )
        cur.execute(
            """
            select job_id,normalized_event_id,partition_key,is_late
            from semantic_correlation_dispatch_jobs where idempotency_key=%s
            """,
            (identity,),
        )
        persisted = dict(cur.fetchone() or {})
        if (
            str(persisted.get("job_id")) != job_id
            or str(persisted.get("normalized_event_id")) != str(event["normalized_event_id"])
            or persisted.get("partition_key") != partition_key
            or bool(persisted.get("is_late")) != is_late
        ):
            raise RuntimeError("semantic dispatch job identity replay conflict")
        job_ids.append(job_id)
    return tuple(job_ids)


def claim_dispatch_jobs(
    cur: Any, *, limit: int = 1, lease_seconds: int = 300,
    allowed_rule_ids: Sequence[str] | None = None,
    allowed_rule_identities: Sequence[tuple[str, int, bytes | str]] | None = None,
    allowed_job_ids: Sequence[str] | None = None,
) -> list[dict[str, Any]]:
    requested = max(1, min(int(limit), MAX_DISPATCH_CLAIM))
    lease = max(60, min(int(lease_seconds), 3600))
    token = str(uuid.uuid4())
    selected_rule_ids = _bounded_rule_ids(allowed_rule_ids)
    selected_rule_identities = _bounded_rule_identities(allowed_rule_identities)
    selected_job_ids = _bounded_job_ids(allowed_job_ids)
    if selected_rule_ids is not None and selected_rule_identities is not None:
        raise ValueError("choose rule IDs or exact rule identities, not both")
    if selected_job_ids == []:
        return []
    filters: list[str] = []
    parameters: list[Any] = []
    if selected_rule_ids is not None:
        filters.append("job.rule_id=any(%s)")
        parameters.append(selected_rule_ids)
    if selected_rule_identities is not None:
        filters.append("(" + " or ".join(
            "(rule.rule_id=%s and rule.rule_version=%s and rule.definition_sha256=%s)"
            for _ in selected_rule_identities
        ) + ")")
        for rule_id, rule_version, definition_sha256 in selected_rule_identities:
            parameters.extend((rule_id, rule_version, definition_sha256))
    if selected_job_ids is not None:
        filters.append("job.job_id=any(%s::uuid[])")
        parameters.append(selected_job_ids)
    rule_filter = "and " + " and ".join(filters) if filters else ""
    parameters.extend((requested, token, lease))
    cur.execute(
        f"""
        with candidates as (
            select job.job_id from semantic_correlation_dispatch_jobs job
            join semantic_correlation_rules rule
              on rule.rule_id=job.rule_id and rule.rule_version=job.rule_version
            where job.attempt_count < job.max_attempts and job.available_at <= now()
              and (job.dispatch_status in ('queued','failed')
                   or (job.dispatch_status='leased' and job.lease_until < now()))
              {rule_filter}
            order by job.available_at,job.created_at,job.job_id
            for update of job skip locked limit %s
        )
        update semantic_correlation_dispatch_jobs job
        set dispatch_status='leased',attempt_count=attempt_count+1,
            lease_token=%s,lease_until=now()+(%s * interval '1 second'),
            heartbeat_at=now(),updated_at=now(),
            last_error_code=null,last_error_detail=null
        from candidates where job.job_id=candidates.job_id
        returning job.*
        """,
        tuple(parameters),
    )
    return [dict(item) for item in (cur.fetchall() or [])]


def heartbeat_dispatch_job(
    cur: Any, *, job_id: str, lease_token: str, lease_seconds: int = 300
) -> bool:
    lease = max(60, min(int(lease_seconds), 3600))
    cur.execute(
        """
        update semantic_correlation_dispatch_jobs
        set heartbeat_at=now(),lease_until=now()+(%s * interval '1 second'),
            updated_at=now()
        where job_id=%s and dispatch_status='leased' and lease_token=%s
        returning job_id
        """,
        (lease, job_id, lease_token),
    )
    return cur.fetchone() is not None


def complete_dispatch_job(cur: Any, *, job_id: str, lease_token: str) -> None:
    cur.execute(
        """
        update semantic_correlation_dispatch_jobs
        set dispatch_status='completed',completed_at=now(),
            lease_token=null,lease_until=null,heartbeat_at=now(),updated_at=now()
        where job_id=%s and dispatch_status='leased' and lease_token=%s
        returning job_id
        """,
        (job_id, lease_token),
    )
    if cur.fetchone() is None:
        raise RuntimeError("semantic dispatch lease was lost")


def fail_dispatch_job(
    cur: Any,
    *,
    job_id: str,
    lease_token: str,
    attempt_count: int,
    max_attempts: int,
    error_code: str,
    error_detail: str,
) -> str:
    terminal = int(attempt_count) >= int(max_attempts)
    status = "quarantined" if terminal else "failed"
    retry_seconds = min(3600, 30 * (2 ** min(max(0, int(attempt_count) - 1), 7)))
    cur.execute(
        """
        update semantic_correlation_dispatch_jobs
        set dispatch_status=%s,available_at=now()+(%s * interval '1 second'),
            lease_token=null,lease_until=null,last_error_code=%s,
            last_error_detail=%s,updated_at=now()
        where job_id=%s and dispatch_status='leased' and lease_token=%s
        returning dispatch_status
        """,
        (
            status,
            retry_seconds,
            error_code[:160],
            error_detail[:1000],
            job_id,
            lease_token,
        ),
    )
    if cur.fetchone() is None:
        raise RuntimeError("semantic dispatch lease was lost while recording failure")
    return status


def load_dispatch_work_item(
    cur: Any,
    *,
    job_id: str,
    lease_token: str,
    archive: ArchiveReader | None = None,
    normalized_before: datetime | None = None,
) -> DispatchWorkItem:
    """Load one lease and a bounded exact-partition event context."""
    cur.execute(
        """
        select job.job_id,job.lease_token,job.is_late,job.partition_key,
               job.occurred_at_utc,trigger.source_event_id,
               trigger.semantic_contract_version,trigger.normalizer_id,
               trigger.normalizer_version,trigger.normalized_at,
               trigger.roles_json as trigger_roles_json,
               trigger.facts_json as trigger_facts_json,
               trigger.quality_json as trigger_quality_json,
               rule.rule_id,rule.rule_version,rule.rule_kind,
               rule.lifecycle_status,rule.definition_json,rule.definition_sha256
        from semantic_correlation_dispatch_jobs job
        join normalized_events trigger
          on trigger.normalized_event_id=job.normalized_event_id
        join semantic_correlation_rules rule
          on rule.rule_id=job.rule_id and rule.rule_version=job.rule_version
        where job.job_id=%s and job.dispatch_status='leased' and job.lease_token=%s
        for share of rule
        """,
        (job_id, lease_token),
    )
    row = dict(cur.fetchone() or {})
    if not row:
        raise RuntimeError("semantic dispatch lease is not available")
    if normalized_before is not None:
        if normalized_before.tzinfo is None:
            raise ValueError("semantic dispatch frozen boundary must be timezone-aware")
        if row["normalized_at"] > normalized_before:
            raise RuntimeError("semantic dispatch trigger is newer than frozen boundary")
    if row["lifecycle_status"] not in EXECUTABLE_RULE_STATES:
        raise RuntimeError("semantic dispatch rule is no longer executable")
    definition = _json_object(row["definition_json"])
    source_rule = CorrelationRuleDefinition(
        rule_id=str(row["rule_id"]),
        rule_version=int(row["rule_version"]),
        rule_kind=str(row["rule_kind"]),
        definition=definition,
    )
    rule = compile_correlation_rule(source_rule)
    if rule.definition_sha256 != bytes(row["definition_sha256"]):
        raise RuntimeError("semantic dispatch rule definition hash mismatch")
    start = row["occurred_at_utc"] - rule.window
    end = row["occurred_at_utc"] + rule.window
    trigger_roles = {
        role: str(value).strip()
        for role, value in _json_object(row["trigger_roles_json"]).items()
        if str(value).strip()
    }
    group_roles = {
        role: trigger_roles.get(role, "")
        for role in rule.join_roles
    }
    trigger_event = NormalizedEvent(
        source_event_id=int(row["source_event_id"]),
        semantic_type="",
        occurred_at_utc=row["occurred_at_utc"],
        roles=trigger_roles,
        facts=_json_object(row.get("trigger_facts_json")),
        quality=_json_object(row.get("trigger_quality_json")),
        semantic_sha256="",
    )
    source_host_partition = rule.partition_kind == "source_host"
    evidence_contract = (
        int(row["semantic_contract_version"]),
        str(row["normalizer_id"]),
        str(row["normalizer_version"]),
    )
    matchable_group = all(group_roles.values()) if source_host_partition else (
        relation_partition_key(rule, trigger_event) == str(row["partition_key"])
    )
    if archive is not None and matchable_group and source_host_partition:
        hydrate_dispatch_context(
            cur,
            archive=archive,
            semantic_types=rule.input_types,
            join_roles=rule.join_roles,
            trigger_roles=trigger_roles,
            partition_key=str(row["partition_key"]),
            start_utc=start,
            end_utc=end,
        )
    context_rows: list[dict[str, Any]] = []
    if matchable_group and source_host_partition:
        encoded_group = json.dumps(
            group_roles,
            sort_keys=True,
            separators=(",", ":"),
        )
        if rule.rule_kind in {"all_of", "sequence"}:
            cur.execute(
                """
                with required(semantic_type) as (
                  select unnest(%s::text[])
                )
                select normalized.source_event_id,normalized.semantic_type,
                       normalized.occurred_at_utc,normalized.roles_json,
                       normalized.facts_json,normalized.quality_json,
                       normalized.semantic_sha256
                from required
                cross join lateral (
                  select source_event_id,semantic_type,occurred_at_utc,
                         roles_json,facts_json,quality_json,semantic_sha256
                  from normalized_events
                  where processing_status='normalized'
                    and semantic_contract_version=%s
                    and normalizer_id=%s and normalizer_version=%s
                    and (%s::timestamptz is null or normalized_at<=%s)
                    and semantic_type=required.semantic_type
                    and roles_json @> %s::jsonb
                    and occurred_at_utc between %s and %s
                  order by abs(extract(epoch from (occurred_at_utc-%s))),
                           occurred_at_utc,source_event_id
                  limit %s
                ) normalized
                order by normalized.occurred_at_utc,
                         normalized.source_event_id
                """,
                (
                    list(rule.input_types),
                    *evidence_contract,
                    normalized_before, normalized_before,
                    encoded_group,
                    start,
                    end,
                    row["occurred_at_utc"],
                    MAX_CONTEXT_EVENTS_PER_IDENTITY,
                ),
            )
        else:
            cur.execute(
                """
                select source_event_id,semantic_type,occurred_at_utc,roles_json,
                       facts_json,quality_json,semantic_sha256
                from normalized_events
                where processing_status='normalized'
                  and semantic_contract_version=%s
                  and normalizer_id=%s and normalizer_version=%s
                  and (%s::timestamptz is null or normalized_at<=%s)
                  and semantic_type=any(%s)
                  and roles_json @> %s::jsonb
                  and occurred_at_utc between %s and %s
                order by occurred_at_utc,source_event_id
                limit %s
                """,
                (
                    *evidence_contract,
                    normalized_before, normalized_before,
                    list(rule.input_types),
                    encoded_group,
                    start,
                    end,
                    MAX_MATCH_EVENTS + 1,
                ),
            )
        context_rows = [dict(item) for item in (cur.fetchall() or [])]
    elif matchable_group:
        context_predicate, context_parameters = _cross_dc_context_predicate(
            rule, str(row["partition_key"])
        )
        cur.execute(
            f"""
            select source_event_id,semantic_type,occurred_at_utc,roles_json,
                   facts_json,quality_json,semantic_sha256
            from normalized_events
            where processing_status='normalized'
              and semantic_contract_version=%s
              and normalizer_id=%s and normalizer_version=%s
              and (%s::timestamptz is null or normalized_at<=%s)
              and semantic_type=any(%s)
              and {context_predicate}
              and occurred_at_utc between %s and %s
            order by occurred_at_utc,source_event_id
            limit %s
            """,
            (
                *evidence_contract,
                normalized_before, normalized_before,
                list(rule.input_types),
                *context_parameters,
                start,
                end,
                MAX_MATCH_EVENTS + 1,
            ),
        )
        context_rows = [dict(item) for item in (cur.fetchall() or [])]
    if len(context_rows) > MAX_MATCH_EVENTS:
        raise RuntimeError("semantic dispatch context exceeds 5000 events")
    events = tuple(
        NormalizedEvent(
            source_event_id=int(item["source_event_id"]),
            semantic_type=str(item["semantic_type"]),
            occurred_at_utc=item["occurred_at_utc"],
            roles=_json_object(item["roles_json"]),
            facts=_json_object(item["facts_json"]),
            quality=_json_object(item["quality_json"]),
            semantic_sha256=bytes(item["semantic_sha256"]).hex(),
        )
        for item in context_rows
    )
    return DispatchWorkItem(
        job_id=str(row["job_id"]),
        lease_token=str(row["lease_token"]),
        trigger_source_event_id=int(row["source_event_id"]),
        is_late=bool(row["is_late"]),
        rule=rule,
        events=events,
        evidence_contract=evidence_contract,
    )


def persist_dispatched_relation(
    cur: Any,
    *,
    rule: CompiledCorrelationRule,
    relation: SemanticRelation,
    late_source_event_ids: Sequence[int] = (),
    evidence_contract: tuple[int, str, str] | None = None,
) -> CandidateDispatchState:
    """Persist a match and reopen it once per newly observed late evidence."""
    evidence_ids = tuple(dict.fromkeys(int(item) for item in relation.source_event_ids))
    late_ids = tuple(dict.fromkeys(int(item) for item in late_source_event_ids))
    if not set(late_ids).issubset(evidence_ids):
        raise ValueError("late evidence must belong to the dispatched relation")
    candidate_id = persist_correlation_candidate(
        cur,
        rule_id=rule.rule_id,
        rule_version=rule.rule_version,
        relation=relation,
        evidence_contract=evidence_contract,
    )
    cur.execute(
        """
        with prior as (
            select count(*) filter (where evidence.is_late) as prior_late_count,
                   max(normalized.occurred_at_utc) as last_evidence_occurred_at
            from semantic_correlation_candidate_evidence evidence
            join normalized_events normalized
              on normalized.normalized_event_id=evidence.normalized_event_id
            where evidence.candidate_id=%s
        ), marked as (
            update semantic_correlation_candidate_evidence evidence
            set is_late=true
            from normalized_events normalized
            where evidence.candidate_id=%s
              and evidence.normalized_event_id=normalized.normalized_event_id
              and normalized.source_event_id=any(%s)
              and not evidence.is_late
            returning 1
        ), changed as (
            select count(*) as changed_count from marked
        )
        update semantic_correlation_candidates candidate
        set reopen_count=candidate.reopen_count + case
                when candidate.candidate_status='expired' and changed.changed_count > 0
                then 1 else 0 end,
            candidate_status=case
                when candidate.candidate_status='expired' and changed.changed_count > 0
                then 'matched' else candidate.candidate_status end,
            closed_at=case
                when candidate.candidate_status='expired' and changed.changed_count > 0
                then null else candidate.closed_at end,
            late_evidence_count=(prior.prior_late_count + changed.changed_count)::integer,
            last_evidence_occurred_at=prior.last_evidence_occurred_at,
            updated_at=now()
        from prior,changed
        where candidate.candidate_id=%s
        returning candidate.candidate_id,candidate.candidate_status,
                  candidate.reopen_count,candidate.late_evidence_count
        """,
        (candidate_id, candidate_id, list(late_ids), candidate_id),
    )
    state = dict(cur.fetchone() or {})
    if not state:
        raise RuntimeError("semantic dispatch candidate state was not persisted")
    return CandidateDispatchState(
        candidate_id=str(state["candidate_id"]),
        candidate_status=str(state["candidate_status"]),
        reopen_count=int(state["reopen_count"]),
        late_evidence_count=int(state["late_evidence_count"]),
    )


def expire_correlation_candidates(
    cur: Any, *, before_utc: datetime, limit: int = 100
) -> tuple[str, ...]:
    if before_utc.tzinfo is None:
        raise ValueError("correlation expiry boundary must be timezone-aware")
    requested = max(1, min(int(limit), 1000))
    boundary = before_utc.astimezone(timezone.utc)
    cur.execute(
        """
        with expiring as (
            select candidate_id from semantic_correlation_candidates
            where candidate_status='matched' and window_end_utc < %s
            order by window_end_utc,candidate_id
            for update skip locked limit %s
        )
        update semantic_correlation_candidates candidate
        set candidate_status='expired',closed_at=now(),updated_at=now()
        from expiring where candidate.candidate_id=expiring.candidate_id
        returning candidate.candidate_id
        """,
        (boundary, requested),
    )
    return tuple(str(item["candidate_id"]) for item in (cur.fetchall() or []))

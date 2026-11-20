"""Durable correlation rule, candidate and replay primitives.

The module has no runtime registration and creates no scenarios, findings or
risk contributions. Callers own transactions and feature-flag enforcement.
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
from server.sli.semantic.semantic_identity import parse_exact_domain_sid_partition


RULE_KINDS = frozenset({
    "action",
    "sequence",
    "all_of",
    "any_of",
    "count",
    "count_then",
    "distinct_count",
    "rate",
    "state_equals",
    "state_changed",
    "relationship_added",
    "relationship_removed",
    "graph_path_created",
    "graph_path_removed",
    "metric_threshold",
    "absence",
    "time_condition",
    "entity_classification",
})
RULE_LIFECYCLE = frozenset({
    "draft", "validated", "test", "shadow", "enabled", "disabled", "deprecated",
})
RULE_TRANSITIONS = {
    "draft": frozenset({"validated", "disabled"}),
    "validated": frozenset({"draft", "test", "disabled"}),
    "test": frozenset({"draft", "shadow", "disabled"}),
    "shadow": frozenset({"enabled", "disabled", "deprecated"}),
    "enabled": frozenset({"disabled", "deprecated"}),
    "disabled": frozenset({"draft", "deprecated"}),
    "deprecated": frozenset(),
}
EXECUTABLE_RULE_STATES = frozenset({"test", "shadow", "enabled"})
MAX_REPLAY_RANGE = timedelta(days=7)
MAX_CLAIM = 16
_FORBIDDEN_DSL_KEYS = frozenset({
    "sql", "shell", "powershell", "python", "csharp", "command", "script",
    "network_call", "http", "url",
})


def _canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(
        dict(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _validate_dsl_value(value: Any, *, path: str = "definition") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            name = str(key).strip().casefold()
            if name in _FORBIDDEN_DSL_KEYS:
                raise ValueError(f"forbidden correlation DSL field: {path}.{key}")
            _validate_dsl_value(item, path=f"{path}.{key}")
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, item in enumerate(value):
            _validate_dsl_value(item, path=f"{path}[{index}]")
        return
    if value is not None and not isinstance(value, (str, int, float, bool)):
        raise ValueError(f"unsupported correlation DSL value at {path}")


@dataclass(frozen=True, kw_only=True)
class CorrelationRuleDefinition:
    rule_id: str
    rule_version: int
    rule_kind: str
    definition: Mapping[str, Any]

    def __post_init__(self) -> None:
        if not self.rule_id.strip() or len(self.rule_id) > 160:
            raise ValueError("rule_id must contain 1..160 characters")
        if self.rule_version <= 0:
            raise ValueError("rule_version must be positive")
        if self.rule_kind not in RULE_KINDS:
            raise ValueError("unsupported correlation rule kind")
        if self.definition.get("type") != self.rule_kind:
            raise ValueError("correlation rule definition type must match rule_kind")
        _validate_dsl_value(self.definition)
        _canonical_json(self.definition)

    @property
    def definition_json(self) -> str:
        return _canonical_json(self.definition)

    @property
    def definition_sha256(self) -> bytes:
        return sha256(self.definition_json.encode("utf-8")).digest()


def _json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    parsed = json.loads(str(value or "{}"))
    if not isinstance(parsed, Mapping):
        raise RuntimeError("correlation JSON must contain an object")
    return dict(parsed)


def register_correlation_rule(cur: Any, *, rule: CorrelationRuleDefinition) -> None:
    """Register an immutable version in DRAFT, accepting only exact replay."""
    cur.execute(
        """
        insert into semantic_correlation_rules(
            rule_id,rule_version,rule_kind,lifecycle_status,
            definition_json,definition_sha256
        ) values (%s,%s,%s,'draft',%s::jsonb,%s)
        on conflict(rule_id,rule_version) do nothing
        """,
        (
            rule.rule_id,
            rule.rule_version,
            rule.rule_kind,
            rule.definition_json,
            rule.definition_sha256,
        ),
    )
    cur.execute(
        """
        select rule_kind,lifecycle_status,definition_json,definition_sha256
        from semantic_correlation_rules where rule_id=%s and rule_version=%s
        """,
        (rule.rule_id, rule.rule_version),
    )
    row = dict(cur.fetchone() or {})
    if not row:
        raise RuntimeError("correlation rule registration did not persist")
    if (
        row.get("rule_kind") != rule.rule_kind
        or _json_object(row.get("definition_json")) != dict(rule.definition)
        or bytes(row.get("definition_sha256") or b"") != rule.definition_sha256
    ):
        raise RuntimeError("correlation rule version replay conflict")


def transition_correlation_rule(
    cur: Any, *, rule_id: str, rule_version: int, target_status: str
) -> str:
    if target_status not in RULE_LIFECYCLE:
        raise ValueError("unsupported correlation rule lifecycle status")
    cur.execute(
        """
        select lifecycle_status from semantic_correlation_rules
        where rule_id=%s and rule_version=%s for update
        """,
        (rule_id, int(rule_version)),
    )
    row = dict(cur.fetchone() or {})
    if not row:
        raise LookupError("correlation rule version not found")
    current = str(row["lifecycle_status"])
    if target_status == current:
        return current
    if target_status not in RULE_TRANSITIONS[current]:
        raise ValueError(f"invalid correlation rule transition: {current} -> {target_status}")
    cur.execute(
        """
        update semantic_correlation_rules
        set lifecycle_status=%s,updated_at=now()
        where rule_id=%s and rule_version=%s and lifecycle_status=%s
        returning lifecycle_status
        """,
        (target_status, rule_id, int(rule_version), current),
    )
    updated = cur.fetchone()
    if not updated:
        raise RuntimeError("correlation rule lifecycle changed concurrently")
    return target_status


def _ensure_executable_rule(cur: Any, *, rule_id: str, rule_version: int) -> None:
    cur.execute(
        """
        select lifecycle_status from semantic_correlation_rules
        where rule_id=%s and rule_version=%s
        for share
        """,
        (rule_id, int(rule_version)),
    )
    row = dict(cur.fetchone() or {})
    if not row:
        raise LookupError("correlation rule version not found")
    if row.get("lifecycle_status") not in EXECUTABLE_RULE_STATES:
        raise RuntimeError("correlation rule is not executable")


def _candidate_key(*, rule_id: str, rule_version: int, contribution_key: str) -> bytes:
    return sha256(
        _canonical_json({
            "rule_id": rule_id,
            "rule_version": int(rule_version),
            "contribution_key": contribution_key,
        }).encode("utf-8")
    ).digest()


def persist_correlation_candidate(
    cur: Any,
    *,
    rule_id: str,
    rule_version: int,
    relation: SemanticRelation,
    evidence_contract: tuple[int, str, str] | None = None,
) -> str:
    """Persist one matched relation and exact normalized-event evidence."""
    if not relation.source_event_ids:
        raise ValueError("correlation candidate requires evidence")
    if relation.confidence not in {"low", "medium", "high"}:
        raise ValueError("unsupported correlation confidence")
    _ensure_executable_rule(cur, rule_id=rule_id, rule_version=rule_version)
    source_ids = tuple(dict.fromkeys(int(item) for item in relation.source_event_ids))
    contract_filter = ""
    parameters: tuple[Any, ...] = (list(source_ids),)
    if evidence_contract is not None:
        semantic_contract_version, normalizer_id, normalizer_version = evidence_contract
        if int(semantic_contract_version) <= 0 or not str(normalizer_id).strip() or not str(normalizer_version).strip():
            raise ValueError("correlation evidence contract is invalid")
        contract_filter = """
          and semantic_contract_version=%s
          and normalizer_id=%s and normalizer_version=%s
        """
        parameters = (
            list(source_ids), int(semantic_contract_version),
            str(normalizer_id), str(normalizer_version),
        )
    cur.execute(
        f"""
        select normalized_event_id,source_event_id,occurred_at_utc,roles_json
        from normalized_events
        where source_event_id=any(%s)
          {contract_filter}
        order by occurred_at_utc,source_event_id
        """,
        parameters,
    )
    rows = [dict(item) for item in (cur.fetchall() or [])]
    by_source = {int(item["source_event_id"]): item for item in rows}
    missing = sorted(set(source_ids) - by_source.keys())
    if missing:
        raise RuntimeError(f"correlation evidence is not normalized: {missing}")
    explicit_partition = str(relation.partition_key or "").strip()
    if explicit_partition:
        if (
            len(explicit_partition) > 512
            or not explicit_partition.startswith("domain:")
            or parse_exact_domain_sid_partition(explicit_partition) is None
        ):
            raise ValueError("correlation candidate partition is not an exact bounded SID key")
        partition_key = explicit_partition
    else:
        hosts = {
            str(_json_object(item["roles_json"]).get("source_host") or "").strip()
            for item in rows
        } - {""}
        if len(hosts) != 1:
            raise RuntimeError("correlation candidate requires one exact source_host partition")
        partition_key = next(iter(hosts))
    times = [item["occurred_at_utc"] for item in rows]
    candidate_key = _candidate_key(
        rule_id=rule_id,
        rule_version=rule_version,
        contribution_key=relation.contribution_key,
    )
    candidate_id = str(
        uuid.uuid5(uuid.NAMESPACE_URL, f"adlog:correlation:{candidate_key.hex()}")
    )
    cur.execute(
        "select pg_advisory_xact_lock(hashtextextended(%s,0))",
        (candidate_key.hex(),),
    )
    cur.execute(
        """
        insert into semantic_correlation_candidates(
            candidate_id,rule_id,rule_version,relation_kind,candidate_status,
            candidate_key,partition_key,window_start_utc,window_end_utc,
            confidence,explanation
        ) values (%s,%s,%s,%s,'matched',%s,%s,%s,%s,%s,%s)
        on conflict(rule_id,rule_version,candidate_key) do nothing
        """,
        (
            candidate_id,
            rule_id,
            int(rule_version),
            relation.relation_kind,
            candidate_key,
            partition_key,
            min(times),
            max(times),
            relation.confidence,
            relation.explanation,
        ),
    )
    cur.execute(
        """
        select candidate_id,relation_kind,partition_key,confidence
        from semantic_correlation_candidates
        where rule_id=%s and rule_version=%s and candidate_key=%s
        for update
        """,
        (rule_id, int(rule_version), candidate_key),
    )
    existing = dict(cur.fetchone() or {})
    if (
        str(existing.get("candidate_id")) != candidate_id
        or existing.get("relation_kind") != relation.relation_kind
        or existing.get("partition_key") != partition_key
    ):
        raise RuntimeError("correlation candidate identity replay conflict")

    for source_event_id in source_ids:
        normalized_id = str(by_source[source_event_id]["normalized_event_id"])
        cur.execute(
            """
            select evidence_order from semantic_correlation_candidate_evidence
            where candidate_id=%s and normalized_event_id=%s
            """,
            (candidate_id, normalized_id),
        )
        if cur.fetchone() is not None:
            continue
        cur.execute(
            """
            select coalesce(max(evidence_order),-1) as last_order
            from semantic_correlation_candidate_evidence where candidate_id=%s
            """,
            (candidate_id,),
        )
        last_order = int(dict(cur.fetchone() or {"last_order": -1})["last_order"])
        cur.execute(
            """
            insert into semantic_correlation_candidate_evidence(
                candidate_id,normalized_event_id,evidence_order
            ) values (%s,%s,%s)
            """,
            (candidate_id, normalized_id, last_order + 1),
        )
    cur.execute(
        """
        select count(*) as evidence_count,max(evidence_order) as maximum_order
        from semantic_correlation_candidate_evidence
        where candidate_id=%s
        """,
        (candidate_id,),
    )
    evidence_state = dict(cur.fetchone() or {})
    if (
        int(evidence_state.get("evidence_count") or 0) > 16384
        or int(evidence_state.get("maximum_order") or -1) >= 16384
    ):
        raise RuntimeError("correlation evidence cannot be safely renumbered")
    # These are deliberately separate statements.  A data-modifying CTE does
    # not guarantee that its first UPDATE becomes visible to a sibling UPDATE,
    # which can transiently violate unique(candidate_id,evidence_order).
    cur.execute(
        """
        update semantic_correlation_candidate_evidence
        set evidence_order=evidence_order+16384
        where candidate_id=%s
        """,
        (candidate_id,),
    )
    cur.execute(
        """
        with ordered as (
            select evidence.normalized_event_id,
                   row_number() over (
                       order by normalized.occurred_at_utc,normalized.source_event_id
                   ) - 1 as evidence_order
            from semantic_correlation_candidate_evidence evidence
            join normalized_events normalized
              on normalized.normalized_event_id=evidence.normalized_event_id
            where evidence.candidate_id=%s
        )
        update semantic_correlation_candidate_evidence evidence
        set evidence_order=ordered.evidence_order
        from ordered
        where evidence.candidate_id=%s
          and evidence.normalized_event_id=ordered.normalized_event_id
        """,
        (candidate_id, candidate_id),
    )
    confidence = max(
        (str(existing.get("confidence") or "low"), relation.confidence),
        key={"low": 0, "medium": 1, "high": 2}.__getitem__,
    )
    cur.execute(
        """
        update semantic_correlation_candidates candidate
        set window_start_utc=least(window_start_utc,%s),
            window_end_utc=greatest(window_end_utc,%s),confidence=%s,
            explanation=%s,last_matched_at=now(),updated_at=now(),
            evidence_count=(select count(*) from semantic_correlation_candidate_evidence evidence
                            where evidence.candidate_id=candidate.candidate_id)
        where candidate_id=%s
        """,
        (min(times), max(times), confidence, relation.explanation, candidate_id),
    )
    return candidate_id


def schedule_correlation_replay(
    cur: Any,
    *,
    rule_id: str,
    rule_version: int,
    range_start_utc: datetime,
    range_end_utc: datetime,
) -> str:
    if range_start_utc.tzinfo is None or range_end_utc.tzinfo is None:
        raise ValueError("correlation replay range must be timezone-aware")
    start = range_start_utc.astimezone(timezone.utc)
    end = range_end_utc.astimezone(timezone.utc)
    if end <= start or end - start > MAX_REPLAY_RANGE:
        raise ValueError("correlation replay range must be within 7 days")
    _ensure_executable_rule(cur, rule_id=rule_id, rule_version=rule_version)
    identity = sha256(
        _canonical_json({
            "rule_id": rule_id,
            "rule_version": int(rule_version),
            "range_start_utc": start.isoformat(),
            "range_end_utc": end.isoformat(),
        }).encode("utf-8")
    ).digest()
    replay_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"adlog:correlation-replay:{identity.hex()}"))
    cur.execute(
        """
        insert into semantic_correlation_replays(
            replay_id,rule_id,rule_version,range_start_utc,range_end_utc,idempotency_key
        ) values (%s,%s,%s,%s,%s,%s)
        on conflict(idempotency_key) do nothing
        """,
        (replay_id, rule_id, int(rule_version), start, end, identity),
    )
    cur.execute(
        """
        select replay_id,rule_id,rule_version,range_start_utc,range_end_utc
        from semantic_correlation_replays where idempotency_key=%s
        """,
        (identity,),
    )
    row = dict(cur.fetchone() or {})
    if str(row.get("replay_id")) != replay_id:
        raise RuntimeError("correlation replay identity conflict")
    return replay_id


def claim_correlation_replays(
    cur: Any, *, limit: int = 1, lease_seconds: int = 300
) -> list[dict[str, Any]]:
    requested = max(1, min(int(limit), MAX_CLAIM))
    lease = max(60, min(int(lease_seconds), 3600))
    lease_token = str(uuid.uuid4())
    cur.execute(
        """
        with candidates as (
            select replay_id from semantic_correlation_replays
            where attempt_count < max_attempts and available_at <= now()
              and (replay_status in ('queued','failed')
                   or (replay_status='leased' and lease_until < now()))
            order by available_at,created_at,replay_id
            for update skip locked limit %s
        )
        update semantic_correlation_replays replay
        set replay_status='leased',attempt_count=attempt_count+1,
            lease_token=%s,lease_until=now()+(%s * interval '1 second'),
            heartbeat_at=now(),updated_at=now(),
            last_error_code=null,last_error_detail=null
        from candidates where replay.replay_id=candidates.replay_id
        returning replay.*
        """,
        (requested, lease_token, lease),
    )
    return [dict(item) for item in (cur.fetchall() or [])]


def heartbeat_correlation_replay(
    cur: Any, *, replay_id: str, lease_token: str, lease_seconds: int = 300
) -> bool:
    lease = max(60, min(int(lease_seconds), 3600))
    cur.execute(
        """
        update semantic_correlation_replays
        set heartbeat_at=now(),lease_until=now()+(%s * interval '1 second'),
            updated_at=now()
        where replay_id=%s and replay_status='leased' and lease_token=%s
        returning replay_id
        """,
        (lease, replay_id, lease_token),
    )
    return cur.fetchone() is not None


def complete_correlation_replay(
    cur: Any,
    *,
    replay_id: str,
    lease_token: str,
    checkpoint_utc: datetime,
    processed_events: int,
    matched_candidates: int,
) -> None:
    if checkpoint_utc.tzinfo is None:
        raise ValueError("correlation replay checkpoint must be timezone-aware")
    if processed_events < 0 or matched_candidates < 0:
        raise ValueError("correlation replay counters must be non-negative")
    cur.execute(
        """
        update semantic_correlation_replays
        set replay_status='completed',completed_at=now(),checkpoint_utc=%s,
            processed_events=%s,matched_candidates=%s,
            lease_token=null,lease_until=null,heartbeat_at=now(),updated_at=now()
        where replay_id=%s and replay_status='leased' and lease_token=%s
          and %s between range_start_utc and range_end_utc
        returning replay_id
        """,
        (
            checkpoint_utc,
            int(processed_events),
            int(matched_candidates),
            replay_id,
            lease_token,
            checkpoint_utc,
        ),
    )
    if cur.fetchone() is None:
        raise RuntimeError("correlation replay lease or checkpoint was invalid")


def fail_correlation_replay(
    cur: Any,
    *,
    replay_id: str,
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
        update semantic_correlation_replays
        set replay_status=%s,available_at=now()+(%s * interval '1 second'),
            lease_token=null,lease_until=null,last_error_code=%s,
            last_error_detail=%s,updated_at=now()
        where replay_id=%s and replay_status='leased' and lease_token=%s
        returning replay_status
        """,
        (
            status,
            retry_seconds,
            error_code[:160],
            error_detail[:1000],
            replay_id,
            lease_token,
        ),
    )
    if cur.fetchone() is None:
        raise RuntimeError("correlation replay lease was lost while recording failure")
    return status

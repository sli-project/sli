"""Pure bounded compiler and matcher for the first correlation DSL slice."""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from bisect import bisect_left
from dataclasses import dataclass
from datetime import timedelta
from hashlib import sha256
import json

from server.sli.semantic.semantic_correlation import SemanticRelation
from server.sli.semantic.semantic_correlation_repository import CorrelationRuleDefinition
from server.sli.semantic.semantic_identity import is_exact_domain_sid
from server.sli.semantic.semantic_processing import CANONICAL_ENTITY_ROLES, NormalizedEvent


MAX_MATCH_INPUTS = 8
MAX_MATCH_EVENTS = 5000
MAX_WINDOW_SECONDS = 86400


@dataclass(frozen=True, kw_only=True)
class CompiledCorrelationRule:
    rule_id: str
    rule_version: int
    rule_kind: str
    input_types: tuple[str, ...]
    join_roles: tuple[str, ...]
    partition_kind: str
    strict_time_order: bool
    continuation_policy: str
    window: timedelta
    minimum_count: int
    output_relation_kind: str
    confidence: str
    explanation: str
    definition_sha256: bytes


def _string_list(value: object, *, name: str, maximum: int) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError(f"{name} must be a list")
    result = tuple(str(item).strip() for item in value if str(item).strip())
    if not result or len(result) > maximum or len(set(result)) != len(result):
        raise ValueError(f"{name} must contain unique bounded values")
    return result


_PARTITION_KINDS = frozenset({
    "source_host", "domain_account_sid", "domain_member_group_sid",
    "domain_account_member_sid",
})
_CONTINUATION_POLICIES = frozenset({"first_admissible", "anchor_all_admissible"})


def _exact_identity(value: object) -> str | None:
    identity = str(value or "").strip()
    return identity if len(identity) <= 184 and is_exact_domain_sid(identity) else None


def _exact_quality(quality: Mapping[str, object], key: str) -> bool:
    detail = quality.get(key)
    return isinstance(detail, Mapping) and str(detail.get("state") or "").strip() == "exact"


def _domain_id(event: NormalizedEvent) -> str | None:
    try:
        domain_id = int(event.facts.get("domain_id"))
    except (TypeError, ValueError):
        return None
    return str(domain_id) if domain_id > 0 else None


def _account_sid(event: NormalizedEvent) -> str | None:
    exact = _exact_identity(event.facts.get("relation_account_sid"))
    if exact and _exact_quality(event.quality, "relation_account_identity"):
        return exact
    role_identity = str(event.roles.get("affected_entity") or "").strip()
    if role_identity.startswith("sid:"):
        return _exact_identity(role_identity[4:])
    return None


def relation_partition_key(
    rule: CompiledCorrelationRule, event: NormalizedEvent
) -> str | None:
    """Return the one explicit partition accepted for this rule and event."""
    if rule.partition_kind == "source_host":
        host = str(event.roles.get("source_host") or "").strip()
        return host if host and len(host) <= 160 else None
    domain_id = _domain_id(event)
    if domain_id is None:
        return None
    if rule.partition_kind == "domain_account_sid":
        account_sid = _account_sid(event)
        return f"domain:{domain_id}|account_sid:{account_sid}" if account_sid else None
    member_sid = _exact_identity(event.facts.get("relation_member_sid"))
    if rule.partition_kind == "domain_member_group_sid":
        group_sid = _exact_identity(event.facts.get("relation_group_sid"))
        if not (member_sid and group_sid and _exact_quality(event.quality, "relation_membership_identity")):
            return None
        return f"domain:{domain_id}|member_sid:{member_sid}|group_sid:{group_sid}"
    if rule.partition_kind == "domain_account_member_sid":
        exact_member_sid = (
            member_sid
            if member_sid and _exact_quality(event.quality, "relation_membership_identity")
            else None
        )
        account_or_member_sid = _account_sid(event) or exact_member_sid
        return (
            f"domain:{domain_id}|account_member_sid:{account_or_member_sid}"
            if account_or_member_sid else None
        )
    return None


def compile_correlation_rule(rule: CorrelationRuleDefinition) -> CompiledCorrelationRule:
    """Compile bounded rule definitions with explicit identity partitions."""
    definition = dict(rule.definition)
    if rule.rule_kind not in {"all_of", "count", "count_then", "sequence"}:
        raise ValueError("rule kind is not supported by the bounded dispatcher")
    input_types = _string_list(
        definition.get("inputs"), name="inputs", maximum=MAX_MATCH_INPUTS
    )
    if rule.rule_kind == "count" and len(input_types) != 1:
        raise ValueError("count matcher requires exactly one input type")
    if rule.rule_kind in {"all_of", "sequence", "count_then"} and len(input_types) < 2:
        raise ValueError(f"{rule.rule_kind} matcher requires at least two input types")
    if rule.rule_kind == "count_then" and len(input_types) != 2:
        raise ValueError("count_then matcher requires failure and terminal input types")
    partition_kind = str(definition.get("partition_kind") or "source_host").strip()
    if partition_kind not in _PARTITION_KINDS:
        raise ValueError("partition_kind is unsupported")
    join_roles: tuple[str, ...] = ()
    if partition_kind == "source_host":
        join_roles = _string_list(
            definition.get("join_roles"), name="join_roles", maximum=4
        )
        if any(role not in CANONICAL_ENTITY_ROLES for role in join_roles):
            raise ValueError("join_roles must use canonical entity roles")
        if "source_host" not in join_roles:
            raise ValueError("join_roles must include source_host")
    elif definition.get("join_roles") not in (None, []):
        raise ValueError("cross-DC partition rules must not declare join_roles")
    continuation_policy = str(
        definition.get("continuation_policy") or "first_admissible"
    ).strip()
    if continuation_policy not in _CONTINUATION_POLICIES:
        raise ValueError("continuation_policy is unsupported")
    if continuation_policy != "first_admissible":
        if rule.rule_kind != "sequence" or len(input_types) != 2 or not bool(definition.get("strict_time_order", False)):
            raise ValueError("anchor_all_admissible requires a strict two-event sequence")
    try:
        window_seconds = int(definition.get("window_seconds"))
    except (TypeError, ValueError) as exc:
        raise ValueError("window_seconds must be an integer") from exc
    if not 1 <= window_seconds <= MAX_WINDOW_SECONDS:
        raise ValueError("window_seconds must be within 24 hours")
    try:
        minimum = int(definition.get("minimum_count", len(input_types)))
    except (TypeError, ValueError) as exc:
        raise ValueError("minimum_count must be an integer") from exc
    if rule.rule_kind in {"count", "count_then"} and not 2 <= minimum <= 1000:
        raise ValueError("minimum_count must be within 2..1000")
    if rule.rule_kind in {"all_of", "sequence"} and minimum != len(input_types):
        raise ValueError(f"{rule.rule_kind} minimum_count must equal its input count")
    if rule.rule_kind == "count_then" and minimum > 1000:
        raise ValueError("count_then minimum_count must be within 2..1000")
    output = str(definition.get("output_relation_kind") or "").strip()
    if not output or len(output) > 200:
        raise ValueError("output_relation_kind is required")
    confidence = str(definition.get("confidence") or "medium").strip().lower()
    if confidence not in {"low", "medium", "high"}:
        raise ValueError("unsupported matcher confidence")
    explanation = str(definition.get("explanation") or "").strip()
    if not explanation or len(explanation) > 2000:
        raise ValueError("matcher explanation is required")
    return CompiledCorrelationRule(
        rule_id=rule.rule_id,
        rule_version=rule.rule_version,
        rule_kind=rule.rule_kind,
        input_types=input_types,
        join_roles=join_roles,
        partition_kind=partition_kind,
        strict_time_order=bool(definition.get("strict_time_order", False)),
        continuation_policy=continuation_policy,
        window=timedelta(seconds=window_seconds),
        minimum_count=minimum,
        output_relation_kind=output,
        confidence=confidence,
        explanation=explanation,
        definition_sha256=rule.definition_sha256,
    )


def _group_key(event: NormalizedEvent, rule: CompiledCorrelationRule) -> tuple[str, ...] | None:
    if rule.partition_kind != "source_host":
        partition_key = relation_partition_key(rule, event)
        return (partition_key,) if partition_key else None
    values = tuple(str(event.roles.get(role) or "").strip() for role in rule.join_roles)
    return values if all(values) else None


def _contribution_key(
    rule: CompiledCorrelationRule,
    group: tuple[str, ...],
    first: NormalizedEvent,
) -> str:
    payload = json.dumps(
        {
            "rule_id": rule.rule_id,
            "rule_version": rule.rule_version,
            "group": group,
            "anchor_event_id": first.source_event_id,
            "anchor_time": first.occurred_at_utc.isoformat(),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return f"dispatch:{sha256(payload.encode('utf-8')).hexdigest()}"


def match_compiled_rule(
    rule: CompiledCorrelationRule,
    events: Sequence[NormalizedEvent],
) -> list[SemanticRelation]:
    if len(events) > MAX_MATCH_EVENTS:
        raise ValueError("dispatcher context exceeds 5000 events")
    allowed = set(rule.input_types)
    grouped: dict[tuple[str, ...], list[NormalizedEvent]] = defaultdict(list)
    for event in events:
        if event.semantic_type not in allowed:
            continue
        key = _group_key(event, rule)
        if key is not None:
            grouped[key].append(event)
    relations: list[SemanticRelation] = []
    for group, members in sorted(grouped.items()):
        ordered = sorted(members, key=lambda item: (item.occurred_at_utc, item.source_event_id))
        positions_by_type: dict[str, list[int]] = defaultdict(list)
        for position, item in enumerate(ordered):
            positions_by_type[item.semantic_type].append(position)
        index = 0
        window_end = 0
        while index < len(ordered):
            first = ordered[index]
            window_end = max(window_end, index + 1)
            while (
                window_end < len(ordered)
                and ordered[window_end].occurred_at_utc - first.occurred_at_utc
                <= rule.window
            ):
                window_end += 1
            if rule.rule_kind == "count":
                if window_end - index < rule.minimum_count:
                    index += 1
                    continue
                evidence = tuple(
                    item.source_event_id for item in ordered[index:window_end]
                )
                next_index = window_end
            elif rule.rule_kind == "count_then":
                if first.semantic_type != rule.input_types[-1]:
                    index += 1
                    continue
                preceding = [
                    item for item in ordered[:index]
                    if item.semantic_type == rule.input_types[0]
                    and item.occurred_at_utc < first.occurred_at_utc
                    and first.occurred_at_utc - item.occurred_at_utc <= rule.window
                ]
                if len(preceding) < rule.minimum_count:
                    index += 1
                    continue
                evidence = tuple(item.source_event_id for item in (*preceding, first))
                next_index = index + 1
            elif rule.rule_kind == "all_of":
                selected: list[NormalizedEvent] = []
                selected_positions: list[int] = []
                for semantic_type in rule.input_types:
                    candidates = positions_by_type[semantic_type]
                    candidate_offset = bisect_left(candidates, index)
                    if (
                        candidate_offset >= len(candidates)
                        or candidates[candidate_offset] >= window_end
                        or (
                            rule.strict_time_order and selected
                            and ordered[candidates[candidate_offset]].occurred_at_utc
                            <= selected[-1].occurred_at_utc
                        )
                    ):
                        selected = []
                        break
                    selected_position = candidates[candidate_offset]
                    selected_positions.append(selected_position)
                    selected.append(ordered[selected_position])
                if not selected:
                    index += 1
                    continue
                evidence = tuple(dict.fromkeys(item.source_event_id for item in selected))
                next_index = max(selected_positions) + 1
            else:
                if first.semantic_type != rule.input_types[0]:
                    index += 1
                    continue
                if rule.continuation_policy == "anchor_all_admissible":
                    continuations = [
                        item for item in ordered[index + 1:window_end]
                        if item.semantic_type == rule.input_types[1]
                        and item.occurred_at_utc > first.occurred_at_utc
                    ]
                    if not continuations:
                        index += 1
                        continue
                    evidence = tuple(
                        item.source_event_id for item in (first, *continuations)
                    )
                    next_index = index + 1
                    relations.append(
                        SemanticRelation(
                            relation_kind=rule.output_relation_kind,
                            source_event_ids=evidence,
                            contribution_key=_contribution_key(rule, group, first),
                            confidence=rule.confidence,
                            explanation=rule.explanation,
                            partition_key=(group[0] if rule.partition_kind != "source_host" else None),
                        )
                    )
                    index = next_index
                    continue
                selected = [first]
                selected_positions = [index]
                prior_position = index
                for semantic_type in rule.input_types[1:]:
                    candidates = positions_by_type[semantic_type]
                    candidate_offset = bisect_left(candidates, prior_position + 1)
                    if (
                        candidate_offset >= len(candidates)
                        or candidates[candidate_offset] >= window_end
                        or (
                            rule.strict_time_order
                            and ordered[candidates[candidate_offset]].occurred_at_utc
                            <= selected[-1].occurred_at_utc
                        )
                    ):
                        selected = []
                        break
                    prior_position = candidates[candidate_offset]
                    selected_positions.append(prior_position)
                    selected.append(ordered[prior_position])
                if not selected:
                    index += 1
                    continue
                evidence = tuple(item.source_event_id for item in selected)
                next_index = selected_positions[-1] + 1
            relations.append(
                SemanticRelation(
                    relation_kind=rule.output_relation_kind,
                    source_event_ids=evidence,
                    contribution_key=_contribution_key(rule, group, first),
                    confidence=rule.confidence,
                    explanation=rule.explanation,
                    partition_key=(group[0] if rule.partition_kind != "source_host" else None),
                )
            )
            index = next_index
    return relations

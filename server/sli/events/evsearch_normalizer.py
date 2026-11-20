"""Pure ES02 normalization and versioned predicates for evsearch.v1.

Readers compile these predicates only after checking their ``required_fields``
against the ES01 publication/scope policy. The projection matchers are a shared
semantic oracle, not a reader or an authorization decision. They consume stable
IDs and server-confirmed facts; display names and raw payloads have no role.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from types import MappingProxyType
from typing import Any

from server.sli.core.time_contract import TimeRangeError, normalize_utc_range
from server.sli.events.evsearch_contract import (
    CONTRACT_VERSION,
    FIELDS,
    GROUPING_VERSION,
    MAX_VALUES,
    ContractError,
    validate_request,
)


@dataclass(frozen=True)
class Condition:
    field: str
    operator: str
    values: tuple[str | int, ...] = ()
    role: str | None = None

    def as_request(self) -> dict[str, Any]:
        result: dict[str, Any] = {"field": self.field, "operator": self.operator}
        if self.role is not None:
            result["role"] = self.role
        if self.operator not in {"exists", "missing"}:
            result["value"] = self.values[0] if self.operator == "eq" else list(self.values)
        return result


@dataclass(frozen=True)
class Period:
    start: datetime
    end: datetime
    timezone: str

    def as_request(self) -> dict[str, str]:
        return {
            "preset": "custom", "from": self.start.isoformat().replace("+00:00", "Z"),
            "to": self.end.isoformat().replace("+00:00", "Z"), "timezone": self.timezone,
        }


@dataclass(frozen=True)
class AccountParticipant:
    entity_id: int
    role: str
    kind: str = "unknown"
    privileged: bool | None = None


@dataclass(frozen=True)
class QuestionPredicate:
    question_id: str
    alternatives: tuple[tuple[Condition, ...], ...]
    account_role: str
    confirmed_privilege: bool = False
    # Reader proof of a NEW effective privilege grant to the target, not a
    # baseline import, a group name, or membership in an arbitrary group.
    confirmed_grant: bool = False
    version: str = "evsearch.questions.v1"

    @property
    def required_fields(self) -> frozenset[str]:
        fields = {c.field for branch in self.alternatives for c in branch}
        if self.confirmed_privilege:
            fields.update({"account", "account_privileged"})
        if self.confirmed_grant:
            fields.add("privilege_grant_confirmed")
        return frozenset(fields)


def _security_events(*ids: int) -> tuple[Condition, ...]:
    return (
        Condition("provider", "in", ("Microsoft-Windows-Security-Auditing",)),
        Condition("channel", "in", ("Security",)),
        Condition("event_id", "in", ids),
    )


QUESTIONS = MappingProxyType({
    "failed_logons": QuestionPredicate("failed_logons", (
        _security_events(4625, 4771, 6273),
        (*_security_events(4776), Condition("outcome", "in", ("failure",))),
    ), "target"),
    "lockouts": QuestionPredicate("lockouts", (_security_events(4740),), "target"),
    "admin_logons": QuestionPredicate("admin_logons", (_security_events(4624),), "target", confirmed_privilege=True),
    "new_admins": QuestionPredicate("new_admins", (_security_events(4728, 4732, 4756),), "target", confirmed_grant=True),
    "group_changes": QuestionPredicate("group_changes", (
        _security_events(4727, 4728, 4729, 4730, 4731, 4732, 4733, 4734, 4735, 4737, 4754, 4755, 4756, 4757, 4758, 4764),
    ), "actor"),
    "log_cleared": QuestionPredicate("log_cleared", (
        _security_events(1102),
        (Condition("provider", "in", ("Microsoft-Windows-Eventlog",)),
         Condition("channel", "in", ("System",)), Condition("event_id", "in", (104,))),
    ), "actor"),
})


@dataclass(frozen=True)
class NormalizedSearch:
    conditions: tuple[Condition, ...]
    period: Period
    question: QuestionPredicate | None
    exclude_machine_system: bool
    account_role: str
    q: str | None
    sort: str
    page_size: int
    entry_context: Mapping[str, Any] | None

    @property
    def required_fields(self) -> frozenset[str]:
        fields = {condition.field for condition in self.conditions}
        if self.question:
            fields.update(self.question.required_fields)
        if self.exclude_machine_system:
            fields.update({"account", "account_kind"})
        if self.q:
            fields.add("q")
        return frozenset(fields)

    def as_request(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "contract_version": CONTRACT_VERSION, "grouping_version": GROUPING_VERSION,
            "conditions": [condition.as_request() for condition in self.conditions],
            "period": self.period.as_request(), "exclude_machine_system": self.exclude_machine_system,
            "sort": self.sort, "page_size": self.page_size,
        }
        if self.question:
            result["question_id"] = self.question.question_id
        if self.q:
            result["q"] = self.q
        if self.entry_context is not None:
            result["entry_context"] = dict(self.entry_context)
        return result


def _period(raw: Mapping[str, Any], now: datetime | None, allowed_period: Period | None) -> Period:
    zone = raw["timezone"]
    try:
        if raw["preset"] == "custom":
            start, end = normalize_utc_range(raw["from"], raw["to"], timezone_name=zone)
        else:
            # Validate the timezone even when both instants already carry UTC.
            normalize_utc_range(None, None, timezone_name=zone)
            instant = datetime.now(timezone.utc) if now is None else now
            if instant.tzinfo is None or instant.utcoffset() is None:
                raise ContractError("invalid_period")
            end_dt = instant.astimezone(timezone.utc)
            delta = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}[raw["preset"]]
            start, end = (end_dt - delta).isoformat(), end_dt.isoformat()
        assert start is not None and end is not None
        period = Period(datetime.fromisoformat(start), datetime.fromisoformat(end), zone)
    except (TimeRangeError, ValueError, OverflowError):
        raise ContractError("invalid_period") from None
    if period.end - period.start > timedelta(days=90):
        raise ContractError("period_too_wide")
    if allowed_period and (period.start < allowed_period.start or period.end > allowed_period.end):
        raise ContractError("period_outside_scope")
    return period


def _conditions(raw: list[dict[str, Any]]) -> tuple[Condition, ...]:
    # A request describes selected values, not UI clicks. Duplicate selections
    # are idempotent; opposite selections move the value to the last operation.
    selections: dict[tuple[str, str | None], dict[str | int, str]] = {}
    presence: dict[tuple[str, str | None], str] = {}
    for item in raw:
        key = (item["field"], item.get("role"))
        operator = item["operator"]
        selections.setdefault(key, {})
        if operator in {"exists", "missing"}:
            if key in presence and presence[key] != operator:
                raise ContractError("invalid_condition")
            presence[key] = operator
            continue
        values = [item["value"]] if operator == "eq" else item["value"]
        for value in values:
            if key[0] == "ip":
                value = str(ip_address(value))
            selections[key][value] = "not_in" if operator == "not_in" else "in"
    result = []
    for field, role in sorted(selections, key=lambda key: (key[0], key[1] or "")):
        selected = selections[(field, role)]
        for operator in ("in", "not_in"):
            values = tuple(sorted(value for value, op in selected.items() if op == operator))
            if len(values) > MAX_VALUES:
                raise ContractError("invalid_condition")
            if values:
                canonical_operator = operator
                if operator == "in" and "in" not in FIELDS[field].operators:
                    if len(values) != 1:
                        raise ContractError("invalid_condition")
                    canonical_operator = "eq"
                result.append(Condition(field, canonical_operator, values, role))
        if (field, role) in presence:
            result.append(Condition(field, presence[(field, role)], role=role))
    return tuple(result)


def normalize_request(
    raw: Mapping[str, Any], *, now: datetime | None = None, allowed_period: Period | None = None,
) -> NormalizedSearch:
    """Resolve one run, without I/O, silent clipping or resolving display names.

    ``allowed_period`` is a server-issued dataset window, never client input.
    Relative presets are elapsed UTC durations; custom dates use time_contract
    (inclusive local date end becomes the next midnight, DST rules included).
    """
    if not isinstance(raw, Mapping):
        raise ContractError("invalid_request")
    request = validate_request({"period": {"preset": "24h", "timezone": "UTC"}, **raw})
    question_id = request.get("question_id")
    question = QUESTIONS.get(question_id) if question_id else None
    if question_id and question is None:
        raise ContractError("unsupported_question")
    context = request.get("entry_context")
    role = "any"
    if context and context.get("kind") == "entity" and context.get("role") in {"actor", "target", "any"}:
        role = context["role"]
    if question:
        role = question.account_role
    conditions = _conditions(request.get("conditions", []))
    # Canonicalization must preserve the ES01 wire contract, including the
    # positive provider/channel context required for Event ID conditions.
    validate_request({**request, "conditions": [c.as_request() for c in conditions]})
    return NormalizedSearch(
        conditions, _period(request["period"], now, allowed_period), question,
        request.get("exclude_machine_system", False), role, request.get("q"),
        request.get("sort", "time_desc"), request.get("page_size", 50),
        MappingProxyType(context) if context is not None else None,
    )


def _participants(event: Mapping[str, Any], role: str) -> tuple[AccountParticipant, ...]:
    return tuple(p for p in (event.get("accounts") or ()) if p.role in {"actor", "target"} and (role == "any" or p.role == role))


def matches_conditions(conditions: tuple[Condition, ...], event: Mapping[str, Any]) -> bool:
    """AND fields/roles, OR included values; NOT IN keeps NULL/missing values.

    Multi-valued accounts are evaluated once per event. Exclusion rejects the
    event if *any* participant in the requested role has a forbidden stable ID.
    Other fields are scalar normalized values in the reader projection.
    """
    for condition in conditions:
        if condition.field == "account":
            values = {p.entity_id for p in _participants(event, condition.role or "any")}
        else:
            value = event.get(condition.field)
            values = set() if value is None else {value}
        if condition.operator == "exists" and not values:
            return False
        if condition.operator == "missing" and values:
            return False
        if condition.operator in {"eq", "in"} and not values.intersection(condition.values):
            return False
        if condition.operator == "not_in" and values.intersection(condition.values):
            return False
    return True


def matches_question(question: QuestionPredicate, event: Mapping[str, Any]) -> bool:
    if not any(matches_conditions(branch, event) for branch in question.alternatives):
        return False
    if question.confirmed_privilege and not any(p.privileged is True for p in _participants(event, question.account_role)):
        return False
    if question.confirmed_grant and event.get("privilege_grant_confirmed") is not True:
        return False
    return True


def matches_account_kind(search: NormalizedSearch, event: Mapping[str, Any]) -> bool:
    """Unknown and service accounts stay visible; never infer kind from a name."""
    return not search.exclude_machine_system or not any(
        p.kind in {"machine", "system"} for p in _participants(event, search.account_role)
    )

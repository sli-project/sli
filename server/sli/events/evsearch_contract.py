"""evsearch.v1 boundary contract; no readers, persistence or HTTP side effects.

Fields in different conditions are ANDed; values of an ``in`` condition are
ORed. ``not_in`` retains missing values; ``exists`` is the explicit way to
exclude them. Participant exclusion matches any entity in the selected role.
Readers must apply the issued scope and the published definition before any
rows, counts, facets, grouping, export or other aggregates are produced.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from ipaddress import ip_address
from types import MappingProxyType
from typing import Any

from server.sli.access.scope import AccessScope
from server.sli.reporting.reporting_v4_definitions import _definition_columns, _json_mapping
from server.sli.reporting.v2.access import resolve_access_scope
from server.sli.reporting.v2.definition import AccessRule

CONTRACT_VERSION = "evsearch.v1"
API_NAMESPACE = "/api/v1/event-search"
ACCESS_KEY = "events.explorer"
LEGACY_REPORT_KEY = "events.journal"
DATASET_KEY = "events.v2"
GROUPING_VERSION = "evsearch.group.v1"
OPERATORS = frozenset({"eq", "in", "not_in", "exists", "missing"})
SORTS = frozenset({"time_desc", "time_asc", "count_desc"})
MAX_CONDITIONS = 32
MAX_VALUES = 100
MAX_TEXT = 256
MAX_Q = 256
MAX_PAGE_SIZE = 100


class ContractError(ValueError):
    """Only a localizable code, never a request value, enters the exception."""

    def __init__(self, code: str):
        self.code = f"evsearch.{code}"
        super().__init__(self.code)


@dataclass(frozen=True)
class Field:
    value_type: str
    operators: frozenset[str] = OPERATORS
    roles: frozenset[str] = frozenset()
    choices: frozenset[str] = frozenset()


# Canonical field keys are also publication keys. A field absent from the
# published dataset/report is unavailable, even if a storage reader has it.
FIELDS = MappingProxyType({
    "action": Field("text"),
    "outcome": Field("text"),
    "reason": Field("text"),
    "account": Field("id", roles=frozenset({"actor", "target", "any"})),
    "source_station": Field("id"),
    "server_id": Field("id"),
    "domain_id": Field("id"),
    "channel": Field("text"),
    "provider": Field("text"),
    "ip": Field("ip"),
    "related_object": Field("id"),
    "event_id": Field("event_id"),
    # Explicit compatibility predicates, never inferred from an action label.
    "category": Field("text"),
    "risk": Field("text"),
    "tier": Field("text"),
    "legacy_journal_view": Field("text", frozenset({"eq"}), choices=frozenset({"attention", "authentication", "accounts", "tasks"})),
    "legacy_journal_q": Field("text", frozenset({"eq"})),
    "legacy_search_q": Field("text", frozenset({"eq"})),
    "file_path": Field("text"),
    "message_sample": Field("text"),
})
REQUEST_KEYS = frozenset({
    "contract_version", "question_id", "conditions", "period", "q",
    "exclude_machine_system", "grouping_version", "sort", "page_size", "entry_context",
})


def _object(value: Any, keys: set[str] | frozenset[str]) -> Mapping:
    if not isinstance(value, Mapping) or set(value) - keys:
        raise ContractError("invalid_request")
    return value


def _text(value: Any, limit: int = MAX_TEXT) -> bool:
    return isinstance(value, str) and 0 < len(value) <= limit and value.strip() == value and not any(ord(c) < 32 or ord(c) == 127 for c in value)


def _value(value: Any, kind: str) -> bool:
    if kind in {"id", "event_id"}:
        return type(value) is int and (0 if kind == "event_id" else 1) <= value <= (2**31 - 1 if kind == "event_id" else 2**63 - 1)
    if not _text(value):
        return False
    if kind == "ip":
        try:
            ip_address(value)
        except ValueError:
            return False
    return True


def validate_request(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Validate wire shape only. ES02 owns time/question/condition normalization.

    No unknown condition is discarded. Stable entity IDs cannot be replaced
    with display names. All values are copied so caller mutation cannot alter
    a validated request. No client-provided access or publication is accepted.
    """
    _object(raw, REQUEST_KEYS)
    if raw.get("contract_version") != CONTRACT_VERSION:
        raise ContractError("unsupported_version")
    if raw.get("grouping_version", GROUPING_VERSION) != GROUPING_VERSION:
        raise ContractError("unsupported_version")
    if not isinstance(raw.get("sort", "time_desc"), str) or raw.get("sort", "time_desc") not in SORTS:
        raise ContractError("invalid_request")
    size = raw.get("page_size", 50)
    if type(size) is not int or not 1 <= size <= MAX_PAGE_SIZE:
        raise ContractError("invalid_request")
    if type(raw.get("exclude_machine_system", False)) is not bool:
        raise ContractError("invalid_request")
    if "q" in raw and not _text(raw["q"], MAX_Q):
        raise ContractError("invalid_request")
    if "question_id" in raw and not _text(raw["question_id"], 64):
        raise ContractError("invalid_request")
    period = _object(raw.get("period"), frozenset({"preset", "from", "to", "timezone"}))
    preset = period.get("preset")
    if not isinstance(preset, str) or preset not in {"24h", "7d", "30d", "custom"} or not _text(period.get("timezone"), 64):
        raise ContractError("invalid_period")
    if preset == "custom":
        if not all(_text(period.get(key), 64) for key in ("from", "to")):
            raise ContractError("invalid_period")
    elif set(period) & {"from", "to"}:
        raise ContractError("invalid_period")
    if "entry_context" in raw:
        context = _object(raw["entry_context"], frozenset({"kind", "finding_id", "entity_id", "role", "return_to"}))
        if context.get("kind") not in ("question", "finding", "entity"):
            raise ContractError("invalid_request")
        for key in ("finding_id", "entity_id"):
            if key in context and not _value(context[key], "id"):
                raise ContractError("invalid_request")
        if "role" in context and context["role"] not in ("actor", "target", "any", "source_station", "related_object"):
            raise ContractError("invalid_request")
        if "return_to" in context and not safe_return_to(context["return_to"]):
            raise ContractError("invalid_request")
    conditions = raw.get("conditions", [])
    if not isinstance(conditions, list) or len(conditions) > MAX_CONDITIONS:
        raise ContractError("invalid_condition")
    for condition in conditions:
        _object(condition, frozenset({"field", "operator", "value", "role"}))
        key, operator = condition.get("field"), condition.get("operator")
        if not isinstance(key, str) or key not in FIELDS:
            raise ContractError("unsupported_field")
        field = FIELDS[key]
        if not isinstance(operator, str) or operator not in field.operators:
            raise ContractError("unsupported_operator")
        if field.roles:
            if not isinstance(condition.get("role"), str) or condition["role"] not in field.roles:
                raise ContractError("invalid_condition")
        elif "role" in condition:
            raise ContractError("invalid_condition")
        if operator in {"exists", "missing"}:
            if "value" in condition:
                raise ContractError("invalid_condition")
            continue
        values = condition.get("value")
        if operator == "eq":
            values = [values]
        if not isinstance(values, list) or not 1 <= len(values) <= MAX_VALUES or not all(_value(v, field.value_type) for v in values):
            raise ContractError("invalid_condition")
        if field.choices and any(v not in field.choices for v in values):
            raise ContractError("invalid_condition")
    if any(c["field"] == "event_id" and c["operator"] not in {"exists", "missing"} for c in conditions):
        if not any(c["field"] in {"provider", "channel"} and c["operator"] in {"eq", "in"} for c in conditions):
            raise ContractError("event_context_required")
    return deepcopy(dict(raw))


def safe_return_to(value: Any) -> bool:
    """A return hint is navigation only, never an access decision."""
    from urllib.parse import unquote, urlsplit

    if not _text(value, 2048):
        return False
    decoded = unquote(value)
    if "\\" in decoded or any(ord(c) < 32 or ord(c) == 127 for c in decoded):
        return False
    try:
        parsed = urlsplit(decoded)
    except ValueError:
        return False
    import re

    allowed = r"/app/(?:event-search|security-events-report|report/[a-z0-9][a-z0-9_.-]{1,79}|events(?:/\d+)?|entities(?:/\d+)?|objects|investigations(?:/\d+)?)"
    return not parsed.scheme and not parsed.netloc and re.fullmatch(allowed, parsed.path) is not None


@dataclass(frozen=True)
class SearchPolicy:
    scope: AccessScope
    fields: frozenset[str]
    action: str
    dataset_key: str = DATASET_KEY
    report_key: str = ACCESS_KEY


def authorize_request(
    request: Mapping[str, Any], *, access: Mapping[str, Any],
    publication: Mapping[str, Any], fields: tuple[str, ...], action: str = "view",
) -> SearchPolicy:
    """Bind server-loaded publication and grants; never combine partial grants.

    ``publication`` has the existing reporting_v4 definition-row shape. ES03
    loads it from the registry. New semantic projections require publication;
    this declaration grants none and changes no existing assignments.
    """
    request = validate_request(request)
    if action not in {"view", "export"}:
        raise ContractError("unsupported_action")
    if publication.get("dataset_key") != DATASET_KEY:
        raise PermissionError("evsearch.policy_denied")
    definition = _json_mapping(publication.get("definition_json"))
    if action not in (definition.get("actions") or ["view"]):
        raise PermissionError("evsearch.policy_denied")
    if action == "export" and ("reports.export" not in (access.get("capabilities") or []) or definition.get("export_policy") != "controlled"):
        raise PermissionError("evsearch.policy_denied")
    field_defs = {item["key"]: item for item in publication.get("fields_json") or []}
    columns = set(_definition_columns(definition, field_defs))
    required = set(fields) | {c["field"] for c in request.get("conditions", [])}
    if request.get("q"):
        required.add("q")
    if request.get("exclude_machine_system"):
        required.add("account_kind")
    # Questions are executable predicates and must declare their dependencies
    # in a server-owned publication, just like filters and output fields.
    if request.get("question_id"):
        dependencies = (definition.get("evsearch_questions") or {}).get(request["question_id"])
        if not isinstance(dependencies, list) or not dependencies:
            raise ContractError("unsupported_question")
        required.update(dependencies)
    if not fields or not required <= columns:
        raise PermissionError("evsearch.policy_denied")
    categories = frozenset(field_defs[key].get("category") for key in required)
    if any(not isinstance(category, str) or not category for category in categories):
        raise PermissionError("evsearch.policy_denied")
    try:
        base = resolve_access_scope(access, AccessRule(ACCESS_KEY), "view")
        scope = resolve_access_scope(access, AccessRule(ACCESS_KEY, required_fields=categories), action)
    except PermissionError as exc:
        raise PermissionError("evsearch.policy_denied") from exc
    if not scope.covers(base):
        raise PermissionError("evsearch.policy_denied")
    return SearchPolicy(base, frozenset(required), action)

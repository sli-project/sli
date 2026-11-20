"""Fail-closed legacy-link translation. Existing routes remain untouched.

Journal view/q predicates preserve the old report's semantics explicitly;
they are not relabelled as a new category or a broader free-text search.
ES03 must publish/implement those predicates before they become executable.
ES29 owns redirects and the UI fallback to the original compatible report.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from server.sli.events.evsearch_contract import (
    CONTRACT_VERSION, ContractError, validate_request,
)

# The server resolver must check access and exact identity. Zero/multiple
# matches are errors, never a reason to drop the condition or pick the first.
IdentityResolver = Callable[[str, str, str | None], Sequence[int]]
LEGACY_KEYS = frozenset({
    "q", "view", "category", "server", "servers", "account", "user", "subject",
    "initiator", "target", "object", "event_id", "event_ids", "channel", "provider",
    "source", "time_from", "time_to", "from", "to", "timezone", "period",
    "risk", "tier", "order", "limit", "cursor", "offset", "return_to",
})
JOURNAL_KEYS = frozenset({
    "q", "view", "server", "time_from", "time_to", "from", "to", "timezone",
    "period", "limit", "cursor", "offset", "return_to", "order",
})


@dataclass(frozen=True)
class LegacyTranslation:
    request: dict[str, Any]
    notices: tuple[str, ...]
    start_empty: bool


def translate_legacy(
    query: Mapping[str, list[str]], *, source: str = "journal",
    resolve_identity: IdentityResolver | None = None,
) -> LegacyTranslation:
    """Translate parse_qs input, rejecting lossy, ambiguous or unknown filters.

    Account/server display strings require an authorized stable-ID resolver.
    Dates remain unnormalized here; the common ES02 time contract resolves
    them once. A half-bounded legacy range cannot silently become 24 hours.
    """
    if source not in {"journal", "search"} or not isinstance(query, Mapping) or set(query) - LEGACY_KEYS:
        raise ContractError("legacy_unsupported_filter")
    if source == "journal" and set(query) - JOURNAL_KEYS:
        raise ContractError("legacy_unsupported_filter")
    for key, values in query.items():
        if not isinstance(values, list) or not values or not all(isinstance(v, str) and v.strip() == v and v for v in values):
            raise ContractError("legacy_unsupported_filter")
        if key not in {"event_id", "event_ids"} and len(values) != 1:
            raise ContractError("legacy_ambiguous_filter")

    def one(*aliases: str) -> str | None:
        values = [query[key][0] for key in aliases if key in query]
        if len(set(values)) > 1:
            raise ContractError("legacy_ambiguous_filter")
        return values[0] if values else None

    conditions: list[dict[str, Any]] = []

    def condition(field: str, value: Any, role: str | None = None, operator: str = "eq") -> None:
        item = {"field": field, "operator": operator, "value": value}
        if role:
            item["role"] = role
        conditions.append(item)

    def identity(field: str, value: str, role: str | None = None) -> int:
        if resolve_identity is None:
            raise ContractError("legacy_identity_unresolved")
        matches = resolve_identity(field, value, role)
        if len(matches) != 1 or type(matches[0]) is not int or not 0 < matches[0] < 2**63:
            raise ContractError("legacy_identity_unresolved")
        return matches[0]

    view = one("view")
    if view and view not in {"all", "attention", "authentication", "accounts", "tasks"}:
        raise ContractError("legacy_unsupported_filter")
    if source == "journal" and view and view != "all":
        condition("legacy_journal_view", view)
    elif source == "search" and view and view != "all":
        if view == "attention":
            condition("risk", "high")
        else:
            condition("category", {"authentication": "authentication", "accounts": "account_management", "tasks": "service_task"}[view])
    for key in ("category", "risk", "tier"):
        if one(key):
            # The old search gives explicit category/risk precedence over view.
            if source == "search":
                conditions[:] = [c for c in conditions if c["field"] != key]
            condition(key, one(key))
    if one("q"):
        condition(f"legacy_{source}_q", one("q"))
    for aliases, role in ((("account", "user"), "any"), (("subject", "initiator"), "actor"), (("target", "object"), "target")):
        value = one(*aliases)
        if value:
            condition("account", identity("account", value, role), role)
    server = one("server", "servers")
    if server:
        # The journal matches one hostname exactly; only the separate search
        # API historically treated a comma-separated server value as a list.
        names = server.split(",") if source == "search" else [server]
        if any(not name.strip() for name in names):
            raise ContractError("legacy_unsupported_filter")
        condition("server_id", [identity("server_id", name.strip()) for name in names], operator="in")
    for field, aliases in (("provider", ("provider", "source")), ("channel", ("channel",))):
        value = one(*aliases)
        if value:
            condition(field, value)
    if "event_id" in query and "event_ids" in query:
        raise ContractError("legacy_ambiguous_filter")
    ids = query.get("event_id", query.get("event_ids", []))
    if ids:
        values = [v for item in ids for v in item.split(",")]
        if not all(v.isascii() and v.isdecimal() and len(v) <= 10 for v in values):
            raise ContractError("legacy_unsupported_filter")
        condition("event_id", [int(v) for v in values], operator="in")
    start, end = one("time_from", "from"), one("time_to", "to")
    if bool(start) != bool(end):
        raise ContractError("invalid_period")
    if start and one("period") not in {None, "custom"}:
        raise ContractError("invalid_period")
    period = {"preset": "custom" if start else one("period") or "24h", "timezone": one("timezone") or "UTC"}
    if start:
        period.update({"from": start, "to": end})
    order = one("order") or "desc"
    if order not in {"asc", "desc"}:
        raise ContractError("legacy_unsupported_filter")
    request: dict[str, Any] = {
        "contract_version": CONTRACT_VERSION, "conditions": conditions, "period": period,
        "sort": f"time_{order}", "exclude_machine_system": False,
    }
    if one("limit"):
        value = one("limit")
        if not value.isascii() or not value.isdecimal() or len(value) > 3:
            raise ContractError("legacy_unsupported_filter")
        request["page_size"] = int(value)
    if one("return_to"):
        request["entry_context"] = {"kind": "question", "return_to": one("return_to")}
    notices = ("evsearch.legacy_paging_reset",) if "cursor" in query or "offset" in query else ()
    return LegacyTranslation(validate_request(request), notices, not bool(conditions or start))

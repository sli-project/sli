"""ES03 bounded hot-event reader; publication and scope precede every row.

This is the PG input to later snapshot/group/aggregate stages, not an HTTP
handler. It never scans raw payloads, guesses identities from names, or treats
an unavailable semantic projection as an absent filter.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
import json
import re
from time import monotonic
from types import MappingProxyType
from typing import Any

from server.sli.access.access_control_v4 import effective_access
from server.sli.access.scope import AccessScope
from server.sli.core.database import query_rows_bounded
from server.sli.events.evsearch_contract import (
    ACCESS_KEY, ContractError, SearchPolicy, authorize_request,
)
from server.sli.events.evsearch_normalizer import (
    Condition, NormalizedSearch, Period, normalize_request,
)
from server.sli.events.evsearch_ownership import EventIdentity, OwnershipError, StoreCapture, capture_binding
from server.sli.events.evsearch_snapshot import MAX_EVENTS, MAX_SNAPSHOT_BYTES, _hash, _json_default, _query_hash
from server.sli.reporting.reporting_v4_definitions import _json_mapping

TIMEOUT_MS = 5000
DEFAULT_FIELDS = ("id", "time_created_utc", "event_id", "channel")
# Authentication outcome only. A logout/service/protection event never becomes
# a successful logon. The 4776 status rule mirrors the source pack's
# _semantic_result_facts; missing status stays unknown.
AUTH_OUTCOME = """case when channel.value='Security'
    and provider.value='Microsoft-Windows-Security-Auditing' then
    case when e.event_id in (4625,4771,6273) then 'failure'
         when e.event_id in (4624,6272) then 'success'
         when e.event_id=4776 and nullif(btrim(facts.result_code),'') is not null then
              case when lower(btrim(facts.result_code)) in ('0','0x0','0x00000000','00000000')
                   then 'success' else 'failure' end
    end end"""
# Only storage-backed projections belong here. Catalog labels, risk, account
# classification/privilege, and legacy semantic predicates need their own
# proven projection; publication alone cannot manufacture one.
SCALARS = MappingProxyType({
    "id": "e.id", "time_created_utc": "e.time_created_utc",
    "event_id": "e.event_id", "server_id": "e.server_id", "domain_id": "e.domain_id",
    "channel": "channel.value", "provider": "provider.value", "ip": "e.ip_address",
    "subject_user_name": "e.subject_user_name", "target_user_name": "e.target_user_name",
    "message_sample": "facts.message_sample",
    "outcome": AUTH_OUTCOME,
})
TEXT_FIELDS = frozenset({"channel", "provider", "ip", "subject_user_name", "target_user_name", "message_sample"})


@dataclass(frozen=True)
class HotQuery:
    sql: str
    params: tuple[Any, ...]
    fields: tuple[str, ...]


@dataclass(frozen=True)
class HotPage:
    search: NormalizedSearch
    policy: SearchPolicy
    items: tuple[dict[str, Any], ...]
    has_more: bool

    @property
    def returned_count(self) -> int:
        return len(self.items)


def _links(field: str, role: str | None = None) -> tuple[str, list[Any]]:
    """Correlate stable links without multiplying events or matching names."""
    parts = ["link.event_id=e.id"]
    params: list[Any] = []
    if field == "account":
        parts.append("kind.value in ('ad_user','ad_computer','security_principal')")
        if role == "any":
            parts.append("role.value in ('actor','target')")
        elif role in {"actor", "target"}:
            parts.append("role.value=?")
            params.append(role)
        else:
            raise ContractError("invalid_condition")
    elif field == "source_station":
        parts.extend(["role.value='source'", "kind.value in ('workstation','asset','ad_computer')"])
    elif field != "related_object":
        raise ContractError("unsupported_field")
    return (
        "from event_entity_links_v2 link "
        "join storage_v2_role role on role.id=link.role_id "
        "join entities_v2 entity on entity.id=link.entity_id "
        "join storage_v2_entity_type kind on kind.id=entity.entity_type_id "
        "where " + " and ".join(parts), params,
    )


def _condition(condition: Condition) -> tuple[str, list[Any]]:
    key, operator = condition.field, condition.operator
    if key in {"account", "source_station", "related_object"}:
        links, params = _links(key, condition.role)
        if operator not in {"exists", "missing"}:
            links += " and link.entity_id=any(?)"
            params.append(list(condition.values))
        negate = "not " if operator in {"not_in", "missing"} else ""
        return f"{negate}exists (select 1 {links})", params
    expression = SCALARS.get(key)
    if expression is None:
        raise ContractError("unsupported_field")
    if operator in {"exists", "missing"}:
        return f"{expression} is {'not ' if operator == 'exists' else ''}null", []
    if operator == "not_in":
        return f"({expression} is null or not ({expression}=any(?)))", [list(condition.values)]
    if operator in {"eq", "in"}:
        return f"{expression}=any(?)", [list(condition.values)]
    raise ContractError("unsupported_operator")


def _scope(scope: AccessScope) -> tuple[str, list[Any]]:
    if scope.mode != "restricted":
        return ("true" if scope.mode == "all" else "false"), []
    branches, params = [], []
    for clause in scope.clauses:
        # There is no reliable mapping of these source-neutral dimensions to
        # this legacy hot schema. Never drop an unsupported clause/dimension.
        if clause.plugin_ids or clause.source_instance_ids:
            raise PermissionError("evsearch.policy_denied")
        parts = []
        if clause.device_ids:
            if any(re.fullmatch(r"server:[1-9][0-9]*", value) is None for value in clause.device_ids):
                raise PermissionError("evsearch.policy_denied")
            parts.append("e.server_id=any(?)")
            params.append([int(value.split(":", 1)[1]) for value in clause.device_ids])
        if clause.entity_ids:
            parts.append("exists (select 1 from event_entity_links_v2 scope_link where scope_link.event_id=e.id and scope_link.entity_id=any(?))")
            params.append(list(clause.entity_ids))
        if clause.collection_scope_ids:
            collections = []
            for value in clause.collection_scope_ids:
                if re.fullmatch(r"ad-domain:[1-9][0-9]*", value):
                    collections.append("e.domain_id=?")
                    params.append(int(value.split(":", 1)[1]))
                elif value.startswith("channel:") and value[8:]:
                    collections.append("channel.value=?")
                    params.append(value[8:])
                else:
                    raise PermissionError("evsearch.policy_denied")
            parts.append("(" + " or ".join(collections) + ")")
        branches.append("(" + " and ".join(parts) + ")")
    return "(" + " or ".join(branches) + ")", params


def _select(field: str) -> str:
    if field in SCALARS:
        return f'{SCALARS[field]} as "{field}"'
    links, _ = _links(field, "any" if field == "account" else None)
    if field == "account":
        return ("coalesce((select jsonb_agg(participant order by participant->>'role', participant->>'entity_id') "
                "from (select distinct jsonb_build_object('entity_id',link.entity_id,'role',role.value) as participant "
                f"{links}) participants),'[]'::jsonb) as account")
    return f'array(select distinct link.entity_id {links} order by link.entity_id) as "{field}"'


def compile_hot_query(
    search: NormalizedSearch, policy: SearchPolicy, *, fields: tuple[str, ...],
    text_fields: tuple[str, ...] = (), capture_limit: int | None = None,
    published_filters: tuple[Mapping[str, Any], ...] = (),
) -> HotQuery:
    """Compile an already authorized run, rechecking actual predicate dependencies."""
    required = set(fields) | search.required_fields | set(text_fields) | {item["field"] for item in published_filters}
    if not fields or not required <= policy.fields or policy.dataset_key != "events.v2" or policy.report_key != ACCESS_KEY:
        raise PermissionError("evsearch.policy_denied")
    if search.sort not in {"time_desc", "time_asc"} and not (search.sort == "count_desc" and capture_limit is not None):
        # Count order belongs to the grouped snapshot, never to a raw page.
        raise ContractError("invalid_request")
    if capture_limit is not None and (type(capture_limit) is not int or not 0 < capture_limit <= MAX_EVENTS):
        raise ContractError("invalid_request")
    scope_sql, params = _scope(policy.scope)
    parts = [scope_sql, "e.time_created_utc>=?", "e.time_created_utc<?"]
    params.extend([search.period.start, search.period.end])
    if search.exclude_machine_system:
        links, values = _links("account", search.account_role)
        # Use the stored entity type and host-scoped, immutable builtin SID.
        # Unknown/service accounts stay visible; display-name prefixes do not
        # classify accounts. Missing links are not evidence of a machine.
        parts.append("not exists (select 1 " + links
                     + " and (kind.value='ad_computer' or entity.natural_key ~* '^sid:.+:s-1-5-(18|19|20)$'))")
        params.extend(values)
    for condition in search.conditions:
        sql, values = _condition(condition)
        parts.append(sql)
        params.extend(values)
    if search.question:
        if search.question.confirmed_privilege or search.question.confirmed_grant:
            raise ContractError("unsupported_question")
        alternatives = []
        for branch in search.question.alternatives:
            predicates = []
            for condition in branch:
                sql, values = _condition(condition)
                predicates.append(sql)
                params.extend(values)
            alternatives.append("(" + " and ".join(predicates) + ")")
        parts.append("(" + " or ".join(alternatives) + ")")
    if search.q:
        if not text_fields or any(field not in TEXT_FIELDS for field in text_fields):
            raise ContractError("unsupported_field")
        # Literal substring of explicitly published text facts/identifiers;
        # user percent signs, SQL syntax and underscores have no special role.
        parts.append("(" + " or ".join(f"strpos(lower({SCALARS[field]}),lower(?))>0" for field in text_fields) + ")")
        params.extend([search.q] * len(text_fields))
    for item in published_filters:
        expression = SCALARS.get(item["field"])
        if expression is None:
            raise ContractError("unsupported_field")
        operator, value = item["op"], item["value"]
        if operator == "in":
            parts.append(f"{expression}=any(?)")
        elif operator in {"eq", "gte", "lte", "contains"}:
            sql_operator = {"eq": "=", "gte": ">=", "lte": "<=", "contains": " ilike "}[operator]
            parts.append(f"{expression}{sql_operator}?")
            if operator == "contains":
                value = f"%{value}%"
        else:
            raise ContractError("unsupported_operator")
        params.append(value)
    selected = ",".join(_select(field) for field in fields)
    if capture_limit is not None:
        # Internal storage identity, never a published/display field. Keep it
        # separate so an id/hash used for ownership cannot bypass field policy.
        selected += (',e.id as "_evsearch_id",e.time_created_utc as "_evsearch_time",'
                     'e.normalized_hash as "_evsearch_fingerprint"')
    joins = "join storage_v2_channel channel on channel.id=e.channel_id "
    if required & {"provider", "outcome"}:
        joins += "left join storage_v2_provider provider on provider.id=e.provider_id "
    if required & {"message_sample", "outcome"}:
        joins += "left join event_facts_v2 facts on facts.event_id=e.id "
    order = "asc" if search.sort == "time_asc" else "desc"
    sql = (f"select {selected} from events_v2_core e {joins}where "
           + " and ".join(f"({part})" for part in parts)
           + f" order by e.time_created_utc {order},e.id {order} limit ?")
    return HotQuery(sql, tuple(params + [(capture_limit if capture_limit is not None else search.page_size) + 1]), fields)


def read_hot_capture(
    search: NormalizedSearch, *, access: Mapping[str, Any], publication: Mapping[str, Any],
    fields: tuple[str, ...], limit: int = MAX_EVENTS, timeout_ms: int = 8000, query_rows=None,
) -> StoreCapture:
    """Detach a full scoped PG statement result for ES06, including old rows.

    No retention cutoff is pushed into SQL: publication gaps may still be
    covered by surviving PG events. A bounded overflow fails the execution;
    it must never be merged as an exhaustive page.
    """
    from server.sli.core.database import QueryTimeoutError
    from server.sli.events.evsearch_history import _publication_filters

    if type(timeout_ms) is not int or not 0 < timeout_ms <= 8000:
        raise ContractError("invalid_request")
    started = monotonic()
    published = tuple(_publication_filters(publication))
    text_fields = ()
    if search.q:
        declared = _json_mapping(publication.get("definition_json")).get("evsearch_q_fields")
        if (not isinstance(declared, list) or not declared
                or any(not isinstance(key, str) or key not in TEXT_FIELDS for key in declared)):
            raise ContractError("unsupported_field")
        text_fields = tuple(dict.fromkeys(declared))
    policy = authorize_request(
        search.as_request(), access=access, publication=publication,
        fields=tuple(sorted(set(fields) | search.required_fields | set(text_fields) | {item["field"] for item in published})),
    )
    query = compile_hot_query(search, policy, fields=fields, text_fields=text_fields,
                              capture_limit=limit, published_filters=published)
    remaining = timeout_ms - int((monotonic() - started) * 1000)
    if remaining <= 350:
        raise OwnershipError("storage_timeout")
    try:
        rows = (query_rows or query_rows_bounded)(query.sql, query.params, statement_timeout_ms=remaining - 250,
                                                wall_timeout_ms=remaining)
    except QueryTimeoutError:
        raise OwnershipError("storage_timeout") from None
    if len(rows) > limit:
        raise OwnershipError("storage_limit_exceeded")
    identities, items, seen, size = [], [], set(), 2
    for row in rows:
        if (monotonic() - started) * 1000 >= timeout_ms:
            raise OwnershipError("storage_timeout")
        try:
            identity = EventIdentity.from_values(row["_evsearch_id"], row["_evsearch_fingerprint"], row["_evsearch_time"])
            if identity.event_id in seen or not search.period.start <= identity.timestamp < search.period.end:
                raise OwnershipError("storage_integrity_error")
            item = {key: row[key] for key in fields}
            size += len(json.dumps(item, ensure_ascii=False, allow_nan=False, default=_json_default).encode()) + 1
            if size > MAX_SNAPSHOT_BYTES:
                raise OwnershipError("storage_limit_exceeded")
            items.append(item)
        except (KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, OwnershipError):
                raise
            raise OwnershipError("storage_integrity_error") from None
        seen.add(identity.event_id)
        identities.append(identity)
    if (monotonic() - started) * 1000 >= timeout_ms:
        raise OwnershipError("storage_timeout")
    return StoreCapture("postgres", capture_binding(search, policy, fields, publication), _query_hash(search),
                        _hash([(item.event_id, item.fingerprint, item.timestamp) for item in identities]),
                        tuple(items), tuple(identities))


def read_hot_page(
    raw: Mapping[str, Any], principal: Mapping[str, Any] | None, *,
    fields: tuple[str, ...] = DEFAULT_FIELDS, action: str = "view",
    now: datetime | None = None, allowed_period: Period | None = None,
) -> HotPage:
    """Load current grants/publication on the server, then perform one bounded read.

    No totals/facets or completeness claims are inferred from this raw page.
    Later stages reuse the compiled WHERE before their own aggregates.
    """
    search = normalize_request(raw, now=now, allowed_period=allowed_period)
    access = effective_access(principal)
    report = next((item for item in access.get("reports") or [] if item.get("report_key") == ACCESS_KEY and item.get("allowed")), None)
    if report is None:
        raise PermissionError("evsearch.policy_denied")
    publications = query_rows_bounded(
        "select r.definition_json,d.dataset_key,d.fields_json "
        "from report_registry_v4 r join report_datasets_v4 d on d.id=r.dataset_id "
        "where r.report_key=? and r.version=? and r.status='published' and d.status='published' limit 1",
        (ACCESS_KEY, report.get("version")), statement_timeout_ms=TIMEOUT_MS,
        wall_timeout_ms=TIMEOUT_MS + 1500,
    )
    if not publications:
        raise PermissionError("evsearch.policy_denied")
    publication = publications[0]
    text_fields: tuple[str, ...] = ()
    if search.q:
        declared = _json_mapping(publication.get("definition_json")).get("evsearch_q_fields")
        if not isinstance(declared, list) or not declared or any(not isinstance(field, str) or field not in TEXT_FIELDS for field in declared):
            raise ContractError("unsupported_field")
        text_fields = tuple(dict.fromkeys(declared))
    # Do not trust a publication's question dependency list to understate the
    # server-owned ES02 predicate. Also authorize every q backing field.
    dependencies = tuple(sorted(set(fields) | search.required_fields | set(text_fields)))
    policy = authorize_request(search.as_request(), access=access, publication=publication, fields=dependencies, action=action)
    query = compile_hot_query(search, policy, fields=fields, text_fields=text_fields)
    rows = query_rows_bounded(query.sql, query.params, statement_timeout_ms=TIMEOUT_MS, wall_timeout_ms=TIMEOUT_MS + 1500)
    # Defense in depth at the output boundary, even for a test/adapter returning
    # extra columns. Predicates and lookahead are already scoped in PostgreSQL.
    items = tuple({field: row[field] for field in fields} for row in rows[:search.page_size])
    return HotPage(search, policy, items, len(rows) > search.page_size)

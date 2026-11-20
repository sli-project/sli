"""ES05 bounded evsearch.v1 reader of published, immutable historical facts.

Internal identities feed ES06 ownership; no HTTP endpoint is installed here.
A successful read proves retained matches, not collection/storage coverage.
Fields requiring a semantic/identity projection absent from this store fail
closed, including negative and missing predicates; they are never discarded.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import closing
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.client import HTTPException
from ipaddress import ip_address
import json
import re
from time import monotonic
from typing import Any

from server.sli.access.scope import AccessScope, DIMENSIONS
from server.sli.events.evsearch_contract import ContractError, authorize_request
from server.sli.events.evsearch_normalizer import (
    Condition, NormalizedSearch, matches_conditions, matches_question,
)
from server.sli.events.evsearch_ownership import EventIdentity, OwnershipError, StoreCapture, capture_binding
from server.sli.events.evsearch_snapshot import _query_hash
from server.sli.reporting.reporting_v4_definitions import _json_mapping
from server.sli.reporting.reporting_v4_catalog import RUNTIME_FILTER_FIELDS
from server.sli.reporting.reporting_v4_query import _typed_filter_value
from server.sli.storage import permanent_fact_history as history
from server.sli.storage.runtime_storage import StorageRouteConsumer, resolve_storage_route
from server.sli.storage.storage_lifecycle_io import _http_stream_json_rows

MAX_BATCHES = 4096
MAX_ROWS = 250_000
MAX_BYTES = 16 * 1024 * 1024
MAX_TIMEOUT_MS = 8000
_IDENTITY_KEYS = (
    "first_event_db_id", "last_event_db_id", "event_count", "link_count",
    "event_sequence_sha256", "link_sequence_sha256",
)
# Canonical fields only; no display-name resolution or inferred semantics.
_CORE = {
    "domain_id": ("domain_id", "Int64"), "channel": ("channel", "String"),
    "provider": ("provider_name", "String"), "ip": ("ip_address", "String"),
    "subject_user_name": ("subject_user_name", "String"),
    "target_user_name": ("target_user_name", "String"),
    "normalized_hash": ("normalized_hash", "String"),
}
_INDEX = {"id": "e.event_db_id", "event_id": "e.event_key",
          "server_id": "e.server_id", "time_created_utc": "e.time_created_utc"}
_FIELDS = frozenset(_CORE) | _INDEX.keys() | {"message_sample", "source_payload_state"}


class HistoryError(ContractError):
    """A localized component failure, never an empty result or a data value."""


@dataclass(frozen=True)
class HistoryResult:
    items: list[dict[str, Any]] = field(repr=False)
    publication_watermark: str
    coverage: str = "unknown"
    source_payload_state: str = "expired"
    capture: StoreCapture | None = field(default=None, repr=False)


def _literal(value: Any) -> str:
    # Values stay in the POST body, never HTTP URL parameters/access logs.
    if type(value) is int:
        return str(value)
    if not isinstance(value, str):
        raise HistoryError("history_predicate_unavailable")
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _expression(key: str) -> str:
    if key in _INDEX:
        return _INDEX[key]
    if key in _CORE:
        name, kind = _CORE[key]
        return f"JSONExtract(e.core_json,'{name}','Nullable({kind})')"
    if key == "message_sample":
        return "JSONExtract(e.facts_json,'message_sample','Nullable(String)')"
    raise HistoryError("history_predicate_unavailable")


def _condition(condition: Condition) -> str:
    column = _expression(condition.field)
    if condition.field == "ip":
        column = f"toIPv6OrNull({column})"
    if condition.operator == "exists":
        return f"isNotNull({column})"
    if condition.operator == "missing":
        return f"isNull({column})"
    values = ",".join(f"toIPv6({_literal(value)})" if condition.field == "ip" else _literal(value)
                      for value in condition.values)
    if condition.operator == "not_in":
        return f"(isNull({column}) OR {column} NOT IN ({values}))"
    if condition.operator in {"eq", "in"}:
        return f"{column} IN ({values})"
    raise HistoryError("history_predicate_unavailable")


def _scope(scope: AccessScope) -> str:
    if scope.mode == "none" or scope.decision_id == "unissued":
        raise PermissionError("evsearch.policy_denied")
    if scope.mode == "all":
        return "1"
    clauses = []
    for clause in scope.clauses:
        predicates = []
        for dimension in DIMENSIONS:
            values = getattr(clause, dimension)
            if not values:
                continue
            if dimension not in {"device_ids", "collection_scope_ids"}:
                raise HistoryError("history_predicate_unavailable")
            alternatives = []
            for value in values:
                if dimension == "device_ids" and re.fullmatch(r"server:[1-9][0-9]*", value):
                    alternatives.append(_condition(Condition("server_id", "eq", (int(value[7:]),))))
                elif dimension == "collection_scope_ids" and re.fullmatch(r"ad-domain:[1-9][0-9]*", value):
                    alternatives.append(_condition(Condition("domain_id", "eq", (int(value[10:]),))))
                elif dimension == "collection_scope_ids" and value.startswith("channel:") and value[8:]:
                    alternatives.append(_condition(Condition("channel", "eq", (value[8:],))))
                else:
                    raise HistoryError("history_predicate_unavailable")
            predicates.append("(" + " OR ".join(alternatives) + ")")
        clauses.append("(" + " AND ".join(predicates) + ")")
    return "(" + " OR ".join(clauses) + ")"


def _allows(scope: AccessScope, event: Mapping[str, Any]) -> bool:
    if scope.mode == "all":
        return True
    dimensions = {"device_ids": {f"server:{event['server_id']}"},
                  "collection_scope_ids": {f"ad-domain:{event.get('domain_id')}", f"channel:{event.get('channel')}"}}
    return any(all(not getattr(clause, key) or set(getattr(clause, key)) & dimensions.get(key, set())
                   for key in DIMENSIONS) for clause in scope.clauses)


def _publication_filters(publication) -> list[dict[str, Any]]:
    filters = _json_mapping(publication.get("definition_json")).get("filters") or []
    if not isinstance(filters, list):
        raise HistoryError("history_predicate_unavailable")
    result = []
    for item in filters:
        if not isinstance(item, Mapping):
            raise HistoryError("history_predicate_unavailable")
        # Seeded {key, ops} entries declare an interactive schema, not a filter.
        if "field" not in item and "value" not in item:
            continue
        key, op = item.get("field"), item.get("op")
        if key not in RUNTIME_FILTER_FIELDS["events.v2"] or op not in {"eq", "in", "contains", "gte", "lte"}:
            raise HistoryError("history_predicate_unavailable")
        try:
            value = _typed_filter_value("events.v2", key, item.get("value"), many=op == "in")
        except (TypeError, ValueError):
            raise HistoryError("history_predicate_unavailable") from None
        # Match the PG builder's types, including timestamp comparisons.
        result.append({"field": key, "op": op, "value": value})
    return result


def _published_predicate(item) -> str:
    key, op, value = item["field"], item["op"], item["value"]
    column = _expression(key)
    if op in {"eq", "in"}:
        return _condition(Condition(key, op, tuple(value) if op == "in" else (value,)))
    if op == "contains":
        return f"{column} ILIKE {_literal('%' + str(value) + '%')}"
    if key == "time_created_utc":
        value_sql = f"parseDateTime64BestEffort({_literal(value)},6,'UTC')"
    else:
        value_sql = _literal(value)
    return f"{column} {'>=' if op == 'gte' else '<='} {value_sql}"


def _compile(search, policy, fields, published):
    if not fields or not set(fields) <= _FIELDS or not search.required_fields <= _FIELDS:
        raise HistoryError("history_predicate_unavailable")
    predicates = [_scope(policy.scope)]
    predicates.extend(_condition(c) for c in search.conditions)
    if search.question:
        if search.question.confirmed_privilege or search.question.confirmed_grant:
            raise HistoryError("history_predicate_unavailable")
        predicates.append("(" + " OR ".join(
            "(" + " AND ".join(_condition(c) for c in branch) + ")"
            for branch in search.question.alternatives
        ) + ")")
    predicates.extend(_published_predicate(item) for item in published)
    return " AND ".join(f"({part})" for part in predicates)


def _indexed_predicates(search, scope):
    """Safe extra bounds before JSON extraction, never a replacement for scope."""
    predicates = [_condition(c) for c in search.conditions if c.field in {"server_id", "event_id"}]
    if search.question:
        keys = [c.values for branch in search.question.alternatives for c in branch if c.field == "event_id"]
        if len(keys) == len(search.question.alternatives):
            predicates.append(_condition(Condition("event_id", "in", tuple(sorted({v for values in keys for v in values})))))
    if scope.mode == "restricted" and all(clause.device_ids for clause in scope.clauses):
        servers = {int(value[7:]) for clause in scope.clauses for value in clause.device_ids}
        predicates.append(_condition(Condition("server_id", "in", tuple(sorted(servers)))))
    return predicates


def _manifest(rows) -> dict[str, dict[str, Any]]:
    if len(rows) > MAX_BATCHES:
        raise HistoryError("history_limit_exceeded")
    result = {}
    try:
        for row in rows:
            identity = {key: int(row[key]) if key.endswith("_id") or key.endswith("_count") else row[key]
                        for key in _IDENTITY_KEYS}
            digest = row["batch_sha256"]
            if (not isinstance(digest, str) or not re.fullmatch(r"[0-9A-F]{64}", digest)
                    or digest in result or history._payload_sha(identity) != digest
                    or not 0 < identity["first_event_db_id"] <= identity["last_event_db_id"]
                    or not 0 < identity["event_count"] <= history.MAX_BATCH_EVENTS
                    or identity["event_count"] > identity["last_event_db_id"] - identity["first_event_db_id"] + 1
                    or identity["link_count"] < 0
                    or any(not isinstance(identity[key], str) or not re.fullmatch(r"[0-9A-F]{64}", identity[key])
                           for key in ("event_sequence_sha256", "link_sequence_sha256"))):
                raise ValueError
            result[digest] = identity
        ordered = sorted(result.values(), key=lambda row: row["first_event_db_id"])
        if any(left["last_event_db_id"] >= right["first_event_db_id"] for left, right in zip(ordered, ordered[1:])):
            raise ValueError
    except (KeyError, TypeError, ValueError, OverflowError):
        raise HistoryError("history_integrity_error") from None
    return result


def _event(row, manifest):
    try:
        core, facts = json.loads(row["core_json"]), json.loads(row["facts_json"])
        batch = manifest[row["batch_sha256"]]
        event_id = int(row["event_db_id"])
        if (not isinstance(core, dict) or not isinstance(facts, dict)
                or history._payload_sha({"core": core, "facts": facts}) != row["row_sha256"]
                or not batch["first_event_db_id"] <= event_id <= batch["last_event_db_id"]
                or int(core["id"]) != event_id or int(core["event_id"]) != int(row["event_key"])
                or int(core["server_id"]) != int(row["server_id"])
                or history._json_ch_time(core["time_created_utc"]) != row["time_created_utc"]
                or str(core.get("noise_class") or "") != row["noise_class"]):
            raise ValueError
        event = {key: core.get(name) for key, (name, _) in _CORE.items()}
        event.update(id=event_id, event_id=int(core["event_id"]), server_id=int(core["server_id"]),
                     time_created_utc=core["time_created_utc"], message_sample=facts.get("message_sample"),
                     source_payload_state="expired")
        if event["ip"] is not None:
            try:
                event["ip"] = str(ip_address(event["ip"]))
            except ValueError:
                event["ip"] = None
        return event
    except (KeyError, TypeError, ValueError, OverflowError):
        raise HistoryError("history_integrity_error") from None


def _query_rows(sql: str, timeout_ms: int) -> list[dict[str, Any]]:
    try:
        port = history.configured_read_port()
    except ValueError:
        raise HistoryError("history_unavailable") from None
    if port is None:
        raise HistoryError("history_unavailable")
    params = {
        "readonly": "1", "max_execution_time": str(timeout_ms / 1000),
        "max_threads": "2", "max_memory_usage": str(128 * 1024 * 1024),
        "max_bytes_before_external_sort": "0", "max_bytes_before_external_group_by": "0",
        "max_result_bytes": str(MAX_BYTES), "result_overflow_mode": "throw",
        "timeout_overflow_mode": "throw", "log_queries": "0", "log_query_threads": "0",
    }
    deadline = monotonic() + timeout_ms / 1000
    rows, size = [], 0
    try:
        with closing(_http_stream_json_rows(
            port, sql + " FORMAT JSONEachRow", timeout=timeout_ms / 1000,
            params=params, auth=history._history_auth(),
        )) as source:
            for row in source:
                if monotonic() >= deadline:
                    raise HistoryError("history_timeout")
                size += len(json.dumps(row, ensure_ascii=False).encode())
                if size > MAX_BYTES or len(rows) >= MAX_ROWS + 1:
                    raise HistoryError("history_limit_exceeded")
                rows.append(row)
    except HistoryError:
        raise
    except TimeoutError:
        raise HistoryError("history_timeout") from None
    except (OSError, HTTPException, RuntimeError):
        raise HistoryError("history_unavailable") from None
    except (TypeError, ValueError):
        raise HistoryError("history_integrity_error") from None
    return rows


class ClickHouseHistoryReader:
    def __init__(self, *, query_rows: Callable = _query_rows, clock: Callable = monotonic):
        self.query_rows, self.clock = query_rows, clock

    def read(
        self, search: NormalizedSearch, *, access: Mapping[str, Any], publication: Mapping[str, Any],
        fields: tuple[str, ...], authorization=None, limit: int = MAX_ROWS, timeout_ms: int = MAX_TIMEOUT_MS,
    ) -> HistoryResult:
        if type(limit) is not int or not 1 <= limit <= MAX_ROWS or type(timeout_ms) is not int or not 0 < timeout_ms <= MAX_TIMEOUT_MS:
            raise ContractError("invalid_request")
        deadline = self.clock() + timeout_ms / 1000
        published = _publication_filters(publication)
        policy = authorize_request(
            search.as_request(), access=access, publication=publication,
            fields=tuple(sorted(set(fields) | search.required_fields | {item["field"] for item in published})),
        )
        predicate = _compile(search, policy, fields, published)
        binding = capture_binding(search, policy, fields, publication)
        # Use the existing cutover admission and explicit history-read switch;
        # this reader never enables primary history or contacts PostgreSQL.
        resolve_storage_route(authorization=authorization, consumer=StorageRouteConsumer.EVENT_SEARCH)
        try:
            enabled = history.primary_read_enabled()
        except (ValueError, RuntimeError):
            raise HistoryError("history_unavailable") from None
        if not enabled:
            raise HistoryError("history_unavailable")

        def remaining():
            value = int((deadline - self.clock()) * 1000)
            if value <= 0:
                raise HistoryError("history_timeout")
            return value

        window = (f"e.time_created_utc >= parseDateTime64BestEffort({_literal(search.period.start.isoformat())},6,'UTC')"
                  f" AND e.time_created_utc < parseDateTime64BestEffort({_literal(search.period.end.isoformat())},6,'UTC')")
        for bound in _indexed_predicates(search, policy.scope):
            window += f" AND ({bound})"
        selected = f"SELECT e.batch_sha256 FROM sli_history.events e PREWHERE {window} WHERE {predicate}"
        batches = _manifest(self.query_rows(
            "SELECT " + ",".join(("batch_sha256", *_IDENTITY_KEYS))
            + " FROM sli_history.published_batches WHERE batch_sha256 IN (" + selected + ")"
            + f" LIMIT {MAX_BATCHES + 1}", remaining(),
        ))
        remaining()
        watermark = history._payload_sha(sorted(batches))
        if not batches:
            return HistoryResult([], watermark, capture=StoreCapture(
                "clickhouse", binding, _query_hash(search), watermark, (), (),
            ))
        direction = "ASC" if search.sort == "time_asc" else "DESC"
        stored = self.query_rows(
            "SELECT e.event_db_id,e.event_key,e.server_id,e.time_created_utc,e.noise_class,"
            "e.core_json,e.facts_json,e.row_sha256,e.batch_sha256 FROM sli_history.events e "
            f"PREWHERE {window} WHERE ({predicate}) AND e.batch_sha256 IN ("
            + ",".join(_literal(digest) for digest in sorted(batches)) + ") "
            + f"ORDER BY e.time_created_utc {direction},e.event_db_id {direction} LIMIT {limit + 1}",
            remaining(),
        )
        if len(stored) > limit:
            raise HistoryError("history_limit_exceeded")
        items, identities, seen = [], [], set()
        for row in stored:
            remaining()
            event = _event(row, batches)
            try:
                timestamp = datetime.fromisoformat(event["time_created_utc"].replace("Z", "+00:00"))
                if timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=timezone.utc)
                valid = (search.period.start <= timestamp < search.period.end
                         and _allows(policy.scope, event) and matches_conditions(search.conditions, event)
                         and (not search.question or matches_question(search.question, event)))
            except (TypeError, ValueError):
                raise HistoryError("history_integrity_error") from None
            if not valid or event["id"] in seen:
                raise HistoryError("history_integrity_error")
            seen.add(event["id"])
            items.append({key: event[key] for key in fields})
            try:
                identities.append(EventIdentity.from_values(event["id"], event["normalized_hash"], event["time_created_utc"]))
            except OwnershipError:
                raise HistoryError("history_integrity_error") from None
        remaining()
        return HistoryResult(items, watermark, capture=StoreCapture(
            "clickhouse", binding, _query_hash(search), watermark, tuple(items), tuple(identities),
        ))

"""ES07 groups over detached ES04/ES06 executions, never over live pages.

The server-owned semantic projection may confirm ``group_identity_complete``
only when every applicable participant/object identity is resolved. Explicit
None means not applicable; an absent field or an unconfirmed identity keeps
the event separate. Existing readers without that projection safely produce
singletons. Neither display labels nor translated action titles are identities.

Ownership is settled BEFORE partial SQL/CH aggregation. Only opaque group keys
and UTC timestamps are sent to the aggregate adapters, from the pinned capture;
no re-read of changing source tables and no retained database transaction.
"""
from __future__ import annotations

import base64
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
import hmac
from ipaddress import ip_address
import json
import secrets
from typing import Any

from server.sli.events.evsearch_contract import GROUPING_VERSION, ContractError
from server.sli.events.evsearch_ownership import (
    StorageCoverage, capture_binding, merge_captures, utc_time,
)
from server.sli.events.evsearch_snapshot import (
    Snapshot, SnapshotError, SnapshotStore, _Entry, _authorization, _hash, _json_default,
)


GROUP_FIELDS = (
    "action", "provider", "channel", "event_id", "outcome", "reason", "logon_type",
    "account", "source_station", "ip", "related_object", "server_id", "domain_id",
    "task_identity", "process_identity", "file_identity",
)
PROJECTION_FIELDS = (*GROUP_FIELDS, "group_identity_complete")
MAX_GROUPS = 10_000


def _ids(value):
    if not isinstance(value, (list, tuple)) or any(type(v) is not int or not 0 < v < 2**63 for v in value):
        raise ValueError
    return sorted(set(value))


def group_key(event: Mapping[str, Any], event_db_id: int) -> str:
    """A store-independent, versioned key; unresolved identities never coalesce."""
    if type(event_db_id) is not int or not 0 < event_db_id < 2**63:
        raise ContractError("storage_integrity_error")
    try:
        if event.get("group_identity_complete") is not True or not set(GROUP_FIELDS) <= event.keys():
            raise ValueError
        identity = {key: event[key] for key in GROUP_FIELDS}
        for key in ("action", "provider", "channel"):
            if not isinstance(identity[key], str) or not identity[key].strip():
                raise ValueError
        for key in ("server_id", "domain_id"):
            if type(identity[key]) is not int or not 0 < identity[key] < 2**63:
                raise ValueError
        if type(identity["event_id"]) is not int or not 0 <= identity["event_id"] < 2**31:
            raise ValueError
        for key in ("outcome", "reason", "logon_type", "task_identity", "process_identity", "file_identity"):
            if identity[key] is not None and (not isinstance(identity[key], str) or not identity[key].strip()):
                raise ValueError
        accounts = identity["account"]
        if not isinstance(accounts, (list, tuple)):
            raise ValueError
        participants = set()
        for participant in accounts:
            if (not isinstance(participant, Mapping) or participant.get("role") not in {"actor", "target"}
                    or type(participant.get("entity_id")) is not int or not 0 < participant["entity_id"] < 2**63):
                raise ValueError
            participants.add((participant["role"], participant["entity_id"]))
        identity["account"] = sorted(participants)
        for key in ("source_station", "related_object"):
            identity[key] = _ids(identity[key])
        if identity["ip"] is not None:
            if not isinstance(identity["ip"], str):
                raise ValueError
            identity["ip"] = str(ip_address(identity["ip"]))
        return _hash({"version": GROUPING_VERSION, "identity": identity})
    except (TypeError, ValueError):
        return _hash({"version": GROUPING_VERSION, "singleton": event_db_id})


@dataclass(frozen=True)
class PartialQuery:
    store: str
    sql: str = field(repr=False)
    params: tuple[Any, ...] = field(default=(), repr=False)


def compile_partial_query(store: str, rows: list[dict[str, str]]) -> PartialQuery:
    """Aggregate only the owned, bounded execution projection, not a raw page.

    Canonicalization happens once in Python so PG/CH JSON encodings, NULL rules
    and hash functions cannot split a group at the storage boundary. No LIMIT
    is applied to partial groups: global sorting/paging follows the merge.
    """
    payload = json.dumps(rows, separators=(",", ":"), allow_nan=False)
    if store == "postgres":
        return PartialQuery(store,
            "select group_key,count(*) as count,min(stamp) as first_seen,max(stamp) as last_seen "
            "from jsonb_to_recordset(?::jsonb) as captured(group_key text,stamp timestamptz) "
            "group by group_key", (payload,))
    if store == "clickhouse":
        from server.sli.events.evsearch_history import _literal

        return PartialQuery(store,
            "SELECT group_key,count() AS count,min(parseDateTime64BestEffort(stamp,6,'UTC')) AS first_seen,"
            "max(parseDateTime64BestEffort(stamp,6,'UTC')) AS last_seen "
            "FROM format(JSONEachRow,'group_key String, stamp String',"
            + _literal("\n".join(json.dumps(row, separators=(",", ":")) for row in rows)) + ") GROUP BY group_key")
    raise ContractError("invalid_request")


def run_partial_query(query: PartialQuery, timeout_ms: int):
    if query.store == "postgres":
        from server.sli.core.database import QueryTimeoutError, query_rows_bounded

        if timeout_ms <= 350:
            raise SnapshotError("snapshot_timeout")
        try:
            return query_rows_bounded(query.sql, query.params, statement_timeout_ms=timeout_ms - 250,
                                      wall_timeout_ms=timeout_ms)
        except QueryTimeoutError:
            raise SnapshotError("snapshot_timeout") from None
    from server.sli.events.evsearch_history import _query_rows

    return _query_rows(query.sql, timeout_ms)


def _partials(rows):
    """Reference reducer, also checks adapter results without trusting counts."""
    result = {}
    for row in rows:
        key, stamp = row["group_key"], utc_time(row["stamp"])
        if key not in result:
            if len(result) >= MAX_GROUPS:
                raise SnapshotError("snapshot_limit_exceeded")
            result[key] = {"group_key": key, "count": 0, "first_seen": stamp, "last_seen": stamp}
        group = result[key]
        group["count"] += 1
        group["first_seen"] = min(group["first_seen"], stamp)
        group["last_seen"] = max(group["last_seen"], stamp)
    return result


def _checked_partials(rows, expected):
    # CH's JSONEachRow serializes UInt64 as a decimal string and timestamps
    # without an offset; this adapter's SQL explicitly requests UTC.
    result = {}
    try:
        for row in rows:
            key = row["group_key"]
            count = row["count"]
            if isinstance(count, str) and count.isascii() and count.isdecimal():
                count = int(count)
            if type(count) is not int or count <= 0 or key in result or key not in expected:
                raise ValueError
            stamps = []
            for name in ("first_seen", "last_seen"):
                value = row[name]
                if isinstance(value, str):
                    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                    value = parsed.replace(tzinfo=utc_time(expected[key][name]).tzinfo) if parsed.tzinfo is None else parsed
                stamps.append(utc_time(value))
            result[key] = {"group_key": key, "count": count, "first_seen": stamps[0], "last_seen": stamps[1]}
        if result != expected:
            raise ValueError
    except (KeyError, TypeError, ValueError, OverflowError):
        raise ContractError("storage_integrity_error") from None
    return result


@dataclass(frozen=True)
class GroupPage:
    execution_id: str
    query_hash: str
    as_of: datetime
    expires_at: datetime
    items: tuple[dict[str, Any], ...] = field(repr=False)
    has_more: bool
    next_cursor: str | None = field(repr=False)
    storage_coverage: StorageCoverage
    coverage: str = "unknown"
    grouping_version: str = GROUPING_VERSION


@dataclass(frozen=True)
class MembersPage:
    execution_id: str
    group_key: str
    items: tuple[dict[str, Any], ...] = field(repr=False)
    has_more: bool
    next_cursor: str | None = field(repr=False)


def _order(group, sort):
    # Integer microseconds avoid floating-point timestamp ties.
    stamp = utc_time(group["last_seen"])
    micros = (stamp.toordinal() * 86400 + stamp.hour * 3600 + stamp.minute * 60 + stamp.second) * 1000000 + stamp.microsecond
    if sort == "count_desc":
        return (-group["count"], -micros, group["group_key"])
    return (micros if sort == "time_asc" else -micros, group["group_key"])


class GroupSnapshotStore(SnapshotStore):
    """Bounded grouped executions with ES04 isolation and signed keyset pages.

    Every page rechecks current server-loaded grants/publication/revision via
    SnapshotStore.get. Cursor values grant no access and cannot trigger a read.
    Loss of this process-local store/key requires a fresh execution.
    """

    def __init__(self, **budgets):
        super().__init__(**budgets)
        self._cursor_secret = secrets.token_bytes(32)

    def start(
        self, *, owner_id, search, access, publication, fields, revision, hot, cold,
        evidence=(), retention_boundary=None, aggregate: Callable = run_partial_query,
        deadline=None, as_of=None,
    ) -> GroupPage:
        started = self.clock()
        as_of = self.utcnow() if as_of is None else utc_time(as_of)
        deadline = min(started + min(self.timeout_seconds, self.ttl_seconds),
                       deadline if deadline is not None else float("inf"))

        def remaining():
            value = int((deadline - self.clock()) * 1000)
            if value <= 0:
                raise SnapshotError("snapshot_timeout")
            return value

        policy, query_hash, binding = _authorization(
            owner_id=owner_id, search=search, access=access, publication=publication, fields=fields, revision=revision,
        )
        expected_binding = capture_binding(search, policy, fields, publication)
        if hot.binding != expected_binding or cold.binding != expected_binding:
            raise ContractError("storage_integrity_error")
        owned = merge_captures(search, hot=hot, cold=cold, evidence=evidence, retention_boundary=retention_boundary,
                               timeout_ms=remaining(), clock=self.clock)
        if len(owned.items) > self.max_events:
            raise SnapshotError("snapshot_limit_exceeded")
        identities = {identity.event_id: identity for capture in (cold, hot) for identity in capture.identities}
        inputs = {"postgres": [], "clickhouse": []}
        members = []
        for item, (event_id, store) in zip(owned.items, owned.manifest.owners):
            remaining()
            # Never let an extra adapter column influence count/grouping.
            projection = {key: item[key] for key in fields if key in item}
            key, stamp = group_key(projection, event_id), identities[event_id].timestamp.isoformat()
            inputs[store].append({"group_key": key, "stamp": stamp})
            # Internal exact membership for ES08, detached under the same TTL
            # and byte budget. Group pages expose aggregates only.
            members.append({"group_key": key, "event_db_id": event_id, "stamp": stamp, "fields": projection, "source_store": store})
        groups = {}
        for store, rows in inputs.items():
            remaining()
            if not rows:
                continue
            expected = _partials(rows)
            query = compile_partial_query(store, rows)
            remaining()
            partials = _checked_partials(aggregate(query, remaining()), expected)
            for key, partial in partials.items():
                remaining()
                if key not in groups:
                    if len(groups) >= MAX_GROUPS:
                        raise SnapshotError("snapshot_limit_exceeded")
                    groups[key] = dict(partial)
                else:
                    group = groups[key]
                    group["count"] += partial["count"]
                    group["first_seen"] = min(group["first_seen"], partial["first_seen"])
                    group["last_seen"] = max(group["last_seen"], partial["last_seen"])
        rows = sorted(groups.values(), key=lambda row: _order(row, search.sort))
        # Store metadata inside the same bounded/expiring payload, so eviction
        # cannot leave a separate unbounded manifest/coverage cache behind.
        coverage = owned.storage_coverage
        envelope = [{"groups": rows, "members": members,
                     "context": {"request": search.as_request(), "fields": list(fields),
                                 "retention_boundary": retention_boundary,
                                 "manifest": asdict(owned.manifest)},
                     "storage_coverage": {
            "status": coverage.status, "confirmed": coverage.confirmed, "unconfirmed": coverage.unconfirmed,
        }}]
        payload = json.dumps(envelope, separators=(",", ":"), allow_nan=False, default=_json_default).encode()
        if len(payload) > self.max_snapshot_bytes:
            raise SnapshotError("snapshot_limit_exceeded")
        entry = _Entry(owner_id, binding, query_hash, as_of, as_of + timedelta(seconds=self.ttl_seconds),
                       started + self.ttl_seconds, payload)
        snapshot = self._retain(entry, remaining)
        return self._page(snapshot, owner_id, search, None)

    def page(self, execution_id, *, owner_id, search, access, publication, fields, revision, cursor=None) -> GroupPage:
        snapshot = self.get(execution_id, owner_id=owner_id, search=search, access=access,
                            publication=publication, fields=fields, revision=revision)
        return self._page(snapshot, owner_id, search, cursor)

    def execution_context(self, execution_id, *, owner_id):
        """Internal context only; caller must reauthorize before any response.

        Kept inside the same expiring byte budget, never a second metadata cache.
        A context lookup grants no access and cannot return event projections.
        """
        with self._lock:
            self._purge()
            entry = self._entries.get(execution_id)
            if entry is None or type(owner_id) is not int or owner_id != entry.owner_id:
                raise SnapshotError("snapshot_expired")
            return entry.result(execution_id).items[0]["context"]

    def members(self, execution_id, *, owner_id, search, access, publication,
                fields, revision, group_key, cursor=None):
        snapshot = self.get(execution_id, owner_id=owner_id, search=search, access=access,
                            publication=publication, fields=fields, revision=revision)
        envelope = snapshot.items[0]
        if not isinstance(group_key, str) or not any(g["group_key"] == group_key for g in envelope["groups"]):
            raise ContractError("invalid_request")
        rows = [r for r in envelope["members"] if r["group_key"] == group_key]
        # Native record IDs are not universally published; exact DB ID breaks
        # timestamp ties without reading an undeclared field or a live source.
        rows.sort(key=lambda r: (utc_time(r["stamp"]), r["event_db_id"]))
        context = _hash(["members", execution_id, owner_id, snapshot.query_hash, group_key, GROUPING_VERSION])
        if cursor is not None:
            after = self._position(cursor, context)
            index = next((i for i, row in enumerate(rows) if str(row["event_db_id"]) == after), None)
            if index is None:
                raise ContractError("invalid_cursor")
            rows = rows[index + 1:]
        items = tuple(rows[:search.page_size])
        more = len(rows) > len(items)
        return MembersPage(execution_id, group_key, items, more,
                           self._token(context, str(items[-1]["event_db_id"])) if more else None)

    def _token(self, context, key):
        raw = json.dumps({"context": context, "after": key}, separators=(",", ":")).encode()
        signature = hmac.digest(self._cursor_secret, raw, "sha256")
        return base64.urlsafe_b64encode(signature + raw).decode().rstrip("=")

    def _position(self, token, context):
        try:
            if not isinstance(token, str) or not 0 < len(token) <= 2048:
                raise ValueError
            value = base64.b64decode(token + "=" * (-len(token) % 4), altchars=b"-_", validate=True)
            signature, raw = value[:32], value[32:]
            if not hmac.compare_digest(signature, hmac.digest(self._cursor_secret, raw, "sha256")):
                raise ValueError
            decoded = json.loads(raw)
            if decoded.get("context") != context or not isinstance(decoded.get("after"), str):
                raise ValueError
            return decoded["after"]
        except (ValueError, TypeError, UnicodeError):
            raise ContractError("invalid_cursor") from None

    def _page(self, snapshot: Snapshot, owner_id, search, cursor):
        envelope = snapshot.items[0]
        groups = envelope["groups"]
        context = _hash([snapshot.execution_id, owner_id, snapshot.query_hash, search.sort, GROUPING_VERSION])
        if cursor is not None:
            key = self._position(cursor, context)
            previous = next((group for group in groups if group["group_key"] == key), None)
            if previous is None:
                raise ContractError("invalid_cursor")
            after = _order(previous, search.sort)
            groups = [group for group in groups if _order(group, search.sort) > after]
        items = tuple(groups[:search.page_size])
        more = len(groups) > len(items)
        coverage = envelope["storage_coverage"]
        return GroupPage(snapshot.execution_id, snapshot.query_hash, snapshot.as_of, snapshot.expires_at,
                         items, more, self._token(context, items[-1]["group_key"]) if more else None,
                         StorageCoverage(coverage["status"],
                                         tuple(tuple(utc_time(t) for t in interval) for interval in coverage["confirmed"]),
                                         tuple(tuple(utc_time(t) for t in interval) for interval in coverage["unconfirmed"])))

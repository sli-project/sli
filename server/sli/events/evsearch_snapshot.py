"""ES04 process-local PG result snapshots, never exported MVCC transactions.

The server supplies the session owner, current grants/publication and projection
revision on *every* access. ``open_rows`` is a bounded, already scoped ES03
reader context: it must honour the supplied row/time budgets and release its
connection on exit. Capture finishes and closes that context before publishing
an execution. Later clicks read detached projections, not live event IDs.

No HTTP endpoint or default reader is installed here. Cache loss (including a
restart or another worker) requires a fresh run, never a transparent live query.
"""
from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable, Iterable, Mapping
from contextlib import AbstractContextManager, contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import secrets
from threading import RLock
from time import monotonic
from typing import Any, Protocol

from server.sli.events.evsearch_contract import ContractError, SearchPolicy, authorize_request
from server.sli.events.evsearch_normalizer import NormalizedSearch

MAX_EVENTS = 250_000
MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
MAX_EXECUTIONS = 128
MAX_LIFETIME_SECONDS = 300
MAX_TIMEOUT_SECONDS = 8


class SnapshotError(ContractError):
    """A localizable reason to rerun; contains no owner or event values."""


class SnapshotReader(Protocol):
    def __call__(
        self, search: NormalizedSearch, policy: SearchPolicy, limit: int, timeout_ms: int,
    ) -> AbstractContextManager[Iterable[Mapping[str, Any]]]: ...


class PostgresSnapshotReader:
    """Adapt an ES03 compiler to a single bounded PG statement/MVCC snapshot.

    The compiler receives the authorized policy and the hard fetch limit; it
    must apply both in SQL before returning projections. The existing database
    adapter closes cursor/connection before returning even on cancellation.
    """

    def __init__(self, compile_query: Callable):
        self.compile_query = compile_query

    @contextmanager
    def __call__(self, search, policy, limit, timeout_ms):
        from server.sli.core.database import QueryTimeoutError, query_rows_bounded

        started = monotonic()
        sql, params = self.compile_query(search, policy, limit)
        remaining = timeout_ms - int((monotonic() - started) * 1000)
        if remaining <= 350:
            raise SnapshotError("snapshot_timeout")
        try:
            rows = query_rows_bounded(
                sql, params, statement_timeout_ms=remaining - 250, wall_timeout_ms=remaining,
            )
        except QueryTimeoutError:
            raise SnapshotError("snapshot_timeout") from None
        yield rows


@dataclass(frozen=True)
class Snapshot:
    execution_id: str
    query_hash: str
    as_of: datetime
    expires_at: datetime
    items: list[dict[str, Any]] = field(repr=False)


@dataclass(frozen=True)
class _Entry:
    owner_id: int = field(repr=False)
    binding: str
    query_hash: str
    as_of: datetime
    expires_at: datetime
    deadline: float
    payload: bytes = field(repr=False)

    def result(self, execution_id: str) -> Snapshot:
        return Snapshot(execution_id, self.query_hash, self.as_of, self.expires_at, json.loads(self.payload))


def _json_default(value):
    if isinstance(value, datetime) and value.tzinfo is not None:
        return value.astimezone(timezone.utc).isoformat()
    raise TypeError("unsupported_snapshot_value")


def _hash(value: Any) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                             allow_nan=False, default=_json_default).encode()).hexdigest()


def _query_hash(search: NormalizedSearch) -> str:
    query = search.as_request()
    # Pagination/presentation changes may reuse the same retained event set.
    query.pop("page_size", None)
    query.pop("entry_context", None)
    return _hash({"query": query, "account_role": search.account_role,
                  "question": asdict(search.question) if search.question else None})


def _authorization(*, owner_id, search, access, publication, fields, revision):
    if (type(owner_id) is not int or owner_id <= 0 or not fields
            or not isinstance(revision, str) or not 0 < len(revision) <= 256):
        raise ContractError("invalid_request")
    # Include semantic dependencies resolved by ES02, not only wire filters.
    policy = authorize_request(
        search.as_request(), access=access, publication=publication,
        fields=tuple(sorted(set(fields) | search.required_fields)),
    )
    scope = policy.scope.to_dict()
    # A newly issued decision for identical rights is not a policy change.
    scope.pop("decision_id", None)
    query_hash = _query_hash(search)
    binding = _hash({
        "owner": owner_id, "query": query_hash, "scope": scope,
        "fields": sorted(fields), "required_fields": sorted(policy.fields),
        "publication": publication, "revision": revision,
        "report_grants": [r for r in access.get("reports", []) if r.get("report_key") == policy.report_key],
        "capabilities": sorted(access.get("capabilities") or []), "subject": access.get("subject", {}),
    })
    return policy, query_hash, binding


class SnapshotStore:
    """One application-owned bounded store; entries never contain DB handles.

    Budgets can be reduced for an installation/test but cannot exceed the plan.
    Overflow rejects the run rather than labelling a partial top as a complete
    result. Old/evicted/foreign IDs have the same ``snapshot_expired`` response.
    """

    def __init__(
        self, *, ttl_seconds: int = MAX_LIFETIME_SECONDS, max_events: int = MAX_EVENTS,
        max_snapshot_bytes: int = MAX_SNAPSHOT_BYTES, max_total_bytes: int = MAX_TOTAL_BYTES,
        max_executions: int = MAX_EXECUTIONS, timeout_seconds: int = MAX_TIMEOUT_SECONDS,
        clock: Callable[[], float] = monotonic,
        utcnow: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ):
        for value, ceiling in (
            (ttl_seconds, MAX_LIFETIME_SECONDS), (max_events, MAX_EVENTS),
            (max_snapshot_bytes, MAX_SNAPSHOT_BYTES), (max_total_bytes, MAX_TOTAL_BYTES),
            (max_executions, MAX_EXECUTIONS), (timeout_seconds, MAX_TIMEOUT_SECONDS),
        ):
            if type(value) is not int or not 0 < value <= ceiling:
                raise ValueError("invalid_snapshot_budget")
        self.ttl_seconds = ttl_seconds
        self.max_events = max_events
        self.max_snapshot_bytes = min(max_snapshot_bytes, max_total_bytes)
        self.max_total_bytes = max_total_bytes
        self.max_executions = max_executions
        self.timeout_seconds = timeout_seconds
        self.clock = clock
        self.utcnow = utcnow
        self._entries: OrderedDict[str, _Entry] = OrderedDict()
        self._size_bytes = 0
        self._lock = RLock()

    @property
    def size_bytes(self) -> int:
        with self._lock:
            return self._size_bytes

    @property
    def execution_count(self) -> int:
        with self._lock:
            return len(self._entries)

    def _remove(self, execution_id):
        entry = self._entries.pop(execution_id)
        self._size_bytes -= len(entry.payload)

    def _purge(self):
        now = self.clock()
        for execution_id, entry in list(self._entries.items()):
            if now >= entry.deadline:
                self._remove(execution_id)

    def start(
        self, *, owner_id: int, search: NormalizedSearch, access: Mapping[str, Any],
        publication: Mapping[str, Any], fields: tuple[str, ...], revision: str,
        open_rows: SnapshotReader,
    ) -> Snapshot:
        started = self.clock()
        as_of = self.utcnow()
        policy, query_hash, binding = _authorization(
            owner_id=owner_id, search=search, access=access, publication=publication, fields=fields, revision=revision,
        )
        with self._lock:
            self._purge()
        encoder = json.JSONEncoder(ensure_ascii=False, separators=(",", ":"), allow_nan=False, default=_json_default)
        payload = bytearray(b"[")
        count = 0
        capture_deadline = started + min(self.timeout_seconds, self.ttl_seconds)

        def remaining_ms():
            remaining = int((capture_deadline - self.clock()) * 1000)
            if remaining <= 0:
                raise SnapshotError("snapshot_timeout")
            return remaining

        # The context is always exited on limit, encoding error or timeout.
        with open_rows(search, policy, self.max_events + 1, remaining_ms()) as rows:
            for row in rows:
                remaining_ms()
                if count >= self.max_events:
                    raise SnapshotError("snapshot_limit_exceeded")
                if count:
                    payload.extend(b",")
                projected = {key: row[key] for key in fields if key in row}
                try:
                    for chunk in encoder.iterencode(projected):
                        remaining_ms()
                        encoded = chunk.encode("utf-8")
                        if len(payload) + len(encoded) + 1 > self.max_snapshot_bytes:
                            raise SnapshotError("snapshot_limit_exceeded")
                        payload.extend(encoded)
                except (TypeError, ValueError) as exc:
                    if isinstance(exc, SnapshotError):
                        raise
                    raise ContractError("invalid_request") from None
                count += 1
        remaining_ms()
        payload.extend(b"]")
        if len(payload) > self.max_snapshot_bytes:
            raise SnapshotError("snapshot_limit_exceeded")
        entry = _Entry(owner_id, binding, query_hash, as_of, as_of + timedelta(seconds=self.ttl_seconds),
                       started + self.ttl_seconds, bytes(payload))
        return self._retain(entry, remaining_ms)

    def _retain(self, entry: _Entry, remaining: Callable) -> Snapshot:
        """Publish a detached, budget-checked execution (raw or ES07 grouped)."""
        execution_id = secrets.token_urlsafe(32)
        with self._lock:
            self._purge()
            remaining()
            while self._entries and (len(self._entries) >= self.max_executions
                                     or self._size_bytes + len(entry.payload) > self.max_total_bytes):
                self._remove(next(iter(self._entries)))
            self._entries[execution_id] = entry
            self._size_bytes += len(entry.payload)
        return entry.result(execution_id)

    def get(
        self, execution_id: str, *, owner_id: int, search: NormalizedSearch,
        access: Mapping[str, Any], publication: Mapping[str, Any], fields: tuple[str, ...], revision: str,
    ) -> Snapshot:
        with self._lock:
            self._purge()
            entry = self._entries.get(execution_id)
            if entry is None or type(owner_id) is not int or owner_id != entry.owner_id:
                raise SnapshotError("snapshot_expired")
            try:
                _, _, binding = _authorization(
                    owner_id=owner_id, search=search, access=access, publication=publication, fields=fields, revision=revision,
                )
            except (PermissionError, ContractError):
                self._remove(execution_id)
                raise SnapshotError("snapshot_invalidated") from None
            if binding != entry.binding:
                self._remove(execution_id)
                raise SnapshotError("snapshot_invalidated")
            self._entries.move_to_end(execution_id)
            return entry.result(execution_id)

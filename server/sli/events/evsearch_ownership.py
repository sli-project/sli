"""ES06 ownership of bounded, authorized captures, before any aggregation.

Inputs are exhaustive captures of the same authorized execution, never pages.
Retention age and batch ID ranges are not evidence of time coverage. Only
server-confirmed intervals, bound to the captured store watermark, may close a
storage gap. Collection coverage remains unknown (ES10 supplies that evidence).
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import re
from time import monotonic
from typing import Any

from server.sli.events.evsearch_contract import ContractError
from server.sli.events.evsearch_normalizer import NormalizedSearch
from server.sli.events.evsearch_snapshot import MAX_EVENTS, MAX_SNAPSHOT_BYTES, _hash, _json_default, _query_hash


class OwnershipError(ContractError):
    """A safe, localizable failure; no event values in errors."""


def utc_time(value) -> datetime:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00")) if isinstance(value, str) else value
        if not isinstance(result, datetime) or result.tzinfo is None or result.utcoffset() is None:
            raise ValueError
        return result.astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        raise OwnershipError("storage_integrity_error") from None


@dataclass(frozen=True, repr=False)
class EventIdentity:
    event_id: int
    fingerprint: str
    timestamp: datetime

    @classmethod
    def from_values(cls, event_id, fingerprint, timestamp):
        if isinstance(fingerprint, (bytes, bytearray, memoryview)):
            fingerprint = bytes(fingerprint).hex()
        if (type(event_id) is not int or not 0 < event_id < 2**63
                or not isinstance(fingerprint, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", fingerprint)):
            raise OwnershipError("storage_integrity_error")
        return cls(event_id, fingerprint.upper(), utc_time(timestamp))


def capture_binding(search, policy, fields, publication):
    scope = policy.scope.to_dict()
    scope.pop("decision_id", None)
    return _hash({"query": _query_hash(search), "scope": scope, "fields": sorted(fields),
                  "policy_fields": sorted(policy.fields), "publication": publication})


@dataclass(frozen=True)
class StoreCapture:
    store: str
    binding: str
    query_hash: str
    watermark: str
    items: tuple[dict[str, Any], ...] = field(repr=False)
    identities: tuple[EventIdentity, ...] = field(repr=False)
    exhaustive: bool = True
    status: str = "ready"


@dataclass(frozen=True)
class StorageInterval:
    """Trusted copy/retention evidence for the entire authorized resource scope."""

    start: datetime
    end: datetime
    store: str
    watermark: str


@dataclass(frozen=True)
class StorageCoverage:
    status: str
    confirmed: tuple[tuple[datetime, datetime], ...]
    unconfirmed: tuple[tuple[datetime, datetime], ...]


@dataclass(frozen=True)
class OwnershipManifest:
    binding: str
    watermarks: tuple[tuple[str, str], ...]
    statuses: tuple[tuple[str, str], ...]
    owners: tuple[tuple[int, str], ...] = field(repr=False)
    retention_boundary: datetime | None


@dataclass(frozen=True)
class OwnedResult:
    items: tuple[dict[str, Any], ...] = field(repr=False)
    manifest: OwnershipManifest
    storage_coverage: StorageCoverage
    # Successful reads/copy proofs cannot prove uninterrupted collection.
    coverage: str = "unknown"


def _coverage(search, captures, evidence):
    intervals = []
    for interval in evidence:
        start, end = utc_time(interval.start), utc_time(interval.end)
        capture = captures.get(interval.store)
        if (start >= end or capture is None or capture.status != "ready"
                or interval.watermark != capture.watermark):
            raise OwnershipError("storage_integrity_error")
        start, end = max(start, search.period.start), min(end, search.period.end)
        if start < end:
            intervals.append((start, end))
    confirmed = []
    for start, end in sorted(intervals):
        if confirmed and start <= confirmed[-1][1]:
            confirmed[-1] = (confirmed[-1][0], max(end, confirmed[-1][1]))
        else:
            confirmed.append((start, end))
    missing, cursor = [], search.period.start
    for start, end in confirmed:
        if cursor < start:
            missing.append((cursor, start))
        cursor = end
    if cursor < search.period.end:
        missing.append((cursor, search.period.end))
    return StorageCoverage("complete" if not missing else "partial" if confirmed else "unknown",
                           tuple(confirmed), tuple(missing))


def merge_captures(
    search: NormalizedSearch, *, hot: StoreCapture, cold: StoreCapture,
    evidence: tuple[StorageInterval, ...] = (), retention_boundary: datetime | None = None,
    timeout_ms: int = 8000, clock=monotonic,
) -> OwnedResult:
    """Pin one owner per ID: PG wins identical overlap, CH owns cold-only IDs.

    Scan the full window in both stores: older PG rows remain a valid fallback
    during copy gaps. A caller may supply an unavailable empty capture, but it
    must preserve the binding and explicitly mark its status as unavailable.
    No count/zero/completeness claim is inferred from the returned rows.
    """
    if type(timeout_ms) is not int or not 0 < timeout_ms <= 8000:
        raise ContractError("invalid_request")
    deadline = clock() + timeout_ms / 1000

    def remaining():
        if clock() >= deadline:
            raise OwnershipError("storage_timeout")

    if (hot.store != "postgres" or cold.store != "clickhouse"
            or not hot.binding or hot.binding != cold.binding
            or hot.query_hash != _query_hash(search) or cold.query_hash != hot.query_hash):
        raise OwnershipError("storage_integrity_error")
    boundary = utc_time(retention_boundary) if retention_boundary is not None else None
    owned, size = {}, 2
    # Validate even discarded copies, before assigning ownership or counting.
    for capture in (hot, cold):
        if not capture.exhaustive:
            raise OwnershipError("storage_limit_exceeded")
        if (capture.status not in {"ready", "unavailable", "timeout"}
                or len(capture.items) != len(capture.identities)
                or (capture.status != "ready" and (capture.items or capture.identities))
                or (capture.status == "ready" and not capture.watermark)):
            raise OwnershipError("storage_integrity_error")
        if len(capture.items) > MAX_EVENTS:
            raise OwnershipError("storage_limit_exceeded")
        seen = set()
        for item, identity in zip(capture.items, capture.identities):
            remaining()
            if not isinstance(identity, EventIdentity):
                raise OwnershipError("storage_integrity_error")
            checked = EventIdentity.from_values(identity.event_id, identity.fingerprint, identity.timestamp)
            if (checked.event_id in seen or not search.period.start <= checked.timestamp < search.period.end
                    or not isinstance(item, Mapping)
                    or ("id" in item and item["id"] != checked.event_id)
                    or ("time_created_utc" in item and utc_time(item["time_created_utc"]) != checked.timestamp)):
                raise OwnershipError("storage_integrity_error")
            seen.add(checked.event_id)
            previous = owned.get(checked.event_id)
            if previous:
                if previous[0] != checked:
                    raise OwnershipError("storage_integrity_error")
                continue
            # Account for projections before allocating the merged snapshot.
            try:
                size += len(json.dumps(item, ensure_ascii=False, allow_nan=False, default=_json_default).encode()) + 1
            except (TypeError, ValueError):
                raise OwnershipError("storage_integrity_error") from None
            if len(owned) >= MAX_EVENTS or size > MAX_SNAPSHOT_BYTES:
                raise OwnershipError("storage_limit_exceeded")
            owned[checked.event_id] = (checked, capture.store, deepcopy(dict(item)))
    ordered = sorted(owned.values(), key=lambda row: (row[0].timestamp, row[0].event_id),
                     reverse=search.sort != "time_asc")
    manifest = OwnershipManifest(hot.binding, ((hot.store, hot.watermark), (cold.store, cold.watermark)),
                                 ((hot.store, hot.status), (cold.store, cold.status)),
                                 tuple((row[0].event_id, row[1]) for row in ordered), boundary)
    coverage = _coverage(search, {hot.store: hot, cold.store: cold}, evidence)
    remaining()
    return OwnedResult(tuple(row[2] for row in ordered), manifest, coverage)

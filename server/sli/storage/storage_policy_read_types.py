from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal

from server.sli.storage.storage_policy_format import _iso

StorageReadQueryKind = Literal["session_analytics", "atomic_evidence"]


StorageReadTier = Literal["postgres_hot", "clickhouse_warm", "canonical_archive"]


StorageReadRepresentation = Literal["atomic_event", "session", "full_payload"]


StorageReadAvailability = Literal[
    "atomic_evidence_available",
    "source_archived",
    "derived_only_available",
    "data_unavailable",
]


@dataclass(frozen=True)
class StorageReadSegment:
    tier: StorageReadTier
    time_from_utc: datetime
    time_to_utc: datetime
    representation: StorageReadRepresentation
    ready: bool
    blocker: str | None = None
    availability: StorageReadAvailability = "data_unavailable"
    source_link: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tier": self.tier,
            "time_from_utc": _iso(self.time_from_utc),
            "time_to_utc": _iso(self.time_to_utc),
            "representation": self.representation,
            "ready": self.ready,
            "blocker": self.blocker,
            "availability": self.availability,
            "source_link": self.source_link,
        }


@dataclass(frozen=True)
class StorageReadPlan:
    query_kind: StorageReadQueryKind
    segments: tuple[StorageReadSegment, ...]
    complete: bool
    blockers: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "query_kind": self.query_kind,
            "segments": [segment.to_dict() for segment in self.segments],
            "complete": self.complete,
            "blockers": list(self.blockers),
        }


def _require_utc_aware(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")
    return value.astimezone(timezone.utc)

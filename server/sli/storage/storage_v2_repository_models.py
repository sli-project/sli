"""Storage V2 repository value types, chunk digest and row codecs (pure, never patched)."""
from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from server.sli.storage.storage_v2_models import (
    EntityCoreV2,
    EventCoreV2,
    EventFactsV2,
    LinkCoreV2,
    canonical_json_bytes,
    sha256_bytes,
)

DICTIONARY_TABLES = {
    "provider": "storage_v2_provider",
    "channel": "storage_v2_channel",
    "computer": "storage_v2_computer",
    "keywords": "storage_v2_keywords",
    "domain": "storage_v2_domain_name",
    "role": "storage_v2_role",
    "extracted_from": "storage_v2_extracted_from",
    "entity_type": "storage_v2_entity_type",
}


@dataclass(frozen=True)
class BackfillCheckpoint:
    worker_name: str
    high_watermark_event_id: int | None = None
    last_verified_event_id: int = 0
    chunk_size: int = 25_000
    state: str = "ready"
    lease_token: str | None = None
    lease_until: datetime | None = None
    source_rows: int = 0
    target_rows: int = 0
    last_error: str | None = None


@dataclass(frozen=True)
class OutboxItem:
    id: int
    batch_id: str
    first_event_id: int
    last_event_id: int
    event_count: int
    event_ids: tuple[int, ...]
    identity_sha256: bytes
    state: str = "pending"
    attempt_count: int = 0
    available_at: datetime = field(default_factory=lambda: datetime.min.replace(tzinfo=timezone.utc))
    lease_token: str | None = None
    lease_until: datetime | None = None
    last_error: str | None = None


@dataclass(frozen=True)
class BackfillChunkAudit:
    worker_name: str
    chunk_start_event_id: int
    chunk_end_event_id: int
    source_event_rows: int
    target_event_rows: int
    source_link_rows: int
    target_link_rows: int
    source_sha256: bytes
    target_sha256: bytes
    archive_event_set_id: str
    archive_link_set_id: str | None
    wal_bytes: int | None = None
    duration_ms: int = 0
    status: str = "verified"


def core_chunk_digest(
    events: Sequence[EventCoreV2],
    entities: Sequence[EntityCoreV2],
    links: Sequence[LinkCoreV2],
    facts: Sequence[EventFactsV2] = (),
) -> bytes:
    digest = hashlib.sha256()
    rows: list[tuple[str, str, bytes]] = []
    rows.extend(("event", str(item.values["id"]), item.source_core_sha256) for item in events)
    rows.extend(
        ("event_facts", str(item.values["event_id"]), item.source_facts_sha256)
        for item in facts
    )
    rows.extend(("entity", str(item.values["id"]), item.source_core_sha256) for item in entities)
    rows.extend(
        (
            "entity_details",
            str(item.values["id"]),
            bytes(item.source_details_sha256) if item.source_details_sha256 is not None else hashlib.sha256(b"null").digest(),
        )
        for item in entities
    )
    rows.extend(
        (
            "link",
            f"{item.values['event_id']}:{item.values['entity_id']}:{item.values['role_id']}",
            item.source_core_sha256,
        )
        for item in links
    )
    for kind, identity, row_hash in sorted(rows):
        digest.update(kind.encode("ascii") + b"\0" + identity.encode("ascii") + b"\0" + bytes(row_hash) + b"\n")
    return digest.digest()


def _resolved_link_core(item: LinkCoreV2, entity_id: int) -> LinkCoreV2:
    """Return the canonical persisted identity without rewriting source evidence."""
    values = dict(item.values)
    values["entity_id"] = int(entity_id)
    details = dict(item.details) if item.details is not None else None
    if details is not None:
        details["entity_id"] = int(entity_id)
    return LinkCoreV2(
        values=values,
        source_core_sha256=sha256_bytes(canonical_json_bytes(values)),
        details=details,
    )


def _resolve_link_cores(
    links: Sequence[LinkCoreV2], entity_mapping: Mapping[int, int]
) -> list[LinkCoreV2]:
    resolved = [
        _resolved_link_core(
            item,
            int(entity_mapping.get(int(item.values["entity_id"]), item.values["entity_id"])),
        )
        for item in links
    ]
    identities = [
        (
            int(item.values["event_id"]),
            int(item.values["entity_id"]),
            int(item.values["role_id"]),
        )
        for item in resolved
    ]
    if len(set(identities)) != len(identities):
        raise RuntimeError("resolved link identity collision")
    return resolved


def _checkpoint_from_row(row: Mapping[str, Any]) -> BackfillCheckpoint:
    return BackfillCheckpoint(
        worker_name=str(row["worker_name"]),
        high_watermark_event_id=int(row["high_watermark_event_id"]) if row.get("high_watermark_event_id") is not None else None,
        last_verified_event_id=int(row.get("last_verified_event_id") or 0),
        chunk_size=int(row.get("chunk_size") or 25_000),
        state=str(row.get("state") or "ready"),
        lease_token=str(row["lease_token"]) if row.get("lease_token") else None,
        lease_until=row.get("lease_until"),
        source_rows=int(row.get("source_rows") or 0),
        target_rows=int(row.get("target_rows") or 0),
        last_error=row.get("last_error"),
    )


def _outbox_from_row(row: Mapping[str, Any]) -> OutboxItem:
    return OutboxItem(
        id=int(row["id"]), batch_id=str(row["batch_id"]), first_event_id=int(row["first_event_id"]),
        last_event_id=int(row["last_event_id"]), event_count=int(row["event_count"]),
        event_ids=tuple(int(value) for value in row["event_ids"]),
        identity_sha256=bytes(row["identity_sha256"]), state=str(row["state"]),
        attempt_count=int(row.get("attempt_count") or 0), available_at=row.get("available_at") or datetime.now(timezone.utc),
        lease_token=str(row["lease_token"]) if row.get("lease_token") else None,
        lease_until=row.get("lease_until"), last_error=row.get("last_error"),
    )

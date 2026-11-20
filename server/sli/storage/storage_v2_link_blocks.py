"""Block-adjacency contract for Storage V2 entity-to-event links.

PostgreSQL stores only these blocks.  Event-first detail reads are served from
the identity-bound compact archive, never by scanning block min/max ranges.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import AbstractSet, Iterable, Mapping, Sequence

from server.sli.storage.storage_v2_compact_archive import (
    INT32_MAX,
    INT64_MAX,
    decode_link_metadata,
    link_identity_struct,
)

BLOCK_SIZE = 512


class LinkBlockError(RuntimeError):
    pass


@dataclass(frozen=True)
class LinkBlock:
    entity_id: int
    block_no: int
    event_ids: tuple[int, ...]
    role_ids: tuple[int, ...]
    identity_sha256: bytes

    @property
    def first_event_id(self) -> int:
        return self.event_ids[0]

    @property
    def last_event_id(self) -> int:
        return self.event_ids[-1]


def _identity(row: Mapping[str, object]) -> tuple[int, int, int]:
    event_id = int(row["event_id"])
    entity_id = int(row["entity_id"])
    role_id = int(row["role_id"])
    if not 0 < event_id <= INT64_MAX:
        raise LinkBlockError("event identity exceeds positive int64 capacity")
    if not 0 < entity_id <= INT32_MAX:
        raise LinkBlockError("entity identity exceeds positive int32 capacity")
    if not 0 <= role_id <= 32_767:
        raise LinkBlockError("role_id exceeds PostgreSQL smallint capacity")
    return event_id, entity_id, role_id


def build_link_blocks(rows: Iterable[Mapping[str, object]], *, block_size: int = BLOCK_SIZE) -> list[LinkBlock]:
    if not 1 <= block_size <= BLOCK_SIZE:
        raise LinkBlockError(f"block_size must be between 1 and {BLOCK_SIZE}")
    identities = sorted(_identity(row) for row in rows)
    if any(left == right for left, right in zip(identities, identities[1:])):
        raise LinkBlockError("duplicate event/entity/role identity")
    by_entity: dict[int, list[tuple[int, int]]] = {}
    for event_id, entity_id, role_id in identities:
        by_entity.setdefault(entity_id, []).append((event_id, role_id))
    blocks: list[LinkBlock] = []
    for entity_id in sorted(by_entity):
        entity_rows = by_entity[entity_id]
        for block_no, start in enumerate(range(0, len(entity_rows), block_size)):
            chunk = entity_rows[start:start + block_size]
            identity_struct = link_identity_struct(chunk[-1][0])
            packed = b"".join(identity_struct.pack(event_id, entity_id, role_id) for event_id, role_id in chunk)
            blocks.append(LinkBlock(
                entity_id=entity_id, block_no=block_no,
                event_ids=tuple(event_id for event_id, _ in chunk),
                role_ids=tuple(role_id for _, role_id in chunk),
                identity_sha256=hashlib.sha256(packed).digest(),
            ))
    return blocks


def validate_link_blocks(blocks: Sequence[LinkBlock]) -> None:
    """Validate immutable block identities before a tail append or acceptance scan."""
    expected_block_no: dict[int, int] = {}
    previous_identity: dict[int, tuple[int, int]] = {}
    seen: set[tuple[int, int, int]] = set()
    for block in blocks:
        if block.block_no != expected_block_no.get(block.entity_id, 0):
            raise LinkBlockError("link block numbers are not contiguous from zero")
        expected_block_no[block.entity_id] = block.block_no + 1
        if not 1 <= len(block.event_ids) <= BLOCK_SIZE:
            raise LinkBlockError("link block size is outside the storage contract")
        if len(block.event_ids) != len(block.role_ids):
            raise LinkBlockError("link block parallel arrays have different lengths")
        identities: list[tuple[int, int, int]] = []
        for event_id, role_id in zip(block.event_ids, block.role_ids):
            identity = _identity({
                "event_id": event_id, "entity_id": block.entity_id, "role_id": role_id,
            })
            if identity in seen:
                raise LinkBlockError("duplicate event/entity/role identity across blocks")
            seen.add(identity)
            identities.append(identity)
        if identities != sorted(identities):
            raise LinkBlockError("link block identities are not ordered")
        prior = previous_identity.get(block.entity_id)
        first = (identities[0][0], identities[0][2])
        last = (identities[-1][0], identities[-1][2])
        if prior is not None and first <= prior:
            raise LinkBlockError("link block ranges overlap or are out of order")
        previous_identity[block.entity_id] = last
        identity_struct = link_identity_struct(identities[-1][0])
        packed = b"".join(identity_struct.pack(*identity) for identity in identities)
        if hashlib.sha256(packed).digest() != block.identity_sha256:
            raise LinkBlockError("link block identity SHA-256 mismatch")


def append_link_block_tail(
    tail: LinkBlock | None,
    rows: Iterable[Mapping[str, object]],
) -> list[LinkBlock]:
    """Return only the changed tail and new blocks; historical blocks stay immutable."""
    incoming = [dict(row) for row in rows]
    if not incoming:
        return []
    identities = [_identity(row) for row in incoming]
    if len(set(identities)) != len(identities):
        raise LinkBlockError("duplicate event/entity/role identity")
    entity_ids = {identity[1] for identity in identities}
    if len(entity_ids) != 1:
        raise LinkBlockError("tail append accepts exactly one entity")
    start_block_no = 0
    combined = incoming
    if tail is not None:
        validate_link_blocks([LinkBlock(
            entity_id=tail.entity_id,
            block_no=0,
            event_ids=tail.event_ids,
            role_ids=tail.role_ids,
            identity_sha256=tail.identity_sha256,
        )])
        if tail.entity_id not in entity_ids:
            raise LinkBlockError("tail entity does not match incoming rows")
        if min((identity[0], identity[2]) for identity in identities) <= (
            tail.event_ids[-1], tail.role_ids[-1]
        ):
            raise LinkBlockError("late or replayed non-identical link requires deterministic entity rebuild")
        combined = [
            {"event_id": event_id, "entity_id": tail.entity_id, "role_id": role_id}
            for event_id, role_id in zip(tail.event_ids, tail.role_ids)
        ] + incoming
        start_block_no = tail.block_no
    rebuilt = build_link_blocks(combined)
    return [
        LinkBlock(
            entity_id=block.entity_id,
            block_no=start_block_no + block.block_no,
            event_ids=block.event_ids,
            role_ids=block.role_ids,
            identity_sha256=block.identity_sha256,
        )
        for block in rebuilt
    ]


def rebuild_link_block_suffix(existing: Sequence[LinkBlock], rows: Iterable[Mapping[str, object]]) -> list[LinkBlock]:
    """Rebuild the affected suffix, preserving all earlier block identities."""
    if not existing:
        raise LinkBlockError("suffix rebuild requires existing blocks")
    start = existing[0].block_no
    entity_id = existing[0].entity_id
    incoming = [dict(row) for row in rows]
    if any(block.entity_id != entity_id for block in existing) or any(
        _identity(row)[1] != entity_id for row in incoming
    ):
        raise LinkBlockError("suffix entity does not match incoming rows")
    validate_link_blocks([
        LinkBlock(block.entity_id, block.block_no - start, block.event_ids, block.role_ids, block.identity_sha256)
        for block in existing
    ])
    combined = [
        {"event_id": event_id, "entity_id": entity_id, "role_id": role_id}
        for block in existing
        for event_id, role_id in zip(block.event_ids, block.role_ids)
    ] + incoming
    return [
        LinkBlock(block.entity_id, block.block_no + start, block.event_ids, block.role_ids, block.identity_sha256)
        for block in build_link_blocks(combined)
    ]


def append_link_blocks(existing: Iterable[LinkBlock], rows: Iterable[Mapping[str, object]]) -> list[LinkBlock]:
    """Idempotently append strictly newer identities; late rows require rebuild/quarantine."""
    current = list(existing)
    known = {
        (event_id, block.entity_id, role_id)
        for block in current
        for event_id, role_id in zip(block.event_ids, block.role_ids)
    }
    incoming_list = [_identity(row) for row in rows]
    incoming = set(incoming_list)
    if len(incoming) != len(incoming_list):
        raise LinkBlockError("duplicate event/entity/role identity")
    new_rows = incoming - known
    max_by_entity = {block.entity_id: block.last_event_id for block in current}
    for event_id, entity_id, _ in new_rows:
        if entity_id in max_by_entity and event_id <= max_by_entity[entity_id]:
            raise LinkBlockError("late or replayed non-identical link requires deterministic entity rebuild")
    combined = [
        {"event_id": event_id, "entity_id": entity_id, "role_id": role_id}
        for event_id, entity_id, role_id in known | new_rows
    ]
    return build_link_blocks(combined)


def validate_no_orphans(blocks: Iterable[LinkBlock], *, event_ids: AbstractSet[int], entity_ids: AbstractSet[int]) -> None:
    for block in blocks:
        if block.entity_id not in entity_ids:
            raise LinkBlockError(f"orphan entity_id {block.entity_id}")
        missing = next((event_id for event_id in block.event_ids if event_id not in event_ids), None)
        if missing is not None:
            raise LinkBlockError(f"orphan event_id {missing}")


def find_event_links_in_archive(compressed: bytes, event_id: int, *, max_matches: int = 10_000) -> list[dict[str, object]]:
    """Exact event-first lookup after the manifest bounded the archive block range."""
    matches = [row for row in decode_link_metadata(compressed) if int(row["event_id"]) == int(event_id)]
    if len(matches) > max_matches:
        raise LinkBlockError("event link lookup exceeds bounded match limit")
    return matches

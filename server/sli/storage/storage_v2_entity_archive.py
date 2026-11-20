"""Identity-bound batch archive for Storage V2 entity display/details."""
from __future__ import annotations

import gzip
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable, Mapping


class EntityArchiveError(RuntimeError):
    pass


@dataclass(frozen=True)
class EntityArchiveBlock:
    first_entity_id: int
    last_entity_id: int
    compressed: bytes
    compressed_sha256: str


def encode_entity_details(rows: Iterable[Mapping[str, Any]]) -> tuple[EntityArchiveBlock, dict[str, Any]]:
    ordered = sorted((dict(row) for row in rows), key=lambda row: int(row["id"]))
    if not ordered:
        raise EntityArchiveError("entity archive block cannot be empty")
    ids = [int(row["id"]) for row in ordered]
    if len(ids) != len(set(ids)):
        raise EntityArchiveError("duplicate entity id in archive block")
    raw = b"".join(
        json.dumps(
            {"id": entity_id, "display_name": row.get("display_name"), "attributes_json": row.get("attributes_json")},
            ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str,
        ).encode("utf-8") + b"\n"
        for entity_id, row in zip(ids, ordered)
    )
    compressed = gzip.compress(raw, compresslevel=6, mtime=0)
    compressed_sha = hashlib.sha256(compressed).hexdigest().upper()
    block = EntityArchiveBlock(ids[0], ids[-1], compressed, compressed_sha)
    return block, {
        "rows": len(ids), "raw_bytes": len(raw), "compressed_bytes": len(compressed),
        "raw_sha256": hashlib.sha256(raw).hexdigest().upper(),
        "compressed_sha256": compressed_sha,
        "identity_sha256": hashlib.sha256(b"".join(value.to_bytes(4, "little", signed=False) for value in ids)).hexdigest().upper(),
        "content_persisted": False,
    }


def decode_entity_details(block: EntityArchiveBlock) -> dict[int, dict[str, Any]]:
    if hashlib.sha256(block.compressed).hexdigest().upper() != block.compressed_sha256:
        raise EntityArchiveError("entity archive compressed SHA-256 mismatch")
    try:
        raw = gzip.decompress(block.compressed)
    except Exception as exc:
        raise EntityArchiveError(f"entity archive compression integrity failure: {exc}") from exc
    result: dict[int, dict[str, Any]] = {}
    for line in raw.splitlines():
        row = json.loads(line.decode("utf-8"))
        entity_id = int(row["id"])
        if entity_id in result:
            raise EntityArchiveError("duplicate entity id while decoding archive")
        result[entity_id] = row
    if not result or min(result) != block.first_entity_id or max(result) != block.last_entity_id:
        raise EntityArchiveError("entity archive range mismatch")
    return result


def read_entity_details_many(
    blocks: Iterable[EntityArchiveBlock], entity_ids: Iterable[int], *, max_blocks: int = 8,
) -> dict[int, dict[str, Any]]:
    requested = {int(value) for value in entity_ids}
    if not requested:
        return {}
    selected = [
        block for block in blocks
        if block.last_entity_id >= min(requested) and block.first_entity_id <= max(requested)
    ]
    if len(selected) > max_blocks:
        raise EntityArchiveError("entity hydration exceeds bounded archive block limit")
    hydrated: dict[int, dict[str, Any]] = {}
    for block in selected:
        for entity_id, row in decode_entity_details(block).items():
            if entity_id in requested:
                hydrated[entity_id] = row
    missing = sorted(requested - hydrated.keys())
    if missing:
        raise EntityArchiveError(f"entity archive is missing requested identities: {missing[:5]}")
    return hydrated

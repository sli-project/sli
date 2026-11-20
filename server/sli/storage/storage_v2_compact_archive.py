"""Deterministic identity-bound compact blocks for Storage V2 link metadata."""
from __future__ import annotations

import gzip
import hashlib
import json
import struct
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

MAGIC = b"SLILNK1\0"
MAGIC_V2 = b"SLILNK2\0"
HEADER_LENGTH = struct.Struct("<I")
IDENTITY = struct.Struct("<iiH")
RECORD = struct.Struct("<iiHfHq")
IDENTITY_V2 = struct.Struct("<qiH")
RECORD_V2 = struct.Struct("<qiHfHq")
INT32_MAX = 2_147_483_647
INT64_MAX = 9_223_372_036_854_775_807
UINT16_MAX = 65_535


class CompactArchiveError(RuntimeError):
    pass


def link_identity_struct(max_event_id: int) -> struct.Struct:
    """Keep legacy hashes for int32 blocks; widen only blocks that need it."""
    return IDENTITY_V2 if max_event_id > INT32_MAX else IDENTITY


def _timestamp_us(value: Any) -> int:
    if isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    elif isinstance(value, datetime):
        parsed = value
    else:
        raise CompactArchiveError("created_at must be an ISO timestamp or datetime")
    if parsed.tzinfo is None:
        raise CompactArchiveError("created_at must include timezone")
    return int(round(parsed.astimezone(timezone.utc).timestamp() * 1_000_000))


def _float32(value: Any) -> float:
    return struct.unpack("<f", struct.pack("<f", float(value)))[0]


def encode_link_metadata(rows: Iterable[Mapping[str, Any]]) -> tuple[bytes, dict[str, Any]]:
    ordered = [dict(row) for row in rows]
    if not ordered:
        raise CompactArchiveError("link metadata block cannot be empty")
    ordered.sort(key=lambda row: (int(row["event_id"]), int(row["entity_id"]), int(row["role_id"])))
    wide = int(ordered[-1]["event_id"]) > INT32_MAX
    identity_struct = IDENTITY_V2 if wide else IDENTITY
    record_struct = RECORD_V2 if wide else RECORD
    magic = MAGIC_V2 if wide else MAGIC
    version = 2 if wide else 1
    extracted_values = sorted({str(row.get("extracted_from") or "") for row in ordered})
    if len(extracted_values) > UINT16_MAX:
        raise CompactArchiveError("extracted_from dictionary exceeds uint16 capacity")
    extracted_ids = {value: index for index, value in enumerate(extracted_values)}
    base_timestamp_us = _timestamp_us(ordered[0]["created_at"])
    identities = bytearray()
    records = bytearray()
    previous: tuple[int, int, int] | None = None
    for row in ordered:
        event_id = int(row["event_id"])
        entity_id = int(row["entity_id"])
        role_id = int(row["role_id"])
        if not 0 < event_id <= INT64_MAX:
            raise CompactArchiveError("event identity exceeds positive int64 capacity")
        if not 0 < entity_id <= INT32_MAX:
            raise CompactArchiveError("entity identity exceeds positive int32 capacity")
        if not 0 <= role_id <= UINT16_MAX:
            raise CompactArchiveError("role_id exceeds uint16 capacity")
        identity = (event_id, entity_id, role_id)
        if identity == previous:
            raise CompactArchiveError(f"duplicate link identity: {identity}")
        previous = identity
        confidence = _float32(row.get("confidence", 1.0))
        if not 0.0 <= confidence <= 1.0:
            raise CompactArchiveError("confidence must be between 0 and 1")
        extracted_id = extracted_ids[str(row.get("extracted_from") or "")]
        delta_us = _timestamp_us(row["created_at"]) - base_timestamp_us
        identities.extend(identity_struct.pack(*identity))
        records.extend(record_struct.pack(event_id, entity_id, role_id, confidence, extracted_id, delta_us))
    header = {
        "format": f"storage-v2-link-metadata-v{version}",
        "rows": len(ordered),
        "record_size": record_struct.size,
        "base_timestamp_us": base_timestamp_us,
        "extracted_from": extracted_values,
        "identity_sha256": hashlib.sha256(identities).hexdigest().upper(),
    }
    header_bytes = json.dumps(header, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    raw = magic + HEADER_LENGTH.pack(len(header_bytes)) + header_bytes + records
    compressed = gzip.compress(raw, compresslevel=6, mtime=0)
    return compressed, {
        "rows": len(ordered), "raw_bytes": len(raw), "compressed_bytes": len(compressed),
        "raw_sha256": hashlib.sha256(raw).hexdigest().upper(),
        "compressed_sha256": hashlib.sha256(compressed).hexdigest().upper(),
        "identity_sha256": header["identity_sha256"], "content_persisted": False,
    }


def decode_link_metadata(compressed: bytes) -> list[dict[str, Any]]:
    try:
        raw = gzip.decompress(compressed)
    except Exception as exc:
        raise CompactArchiveError(f"compressed block integrity failure: {exc}") from exc
    if not raw.startswith((MAGIC, MAGIC_V2)) or len(raw) < len(MAGIC) + HEADER_LENGTH.size:
        raise CompactArchiveError("invalid compact link metadata magic")
    wide = raw.startswith(MAGIC_V2)
    identity_struct = IDENTITY_V2 if wide else IDENTITY
    record_struct = RECORD_V2 if wide else RECORD
    version = 2 if wide else 1
    offset = len(MAGIC)
    header_length = HEADER_LENGTH.unpack_from(raw, offset)[0]
    offset += HEADER_LENGTH.size
    try:
        header = json.loads(raw[offset:offset + header_length].decode("utf-8"))
    except Exception as exc:
        raise CompactArchiveError(f"invalid compact link metadata header: {exc}") from exc
    offset += header_length
    if header.get("format") != f"storage-v2-link-metadata-v{version}" or header.get("record_size") != record_struct.size:
        raise CompactArchiveError("unsupported compact link metadata format")
    expected_rows = int(header.get("rows", -1))
    payload = raw[offset:]
    if expected_rows < 0 or len(payload) != expected_rows * record_struct.size:
        raise CompactArchiveError("compact link metadata row framing mismatch")
    dictionary = list(header.get("extracted_from") or [])
    base_timestamp_us = int(header["base_timestamp_us"])
    identities = bytearray()
    decoded: list[dict[str, Any]] = []
    previous: tuple[int, int, int] | None = None
    for position in range(0, len(payload), record_struct.size):
        event_id, entity_id, role_id, confidence, extracted_id, delta_us = record_struct.unpack_from(payload, position)
        identity = (event_id, entity_id, role_id)
        if previous is not None and identity <= previous:
            raise CompactArchiveError("compact link identities are not strictly ordered")
        previous = identity
        if extracted_id >= len(dictionary):
            raise CompactArchiveError("compact link dictionary reference is out of range")
        identities.extend(identity_struct.pack(*identity))
        timestamp = datetime.fromtimestamp((base_timestamp_us + delta_us) / 1_000_000, tz=timezone.utc)
        decoded.append({
            "event_id": event_id, "entity_id": entity_id, "role_id": role_id,
            "confidence": confidence, "extracted_from": dictionary[extracted_id],
            "created_at": timestamp.isoformat().replace("+00:00", "Z"),
        })
    actual_identity_sha = hashlib.sha256(identities).hexdigest().upper()
    if actual_identity_sha != header.get("identity_sha256"):
        raise CompactArchiveError("compact link identity SHA-256 mismatch")
    return decoded

from __future__ import annotations

import struct

import pytest

from server.sli.storage.storage_v2_compact_archive import (
    CompactArchiveError,
    decode_link_metadata,
    encode_link_metadata,
)


def _f32(value: float) -> float:
    return struct.unpack("<f", struct.pack("<f", value))[0]


def test_link_metadata_roundtrip_binds_identity_dictionary_and_nonmonotonic_time() -> None:
    rows = [
        {"event_id": 2, "entity_id": 9, "role_id": 3, "confidence": 0.7, "extracted_from": "xml", "created_at": "2026-07-14T00:00:00.123456Z"},
        {"event_id": 1, "entity_id": 7, "role_id": 1, "confidence": 1.0, "extracted_from": "event_data", "created_at": "2026-07-14T00:00:05.654321Z"},
    ]
    compressed, evidence = encode_link_metadata(rows)
    decoded = decode_link_metadata(compressed)
    assert [(row["event_id"], row["entity_id"], row["role_id"]) for row in decoded] == [(1, 7, 1), (2, 9, 3)]
    assert decoded[0]["created_at"] == "2026-07-14T00:00:05.654321Z"
    assert decoded[1]["created_at"] == "2026-07-14T00:00:00.123456Z"
    assert decoded[1]["confidence"] == _f32(0.7)
    assert decoded[1]["extracted_from"] == "xml"
    assert evidence["rows"] == 2
    assert evidence["content_persisted"] is False


@pytest.mark.parametrize("event_id", [1, 2_147_483_648])
def test_link_metadata_corruption_is_rejected(event_id) -> None:
    compressed, _ = encode_link_metadata([{"event_id": event_id, "entity_id": 2, "role_id": 3, "confidence": 1.0, "extracted_from": "xml", "created_at": "2026-07-14T00:00:00Z"}])
    damaged = bytearray(compressed)
    damaged[len(damaged) // 2] ^= 0x40
    with pytest.raises(CompactArchiveError):
        decode_link_metadata(bytes(damaged))


def test_link_metadata_rejects_int64_overflow_and_duplicates() -> None:
    base = {"event_id": 1, "entity_id": 2, "role_id": 3, "confidence": 1.0, "extracted_from": "xml", "created_at": "2026-07-14T00:00:00Z"}
    with pytest.raises(CompactArchiveError, match="int64"):
        encode_link_metadata([{**base, "event_id": 9_223_372_036_854_775_808}])
    with pytest.raises(CompactArchiveError, match="duplicate"):
        encode_link_metadata([base, dict(base)])
    with pytest.raises(CompactArchiveError, match="int32"):
        encode_link_metadata([{**base, "entity_id": 2_147_483_648}])


@pytest.mark.parametrize("event_id", [2_147_483_648, 9_223_372_036_854_775_807])
def test_link_metadata_roundtrip_accepts_bigint_events(event_id) -> None:
    rows = [
        {"event_id": 1, "entity_id": 2, "role_id": 3, "created_at": "2026-07-14T00:00:00Z"},
        {"event_id": event_id, "entity_id": 2, "role_id": 3, "created_at": "2026-07-14T00:00:00Z"},
    ]
    compressed, _ = encode_link_metadata(rows)
    assert [row["event_id"] for row in decode_link_metadata(compressed)] == [1, event_id]


def test_legacy_link_archive_encoding_is_unchanged() -> None:
    import gzip
    import hashlib

    compressed, metadata = encode_link_metadata([
        {"event_id": 1, "entity_id": 2, "role_id": 3, "created_at": "2026-07-14T00:00:00Z"},
    ])
    raw = gzip.decompress(compressed)
    assert raw.startswith(b"SLILNK1\0")
    assert metadata["identity_sha256"] == hashlib.sha256(struct.pack("<iiH", 1, 2, 3)).hexdigest().upper()
    assert decode_link_metadata(compressed)[0]["event_id"] == 1

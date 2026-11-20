from __future__ import annotations

import hashlib

from scripts.maintenance.stage7_clickhouse_candidate_a import (
    _payload_sha256,
    _prepare_insert_row,
    _render_multiset_accumulator,
    _update_link_digest,
    _update_multiset_accumulator,
    _verification_row_digest,
)


def test_payload_hash_distinguishes_null_from_empty() -> None:
    base = {"event_data_json": "{}", "record_xml": "<x/>"}
    null_hash = _payload_sha256({**base, "message_text": None})
    empty_hash = _payload_sha256({**base, "message_text": ""})

    assert null_hash != empty_hash
    assert len(null_hash) == 64


def test_link_digest_is_order_and_role_sensitive() -> None:
    first = hashlib.sha256()
    second = hashlib.sha256()
    _update_link_digest(first, 10, [100, 200], [1, 2])
    _update_link_digest(second, 10, [200, 100], [2, 1])

    assert first.digest() != second.digest()


def test_prepare_insert_row_keeps_full_payload() -> None:
    row = {
        "id": 10,
        "time_created_utc": "2026-07-27T01:02:03.123456+00:00",
        "normalized_at": "2026-07-27T01:02:04.123456+00:00",
        "event_data_json": '{"x":1}',
        "message_text": "message",
        "record_xml": "<Event/>",
    }

    prepared = _prepare_insert_row(
        row,
        portable_uid="sli-event-v1:" + "a" * 64,
        entity_ids=[1],
        role_ids=[2],
    )

    assert prepared["source_id"] == 10
    assert prepared["event_data_json"] == '{"x":1}'
    assert prepared["record_xml"] == "<Event/>"
    assert prepared["entity_ids"] == [1]


def _multiset(rows: list[dict[str, object]]) -> dict[str, str]:
    xor_value = 0
    sum_value = 0
    for row in rows:
        digest = _verification_row_digest(
            source_id=int(row["source_id"]),
            event_uid_value=str(row["event_uid_value"]),
            payload_hash=str(row["payload_hash"]),
            entity_ids=[int(value) for value in row["entity_ids"]],
            role_ids=[int(value) for value in row["role_ids"]],
        )
        xor_value, sum_value = _update_multiset_accumulator(
            xor_value,
            sum_value,
            digest,
        )
    return _render_multiset_accumulator(xor_value, sum_value)


def test_verification_multiset_is_order_independent_and_duplicate_sensitive() -> None:
    rows = [
        {
            "source_id": 10,
            "event_uid_value": "sli-event-v1:" + "a" * 64,
            "payload_hash": "ab" * 32,
            "entity_ids": [100],
            "role_ids": [1],
        },
        {
            "source_id": 20,
            "event_uid_value": "sli-event-v1:" + "b" * 64,
            "payload_hash": "cd" * 32,
            "entity_ids": [200, 300],
            "role_ids": [2, 3],
        },
    ]

    assert _multiset(rows) == _multiset(list(reversed(rows)))
    assert _multiset(rows) != _multiset([*rows, rows[0]])

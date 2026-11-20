from __future__ import annotations

import pytest

from server.sli.storage.storage_v2_compact_archive import encode_link_metadata
from server.sli.storage.storage_v2_link_blocks import (
    LinkBlockError,
    append_link_block_tail,
    append_link_blocks,
    build_link_blocks,
    find_event_links_in_archive,
    validate_link_blocks,
    validate_no_orphans,
)


def _row(event_id: int, entity_id: int = 7, role_id: int = 2) -> dict[str, int]:
    return {"event_id": event_id, "entity_id": entity_id, "role_id": role_id}


def test_blocks_are_stable_sorted_parallel_and_bounded() -> None:
    blocks = build_link_blocks([_row(value) for value in range(600, 0, -1)])
    assert [block.block_no for block in blocks] == [0, 1]
    assert len(blocks[0].event_ids) == 512
    assert blocks[0].event_ids == tuple(sorted(blocks[0].event_ids))
    assert len(blocks[0].event_ids) == len(blocks[0].role_ids)
    assert len(blocks[0].identity_sha256) == 32


def test_retry_is_idempotent_and_late_identity_is_rejected() -> None:
    blocks = build_link_blocks([_row(10), _row(20)])
    assert append_link_blocks(blocks, [_row(10), _row(20)]) == blocks
    appended = append_link_blocks(blocks, [_row(30)])
    assert appended[0].event_ids == (10, 20, 30)
    with pytest.raises(LinkBlockError, match="late"):
        append_link_blocks(blocks, [_row(15)])


def test_duplicates_and_orphans_are_rejected() -> None:
    with pytest.raises(LinkBlockError, match="duplicate"):
        build_link_blocks([_row(1), _row(1)])
    with pytest.raises(LinkBlockError, match="duplicate"):
        append_link_blocks([], [_row(1), _row(1)])
    with pytest.raises(LinkBlockError, match="smallint"):
        build_link_blocks([_row(1, role_id=32_768)])
    blocks = build_link_blocks([_row(1)])
    validate_no_orphans(blocks, event_ids={1}, entity_ids={7})
    with pytest.raises(LinkBlockError, match="orphan event"):
        validate_no_orphans(blocks, event_ids=set(), entity_ids={7})


def test_event_first_lookup_is_exact_and_archive_backed() -> None:
    rows = [
        {**_row(1), "confidence": 1.0, "extracted_from": "xml", "created_at": "2026-07-14T00:00:00Z"},
        {**_row(2), "confidence": 0.8, "extracted_from": "event_data", "created_at": "2026-07-14T00:00:01Z"},
    ]
    compressed, _ = encode_link_metadata(rows)
    matches = find_event_links_in_archive(compressed, 2)
    assert [(row["event_id"], row["entity_id"], row["role_id"]) for row in matches] == [(2, 7, 2)]


def test_tail_append_changes_only_tail_and_new_blocks() -> None:
    original = build_link_blocks([_row(value) for value in range(1, 513)])[0]
    changed = append_link_block_tail(original, [_row(513)])
    assert changed[0] == original
    assert changed[1].block_no == 1
    assert changed[1].event_ids == (513,)


def test_block_integrity_rejects_hash_and_number_corruption() -> None:
    block = build_link_blocks([_row(1)])[0]
    validate_link_blocks([block])
    with pytest.raises(LinkBlockError, match="SHA-256"):
        validate_link_blocks([block.__class__(
            entity_id=block.entity_id, block_no=block.block_no,
            event_ids=block.event_ids, role_ids=block.role_ids,
            identity_sha256=b"x" * 32,
        )])
    with pytest.raises(LinkBlockError, match="contiguous"):
        validate_link_blocks([block.__class__(
            entity_id=block.entity_id, block_no=2,
            event_ids=block.event_ids, role_ids=block.role_ids,
            identity_sha256=block.identity_sha256,
        )])


def test_tail_append_crosses_int32_boundary_and_preserves_old_hashes() -> None:
    import hashlib
    import struct

    tail = build_link_blocks([_row(2_147_483_647)])[0]
    assert tail.identity_sha256 == hashlib.sha256(struct.pack("<iiH", 2_147_483_647, 7, 2)).digest()
    changed = append_link_block_tail(tail, [_row(2_147_483_648), _row(9_223_372_036_854_775_807)])
    validate_link_blocks(changed)
    assert changed[0].event_ids == (2_147_483_647, 2_147_483_648, 9_223_372_036_854_775_807)
    with pytest.raises(LinkBlockError, match="int64"):
        build_link_blocks([_row(9_223_372_036_854_775_808)])


@pytest.mark.parametrize("event_id,role_id", [(1, 2), (1025, 2), (1024, 1), (2049, 2), (3001, 2)])
def test_late_suffix_equals_full_rebuild_and_preserves_prefix(event_id, role_id):
    from server.sli.storage.storage_v2_link_blocks import rebuild_link_block_suffix

    rows = [_row(value) for value in range(2, 3602, 2)]
    original = build_link_blocks(rows)
    incoming = [_row(event_id, role_id=role_id)]
    start = next(i for i, block in enumerate(original) if block.last_event_id >= event_id)
    changed = rebuild_link_block_suffix(original[start:], incoming)
    combined = original[:start] + changed
    assert combined == build_link_blocks(rows + incoming)
    validate_link_blocks(combined)
    assert [block.identity_sha256 for block in combined[:start]] == [block.identity_sha256 for block in original[:start]]


def test_late_suffix_checks_stored_hash_and_entity():
    from dataclasses import replace

    from server.sli.storage.storage_v2_link_blocks import rebuild_link_block_suffix

    blocks = build_link_blocks([_row(value) for value in range(2, 1202, 2)])
    with pytest.raises(LinkBlockError, match="SHA-256"):
        rebuild_link_block_suffix([replace(blocks[-1], identity_sha256=b"x" * 32)], [_row(1101)])
    with pytest.raises(LinkBlockError, match="entity"):
        rebuild_link_block_suffix(blocks[-1:], [_row(1101, entity_id=8)])

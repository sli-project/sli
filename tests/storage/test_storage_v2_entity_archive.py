from __future__ import annotations

import pytest

from server.sli.storage.storage_v2_archive import (
    ArchiveIntegrityError,
    ArchivePublisher,
    ArchiveReader,
    InMemoryArchiveManifestStore,
)
from server.sli.storage.storage_v2_entity_archive import (
    EntityArchiveError,
    encode_entity_details,
    read_entity_details_many,
)


def test_entity_archive_exact_batch_hydration_without_n_plus_one() -> None:
    first, _ = encode_entity_details([
        {"id": 1, "display_name": "Алиса", "attributes_json": {"department": "ИБ"}},
        {"id": 2, "display_name": "Bob", "attributes_json": {}},
    ])
    second, _ = encode_entity_details([{"id": 100, "display_name": "Service", "attributes_json": {"kind": "svc"}}])
    result = read_entity_details_many([first, second], [2, 100], max_blocks=2)
    assert result[2]["display_name"] == "Bob"
    assert result[100]["attributes_json"] == {"kind": "svc"}


def test_entity_archive_is_bounded_and_detects_corruption() -> None:
    first, _ = encode_entity_details([{"id": 1, "display_name": "A", "attributes_json": {}}])
    second, _ = encode_entity_details([{"id": 2, "display_name": "B", "attributes_json": {}}])
    with pytest.raises(EntityArchiveError, match="bounded"):
        read_entity_details_many([first, second], [1, 2], max_blocks=1)
    damaged = type(first)(first.first_entity_id, first.last_entity_id, first.compressed + b"x", first.compressed_sha256)
    with pytest.raises(EntityArchiveError, match="SHA-256"):
        read_entity_details_many([damaged], [1])


def test_entity_archive_uses_published_manifest_for_bounded_hydration(tmp_path) -> None:
    store = InMemoryArchiveManifestStore()
    publisher = ArchivePublisher(tmp_path.resolve(), store)
    publisher.publish_rows(
        archive_set_id="00000000-0000-4000-8000-000000000033",
        archive_kind="entity_detail",
        block_index=0,
        event_id_field="id",
        rows=[
            {"id": 1, "display_name": "Алиса", "attributes_json": {"department": "ИБ"}},
            {"id": 2, "display_name": "Bob", "attributes_json": {}},
        ],
    )
    publisher.publish_rows(
        archive_set_id="00000000-0000-4000-8000-000000000036",
        archive_kind="entity_detail",
        block_index=0,
        event_id_field="id",
        rows=[{"id": 100, "display_name": "Service", "attributes_json": {"kind": "svc"}}],
    )
    reader = ArchiveReader(store, archive_root=tmp_path.resolve())
    result = reader.read_entity_details_many([2, 100], max_blocks=2)
    assert result[2]["display_name"] == "Bob"
    assert result[100]["attributes_json"] == {"kind": "svc"}
    with pytest.raises(ArchiveIntegrityError, match="bounded"):
        reader.read_entity_details_many([1, 100], max_blocks=1)


def test_link_detail_archive_hydrates_many_events_with_one_block_read(tmp_path, monkeypatch) -> None:
    store = InMemoryArchiveManifestStore()
    publisher = ArchivePublisher(tmp_path.resolve(), store)
    publisher.publish_rows(
        archive_set_id="00000000-0000-4000-8000-000000000044",
        archive_kind="link_detail",
        block_index=0,
        event_id_field="event_id",
        rows=[
            {"event_id": 10, "entity_id": 1, "evidence_json": {"field": "SubjectUserSid"}},
            {"event_id": 11, "entity_id": 2, "attributes_json": {"source": "normalized"}},
        ],
    )
    reader = ArchiveReader(store, archive_root=tmp_path.resolve())
    reads = []
    original = reader.read_block_rows
    monkeypatch.setattr(
        reader, "read_block_rows",
        lambda block: reads.append(block.object_location) or original(block),
    )

    result = reader.read_link_details_many([10, 11], max_blocks=1)

    assert result[10][0]["entity_id"] == 1
    assert result[11][0]["attributes_json"] == {"source": "normalized"}
    assert len(reads) == 1

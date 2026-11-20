from scripts.maintenance.stage7_clickhouse_candidate_b import (
    _prepare_b_row,
    _row_digest,
)


def test_candidate_b_stores_locator_and_omits_duplicate_payload() -> None:
    row = {
        "id": 10,
        "time_created_utc": "2026-07-27T01:02:03.123456+00:00",
        "normalized_hash": "ab" * 32,
        "event_data_json": '{"secret":true}',
        "message_text": "large payload",
        "record_xml": "<Event/>",
    }

    prepared = _prepare_b_row(
        row,
        portable_uid="sli-event-v1:" + "c" * 64,
        raw_frame_no=7,
        entity_ids=[100],
        role_ids=[2],
    )

    assert prepared["source_id"] == 10
    assert prepared["event_uid_hex"] == "c" * 64
    assert prepared["raw_frame_no"] == 7
    assert prepared["entity_ids"] == [100]
    assert "event_data_json" not in prepared
    assert "message_text" not in prepared
    assert "record_xml" not in prepared
    assert len(_row_digest(prepared)) == 32

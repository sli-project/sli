from scripts.run_dc_log_pilot import apply_collection_not_before_floor


def test_floor_replaces_retired_cursor_without_advancing_persisted_state() -> None:
    source = {
        "DNS Server": {
            "start_time_utc": "2026-07-21T12:58:36+00:00",
            "after_record_id": 30_905_983,
            "cursor_event_time_utc": "2026-07-21T12:58:36+00:00",
        },
        "Security": {
            "start_time_utc": "2026-07-26T23:00:00+00:00",
            "after_record_id": 1_430_103_701,
            "cursor_event_time_utc": "2026-07-26T23:00:00+00:00",
        },
    }

    result = apply_collection_not_before_floor(
        source,
        "2026-07-25T17:00:00+00:00",
    )

    assert result["DNS Server"] == {
        "start_time_utc": "2026-07-25T17:00:00+00:00",
        "after_record_id": None,
        "cursor_event_time_utc": "2026-07-21T12:58:36+00:00",
        "not_before_floor_applied": True,
    }
    assert result["Security"] == source["Security"]
    assert source["DNS Server"]["after_record_id"] == 30_905_983


def test_missing_floor_preserves_plan() -> None:
    source = {
        "DNS Server": {
            "start_time_utc": "2026-07-21T12:58:36+00:00",
            "after_record_id": 30_905_983,
        }
    }

    assert apply_collection_not_before_floor(source, None) == source


def test_floor_rejects_cursor_without_proven_event_time() -> None:
    source = {
        "DNS Server": {
            "start_time_utc": "2026-07-27T00:00:00+00:00",
            "after_record_id": 30_905_983,
            "cursor_event_time_utc": None,
        }
    }

    result = apply_collection_not_before_floor(
        source,
        "2026-07-25T17:00:00+00:00",
    )

    assert result["DNS Server"]["start_time_utc"] == source["DNS Server"]["start_time_utc"]
    assert result["DNS Server"]["after_record_id"] is None
    assert result["DNS Server"]["not_before_floor_applied"] is True

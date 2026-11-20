from __future__ import annotations

import pytest

from server.sli.events.event_catalog import all_event_catalog_entries
from server.sli.storage.storage_policy import resolve_catalogue_retention


def test_high_volume_authentication_budget_is_positive_and_representative() -> None:
    entries = {
        str(entry["event_key"]): entry
        for entry in all_event_catalog_entries()
    }

    for event_key in ("4608", "4624", "4634"):
        budget = entries[event_key]["lifecycle"]["promotion"]["budget"]
        assert budget["calibration"] == "representative"
        assert all(
            isinstance(budget[field], int) and budget[field] > 0
            for field in (
                "events_per_day_upper",
                "source_bytes_per_event_upper",
                "derived_bytes_per_object_upper",
            )
        )


def test_high_volume_zero_budget_is_rejected_before_admission() -> None:
    entry = {
        "lifecycle": {
            "raw_payload_days": 2,
            "record_days": 7,
            "warm_record_days": 365,
            "rollup": "authentication_session",
            "rollup_role": "open",
            "promotion": {
                "version": "descriptor-lifecycle-v2",
                "archive_requirement": "no_archive",
                "post_promotion_disposition": "delete_source",
                "read_representation": "derived_only",
                "high_volume": True,
                "semantic_role": "authentication_boundary",
                "hot_need": "raw_investigation_window",
                "warm_value": "closed_or_incomplete_authentication_history",
                "executable_lifecycle": "existing_warm_then_retention_executor",
                "budget": {
                    "events_per_day_upper": 0,
                    "source_bytes_per_event_upper": 0,
                    "derived_bytes_per_object_upper": 0,
                    "calibration": "representative",
                },
            },
        },
    }

    with pytest.raises(ValueError, match="high-volume lifecycle budget bounds must be positive"):
        resolve_catalogue_retention(entry)

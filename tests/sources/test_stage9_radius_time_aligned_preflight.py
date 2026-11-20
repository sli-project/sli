from __future__ import annotations

from datetime import datetime, timezone
import json

import pytest

from scripts.maintenance.stage9_radius_time_aligned_preflight import (
    RadiusTimeAlignedPlanError,
    aggregate_observations,
    build_time_aligned_xpath,
    load_plan,
    parse_accounting_sample,
    validate_plan,
)
from server.source_packs.radius.accounting import (
    DATABASE_COMPATIBLE_COLUMNS,
)


def _accounting_line() -> str:
    values = [""] * len(DATABASE_COMPATIBLE_COLUMNS)
    index = {
        name: position
        for position, name in enumerate(DATABASE_COMPATIBLE_COLUMNS)
    }
    values[index["ComputerName"]] = "nps"
    values[index["ServiceName"]] = "IAS"
    values[index["Record-Date"]] = "07/30/2026"
    values[index["Record-Time"]] = "08:00:00"
    values[index["Packet-Type"]] = "4"
    values[index["NAS-Identifier"]] = "vpn-a"
    values[index["Event-Timestamp"]] = "1785373200"
    values[index["Acct-Status-Type"]] = "1"
    values[index["Acct-Session-Id"]] = "opaque"
    return ",".join(values)


def test_plan_is_bounded_read_only_and_owner_authorized(
    legacy_radius_target_inventory,
) -> None:
    result = validate_plan(load_plan())
    assert result["status"] == "owner_authorized"
    assert result["source_contact"] is False
    assert result["target_count"] == 1
    assert result["limits"]["nps_events"] == 500
    assert result["limits"]["accounting_bytes"] == 262_144
    assert result["limits"]["maximum_alignment_span_seconds"] == 10_800


def test_plan_rejects_limit_change() -> None:
    plan = load_plan()
    plan["limits"]["nps_events"] = 501
    with pytest.raises(
        RadiusTimeAlignedPlanError,
        match="bounded_limits_changed",
    ):
        validate_plan(plan)


def test_accounting_local_time_is_converted_to_utc_in_memory() -> None:
    records, counts = parse_accounting_sample(
        [_accounting_line()],
        utc_offset_minutes=420,
    )
    assert counts["lifecycle_rows"] == 1
    assert records[0]["record_time_utc"] == datetime(
        2026, 7, 30, 1, 0, tzinfo=timezone.utc
    )


def test_xpath_uses_exact_accounting_derived_utc_interval() -> None:
    xpath = build_time_aligned_xpath(
        datetime(2026, 7, 30, 0, 50, tzinfo=timezone.utc),
        datetime(2026, 7, 30, 1, 10, tzinfo=timezone.utc),
    )
    assert "EventID=6272 or EventID=6273" in xpath
    assert "2026-07-30T00:50:00.000Z" in xpath
    assert "2026-07-30T01:10:00.000Z" in xpath


def test_aggregate_proves_join_without_persisting_values() -> None:
    event_time = datetime(2026, 7, 30, 1, 0, tzinfo=timezone.utc)
    result = aggregate_observations(
        [
            {
                "event_id": 6272,
                "event_time_utc": event_time,
                "session_id": "opaque",
                "nas_identity": "vpn-a",
                "subject_sid": "S-1-5-21-1",
            }
        ],
        [
            {
                "lifecycle": "start",
                "session_id": "opaque",
                "nas_identity": "VPN-A",
                "record_time_utc": event_time,
                "event_time_utc": event_time,
            }
        ],
        accounting_counts={"lifecycle_rows": 1},
        alignment_span_seconds=0,
        caps={
            "accounting_candidate_cap_reached": False,
            "accounting_record_cap_reached": False,
            "accounting_byte_cap_reached": False,
            "selected_file_was_sampled_not_fully_read": False,
            "nps_event_cap_reached": False,
        },
    )
    assert result["classification"] == {
        "correlation": "proven_on_time_aligned_bounded_sample",
        "timestamp": "event_timestamp_proven",
    }
    encoded = json.dumps(result)
    assert "opaque" not in encoded
    assert "vpn-a" not in encoded.casefold()
    assert "S-1-5-21-1" not in encoded


def test_aggregate_fails_closed_when_sample_is_truncated() -> None:
    event_time = datetime(2026, 7, 30, 1, 0, tzinfo=timezone.utc)
    result = aggregate_observations(
        [
            {
                "event_id": 6272,
                "event_time_utc": event_time,
                "session_id": "same",
                "nas_identity": "vpn",
                "subject_sid": "S-1-5-21-1",
            }
        ],
        [
            {
                "lifecycle": "start",
                "session_id": "same",
                "nas_identity": "vpn",
                "record_time_utc": event_time,
                "event_time_utc": event_time,
            }
        ],
        accounting_counts={"lifecycle_rows": 1},
        alignment_span_seconds=0,
        caps={"nps_event_cap_reached": True},
    )
    assert result["classification"]["correlation"] == (
        "correlation_not_proven"
    )


def test_accounting_tail_limit_still_allows_bounded_sample_conclusion() -> None:
    event_time = datetime(2026, 7, 30, 1, 0, tzinfo=timezone.utc)
    result = aggregate_observations(
        [
            {
                "event_id": 6272,
                "event_time_utc": event_time,
                "session_id": "same",
                "nas_identity": "vpn",
                "subject_sid": "S-1-5-21-1",
            }
        ],
        [
            {
                "lifecycle": "start",
                "session_id": "same",
                "nas_identity": "vpn",
                "record_time_utc": event_time,
                "event_time_utc": event_time,
            }
        ],
        accounting_counts={"lifecycle_rows": 1},
        alignment_span_seconds=0,
        caps={
            "accounting_byte_cap_reached": True,
            "selected_file_was_sampled_not_fully_read": True,
            "nps_event_cap_reached": False,
        },
    )
    assert result["classification"]["correlation"] == (
        "proven_on_time_aligned_bounded_sample"
    )

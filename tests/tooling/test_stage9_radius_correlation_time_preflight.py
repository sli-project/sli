from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import pytest

from scripts.maintenance.stage9_radius_correlation_time_preflight import (
    PLAN_PATH,
    RadiusCorrelationTimePlanError,
    aggregate_observations,
    load_plan,
    validate_plan,
)


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = (
    ROOT
    / "scripts"
    / "maintenance"
    / "stage9_radius_correlation_time_preflight.py"
)


def test_plan_is_bounded_owner_authorized_and_read_only(
    legacy_radius_target_inventory,
) -> None:
    result = validate_plan(load_plan())
    assert result["status"] == "owner_authorized"
    assert result["source_contact"] is False
    assert result["read_only"] is True
    assert result["target_count"] == 1
    assert result["limits"] == {
        "target_count": 1,
        "window_hours": 24,
        "event_ids": [6272, 6273],
        "nps_events": 100,
        "accounting_files": 1,
        "accounting_candidates": 20,
        "accounting_records": 200,
        "accounting_bytes": 262_144,
        "source_timezone_queries": 1,
        "overall_timeout_seconds": 60,
    }


def test_plan_persists_only_aggregates_and_keeps_identity_fail_closed() -> None:
    plan = load_plan()
    assert "account_session_identifier" in plan["prohibited_persistence"]
    assert "subject_sid" in plan["prohibited_persistence"]
    assert "user_name" in plan["prohibited_persistence"]
    assert "source_instance_creation" in plan["prohibited_actions"]
    assert plan["evaluation_contract"]["username_is_not_exact_identity"] is True
    assert plan["evaluation_contract"]["no_match_result"] == (
        "correlation_not_proven"
    )
    assert plan["evaluation_contract"]["ambiguous_match_result"] == (
        "correlation_not_proven"
    )


def test_plan_rejects_authorization_or_limit_changes() -> None:
    plan = load_plan()
    plan["status"] = "awaiting_owner_authorization"
    with pytest.raises(
        RadiusCorrelationTimePlanError,
        match="owner_authorization_required",
    ):
        validate_plan(plan)

    plan = load_plan()
    plan["limits"]["nps_events"] = 101
    with pytest.raises(
        RadiusCorrelationTimePlanError,
        match="bounded_limits_changed",
    ):
        validate_plan(plan)


def test_active_target_inventory_is_current_owner_confirmed_target() -> None:
    plan = json.loads(PLAN_PATH.read_text(encoding="utf-8"))
    inventory_path = ROOT / plan["targets_source"]
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    assert "current owner-confirmed" in inventory["description"].casefold()
    assert len(inventory["targets"]) == 1
    target = inventory["targets"][0]
    assert set(target) == {"source_name", "connect_address", "owner_confirmed_ip"}
    assert all(isinstance(value, str) and value for value in target.values())
    assert target["source_name"] == target["connect_address"]
    assert target["source_name"] != "radius01.example.invalid"


def test_entry_point_runs_from_unrelated_working_directory(
    tmp_path: Path,
) -> None:
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--validate-only"],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert completed.returncode != 0
    assert "approved_target_changed" in completed.stderr


def test_entry_point_requires_explicit_validate_only(tmp_path: Path) -> None:
    completed = subprocess.run(
        [sys.executable, str(SCRIPT)],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert completed.returncode != 0
    assert "choose_exactly_one_mode" in completed.stderr


def test_aggregate_proves_exact_join_without_persisting_values() -> None:
    from datetime import datetime, timezone

    event_time = datetime(2026, 7, 30, 1, 0, tzinfo=timezone.utc)
    result = aggregate_observations(
        [
            {
                "event_id": 6272,
                "event_time_utc": event_time,
                "session_id": "opaque-session",
                "nas_identity": "vpn-a",
                "subject_sid": "S-1-5-21-1",
            }
        ],
        [
            {
                "lifecycle": "start",
                "session_id": "opaque-session",
                "nas_identity": "VPN-A",
                "event_timestamp_raw": "1785373220",
                "event_time_utc": datetime(
                    2026, 7, 30, 1, 0, 20, tzinfo=timezone.utc
                ),
            }
        ],
        record_time_shapes={"slash_mdy_hms": 1},
        timezone_metadata={
            "status": "observed",
            "timezone_id": "N. Central Asia Standard Time",
            "utc_offset_minutes": 420,
            "dynamic_daylight_time_disabled": None,
        },
        caps={"nps_event_cap_reached": False},
    )
    assert result["classification"] == {
        "correlation": "proven_on_bounded_sample",
        "timestamp": "event_timestamp_proven_on_joined_starts",
    }
    assert result["one_to_one_ambiguous_and_unmatched_counts"] == {
        "one_to_one_records": 1,
        "ambiguous_records": 0,
        "unmatched_records": 0,
    }
    encoded = json.dumps(result)
    assert "opaque-session" not in encoded
    assert "vpn-a" not in encoded.casefold()
    assert "S-1-5-21-1" not in encoded


def test_aggregate_fails_closed_on_ambiguous_join() -> None:
    event = {
        "event_id": 6272,
        "event_time_utc": None,
        "session_id": "same",
        "nas_identity": "vpn",
        "subject_sid": "S-1-5-21-1",
    }
    result = aggregate_observations(
        [event, dict(event)],
        [
            {
                "lifecycle": "start",
                "session_id": "same",
                "nas_identity": "vpn",
                "event_timestamp_raw": "",
                "event_time_utc": None,
            }
        ],
        record_time_shapes={},
        timezone_metadata={"status": "inaccessible"},
        caps={},
    )
    assert result["classification"]["correlation"] == (
        "correlation_not_proven"
    )
    assert result["one_to_one_ambiguous_and_unmatched_counts"][
        "ambiguous_records"
    ] == 1



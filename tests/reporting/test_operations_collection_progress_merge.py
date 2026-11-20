from __future__ import annotations

from datetime import datetime, timezone

import pytest

from server.sli.reporting.ui_operations import (
    _collector_health_with_collection_progress,
    collection_progress_view,
)


def _collector() -> dict:
    return {
        "items": [
            {"server": "DC1", "channel": "System", "collection_label": "проверка сильно отстаёт", "collection_severity": "high", "event_observation_label": "нужна новая проверка канала", "event_observation_severity": "warn"},
            {"server": "DC1", "channel": "Security", "collection_label": "есть задержка проверки", "collection_severity": "warn", "event_observation_label": "события догоняются", "event_observation_severity": "warn"},
            {"server": "DC2", "channel": "Security", "collection_label": "проверка сильно отстаёт", "collection_severity": "high", "event_observation_label": "нужна новая проверка канала", "event_observation_severity": "warn"},
        ]
    }


def _progress(status: str = "running") -> dict:
    return {
        "status": status,
        "worker_status": status,
        "job_status": status,
        "items": [
            {"server": "DC1", "channel": "System", "boundary_reached": True, "recovery_mode": False, "check_state": "current"},
            {"server": "DC1", "channel": "Security", "boundary_reached": False, "recovery_mode": True},
            {"server": "DC2", "channel": "Security", "boundary_reached": False, "recovery_mode": False},
        ],
    }


def test_live_collection_progress_replaces_stale_channel_wording() -> None:
    original = _collector()

    result = _collector_health_with_collection_progress(original, _progress())

    assert [item["collection_label"] for item in result["items"]] == [
        "граница прочитана при последней успешной проверке",
        "канал догоняет границу",
        "проверяется текущая граница",
    ]
    assert [item["event_observation_label"] for item in result["items"]] == [item["event_observation_label"] for item in original["items"]]
    assert [item["collection_severity"] for item in result["items"]] == ["ok", "warn", "warn"]
    assert original["items"][0]["collection_label"] == "проверка сильно отстаёт"


def test_failed_worker_does_not_mask_collector_warning() -> None:
    original = _collector()

    result = _collector_health_with_collection_progress(original, _progress("failed"))

    assert result == original


def test_current_boundary_is_independent_of_event_age_while_worker_sleeps() -> None:
    original = _collector()
    progress = _progress("partial")

    result = _collector_health_with_collection_progress(original, progress)

    assert result["items"][0]["collection_label"] == (
        "граница прочитана при последней успешной проверке"
    )
    assert result["items"][0]["event_observation_label"] == (
        "нужна новая проверка канала"
    )
    assert result["items"][0]["event_observation_severity"] == "warn"
    assert result["items"][1]["collection_label"] == (
        "канал ожидает следующую bounded-порцию"
    )
    assert result["items"][2]["collection_label"] == "проверка сильно отстаёт"


def test_completed_security_outside_recovery_is_a_durable_boundary() -> None:
    collector = {
        "items": [
            {
                "server": "DC2",
                "channel": "Security",
                "last_status": "completed",
                "recovery_mode": False,
                "adaptive_action": "keep:completed_streak; 50000->50000; recovery=off",
                "adaptive_limit": 50_000,
            }
        ]
    }
    workers = {
        "items": [
            {
                "worker_name": "collection",
                "status": "partial",
                "details": {"last_result": {"job_id": 8, "status": "partial"}},
            }
        ]
    }

    result = collection_progress_view(collector, workers)

    assert result["boundaries_reached"] == 1
    assert result["channels_in_recovery"] == 0
    assert result["items"][0]["boundary_reached"] is True


@pytest.mark.parametrize("status,checked,state", [
    ("completed", "2020-01-01T00:00:00Z", "stale"),
    ("failed", "2020-01-01T00:00:00Z", "error"),
    ("access_denied", "2020-01-01T00:00:00Z", "error"),
    ("completed", None, "stale"),
])
def test_historical_boundary_is_not_current_health(status, checked, state):
    collector = {"items": [{
        "server": "fixture-node", "channel": "Security", "last_status": status,
        "last_successful_collection_utc": checked, "last_event_time_utc": "2019-01-01T00:00:00Z",
        "adaptive_action": "exit_recovery:source_boundary_reached", "collection_severity": "high",
        "collection_label": "previous check is old", "event_observation_label": "old event",
    }]}
    progress = collection_progress_view(collector, {"items": []})
    assert progress["status"] == ("failed" if state == "error" else "stale")
    assert progress["items"][0]["boundary_reached"] is True
    assert progress["items"][0]["check_state"] == state
    assert progress["items"][0]["boundary_checked_at_utc"] == checked
    merged = _collector_health_with_collection_progress(collector, progress)
    assert merged["items"][0]["collection_severity"] == "high"
    assert merged["items"][0]["event_observation_label"] == "old event"


def test_recent_check_with_old_event_can_confirm_current_boundary():
    checked = datetime.now(timezone.utc).isoformat()
    progress = collection_progress_view({"items": [{
        "server": "fixture-node", "channel": "System", "last_status": "completed",
        "last_successful_collection_utc": checked, "last_event_time_utc": "2019-01-01T00:00:00Z",
    }]}, {"items": []})
    assert progress["status"] == "completed"
    assert progress["items"][0]["check_state"] == "current"


def test_runtime_block_keeps_its_reason_and_confirmed_date():
    checked = datetime.now(timezone.utc).isoformat()
    progress = collection_progress_view({"items": [{
        "server": "fixture-node", "channel": "Security", "last_status": "completed",
        "last_successful_collection_utc": checked, "last_event_time_utc": "2019-01-01T00:00:00Z",
    }]}, {"items": []}, {"collection_block_reason": "windows_event_log_access_denied",
                           "collection_block": {"first_seen_at": "2026-10-01T00:00:00Z"}})
    assert progress["status"] == "blocked"
    assert progress["block_reason"] == "windows_event_log_access_denied"
    assert progress["blocked_since_utc"] == "2026-10-01T00:00:00Z"

from __future__ import annotations

from server.sli.sources.radius_vpn_operations import _public_item


def _row(**updates) -> dict:
    value = {
        "source_activation": "disabled",
        "subscription_activation": "disabled",
        "queued_delivery_count": 0,
        "leased_delivery_count": 0,
        "failed_delivery_count": 0,
        "quarantined_delivery_count": 0,
        "projected_session_count": 8,
        "identity_unresolved_count": 23,
        "timestamp_unresolved_count": 0,
        "direct_capability_assignment_count": 0,
        "package_capability_mapping_count": 0,
        "ephemeral_login_exists": False,
        "manual_worker_session_exists": False,
        "continuous_runtime_enabled": False,
        "autostart_enabled": False,
        "resource_profile_id": "stage9-radius-manual-bounded-v1",
    }
    value.update(updates)
    return value


def test_actual_manual_pilot_states_are_not_conflated_with_worker_or_queue_state() -> None:
    item = _public_item(_row())
    assert item["plugin_state"] == "bundled_supervised_production"
    assert item["source_state"] == "disabled"
    assert item["worker_state"] == "manual_idle"
    assert item["queue_state"] == "drained"
    assert item["dataset_state"] == "partial"
    assert item["access_state"] == "owner_only"
    assert item["resource_profile"]["status"] == "configured_manual_inactive"
    assert item["resource_profile"]["ready_for_long_lived_worker"] is False
    assert item["resource_profile"]["declared_limits"]["records_per_run"] == {
        "value": 1000,
        "unit": "records",
    }


def test_pending_and_failure_states_remain_visible() -> None:
    pending = _public_item(_row(queued_delivery_count=2))
    assert pending["queue_state"] == "pending_manual"
    failure = _public_item(
        _row(failed_delivery_count=1, ephemeral_login_exists=True)
    )
    assert failure["queue_state"] == "attention"
    assert failure["worker_state"] == "attention"


def test_dataset_distinguishes_absent_incomplete_and_available() -> None:
    assert _public_item(_row(
        projected_session_count=0,
        identity_unresolved_count=0,
    ))["dataset_state"] == "not_collected"
    assert _public_item(_row(
        projected_session_count=0,
        identity_unresolved_count=2,
    ))["dataset_state"] == "identity_incomplete"
    assert _public_item(_row(
        projected_session_count=2,
        identity_unresolved_count=0,
    ))["dataset_state"] == "available"


def test_unknown_resource_profile_is_visible_not_silently_defaulted() -> None:
    item = _public_item(_row(resource_profile_id="unknown-profile"))
    assert item["resource_profile"] == {
        "status": "not_registered",
        "profile_id": "unknown-profile",
        "ready_for_long_lived_worker": False,
    }

from __future__ import annotations

import pytest


def test_list_components_includes_both_radius_plugins_and_semantic() -> None:
    from server.sli.ops.runtime_component_registry import list_components

    names = {c.name for c in list_components()}
    assert {
        "plugin_radius_acquisition",
        "plugin_radius_session_observation",
        "semantic",
        "collection",
    } <= names


def test_get_returns_component_with_expected_fields() -> None:
    from server.sli.ops.runtime_component_registry import get

    component = get("collection")
    assert component.script == "collection_worker.py"
    assert component.is_plugin is False
    assert component.supervised is True
    assert component.feature_enabled is True


def test_get_raises_for_unknown_component() -> None:
    from server.sli.ops.runtime_component_registry import get

    with pytest.raises(KeyError):
        get("does_not_exist")


def test_is_plugin_distinguishes_plugin_from_regular_workers() -> None:
    from server.sli.ops.runtime_component_registry import is_plugin

    assert is_plugin("plugin_radius_acquisition") is True
    assert is_plugin("plugin_radius_session_observation") is True
    assert is_plugin("collection") is False
    assert is_plugin("semantic") is False


def test_semantic_production_is_supervised_with_dedicated_entrypoint() -> None:
    from server.sli.ops.runtime_component_registry import get

    semantic = get("semantic")
    assert semantic.script == "semantic_production_worker.py"
    assert semantic.feature_enabled is True
    assert semantic.supervised is True


def test_computers_v6_source_is_retained_unsupervised_for_manual_rollback() -> None:
    from server.sli.ops.runtime_component_registry import get
    from scripts.maintenance import worker_supervisor

    source = get("computers_v6_source")
    assert source.script == "computers_v6_source_worker.py"
    assert source.expected_interval_seconds == 12 * 60 * 60
    assert source.supervised is False
    assert source.feature_enabled is False
    assert "computers_v6_source" not in worker_supervisor.MANAGED
    assert "computers_v6_source" not in worker_supervisor.START_ORDER


def test_computers_v5_snapshot_is_retained_for_manual_rollback_only() -> None:
    from server.sli.ops.runtime_component_registry import get
    from scripts.maintenance import worker_supervisor

    component = get("computers_v5_snapshot")
    assert component.script == "computers_report_v5_snapshot_worker.py"
    assert component.feature_enabled is False
    assert component.supervised is False
    assert "computers_v5_snapshot" not in worker_supervisor.MANAGED
    assert "computers_v5_snapshot" not in worker_supervisor.START_ORDER


def test_plugin_components_carry_their_component_id() -> None:
    from server.sli.ops.runtime_component_registry import get

    acquisition = get("plugin_radius_acquisition")
    observation = get("plugin_radius_session_observation")
    assert acquisition.plugin_component_id == "radius-acquisition"
    assert observation.plugin_component_id == "radius-session-observation"
    assert acquisition.script == "remote_access_plugin_host.py"
    assert observation.script == "remote_access_plugin_host.py"


def test_ad_snapshot_projection_worker_is_registered_but_dormant() -> None:
    from server.sli.ops.runtime_component_registry import get

    retired = {
        "ad_context_snapshot": "ad_context_snapshot_worker.py",
        "ad_snapshot_projection": "ad_snapshot_projection_worker.py",
        "computers_v5_snapshot": "computers_report_v5_snapshot_worker.py",
        "computers_v6_source": "computers_v6_source_worker.py",
        "computers_v6_snapshot": "computers_report_v6_snapshot_worker.py",
        "users_v2_snapshot": "users_report_v2_snapshot_worker.py",
    }
    for name, script in retired.items():
        component = get(name)
        assert component.script == script
        assert component.feature_enabled is False
        assert component.supervised is False

    coordinator = get("ad_snapshot_manifest_coordinator")
    assert coordinator.script == "ad_snapshot_manifest_coordinator_worker.py"
    assert coordinator.expected_interval_seconds == 12 * 60 * 60
    assert coordinator.feature_enabled is True
    assert coordinator.supervised is True

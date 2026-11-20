from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from server.sli.access.access_control_v4 import route_capability
from server.sli.sources.plugin_management import (
    PluginManagementError,
    build_plugin_management_catalog,
    get_plugin_management,
    load_plugin_management_registry,
)
from server.api.http_server import _required_read_role


ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "config" / "stage10_plugin_management_v1.json"


def _registry() -> dict:
    return json.loads(CONFIG.read_text(encoding="utf-8"))


def _radius_payload(plugin_id: str = "sli.remote-access") -> dict:
    return {
        "contract_id": "sli.radius-vpn-operations.v1",
        "status": "ok",
        "contains_identity_or_event_payload": False,
        "items": [
            {
                "plugin_id": plugin_id,
                "source_instance_id": "radius.example",
                "plugin_state": "bundled_manual_pilot",
                "source_state": "disabled",
                "worker_state": "manual_idle",
                "queue_state": "drained",
                "dataset_state": "available",
                "access_state": "owner_only",
                "resource_profile": {
                    "profile_id": "stage9-radius-manual-bounded-v1",
                    "ready_for_long_lived_worker": False,
                },
                "raw_identity": "must-not-pass",
            }
        ],
    }


def test_registry_separates_plugin_package_from_source_pack() -> None:
    registry = load_plugin_management_registry()
    by_id = {item["plugin_id"]: item for item in registry["plugins"]}
    assert set(by_id) == {"sli.remote-access", "sli.windows.ad-dc"}
    assert by_id["sli.remote-access"]["source_pack_ids"] == [
        "sli.windows.vpn-radius"
    ]
    assert {name for name, action in registry["lifecycle_actions"].items() if action["available"]} == {"enable", "disable"}


def test_radius_is_supervised_production_plugin_owned() -> None:
    registry = load_plugin_management_registry()
    by_id = {item["plugin_id"]: item for item in registry["plugins"]}
    radius = by_id["sli.remote-access"]
    assert radius["runtime_ownership_kind"] == "plugin"
    assert radius["runtime_enabled"] is True
    assert radius["autostart_enabled"] is True
    assert radius["source_contact_allowed"] is True
    assert radius["management_state"] == "supervised_production"
    assert radius["version_state"] == "packaged_manifest_supervised_runtime"
    assert radius["runtime_ownership"] == "plugin_owned_supervised_production"


def test_ad_dc_is_core_owned_final_without_plugin_runtime_fields() -> None:
    registry = load_plugin_management_registry()
    by_id = {item["plugin_id"]: item for item in registry["plugins"]}
    ad_dc = by_id["sli.windows.ad-dc"]
    assert ad_dc["runtime_ownership_kind"] == "core"
    assert ad_dc["runtime_ownership"] == "core_owned_final"
    assert "runtime_enabled" not in ad_dc
    assert "autostart_enabled" not in ad_dc
    assert "source_contact_allowed" not in ad_dc


def test_source_only_catalog_does_not_open_observed_runtime() -> None:
    catalog = build_plugin_management_catalog(include_observed=False)
    assert catalog["read_only"] is True
    assert catalog["mutation_api_enabled"] is True
    assert catalog["runtime_changed"] is False
    remote = next(item for item in catalog["items"] if item["plugin_id"] == "sli.remote-access")
    assert remote["observed"] == {
        "status": "not_requested",
        "source_count": 0,
        "sources": [],
    }


def test_live_read_projection_is_bounded_and_strips_unapproved_fields() -> None:
    catalog = build_plugin_management_catalog(radius_loader=_radius_payload)
    remote = next(item for item in catalog["items"] if item["plugin_id"] == "sli.remote-access")
    assert remote["observed"]["status"] == "ok"
    assert remote["observed"]["source_count"] == 1
    assert remote["package_version"] == "0.1.0"
    assert remote["package_manifest"] == "sli.remote-access.package.v1"
    assert "raw_identity" not in remote["observed"]["sources"][0]
    assert remote["observed"]["contains_identity_or_event_payload"] is False


def test_wrong_observed_plugin_is_localized_as_unavailable() -> None:
    catalog = build_plugin_management_catalog(
        radius_loader=lambda: _radius_payload("sli.windows.vpn-radius")
    )
    remote = next(item for item in catalog["items"] if item["plugin_id"] == "sli.remote-access")
    assert remote["observed"]["status"] == "unavailable"
    assert remote["observed"]["error_type"] == "PluginManagementError"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value["lifecycle_actions"]["install"].update(available=True),
        lambda value: value["plugins"][0].update(package_version="1.0.0"),
        lambda value: value["plugins"][0]["source_pack_ids"].append(
            "sli.windows.vpn-radius"
        ),
        lambda value: value["plugins"][0].update(runtime_enabled=False),
        lambda value: value["plugins"][0].update(runtime_ownership_kind="core"),
        lambda value: value["plugins"][1].update(runtime_ownership_kind="plugin"),
        lambda value: value["plugins"][1].update(runtime_enabled=True),
    ],
)
def test_unsafe_or_unverified_registry_fails_closed(
    mutation, tmp_path: Path
) -> None:
    value = deepcopy(_registry())
    mutation(value)
    path = tmp_path / "registry.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(PluginManagementError):
        load_plugin_management_registry(path)


def test_detail_is_exact_and_unknown_plugin_is_not_found() -> None:
    result = get_plugin_management("sli.windows.ad-dc", include_observed=False)
    assert result["item"]["plugin_id"] == "sli.windows.ad-dc"
    with pytest.raises(PluginManagementError, match="plugin_not_found"):
        get_plugin_management("sli.unknown", include_observed=False)


def test_http_paths_are_operator_and_capability_scoped() -> None:
    assert _required_read_role("/api/v1/operations/plugins") == "operator"
    assert route_capability("/api/v1/operations/plugins") == "operations.view"
    assert (
        route_capability("/api/v1/operations/plugins/sli.remote-access")
        == "operations.view"
    )



from __future__ import annotations

from copy import deepcopy

import pytest

from server.sli.sources.plugin_package_manifest import (
    MANIFEST_PATH,
    PluginPackageManifestError,
    _load,
    load_and_validate_remote_access_manifest,
    validate_remote_access_manifest,
)


def test_remote_access_manifest_validates_registered_component_inventory() -> None:
    result = load_and_validate_remote_access_manifest()
    assert result["plugin_id"] == "sli.remote-access"
    assert result["plugin_version"] == "0.1.0"
    assert result["component_count"] == 7
    assert {item["component_id"] for item in _load(MANIFEST_PATH)["components"]["reports"]} == {"vpn.audit", "vpn.connections"}
    assert set(result["handler_hashes"]) == {
        "stage9-radius-manual-worker",
        "stage9-radius-session-consumer-manual",
    }


def test_manifest_cannot_supply_arbitrary_executable_material() -> None:
    broken = deepcopy(_load(MANIFEST_PATH))
    broken["components"]["workers"][0]["command"] = "python arbitrary.py"
    with pytest.raises(
        PluginPackageManifestError,
        match="executable_or_sensitive_manifest_key:command",
    ):
        validate_remote_access_manifest(broken)


def test_manifest_handler_must_be_reviewed_allowlist_id() -> None:
    broken = deepcopy(_load(MANIFEST_PATH))
    broken["components"]["workers"][0]["handler_id"] = "unknown-handler"
    with pytest.raises(PluginPackageManifestError, match="handler_allowlist"):
        validate_remote_access_manifest(broken)


def test_manifest_production_runtime_must_match_runtime_registry() -> None:
    broken = deepcopy(_load(MANIFEST_PATH))
    broken["production_runtime"]["components"]["radius-acquisition"] = "not_a_registered_component"
    with pytest.raises(
        PluginPackageManifestError,
        match="manifest_production_runtime_mismatch",
    ):
        validate_remote_access_manifest(broken)



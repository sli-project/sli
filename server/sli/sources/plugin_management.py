"""Fail-closed plugin package projection with durable lifecycle management."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from typing import Any, Callable, Mapping

from server.sli.sources.plugin_resource_profiles import validate_resource_profile_registry
from server.sli.sources.plugin_package_manifest import (
    load_and_validate_remote_access_manifest,
)


ROOT = Path(__file__).resolve().parents[3]
REGISTRY_PATH = ROOT / "config" / "stage10_plugin_management_v1.json"
ARCHITECTURE_PATH = ROOT / "config" / "plugin_architecture_v2.json"
RESOURCE_PROFILES_PATH = ROOT / "config" / "stage10_plugin_resource_profiles_v1.json"
RADIUS_REGISTRATION_PATH = ROOT / "config" / "stage9_radius_registration_v1.json"
AD_DC_REGISTRATION_PATH = (
    ROOT / "config" / "stage9_ad_dc_compatibility_registration_v1.json"
)

PLUGIN_IDS = frozenset({"sli.remote-access", "sli.windows.ad-dc"})
LIFECYCLE_ACTIONS = (
    "install",
    "upgrade",
    "rollback",
    "enable",
    "disable",
    "drain",
    "detach",
)
SECTIONS = (
    "overview",
    "sources",
    "workers",
    "queues",
    "resources",
    "access",
    "versions",
    "audit",
)
SAFE_RADIUS_FIELDS = (
    "source_instance_id",
    "plugin_state",
    "source_state",
    "worker_state",
    "queue_state",
    "dataset_state",
    "access_state",
    "resource_profile",
)


class PluginManagementError(ValueError):
    """The management registry or observed projection is ambiguous or unsafe."""


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise PluginManagementError("plugin_management_object_required")
    return value


def load_plugin_management_registry(path: Path = REGISTRY_PATH) -> dict[str, Any]:
    value = _load_json(path)
    expected = {
        "schema_version": 2,
        "contract_id": "sli.plugin-management.v1",
        "status": "runtime_state_management_enabled",
        "architecture_decision_id": "sli.plugin-architecture.v2",
        "read_only_api_enabled": True,
        "mutation_api_enabled": True,
        "production_read_path_cutover": False,
        "destructive_purge_allowed": False,
    }
    for key, expected_value in expected.items():
        if value.get(key) != expected_value:
            raise PluginManagementError(f"plugin_management_{key}_invalid")
    limits = value.get("limits")
    if limits != {
        "plugins": 20,
        "source_packs_per_plugin": 20,
        "observed_sources_per_plugin": 20,
    }:
        raise PluginManagementError("plugin_management_limits_invalid")
    if value.get("sections") != list(SECTIONS):
        raise PluginManagementError("plugin_management_sections_invalid")
    actions = value.get("lifecycle_actions")
    if not isinstance(actions, dict) or tuple(actions) != LIFECYCLE_ACTIONS:
        raise PluginManagementError("plugin_management_actions_invalid")
    for name, action in actions.items():
        if not isinstance(action, dict):
            raise PluginManagementError(f"plugin_management_action_object:{name}")
        executable = name in {"enable", "disable"}
        if action.get("available") is not executable:
            raise PluginManagementError(f"plugin_management_action_enabled:{name}")
        if (
            not isinstance(action.get("reason"), str)
            or not action["reason"]
            or action.get("future_confirmation") != ("revision_required" if executable else "required")
        ):
            raise PluginManagementError(f"plugin_management_action_guard:{name}")
    plugins = value.get("plugins")
    if not isinstance(plugins, list) or len(plugins) != 2:
        raise PluginManagementError("plugin_management_plugins_invalid")
    seen: set[str] = set()
    for plugin in plugins:
        if not isinstance(plugin, dict):
            raise PluginManagementError("plugin_management_plugin_object_required")
        plugin_id = plugin.get("plugin_id")
        if plugin_id not in PLUGIN_IDS or plugin_id in seen:
            raise PluginManagementError("plugin_management_plugin_id_invalid")
        seen.add(plugin_id)
        for key in (
            "display_name",
            "delivery",
            "trust",
            "management_state",
            "version_state",
            "registration_contract",
            "runtime_ownership",
        ):
            if not isinstance(plugin.get(key), str) or not plugin[key]:
                raise PluginManagementError(
                    f"plugin_management_plugin_{key}_invalid:{plugin_id}"
                )
        if plugin_id == "sli.remote-access":
            if (
                plugin.get("package_version") != "0.1.0"
                or plugin.get("version_state")
                != "packaged_manifest_supervised_runtime"
                or plugin.get("package_manifest")
                != "sli.remote-access.package.v1"
                or plugin.get("runtime_enabled") is not True
                or plugin.get("autostart_enabled") is not True
                or plugin.get("source_contact_allowed") is not True
                or plugin.get("runtime_ownership_kind") != "plugin"
            ):
                raise PluginManagementError(
                    "plugin_management_remote_access_manifest_invalid"
                )
        elif (
            plugin.get("package_version") is not None
            or "package_manifest" in plugin
            or "runtime_enabled" in plugin
            or "autostart_enabled" in plugin
            or "source_contact_allowed" in plugin
            or plugin.get("runtime_ownership_kind") != "core"
        ):
            raise PluginManagementError(
                f"plugin_management_unverified_package_version:{plugin_id}"
            )
        for key, maximum in (
            ("source_pack_ids", limits["source_packs_per_plugin"]),
            ("resource_profile_ids", 20),
        ):
            items = plugin.get(key)
            if (
                not isinstance(items, list)
                or len(items) > maximum
                or len(items) != len(set(items))
                or any(not isinstance(item, str) or not item for item in items)
            ):
                raise PluginManagementError(
                    f"plugin_management_plugin_{key}_invalid:{plugin_id}"
                )
    if seen != PLUGIN_IDS:
        raise PluginManagementError("plugin_management_plugin_set_invalid")
    if not isinstance(value.get("explicitly_out_of_scope"), list):
        raise PluginManagementError("plugin_management_out_of_scope_invalid")
    return value


def _validate_cross_contracts(registry: Mapping[str, Any]) -> dict[str, Any]:
    architecture = _load_json(ARCHITECTURE_PATH)
    if (
        architecture.get("decision_id") != registry["architecture_decision_id"]
        or architecture.get("status") != "owner_accepted_design_boundary"
    ):
        raise PluginManagementError("plugin_management_architecture_mismatch")
    resource_registry = _load_json(RESOURCE_PROFILES_PATH)
    validate_resource_profile_registry(resource_registry)
    package = load_and_validate_remote_access_manifest()
    resource_owners = {
        item["profile_id"]: (item["plugin_id"], item["source_pack_id"])
        for item in resource_registry["profiles"]
    }
    radius = _load_json(RADIUS_REGISTRATION_PATH)
    ad_dc = _load_json(AD_DC_REGISTRATION_PATH)
    by_id = {item["plugin_id"]: item for item in registry["plugins"]}
    remote = by_id["sli.remote-access"]
    if (
        remote["source_pack_ids"] != ["sli.windows.vpn-radius"]
        or remote["package_version"] != package["plugin_version"]
        or remote["package_manifest"] != package["manifest_id"]
        or radius.get("subscription", {}).get("consumer_id")
        != "sli.windows.vpn-radius"
        or any(
            resource_owners.get(profile_id)
            != ("sli.remote-access", "sli.windows.vpn-radius")
            for profile_id in remote["resource_profile_ids"]
        )
    ):
        raise PluginManagementError("plugin_management_remote_access_identity_mismatch")
    ad = by_id["sli.windows.ad-dc"]
    if (
        ad_dc.get("plugin_id") != ad["plugin_id"]
        or [item.get("pack_id") for item in ad_dc.get("source_packs", [])]
        != ad["source_pack_ids"]
        or ad_dc.get("state", {}).get("component_runtime")
        != ad["runtime_ownership"]
    ):
        raise PluginManagementError("plugin_management_ad_dc_identity_mismatch")
    return {
        "architecture": architecture,
        "resources": resource_registry,
        "package": package,
        "ad_dc": ad_dc,
    }


def _default_radius_loader() -> dict[str, Any]:
    from server.sli.plugins.registry import call_plugin

    payload = call_plugin("sli.remote-access", "get_radius_vpn_operations")
    if payload.get("state") == "not_installed":
        return {"contract_id": "sli.radius-vpn-operations.v1", "status": "not_installed",
                "items": [], "contains_identity_or_event_payload": False}
    return payload


def _remote_access_observation(
    loader: Callable[[], Mapping[str, Any]], maximum: int
) -> dict[str, Any]:
    try:
        payload = loader()
        if (
            payload.get("contract_id") != "sli.radius-vpn-operations.v1"
            or payload.get("contains_identity_or_event_payload") is not False
        ):
            raise PluginManagementError("plugin_management_radius_contract_invalid")
        items = payload.get("items")
        if not isinstance(items, list) or len(items) > maximum:
            raise PluginManagementError("plugin_management_radius_items_invalid")
        projected = []
        for item in items:
            if not isinstance(item, Mapping) or item.get("plugin_id") != "sli.remote-access":
                raise PluginManagementError("plugin_management_radius_plugin_mismatch")
            projected.append({key: deepcopy(item.get(key)) for key in SAFE_RADIUS_FIELDS})
        return {
            "status": str(payload.get("status") or "ok"),
            "source_count": len(projected),
            "sources": projected,
            "contains_identity_or_event_payload": False,
        }
    except Exception as exc:
        return {
            "status": "unavailable",
            "source_count": 0,
            "sources": [],
            "contains_identity_or_event_payload": False,
            "error_type": type(exc).__name__,
        }


def build_plugin_management_catalog(
    *,
    include_observed: bool = True,
    radius_loader: Callable[[], Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    registry = load_plugin_management_registry()
    cross = _validate_cross_contracts(registry)
    actions = deepcopy(registry["lifecycle_actions"])
    items = []
    for plugin in registry["plugins"]:
        item = deepcopy(plugin)
        item["sections"] = list(registry["sections"])
        item["lifecycle_actions"] = deepcopy(actions)
        if plugin["plugin_id"] == "sli.remote-access":
            item["observed"] = (
                _remote_access_observation(
                    radius_loader or _default_radius_loader,
                    registry["limits"]["observed_sources_per_plugin"],
                )
                if include_observed
                else {"status": "not_requested", "source_count": 0, "sources": []}
            )
        else:
            for action in item["lifecycle_actions"].values():
                action["available"] = False
            item["observed"] = {
                "status": "compatibility_registered_not_live_asserted",
                "state": deepcopy(cross["ad_dc"]["state"]),
                "source_count": 0,
                "sources": [],
            }
        items.append(item)
    return {
        "contract_id": registry["contract_id"],
        "status": registry["status"],
        "read_only": True,
        "mutation_api_enabled": True,
        "runtime_changed": False,
        "source_contact": False,
        "items": items,
        "limits": deepcopy(registry["limits"]),
        "explicitly_out_of_scope": list(registry["explicitly_out_of_scope"]),
    }


def get_plugin_management(
    plugin_id: str,
    *,
    include_observed: bool = True,
    radius_loader: Callable[[], Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    clean_id = str(plugin_id or "").strip()
    if not clean_id or len(clean_id) > 128:
        raise PluginManagementError("invalid_plugin_id")
    catalog = build_plugin_management_catalog(
        include_observed=include_observed,
        radius_loader=radius_loader,
    )
    item = next((item for item in catalog["items"] if item["plugin_id"] == clean_id), None)
    if item is None:
        raise PluginManagementError("plugin_not_found")
    return {
        "contract_id": catalog["contract_id"],
        "status": catalog["status"],
        "read_only": True,
        "mutation_api_enabled": True,
        "item": item,
    }

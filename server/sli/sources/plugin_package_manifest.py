"""Validate reviewed Stage 10 plugin package manifests without executing them."""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from server.sli.ops.runtime_component_registry import get as get_runtime_component
from server.sli.plugin_validation import FORBIDDEN_KEYS

ROOT = Path(__file__).resolve().parents[3]
MANIFEST_PATH = ROOT / "config/plugin_packages/sli.remote-access.json"
ARCHITECTURE_PATH = ROOT / "config/plugin_architecture_v2.json"
MANAGEMENT_PATH = ROOT / "config/stage10_plugin_management_v1.json"
SOURCE_PACK_PATH = ROOT / "config/source_packs/radius.json"
REGISTRATION_PATH = ROOT / "config/stage9_radius_registration_v1.json"
RESOURCE_PROFILES_PATH = ROOT / "config/stage10_plugin_resource_profiles_v1.json"
POSTGRES_ISOLATION_PATH = ROOT / "config/stage10_plugin_postgresql_isolation_v1.json"

HANDLER_ALLOWLIST = {
    "stage9-radius-manual-worker": ROOT / "scripts/maintenance/stage9_radius_manual_worker.py",
    "stage9-radius-session-consumer-manual": ROOT / "scripts/maintenance/stage9_radius_session_consumer_manual.py",
}
SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


class PluginPackageManifestError(ValueError):
    """The reviewed package manifest is inconsistent or executable by data."""


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise PluginPackageManifestError(f"object_required:{path.name}")
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _reject_executable_material(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if str(key).casefold() in FORBIDDEN_KEYS:
                raise PluginPackageManifestError(
                    f"executable_or_sensitive_manifest_key:{key}"
                )
            _reject_executable_material(item)
    elif isinstance(value, list):
        for item in value:
            _reject_executable_material(item)


def _component_map(items: Any, kind: str) -> dict[str, dict[str, Any]]:
    if not isinstance(items, list) or not items:
        raise PluginPackageManifestError(f"components_required:{kind}")
    result: dict[str, dict[str, Any]] = {}
    for raw in items:
        if not isinstance(raw, dict):
            raise PluginPackageManifestError(f"component_object_required:{kind}")
        component_id = raw.get("component_id")
        if not isinstance(component_id, str) or not component_id or component_id in result:
            raise PluginPackageManifestError(f"component_id_invalid:{kind}")
        if not isinstance(raw.get("state"), str) or not raw["state"]:
            raise PluginPackageManifestError(f"component_state_invalid:{component_id}")
        result[component_id] = raw
    return result


def validate_remote_access_manifest(
    manifest: Mapping[str, Any],
) -> dict[str, Any]:
    _reject_executable_material(manifest)
    expected = {
        "schema_version": 2,
        "manifest_id": "sli.remote-access.package.v1",
        "status": "accepted_supervised_production_metadata",
        "architecture_decision_id": "sli.plugin-architecture.v2",
        "plugin_id": "sli.remote-access",
        "plugin_version": "0.1.0",
        "delivery": "bundled_reviewed",
        "trust": "bundled_reviewed_only",
        "lifecycle_actions_enabled": False,
        "runtime_enabled": True,
        "autostart_enabled": True,
        "source_contact_allowed": True,
        "production_read_path_cutover": False,
    }
    for key, expected_value in expected.items():
        if manifest.get(key) != expected_value:
            raise PluginPackageManifestError(f"manifest_{key}_invalid")
    core_api = manifest.get("core_api")
    if core_api != {"minimum": "1.0.0", "maximum_exclusive": "2.0.0"}:
        raise PluginPackageManifestError("manifest_core_api_invalid")
    if not SEMVER.fullmatch(str(manifest["plugin_version"])):
        raise PluginPackageManifestError("manifest_version_invalid")

    components = manifest.get("components")
    if not isinstance(components, dict) or set(components) != {
        "source_packs", "adapters", "workers", "datasets", "reports", "resource_profiles"
    }:
        raise PluginPackageManifestError("manifest_component_groups_invalid")
    source_packs = _component_map(components["source_packs"], "source_packs")
    adapters = _component_map(components["adapters"], "adapters")
    workers = _component_map(components["workers"], "workers")
    datasets = _component_map(components["datasets"], "datasets")
    reports = _component_map(components["reports"], "reports")
    if set(source_packs) != {"sli.windows.vpn-radius"}:
        raise PluginPackageManifestError("manifest_source_pack_set_invalid")
    if set(adapters) != {"radius-accounting-database-compatible-v1"}:
        raise PluginPackageManifestError("manifest_adapter_set_invalid")
    if set(workers) != {"radius-acquisition", "radius-session-observation"}:
        raise PluginPackageManifestError("manifest_worker_set_invalid")
    if set(datasets) != {"vpn.sessions"} or set(reports) != {"vpn.audit", "vpn.connections"}:
        raise PluginPackageManifestError("manifest_product_component_set_invalid")
    handler_ids = {str(item.get("handler_id") or "") for item in workers.values()}
    if handler_ids != set(HANDLER_ALLOWLIST) or not all(
        path.is_file() for path in HANDLER_ALLOWLIST.values()
    ):
        raise PluginPackageManifestError("manifest_handler_allowlist_mismatch")
    if components["resource_profiles"] != ["stage9-radius-manual-bounded-v1"]:
        raise PluginPackageManifestError("manifest_resource_profile_invalid")

    production_runtime = manifest.get("production_runtime")
    if not isinstance(production_runtime, dict):
        raise PluginPackageManifestError("manifest_production_runtime_invalid")
    host_script = production_runtime.get("host_script")
    if host_script != "scripts/runtime/remote_access_plugin_host.py":
        raise PluginPackageManifestError("manifest_production_runtime_mismatch")
    runtime_components = production_runtime.get("components")
    if not isinstance(runtime_components, dict) or set(runtime_components) != set(workers):
        raise PluginPackageManifestError("manifest_production_runtime_mismatch")
    for component_id, runtime_name in runtime_components.items():
        try:
            component = get_runtime_component(str(runtime_name))
        except KeyError:
            raise PluginPackageManifestError("manifest_production_runtime_mismatch")
        if (
            component.plugin_component_id != component_id
            or f"scripts/runtime/{component.script}" != host_script
            or component.supervised is not True
            or component.feature_enabled is not True
        ):
            raise PluginPackageManifestError("manifest_production_runtime_mismatch")

    architecture = _load(ARCHITECTURE_PATH)
    if architecture.get("decision_id") != manifest["architecture_decision_id"]:
        raise PluginPackageManifestError("manifest_architecture_mismatch")
    required_boundaries = set(manifest.get("required_worker_boundaries") or [])
    if required_boundaries != {
        "windows_identity", "job_object", "working_directory_acl", "network_policy",
        "component_secret_handle", "allowlisted_handler", "postgres_role",
        "db_timeouts", "runtime_identity",
    }:
        raise PluginPackageManifestError("manifest_worker_boundaries_invalid")

    management = _load(MANAGEMENT_PATH)
    remote = next(
        (item for item in management.get("plugins", []) if item.get("plugin_id") == manifest["plugin_id"]),
        None,
    )
    if not isinstance(remote, dict) or remote.get("source_pack_ids") != list(source_packs):
        raise PluginPackageManifestError("manifest_management_mismatch")
    source_pack = _load(SOURCE_PACK_PATH)
    registration = _load(REGISTRATION_PATH)
    profiles = _load(RESOURCE_PROFILES_PATH)
    isolation = _load(POSTGRES_ISOLATION_PATH)
    if (
        source_pack.get("pack_id") != "sli.windows.vpn-radius"
        or source_pack.get("version") != source_packs["sli.windows.vpn-radius"].get("component_version")
        or registration.get("source", {}).get("adapter_binding") not in adapters
        or registration.get("subscription", {}).get("consumer_component_id") not in workers
        or isolation.get("plugin_id") != manifest["plugin_id"]
    ):
        raise PluginPackageManifestError("manifest_registered_components_mismatch")
    profile_ids = {item.get("profile_id") for item in profiles.get("profiles", [])}
    if set(components["resource_profiles"]) - profile_ids:
        raise PluginPackageManifestError("manifest_profile_not_registered")
    migrations = manifest.get("migrations")
    if migrations != {
        "compatibility_existing": [58, 59, 60, 61, 62, 63, 64, 65],
        "core_prerequisites": [66],
        "plugin_owned_prepared": [67],
    }:
        raise PluginPackageManifestError("manifest_migrations_invalid")
    if not isinstance(manifest.get("explicitly_not_proven"), list):
        raise PluginPackageManifestError("manifest_limitations_required")
    return {
        "manifest_id": manifest["manifest_id"],
        "plugin_id": manifest["plugin_id"],
        "plugin_version": manifest["plugin_version"],
        "component_count": sum(
            len(components[key])
            for key in ("source_packs", "adapters", "workers", "datasets", "reports")
        ),
        "handler_hashes": {
            handler_id: _sha256(path)
            for handler_id, path in sorted(HANDLER_ALLOWLIST.items())
        },
        "manifest_sha256": _sha256(MANIFEST_PATH),
    }


def load_and_validate_remote_access_manifest() -> dict[str, Any]:
    return validate_remote_access_manifest(_load(MANIFEST_PATH))

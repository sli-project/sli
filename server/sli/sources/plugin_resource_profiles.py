"""Source-only validation and honest projection of plugin resource profiles."""
from __future__ import annotations

from typing import Any, Mapping


REQUIRED_HARD_PROCESS_LIMITS = (
    "cpu_hard_limit",
    "memory_bytes",
    "pids",
    "job_object_kill_on_close",
    "working_directory_acl",
    "network_allowlist_enforced",
)
REQUIRED_OBSERVABILITY_FIELDS = (
    "profile_id",
    "mode",
    "activation_state",
    "temporary_profile",
    "effective_until_utc",
    "reason",
    "declared_limits",
    "enforced_limits",
    "actual_usage",
    "deviations",
    "missing_hard_limits",
)
ALLOWED_MODES = frozenset({"normal", "diagnostic_manual", "emergency"})
ALLOWED_ACTIVATION_STATES = frozenset({"disabled", "enabled", "blocked"})


class PluginResourceProfileError(ValueError):
    """Fail-closed resource profile contract violation."""


def validate_resource_profile_registry(value: Mapping[str, Any]) -> dict[str, Any]:
    expected_header = {
        "schema_version": 1,
        "contract_id": "sli.plugin-resource-profiles.v1",
        "status": "prepared_source_inventory",
        "runtime_enabled": False,
        "autostart_enabled": False,
        "source_contact_allowed": False,
        "production_configuration_changed": False,
    }
    for key, expected in expected_header.items():
        if value.get(key) != expected:
            raise PluginResourceProfileError(f"registry_{key}_invalid")
    modes = value.get("profile_modes")
    if not isinstance(modes, dict) or set(modes) != {
        "normal",
        "diagnostic",
        "emergency",
    }:
        raise PluginResourceProfileError("profile_modes_invalid")
    profiles = value.get("profiles")
    if not isinstance(profiles, list) or not profiles:
        raise PluginResourceProfileError("profiles_required")
    seen: set[str] = set()
    results = []
    for profile in profiles:
        if not isinstance(profile, dict):
            raise PluginResourceProfileError("profile_object_required")
        profile_id = str(profile.get("profile_id") or "")
        if not profile_id or profile_id in seen:
            raise PluginResourceProfileError("profile_id_invalid_or_duplicate")
        seen.add(profile_id)
        results.append(validate_resource_profile(profile))
    return {
        "contract_id": expected_header["contract_id"],
        "profile_count": len(results),
        "profiles": results,
        "long_lived_normal_profile_defined": (
            modes["normal"] != "not_defined_for_long_lived_plugin_worker"
        ),
        "runtime_enabled": False,
    }


def validate_resource_profile(profile: Mapping[str, Any]) -> dict[str, Any]:
    for key in (
        "profile_id",
        "plugin_id",
        "source_pack_id",
        "component_id",
        "source_instance_id",
    ):
        if not isinstance(profile.get(key), str) or not profile[key].strip():
            raise PluginResourceProfileError(f"profile_{key}_invalid")
    if profile.get("mode") not in ALLOWED_MODES:
        raise PluginResourceProfileError("profile_mode_invalid")
    if profile.get("activation_state") not in ALLOWED_ACTIVATION_STATES:
        raise PluginResourceProfileError("profile_activation_state_invalid")
    if not isinstance(profile.get("temporary_profile"), bool):
        raise PluginResourceProfileError("temporary_profile_flag_required")
    if profile.get("temporary_profile") and not profile.get(
        "reason_required_when_active"
    ):
        raise PluginResourceProfileError("temporary_profile_reason_guard_missing")
    limits = profile.get("application_limits")
    if not isinstance(limits, list) or not limits:
        raise PluginResourceProfileError("application_limits_required")
    keys: set[str] = set()
    for item in limits:
        if not isinstance(item, dict):
            raise PluginResourceProfileError("application_limit_object_required")
        key = item.get("key")
        if not isinstance(key, str) or not key or key in keys:
            raise PluginResourceProfileError("application_limit_key_invalid_or_duplicate")
        keys.add(key)
        if not isinstance(item.get("value"), int) or item["value"] < 1:
            raise PluginResourceProfileError("application_limit_value_invalid")
        for required in ("unit", "enforcement", "change_control"):
            if not isinstance(item.get(required), str) or not item[required]:
                raise PluginResourceProfileError(
                    f"application_limit_{required}_invalid"
                )
    hard = profile.get("hard_process_limits")
    if not isinstance(hard, dict) or set(hard) != set(REQUIRED_HARD_PROCESS_LIMITS):
        raise PluginResourceProfileError("hard_process_limit_shape_invalid")
    observations = profile.get("observability_fields")
    if observations != list(REQUIRED_OBSERVABILITY_FIELDS):
        raise PluginResourceProfileError("observability_fields_invalid")
    missing = sorted(name for name, limit in hard.items() if limit is None)
    return {
        "profile_id": profile["profile_id"],
        "plugin_id": profile["plugin_id"],
        "source_pack_id": profile["source_pack_id"],
        "application_limit_count": len(limits),
        "hard_process_limit_count": len(hard) - len(missing),
        "missing_hard_limits": missing,
        "ready_for_long_lived_worker": not missing
        and profile["mode"] == "normal",
    }


def project_resource_profile_status(
    profile: Mapping[str, Any],
    *,
    reason: str | None = None,
    actual_usage: Mapping[str, int | float] | None = None,
) -> dict[str, Any]:
    validated = validate_resource_profile(profile)
    active = profile["activation_state"] == "enabled"
    if active and profile["temporary_profile"] and not (reason or "").strip():
        raise PluginResourceProfileError("active_temporary_profile_reason_required")
    return {
        "profile_id": profile["profile_id"],
        "plugin_id": profile["plugin_id"],
        "source_pack_id": profile["source_pack_id"],
        "mode": profile["mode"],
        "activation_state": profile["activation_state"],
        "temporary_profile": profile["temporary_profile"],
        "effective_until_utc": profile.get("effective_until_utc"),
        "reason": reason if active else None,
        "declared_limits": {
            item["key"]: {"value": item["value"], "unit": item["unit"]}
            for item in profile["application_limits"]
        },
        "enforced_limits": {
            item["key"]: item["enforcement"]
            for item in profile["application_limits"]
        },
        "actual_usage": dict(actual_usage or {}),
        "deviations": [],
        "missing_hard_limits": validated["missing_hard_limits"],
        "ready_for_long_lived_worker": validated["ready_for_long_lived_worker"],
    }

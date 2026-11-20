"""Fail-closed Stage 10 plugin lifecycle planning without side effects."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterable, Mapping


ROOT = Path(__file__).resolve().parents[3]
CONFIG_PATH = ROOT / "config" / "stage10_plugin_lifecycle_v1.json"
MANIFEST_PATH = ROOT / "config" / "plugin_packages" / "sli.remote-access.json"
PLUGIN_ID_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{2,79}$")
VERSION_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


class PluginLifecycleError(ValueError):
    """A lifecycle request is invalid or attempts an unaccepted side effect."""


@dataclass(frozen=True)
class PluginLifecycleState:
    plugin_id: str
    revision: int
    package_version: str
    rollback_version: str | None
    package_lifecycle: str
    desired_activation: str
    observed_health: str
    component_runtime: str
    queue_state: str
    immutable_evidence_count: int
    detach_reader_ready: bool
    read_report_parity: bool
    accepted_live_boundaries: tuple[str, ...] = ()


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise PluginLifecycleError(f"plugin_lifecycle_object_required:{path.name}")
    return value


def load_plugin_lifecycle_contract(path: Path = CONFIG_PATH) -> dict[str, Any]:
    value = _load_json(path)
    expected = {
        "schema_version": 1,
        "contract_id": "sli.plugin-lifecycle.v1",
        "status": "bundled_install_executor_ready_runtime_disabled",
        "architecture_decision_id": "sli.plugin-architecture.v2",
        "trust": "bundled_reviewed_only",
        "supported_plugin_ids": ["sli.remote-access"],
        "required_capability": "plugins.manage",
        "capability_registered": True,
        "mutation_execution_enabled": True,
        "executable_actions": ["install"],
        "runtime_enabled": False,
        "autostart_enabled": False,
        "source_contact_allowed": False,
        "process_control_allowed": False,
        "database_mutation_allowed": False,
        "production_read_path_cutover": False,
        "destructive_purge_allowed": False,
        "actions": [
            "install", "upgrade", "rollback", "enable", "drain",
            "disable", "detach",
        ],
        "install_semantics": "register_bundled_release_manifest_only",
        "confirmation_required": True,
        "audit_category": "plugin_lifecycle",
        "audit_actor_source": "server_authoritative_principal_only",
    }
    for key, expected_value in expected.items():
        if value.get(key) != expected_value:
            raise PluginLifecycleError(f"plugin_lifecycle_contract_invalid:{key}")
    if set(value.get("state_axes") or {}) != {
        "package_lifecycle", "desired_activation", "observed_health",
        "component_runtime", "queue_state",
    }:
        raise PluginLifecycleError("plugin_lifecycle_state_axes_invalid")
    if len(value.get("required_live_boundaries") or []) != 9:
        raise PluginLifecycleError("plugin_lifecycle_boundaries_invalid")
    if len(value.get("forbidden_effects") or []) < 8:
        raise PluginLifecycleError("plugin_lifecycle_forbidden_effects_missing")
    if set(value.get("explicitly_not_proven") or []) != {
        "accepted_live_worker_boundaries",
        "queue_drain_executor",
        "process_supervisor_executor",
        "versioned_upgrade_or_rollback_executor",
        "detach_reader_acceptance",
        "production_mutation_api",
    }:
        raise PluginLifecycleError("plugin_lifecycle_limitations_missing")
    return value


def initial_remote_access_state() -> PluginLifecycleState:
    manifest = _load_json(MANIFEST_PATH)
    if (
        manifest.get("plugin_id") != "sli.remote-access"
        or manifest.get("status") != "accepted_supervised_production_metadata"
        or manifest.get("delivery") != "bundled_reviewed"
        or manifest.get("trust") != "bundled_reviewed_only"
        or not VERSION_RE.fullmatch(str(manifest.get("plugin_version") or ""))
    ):
        raise PluginLifecycleError("plugin_lifecycle_manifest_invalid")
    return PluginLifecycleState(
        plugin_id="sli.remote-access",
        revision=1,
        package_version=str(manifest["plugin_version"]),
        rollback_version=None,
        package_lifecycle="validated",
        desired_activation="disabled",
        observed_health="unknown",
        component_runtime="stopped",
        queue_state="drained",
        immutable_evidence_count=1,
        detach_reader_ready=False,
        read_report_parity=False,
    )


def _validate_state(
    state: PluginLifecycleState, contract: Mapping[str, Any]
) -> None:
    if (
        state.plugin_id not in set(contract["supported_plugin_ids"])
        or not PLUGIN_ID_RE.fullmatch(state.plugin_id)
        or state.revision < 1
        or not VERSION_RE.fullmatch(state.package_version)
        or (
            state.rollback_version is not None
            and not VERSION_RE.fullmatch(state.rollback_version)
        )
        or state.immutable_evidence_count < 1
    ):
        raise PluginLifecycleError("plugin_lifecycle_state_identity_invalid")
    axes = contract["state_axes"]
    for key in axes:
        if getattr(state, key) not in set(axes[key]):
            raise PluginLifecycleError(f"plugin_lifecycle_state_invalid:{key}")
    allowed_boundaries = set(contract["required_live_boundaries"])
    if not set(state.accepted_live_boundaries) <= allowed_boundaries:
        raise PluginLifecycleError("plugin_lifecycle_unknown_boundary")


def _token(action: str, plugin_id: str, revision: int, digest: str) -> str:
    plugin = plugin_id.upper().replace(".", "-")
    return f"PLUGIN-{action.upper()}-{plugin}-R{revision}-{digest[:12].upper()}"


def plan_plugin_lifecycle(
    *,
    action: str,
    state: PluginLifecycleState,
    actor_capabilities: Iterable[str],
    target_version: str | None = None,
    contract: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    value = dict(contract or load_plugin_lifecycle_contract())
    _validate_state(state, value)
    clean_action = str(action or "").strip().lower()
    if clean_action not in set(value["actions"]):
        raise PluginLifecycleError("plugin_lifecycle_action_invalid")
    capabilities = {str(item) for item in actor_capabilities}
    blockers: list[str] = []
    if value["required_capability"] not in capabilities:
        blockers.append("plugins_manage_required")
    effects: dict[str, Any] = {}
    version = target_version
    if clean_action == "install":
        if state.package_lifecycle != "validated":
            blockers.append("install_requires_validated_package")
        effects["package_lifecycle"] = "registered"
        version = state.package_version
    elif clean_action == "upgrade":
        if not version or not VERSION_RE.fullmatch(version):
            blockers.append("upgrade_target_version_invalid")
        if (
            state.package_lifecycle != "registered"
            or state.desired_activation != "disabled"
            or state.component_runtime != "stopped"
            or state.queue_state != "drained"
        ):
            blockers.append("upgrade_requires_registered_disabled_stopped_drained")
        if version == state.package_version:
            blockers.append("upgrade_target_must_differ")
        effects.update(
            package_version=version,
            rollback_version=state.package_version,
        )
    elif clean_action == "rollback":
        if state.rollback_version is None:
            blockers.append("rollback_version_missing")
        if (
            state.package_lifecycle != "registered"
            or state.desired_activation != "disabled"
            or state.component_runtime != "stopped"
            or state.queue_state != "drained"
        ):
            blockers.append("rollback_requires_registered_disabled_stopped_drained")
        version = state.rollback_version
        effects.update(package_version=version, rollback_version=None)
    elif clean_action == "enable":
        missing = sorted(
            set(value["required_live_boundaries"])
            - set(state.accepted_live_boundaries)
        )
        if state.package_lifecycle != "registered":
            blockers.append("enable_requires_registered_package")
        if state.component_runtime != "stopped":
            blockers.append("enable_requires_stopped_runtime")
        if missing:
            blockers.append("enable_live_boundaries_not_accepted")
        effects["desired_activation"] = "enabled_manual"
    elif clean_action == "drain":
        if state.package_lifecycle != "registered":
            blockers.append("drain_requires_registered_package")
        if state.component_runtime not in {"running", "failed"}:
            blockers.append("drain_requires_running_or_failed_runtime")
        effects.update(component_runtime="draining", desired_activation="disabled")
    elif clean_action == "disable":
        if state.package_lifecycle != "registered":
            blockers.append("disable_requires_registered_package")
        if state.component_runtime != "stopped" or state.queue_state != "drained":
            blockers.append("disable_requires_stopped_drained")
        effects.update(desired_activation="disabled", observed_health="unknown")
    elif clean_action == "detach":
        if (
            state.package_lifecycle != "registered"
            or state.desired_activation != "disabled"
            or state.component_runtime != "stopped"
            or state.queue_state != "drained"
        ):
            blockers.append("detach_requires_registered_disabled_stopped_drained")
        if not state.detach_reader_ready or not state.read_report_parity:
            blockers.append("detach_reader_and_parity_required")
        effects.update(
            package_lifecycle="detached",
            desired_activation="disabled",
            component_runtime="stopped",
            queue_state="drained",
        )
    envelope = {
        "contract_id": value["contract_id"],
        "plugin_id": state.plugin_id,
        "requested_action": clean_action,
        "expected_revision": state.revision,
        "target_version": version,
        "effects": effects,
        "preserve_immutable_evidence": True,
        "production_read_path_cutover": False,
        "destructive_purge": False,
    }
    digest = hashlib.sha256(
        json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    preconditions_met = not blockers
    return {
        **envelope,
        "plan_sha256": digest,
        "confirmation": _token(clean_action, state.plugin_id, state.revision, digest),
        "required_capability": value["required_capability"],
        "preconditions_met": preconditions_met,
        "execution_allowed": preconditions_met
        and value["capability_registered"] is True
        and value["mutation_execution_enabled"] is True
        and clean_action in value["executable_actions"],
        "blockers": blockers + [
            item for item, blocked in (
                ("plugins_manage_capability_not_registered", value["capability_registered"] is not True),
                ("plugin_lifecycle_execution_disabled", value["mutation_execution_enabled"] is not True),
                ("plugin_lifecycle_action_not_executable", clean_action not in value["executable_actions"]),
            ) if blocked
        ],
        "audit_event": {
            "category": value["audit_category"],
            "action_key": f"plugin.{clean_action}",
            "target_kind": "plugin",
            "target_key": state.plugin_id,
            "details": {
                "expected_revision": state.revision,
                "plan_sha256": digest,
            },
        },
        "forbidden_effects": list(value["forbidden_effects"]),
        "state_before": asdict(state),
    }


def execute_plugin_lifecycle(*, plan: Mapping[str, Any], confirmation: str) -> None:
    """Production execution stays impossible until a later accepted contract."""
    if confirmation != plan.get("confirmation"):
        raise PluginLifecycleError("plugin_lifecycle_confirmation_invalid")
    if plan.get("execution_allowed") is not True:
        raise PluginLifecycleError("plugin_lifecycle_execution_disabled")
    raise PluginLifecycleError("plugin_lifecycle_executor_requires_operation_context")

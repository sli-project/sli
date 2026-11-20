"""Pure fixture-only Stage 10 state machine for plugin isolation invariants."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[3]
CONFIG_PATH = ROOT / "config" / "stage10_plugin_isolation_fixture_v1.json"
ARCHITECTURE_PATH = ROOT / "config" / "plugin_architecture_v2.json"
PLUGIN_IDS = frozenset({"sli.remote-access", "sli.windows.ad-dc"})
REQUIRED_SCENARIOS = (
    "independent_disable",
    "failure_isolation",
    "resource_exhaustion_isolation",
    "independent_upgrade_and_rollback",
    "detach_without_core_or_peer_outage",
    "read_and_report_parity_before_ownership_cutover",
)


class PluginIsolationFixtureError(ValueError):
    """A fixture transition would weaken or overstate plugin isolation."""


def load_isolation_fixture(path: Path = CONFIG_PATH) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise PluginIsolationFixtureError("isolation_fixture_object_required")
    expected = {
        "schema_version": 1,
        "contract_id": "sli.plugin-isolation-fixture.v1",
        "status": "prepared_fixture_only",
        "architecture_decision_id": "sli.plugin-architecture.v2",
        "fixture_only": True,
        "runtime_enabled": False,
        "source_contact_allowed": False,
        "database_access_allowed": False,
        "process_control_allowed": False,
        "autostart_enabled": False,
        "production_read_path_cutover": False,
    }
    for key, expected_value in expected.items():
        if value.get(key) != expected_value:
            raise PluginIsolationFixtureError(f"isolation_fixture_{key}_invalid")
    architecture = json.loads(ARCHITECTURE_PATH.read_text(encoding="utf-8"))
    if (
        architecture.get("decision_id") != value["architecture_decision_id"]
        or architecture.get("status") != "owner_accepted_design_boundary"
        or architecture.get("stage10_acceptance_requires")
        != list(REQUIRED_SCENARIOS)
    ):
        raise PluginIsolationFixtureError("isolation_fixture_architecture_mismatch")
    if value.get("required_scenarios") != list(REQUIRED_SCENARIOS):
        raise PluginIsolationFixtureError("isolation_fixture_scenarios_invalid")
    core = value.get("core")
    if core != {"health": "healthy_fixture", "runtime": "running_fixture"}:
        raise PluginIsolationFixtureError("isolation_fixture_core_invalid")
    plugins = value.get("plugins")
    if not isinstance(plugins, list) or len(plugins) != 2:
        raise PluginIsolationFixtureError("isolation_fixture_plugins_invalid")
    seen: set[str] = set()
    for plugin in plugins:
        if not isinstance(plugin, dict):
            raise PluginIsolationFixtureError("isolation_fixture_plugin_object_required")
        plugin_id = plugin.get("plugin_id")
        if plugin_id not in PLUGIN_IDS or plugin_id in seen:
            raise PluginIsolationFixtureError("isolation_fixture_plugin_id_invalid")
        seen.add(plugin_id)
        version = plugin.get("package_version")
        if not isinstance(version, str) or not version.endswith("-fixture"):
            raise PluginIsolationFixtureError("isolation_fixture_version_invalid")
        for key in (
            "package_lifecycle",
            "desired_activation",
            "observed_health",
            "component_runtime",
            "queue_state",
            "dataset_state",
        ):
            if not isinstance(plugin.get(key), str) or not plugin[key].endswith(
                "_fixture"
            ):
                raise PluginIsolationFixtureError(
                    f"isolation_fixture_plugin_state_invalid:{plugin_id}:{key}"
                )
        for key in ("detach_reader_ready", "read_report_parity"):
            if plugin.get(key) is not True:
                raise PluginIsolationFixtureError(
                    f"isolation_fixture_guard_missing:{plugin_id}:{key}"
                )
        refs = plugin.get("immutable_evidence_refs")
        if (
            not isinstance(refs, list)
            or not refs
            or len(refs) != len(set(refs))
            or any(not isinstance(item, str) or not item.startswith("fixture-evidence:") for item in refs)
        ):
            raise PluginIsolationFixtureError(
                f"isolation_fixture_evidence_invalid:{plugin_id}"
            )
    if seen != PLUGIN_IDS:
        raise PluginIsolationFixtureError("isolation_fixture_plugin_set_invalid")
    not_proven = value.get("explicitly_not_proven")
    if not isinstance(not_proven, list) or len(not_proven) < 7:
        raise PluginIsolationFixtureError("isolation_fixture_limitations_required")
    return value


class PluginIsolationFixture:
    """In-memory transition model; it has no process, DB or source entrypoint."""

    def __init__(self, config: Mapping[str, Any]):
        self.core = deepcopy(dict(config["core"]))
        self.plugins = {
            item["plugin_id"]: {
                **deepcopy(dict(item)),
                "rollback_versions": [],
            }
            for item in config["plugins"]
        }

    @classmethod
    def from_config(cls) -> "PluginIsolationFixture":
        return cls(load_isolation_fixture())

    def snapshot(self) -> dict[str, Any]:
        return {"core": deepcopy(self.core), "plugins": deepcopy(self.plugins)}

    def _plugin(self, plugin_id: str) -> dict[str, Any]:
        try:
            return self.plugins[plugin_id]
        except KeyError as exc:
            raise PluginIsolationFixtureError("isolation_fixture_plugin_not_found") from exc

    def disable(self, plugin_id: str) -> None:
        plugin = self._plugin(plugin_id)
        plugin["desired_activation"] = "disabled_fixture"
        plugin["component_runtime"] = "stopped_fixture"
        plugin["observed_health"] = "disabled_fixture"

    def inject_failure(self, plugin_id: str) -> None:
        plugin = self._plugin(plugin_id)
        plugin["observed_health"] = "failed_fixture"
        plugin["component_runtime"] = "failed_fixture"
        plugin["dataset_state"] = "blocked_fixture"

    def inject_resource_exhaustion(self, plugin_id: str) -> None:
        plugin = self._plugin(plugin_id)
        plugin["observed_health"] = "resource_exhausted_fixture"
        plugin["component_runtime"] = "terminated_fixture"
        plugin["queue_state"] = "quarantined_fixture"
        plugin["dataset_state"] = "blocked_fixture"

    def upgrade(self, plugin_id: str, version: str) -> None:
        plugin = self._plugin(plugin_id)
        if (
            plugin["desired_activation"] != "disabled_fixture"
            or plugin["component_runtime"] != "stopped_fixture"
            or plugin["queue_state"] != "drained_fixture"
        ):
            raise PluginIsolationFixtureError("upgrade_requires_disabled_drained_plugin")
        if not isinstance(version, str) or not version.endswith("-fixture"):
            raise PluginIsolationFixtureError("upgrade_fixture_version_required")
        plugin["rollback_versions"].append(plugin["package_version"])
        plugin["package_version"] = version

    def rollback(self, plugin_id: str) -> None:
        plugin = self._plugin(plugin_id)
        if not plugin["rollback_versions"]:
            raise PluginIsolationFixtureError("rollback_version_missing")
        plugin["package_version"] = plugin["rollback_versions"].pop()

    def detach(self, plugin_id: str) -> None:
        plugin = self._plugin(plugin_id)
        if (
            plugin["desired_activation"] != "disabled_fixture"
            or plugin["component_runtime"] != "stopped_fixture"
            or plugin["queue_state"] != "drained_fixture"
            or plugin["detach_reader_ready"] is not True
            or plugin["read_report_parity"] is not True
        ):
            raise PluginIsolationFixtureError("detach_preconditions_not_met")
        plugin["package_lifecycle"] = "detached_fixture"
        plugin["dataset_state"] = "retained_read_only_fixture"

    def plan_ownership_cutover(self, plugin_id: str) -> dict[str, Any]:
        plugin = self._plugin(plugin_id)
        if plugin["read_report_parity"] is not True:
            raise PluginIsolationFixtureError("read_report_parity_required")
        return {
            "eligible": True,
            "executed": False,
            "production_read_path_cutover": False,
        }

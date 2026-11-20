"""Pure Stage 10 admission and two-cell drain planning.

The module deliberately has no database, process or source entrypoint.  It
makes the state transitions required by a later durable executor explicit and
testable before any live plugin runtime is enabled.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Mapping

from server.sli.sources.plugin_lifecycle import PluginLifecycleState


ROOT = Path(__file__).resolve().parents[3]
CONFIG_PATH = ROOT / "config" / "stage10_plugin_runtime_admission_v1.json"
ACQUISITION = "radius-acquisition"
CONSUMER = "radius-session-observation"


class PluginRuntimeAdmissionError(ValueError):
    """The admission snapshot or requested transition is invalid."""


@dataclass(frozen=True)
class PluginComponentAdmission:
    acquisition_mode: str
    consumer_mode: str
    active_acquisition_leases: int = 0
    active_consumer_leases: int = 0


@dataclass(frozen=True)
class PluginQueueSnapshot:
    queued: int = 0
    leased: int = 0
    failed: int = 0
    quarantined: int = 0

    @property
    def nonterminal(self) -> int:
        return self.queued + self.leased + self.failed + self.quarantined


def load_runtime_admission_contract(
    path: Path = CONFIG_PATH,
) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    expected = {
        "schema_version": 1,
        "contract_id": "sli.plugin-runtime-admission.v1",
        "status": "source_contract_runtime_disabled",
        "architecture_decision_id": "sli.plugin-architecture.v2",
        "plugin_id": "sli.remote-access",
        "admission_modes": ["closed", "open", "drain_only"],
        "runtime_enabled": False,
        "autostart_enabled": False,
        "database_mutation_enabled": False,
        "source_contact_allowed": False,
        "process_control_allowed": False,
    }
    if not isinstance(value, dict):
        raise PluginRuntimeAdmissionError("runtime_admission_object_required")
    for key, expected_value in expected.items():
        if value.get(key) != expected_value:
            raise PluginRuntimeAdmissionError(
                f"runtime_admission_contract_invalid:{key}"
            )
    components = value.get("components")
    if not isinstance(components, Mapping) or set(components) != {
        ACQUISITION,
        CONSUMER,
    }:
        raise PluginRuntimeAdmissionError(
            "runtime_admission_components_invalid"
        )
    if not (
        components[ACQUISITION] == {
            "source_contact": True,
            "normal_mode": "open",
            "drain_mode": "closed",
        }
        and components[CONSUMER] == {
            "source_contact": False,
            "normal_mode": "open",
            "drain_mode": "drain_only",
        }
    ):
        raise PluginRuntimeAdmissionError(
            "runtime_admission_component_policy_invalid"
        )
    if set(value.get("queue_nonterminal_states") or ()) != {
        "queued",
        "leased",
        "failed",
        "quarantined",
    }:
        raise PluginRuntimeAdmissionError(
            "runtime_admission_queue_states_invalid"
        )
    if len(value.get("drain_sequence") or ()) != 7:
        raise PluginRuntimeAdmissionError(
            "runtime_admission_drain_sequence_invalid"
        )
    if set(value.get("explicitly_not_proven") or ()) != {
        "durable_component_admission_registry",
        "database_admission_lease_executor",
        "live_process_supervisor",
        "live_queue_drain",
    }:
        raise PluginRuntimeAdmissionError(
            "runtime_admission_limitations_invalid"
        )
    return value


def _validate_counts(
    admission: PluginComponentAdmission,
    queue: PluginQueueSnapshot | None = None,
) -> None:
    modes = {"closed", "open", "drain_only"}
    counts = (
        admission.active_acquisition_leases,
        admission.active_consumer_leases,
    )
    if (
        admission.acquisition_mode not in modes
        or admission.consumer_mode not in modes
        or any(isinstance(item, bool) or item < 0 for item in counts)
    ):
        raise PluginRuntimeAdmissionError(
            "runtime_admission_snapshot_invalid"
        )
    if queue is not None:
        values = (queue.queued, queue.leased, queue.failed, queue.quarantined)
        if any(isinstance(item, bool) or item < 0 for item in values):
            raise PluginRuntimeAdmissionError("runtime_queue_snapshot_invalid")


def admission_allowed(
    *,
    component_id: str,
    state: PluginLifecycleState,
    admission: PluginComponentAdmission,
) -> bool:
    """Return the future durable admission decision for one component."""
    load_runtime_admission_contract()
    _validate_counts(admission)
    if state.plugin_id != "sli.remote-access" or state.package_lifecycle != "registered":
        return False
    if component_id == ACQUISITION:
        return (
            state.desired_activation == "enabled_manual"
            and state.component_runtime == "running"
            and admission.acquisition_mode == "open"
        )
    if component_id == CONSUMER:
        return (
            (
                state.desired_activation == "enabled_manual"
                and state.component_runtime == "running"
                and admission.consumer_mode == "open"
            )
            or (
                state.desired_activation == "disabled"
                and state.component_runtime == "draining"
                and admission.consumer_mode == "drain_only"
            )
        )
    raise PluginRuntimeAdmissionError("runtime_admission_component_unknown")


def plan_begin_drain(
    *,
    state: PluginLifecycleState,
    admission: PluginComponentAdmission,
) -> dict[str, Any]:
    """Close producer admission while preserving bounded consumer drain."""
    contract = load_runtime_admission_contract()
    _validate_counts(admission)
    blockers: list[str] = []
    if (
        state.plugin_id != contract["plugin_id"]
        or state.package_lifecycle != "registered"
        or state.desired_activation != "enabled_manual"
        or state.component_runtime not in {"running", "failed"}
    ):
        blockers.append("drain_requires_registered_enabled_runtime")
    if admission.acquisition_mode != "open":
        blockers.append("drain_requires_open_acquisition_admission")
    if admission.consumer_mode != "open":
        blockers.append("drain_requires_open_consumer_admission")
    return {
        "status": "ready" if not blockers else "blocked",
        "blockers": blockers,
        "effects": {
            "desired_activation": "disabled",
            "component_runtime": "draining",
            "queue_state": "backlog",
            "acquisition_mode": "closed",
            "consumer_mode": "drain_only",
        },
        "active_acquisition_leases_to_wait": (
            admission.active_acquisition_leases
        ),
        "source_contact_allowed": False,
        "process_control_allowed": False,
        "database_mutation_enabled": False,
    }


def plan_complete_drain(
    *,
    state: PluginLifecycleState,
    admission: PluginComponentAdmission,
    queue: PluginQueueSnapshot,
) -> dict[str, Any]:
    """Allow stop only after all producer, queue and consumer work is gone."""
    load_runtime_admission_contract()
    _validate_counts(admission, queue)
    blockers: list[str] = []
    if not (
        state.plugin_id == "sli.remote-access"
        and state.package_lifecycle == "registered"
        and state.desired_activation == "disabled"
        and state.component_runtime == "draining"
    ):
        blockers.append("drain_completion_requires_draining_state")
    if admission.acquisition_mode != "closed":
        blockers.append("acquisition_admission_must_be_closed")
    if admission.consumer_mode != "drain_only":
        blockers.append("consumer_must_remain_drain_only")
    if admission.active_acquisition_leases:
        blockers.append("active_acquisition_leases_present")
    if queue.queued:
        blockers.append("queued_deliveries_present")
    if queue.leased:
        blockers.append("leased_deliveries_present")
    if queue.failed:
        blockers.append("failed_deliveries_present")
    if queue.quarantined:
        blockers.append("quarantined_deliveries_present")
    if admission.active_consumer_leases:
        blockers.append("active_consumer_leases_present")
    return {
        "status": "ready" if not blockers else "blocked",
        "blockers": blockers,
        "effects": {
            "component_runtime": "stopped",
            "queue_state": "drained",
            "acquisition_mode": "closed",
            "consumer_mode": "closed",
        },
        "queue_nonterminal": queue.nonterminal,
        "source_contact_allowed": False,
        "process_control_allowed": False,
        "database_mutation_enabled": False,
    }

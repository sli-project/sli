from __future__ import annotations

from dataclasses import replace

from server.sli.sources.plugin_lifecycle import initial_remote_access_state
from server.sli.sources.plugin_runtime_admission import (
    ACQUISITION,
    CONSUMER,
    PluginComponentAdmission,
    PluginQueueSnapshot,
    admission_allowed,
    plan_begin_drain,
    plan_complete_drain,
)


def _running():
    return replace(
        initial_remote_access_state(),
        revision=2,
        package_lifecycle="registered",
        desired_activation="enabled_manual",
        observed_health="ready",
        component_runtime="running",
        queue_state="backlog",
    )


def _draining():
    return replace(
        _running(),
        desired_activation="disabled",
        component_runtime="draining",
    )


def test_drain_closes_producer_but_keeps_consumer_admitted() -> None:
    open_cells = PluginComponentAdmission("open", "open")
    begin = plan_begin_drain(state=_running(), admission=open_cells)
    assert begin["status"] == "ready"
    assert begin["effects"]["acquisition_mode"] == "closed"
    assert begin["effects"]["consumer_mode"] == "drain_only"

    draining_cells = PluginComponentAdmission("closed", "drain_only")
    assert not admission_allowed(
        component_id=ACQUISITION,
        state=_draining(),
        admission=draining_cells,
    )
    assert admission_allowed(
        component_id=CONSUMER,
        state=_draining(),
        admission=draining_cells,
    )


def test_drain_completion_requires_empty_queue_and_no_leases() -> None:
    active = plan_complete_drain(
        state=_draining(),
        admission=PluginComponentAdmission("closed", "drain_only", 1, 1),
        queue=PluginQueueSnapshot(queued=1, leased=1, failed=1, quarantined=1),
    )
    assert active["status"] == "blocked"
    assert set(active["blockers"]) >= {
        "active_acquisition_leases_present",
        "active_consumer_leases_present",
        "queued_deliveries_present",
        "leased_deliveries_present",
        "failed_deliveries_present",
        "quarantined_deliveries_present",
    }

    completed = plan_complete_drain(
        state=_draining(),
        admission=PluginComponentAdmission("closed", "drain_only"),
        queue=PluginQueueSnapshot(),
    )
    assert completed["status"] == "ready"
    assert completed["effects"]["component_runtime"] == "stopped"
    assert completed["effects"]["queue_state"] == "drained"



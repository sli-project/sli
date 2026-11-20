"""Regression coverage for each guard outcome named in the ticket's
acceptance criteria - `_decide_plugin`/`_decide_normal` are the single place
both the CLI path (`main()`) and the batched cycle path (`evaluate_cycle`)
get their decision from, so testing them here covers both.
"""
from __future__ import annotations


def test_safe_to_launch_when_nothing_recorded_and_no_process_running() -> None:
    from scripts.maintenance.worker_guard import _decide_normal

    code, decision, extra = _decide_normal(
        "entity_state", pids=[], row=None, collection_block=None,
    )
    assert (code, decision) == (0, "safe_to_launch")
    assert extra["recorded_worker_id"] is None


def test_safe_to_restart_missing_worker_when_heartbeat_fresh_but_process_gone() -> None:
    from scripts.maintenance.worker_guard import _decide_normal

    row = ("worker-1", 4242, "running", 60, "2026-01-01", 30.0)
    code, decision, extra = _decide_normal(
        "entity_state", pids=[], row=row, collection_block=None,
    )
    assert (code, decision) == (0, "safe_to_restart_missing_worker")
    assert extra["recovery_reason"] == "recorded_process_absent_from_trusted_inventory"


def test_refused_worker_already_running_when_recorded_pid_matches_live_process() -> None:
    from scripts.maintenance.worker_guard import _decide_normal

    row = ("worker-1", 4242, "running", 60, "2026-01-01", 30.0)
    code, decision, extra = _decide_normal(
        "entity_state", pids=[4242], row=row, collection_block=None,
    )
    assert (code, decision) == (9, "refused_worker_already_running")
    assert extra["conflicting_pid"] == 4242


def test_refused_process_already_running_when_no_row_but_process_present() -> None:
    from scripts.maintenance.worker_guard import _decide_normal

    code, decision, extra = _decide_normal(
        "entity_state", pids=[555], row=None, collection_block=None,
    )
    assert (code, decision) == (9, "refused_process_already_running")
    assert extra["conflicting_pids"] == [555]


def test_refused_collection_block_active_for_collection_worker() -> None:
    from scripts.maintenance.worker_guard import _decide_normal

    block = (True, "manual_hold", "operator must clear the block")
    code, decision, extra = _decide_normal(
        "collection", pids=[], row=None, collection_block=block,
    )
    assert (code, decision) == (10, "refused_collection_block_active")
    assert extra["reason_code"] == "manual_hold"
    assert extra["operator_action"] == "operator must clear the block"


def test_safe_to_launch_plugin_component_when_admission_and_state_allow_it() -> None:
    from scripts.maintenance.worker_guard import _decide_plugin

    code, decision, extra = _decide_plugin(
        "radius-acquisition",
        pids=[],
        plugin_state=("enabled_manual", "running", "open"),
    )
    assert (code, decision) == (0, "safe_to_launch_plugin_component")
    assert extra["plugin_component_id"] == "radius-acquisition"


def test_refused_plugin_component_disabled_for_unrecognized_state() -> None:
    from scripts.maintenance.worker_guard import _decide_plugin

    code, decision, extra = _decide_plugin(
        "radius-acquisition", pids=[], plugin_state=("disabled", "stopped", "closed"),
    )
    assert (code, decision) == (10, "refused_plugin_component_disabled")


def test_session_observation_allows_draining_state_acquisition_does_not() -> None:
    from scripts.maintenance.worker_guard import _decide_plugin

    draining = ("disabled", "draining", "drain_only")
    observation_code, observation_decision, _ = _decide_plugin(
        "radius-session-observation", pids=[], plugin_state=draining,
    )
    acquisition_code, acquisition_decision, _ = _decide_plugin(
        "radius-acquisition", pids=[], plugin_state=draining,
    )
    assert (observation_code, observation_decision) == (0, "safe_to_launch_plugin_component")
    assert (acquisition_code, acquisition_decision) == (10, "refused_plugin_component_disabled")


def test_refused_plugin_component_recent_failure_backs_off_after_a_blocked_heartbeat(
    monkeypatch,
) -> None:
    from scripts.maintenance import worker_guard

    monkeypatch.setattr(
        worker_guard, "_recent_plugin_block",
        lambda component_id: {"heartbeat_age_seconds": 5, "retry_after_seconds": 1795, "phase": "cycle_failed"},
    )
    code, decision, extra = worker_guard._decide_plugin(
        "radius-acquisition",
        pids=[],
        plugin_state=("enabled_manual", "running", "open"),
    )
    assert (code, decision) == (10, "refused_plugin_component_recent_failure")
    assert extra["retry_after_seconds"] == 1795


def test_refused_process_inventory_unavailable_reported_by_evaluate_cycle() -> None:
    from scripts.maintenance import worker_guard

    def failing_inventory():
        return [], "process_inventory_failed:exit_1:access denied"

    results = worker_guard.evaluate_cycle(
        ["entity_state"], process_inventory=failing_inventory,
    )
    assert results["entity_state"]["decision"] == "refused_process_inventory_unavailable"
    assert results["entity_state"]["code"] == 1


def test_refused_dsn_missing_reported_by_evaluate_cycle(monkeypatch) -> None:
    from scripts.maintenance import worker_guard

    monkeypatch.setattr(worker_guard.os, "environ", {}, raising=False)
    monkeypatch.delenv("ADLOG_PG_DSN", raising=False)
    monkeypatch.setattr(
        worker_guard, "load_config",
        lambda: type("Cfg", (), {"postgres_dsn": ""})(),
    )

    results = worker_guard.evaluate_cycle(
        ["entity_state"], process_inventory=lambda: ([], None),
    )
    assert results["entity_state"]["decision"] == "refused_dsn_missing"
    assert results["entity_state"]["code"] == 1

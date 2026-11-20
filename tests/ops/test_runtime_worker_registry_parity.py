"""Regression guard: supervisor, guard and Operations must agree on the set
of runtime components. This is the test the ticket asks for explicitly - it
is not an sleep/wait or a heuristic, it is a set comparison against the one
canonical registry.
"""
from __future__ import annotations


def test_supervisor_guard_and_operations_share_the_same_worker_set() -> None:
    from scripts.maintenance import worker_guard, worker_supervisor
    from server.sli.ops import runtime_workers
    from server.sli.ops.runtime_component_registry import list_components

    registry_names = {c.name for c in list_components()}
    supervised_names = {c.name for c in list_components() if c.supervised}
    operations_registry_names = {
        c.name for c in list_components() if c.visible_in_operations
    }

    guard_names = {*worker_guard.WORKER_SCRIPTS, *worker_guard.PLUGIN_WORKERS}
    supervisor_names = set(worker_supervisor.MANAGED)
    operations_names = {name for name, _label in runtime_workers.WORKER_SPECS}

    assert guard_names == registry_names
    assert supervisor_names == supervised_names
    assert operations_names == operations_registry_names
    assert set(worker_supervisor.START_ORDER) == supervised_names


def test_both_radius_plugin_components_are_visible_in_operations() -> None:
    from server.sli.ops import runtime_workers

    names = {name for name, _label in runtime_workers.WORKER_SPECS}
    assert "plugin_radius_acquisition" in names
    assert "plugin_radius_session_observation" in names


def test_unused_rollback_workers_stay_guard_visible_but_are_hidden_from_operations() -> None:
    from scripts.maintenance import worker_guard, worker_supervisor
    from server.sli.ops import runtime_workers

    guard_names = {*worker_guard.WORKER_SCRIPTS, *worker_guard.PLUGIN_WORKERS}
    operations_names = {name for name, _label in runtime_workers.WORKER_SPECS}
    hidden = {
        "ad_context_snapshot",
        "ad_snapshot_projection",
        "computers_v5_snapshot",
        "computers_v6_source",
    }
    assert hidden <= guard_names
    assert not hidden & operations_names
    assert not hidden & set(worker_supervisor.MANAGED)
    assert not hidden & set(worker_supervisor.START_ORDER)


def test_semantic_production_is_managed_but_requires_admission(monkeypatch) -> None:
    from scripts.maintenance import worker_supervisor

    assert "semantic" in worker_supervisor.MANAGED
    assert "semantic" in worker_supervisor.START_ORDER
    monkeypatch.delenv("ADLOG_SEMANTIC_PRODUCTION_ENABLED", raising=False)
    assert not worker_supervisor.semantic_production_admitted()


def test_guard_workers_and_supervisor_managed_workers_match_apart_from_unsupervised() -> None:
    from scripts.maintenance import worker_guard, worker_supervisor
    from server.sli.ops.runtime_component_registry import list_components

    guard_names = {*worker_guard.WORKER_SCRIPTS, *worker_guard.PLUGIN_WORKERS}
    unsupervised_names = {component.name for component in list_components() if not component.supervised}
    assert guard_names - unsupervised_names == set(worker_supervisor.MANAGED)

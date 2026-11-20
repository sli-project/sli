from __future__ import annotations

from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
LEGACY_AD_WORKERS = frozenset(
    {
        "ad_context_snapshot",
        "ad_snapshot_projection",
        "computers_v5_snapshot",
        "computers_v6_source",
        "computers_v6_snapshot",
        "users_v2_snapshot",
    }
)
AD_RUNTIME_ENTRYPOINTS = {
    "ad_context_snapshot": "ad_context_snapshot_worker.py",
    "ad_snapshot_manifest_coordinator": "ad_snapshot_manifest_coordinator_worker.py",
    "ad_snapshot_projection": "ad_snapshot_projection_worker.py",
    "computers_v5_snapshot": "computers_report_v5_snapshot_worker.py",
    "computers_v6_snapshot": "computers_report_v6_snapshot_worker.py",
    "computers_v6_source": "computers_v6_source_worker.py",
    "users_v2_snapshot": "users_report_v2_snapshot_worker.py",
}
UNRELATED_SUPERVISED_ROOTS = frozenset(
    {
        "collection",
        "entity_state",
        "plugin_radius_acquisition",
        "plugin_radius_session_observation",
        "post_collection",
        "semantic",
        "storage_lifecycle",
        "what_where_when_projection",
    }
)


def test_e4_supervisor_starts_only_canonical_ad_worker_without_phase_drift() -> None:
    from scripts.maintenance import worker_supervisor
    from scripts.runtime import ad_snapshot_manifest_coordinator_worker as coordinator

    assert coordinator.SCHEDULE_TIMEZONE == "Asia/Novosibirsk"
    assert set(coordinator.SCHEDULE_LOCAL_HOURS) == {6, 18}
    assert worker_supervisor.MANAGED["ad_snapshot_manifest_coordinator"] == (
        "ad_snapshot_manifest_coordinator_worker.py",
        ["--no-initial-delay"],
    )
    assert worker_supervisor.START_ORDER == (
        "semantic",
        "storage_lifecycle",
        "entity_state",
        "what_where_when_projection",
        "post_collection",
        "collection",
        "ad_snapshot_manifest_coordinator",
        "plugin_radius_session_observation",
        "plugin_radius_acquisition",
    )
    assert not LEGACY_AD_WORKERS & set(worker_supervisor.MANAGED)


def test_e4_full_runtime_ad_entrypoint_inventory_is_canonical_or_retired() -> None:
    from scripts.maintenance import worker_supervisor
    from server.sli.ops.runtime_component_registry import list_components

    runtime_entrypoint_scripts = {
        path.name
        for path in (ROOT / "scripts" / "runtime").glob("*_worker.py")
        if path.name.startswith(("ad_", "computers_", "users_"))
    }
    components = {component.name: component for component in list_components()}

    assert runtime_entrypoint_scripts == set(AD_RUNTIME_ENTRYPOINTS.values())
    assert {
        name: components[name].script for name in AD_RUNTIME_ENTRYPOINTS
    } == AD_RUNTIME_ENTRYPOINTS
    assert components["ad_snapshot_manifest_coordinator"].feature_enabled
    assert components["ad_snapshot_manifest_coordinator"].supervised
    assert all(
        not components[name].feature_enabled and not components[name].supervised
        for name in LEGACY_AD_WORKERS
    )
    assert {
        name for name in worker_supervisor.MANAGED if name in AD_RUNTIME_ENTRYPOINTS
    } == {"ad_snapshot_manifest_coordinator"}
    assert UNRELATED_SUPERVISED_ROOTS <= set(worker_supervisor.MANAGED)
    assert UNRELATED_SUPERVISED_ROOTS <= set(worker_supervisor.START_ORDER)

    # `_start` looks up MANAGED before it can construct or spawn a process.
    # These calls therefore prove supervisor refusal without launching anything.
    for name in LEGACY_AD_WORKERS:
        with pytest.raises(KeyError):
            worker_supervisor._start(name)


def test_e4_supervisor_evaluation_never_addresses_retired_ad_workers(monkeypatch) -> None:
    from scripts.maintenance import worker_supervisor

    guarded: list[tuple[str, ...]] = []
    monkeypatch.setattr(
        worker_supervisor,
        "verify_collection_identity",
        lambda: {"status": "ok"},
    )
    monkeypatch.setattr(
        worker_supervisor.worker_guard,
        "evaluate_cycle",
        lambda names: guarded.append(tuple(names))
        or {name: {"code": 9, "decision": "healthy"} for name in names},
    )
    monkeypatch.setattr(worker_supervisor, "_log", lambda *_args, **_kwargs: None)

    result = worker_supervisor.evaluate_once()

    assert guarded == [tuple(worker_supervisor.MANAGED)]
    assert set(result["workers"]) == set(worker_supervisor.START_ORDER)
    assert not LEGACY_AD_WORKERS & set(result["workers"])

from copy import deepcopy
import json

import pytest

from scripts.runtime import ad_snapshot_manifest_coordinator_worker as coordinator
from server.ad_context import snapshot_manifest
from server.sli.core import job_queue
from server.sli.sources import ad_gpo_jobs, ad_snapshot_projection, plugin_state
from tests.migrations.test_ad_snapshot_rejected_blockers import SLOT, _descriptor
from tests.unit.test_ad_gpo_core_jobs import MANIFEST_ID, SnapshotConnection, job


@pytest.mark.parametrize("gpo_enabled", [False, True])
def test_legacy_cycle_publishes_and_replays_the_collected_composition(gpo_enabled):
    acquired = []
    stored = {}
    domain = {"id": 7, "sid": "S-1-5-21-1-2-3", "dns": "example.test"}

    def acquire(family):
        acquired.append(family)
        return {
            "bundle": {"run_id": f"00000000-0000-4000-8000-{len(acquired):012d}"},
            "base_complete": True, "computer_rows": [],
            "acquisition": {"profile": coordinator.BASE_PROFILE,
                            "user_full_queries": 1, "computer_full_queries": 1},
        }

    def publish(manifest):
        stored["manifest"] = deepcopy(manifest)
        return {"manifest_id": manifest["manifest_id"], "readback_verified": True}

    def import_gpo(bundle):
        assert gpo_enabled, "disabled GPO must not be imported"
        return _descriptor("gpo_v2", bundle["run_id"], "9")

    options = dict(
        slot_start_utc=SLOT, domain=domain, execute=True, gpo_enabled=gpo_enabled,
        acquire_ad_family=acquire,
        import_ad_family=lambda bundle, family: _descriptor(family, bundle["run_id"], "a"),
        persist_users=lambda _: _descriptor("users_v2", "121", "b"),
        persist_computers=lambda _: _descriptor(
            "computers_v6", "00000000-0000-4000-8000-000000000101", "c"),
        import_gpo=import_gpo, publish=publish,
        lookup_existing=lambda **_: stored.get("manifest"),
        resolve_existing_source=lambda member: {
            **member, "domain_id": 7, "domain_sid": domain["sid"],
            "domain_dns": domain["dns"], "import_state": "completed"},
        verify_existing_base=lambda _: {"usable": True},
    )
    result = coordinator.run_one_shot(**options)
    assert result["status"] == "published"
    assert result["coverage_state"] == "complete"
    expected = ["base_ad", "gpo"] if gpo_enabled else ["base_ad"]
    assert result["composition"] == {"version": 1, "parts": expected}
    assert ("ad_gpo_governance" in acquired) is gpo_enabled
    assert result["acquisition"]["gpo_v2_queries"] == int(gpo_enabled)
    # Same-slot replay retains the frozen composition even after a switch.
    acquired.clear()
    replay = coordinator.run_one_shot(**{**options, "gpo_enabled": not gpo_enabled})
    assert replay["status"] == "replayed_existing"
    assert replay["composition"] == result["composition"]
    assert acquired == []


@pytest.mark.parametrize("enabled,runtime,expected", [
    (False, "stopped", False), (True, "stopped", False), (True, "running", True),
])
def test_legacy_gpo_switch_uses_plugin_state(monkeypatch, enabled, runtime, expected):
    monkeypatch.setattr(ad_gpo_jobs, "allowed_plugins", lambda: frozenset({"sli.ad", "sli.gpo"}))
    monkeypatch.setattr(plugin_state, "list_plugin_states", lambda: [{
        "plugin_id": "sli.gpo", "enabled": enabled, "component_runtime": runtime,
    }])
    assert ad_gpo_jobs.gpo_snapshot_enabled() is expected


def test_legacy_gpo_switch_respects_disabled_core_jobs(monkeypatch):
    monkeypatch.setattr(ad_gpo_jobs, "allowed_plugins", lambda: frozenset({"sli.ad"}))
    monkeypatch.setattr(plugin_state, "list_plugin_states", lambda: pytest.fail("GPO is already off"))
    assert ad_gpo_jobs.gpo_snapshot_enabled() is False


def test_legacy_gpo_switch_preserves_unregistered_bundled_default(monkeypatch):
    monkeypatch.setattr(ad_gpo_jobs, "allowed_plugins", lambda: frozenset({"sli.ad", "sli.gpo"}))
    monkeypatch.setattr(plugin_state, "list_plugin_states", lambda: [])
    assert ad_gpo_jobs.gpo_snapshot_enabled() is True


def test_base_only_manifest_publishes_core_and_legacy_outputs_without_gpo(monkeypatch):
    monkeypatch.setattr(ad_gpo_jobs, "allowed_plugins", lambda: frozenset({"sli.ad"}))
    legacy = SnapshotConnection()
    legacy.manifest["members"] = [
        row for row in legacy.manifest["members"] if row["family"] != "gpo_v2"]
    core = SnapshotConnection()
    core.manifest = deepcopy(legacy.manifest)
    result = ad_snapshot_projection.run_exact_manifest_projection_cycle(
        legacy, manifest_id=MANIFEST_ID, worker_id="synthetic-legacy")
    assert result["status"] == "completed"
    assert "ad.gpo.v2" not in legacy.outputs
    spec = job()
    staged = ad_gpo_jobs.stage(core, spec)
    assert staged["composition"] == {"version": 1, "parts": ["base_ad"]}
    assert job_queue.publish(core, spec, staged, ad_gpo_jobs.apply) == "committed"
    assert core.outputs["ad.state"] == legacy.outputs["ad.state"]
    assert core.outputs["ad.state"]["payload_json"]["composition"] == staged["composition"]
    assert core.receipts["ad.state"]["status"] == "completed"
    assert core.receipts["ad.gpo.v2"]["status"] == "pending"
    saved_result = json.loads(core.calls[-1][1][-1])
    assert saved_result["composition"] == staged["composition"]


def test_composition_is_derived_from_frozen_members():
    assert snapshot_manifest.snapshot_composition({"members": {
        "ad_context_base": {}, "computers_v6": {}, "gpo_v2": {},
    }}) == {"version": 1, "parts": ["base_ad", "gpo"]}


def test_gpo_job_is_blocked_for_a_base_only_manifest():
    connection = SnapshotConnection()
    connection.manifest["members"] = [
        row for row in connection.manifest["members"] if row["family"] != "gpo_v2"]
    result = ad_gpo_jobs.stage(connection, job("gpo-snapshot"))
    assert result["status"] == "blocked"
    assert result["error_code"] == "snapshot_part_not_collected"
    assert connection.outputs == {}


def test_changed_composition_is_rejected_before_core_publication():
    connection = SnapshotConnection()
    spec = job()
    staged = ad_gpo_jobs.stage(connection, spec)
    staged["composition"] = {"version": 1, "parts": ["base_ad"]}
    with pytest.raises(ValueError, match="snapshot_result_changed"):
        job_queue.publish(connection, spec, staged, ad_gpo_jobs.apply)
    assert connection.outputs == {}

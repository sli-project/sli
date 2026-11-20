"""Stage 17: cross-plugin admission stops new output and keeps immutable history."""
from copy import deepcopy
from dataclasses import asdict
import json

import pytest

from server.sli.core.job_registry import validate_shape
from server.sli.plugins import registry, update_runtime
from server.sli.plugins.sigma import registration
from server.sli.sigma import plugin_dependencies as dependencies
from server.sli.sigma.detection_input import load_detection_match
from tests.unit.test_sigma_process_chain import Archive, Cursor, evaluate, fixture


@pytest.fixture(autouse=True)
def isolated_packages(monkeypatch):
    monkeypatch.delenv("SLI_PLUGIN_RUNTIME_DIR", raising=False)
    monkeypatch.delenv("SLI_PLUGIN_LOCK_DIR", raising=False)
    monkeypatch.setattr(update_runtime, "_pinned", {})
    registry.registered_plugins.cache_clear()
    yield
    registry.registered_plugins.cache_clear()


def test_registration_declares_only_draft_candidates_and_no_work(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("registration must not start work or connect to a database")

    monkeypatch.setattr("server.sli.core.postgres_runtime_pipeline.connect", forbidden)
    monkeypatch.setattr("subprocess.Popen", forbidden)
    monkeypatch.setattr("threading.Thread.start", forbidden)
    contribution = registry.Contributions()
    registration.register(contribution)
    assert set(contribution.hooks) == {
        "health", "semantic_capabilities", "chain_candidates", "evaluate_process_chain",
    }
    assert contribution.jobs == {}
    assert contribution.hooks["health"]() is True
    assert contribution.hooks["semantic_capabilities"]() == {"sli.sigma.detection-match.v1": "1.0.0"}
    assert contribution.hooks["chain_candidates"]() == ({
        "chain_id": "sli.sigma.process.confirmed_end", "chain_version": 1, "lifecycle_state": "draft",
    },)
    assert registry.plugin_installed("sli.sigma")


def test_manifest_declares_required_dependency_and_reviewed_hooks_pin_capabilities():
    schema = json.loads((registry.ROOT / "config/plugin_architecture_v3.json").read_text("utf-8"))
    for plugin_id, contract_id, version in dependencies.REQUIREMENTS:
        manifest = json.loads((registry.ROOT / f"config/plugin_packages/v3/{plugin_id}.json").read_text("utf-8"))
        validate_shape(manifest, schema, schema)
        assert registry.plugin_hook(plugin_id, "semantic_capabilities")()[contract_id] == version
        if plugin_id == "sli.sigma":
            assert contract_id in manifest["capabilities"]
            assert manifest["dependencies"] == [dependencies.NATIVE_DEPENDENCY]
            assert not manifest["sources"] and not manifest["schedules"] and not manifest["handlers"]


@pytest.mark.parametrize("plugin_id", ["sli.ad", "sli.sigma"])
@pytest.mark.parametrize("mode", ["test", "shadow", "enabled"])
@pytest.mark.parametrize("transition", ["missing", "uninstall", "deactivate", "drain", "version", "unconfigured"])
def test_missing_or_inactive_dependency_blocks_new_output_and_preserves_history(plugin_id, mode, transition):
    rows, item = fixture(mode=mode)
    cur, archive = Cursor(rows, (item,)), Archive(rows)
    prior, = evaluate(rows, (item,), cursor=cur, archive=archive).results
    retained = asdict(prior)
    sources_before, matches_before = deepcopy(cur.sources), deepcopy(cur.matches)
    state = cur.plugin_states[plugin_id]
    if transition == "missing":
        cur.plugin_states.pop(plugin_id)
    elif transition == "uninstall":
        state.update(installed=False, enabled=False, component_runtime="stopped")
    elif transition == "deactivate":
        state.update(enabled=False, component_runtime="stopped")
    elif transition == "drain":
        state.update(component_runtime="draining")
    elif transition == "version":
        state.update(package_version="2.0.0")
    else:
        state.update(configured=False)
    cur.calls.clear()
    archive.calls.clear()
    blocked = evaluate(rows, (item,), cursor=cur, archive=archive)
    assert blocked.state == "blocked"
    assert blocked.results == blocked.unmatched_match_ids == blocked.late_match_ids == ()
    assert blocked.blocked_match_ids == (item.match_id,)
    blocker, = blocked.blockers
    assert blocker.plugin_id == plugin_id
    assert blocker.reason == {
        "missing": "plugin_not_installed", "uninstall": "plugin_not_installed",
        "deactivate": "plugin_inactive", "drain": "plugin_inactive",
        "version": "plugin_version_unavailable", "unconfigured": "plugin_not_configured",
    }[transition]
    assert cur.calls == [("select * from public.read_sigma_chain_plugin_states_v1()", ())]
    assert archive.calls == []
    # The normal historical reader is independent of chain admission.
    assert load_detection_match(cur, match_id=item.match_id) == item
    assert cur.sources == sources_before and cur.matches == matches_before
    assert asdict(prior) == retained


@pytest.mark.parametrize("plugin_id", ["sli.ad", "sli.sigma"])
@pytest.mark.parametrize("absent", ["manifest", "entry"])
def test_physical_package_removal_is_seen_even_after_registry_was_cached(monkeypatch, plugin_id, absent):
    from pathlib import Path

    rows, item = fixture()
    cur, archive = Cursor(rows, (item,)), Archive(rows)
    assert registry.plugin_installed(plugin_id)
    real_is_file = Path.is_file
    path = (registry.ROOT / f"config/plugin_packages/v3/{plugin_id}.json" if absent == "manifest"
            else registry.ROOT / Path(*registry.BUNDLED[plugin_id].split(".")).with_suffix(".py"))
    monkeypatch.setattr(Path, "is_file", lambda value: False if value == path else real_is_file(value))
    result = evaluate(rows, (item,), cursor=cur, archive=archive)
    assert result.state == "blocked" and result.blockers[0].reason == "plugin_not_installed"
    assert cur.calls == archive.calls == []


@pytest.mark.parametrize("plugin_id", ["sli.ad", "sli.sigma"])
def test_updater_fence_blocks_chain_before_source_reads(monkeypatch, plugin_id):
    rows, item = fixture()
    cur, archive = Cursor(rows, (item,)), Archive(rows)
    monkeypatch.setattr(update_runtime, "fenced", lambda value: value == plugin_id)
    blocked = evaluate(rows, (item,), cursor=cur, archive=archive)
    assert blocked.state == "blocked" and blocked.blockers[0].reason == "plugin_update_draining"
    assert cur.calls == archive.calls == []


@pytest.mark.parametrize("capabilities", [{}, {"sli.ad.process-episode.v1": "2.0.0"}])
def test_wrong_or_missing_capability_is_blocked(monkeypatch, capabilities):
    rows, item = fixture()
    cur = Cursor(rows, (item,))
    real_hook = registry.plugin_hook
    monkeypatch.setattr(registry, "plugin_hook", lambda plugin, name: (
        (lambda: capabilities) if plugin == "sli.ad" else real_hook(plugin, name)))
    blocked = evaluate(rows, (item,), cursor=cur)
    assert blocked.state == "blocked" and blocked.blockers[0].reason == "plugin_capability_unavailable"
    assert cur.calls == []


def test_explicit_reactivation_replays_same_result_without_changing_prior_identity():
    rows, item = fixture()
    cur = Cursor(rows, (item,))
    original = evaluate(rows, (item,), cursor=cur)
    cur.plugin_states["sli.ad"].update(enabled=False, component_runtime="stopped")
    assert evaluate(rows, (item,), cursor=cur).state == "blocked"
    cur.plugin_states["sli.ad"].update(enabled=True, component_runtime="running")
    replay = evaluate(rows, (item,), cursor=cur)
    assert replay.state == "completed" and replay == original


def test_registered_hook_uses_same_gate_and_does_not_bypass_missing_dependency():
    from server.sli.sigma.process_chain import ProcessChainRule
    from tests.unit.test_sigma_process_chain import NOW, SCOPE, reference

    rows, item = fixture()
    cur = Cursor(rows, (item,))
    cur.plugin_states.pop("sli.ad")
    result = registry.call_plugin("sli.sigma", "evaluate_process_chain", cur,
        rule=ProcessChainRule(execution_sha256=item.execution_sha256, scope=SCOPE, evaluation_mode="test"),
        match_ids=(item.match_id,), source_refs=tuple(reference(row) for row in rows),
        archive=Archive(rows), watermark=NOW)
    assert result.state == "blocked" and result.results == ()

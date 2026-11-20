from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from server.sli.sources.plugin_isolation_fixture import (
    PluginIsolationFixture,
    PluginIsolationFixtureError,
    load_isolation_fixture,
)


ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "config" / "stage10_plugin_isolation_fixture_v1.json"


def _config() -> dict:
    return json.loads(CONFIG.read_text(encoding="utf-8"))


def test_fixture_is_explicitly_source_process_and_db_free() -> None:
    value = load_isolation_fixture()
    assert value["fixture_only"] is True
    assert value["runtime_enabled"] is False
    assert value["source_contact_allowed"] is False
    assert value["database_access_allowed"] is False
    assert value["process_control_allowed"] is False
    assert value["architecture_decision_id"] == "sli.plugin-architecture.v2"


@pytest.mark.parametrize(
    "action",
    ["disable", "inject_failure", "inject_resource_exhaustion"],
)
def test_target_failure_or_stop_does_not_change_peer_or_core(action: str) -> None:
    model = PluginIsolationFixture(_config())
    before = model.snapshot()
    getattr(model, action)("sli.remote-access")
    after = model.snapshot()
    assert after["core"] == before["core"]
    assert after["plugins"]["sli.windows.ad-dc"] == before["plugins"]["sli.windows.ad-dc"]


def test_upgrade_requires_disabled_drained_state_and_rolls_back_exactly() -> None:
    model = PluginIsolationFixture(_config())
    with pytest.raises(
        PluginIsolationFixtureError,
        match="upgrade_requires_disabled_drained_plugin",
    ):
        model.upgrade("sli.remote-access", "1.1.0-fixture")
    model.disable("sli.remote-access")
    model.upgrade("sli.remote-access", "1.1.0-fixture")
    assert model.snapshot()["plugins"]["sli.remote-access"]["package_version"] == "1.1.0-fixture"
    model.rollback("sli.remote-access")
    assert model.snapshot()["plugins"]["sli.remote-access"]["package_version"] == "1.0.0-fixture"


def test_detach_requires_parity_and_preserves_evidence() -> None:
    config = _config()
    config["plugins"][0]["read_report_parity"] = False
    model = PluginIsolationFixture(config)
    model.disable("sli.remote-access")
    with pytest.raises(PluginIsolationFixtureError, match="detach_preconditions_not_met"):
        model.detach("sli.remote-access")

    model = PluginIsolationFixture(_config())
    before = model.snapshot()["plugins"]["sli.remote-access"]["immutable_evidence_refs"]
    model.disable("sli.remote-access")
    model.detach("sli.remote-access")
    after = model.snapshot()["plugins"]["sli.remote-access"]
    assert after["immutable_evidence_refs"] == before
    assert after["dataset_state"] == "retained_read_only_fixture"


def test_cutover_is_only_a_nonexecuting_plan_and_requires_parity() -> None:
    model = PluginIsolationFixture(_config())
    assert model.plan_ownership_cutover("sli.remote-access") == {
        "eligible": True,
        "executed": False,
        "production_read_path_cutover": False,
    }
    config = _config()
    config["plugins"][0]["read_report_parity"] = False
    with pytest.raises(PluginIsolationFixtureError, match="read_report_parity_required"):
        PluginIsolationFixture(config).plan_ownership_cutover("sli.remote-access")


def test_fixture_cannot_claim_real_version_or_runtime(tmp_path: Path) -> None:
    value = deepcopy(_config())
    value["plugins"][0]["package_version"] = "1.0.0"
    path = tmp_path / "fixture.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(PluginIsolationFixtureError, match="version_invalid"):
        load_isolation_fixture(path)



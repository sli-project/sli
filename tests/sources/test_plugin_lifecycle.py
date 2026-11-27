from __future__ import annotations

from dataclasses import replace

import pytest

from deploy.linux.sli_core.plugin_lifecycle import (
    PluginLifecycleError,
    execute_plugin_lifecycle,
    initial_remote_access_state,
    load_plugin_lifecycle_contract,
    plan_plugin_lifecycle,
)


CAPS = {"plugins.manage"}


def test_contract_is_source_only_and_cannot_execute() -> None:
    contract = load_plugin_lifecycle_contract()
    assert contract["install_semantics"] == "register_bundled_release_manifest_only"
    assert contract["capability_registered"] is True
    assert contract["mutation_execution_enabled"] is True
    assert contract["executable_actions"] == ["install"]
    assert contract["process_control_allowed"] is False
    assert contract["database_mutation_allowed"] is False
    assert contract["source_contact_allowed"] is False
    assert contract["autostart_enabled"] is False
    assert contract["destructive_purge_allowed"] is False


def test_install_is_only_bundled_manifest_registration_plan() -> None:
    state = initial_remote_access_state()
    plan = plan_plugin_lifecycle(
        action="install", state=state, actor_capabilities=CAPS
    )
    assert plan["preconditions_met"] is True
    assert plan["execution_allowed"] is True
    assert plan["effects"] == {"package_lifecycle": "registered"}
    assert plan["target_version"] == "0.1.0"
    assert "dynamic_external_package_execution" in plan["forbidden_effects"]
    assert plan["audit_event"]["action_key"] == "plugin.install"


def test_enable_requires_all_independent_live_boundaries() -> None:
    state = replace(
        initial_remote_access_state(), package_lifecycle="registered"
    )
    blocked = plan_plugin_lifecycle(
        action="enable", state=state, actor_capabilities=CAPS
    )
    assert "enable_live_boundaries_not_accepted" in blocked["blockers"]
    contract = load_plugin_lifecycle_contract()
    accepted = replace(
        state,
        accepted_live_boundaries=tuple(contract["required_live_boundaries"]),
    )
    planned = plan_plugin_lifecycle(
        action="enable", state=accepted, actor_capabilities=CAPS
    )
    assert planned["preconditions_met"] is True
    assert planned["effects"] == {"desired_activation": "enabled_manual"}
    assert planned["execution_allowed"] is False


def test_disable_does_not_detach_purge_or_delete_evidence() -> None:
    state = replace(
        initial_remote_access_state(), package_lifecycle="registered",
        desired_activation="enabled_manual",
    )
    plan = plan_plugin_lifecycle(
        action="disable", state=state, actor_capabilities=CAPS
    )
    assert plan["preconditions_met"] is True
    assert plan["effects"] == {
        "desired_activation": "disabled",
        "observed_health": "unknown",
    }
    assert plan["preserve_immutable_evidence"] is True
    assert plan["destructive_purge"] is False
    assert "package_lifecycle" not in plan["effects"]


def test_detach_requires_reader_parity_and_preserves_results() -> None:
    state = replace(
        initial_remote_access_state(), package_lifecycle="registered"
    )
    blocked = plan_plugin_lifecycle(
        action="detach", state=state, actor_capabilities=CAPS
    )
    assert "detach_reader_and_parity_required" in blocked["blockers"]
    ready = replace(state, detach_reader_ready=True, read_report_parity=True)
    plan = plan_plugin_lifecycle(
        action="detach", state=ready, actor_capabilities=CAPS
    )
    assert plan["preconditions_met"] is True
    assert plan["effects"]["package_lifecycle"] == "detached"
    assert plan["production_read_path_cutover"] is False
    assert plan["preserve_immutable_evidence"] is True


def test_confirmation_is_bound_to_revision_action_and_effects() -> None:
    state = initial_remote_access_state()
    install = plan_plugin_lifecycle(
        action="install", state=state, actor_capabilities=CAPS
    )
    later = plan_plugin_lifecycle(
        action="install", state=replace(state, revision=2),
        actor_capabilities=CAPS,
    )
    assert install["confirmation"] != later["confirmation"]
    assert install["plan_sha256"] != later["plan_sha256"]


def test_missing_capability_is_visible_and_execution_always_fails_closed() -> None:
    plan = plan_plugin_lifecycle(
        action="install", state=initial_remote_access_state(),
        actor_capabilities=set(),
    )
    assert "plugins_manage_required" in plan["blockers"]
    with pytest.raises(PluginLifecycleError, match="confirmation_invalid"):
        execute_plugin_lifecycle(plan=plan, confirmation="wrong")
    with pytest.raises(PluginLifecycleError, match="execution_disabled"):
        execute_plugin_lifecycle(plan=plan, confirmation=plan["confirmation"])



from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from server.sli.sources.plugin_resource_profiles import (
    PluginResourceProfileError,
    project_resource_profile_status,
    validate_resource_profile_registry,
)


ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "config" / "stage10_plugin_resource_profiles_v1.json"


def _registry():
    return json.loads(CONFIG.read_text(encoding="utf-8"))


def test_registry_is_source_only_and_has_no_false_normal_profile():
    result = validate_resource_profile_registry(_registry())
    assert result["profile_count"] == 1
    assert result["long_lived_normal_profile_defined"] is False
    assert result["runtime_enabled"] is False


def test_manual_profile_projects_declared_limits_and_missing_hard_limits():
    profile = _registry()["profiles"][0]
    projection = project_resource_profile_status(profile)
    assert projection["plugin_id"] == "sli.remote-access"
    assert projection["source_pack_id"] == "sli.windows.vpn-radius"
    assert projection["activation_state"] == "disabled"
    assert projection["reason"] is None
    assert projection["declared_limits"]["records_per_run"] == {
        "value": 1000,
        "unit": "records",
    }
    assert projection["ready_for_long_lived_worker"] is False
    assert projection["missing_hard_limits"] == [
        "cpu_hard_limit",
        "job_object_kill_on_close",
        "memory_bytes",
        "network_allowlist_enforced",
        "pids",
        "working_directory_acl",
    ]


def test_active_temporary_profile_requires_visible_reason():
    profile = deepcopy(_registry()["profiles"][0])
    profile["activation_state"] = "enabled"
    with pytest.raises(
        PluginResourceProfileError,
        match="active_temporary_profile_reason_required",
    ):
        project_resource_profile_status(profile)
    assert project_resource_profile_status(
        profile, reason="bounded diagnostic run"
    )["reason"] == "bounded diagnostic run"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda profile: profile["application_limits"].append(
            deepcopy(profile["application_limits"][0])
        ),
        lambda profile: profile["hard_process_limits"].pop("pids"),
        lambda profile: profile.update(mode="unknown"),
        lambda profile: profile["application_limits"][0].update(value=0),
        lambda profile: profile.pop("source_pack_id"),
    ],
)
def test_invalid_or_ambiguous_profile_fails_closed(mutation):
    value = _registry()
    mutation(value["profiles"][0])
    with pytest.raises(PluginResourceProfileError):
        validate_resource_profile_registry(value)



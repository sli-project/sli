from __future__ import annotations

from server.sli.sources.source_onboarding import plan_dc_onboarding


def test_dc_onboarding_preflight_is_valid_and_side_effect_free() -> None:
    plan = plan_dc_onboarding(
        {
            "hostname": "DC3",
            "connect_address": "192.0.2.11",
            "channels": ["Security", "System"],
        },
        existing_hostnames=("DC1", "DC2"),
    )

    assert plan.valid is True
    assert plan.source_pack_id == "sli.windows.ad-dc"
    assert plan.adapter_id == "windows-eventlog-pywin32"
    assert plan.public_dict()["api_version"] == "v1"
    assert plan.public_dict()["network_actions"] == []
    assert plan.public_dict()["database_actions"] == []
    assert plan.public_dict()["collection_actions"] == []


def test_dc_onboarding_preflight_rejects_duplicate_unknown_channel_and_unsafe_address() -> None:
    plan = plan_dc_onboarding(
        {
            "hostname": "DC1",
            "connect_address": "https://not-a-controller",
            "channels": ["Security", "Untrusted/Other"],
            "adapter_id": "made-up-adapter",
        },
        existing_hostnames=("dc1",),
    )

    assert plan.valid is False
    assert {issue.code for issue in plan.issues} == {
        "duplicate_hostname",
        "invalid_connect_address",
        "unsupported_channel",
        "unsupported_adapter",
        "unknown_adapter",
    }


def test_dc_onboarding_preflight_requires_explicit_channels() -> None:
    plan = plan_dc_onboarding({"hostname": "DC3", "connect_address": "dc3.example.test"})

    assert plan.valid is False
    assert [issue.code for issue in plan.issues] == ["missing_channels"]


def test_preflight_api_is_admin_only_and_never_enters_mutation_routing() -> None:
    source = __import__("pathlib").Path("server/api/routes/operations.py").read_text(encoding="utf-8")
    route = source[source.index('if path == "/api/v1/source-onboarding/preflight"'):source.index("def _handle_source_packs_api")]
    handler = source[source.index("def _handle_source_onboarding_preflight"):source.index("def _handle_v1_operation_source_api")]
    assert "_handle_source_onboarding_preflight(handler)" in route
    assert 'handler._require_access("admin")' in handler
    assert "get_configured_domain_controller_targets()" in handler
    assert "plan_dc_onboarding" in handler

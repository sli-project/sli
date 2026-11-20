from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from server.sli.events.event_catalog import all_event_catalog_entries
from server.sli.sources.plugin_compatibility_registration import (
    DATASET_REPORT_PARITY_PATH,
    REGISTRATION_PATH,
    CompatibilityRegistrationError,
    build_ad_dc_adapter_worker_parity_evidence,
    build_ad_dc_compatibility_evidence,
    build_ad_dc_dataset_report_parity_evidence,
    build_ad_dc_source_pack_parity_evidence,
    load_ad_dc_compatibility_registration,
    load_ad_dc_dataset_report_parity,
    validate_ad_dc_compatibility_registration,
    validate_ad_dc_dataset_report_parity,
)
from server.source_packs.registry import resolve_source_pack


def _raw_registration() -> dict:
    return json.loads(REGISTRATION_PATH.read_text(encoding="utf-8"))


def _raw_dataset_report_parity() -> dict:
    return json.loads(DATASET_REPORT_PARITY_PATH.read_text(encoding="utf-8"))


def test_registration_binds_existing_source_packs_without_execution_change() -> None:
    registration = load_ad_dc_compatibility_registration()
    assert registration.plugin_id == "sli.windows.ad-dc"
    assert registration.mode == "compatibility_only"
    assert registration.source_pack_ids == (
        "sli.windows.ad-dc",
        "sli.windows.ad-context",
    )
    assert registration.state["component_runtime"] == "core_owned_final"
    assert (
        registration.ownership["warm_authentication_session"]
        == "core_hosted_compatibility"
    )
    assert registration.public_dict()["execution_changed"] is False


def test_registration_does_not_change_existing_event_routing() -> None:
    before_ad = resolve_source_pack(
        "Security",
        "Microsoft-Windows-Security-Auditing",
        "4624",
    )
    before_radius = resolve_source_pack(
        "Security",
        "Microsoft-Windows-Security-Auditing",
        "6272",
    )
    load_ad_dc_compatibility_registration()
    after_ad = resolve_source_pack(
        "Security",
        "Microsoft-Windows-Security-Auditing",
        "4624",
    )
    after_radius = resolve_source_pack(
        "Security",
        "Microsoft-Windows-Security-Auditing",
        "6272",
    )
    assert before_ad == after_ad
    assert before_radius == after_radius
    assert after_ad is not None and after_ad.pack_id == "sli.windows.ad-dc"
    assert (
        after_radius is not None
        and after_radius.pack_id == "sli.windows.vpn-radius"
    )


@pytest.mark.parametrize(
    "change_key",
    [
        "source_contact",
        "cursor",
        "database",
        "runtime_activation",
        "autostart",
        "access",
        "product_runtime_ownership",
    ],
)
def test_registration_rejects_every_execution_change(change_key: str) -> None:
    value = _raw_registration()
    value["changes"][change_key] = True
    with pytest.raises(
        CompatibilityRegistrationError,
        match="compatibility_registration_changes_execution",
    ):
        validate_ad_dc_compatibility_registration(value)


def test_registration_declares_ownership_decision_as_core_owned_final() -> None:
    value = _raw_registration()
    assert value["ownership_decision"]["model"] == "core_owned_final"
    assert value["ownership_decision"]["decision_basis"]
    assert value["ownership_decision"]["decision_date"]
    assert value["ownership_decision"]["rationale"]
    registration = load_ad_dc_compatibility_registration()
    assert registration.state["component_runtime"] == "core_owned_final"


def test_registration_rejects_missing_or_wrong_ownership_decision() -> None:
    value = _raw_registration()
    value["ownership_decision"]["model"] = "plugin_owned"
    with pytest.raises(
        CompatibilityRegistrationError,
        match="compatibility_model_must_equal_core_owned_final",
    ):
        validate_ad_dc_compatibility_registration(value)


def test_registration_marks_strangler_steps_unauthorized() -> None:
    value = _raw_registration()
    assert value["potential_strangler_steps"] == [
        "source_pack_parity",
        "dataset_and_report_parity",
        "adapter_parity",
        "worker_parity",
        "separate_read_path_cutover_decision",
    ]
    assert value["strangler_steps_authorized"] is False
    value["strangler_steps_authorized"] = True
    with pytest.raises(
        CompatibilityRegistrationError,
        match="compatibility_strangler_steps_authorized_must_equal_False",
    ):
        validate_ad_dc_compatibility_registration(value)


def test_registration_rejects_pack_hash_drift() -> None:
    value = _raw_registration()
    value["source_packs"][0]["manifest_sha256"] = "0" * 64
    with pytest.raises(
        CompatibilityRegistrationError,
        match="compatibility_source_pack_hash_drift",
    ):
        validate_ad_dc_compatibility_registration(value)


def test_registration_rejects_warm_storage_ownership_transfer() -> None:
    value = deepcopy(_raw_registration())
    value["ownership"]["warm_authentication_session"] = "plugin_owned"
    with pytest.raises(
        CompatibilityRegistrationError,
        match="compatibility_warm_authentication_session",
    ):
        validate_ad_dc_compatibility_registration(value)


def test_evidence_is_payload_free_and_stops_before_parity() -> None:
    evidence = build_ad_dc_compatibility_evidence()
    assert evidence["status"] == "accepted_source_only"
    assert evidence["source_contact"] is False
    assert evidence["database_changed"] is False
    assert evidence["cursor_changed"] is False
    assert evidence["runtime_changed"] is False
    assert evidence["autostart_changed"] is False
    assert evidence["access_changed"] is False
    assert (
        evidence["next_gate"]
        == "source_pack_parity_without_runtime_ownership_transfer"
    )


def test_source_pack_parity_covers_every_exact_catalog_identity() -> None:
    evidence = build_ad_dc_source_pack_parity_evidence()
    event_pack = evidence["event_pack"]
    expected_catalog_count = len(all_event_catalog_entries())
    assert event_pack["catalog_entry_count"] == expected_catalog_count
    assert event_pack["exact_route_count"] == expected_catalog_count
    assert event_pack["normalizer_resolution_count"] == expected_catalog_count
    assert set(event_pack["channel_counts"]) == {
        "Security",
        "System",
        "Directory Service",
        "DNS Server",
        "Microsoft-Windows-PowerShell/Operational",
        "Microsoft-Windows-TaskScheduler/Operational",
    }


def test_source_pack_parity_matches_context_worker_and_execution_wiring() -> None:
    evidence = build_ad_dc_source_pack_parity_evidence()
    assert evidence["context_pack"]["sections"] == [
        "privileged_membership",
        "directory_accounts",
        "directory_group_graph",
        "directory_exact_logon",
        "vpn_membership",
        "gpo_governance",
        "domain_posture",
        "domain_health",
    ]
    assert (
        evidence["context_pack"]["sections"]
        == evidence["context_pack"]["worker_sections"]
    )
    assert all(evidence["execution_wiring"].values())
    assert evidence["source_contact"] is False
    assert evidence["runtime_changed"] is False
    assert (
        evidence["next_gate"]
        == "dataset_and_report_parity_without_read_path_cutover"
    )


def test_dataset_report_parity_registration_is_exact_and_source_only() -> None:
    parity = load_ad_dc_dataset_report_parity()
    assert parity.registration_id == "sli.stage9.ad-dc.compatibility.v1"
    assert [item.dataset_key for item in parity.contracts] == [
        "ad.audit.snapshot",
        "ad.accounts.privileged",
        "ad.accounts.vpn",
        "ad.gpo.governance",
    ]
    assert [item.report_key for item in parity.contracts] == [
        "ad.state",
        "ad.privileged",
        "vpn.audit",
        "ad.gpo.review",
    ]


@pytest.mark.parametrize(
    "change_key",
    [
        "source_contact",
        "database",
        "migration",
        "runtime_activation",
        "autostart",
        "access_assignment",
        "report_publication",
        "frontend",
        "read_path_cutover",
        "product_runtime_ownership",
    ],
)
def test_dataset_report_parity_rejects_execution_change(change_key: str) -> None:
    value = _raw_dataset_report_parity()
    value["changes"][change_key] = True
    with pytest.raises(
        CompatibilityRegistrationError,
        match="dataset_report_parity_changes_execution",
    ):
        validate_ad_dc_dataset_report_parity(value)


def test_dataset_report_parity_rejects_route_or_identity_drift() -> None:
    value = _raw_dataset_report_parity()
    value["contracts"][2]["target_path"] = "/reports/vpn"
    with pytest.raises(
        CompatibilityRegistrationError,
        match="dataset_report_parity_contract_identity_or_order_invalid",
    ):
        validate_ad_dc_dataset_report_parity(value)


def test_dataset_report_parity_covers_runtime_access_routes_and_frontend() -> None:
    evidence = build_ad_dc_dataset_report_parity_evidence()
    assert evidence["status"] == "accepted_source_contract_parity"
    assert evidence["production_state_asserted"] is False
    assert evidence["read_path_cutover"] is False
    assert evidence["source_contact"] is False
    assert evidence["database_changed"] is False
    assert evidence["context_pack_sections"] == [
        "privileged_membership",
        "directory_accounts",
        "directory_group_graph",
        "directory_exact_logon",
        "vpn_membership",
        "gpo_governance",
        "domain_posture",
        "domain_health",
    ]
    assert len(evidence["contracts"]) == 4
    for contract in evidence["contracts"]:
        assert contract["runtime_query_branch"] is True
        assert contract["registry_definition"] is True
        assert contract["workspace_columns"] is True
        assert contract["route_migration"] is True
        assert contract["access_scope_declarations"] >= 2
        assert contract["frontend_consumer"] is True
        assert contract["scope_kinds"] == ["all", "server", "domain"]
    assert (
        evidence["next_gate"]
        == "adapter_and_worker_parity_without_read_path_cutover"
    )


@pytest.mark.parametrize(
    ("relative_path", "marker", "error_code"),
    [
        (
            "server/sli/plugins/remote_access/reports/accounts_dataset.py",
            marker,
            "runtime_source_mismatch",
        )
        for marker in (
            "relation.source_section='vpn_membership'",
            "privileged.source_section='privileged_membership'",
            "{_src.VPN_ACCOUNT_ATTRIBUTES_LATERAL}",
        )
    ] + [
        (
            "server/sli/reporting/reporting_v4.py",
            '"sli.remote-access", "accounts_dataset",',
            "runtime_reader_wiring_missing",
        ),
        (
            "server/sli/plugins/remote_access/registration.py",
            '"accounts_dataset": _deferred(',
            "runtime_reader_wiring_missing",
        ),
        (
            "server/sli/plugins/remote_access/registration.py",
            '"read_accounts"',
            "runtime_reader_wiring_missing",
        ),
        (
            "server/sli/plugins/remote_access/reports/accounts_dataset.py",
            "def read_accounts(",
            "runtime_reader_missing",
        ),
    ],
)
def test_dataset_report_parity_rejects_plugin_reader_drift(
    monkeypatch, relative_path: str, marker: str, error_code: str,
) -> None:
    from server.sli.sources import plugin_compatibility_registration as registration

    target_path = registration.ROOT / relative_path
    read_text = Path.read_text

    def read_with_reader_drift(path: Path, *args, **kwargs) -> str:
        source = read_text(path, *args, **kwargs)
        if path == target_path:
            assert marker in source
            # Leave summary SQL intact: it must not hide a broken dataset reader.
            replacement = (
                marker.replace("accounts", "unwired_accounts")
                if "accounts" in marker else "unwired"
            )
            return source.replace(marker, replacement, 1)
        return source

    monkeypatch.setattr(Path, "read_text", read_with_reader_drift)
    with pytest.raises(
        CompatibilityRegistrationError,
        match=f"dataset_report_parity_{error_code}:ad.accounts.vpn",
    ):
        build_ad_dc_dataset_report_parity_evidence()


def test_literal_inspector_resolves_only_prior_literal_symbols(tmp_path) -> None:
    from server.sli.sources.plugin_compatibility_registration import (
        _literal_assignment_value,
    )

    accepted = tmp_path / "accepted.py"
    accepted.write_text(
        'FRAGMENT = "safe"\nTARGET = {"field": FRAGMENT}\n', encoding="utf-8"
    )
    assert _literal_assignment_value(accepted, "TARGET") == {"field": "safe"}

    rejected = tmp_path / "rejected.py"
    rejected.write_text(
        'TARGET = {"field": build_dynamic_value()}\n', encoding="utf-8"
    )
    with pytest.raises(
        CompatibilityRegistrationError,
        match="compatibility_literal_assignment_invalid",
    ):
        _literal_assignment_value(rejected, "TARGET")


def test_adapter_worker_parity_uses_only_allowlisted_existing_components() -> None:
    evidence = build_ad_dc_adapter_worker_parity_evidence()
    assert evidence["status"] == "accepted_adapter_and_worker_source_parity"
    assert evidence["source_contact"] is False
    assert evidence["database_changed"] is False
    assert evidence["runtime_started"] is False
    assert evidence["autostart_changed"] is False
    assert evidence["ownership_transferred"] is False
    assert evidence["read_path_cutover"] is False
    assert [
        item["adapter_id"] for item in evidence["adapter_parity"]["items"]
    ] == [
        "windows-eventlog-pywin32",
        "windows-eventlog-powershell",
        "ad-context-powershell",
    ]
    assert all(
        item["allowlisted_for_pack"]
        for item in evidence["adapter_parity"]["items"]
    )
    assert [item["role"] for item in evidence["worker_parity"]["items"]] == [
        "event_collection",
        "ad_context_snapshot",
        "core_post_collection",
        "core_entity_state",
    ]
    assert all(
        item["manual_once_supported"]
        and item["process_lock_present"]
        and item["heartbeat_present"]
        and not item["runtime_started"]
        for item in evidence["worker_parity"]["items"]
    )
    assert evidence["next_gate"] == "separate_read_path_cutover_decision"


@pytest.mark.parametrize(
    "missing_marker",
    ["snapshot_packet(bundle,", "import_snapshot_packet("],
)
def test_adapter_worker_parity_rejects_missing_snapshot_packet_wiring(
    monkeypatch, missing_marker: str,
) -> None:
    from server.sli.sources import plugin_compatibility_registration as registration

    worker_path = (
        registration.ROOT / "scripts/runtime/ad_context_snapshot_worker.py"
    )
    read_text = Path.read_text

    def read_without_packet_step(path: Path, *args, **kwargs) -> str:
        source = read_text(path, *args, **kwargs)
        if path == worker_path:
            assert missing_marker in source
            return source.replace(missing_marker, "unwired(")
        return source

    monkeypatch.setattr(Path, "read_text", read_without_packet_step)
    with pytest.raises(
        CompatibilityRegistrationError,
        match=(
            "adapter_worker_parity_worker_wiring_missing:"
            "scripts/runtime/ad_context_snapshot_worker.py"
        ),
    ):
        build_ad_dc_adapter_worker_parity_evidence()

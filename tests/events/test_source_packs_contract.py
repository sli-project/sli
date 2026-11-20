from __future__ import annotations

from server.sli.events.event_catalog import lookup_event_catalog
from server.source_packs.registry import (
    canonical_manifest_sha256,
    catalog_paths_for_event,
    get_source_pack,
    list_source_packs,
    resolve_source_pack,
    source_pack_metadata_for_channels,
    resolve_source_normalizer,
    validate_adapter_for_channels,
    validate_adapter_for_pack,
)
from server.source_packs.adapters import (
    AD_CONTEXT_POWERSHELL,
    WINDOWS_EVENTLOG_POWERSHELL,
    WINDOWS_EVENTLOG_PYTHON,
    AdContextRequest,
    WindowsEventLogRequest,
    adapter_id_for_backend,
    build_windows_eventlog_command,
    build_ad_context_command,
    get_source_adapter,
    list_source_adapters,
)
from pathlib import Path
import os
import pytest
from server.sli.semantic.event_card_semantics import build_event_card


def test_manifest_hash_is_stable_across_checkout_line_endings() -> None:
    lf = b'{\n  "schema_version": 1\n}\n'
    crlf = lf.replace(b"\n", b"\r\n")

    assert canonical_manifest_sha256(lf) == canonical_manifest_sha256(crlf)


def test_builtin_dc_pack_declares_existing_channels_and_safe_adapters():
    pack = get_source_pack("sli.windows.ad-dc")
    assert pack is not None
    assert "Security" in pack.channels
    assert "Microsoft-Windows-TaskScheduler/Operational" in pack.channels
    assert set(pack.adapters) == {"windows-eventlog-pywin32", "windows-eventlog-powershell"}
    assert pack.catalog_path.name == "event_catalog.json"
    assert len(pack.manifest_sha256) == 64
    assert pack.source_kind == "event"
    assert pack.normalizer_id == "windows-ad-dc-v1"
    assert pack.sections == ()
    assert pack.public_dict() in list_source_packs()


def test_builtin_ad_context_pack_is_context_only_and_allowlisted():
    pack = get_source_pack("sli.windows.ad-context")
    assert pack is not None
    assert pack.source_kind == "context"
    assert pack.version == "0.10.0"
    assert pack.channels == ()
    assert pack.sections == (
        "privileged_membership",
        "directory_accounts",
        "directory_group_graph",
        "directory_exact_logon",
        "vpn_membership",
        "gpo_governance",
        "domain_posture",
        "domain_health",
    )
    assert pack.catalog_path is None
    assert validate_adapter_for_pack(AD_CONTEXT_POWERSHELL, pack.pack_id)["pack_id"] == pack.pack_id


def test_bundled_adapter_registry_has_no_dynamic_adapter_loading():
    adapters = list_source_adapters()
    assert {item["adapter_id"] for item in adapters} == {
        WINDOWS_EVENTLOG_PYTHON, WINDOWS_EVENTLOG_POWERSHELL, AD_CONTEXT_POWERSHELL
    }
    assert get_source_adapter(WINDOWS_EVENTLOG_PYTHON).output_contract == "normalized-event-jsonl-v1"
    assert get_source_adapter("untrusted-module") is None


def test_source_adapter_api_is_an_authenticated_it_operations_surface() -> None:
    source = Path("server/api/http_server.py").read_text(encoding="utf-8")
    route_source = Path("server/api/routes/operations.py").read_text(encoding="utf-8")
    assert '"/api/v1/source-adapters"' in source
    assert 'if path == "/api/v1/source-adapters":' in route_source
    assert "SourceAdaptersResponse(items=list_source_adapters())" in route_source


def test_every_current_dc_channel_resolves_to_one_pack_and_each_declared_adapter():
    pack = get_source_pack("sli.windows.ad-dc")
    assert pack is not None
    assert len(pack.channels) == 6
    for channel in pack.channels:
        assert resolve_source_pack(channel) == pack
        for adapter in pack.adapters:
            assert validate_adapter_for_channels(adapter, [channel])[0]["pack_id"] == pack.pack_id


def test_dc_pack_provider_resolution_is_exact_when_provider_is_available() -> None:
    pack = get_source_pack("sli.windows.ad-dc")
    assert pack is not None
    assert (
        resolve_source_pack(
            "Security",
            "Microsoft-Windows-Security-Auditing",
        )
        == pack
    )
    assert resolve_source_pack("System", "Unrelated-Provider") is None
    assert resolve_source_normalizer("System", "Unrelated-Provider") is None


def test_dc_catalog_is_resolved_through_pack_without_changing_event_semantics():
    pack = resolve_source_pack("Microsoft-Windows-TaskScheduler/Operational", "Microsoft-Windows-TaskScheduler")
    assert pack is not None
    assert pack.pack_id == "sli.windows.ad-dc"
    assert catalog_paths_for_event("Security")[0] == pack.catalog_path
    event = lookup_event_catalog(140, "Microsoft-Windows-TaskScheduler/Operational", "Microsoft-Windows-TaskScheduler")
    assert event is not None
    assert event["card"]["action"] == "Изменено задание планировщика Windows"


def test_unknown_channel_has_no_pack_but_keeps_legacy_catalog_fallback():
    assert resolve_source_pack("Unrelated/Channel") is None
    paths = catalog_paths_for_event("Unrelated/Channel")
    assert len(paths) == 1
    assert paths[0].name == "event_catalog.json"


def test_collection_metadata_is_declarative_and_groups_dc_channels_once():
    metadata = source_pack_metadata_for_channels(["Security", "System", "Unrelated/Channel"])
    assert [item["pack_id"] for item in metadata] == [
        "sli.windows.ad-dc",
        "sli.windows.vpn-radius",
        "sli.windows.workstations",
    ]
    assert metadata[0] == {
        "pack_id": "sli.windows.ad-dc",
        "version": "1.4.0",
        "display_name": "Windows Active Directory Domain Controller",
        "source_kind": "event",
        "channels": [
            "Security",
            "System",
            "Directory Service",
            "DNS Server",
            "Microsoft-Windows-PowerShell/Operational",
            "Microsoft-Windows-TaskScheduler/Operational",
        ],
        "sections": [],
        "adapters": ["windows-eventlog-pywin32", "windows-eventlog-powershell"],
        "entity_contract": "catalog-field-roles-v1",
        "analysis_contract": "catalog-semantics-v1",
        "normalizer": "windows-ad-dc-v1",
        "manifest_sha256": metadata[0]["manifest_sha256"],
    }
    assert metadata[1] == {
        "pack_id": "sli.windows.vpn-radius",
        "version": "0.1.0",
        "display_name": "Windows NPS and VPN/RADIUS",
        "source_kind": "event",
        "channels": ["Security"],
        "sections": [],
        "adapters": ["windows-eventlog-pywin32", "windows-eventlog-powershell"],
        "entity_contract": "identity-ladder-v1",
        "analysis_contract": "radius-authentication-observation-v1",
        "normalizer": "windows-nps-radius-v1",
        "manifest_sha256": metadata[1]["manifest_sha256"],
    }


def test_dc_pack_resolves_only_its_allowlisted_normalizer() -> None:
    normalizer = resolve_source_normalizer("Security")
    assert normalizer is not None
    assert normalizer.normalizer_id == "windows-ad-dc-v1"
    assert resolve_source_normalizer("Unrelated/Channel") is None


def test_declared_dc_adapters_are_validated_before_collection_command():
    metadata = validate_adapter_for_channels(WINDOWS_EVENTLOG_PYTHON, ["Security", "System"])
    assert metadata[0]["pack_id"] == "sli.windows.ad-dc"
    try:
        validate_adapter_for_channels("not-a-dc-adapter", ["Security"])
    except ValueError as exc:
        assert "sli.windows.ad-dc" in str(exc)
    else:  # pragma: no cover - the assertion above must fail closed.
        raise AssertionError("undeclared adapter must be rejected for a claimed channel")


@pytest.mark.parametrize("adapter_id", [WINDOWS_EVENTLOG_PYTHON, WINDOWS_EVENTLOG_POWERSHELL])
def test_packet_only_pack_keeps_event_ownership_without_claiming_dc_collection(adapter_id):
    pack = get_source_pack("sli.windows.file-audit")
    assert pack is not None
    assert pack.adapters == ()
    assert resolve_source_pack("Security", "Microsoft-Windows-Security-Auditing", "4663") == pack
    metadata = source_pack_metadata_for_channels(["Security", "System", "Security"])
    assert [item["pack_id"] for item in metadata] == [
        "sli.windows.ad-dc",
        "sli.windows.vpn-radius",
        "sli.windows.workstations",
    ]
    assert validate_adapter_for_channels(adapter_id, ["Security", "System"]) == metadata
    with pytest.raises(ValueError, match="not declared by source pack sli.windows.file-audit"):
        validate_adapter_for_pack(adapter_id, pack.pack_id)


def test_windows_eventlog_adapter_preserves_backend_specific_boolean_contract():
    request = WindowsEventLogRequest(
        backend="powershell", python_executable="python", python_script=Path("collect.py"),
        powershell_script=Path("collect.ps1"), computer_name="192.0.2.1", source_name="DC1",
        hours=1, max_events_per_channel=50000, channel_timeout_seconds=300, output_root=Path("raw"),
        channels=("Security", "System"), collection_mode="current", collect_message=False,
        channel_limits={}, channel_timeouts={}, start_time_utc=None, channel_start_times={}, channel_after_record_ids={},
    )
    command = build_windows_eventlog_command(request)
    assert "-CollectMessage:$false" in command
    channels_index = command.index("-Channels")
    assert command[channels_index + 1] == "Security,System"
    assert command.count("-Channels") == 1
    assert adapter_id_for_backend("powershell") == WINDOWS_EVENTLOG_POWERSHELL
    assert adapter_id_for_backend("python") == WINDOWS_EVENTLOG_PYTHON


def test_ad_context_command_uses_only_repository_script_and_builds_no_process():
    powershell = (
        str(Path(os.environ.get("WINDIR") or r"C:\Windows") / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe")
        if os.name == "nt" else "/usr/bin/pwsh"
    )
    request = AdContextRequest(
        powershell_executable=powershell,
        output_path=Path("bundle.json"),
        run_id="00000000-0000-4000-8000-000000000046",
        directory_server="dc1.host13.example.invalid",
        search_base="DC=example,DC=local",
        domain="host13.example.invalid",
        sections=("privileged_membership",),
        privileged_groups=("S-1-5-21-100000003-200000003-300000003-512",),
    )
    command = build_ad_context_command(request)
    script = Path(command[command.index("-File") + 1])
    assert script.name == "Export-AdContextBundle.ps1"
    assert script.is_file()
    assert "dc1.host13.example.invalid" == command[command.index("-DirectoryServer") + 1]
    assert "S-1-5-21-100000003-200000003-300000003-512" == command[command.index("-PrivilegedGroups") + 1]
    assert "2000" == command[command.index("-MaxRecords") + 1]
    try:
        build_ad_context_command(AdContextRequest(**{**request.__dict__, "powershell_executable": "evil.exe"}))
    except ValueError as exc:
        assert "allowlisted" in str(exc)
    else:
        raise AssertionError("unknown executable must be rejected")


def test_directory_context_command_keeps_technical_inventory_in_same_bounded_contour():
    powershell = (
        str(Path(os.environ.get("WINDIR") or r"C:\Windows") / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe")
        if os.name == "nt" else "/usr/bin/pwsh"
    )
    command = build_ad_context_command(AdContextRequest(
        powershell_executable=powershell,
        output_path=Path("bundle.json"),
        run_id="00000000-0000-4000-8000-000000000047",
        directory_server="dc1.host13.example.invalid",
        search_base="DC=example,DC=local",
        domain="host13.example.invalid",
        sections=("directory_accounts",),
        technical_servers=("DC1", "DC2"),
        technical_inventory_timeout_seconds=20,
    ))

    assert command[command.index("-TechnicalServers") + 1] == "DC1,DC2"
    assert command[command.index("-TechnicalInventoryTimeoutSeconds") + 1] == "20"


def test_dc_event_card_exposes_pack_provenance_without_changing_analyst_meaning():
    card = build_event_card({
        "event_id": 140,
        "channel": "Microsoft-Windows-TaskScheduler/Operational",
        "provider_name": "Microsoft-Windows-TaskScheduler",
        "server": "DC1",
        "event_data": {"TaskName": "\\Microsoft\\Windows\\Example", "UserName": "DOMAIN\\DC1$"},
    })
    assert card["title"] == "Изменено задание планировщика Windows"
    assert card["source_pack"]["pack_id"] == "sli.windows.ad-dc"

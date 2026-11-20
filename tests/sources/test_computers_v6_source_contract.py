from __future__ import annotations

import copy
import hashlib
import importlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
ADAPTER = ROOT / "scripts/ad_context/Export-ComputersV6ReferenceSnapshot.ps1"
REFERENCE = (
    ROOT
    / "scripts/ad_context/collect_ad_inventory_evidence.ps1"
)
def _source_api():
    path = ROOT / "server/sli/sources/computers_v6_source.py"
    assert path.is_file(), "V6 source snapshot parser is missing"
    return importlib.import_module("server.sli.sources.computers_v6_source")


def _source_state(
    name: str,
    status: str = "observed",
    *,
    value=None,
    observed_at: str | None = "2026-08-30T01:05:00Z",
    error=None,
    details=None,
) -> dict:
    return {
        "status": status,
        "source": name,
        "value": value,
        "observed_at": observed_at,
        "error": error,
        "details": details,
    }


def _production_snapshot() -> dict:
    source_names = (
        "ad",
        "dns",
        "os",
        "site",
        "last_logon_timestamp",
        "exact_last_logon",
        "dc_events",
    )
    sources = {name: _source_state(name) for name in source_names}
    sources["ad"]["value"] = None
    sources["dns"]["value"] = {"ipv4": ["10.0.0.10"], "ipv6": []}
    sources["os"]["value"] = {
        "name": "Windows Server 2022 Standard",
        "version": "10.0 (20348)",
        "service_pack": "",
    }
    sources["site"]["value"] = "HQ"
    sources["last_logon_timestamp"]["value"] = "2026-08-29T12:00:00Z"
    sources["exact_last_logon"]["value"] = "2026-08-29T12:30:00Z"
    sources["dc_events"] = _source_state(
        "dc_events", "not_collected", observed_at=None
    )
    return {
        "schema_version": "2.0",
        "metadata": {
            "snapshot_id": "00000000-0000-4000-8000-000000000114",
            "label": "AD inventory 2026-08-30 01:10:00 UTC",
            "started_at": "2026-08-30T01:00:00Z",
            "completed_at": "2026-08-30T01:10:00Z",
            "query_dc": "dc01.example.test",
            "domain": "example.test",
            "search_base": None,
            "collection_status": "complete",
            "object_count": 1,
            "collector_version": "evidence-collector-1.0",
            "sources": [
                {
                    "name": name,
                    "status": state["status"],
                    "requested": name != "dc_events",
                    "counts": {state["status"]: 1},
                }
                for name, state in sources.items()
            ],
            "errors": [],
        },
        "objects": [
            {
                "id": "00000000-0000-4000-8000-000000000001",
                "objectGuid": "00000000-0000-4000-8000-000000000001",
                "name": "APP-01",
                "dnsHostName": "app-01.example.test",
                "enabled": True,
                "deviceType": "server",
                "classification": {
                    "status": "observed",
                    "value": "server",
                    "rule_id": "device-classification/os-server-v1",
                    "evidence": ["OperatingSystem contains Server"],
                },
                "ipv4s": ["10.0.0.10"],
                "ipv6s": [],
                "osName": "Windows Server 2022 Standard",
                "osVersion": "10.0 (20348)",
                "osBuild": "20348",
                "osFamily": "Windows Server 2022",
                "servicePack": "",
                "ou": "Servers",
                "distinguishedName": "CN=APP-01,OU=Servers,DC=example,DC=test",
                "canonicalName": "example.test/Servers/APP-01",
                "domain": "example.test",
                "adSite": "HQ",
                "lastLogonTimestamp": "2026-08-29T12:00:00Z",
                "exactLastLogon": "2026-08-29T12:30:00Z",
                "eventLastSeen": None,
                "passwordLastSet": "2026-07-01T00:00:00Z",
                "whenCreated": "2025-01-01T00:00:00Z",
                "whenChanged": "2026-08-29T00:00:00Z",
                "description": "Application server",
                "location": "Datacenter",
                "managedBy": None,
                "sid": "S-1-5-21-1-2-3-1001",
                "userAccountControl": 4096,
                "spns": ["HOST/app-01.example.test"],
                "trustedForDelegation": False,
                "trustedToAuthForDelegation": False,
                "roleHint": "Сервер",
                "roleEvidence": "OperatingSystem contains Server",
                "collectedAt": "2026-08-30T01:05:00Z",
                "queryDc": "dc01.example.test",
                "collectorVersion": "evidence-collector-1.0",
                "sources": sources,
                "collectionErrors": [],
            }
        ],
    }


def _c008() -> None:
    api = _source_api()
    accepted = api.validate_computers_v6_snapshot(_production_snapshot())
    assert accepted["metadata"]["object_count"] == 1

    demo = _production_snapshot()
    demo["metadata"]["snapshot_id"] = "demo-current-20260830"
    demo["metadata"]["collector_version"] = "evidence-collector-demo-1.0"
    with pytest.raises(api.ComputersV6SourceContractError, match="demo"):
        api.validate_computers_v6_snapshot(demo)

    mismatched = _production_snapshot()
    mismatched["metadata"]["object_count"] = 2
    with pytest.raises(api.ComputersV6SourceContractError, match="object_count"):
        api.validate_computers_v6_snapshot(mismatched)


def _c068() -> None:
    api = _source_api()
    expected = {"status", "source", "value", "observed_at", "error", "details"}
    assert set(api.SOURCE_STATE_FIELDS) == expected
    accepted = api.validate_computers_v6_snapshot(_production_snapshot())
    for source_state in accepted["objects"][0]["sources"].values():
        assert expected.issubset(source_state)

    incomplete = _production_snapshot()
    del incomplete["objects"][0]["sources"]["dns"]["details"]
    with pytest.raises(api.ComputersV6SourceContractError, match="source_state_fields"):
        api.validate_computers_v6_snapshot(incomplete)


def _with_site_state(
    status: str,
    *,
    value=None,
    observed_at: str | None = "2026-08-30T01:05:00Z",
    error=None,
    details=None,
    requested: bool = True,
) -> dict:
    snapshot = _production_snapshot()
    snapshot["objects"][0]["sources"]["site"] = _source_state(
        "site",
        status,
        value=value,
        observed_at=observed_at,
        error=error,
        details=details,
    )
    stage = next(
        source
        for source in snapshot["metadata"]["sources"]
        if source["name"] == "site"
    )
    stage.update(status=status, requested=requested, counts={status: 1})
    if status not in {"observed", "not_collected", "not_applicable"}:
        snapshot["metadata"]["collection_status"] = "partial"
    return snapshot


def _error(status: str) -> list[dict]:
    return [
        {
            "source": "site",
            "status": status,
            "code": f"site_{status}",
            "message": f"site {status}",
            "target": "example.test",
        }
    ]


def _c069() -> None:
    api = _source_api()
    assert api.SOURCE_STATUS_MEANINGS["observed"] == (
        "source successfully produced an observation"
    )
    missing_time = _with_site_state("observed", value="HQ", observed_at=None)
    with pytest.raises(api.ComputersV6SourceContractError, match="observed_at"):
        api.validate_computers_v6_snapshot(missing_time)


def _c070() -> None:
    api = _source_api()
    assert "explicitly not queried" in api.SOURCE_STATUS_MEANINGS["not_collected"]
    skipped = _with_site_state(
        "not_collected", observed_at=None, requested=False
    )
    api.validate_computers_v6_snapshot(skipped)
    skipped["objects"][0]["sources"]["site"]["value"] = "HQ"
    with pytest.raises(api.ComputersV6SourceContractError, match="not_collected"):
        api.validate_computers_v6_snapshot(skipped)


def _c071() -> None:
    api = _source_api()
    assert "prerequisite" in api.SOURCE_STATUS_MEANINGS["not_evaluated"]
    blocked = _with_site_state(
        "not_evaluated",
        details={
            "reason": "no_ipv4_for_site_mapping",
            "dependency": "dns",
            "dependency_status": "no_record",
        },
    )
    api.validate_computers_v6_snapshot(blocked)
    blocked["objects"][0]["sources"]["site"]["details"] = None
    with pytest.raises(api.ComputersV6SourceContractError, match="details"):
        api.validate_computers_v6_snapshot(blocked)


def _c072() -> None:
    api = _source_api()
    assert "field was absent" in api.SOURCE_STATUS_MEANINGS["missing_in_source"]
    missing = _with_site_state(
        "missing_in_source", details={"missing_field": "site"}
    )
    api.validate_computers_v6_snapshot(missing)
    missing["objects"][0]["sources"]["site"]["observed_at"] = None
    with pytest.raises(api.ComputersV6SourceContractError, match="observed_at"):
        api.validate_computers_v6_snapshot(missing)


def _c073() -> None:
    api = _source_api()
    assert "no matching record" in api.SOURCE_STATUS_MEANINGS["no_record"]
    no_record = _with_site_state(
        "no_record", details={"reason": "no_matching_ad_subnet"}
    )
    api.validate_computers_v6_snapshot(no_record)
    no_record["objects"][0]["sources"]["site"]["observed_at"] = None
    with pytest.raises(api.ComputersV6SourceContractError, match="observed_at"):
        api.validate_computers_v6_snapshot(no_record)


def _c074() -> None:
    api = _source_api()
    assert "part of the required result" in api.SOURCE_STATUS_MEANINGS["partial"]
    partial = _with_site_state(
        "partial",
        value="HQ",
        error=_error("failed"),
        details={"queried": 1, "failed": 1},
    )
    api.validate_computers_v6_snapshot(partial)
    partial["objects"][0]["sources"]["site"]["details"] = None
    with pytest.raises(api.ComputersV6SourceContractError, match="details"):
        api.validate_computers_v6_snapshot(partial)


def _assert_error_status(clause_status: str) -> None:
    api = _source_api()
    failed = _with_site_state(clause_status, error=_error(clause_status))
    api.validate_computers_v6_snapshot(failed)
    failed["objects"][0]["sources"]["site"]["error"] = None
    with pytest.raises(api.ComputersV6SourceContractError, match="error"):
        api.validate_computers_v6_snapshot(failed)


def _c075() -> None:
    api = _source_api()
    assert api.SOURCE_STATUS_MEANINGS["failed"] == "source operation failed"
    _assert_error_status("failed")


def _c076() -> None:
    api = _source_api()
    assert "access was denied" in api.SOURCE_STATUS_MEANINGS["access_denied"]
    _assert_error_status("access_denied")


def _c077() -> None:
    api = _source_api()
    assert "could not be converted" in api.SOURCE_STATUS_MEANINGS["parse_error"]
    _assert_error_status("parse_error")


def _c078() -> None:
    api = _source_api()
    assert "inapplicable" in api.SOURCE_STATUS_MEANINGS["not_applicable"]
    inapplicable = _with_site_state(
        "not_applicable",
        observed_at=None,
        details={"reason": "source_not_applicable"},
    )
    api.validate_computers_v6_snapshot(inapplicable)


def _c079() -> None:
    api = _source_api()
    assert set(api.NON_HEALTHY_SOURCE_STATUSES) == (
        set(api.SOURCE_STATUS_MEANINGS) - {"observed"}
    )
    assert api.source_is_healthy("observed") is True
    for status in api.NON_HEALTHY_SOURCE_STATUSES:
        assert api.source_is_healthy(status) is False


def _c080() -> None:
    api = _source_api()
    state = _source_state("site", "not_collected", observed_at=None)
    assert api.is_source_quality_issue(state, requested=True) is True
    assert api.is_source_quality_issue(state, requested=False) is False
    failed = _source_state("site", "failed", error=_error("failed"))
    assert api.is_source_quality_issue(failed, requested=False) is True


def _c081() -> None:
    api = _source_api()
    assert tuple(api.QUALITY_CATEGORIES) == (
        "source_error",
        "not_collected",
        "not_evaluated",
        "no_record_or_missing_source",
        "partial",
        "missing_field",
    )
    expected = {
        "failed": "source_error",
        "access_denied": "source_error",
        "parse_error": "source_error",
        "not_collected": "not_collected",
        "not_evaluated": "not_evaluated",
        "no_record": "no_record_or_missing_source",
        "missing_in_source": "no_record_or_missing_source",
        "partial": "partial",
    }
    for status, category in expected.items():
        assert api.quality_category_for_source_state(status, requested=True) == category
    assert api.quality_category_for_source_state("observed", requested=True) is None
    assert api.quality_category_for_source_state("not_applicable", requested=True) is None
    assert api.quality_category_for_source_state("not_collected", requested=False) is None


def _c082() -> None:
    api = _source_api()
    item = copy.deepcopy(_production_snapshot()["objects"][0])
    assert api.missing_required_object_fields(item) == []
    item["osName"] = None
    item["dnsHostName"] = ""
    item["distinguishedName"] = None
    item["eventLastSeen"] = None
    item["exactLastLogon"] = None
    item["lastLogonTimestamp"] = None
    assert api.missing_required_object_fields(item) == [
        "osName",
        "dnsHostName",
        "lastObserved",
        "distinguishedName",
    ]


def _adapter_text() -> str:
    assert ADAPTER.is_file(), "V6 production source adapter is missing"
    return ADAPTER.read_text(encoding="utf-8")


def _reference_text() -> str:
    assert REFERENCE.is_file(), "approved Computers reference collector is missing"
    return REFERENCE.read_text(encoding="utf-8")


def _function(text: str, name: str, next_name: str | None = None) -> str:
    start = text.index(f"function {name}")
    if next_name is None:
        return text[start:]
    return text[start : text.index(f"function {next_name}", start)]


def _c097() -> None:
    adapter = _adapter_text()
    reference = _reference_text()
    assert adapter.startswith("#requires -Version 5.1")
    pinned_hash_match = re.search(
        r"(?m)^\$ApprovedReferenceSha256 = '([0-9a-f]{64})'$", adapter
    )
    assert pinned_hash_match is not None, "approved reference hash pin is missing"
    actual_reference_hash = hashlib.sha256(REFERENCE.read_bytes()).hexdigest()
    assert pinned_hash_match.group(1) == actual_reference_hash
    assert "collect_ad_inventory_evidence.ps1" in adapter
    assert "[IO.File]::ReadAllText($ReferenceCollector" in adapter
    assert "[ScriptBlock]::Create($ReferenceSource)" in adapter
    assert "& $ReferenceScript @ForwardParameters" in adapter
    forbidden = re.compile(
        r"\b(?:Set|Remove|Add|Move|Rename|Enable|Disable)-AD[A-Za-z]+\b"
        r"|\bInvoke-Command\b|\bEnter-PSSession\b|\bRestart-Computer\b"
        r"|\bStop-Computer\b|\bSet-DnsServer[A-Za-z]+\b",
        re.IGNORECASE,
    )
    assert forbidden.search(adapter) is None
    assert forbidden.search(reference) is None
    assert "ConvertTo-Json" in reference
    assert "Set-Content -LiteralPath $OutputPath" in reference


def _c098() -> None:
    adapter = _adapter_text()
    param_block = adapter.split("param(", 1)[1].split("\n)", 1)[0]
    for parameter in (
        "$Server",
        "$SearchBase",
        "$OutputPath",
        "$SkipDns",
        "$CollectAdSite",
        "$CollectExactLastLogon",
    ):
        assert parameter in param_block
        assert f"'{parameter[1:]}'" in adapter


def _c099() -> None:
    text = _reference_text()
    properties = text.split("$Properties = @(", 1)[1].split("\n)", 1)[0]
    for property_name in (
        "Enabled",
        "DNSHostName",
        "OperatingSystem",
        "OperatingSystemVersion",
        "OperatingSystemServicePack",
        "LastLogonDate",
        "lastLogonTimestamp",
        "PasswordLastSet",
        "whenCreated",
        "whenChanged",
        "Description",
        "Location",
        "ManagedBy",
        "CanonicalName",
        "DistinguishedName",
        "ServicePrincipalName",
        "userAccountControl",
        "TrustedForDelegation",
        "TrustedToAuthForDelegation",
        "ObjectGUID",
        "SID",
    ):
        assert f"'{property_name}'" in properties
    assert "$QueryParameters.SearchBase = $SearchBase" in text
    assert "$Computers = @(Get-ADComputer @QueryParameters)" in text


def _c100() -> None:
    text = _reference_text()
    state = _function(text, "New-SourceState", "New-CollectionError")
    for field in ("status", "source", "value", "observed_at", "error", "details"):
        assert re.search(rf"(?m)^\s*{field}\s*=", state)
    for field in (
        "schema_version",
        "metadata",
        "snapshot_id",
        "collection_status",
        "object_count",
        "collector_version",
        "sources",
        "errors",
        "objects",
        "collectionErrors",
        "classification",
    ):
        assert field in text


def _c101() -> None:
    text = _function(
        _reference_text(), "Resolve-ComputerAddresses", "Convert-IPv4ToUInt32"
    )
    assert "if ($SkipDns)" in text
    assert "-Status 'not_collected' -Source 'dns'" in text
    assert "missing_field = 'DNSHostName'" in text
    assert "resolve_dns_name_not_available" in text


def _c102() -> None:
    text = _function(
        _reference_text(), "Resolve-ComputerAddresses", "Convert-IPv4ToUInt32"
    )
    assert "foreach ($QueryType in @('A', 'AAAA'))" in text
    assert "$IPv4 | Sort-Object -Unique" in text
    assert "$IPv6 | Sort-Object -Unique" in text
    for status in ("observed", "partial", "no_record"):
        assert f"-Status '{status}' -Source 'dns'" in text
    assert "Get-AggregateErrorStatus" in text


def _c103() -> None:
    text = _reference_text()
    matcher = _function(text, "Get-IPv4SubnetMatch", "Get-OuPath")
    assert "Sort-Object PrefixLength -Descending" in matcher
    assert "if ($CollectAdSite)" in text
    assert "Get-ADReplicationSubnet" in text
    assert "$Match.PrefixLength -gt $BestMatch.PrefixLength" in text


def _c104() -> None:
    text = _reference_text()
    for token in (
        "dependency_status = [string]$DnsResult.State.status",
        "reason = 'no_matching_ad_subnet'",
        "$SiteStageError.status",
    ):
        assert token in text
    assert "-Status 'not_evaluated' -Source 'site'" in text
    assert "-Status 'no_record' -Source 'site'" in text


def _c105() -> None:
    text = _function(_reference_text(), "Get-ExactLastLogonMap", None)
    assert "foreach ($Dc in $DomainControllers)" in text
    assert "Properties = @('lastLogon', 'ObjectGUID')" in text
    assert "([string]$Row.ObjectGUID).ToLowerInvariant()" in text
    assert "$FileTime -gt $Result[$Key].MaxFileTime" in text
    assert "if ($CollectExactLastLogon)" in text


def _c106() -> None:
    text = _reference_text()
    assert "$ExactData.SuccessfulDcs.Count -lt $ExactData.TotalDc" in text
    assert "-Status 'partial' -Source 'exact_last_logon'" in text
    assert "-Status 'observed' -Source 'exact_last_logon'" in text
    for detail in ("queried_dc", "total_dc", "failed_dc", "max_dc"):
        assert detail in text


def _c107() -> None:
    text = _function(
        _reference_text(), "Get-DeviceClassification", "Get-ExactLastLogonMap"
    )
    dc = text.index("$DomainControllerNames.Contains")
    server_os = text.index("$OperatingSystem -match '(?i)\\bserver\\b'")
    client_os = text.index("$OperatingSystem -match '(?i)windows")
    assert dc < server_os < client_os


def _c108() -> None:
    text = _function(
        _reference_text(), "Get-DeviceClassification", "Get-ExactLastLogonMap"
    )
    spn_branch = (
        text.split("if ($SpnText", 1)[1]
        .split("return [pscustomobject]@{", 1)[1]
        .split("    }", 1)[0]
    )
    assert "value   = 'unknown'" in spn_branch
    assert "status  = 'partial'" in spn_branch
    assert "value   = 'unknown'" in text.rsplit("return [pscustomobject]@{", 1)[1]


def _c109() -> None:
    text = _reference_text()
    failure = text.split("catch {", 4)[4].split("$SubnetRecords = @()", 1)[0]
    assert "$FailedSnapshot = [ordered]@{" in failure
    assert "collection_status = 'failed'" in failure
    assert "objects = @()" in failure
    assert failure.index("Set-Content -LiteralPath $OutputPath") < failure.index(
        'throw "AD computer query failed.'
    )


def _c110() -> None:
    text = _reference_text()
    assert "A failure in an optional source does not discard" in text
    assert "foreach ($Computer in $Computers)" in text
    assert "foreach ($DnsError in @($DnsResult.State.error))" in text
    assert "[void]$ObjectErrors.Add($SiteStageError)" in text
    assert "foreach ($ExactError in @($ExactData.Errors))" in text
    assert "collectionErrors             = @($ObjectErrors)" in text


def _c111() -> None:
    text = _reference_text()
    stage = _function(text, "Get-StageStatus", None)
    assert "$Counts.ContainsKey('partial')" in stage
    assert "$Counts.ContainsKey('not_evaluated')" in stage
    assert "$CollectionStatus = if (" in stage
    assert ") { 'partial' } else { 'complete' }" in stage
    for name in ("dns", "os", "site", "last_logon_timestamp", "exact_last_logon"):
        assert re.search(rf"name = '{name}'.*requested =", stage)


def _c112() -> None:
    text = _reference_text()
    assert "dc_events            = New-SourceState -Status 'not_collected'" in text
    assert "name = 'dc_events'; status = 'not_collected'; requested = $false" in text
    assert "Get-WinEvent" not in text
    assert "Test-Connection" not in text
    assert "lastLogonTimestamp" in text
    for forbidden_claim in ("compliance_status", "severity_score", "lifecycle_status"):
        assert forbidden_claim not in text


CLAUSE_CHECKS = {
    "C008": _c008,
    "C068": _c068,
    "C069": _c069,
    "C070": _c070,
    "C071": _c071,
    "C072": _c072,
    "C073": _c073,
    "C074": _c074,
    "C075": _c075,
    "C076": _c076,
    "C077": _c077,
    "C078": _c078,
    "C079": _c079,
    "C080": _c080,
    "C081": _c081,
    "C082": _c082,
    "C097": _c097,
    "C098": _c098,
    "C099": _c099,
    "C100": _c100,
    "C101": _c101,
    "C102": _c102,
    "C103": _c103,
    "C104": _c104,
    "C105": _c105,
    "C106": _c106,
    "C107": _c107,
    "C108": _c108,
    "C109": _c109,
    "C110": _c110,
    "C111": _c111,
    "C112": _c112,
}


@pytest.mark.parametrize("clause_id", CLAUSE_CHECKS)
def test_v6_clause(clause_id: str) -> None:
    CLAUSE_CHECKS[clause_id]()


def test_source_parser_accepts_utf8_json_and_enforces_byte_bound() -> None:
    api = _source_api()
    raw = json.dumps(
        _production_snapshot(), ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    parsed = api.parse_computers_v6_snapshot(raw, max_bytes=len(raw))
    assert parsed["objects"][0]["name"] == "APP-01"

    with pytest.raises(api.ComputersV6SourceContractError, match="size"):
        api.parse_computers_v6_snapshot(raw, max_bytes=len(raw) - 1)
    with pytest.raises(api.ComputersV6SourceContractError, match="json"):
        api.parse_computers_v6_snapshot(b"{not-json", max_bytes=100)


def test_validator_requires_explicit_metadata_identity_and_source_schema() -> None:
    api = _source_api()

    missing_metadata = _production_snapshot()
    del missing_metadata["metadata"]["query_dc"]
    with pytest.raises(api.ComputersV6SourceContractError, match="metadata_fields"):
        api.validate_computers_v6_snapshot(missing_metadata)

    mismatched_identity = _production_snapshot()
    mismatched_identity["objects"][0]["objectGuid"] = (
        "00000000-0000-4000-8000-000000000002"
    )
    with pytest.raises(api.ComputersV6SourceContractError, match="stable_identity"):
        api.validate_computers_v6_snapshot(mismatched_identity)

    duplicate = _production_snapshot()
    duplicate["objects"].append(copy.deepcopy(duplicate["objects"][0]))
    duplicate["metadata"]["object_count"] = 2
    with pytest.raises(api.ComputersV6SourceContractError, match="duplicate"):
        api.validate_computers_v6_snapshot(duplicate)

    missing_source = _production_snapshot()
    del missing_source["objects"][0]["sources"]["exact_last_logon"]
    with pytest.raises(api.ComputersV6SourceContractError, match="required_sources"):
        api.validate_computers_v6_snapshot(missing_source)


def test_optional_source_failures_preserve_valid_base_inventory() -> None:
    api = _source_api()
    snapshot = _production_snapshot()
    snapshot["metadata"]["collection_status"] = "partial"
    optional_states = {
        "dns": _source_state(
            "dns", "failed", error=_error("failed"), details={"stage": "A+AAAA"}
        ),
        "site": _source_state(
            "site",
            "not_evaluated",
            details={
                "reason": "no_ipv4_for_site_mapping",
                "dependency": "dns",
                "dependency_status": "failed",
            },
        ),
        "exact_last_logon": _source_state(
            "exact_last_logon",
            "partial",
            value="2026-08-29T12:30:00Z",
            error=_error("failed"),
            details={"queried_dc": 1, "total_dc": 2, "failed_dc": ["dc02"]},
        ),
    }
    for name, state in optional_states.items():
        snapshot["objects"][0]["sources"][name] = state
        stage = next(
            item for item in snapshot["metadata"]["sources"] if item["name"] == name
        )
        stage.update(status=state["status"], requested=True, counts={state["status"]: 1})

    accepted = api.validate_computers_v6_snapshot(snapshot)
    assert api.base_inventory_status(accepted) == "observed"
    assert len(accepted["objects"]) == 1

    invalid_base = copy.deepcopy(snapshot)
    invalid_base["objects"][0]["sources"]["ad"] = _source_state(
        "ad", "failed", error=_error("failed")
    )
    with pytest.raises(api.ComputersV6SourceContractError, match="base_ad"):
        api.validate_computers_v6_snapshot(invalid_base)

    failed_empty = _production_snapshot()
    failed_empty["objects"] = []
    failed_empty["metadata"]["object_count"] = 0
    failed_empty["metadata"]["collection_status"] = "failed"
    failed_empty["metadata"]["sources"] = [
        {"name": "ad", "status": "failed", "requested": True, "counts": {"failed": 0}}
    ]
    assert api.base_inventory_status(
        api.validate_computers_v6_snapshot(failed_empty)
    ) == "failed"


class _LatestCursor:
    def __init__(self, row) -> None:
        self.row = row
        self.statement: tuple[str, tuple] | None = None

    def execute(self, sql: str, params: tuple = ()) -> None:
        self.statement = (sql, params)

    def fetchone(self):
        return self.row


class _LatestConnection:
    def __init__(self, cursor: _LatestCursor) -> None:
        self.cursor_value = cursor

    def cursor(self):
        cursor = self.cursor_value

        class _Context:
            def __enter__(self):
                return cursor

            def __exit__(self, *_args):
                return False

        return _Context()


def test_latest_source_loader_is_hash_verified_and_bounded_to_one_row() -> None:
    api = _source_api()
    snapshot = _production_snapshot()
    payload_text, payload_sha256 = api.canonical_computers_v6_snapshot(snapshot)
    row = {
        "source_snapshot_id": 114,
        "domain_id": 7,
        "snapshot_uuid": snapshot["metadata"]["snapshot_id"],
        "source_completed_at_utc": snapshot["metadata"]["completed_at"],
        "captured_at_utc": "2026-08-30T01:11:00Z",
        "collection_status": "complete",
        "base_inventory_status": "observed",
        "object_count": 1,
        "payload_json": payload_text,
        "payload_sha256": payload_sha256,
    }
    cursor = _LatestCursor(row)
    loaded = api.load_latest_computers_v6_source_snapshot(
        _LatestConnection(cursor), domain_fqdn="example.test"
    )
    assert loaded["source_snapshot_id"] == 114
    assert loaded["snapshot"]["objects"][0]["objectGuid"].endswith("0001")
    assert cursor.statement is not None
    sql, params = cursor.statement
    assert "limit 1" in " ".join(sql.casefold().split())
    assert params == ("example.test",)

    tampered = dict(row)
    tampered["payload_sha256"] = b"x" * 32
    with pytest.raises(api.ComputersV6SourceContractError, match="hash"):
        api.load_latest_computers_v6_source_snapshot(
            _LatestConnection(_LatestCursor(tampered)), domain_fqdn="example.test"
        )


def test_validator_rejects_impossible_time_and_dc_event_provenance() -> None:
    api = _source_api()

    reversed_window = _production_snapshot()
    reversed_window["metadata"]["completed_at"] = "2026-08-30T00:59:59Z"
    with pytest.raises(api.ComputersV6SourceContractError, match="time_window"):
        api.validate_computers_v6_snapshot(reversed_window)

    naive_time = _production_snapshot()
    naive_time["metadata"]["completed_at"] = "2026-08-30T01:10:00"
    with pytest.raises(api.ComputersV6SourceContractError, match="timezone"):
        api.validate_computers_v6_snapshot(naive_time)

    invented_event = _production_snapshot()
    invented_event["objects"][0]["sources"]["dc_events"] = _source_state(
        "dc_events", "observed", value="4624"
    )
    with pytest.raises(api.ComputersV6SourceContractError, match="dc_events"):
        api.validate_computers_v6_snapshot(invented_event)


def test_source_boundary_limits_cannot_be_relaxed_by_callers() -> None:
    api = _source_api()
    snapshot = _production_snapshot()
    raw = json.dumps(snapshot, separators=(",", ":")).encode("utf-8")

    with pytest.raises(api.ComputersV6SourceContractError, match="byte.*bound"):
        api.parse_computers_v6_snapshot(
            raw,
            max_bytes=api.MAX_SNAPSHOT_BYTES + 1,
        )
    with pytest.raises(api.ComputersV6SourceContractError, match="object.*bound"):
        api.validate_computers_v6_snapshot(
            snapshot,
            max_objects=api.MAX_OBJECTS + 1,
        )

    cursor = _LatestCursor(None)
    with pytest.raises(api.ComputersV6SourceContractError, match="object.*bound"):
        api.load_latest_computers_v6_source_snapshot(
            _LatestConnection(cursor),
            domain_fqdn="example.test",
            max_objects=api.MAX_OBJECTS + 1,
        )
    assert cursor.statement is None

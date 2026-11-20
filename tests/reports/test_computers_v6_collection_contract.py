from __future__ import annotations

import json
from pathlib import Path

import pytest

from server.ad_context.contracts import AdContextContractError, validate_bundle
from server.sli.reports.computers_v5_reporting import _quality_issues as v5_quality_issues
from scripts.maintenance.ad_context_live_canary import SECTION_PACK_VERSIONS
from tests.tooling.test_ad_context_foundation import _supplemental_bundle


COLLECTOR = Path("scripts/ad_context/Export-AdAuditContextBundle.ps1")

COMPUTER_REFERENCE_PROPERTIES = (
    "OperatingSystemServicePack",
    "CanonicalName",
    "Description",
    "Location",
    "ManagedBy",
    "PasswordLastSet",
    "whenChanged",
    "servicePrincipalName",
    "TrustedForDelegation",
    "TrustedToAuthForDelegation",
    "userAccountControl",
)

COMPUTER_REFERENCE_ATTRIBUTE_SOURCES = {
    "operating_system_service_pack": "OperatingSystemServicePack",
    "canonical_name": "CanonicalName",
    "description": "Description",
    "location": "Location",
    "managed_by": "ManagedBy",
    "password_last_set_utc": "PasswordLastSet",
    "created_utc": "whenCreated",
    "when_changed_utc": "whenChanged",
    "service_principal_names": "servicePrincipalName",
    "trusted_for_delegation": "TrustedForDelegation",
    "trusted_to_auth_for_delegation": "TrustedToAuthForDelegation",
    "user_account_control": "userAccountControl",
}


def _computer_bundle() -> dict:
    bundle = _supplemental_bundle()
    bundle["source_pack_version"] = "0.9.0"
    record = bundle["records"][0]
    record["identity"] = {
        "kind": "ad_computer",
        "domain_sid": bundle["domain"]["sid"],
        "object_guid": "00000000-0000-4000-8000-000000000065",
        "object_sid": "S-1-5-21-100000003-200000003-300000003-2101",
    }
    record["attributes"] = {
        "display_name": "APP-SRV-01",
        "sam_account_name": "APP-SRV-01$",
        "distinguished_name": "CN=APP-SRV-01,OU=Servers,DC=example,DC=local",
        "canonical_name": "example.local/Servers/APP-SRV-01",
        "enabled": True,
        "object_class": "computer",
        "last_logon_utc": bundle["observed_at_utc"],
        "created_utc": "2025-01-01T00:00:00Z",
        "password_last_set_utc": "2026-07-01T00:00:00Z",
        "when_changed_utc": "2026-07-20T11:00:00Z",
        "description": "Application server",
        "location": "Datacenter A",
        "managed_by": "CN=IT Operations,OU=Groups,DC=example,DC=local",
        "service_principal_names": ["HOST/app-srv-01.example.local"],
        "trusted_for_delegation": False,
        "trusted_to_auth_for_delegation": False,
        "user_account_control": 4096,
        "operating_system_service_pack": "Service Pack 1",
        "attribute_states": {
            "enabled": {"state": "present", "source_attribute": "Enabled"},
            "last_logon_utc": {"state": "present", "source_attribute": "LastLogonDate"},
            "dns_host_name": {"state": "absent_in_source", "source_attribute": "DNSHostName"},
            "operating_system": {"state": "present", "source_attribute": "OperatingSystem"},
            "operating_system_version": {"state": "present", "source_attribute": "OperatingSystemVersion"},
        },
        "computer_reference_attribute_states": {
            "enabled": {"state": "present", "source_attribute": "Enabled"},
            "last_logon_utc": {"state": "present", "source_attribute": "LastLogonDate"},
            "dns_host_name": {"state": "absent_in_source", "source_attribute": "DNSHostName"},
            "operating_system": {"state": "present", "source_attribute": "OperatingSystem"},
            "operating_system_version": {"state": "present", "source_attribute": "OperatingSystemVersion"},
            **{
                key: {"state": "present", "source_attribute": source}
                for key, source in COMPUTER_REFERENCE_ATTRIBUTE_SOURCES.items()
                if key not in {
                    "enabled",
                    "last_logon_utc",
                    "dns_host_name",
                    "operating_system",
                    "operating_system_version",
                }
            },
        },
    }
    return bundle


def test_computer_query_requests_reference_ad_properties() -> None:
    source = COLLECTOR.read_text(encoding="utf-8")
    assert source.startswith("#requires -Version 5.1")
    block = source.split("$computerProperties = @(", 1)[1].split(")\n        $computers", 1)[0]

    for property_name in COMPUTER_REFERENCE_PROPERTIES:
        assert f'"{property_name}"' in block

    base_block = source.split("$baseComputerProperties = @(", 1)[1].split(") | Sort-Object -Unique", 1)[0]
    assert '"OperatingSystemServicePack"' in base_block


def test_computer_contract_accepts_reference_ad_fields_with_provenance() -> None:
    normalized = validate_bundle(_computer_bundle())
    attributes = normalized["records"][0]["attributes"]

    assert attributes["canonical_name"] == "example.local/Servers/APP-SRV-01"
    assert attributes["location"] == "Datacenter A"
    assert attributes["service_principal_names"] == ["HOST/app-srv-01.example.local"]
    assert attributes["operating_system_service_pack"] == "Service Pack 1"
    assert attributes["computer_reference_attribute_states"]["operating_system_service_pack"] == {
        "state": "present",
        "source_attribute": "OperatingSystemServicePack",
    }
    assert attributes["computer_reference_attribute_states"]["when_changed_utc"] == {
        "state": "present",
        "source_attribute": "whenChanged",
    }


def test_computer_contract_requires_provenance_for_every_supported_reference_field() -> None:
    bundle = _computer_bundle()
    del bundle["records"][0]["attributes"]["computer_reference_attribute_states"]["managed_by"]

    with pytest.raises(AdContextContractError, match="every supported computer attribute"):
        validate_bundle(bundle)


def test_reference_provenance_does_not_change_v5_quality_semantics() -> None:
    attributes = validate_bundle(_computer_bundle())["records"][0]["attributes"]

    assert set(attributes["attribute_states"]) == {
        "enabled",
        "last_logon_utc",
        "dns_host_name",
        "operating_system",
        "operating_system_version",
    }
    without_reference_states = dict(attributes)
    without_reference_states.pop("computer_reference_attribute_states")
    assert v5_quality_issues(attributes, attributes["attribute_states"]) == v5_quality_issues(
        without_reference_states,
        without_reference_states["attribute_states"],
    )


def test_legacy_source_pack_does_not_require_v6_reference_provenance() -> None:
    bundle = _computer_bundle()
    bundle["source_pack_version"] = "0.8.0"
    del bundle["records"][0]["attributes"]["computer_reference_attribute_states"]

    validate_bundle(bundle)


def test_enriched_collector_and_source_pack_publish_the_same_new_version() -> None:
    source_pack = json.loads(
        Path("config/source_packs/ad_context.json").read_text(encoding="utf-8")
    )
    collector = COLLECTOR.read_text(encoding="utf-8")

    assert source_pack["version"] == "0.10.0"
    assert 'source_pack_version = "0.10.0"' in collector


def test_audit_canary_accepts_the_enriched_exporter_version() -> None:
    assert SECTION_PACK_VERSIONS["privileged_membership"] == "0.5.0"
    assert {
        version
        for section, version in SECTION_PACK_VERSIONS.items()
        if section != "privileged_membership"
    } == {"0.10.0"}

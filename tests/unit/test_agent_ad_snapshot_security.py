"""Daily AD posture survives capture and import without source access or a DB."""
from copy import deepcopy
from pathlib import Path

import pytest

from server.ad_context.contracts import AdContextContractError, validate_bundle
from server.sli.agents import ad_snapshot_import as importer
from server.sli.plugins.ad.context.repository import materialize_entity_attributes
from server.sli.reports import computers_v6_reporting as report
from sli_agent import ad_snapshot
from sli_agent.ad_snapshot import normalize_capture
from test_agent_ad_snapshot import NOW, SID, config, directory
from test_agent_ad_snapshot_import import complete_families, cycle
from test_computers_ad_security import row

RBCD = "msds-allowedtoactonbehalfofotheridentity"
DIGEST = "a" * 64


def captured(properties, *, kind="ad_computer", schema=None):
    raw = directory(1)
    source = next(item for item in raw["objects"] if item["kind"] == kind)
    source["properties"].update(properties)
    raw["schema_attributes"] = schema or {}
    cfg = config(expensive_flags={})
    families = {name: data for name, (data, _) in normalize_capture(raw, cfg, observed_at=NOW).items()}
    return cfg, families


def attributes(families, kind="ad_computer"):
    base = validate_bundle(families["ad_context_base"])
    return next(record["attributes"] for record in base["records"]
                if record["section"] == "directory_accounts" and record.get("identity", {}).get("kind") == kind)


@pytest.mark.parametrize("kind", ["ad_user", "ad_computer"])
@pytest.mark.parametrize("status", ["observed", "partial"])
def test_rbcd_trustees_and_digest_survive_contract_and_supplemental_import(kind, status):
    sids = [SID + "-2001", SID + "-2002"]
    _, families = captured({RBCD: {"present": True, "status": status, "sids": sids[::-1] + sids,
                                  "descriptor_sha256": DIGEST, "arbitrary": "discard-marker"}}, kind=kind)
    attrs = attributes(families, kind)
    assert attrs["resource_based_delegation_present"] is True
    assert attrs["resource_based_delegation_sids"] == sids
    assert attrs["resource_based_delegation_status"] == status
    assert attrs["resource_based_delegation_descriptor_sha256"] == DIGEST
    assert "discard-marker" not in str(families)
    merged = materialize_entity_attributes(attrs, {"exact_last_logon_status": "not_collected"}, section="directory_exact_logon")
    for key in attrs:
        assert merged[key] == attrs[key]


@pytest.mark.parametrize("value,present,status,sids", [
    (None, None, "not_returned", None),
    (True, True, "not_collected", None),
    (False, False, "observed", []),
    ({"present": True, "status": "parse_error", "sids": None}, True, "parse_error", None),
    ({"present": True, "status": "observed", "sids": ["invalid"]}, True, "parse_error", None),
    ({"present": True, "status": "observed", "sids": [SID] * 257}, True, "parse_error", None),
    ("unexpected-binary-marker", None, "parse_error", None),
])
def test_unavailable_rbcd_never_becomes_false_or_an_empty_trustee_list(value, present, status, sids):
    _, families = captured({RBCD: value})
    attrs = attributes(families)
    assert attrs["resource_based_delegation_present"] is present
    assert attrs["resource_based_delegation_status"] == status
    assert attrs["resource_based_delegation_sids"] == sids
    assert "unexpected-binary-marker" not in str(families)


@pytest.mark.parametrize("source,target", [
    ("pwdlastset", "password_last_set"),
    ("mslaps-passwordexpirationtime", "laps_password_expiration"),
    ("ms-mcs-admpwdexpirationtime", "legacy_laps_password_expiration"),
])
@pytest.mark.parametrize("value,status,stamp", [
    (None, "not_returned", None), (0, "not_set", None), ("0", "not_set", None),
    ("invalid", "parse_error", None), (-1, "parse_error", None),
    (9999999999999999999999999999, "parse_error", None),
    ("2026-10-09T12:00:00Z", "observed", "2026-10-09T12:00:00Z"),
    (134040528000000000, "observed", "2025-10-04T12:00:00Z"),
])
def test_date_evidence_preserves_zero_missing_and_invalid_values(source, target, value, status, stamp):
    _, families = captured({source: value})
    attrs = attributes(families)
    assert attrs[target + "_status"] == status
    assert attrs[target + "_utc"] == stamp


@pytest.mark.parametrize("schema,status", [("absent", "schema_absent"), ("present", "not_returned"),
                                          ("not_evaluated", "not_returned")])
def test_schema_presence_does_not_claim_object_read_permissions(schema, status):
    _, families = captured({}, schema={name: schema for name in (
        RBCD, "mslaps-passwordexpirationtime", "ms-mcs-admpwdexpirationtime")})
    attrs = attributes(families)
    for key in ("resource_based_delegation_status", "laps_password_expiration_status", "legacy_laps_password_expiration_status"):
        assert attrs[key] == status
    assert attrs["resource_based_delegation_present"] is None


def test_agent_import_and_computers_overlay_retain_posture_and_machine_password_evidence():
    cfg, families = captured({RBCD: {"present": True, "status": "observed", "sids": [SID + "-2001"],
                                   "descriptor_sha256": DIGEST},
        "pwdlastset": 0, "mslaps-passwordexpirationtime": "2026-10-09T12:00:00Z",
        "ms-mcs-admpwdexpirationtime": 0, "msds-allowedtodelegateto": ["HTTP/service.invalid"],
        "serviceprincipalname": ["HOST/host.invalid"], "useraccountcontrol": 4096 | 524288})
    bundles, computers = importer.prepare_ad_cycle(cycle(cfg), families)
    attrs = attributes({"ad_context_base": bundles["ad_context_base"]})
    source = computers["objects"][0]
    item = report._item(row(), 90)
    item["object_guid"] = source["objectGuid"]
    report._apply_computers_v6_source_overlay(item, {"by_guid": {source["objectGuid"]: source},
        "source_snapshot": {"completed_at_utc": NOW.isoformat()}})
    for key in ("resource_based_delegation_sids", "resource_based_delegation_status",
                "resource_based_delegation_descriptor_sha256", "password_last_set_status",
                "laps_password_expiration_status", "legacy_laps_password_expiration_status"):
        assert item[key] == attrs[key]
    assert item["delegation"] == {"unconstrained": True, "constrained": True, "resource_based": True}
    assert item["laps"]["state"] == "metadata_present"
    assert source["passwordLastSet"] is None
    assert source["spns"] == ["HOST/host.invalid"]
    assert source["osVersion"] == "10.0 (20348)"


@pytest.mark.parametrize("key,value", [
    ("laps_password_expiration_status", "unexpected"),
    ("resource_based_delegation_status", "unexpected"),
    ("resource_based_delegation_sids", ["invalid"]),
    ("resource_based_delegation_sids", "invalid"),
])
def test_import_contract_rejects_invalid_posture_metadata(key, value):
    _, families = complete_families()
    bundle = deepcopy(families["ad_context_base"])
    record = next(record for record in bundle["records"] if record["section"] == "directory_accounts")
    record["attributes"][key] = value
    with pytest.raises(AdContextContractError):
        validate_bundle(bundle)


def test_powershell_only_exports_reduced_rbcd_and_queries_non_secret_laps_schema():
    script = Path(ad_snapshot.__file__).with_suffix(".ps1").read_text(encoding="utf-8")
    conversion = script.split("function Convert-Value", 1)[1].split("function Read-Properties", 1)[0]
    assert "RawSecurityDescriptor" in conversion and "AccessAllowed" in conversion
    assert "descriptor_sha256" in conversion and "256" in conversion
    assert "schema_attributes = $schemaAttributes" in script
    for name in ("msLAPS-PasswordExpirationTime", "ms-Mcs-AdmPwdExpirationTime"):
        assert f"(lDAPDisplayName={name})" in script
    assert "mslaps-password" not in ad_snapshot.LDAP_ATTRIBUTES
    assert "mslaps-encryptedpassword" not in ad_snapshot.LDAP_ATTRIBUTES
    assert "msds-managedpassword" not in ad_snapshot.LDAP_ATTRIBUTES

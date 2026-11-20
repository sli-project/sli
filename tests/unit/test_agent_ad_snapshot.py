"""Agent AD acquisition contracts, entirely synthetic and without a directory."""
from __future__ import annotations

import json
import io
import threading
import time
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

import pytest

from server.ad_context.contracts import ENTITY_ATTRIBUTE_KEYS, validate_bundle
from sli_agent.ad_snapshot import ADSnapshotModule, LDAP_ATTRIBUTES, normalize_capture
from sli_agent import ad_snapshot
from sli_agent.envelope import canonical
from sli_agent.snapshot_stream import MODULE_FAMILIES, SnapshotStream, policy

NOW = datetime(2026, 10, 8, 12, tzinfo=timezone.utc)
SID = "S-1-5-21-1-2-3"
DN = "DC=directory,DC=invalid"


def config(**changes):
    return policy("sli.ad-snapshot", {
        "source_instance_id": "00000000-0000-4000-8000-000000000001",
        "domain_sid": SID, "domain_dns": "directory.invalid", "scope": DN,
        "expensive_flags": {"exact_last_logon": True}, **changes,
    })


def obj(index, kind="ad_user", **props):
    return {"kind": kind, "properties": {
        "objectguid": str(UUID(int=index)), "objectsid": f"{SID}-{100000 + index}",
        "distinguishedname": f"CN=object-{index},{DN}", "name": f"object-{index}",
        "samaccountname": f"object-{index}", "useraccountcontrol": 512,
        "primarygroupid": 513, "memberof": [], **props,
    }}


def directory(count=2100):
    objects = [obj(i) for i in range(1, count + 1)]
    objects += [obj(10001, "ad_computer", dnshostname="host.invalid",
                    operatingsystem="Windows Server", operatingsystemversion="10.0 (20348)"),
                obj(100513, "ad_group", member=[], primarygroupid=None, objectsid=f"{SID}-513"),
                obj(30001, "ad_group", **({"member;range=0-1499": [o["properties"]["distinguishedname"] for o in objects[:1500]],
                                          "member;range=1500-*": [o["properties"]["distinguishedname"] for o in objects[1500:]]}
                                         if count > 1500 else {"member": [o["properties"]["distinguishedname"] for o in objects]}),
                    memberof=[f"CN=object-30002,{DN}"]),
                obj(30002, "ad_group", member=[f"CN=object-30001,{DN}"],
                    memberof=[f"CN=object-30001,{DN}"])]
    return {"domain": {"sid": SID, "dns_name": "directory.invalid", "default_nc": DN},
            "objects": objects, "states": {}, "surveys": [
                {"dc": "dc-a.invalid", "status": "complete", "values": {str(UUID(int=1)): 134040528000000000}},
                {"dc": "dc-b.invalid", "status": "complete", "values": {str(UUID(int=1)): 134041392000000000}},
                {"dc": "dc-c.invalid", "status": "failed", "values": {}},
            ]}


def test_large_directory_ranges_cycles_primary_group_and_dc_coverage():
    result = normalize_capture(directory(), config(), observed_at=NOW)
    base = validate_bundle(result["ad_context_base"][0])
    relations = [r for r in base["records"] if r["record_type"] == "relation"]
    assert len([r for r in relations if r["target_record_key"].endswith(str(UUID(int=30001)))
                and r["attributes"]["membership_type"] == "direct"]) == 2101
    assert any(r["attributes"]["membership_type"] == "primary" for r in relations)
    assert any(r["source_record_key"].endswith(str(UUID(int=30002)))
               and r["target_record_key"].endswith(str(UUID(int=30001))) for r in relations)
    exact = next(r["attributes"] for r in base["records"]
                 if r["section"] == "directory_exact_logon" and r.get("identity", {}).get("object_guid") == str(UUID(int=1)))
    assert exact["exact_last_logon_utc"] == "2025-10-05T12:00:00Z"
    assert exact["exact_last_logon_status"] == "partial"
    assert exact["exact_last_logon_successful_dc_count"] == 2
    assert exact["exact_last_logon_discovered_dc_count"] == 3
    assert exact["exact_last_logon_failed_dcs"] == ["dc-c.invalid"]


@pytest.mark.parametrize("service_class", ["msDS-ManagedServiceAccount", "msDS-GroupManagedServiceAccount"])
def test_user_security_attributes_survive_agent_bundle_validation(service_class):
    raw = directory(1)
    raw["objects"][0]["properties"].update(
        objectclass=["top", "person", "user", "computer", service_class],
        useraccountcontrol=512 | sum(ad_snapshot.UAC_FLAGS.values()),
        serviceprincipalname=["HTTP/service.invalid"], admincount=1,
    )
    bundle = validate_bundle(normalize_capture(raw, config(), observed_at=NOW)["ad_context_base"][0])
    attrs = next(record["attributes"] for record in bundle["records"]
                 if record.get("section") == "directory_accounts" and record.get("identity", {}).get("kind") == "ad_user")
    assert attrs["object_class"] == "user" and service_class in attrs["object_classes"]
    assert attrs["service_principal_names"] == ["HTTP/service.invalid"] and attrs["admin_count"] == 1
    for name in ("password_never_expires", "password_not_required", "allow_reversible_password_encryption",
                 "does_not_require_preauth", "smartcard_logon_required", "account_not_delegated"):
        assert attrs[name] is True


def test_agent_search_includes_managed_accounts_as_users_without_computer_duplicates():
    script = (Path(ad_snapshot.__file__).with_suffix(".ps1")).read_text(encoding="utf-8")
    user_filter = next(line for line in script.splitlines() if "Collect $base" in line and "'ad_user'" in line)
    computer_filter = next(line for line in script.splitlines() if "Collect $base" in line and "'ad_computer'" in line)
    for class_name in ("msDS-ManagedServiceAccount", "msDS-GroupManagedServiceAccount"):
        assert f"(objectClass={class_name})" in user_filter
        assert f"(!(objectClass={class_name}))" in computer_filter


def test_computer_classification_survives_agent_bundle_validation():
    raw = directory(1)
    computer = next(item for item in raw["objects"] if item["kind"] == "ad_computer")
    computer["properties"]["objectclass"] = ["top", "person", "user", "computer"]
    bundle = validate_bundle(normalize_capture(raw, config(), observed_at=NOW)["ad_context_base"][0])
    records = [record for record in bundle["records"] if record.get("identity", {}).get("kind") == "ad_computer"
               and record["section"] == "directory_accounts"]
    assert len(records) == 1
    assert records[0]["section"] == "directory_accounts"
    assert records[0]["attributes"]["object_class"] == "computer"
    assert records[0]["attributes"]["object_classes"] == ["top", "person", "user", "computer"]


def test_allowlist_and_secrets_removed_before_frozen_capture(tmp_path):
    raw = directory(2)
    raw["objects"][0]["properties"].update({"unicodepwd": "secret-marker", "ms-mcs-admpwd": "secret-marker",
                                          "msds-managedpassword": "secret-marker", "arbitrary": "secret-marker"})
    families = normalize_capture(raw, config(), observed_at=NOW)
    for family, (bundle, _) in families.items():
        if family != "computers_v6":
            validate_bundle(bundle)
            assert all(set(r.get("attributes", {})) <= ENTITY_ATTRIBUTE_KEYS | {"attribute_states", "computer_reference_attribute_states"} or r["record_type"] == "relation"
                       for r in bundle["records"])
    stream = SnapshotStream(tmp_path, "sli.ad-snapshot")
    stream.freeze(stream.begin(config(), now=NOW), families)
    assert "secret-marker" not in (stream.root / "cycle.json").read_text()
    assert any(r.get("code") == "sensitive_fields_masked" for r in families["ad_context_base"][0]["records"])
    assert not {"unicodepwd", "supplementalcredentials", "msds-managedpassword", "ms-mcs-admpwd",
                "mslaps-password", "mslaps-encryptedpassword"} & set(LDAP_ATTRIBUTES)


@pytest.mark.parametrize("limit", [10, 100])
def test_record_overflow_is_bounded_partial_without_reconciliation(limit):
    cfg = config(max_objects=limit)
    families = normalize_capture(directory(200), cfg, observed_at=NOW)
    assert sum(count for _, count in families.values()) <= limit
    assert all(section["status"] != "complete" for family, (bundle, _) in families.items()
               if family != "computers_v6" for section in bundle["sections"])
    assert all(bundle["mode"] == "targeted" for family, (bundle, _) in families.items() if family != "computers_v6")


def test_byte_overflow_is_explicit_partial():
    families = normalize_capture(directory(20), config(max_bytes=12000), observed_at=NOW)
    assert sum(len(canonical(bundle)) for family, (bundle, _) in families.items() if family != "computers_v6") <= 12000
    assert families["ad_context_base"][0]["mode"] == "targeted"


def test_unresolved_links_and_missing_range_are_partial():
    raw = directory(2)
    raw["objects"][0]["properties"]["memberof"] = [f"CN=missing,{DN}"]
    raw["objects"][1]["properties"]["primarygroupid"] = 99999
    props = raw["objects"][-2]["properties"]
    props["member;range=0-1"] = props.pop("member")
    families = normalize_capture(raw, config(), observed_at=NOW)
    base = families["ad_context_base"][0]
    assert next(s for s in base["sections"] if s["name"] == "directory_group_graph")["status"] == "partial"
    assert any(r.get("attributes", {}).get("unresolved_group_dns") for r in base["records"])
    assert any(r.get("attributes", {}).get("unresolved_primary_group_sid") for r in base["records"])


def test_optional_checks_not_collected_and_domain_binding():
    raw = directory(2)
    cfg = config(expensive_flags={})
    families = normalize_capture(raw, cfg, observed_at=NOW)
    computer = families["computers_v6"][0]["objects"][0]
    assert all(computer["sources"][s]["status"] == "not_collected" for s in ("dns", "site", "exact_last_logon", "dc_events"))
    raw["domain"]["sid"] = "S-1-5-21-9-8-7"
    with pytest.raises(ValueError, match="agent_ad_domain_mismatch"):
        normalize_capture(raw, cfg, observed_at=NOW)


def test_module_uses_frozen_policy_and_fake_powershell_output():
    calls = []
    def reader(cfg, *, deadline, stop):
        calls.append(deepcopy(cfg))
        return json.dumps(directory(2))
    module = ADSnapshotModule(config(), reader=reader)
    frozen = config(expensive_flags={})
    families = module.capture(frozen, deadline=time.monotonic() + 30, stop=threading.Event())
    assert calls == [frozen]
    assert set(families) == set(MODULE_FAMILIES["sli.ad-snapshot"])


def test_capture_cancellation_and_private_parse_errors():
    stop = threading.Event()
    stop.set()
    module = ADSnapshotModule(config(), reader=lambda *a, **k: "private-marker")
    with pytest.raises(ValueError, match="agent_ad_capture_cancelled"):
        module.capture(config(), deadline=time.monotonic() + 30, stop=stop)
    stop.clear()
    with pytest.raises(ValueError, match="^agent_ad_capture_invalid$"):
        module.capture(config(), deadline=time.monotonic() + 30, stop=stop)


def test_requested_unresolved_group_is_failed_not_optional_skip():
    families = normalize_capture(directory(2), config(groups=[f"vpn:{SID}-999999"]), observed_at=NOW)
    bundle = validate_bundle(families["ad_vpn_membership"][0])
    assert bundle["sections"][0]["status"] == "failed"
    assert bundle["sections"][0]["error_code"] == "collection_incomplete"
    assert bundle["records"] == []


def test_computed_password_expired_and_infrastructure_allowlist():
    raw = directory(2)
    raw["objects"][0]["properties"]["msds-user-account-control-computed"] = 8388608 | 16
    raw["objects"] += [obj(50001, "domain", minpwdlength=14, lockoutthreshold=5),
                       obj(50002, "domain_trust", trustpartner="peer.invalid", trustdirection=3, trusttype=2),
                       obj(50003, "security_principal", objectclass=["organizationalUnit"]),
                       obj(50004, "security_principal", objectclass=["site"])]
    result = normalize_capture(raw, config(), observed_at=NOW)
    base = validate_bundle(result["ad_context_base"][0])
    attrs = next(r["attributes"] for r in base["records"] if r["record_key"].endswith(str(UUID(int=1))))
    assert attrs["password_expired"] is True and attrs["locked_out"] is True
    posture = validate_bundle(result["ad_domain_posture"][0])
    assert {r["identity"]["kind"] for r in posture["records"]} >= {"domain", "domain_trust", "password_policy"}
    assert {r["attributes"].get("infrastructure_role") for r in posture["records"]} >= {"site", "organizational_unit"}


def test_computer_membership_has_no_directory_only_provenance():
    result = normalize_capture(directory(2), config(groups=[f"privileged:{SID}-513"]), observed_at=NOW)
    bundle = validate_bundle(result["ad_privileged_membership"][0])
    computers = [r for r in bundle["records"] if r.get("identity", {}).get("kind") == "ad_computer"]
    assert len(computers) == 1
    assert "computer_reference_attribute_states" not in computers[0]["attributes"]


def test_requested_exact_logon_without_any_survey_is_failed():
    raw = directory(2)
    raw["surveys"] = []
    base = normalize_capture(raw, config(), observed_at=NOW)["ad_context_base"][0]
    assert base["sections"][2]["status"] == "failed"
    assert next(r for r in base["records"] if r["record_key"].endswith(str(UUID(int=1))))["attributes"]["exact_last_logon_status"] == "failed"


@pytest.mark.parametrize("properties", [{"serviceprincipalname": ["service/host.invalid"] * 257}, {"description": "x" * 4097}])
def test_attribute_contract_overflow_is_an_explicit_bounded_partial(properties):
    raw = directory(2)
    raw["objects"][0]["properties"].update(properties)
    result = normalize_capture(raw, config(), observed_at=NOW)
    for family, (data, count) in result.items():
        assert count == 0
        if family != "computers_v6":
            validate_bundle(data)
            assert data["mode"] == "targeted"
            assert all(section["error_code"] == "agent_ad_size_limit" for section in data["sections"])


def test_powershell_reader_uses_stdin_policy_without_credentials_or_raw_files(monkeypatch):
    class Input(io.BytesIO):
        def close(self):
            self.sent = self.getvalue()
            super().close()
    class Process:
        pid = 42
        returncode = 0
        stdin = Input()
        stdout = io.BytesIO(json.dumps(directory(2)).encode("utf-8"))
        def poll(self):
            return self.returncode
        def wait(self, timeout=None):
            return self.returncode
    process = Process()
    calls = []
    def start(args, **kwargs):
        calls.append((args, kwargs))
        return process
    monkeypatch.setattr(ad_snapshot.subprocess, "Popen", start)
    result = ad_snapshot.PowerShellDirectoryReader()(config(), deadline=time.monotonic() + 30, stop=threading.Event())
    assert result == directory(2)
    args, kwargs = calls[0]
    assert args[-2] == "-File" and args[-1].endswith("ad_snapshot.ps1")
    assert kwargs["stderr"] == ad_snapshot.subprocess.DEVNULL
    assert json.loads(process.stdin.sent)["ldap_attributes"] == list(LDAP_ATTRIBUTES)


def test_agent_release_requires_powershell_and_all_snapshot_modules():
    from server.sli.release_package import PackageError
    from sli_agent.updates import REQUIRED_FILES, validate_payload
    assert {"sli_agent/ad_snapshot.ps1", "sli_agent/ad_snapshot.py", "sli_agent/ad_snapshot_security.py", "sli_agent/ad_snapshot_computers.py",
            "sli_agent/snapshot_stream.py", "sli_agent/gpo_snapshot.py"} <= REQUIRED_FILES
    validate_payload(REQUIRED_FILES)
    with pytest.raises(PackageError, match="agent_update_payload_invalid"):
        validate_payload(REQUIRED_FILES - {"sli_agent/ad_snapshot.ps1"})
    with pytest.raises(PackageError, match="agent_update_payload_invalid"):
        validate_payload(REQUIRED_FILES - {"sli_agent/ad_snapshot_security.py"})


@pytest.mark.parametrize("name", ["ad_snapshot.ps1", "gpo_snapshot.ps1"])
def test_directory_readers_use_service_credentials_with_signing_and_sealing(name):
    source = (Path(__file__).resolve().parents[2] / "sli_agent" / name).read_text("utf-8-sig")
    assert ", $null, $null, $auth)" not in source
    assert "$entry.AuthenticationType = $auth" in source
    assert "AuthenticationTypes]::Secure" in source
    assert "AuthenticationTypes]::Signing" in source
    assert "AuthenticationTypes]::Sealing" in source


def test_directory_display_name_and_policy_duration_match_legacy_shapes():
    raw = directory(2)
    raw["objects"][0]["properties"]["displayname"] = "Synthetic display"
    raw["objects"].append(obj(50001, "domain", maxpwdage=-42 * 86400 * 10_000_000,
                              lockoutduration=-1800 * 10_000_000))
    families = normalize_capture(raw, config(), observed_at=NOW)
    attrs = next(r["attributes"] for r in families["ad_context_base"][0]["records"] if r["record_key"].endswith(str(UUID(int=1))))
    assert attrs["display_name"] == "Synthetic display"
    default_policy = next(r for r in families["ad_domain_posture"][0]["records"] if r["identity"]["kind"] == "password_policy")
    assert default_policy["attributes"]["password_max_age"] == "42.00:00:00"
    assert default_policy["attributes"]["lockout_duration"] == "00:30:00"


def test_dc_site_and_health_replication_are_importable_without_diagnostic_text():
    raw = directory(2)
    raw["health"] = [{"properties": raw["objects"][2]["properties"],
        "metadata": {"site_name": "synthetic-site", "is_global_catalog": True,
                     "is_read_only": False, "operation_master_roles": ["pdc_emulator"]},
        "checks": {"connectivity_state": "failed", "dns_state": "passed"}}]
    raw["replication"] = [{"source_dc": "dc-a.invalid", "destination_dc": "dc-b.invalid",
        "naming_context": DN, "last_replication_attempt_utc": NOW.isoformat(),
        "last_replication_success_utc": NOW.isoformat(), "consecutive_failure_count": 1, "last_replication_result": 1722}]
    result = normalize_capture(raw, config(), observed_at=NOW)
    health = validate_bundle(result["ad_domain_health"][0])
    attrs = next(r["attributes"] for r in health["records"] if r["identity"]["kind"] == "ad_computer")
    assert attrs["site_name"] == "synthetic-site" and attrs["is_global_catalog"] is True
    assert attrs["connectivity_state"] == "failed" and attrs["netlogon_state"] == "not_collected"
    assert next(r for r in health["records"] if r["identity"]["kind"] == "replication_link")["attributes"]["replication_state"] == "failed"

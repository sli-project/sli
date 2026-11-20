from copy import deepcopy
import json
from pathlib import Path

import pytest

from server.ad_context.contracts import AdContextContractError, validate_bundle
from server.sli.plugins.gpo import effective_access as access
from server.sli.sources.gpo_v2_source import GpoV2SourceContractError, canonical_snapshot, validate_snapshot

DOMAIN = "S-1-5-21-1-2-3"


def entity(key, rid, kind="ad_group", **attrs):
    return {"record_key": key, "section": "directory_group_graph",
            "identity": {"object_sid": f"{DOMAIN}-{rid}", "kind": kind},
            "attributes": {"display_name": key, "group_category": "Security", **attrs}}


def relation(child, parent, membership_type="direct"):
    return {"source_record_key": child, "target_record_key": parent,
            "attributes": {"membership_type": membership_type}}


def graph():
    return {"state": "ok", "computers_collected": True,
            "entities": [entity("user-a", 1101, "ad_user"), entity("computer-a", 1102, "ad_computer"),
                         entity("group-a", 2101), entity("group-b", 2102)],
            "relations": [relation("user-a", "group-a"), relation("computer-a", "group-a", "primary"),
                          relation("group-a", "group-b")],
            "source": {"run_id": "00000000-0000-4000-8000-000000000001", "observed_at_utc": "2026-10-07T00:00:00Z"}}


def ace(index=0, *, sid=f"{DOMAIN}-2102", mask=0x20010 | 0x100 | 0x20 | 0x40000, effect="Allow", **extra):
    return {"id": f"ace-{index}", "gpo_id": "gpo-a", "ace_index": index, "trustee_sid": sid,
            "access_mask": mask, "access_control_type": effect, "object_type": access.EMPTY_GUID,
            "inherited": False, "propagation_flags": 0, **extra}


def snapshot(*aces):
    return {"domain": {"sid": DOMAIN, "dns_name": "example.invalid"}, "observed_at": "2026-10-07T01:00:00Z",
            "collection_status": "complete", "completed_at": "2026-10-07T01:01:00Z",
            "gpos": [{"id": "gpo-a", "display_name": "policy-a", "source_states": {"acl": {"status": "observed"}}}],
            "acl": list(aces or [ace()])}


def test_nested_user_and_computer_paths_include_primary_group_and_ace():
    data = access.analyze_access(snapshot(), graph(), mode="filtering")
    assert data["state"] == "ok"
    assert {item["principal_type"] for item in data["items"]} == {"ad_user", "ad_computer"}
    user = next(item for item in data["items"] if item["principal"] == "user-a")
    assert user["path_keys"] == ["user-a", "group-a", "group-b"]
    assert user["path"] == "user-a → group-a → group-b → policy-a [ACE 0]"
    assert user["outcome"] == "allowed"
    assert user["graph_run_id"] == graph()["source"]["run_id"]


def test_cycles_and_diamond_paths_are_bounded_and_deterministic():
    source = graph()
    source["relations"] += [relation("group-b", "group-a"), relation("user-a", "group-b")]
    result = access.resolve_membership(source["entities"], source["relations"])
    assert result["cycles"] > 0
    assert result["paths"]["user-a"][f"{DOMAIN}-2102"] == ["user-a", "group-b"]
    assert not result["truncated"]


def test_depth_and_work_limits_preserve_unknown_instead_of_zero():
    source = graph()
    resolved = access.resolve_membership(source["entities"], source["relations"], max_depth=1)
    assert resolved["depth_limited"] and resolved["incomplete"]
    assert f"{DOMAIN}-2102" not in resolved["paths"]["user-a"]
    limited = access.resolve_membership(source["entities"], source["relations"], max_steps=1)
    assert limited["truncated"]
    result = access.analyze_access(snapshot(), source, mode="filtering", max_depth=1)
    assert result["state"] == "partial" and result["items"][0]["outcome"] == "unknown"


def test_distribution_groups_do_not_grant_security_membership():
    source = graph()
    source["entities"][2]["attributes"]["group_category"] = "Distribution"
    result = access.analyze_access(snapshot(), source, mode="filtering")
    assert result["items"][0]["outcome"] == "unknown"
    assert not any(item.get("principal") for item in result["items"])


@pytest.mark.parametrize("missing", ["unresolved_group_dns", "unresolved_primary_group_sid"])
def test_unresolved_memberships_do_not_claim_effective_access(missing):
    source = graph()
    source["entities"][0]["attributes"][missing] = ["unresolved"]
    data = access.analyze_access(snapshot(), source, mode="delegation")
    assert data["state"] == "partial"
    assert {item["outcome"] for item in data["items"]} == {"unknown"}


def test_read_and_apply_can_come_from_different_trustees_and_deny_is_honored():
    grant = ace(mask=0x100, object_type=access.APPLY_GUID)
    read = ace(1, sid="S-1-5-11", mask=0x20010)
    data = access.analyze_access(snapshot(grant, read), graph(), mode="filtering")
    assert {item["outcome"] for item in data["items"]} == {"allowed"}
    assert all(item["read_ace_ids"] == ["ace-1"] for item in data["items"])
    denied = ace(0, sid=f"{DOMAIN}-1101", mask=0x100, effect="Deny", object_type=access.APPLY_GUID)
    grant["ace_index"] = 2
    grant["id"] = "ace-2"
    data = access.analyze_access(snapshot(denied, read, grant), graph(), mode="filtering")
    assert next(item for item in data["items"] if item.get("principal") == "user-a")["outcome"] == "denied"
    assert next(item for item in data["items"] if item.get("principal") == "computer-a")["outcome"] == "allowed"


def test_explicit_allow_precedes_inherited_deny_and_read_is_required():
    allow = ace(mask=0x20010 | 0x100)
    deny = ace(1, effect="Deny", mask=0x100, inherited=True)
    data = access.analyze_access(snapshot(allow, deny), graph(), mode="filtering")
    assert all(item["outcome"] == "allowed" for item in data["items"] if item.get("principal"))
    data = access.analyze_access(snapshot(ace(mask=0x100)), graph(), mode="filtering")
    assert all(item["outcome"] == "denied" for item in data["items"])


def test_attribute_specific_aces_and_inherit_only_do_not_overclaim():
    assert access.ace_rights(ace(propagation_flags=2)) == set()
    assert access.ace_rights(ace(mask=0x30, object_type=access.APPLY_GUID)) == set()
    data = access.analyze_access(snapshot(ace(), ace(1, mask=0x10, object_type=access.APPLY_GUID)), graph(), mode="filtering")
    assert data["state"] == "partial" and all(item["outcome"] == "unknown" for item in data["items"])
    assert {"edit", "modify_permissions", "apply"} <= access.ace_rights(ace(mask=0x10000000))


@pytest.mark.parametrize("sid,kind,expected", [
    ("S-1-5-11", "", "broad_edit"), ("S-1-1-0", "", "broad_edit"),
    (f"{DOMAIN}-513", "ad_group", "broad_edit"), (f"{DOMAIN}-512", "ad_group", "admin_edit"),
    ("S-1-5-32-544", "ad_group", "admin_edit"), (f"{DOMAIN}-2102", "ad_group", "non_admin_group_edit"),
    (f"{DOMAIN}-520", "ad_group", "non_admin_group_edit"),
    (f"{DOMAIN}-1101", "ad_user", "direct_principal_edit"), (f"{DOMAIN}-9999", "", "unknown_trustee_edit"),
])
def test_delegation_risk_is_sid_based(sid, kind, expected):
    assert access.delegation_risk(sid, kind, domain_sid=DOMAIN) == expected


def test_risky_delegation_is_resolved_and_deny_does_not_raise_a_risk():
    source = graph()
    source["entities"][-1]["attributes"]["display_name"] = "Domain Admins"
    data = access.analyze_access(snapshot(), source, mode="delegation")
    assert {item["risk"] for item in data["items"]} == {"non_admin_group_edit"}
    data = access.analyze_access(snapshot(ace(effect="Deny")), source, mode="delegation")
    assert {item["risk"] for item in data["items"]} == {"none"}


def test_old_acl_and_graph_snapshots_and_row_limits_are_explicit():
    old = snapshot()
    del old["acl"]
    old["gpos"][0]["source_states"].pop("acl")
    data = access.analyze_access(old, graph(), mode="filtering")
    assert data["state"] == "partial" and data["items"][0]["outcome"] == "not_collected"
    source = graph()
    source["computers_collected"] = False
    data = access.analyze_access(snapshot(), source, mode="filtering")
    assert data["state"] == "partial" and all(item["outcome"] == "unknown" for item in data["items"])
    data = access.analyze_access(snapshot(), graph(), mode="delegation", max_rows=1)
    assert len(data["items"]) == 1 and data["coverage"]["truncated"]


def test_search_is_applied_before_the_effective_row_limit():
    data = access.analyze_access(snapshot(), graph(), mode="filtering", query="user-a", max_rows=1)
    assert data["items"][0]["principal"] == "user-a"
    data = access.analyze_access(snapshot(), graph(), mode="filtering", query="absent")
    assert data["items"] == []


def topology():
    root_dn = "DC=example,DC=invalid"
    root = {"id": "domain", "name": "domain-a", "scope_type": "domain", "distinguished_name": root_dn, "gpo_inheritance_blocked": False}
    ou = {"id": "ou", "name": "ou-a", "scope_type": "ou", "distinguished_name": f"OU=a,{root_dn}", "gpo_inheritance_blocked": True}
    child = {**ou, "id": "child", "name": "ou-b", "distinguished_name": f"OU=b,{ou['distinguished_name']}", "gpo_inheritance_blocked": False}
    data = snapshot()
    data.update(scopes=[root, ou, child], links=[{"id": "link-a", "gpo_id": "gpo-a", "scope_id": "domain", "enabled": True, "enforced": False}],
                source_states={"links": {"status": "observed"}})
    return data


def test_inheritance_blocks_enforcement_and_disabled_links():
    source = topology()
    data = access.linked_scopes(source)
    assert {item["scope_name"]: item["outcome"] for item in data["items"]} == {"domain-a": "linked", "ou-a": "blocked", "ou-b": "blocked"}
    source["links"][0]["enforced"] = True
    assert all(item["outcome"] == "linked" for item in access.linked_scopes(source)["items"])
    source["links"][0]["enabled"] = False
    assert all(item["outcome"] == "disabled" for item in access.linked_scopes(source)["items"])


def test_direct_links_are_not_blocked_and_sites_wmi_are_not_inferred():
    source = topology()
    source["links"][0]["scope_id"] = "ou"
    assert all(item["outcome"] == "linked" for item in access.linked_scopes(source)["items"])
    source["scopes"].append({"id": "site", "name": "site-a", "scope_type": "site", "distinguished_name": "CN=site-a,CN=Sites", "gpo_inheritance_blocked": False})
    source["links"][0]["scope_id"] = "site"
    source["gpos"][0]["wmi_filter_id"] = "wmi-a"
    data = access.linked_scopes(source)
    assert len(data["items"]) == 1
    assert data["items"][0]["wmi_state"] == "not_collected"
    assert data["state"] == "partial"
    source["wmi_filters"] = [{"id": "wmi-a", "name": "filter-a", "source_state": {"status": "observed"},
                              "queries": [{"namespace": "root/cimv2", "query": "SELECT * FROM Win32_OperatingSystem"}]}]
    data = access.linked_scopes(source)
    assert data["state"] == "ok"
    assert data["items"][0]["wmi_queries"] == ["root/cimv2: SELECT * FROM Win32_OperatingSystem"]
    assert access._dn_suffixes(r"OU=a\,b,DC=example,DC=invalid") == [r"OU=a\,b,DC=example,DC=invalid", "DC=example,DC=invalid", "DC=invalid"]


class FakeCursor:
    def __init__(self, source, entities, relations):
        self.source, self.entities, self.relations = source, entities, relations
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def execute(self, sql, params=()):
        self.calls.append((sql, params))

    def fetchone(self):
        return self.source

    def fetchall(self):
        rows = self.relations if "ad_context_relation_versions" in self.calls[-1][0] else self.entities
        return [{"attributes_json": row} for row in rows]


class FakeConnection:
    def __init__(self, cursor):
        self.cur = cursor

    def cursor(self):
        return self.cur


def test_reader_pins_one_authorized_domain_run_and_observed_versions():
    source = graph()
    metadata = {**source["source"], "domain_id": 7, "section_status": "complete", "record_count": 7,
                "scope_json": {"computer_membership_collected": True}}
    cursor = FakeCursor(metadata, source["entities"], source["relations"])
    loaded = access.load_directory_graph(snapshot(), domain_ids=[7], connection=FakeConnection(cursor))
    assert loaded["state"] == "ok" and loaded["computers_collected"]
    assert cursor.calls[2][1] == (DOMAIN, "example.invalid", snapshot()["observed_at"], [7], [7])
    for sql, params in cursor.calls[3:]:
        assert "evidence.source_run_id=%s::uuid" in sql and "valid_from_utc<=evidence.observed_at_utc" in sql
        assert params[:2] == (7, metadata["run_id"])
    cursor = FakeCursor(None, [], [])
    assert access.load_directory_graph(snapshot(), domain_ids=[7], connection=FakeConnection(cursor))["state"] == "not_collected"
    assert len(cursor.calls) == 3
    with pytest.raises(PermissionError):
        access.load_directory_graph(snapshot(), domain_ids=[], connection=FakeConnection(cursor))


def test_reader_marks_missing_records_and_old_computer_coverage():
    source = graph()
    cursor = FakeCursor({**source["source"], "domain_id": 7, "section_status": "complete", "record_count": 99, "scope_json": {}}, source["entities"], source["relations"])
    loaded = access.load_directory_graph(snapshot(), domain_ids=[7], connection=FakeConnection(cursor))
    assert loaded["state"] == "partial" and loaded["missing_records"] and not loaded["computers_collected"]


def production_snapshot():
    data = json.loads(Path("tests/fixtures/gpo_v2_reference_current.json").read_text(encoding="utf-8"))
    data["demo"] = False
    data["demo_notice"] = None
    return data


def test_optional_acl_contract_preserves_old_hash_and_validates_new_aces():
    old = production_snapshot()
    before = canonical_snapshot(old)
    assert "acl" not in validate_snapshot(old)
    assert canonical_snapshot(validate_snapshot(old)) == before
    new = deepcopy(old)
    new["acl"] = [ace(gpo_id=new["gpos"][0]["id"])]
    new["gpos"][0]["source_states"]["acl"] = {"status": "observed"}
    assert validate_snapshot(new)["acl"] == new["acl"]
    for field, value in [("gpo_id", "missing"), ("ace_index", True), ("access_mask", "write"), ("trustee_sid", "group-name"), ("object_type", "bad"), ("access_control_type", "unknown")]:
        invalid = deepcopy(new)
        invalid["acl"][0][field] = value
        with pytest.raises(GpoV2SourceContractError):
            validate_snapshot(invalid)
    del new["acl"]
    with pytest.raises(GpoV2SourceContractError, match="gpo_acl_array_required"):
        validate_snapshot(new)


def test_optional_computer_coverage_is_hash_protected_and_backward_compatible():
    bundle = {"schema_version": "ad-context-bundle/v1", "source_pack_id": "sli.windows.ad-context", "source_pack_version": "0.10.0",
              "run_id": "00000000-0000-4000-8000-000000000002", "mode": "full",
              "domain": {"sid": DOMAIN, "dns_name": "example.invalid"}, "scope": {"search_base": "DC=example,DC=invalid"},
              "observed_at_utc": "2026-10-07T00:00:00Z", "sections": [{"name": "directory_group_graph", "status": "complete", "record_count": 0, "duration_ms": 1, "error_code": None}], "records": []}
    old = validate_bundle(bundle)
    assert "computer_membership_collected" not in old["scope"]
    assert validate_bundle(old)["bundle_sha256"] == old["bundle_sha256"]
    bundle["scope"]["computer_membership_collected"] = True
    new = validate_bundle(bundle)
    assert new["scope"]["computer_membership_collected"] is True
    assert new["bundle_sha256"] != old["bundle_sha256"]
    bundle["scope"]["computer_membership_collected"] = "true"
    with pytest.raises(AdContextContractError):
        validate_bundle(bundle)
    bundle["scope"]["computer_membership_collected"] = True
    bundle["sections"][0]["status"] = "partial"
    with pytest.raises(AdContextContractError):
        validate_bundle(bundle)

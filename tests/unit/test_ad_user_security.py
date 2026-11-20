"""Daily-snapshot security facts and report rules, with no directory or DB."""
from copy import deepcopy

import pytest

from server.sli.core import ad_service_exceptions
from server.sli.plugins.ad.reports import users_security, users_v2_views
from server.sli.plugins.ad import directory_projection
from server.sli.plugins.ad.reports import users_v2_reporting
from server.sli.reporting.v2.reports import users
from tests.reporting.test_users_five_tabs import account, context

OBSERVED = "2026-10-16T00:00:00Z"
SID = "S-1-5-21-1-2-3-1001"
POLICY = {"password_age": 365, "inactivity": 90}


def user(**overrides):
    return account(1, sid=SID, passwordLastSet=OBSERVED, lastLogonTimestamp=OBSERVED,
                   userPrincipalName="fixture@directory.invalid", **overrides)


def row(value, **kwargs):
    return users_v2_views.user_row(value, OBSERVED, POLICY, **kwargs)


@pytest.mark.parametrize("field,bit", users_security.UAC_FLAGS.items())
def test_each_uac_bit_is_projected_without_mutating_snapshot(field, bit):
    source = user(userAccountControl=512 | bit)
    original = deepcopy(source)
    facts = users_security.facts(source)
    assert facts[field] is True
    assert all(facts[name] is (name == field) for name in users_security.UAC_FLAGS)
    assert source == original
    assert users_security.facts({**source, field: False})[field] is True


@pytest.mark.parametrize("uac", [None, "invalid", -1, True, 512.5])
def test_unknown_uac_never_fabricates_flags(uac):
    facts = users_security.facts(user(userAccountControl=uac, passwordNotRequired="false"))
    assert all(facts[name] is None for name in users_security.UAC_FLAGS)
    assert row(facts)["reason_keys"] == []


def test_explicit_boolean_attributes_work_without_raw_uac():
    result = row(user(passwordNotRequired=True, doesNotRequirePreAuth=True))
    assert set(result["reason_keys"]) == {"password_not_required", "kerberos_no_preauth"}
    assert all(reason["severity"] == "high" for reason in result["reasons"])


def test_protective_flags_are_visible_without_creating_a_risk():
    result = row(user(userAccountControl=512 | 0x40000 | 0x100000))
    assert result["smartcard_required"] is result["account_not_delegated"] is True
    assert len(result["flags"]) == 2
    assert result["reasons"] == []


def test_reversible_encryption_is_visible_and_requires_review():
    result = row(user(userAccountControl=512 | 0x80))
    assert result["reversible_encryption"] is True
    assert result["reason_keys"] == ["sensitive_uac_flag"]


@pytest.mark.parametrize("classes,spns,expected", [
    ([], [], None), ([], ["HTTP/service.invalid"], "spn"),
    (["top", "user", "computer", "msDS-ManagedServiceAccount"], [], "msa"),
    (["top", "user", "msDS-ManagedServiceAccount", "msDS-GroupManagedServiceAccount"], ["HTTP/service.invalid"], "gmsa"),
])
def test_service_classification_uses_spn_or_classes_only(classes, spns, expected):
    assert row(user(objectClasses=classes, servicePrincipalNames=spns))["service_account_type"] == expected
    assert users_security.facts({"samAccountName": "service-account$"})["serviceAccountType"] is None


@pytest.mark.parametrize("relation", ["direct", "nested", "primary"])
def test_spn_and_never_expiring_password_on_a_privileged_account(relation):
    value = user(userAccountControl=512 | 0x10000, servicePrincipalNames=["HTTP/service.invalid"],
                 memberships={"status": "observed", "effective": [{"id": "g:1", "watchGroup": True, "relation": relation}]})
    result = row(value)
    assert set(result["reason_keys"]) == {"spn_privileged", "privileged_password_never_expires", "watch_group_membership"}
    reasons = [reason for reason in result["reasons"] if reason["key"] in users_security.RISK_KEYS]
    assert all(reason["severity"] == "high" and reason["evidence"]["snapshot_at"] == OBSERVED for reason in reasons)


def test_direct_privilege_evidence_is_used_but_admin_count_alone_is_historical():
    value = user(adminCount=1, passwordNeverExpires=True, servicePrincipalNames=["HTTP/service.invalid"])
    assert row(value)["admin_count"] == 1
    assert row(value)["reasons"] == []
    value["privilegedMemberships"] = [{"group_id": 10, "relation": "direct"}]
    assert set(row(value)["reason_keys"]) == {"spn_privileged", "privileged_password_never_expires"}


@pytest.mark.parametrize("date,state,expected", [
    ("2025-10-16T00:00:00Z", "observed", False),
    ("2025-10-15T23:59:59Z", "observed", True),
    ("2025-10-15T23:59:59Z", "failed", False),
    ("2027-01-01T00:00:00Z", "observed", False),
    (None, "observed", False), ("invalid", "observed", False),
])
def test_spn_password_age_has_a_strict_365_day_boundary_and_no_unknown_verdict(date, state, expected):
    value = user(servicePrincipalNames=["HTTP/service.invalid"])
    value.update(passwordLastSet=date, sourceStates={"directory": {"status": state, "observed_at": OBSERVED}})
    result = row(value)
    assert ("spn_old_password" in result["reason_keys"]) is expected
    if expected:
        reason = next(reason for reason in result["reasons"] if reason["key"] == "spn_old_password")
        assert reason["severity"] == "medium"
        assert reason["evidence"]["password_last_set"] == date
    value["sourceStates"]["directory"]["observed_at"] = "2025-10-16T00:00:00Z"
    assert "spn_old_password" not in row(value)["reason_keys"]


@pytest.mark.parametrize("enabled", [True, False])
def test_service_exception_cannot_hide_unconditional_or_privileged_risks(enabled):
    value = user(userAccountControl=512 | 0x20 | 0x400000 | 0x10000,
                 servicePrincipalNames=["HTTP/service.invalid"], privilegedMemberships=[{"relation": "direct"}])
    value.update(enabled=enabled, passwordLastSet="2020-01-01T00:00:00Z", lastLogonTimestamp="2020-01-01T00:00:00Z")
    exceptions = {SID: {"sid": SID, "excluded_by": "fixture-admin", "excluded_at": OBSERVED}}
    result = row(value, service_exceptions=exceptions)
    assert set(result["reason_keys"]) == {"password_not_required", "kerberos_no_preauth", "spn_privileged", "privileged_password_never_expires"}
    assert result["service_exception"] == exceptions[SID]
    value.pop("servicePrincipalNames")
    result = row(value, service_exceptions=exceptions)
    assert result["service_exception"] is None and "password_age" in result["reason_keys"]


def test_exception_matches_only_exact_sid_and_service_accounts():
    value = user(servicePrincipalNames=["HTTP/service.invalid"])
    value["passwordLastSet"] = "2020-01-01T00:00:00Z"
    assert "spn_old_password" in row(value, service_exceptions={SID + "0": {"sid": SID + "0"}})["reason_keys"]


def test_risk_tab_includes_new_reasons_filters_and_exports_with_fakes(monkeypatch):
    snapshot = {"metadata": {"observed_at": OBSERVED, "coverage": {"state": "complete"}},
                "users": [user(userAccountControl=512 | 0x20)], "groups": []}
    monkeypatch.setattr(users, "_snapshots", lambda *_a, **_k: {"state": "ok", "current": snapshot})
    monkeypatch.setattr(users.ad_hygiene_policy, "thresholds", lambda: POLICY)
    monkeypatch.setattr(ad_service_exceptions, "configured", lambda: {})
    result = users._query(context("risk", reason="password_not_required"))
    assert result["filtered_count"] == result["coverage"]["risk_accounts"] == 1
    assert result["items"][0]["severity"] == "high"
    assert any(option["value"] == "password_not_required" for option in result["filter_options"]["reason"])
    csv, _ = users._export(context("risk"))
    assert "Пароль не требуется" in csv


def test_security_attributes_survive_both_directory_adapters():
    attrs = {"object_classes": ["user", "msDS-GroupManagedServiceAccount"], "user_account_control": 512 | 0x20,
             "service_principal_names": ["HTTP/service.invalid"], "admin_count": 1}
    item = {"entity_id": 1, "domain_id": 1, "display_name": "Synthetic account", "observed_at_utc": OBSERVED}
    sections = {(1, "directory_accounts"): {"observed_at": OBSERVED, "status": "observed"}}
    exact = {"versions": {1: {"directory_accounts": {"observed_at": OBSERVED, "attributes": attrs}}},
             "domains": {1: 1}, "aliases": {}, "sections": sections,
             "graph": {"references": {}, "groups": [], "user_edges": {}, "parent_edges": {}}}
    current = directory_projection.build_directory_projection(items=[item], coverage={}, requested_domain_ids=[1], exact_inputs=exact)
    legacy = users_v2_reporting._user(item, attrs, {}, group_state="observed")
    for snapshot_user in (current["users"][0], legacy):
        assert snapshot_user["objectClasses"] == attrs["object_classes"]
        result = row(snapshot_user)
        assert result["service_account_type"] == "gmsa" and result["admin_count"] == 1
        assert "password_not_required" in result["reason_keys"]


def test_report_does_not_derive_privilege_or_flags_from_denied_raw_fields(monkeypatch):
    from dataclasses import replace

    value = user(userAccountControl=512 | 0x20, adminCount=1, servicePrincipalNames=["HTTP/service.invalid"],
                 privilegedMemberships=[{"relation": "direct", "group_id": 10}])
    snapshot = {"metadata": {"observed_at": OBSERVED, "coverage": {"state": "complete"}}, "users": [value], "groups": []}
    monkeypatch.setattr(users, "_snapshots", lambda *_a, **_k: {"state": "ok", "current": snapshot})
    monkeypatch.setattr(users.ad_hygiene_policy, "thresholds", lambda: POLICY)
    monkeypatch.setattr(ad_service_exceptions, "configured", lambda: pytest.fail("restricted access read exceptions"))
    data = users._prepare(replace(context("risk"), field_access=lambda fields: fields <= {"identity_basic", "security", "technical"}))
    raw, result = data["rows"][0]
    assert "adminCount" not in raw and "privilegedMemberships" not in raw
    assert result["admin_count"] is None and "spn_privileged" not in result["reason_keys"]
    data = users._prepare(replace(context("risk"), field_access=lambda fields: fields <= {"identity_basic", "privilege", "technical"}))
    raw, result = data["rows"][0]
    assert "userAccountControl" not in raw
    assert result["password_not_required"] is None

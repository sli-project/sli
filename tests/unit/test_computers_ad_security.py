"""Computer snapshot and report regression tests; no directory or database."""
from copy import deepcopy
from datetime import datetime, timedelta

import pytest

from server.sli.reports import computers_v6_reporting as report
from server.sli.plugins.ad.reports.computer_security import unsupported_os
from server.sli.plugins.ad.reports.definitions import computers as definition
from server.sli.sources.computers_v6_source import validate_computers_v6_snapshot
from test_agent_ad_snapshot import NOW, config, directory
from sli_agent.ad_snapshot import LDAP_ATTRIBUTES, normalize_capture


def capture(**properties):
    raw = directory(1)
    computer = next(obj for obj in raw["objects"] if obj["kind"] == "ad_computer")
    computer["properties"].update(properties)
    return normalize_capture(raw, config(expensive_flags={}), observed_at=NOW)


def row(**attributes):
    return {"entity_id": 1, "domain_id": 1, "display_name": "computer-1",
            "observed_at_utc": NOW.isoformat(), "attributes": {"attributes": {
                "enabled": True, "operating_system": "Windows 11 Pro", **attributes}}}


def codes(item):
    return {reason["code"] for reason in item["reasons"]}


def fake_report(monkeypatch, source_row, overlay=None):
    queries = []

    def query(sql, *args, **kwargs):
        queries.append(sql)
        return [source_row]

    monkeypatch.setattr(report, "query_rows_bounded", query)
    monkeypatch.setattr(report, "_coverage", lambda _: {"state": "complete"})
    monkeypatch.setattr(report, "_load_computers_v6_source_overlay", lambda _: overlay or {})
    monkeypatch.setattr(report, "_semantic_rows", lambda _: [])
    monkeypatch.setattr(report, "_load_snapshot_comparison", lambda _: {})
    return queries


def test_canonical_computer_query_does_not_require_legacy_object_class(monkeypatch):
    queries = fake_report(monkeypatch, row())
    result = report.get_computers_v6_report(domain_ids=[1], view="all")
    assert result["filtered_count"] == 1
    assert "entity_type.value='ad_computer'" in queries[0]
    assert "object_class" not in queries[0]


@pytest.mark.parametrize("age,expected", [(24, "complete"), (24.01, "stale")])
def test_snapshot_freshness_boundary(monkeypatch, age, expected):
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW

    monkeypatch.setattr(report, "datetime", Clock)
    state = report._source_snapshot_public_state({"base_inventory_status": "observed",
        "collection_status": "complete", "source_completed_at_utc": (NOW - timedelta(hours=age)).isoformat()})
    assert state["state"] == expected


def test_stale_computer_snapshot_marks_report_even_with_fresh_directory(monkeypatch):
    fake_report(monkeypatch, row(), {"source_snapshot": {
        "state": "stale", "completed_at_utc": (NOW - timedelta(days=2)).isoformat()}})
    result = report.get_computers_v6_report(domain_ids=[1], view="all")
    assert result["state"] == "stale"
    assert result["coverage"]["state"] == "stale"


def test_old_overlay_cannot_replace_new_directory_computer():
    item = report._item(row(operating_system="Windows 11 Pro"), 90)
    item["object_guid"] = "00000000-0000-0000-0000-000000000001"
    report._apply_computers_v6_source_overlay(item, {"source_snapshot": {
        "completed_at_utc": (NOW - timedelta(days=30)).isoformat()}, "by_guid": {
            item["object_guid"]: {"osName": "Windows 7", "collectedAt": (NOW - timedelta(days=30)).isoformat()}}})
    assert item["operating_system"] == "Windows 11 Pro"


@pytest.mark.parametrize("os_name", ["Windows XP Professional", "Windows 7 Professional",
    "Windows 8.1 Pro", "Windows 8 Pro", "Windows Vista Business", "Windows Server 2003 R2", "Windows Server 2008",
    "Windows Server 2008 R2 Standard", "Windows Server 2012", "Windows Server 2012 R2 Standard"])
def test_unsupported_windows_has_explained_attention_reason(os_name):
    item = report._item(row(operating_system=os_name), 90)
    reason = next(reason for reason in item["reasons"] if reason["code"] == "unsupported_os")
    assert reason["label"] == "ОС без поддержки"
    assert reason["support_end_date"]
    assert reason["limitation"]


@pytest.mark.parametrize("os_name", [None, "Windows 11 Pro", "Windows Server 2022", "Windows 10 Enterprise LTSC", "Other OS"])
def test_unknown_or_supported_edition_is_not_declared_unsupported(os_name):
    assert "unsupported_os" not in codes(report._item(row(operating_system=os_name), 90))


@pytest.mark.parametrize("days,enabled,expected", [(90, True, False), (91, True, True), (91, False, False), (None, True, False)])
def test_enabled_computer_inactivity_owner_threshold(days, enabled, expected, monkeypatch):
    item_row = row(enabled=enabled, last_logon_utc=(NOW - timedelta(days=days)).isoformat() if days else None)
    fake_report(monkeypatch, item_row)
    item = report.get_computers_v6_report(domain_ids=[1], view="all")["items"][0]
    assert ("stale_activity" in codes(item)) is expected
    threshold = next(param for param in definition.REPORT.params if param.key == "threshold_days")
    assert threshold.default == "90"
    if days == 90 and enabled:
        assert item["activity_state"] == "recent"
        assert item["activity"]["evidence"]["threshold_days"] == 90


def test_agent_security_metadata_survives_snapshot_and_overlay_without_passwords():
    families = capture(**{"useraccountcontrol": 8192 | 524288,
        "mslaps-passwordexpirationtime": "2026-10-09T12:00:00Z",
        "ms-mcs-admpwdexpirationtime": "2026-10-07T12:00:00Z",
        "msds-allowedtodelegateto": ["HTTP/service.invalid"],
        "msds-allowedtoactonbehalfofotheridentity": True,
        "mslaps-password": "discard-secret-marker"})
    snapshot = validate_computers_v6_snapshot(families["computers_v6"][0])
    source = snapshot["objects"][0]
    assert source["deviceType"] == "domain_controller"
    assert source["lapsPasswordExpiration"] == "2026-10-09T12:00:00Z"
    assert source["legacyLapsPasswordExpiration"] == "2026-10-07T12:00:00Z"
    assert source["resourceBasedDelegationPresent"] is True
    assert "discard-secret-marker" not in str(families)
    assert not {"mslaps-password", "ms-mcs-admpwd", "mslaps-encryptedpassword"} & set(LDAP_ATTRIBUTES)
    item = report._item(row(), 90)
    item["object_guid"] = source["objectGuid"]
    report._apply_computers_v6_source_overlay(item, {"by_guid": {source["objectGuid"]: source},
        "source_snapshot": {"completed_at_utc": NOW.isoformat()}})
    report._requalify_computers_v6_item(item, 90)
    assert item["computer_type"] == "domain_controller"
    assert item["laps"]["state"] == "metadata_present"
    assert item["delegation"] == {"unconstrained": True, "constrained": True, "resource_based": True}
    assert "unconstrained_delegation" in codes(item)
    assert report._view_matches(item, "server_enabled")


def test_laps_expired_and_missing_metadata_are_distinct():
    expired = report._item(row(laps_password_expiration_utc="2026-10-07T12:00:00Z"), 90)
    assert expired["laps"]["state"] == "expired"
    assert "laps_expired" in codes(expired)
    unknown = report._item(row(), 90)
    assert unknown["laps"]["state"] == "unknown"
    assert "laps_expired" not in codes(unknown)


def test_snapshot_classification_does_not_lose_agent_workstation_type():
    snapshot = capture(operatingsystem="Windows 11 Pro")["computers_v6"][0]
    source = snapshot["objects"][0]
    item = report._item(row(operating_system=None), 90)
    item["object_guid"] = source["objectGuid"]
    report._apply_computers_v6_source_overlay(item, {"by_guid": {source["objectGuid"]: deepcopy(source)}})
    assert item["computer_type"] == "workstation"


@pytest.mark.parametrize("stamp,expected", [
    ("2020-01-14T23:59:59+00:00", None), ("2020-01-15T00:00:00+00:00", "2020-01-14"),
])
def test_os_support_uses_evaluation_date_not_hardcoded_ended_state(stamp, expected):
    assert unsupported_os("Windows 7 Professional", None, datetime.fromisoformat(stamp)) == expected


@pytest.mark.parametrize("properties,state,unconstrained,constrained,rbcd", [
    ({"useraccountcontrol": 512}, "unknown", False, None, None),
    ({"useraccountcontrol": 512, "msds-allowedtodelegateto": [],
      "msds-allowedtoactonbehalfofotheridentity": False}, "unknown", False, False, False),
    ({"useraccountcontrol": 512, "ms-mcs-admpwdexpirationtime": "2026-10-09T12:00:00Z"},
     "metadata_present", False, None, None),
])
def test_snapshot_preserves_unknown_absent_and_legacy_security_metadata(properties, state, unconstrained, constrained, rbcd):
    source = capture(**properties)["computers_v6"][0]["objects"][0]
    item = report._item(row(), 90)
    item["object_guid"] = source["objectGuid"]
    report._apply_computers_v6_source_overlay(item, {"by_guid": {source["objectGuid"]: source},
        "source_snapshot": {"completed_at_utc": NOW.isoformat()}})
    assert item["laps"]["state"] == state
    assert item["delegation"] == {"unconstrained": unconstrained, "constrained": constrained, "resource_based": rbcd}


def test_dc_is_filterable_separately_and_server_metrics_still_partition(monkeypatch):
    fake_report(monkeypatch, row(user_account_control=8192))
    result = report.get_computers_v6_report(domain_ids=[1], view="server_enabled", computer_type="domain_controller")
    assert result["filtered_count"] == 1
    assert result["items"][0]["computer_type"] == "domain_controller"
    assert result["summary"]["server_enabled"] == result["summary"]["total_computers"] == 1

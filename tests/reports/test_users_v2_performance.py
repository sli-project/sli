"""Cold Users V2 requests use bulk inputs and preserve the snapshot contract."""
from unittest.mock import patch

import pytest

from scripts.dev.profile_users_v2 import SyntheticDirectory
from server.sli.reporting.v2.reports import users as report
from server.sli.reports import ad_hygiene_policy, users_reporting, users_v2_reporting
from tests.reporting.test_reporting_v2_field_access import access, call, grant


def _previous_snapshot():
    """The previous adapter's two-page merge, using the unchanged V1 mode."""
    common = {"domain_ids": [1], "limit": users_reporting.USERS_INPUT_LIMIT,
              "max_page_limit": users_reporting.USERS_INPUT_LIMIT}
    active = users_reporting.get_users_report(view="active", **common)
    disabled = users_reporting.get_users_report(view="disabled", **common)
    merged = {int(item["entity_id"]): dict(item) for item in [*active["items"], *disabled["items"]]}
    for item in users_v2_reporting._directory_user_population(domain_ids=[1]):
        merged.setdefault(int(item["entity_id"]), item)
    coverage = dict(active["coverage"])
    projection = users_v2_reporting.build_directory_projection(
        items=[merged[key] for key in sorted(merged)], coverage=coverage, requested_domain_ids=[1],
    )
    return users_v2_reporting.snapshot_from_directory_projection(projection, coverage=coverage, active=active)


@pytest.mark.parametrize("size", [1500, 3000])
def test_cold_enabled_response_has_constant_database_query_count(size, monkeypatch):
    directory = SyntheticDirectory(size)
    with directory.installed():
        monkeypatch.setattr(users_reporting, "evaluate_account_risks", lambda *_a, **_k: pytest.fail("V2 read V1 risks"))
        fields = report.ALL_FIELDS
        response, status = call(monkeypatch, report.REPORT, access(grant(fields), key=report.REPORT_KEY),
                                "/data", {"tab": ["all"], "account_state": ["enabled"], "limit": ["100"]}).sent[-1]
    assert status == 200
    assert response["filtered_count"] == sum(row["attributes"]["attributes"]["enabled"] is True for row in directory.accounts)
    assert len(response["items"]) == 100
    # Nine bulk inventory queries, including two alias batches, two policy
    # reads and one service-exception setting read per request.
    assert sum(directory.calls.values()) == 12
    assert "setting:reports.domain_fqdn" not in directory.calls
    assert directory.calls["aliases"] == 2
    assert directory.calls["complete_population"] == 1
    assert all(count == 1 for key, count in directory.calls.items() if key != "aliases")
    assert "acceptances" not in directory.calls


@pytest.mark.parametrize("size,cap", [(0, None), (120, None), (1500, None), (1500, 100), (1500, 1000)])
def test_single_inventory_snapshot_matches_previous_merge(size, cap, monkeypatch):
    if cap:
        monkeypatch.setattr(users_reporting, "USERS_INPUT_LIMIT", cap)
        monkeypatch.setattr(users_v2_reporting, "USERS_INPUT_LIMIT", cap)
    with SyntheticDirectory(size).installed():
        previous = _previous_snapshot()
        current = users_v2_reporting.build_users_v2_snapshot(domain_ids=[1])
    # Includes unknown enabled state, $-suffixed users, direct privileges,
    # primary/nested memberships, coverage, missing facts and source states.
    assert current == previous
    if cap is None:
        assert len(current["users"]) == size


def test_legacy_report_reads_policy_once_and_keeps_risk_evidence():
    with SyntheticDirectory(120).installed(), patch.object(ad_hygiene_policy, "thresholds", wraps=ad_hygiene_policy.thresholds) as thresholds:
        response = users_reporting.get_users_report(domain_ids=[1], view="active", limit=100)
    assert thresholds.call_count == 1
    assert response["items"]
    risk = next(item for item in response["items"][0]["risks"] if item["risk_key"] == "password_older_than_90_days")
    assert risk["evidence"]["threshold_days"] == 90
    assert risk["qualification"] == "matched"


def test_enabled_permission_denial_precedes_inventory_reads(monkeypatch):
    with SyntheticDirectory(1500).installed() as directory:
        response, status = call(monkeypatch, report.REPORT,
                                access(grant({"identity_basic"}), key=report.REPORT_KEY),
                                "/data", {"tab": ["all"], "account_state": ["enabled"]}).sent[-1]
    assert status == 403 and response["state"] == "denied"
    assert not directory.calls


def test_restricted_fields_still_use_projected_snapshot(monkeypatch):
    with SyntheticDirectory(120).installed():
        response, status = call(monkeypatch, report.REPORT,
                                access(grant({"identity_basic", "security"}), key=report.REPORT_KEY),
                                "/data", {"tab": ["all"], "account_state": ["enabled"]}).sent[-1]
    assert status == 200 and response["items"]
    assert all("department" not in row and "direct_groups" not in row and "dn" not in row for row in response["items"])


def _two_population_snapshot(domain_ids=None):
    """Pre-reuse V2 path, including its independently limited legacy input."""
    active = users_reporting.get_users_report(
        domain_ids=domain_ids, view="active", _directory_only=True,
        limit=users_reporting.USERS_INPUT_LIMIT,
        max_page_limit=users_reporting.USERS_INPUT_LIMIT,
    )
    merged = {int(item["entity_id"]): dict(item) for item in active["items"]}
    for item in users_v2_reporting._directory_user_population(domain_ids=domain_ids):
        merged.setdefault(int(item["entity_id"]), item)
    coverage = dict(active["coverage"])
    projection = users_v2_reporting.build_directory_projection(
        items=[merged[key] for key in sorted(merged)], coverage=coverage, requested_domain_ids=domain_ids,
    )
    return users_v2_reporting.snapshot_from_directory_projection(projection, coverage=coverage, active=active)


@pytest.mark.parametrize("size,cap", [(0, 100), (99, 100), (100, 100), (101, 100), (220, 100), (1500, 10000)])
def test_reuse_complete_population_only_when_untruncated(size, cap, monkeypatch):
    monkeypatch.setattr(users_reporting, "USERS_INPUT_LIMIT", cap)
    monkeypatch.setattr(users_v2_reporting, "USERS_INPUT_LIMIT", cap)
    directory = SyntheticDirectory(size)
    # Concentrate $ accounts before the cap. With truncation, the separately
    # filtered legacy read must still reach regular accounts beyond that cap.
    for row in directory.accounts[:min(50, size)]:
        attrs = row["attributes"]["attributes"]
        attrs["sam_account_name"] = f"fixture-{row['entity_id']}$"
    with directory.installed():
        expected = _two_population_snapshot([1])
        directory.calls.clear()
        actual = users_v2_reporting.build_users_v2_snapshot(domain_ids=[1])
    assert actual == expected
    assert directory.calls["complete_population"] == 1
    assert directory.calls["legacy_population"] == (1 if size > cap else 0)
    if size > cap:
        assert any(user["entityId"] > cap for user in actual["users"])


def test_reused_rows_match_nested_sql_filter_and_recheck_domain_scope():
    directory = SyntheticDirectory(3)
    directory.accounts[0]["attributes"]["attributes"]["sam_account_name"] = "nested$"
    directory.accounts[1]["attributes"] = {"sam_account_name": "flat$", "enabled": True}
    directory.accounts[2]["domain_id"] = 2
    with directory.installed():
        response = users_reporting.get_users_report(
            domain_ids=[1], _directory_only=True, _directory_rows=directory.accounts,
        )
    assert [row["entity_id"] for row in response["items"]] == [2]
    assert directory.calls["legacy_population"] == 0


def test_empty_scope_rejects_reused_rows_without_database_reads():
    directory = SyntheticDirectory(3)
    with directory.installed():
        response = users_reporting.get_users_report(
            domain_ids=[], _directory_only=True, _directory_rows=directory.accounts,
        )
    assert response["items"] == []
    assert not directory.calls

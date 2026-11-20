"""Synthetic AD report supplements; no database, DNS or live sources."""
from datetime import datetime, timedelta, timezone

import pytest

from server.sli.plugins.ad.reports import report_additions as additions, review_checks
from server.sli.plugins.ad.reports.definitions import computers, users
from server.sli.reporting.v2.definition import QueryContext
from tests.reporting.test_ad_review_checks import bundle, computer, rows, by_key
from tests.reporting.test_reporting_v2_field_access import access, call, grant

NOW = datetime(2026, 10, 17, 3, tzinfo=timezone.utc)
GUID = "00000000-0000-4000-8000-000000000001"
HOST = {"entity_id": 1, "object_guid": GUID, "domain_id": 2}


@pytest.fixture(autouse=True)
def no_database(monkeypatch):
    monkeypatch.setattr(additions, "query_rows_bounded", lambda *args, **kwargs: pytest.fail("unexpected database read"))


def agent(**kwargs):
    return {"entity_id": 1, "domain_id": 2, "object_guid": GUID,
            "created_at": NOW - timedelta(days=10), "bound_at": NOW - timedelta(days=10), "last_seen": NOW - timedelta(minutes=3),
            "version": "1.2.3", "status": "active", **kwargs}


def test_registry_matching_is_domain_scoped_and_not_by_host_name():
    assert additions.agent_status(HOST, 2, [agent()], at=NOW)["state"] == "installed"
    assert additions.agent_status(HOST, 3, [agent()], at=NOW)["state"] == "absent"
    assert additions.agent_status({"object_guid": "different", "display_name": "same"}, 2, [agent()], at=NOW)["state"] == "absent"
    assert additions.agent_status(HOST, 2, [agent(), agent(entity_id=3)], at=NOW)["state"] == "unknown"


def test_registry_failure_unbound_or_truncated_is_unknown():
    for registry in (None, [agent(entity_id=None, object_guid=None)], [agent()] * 10001):
        assert additions.agent_status(HOST, 2, registry, at=NOW)["state"] == "unknown"
    assert additions.agent_status(HOST, 2, [], at=NOW)["state"] == "absent"


def test_silent_agent_keeps_signal_age_and_never_becomes_absent():
    status = additions.agent_status(HOST, 2, [agent(last_seen=NOW - timedelta(days=3))], at=NOW)
    assert status["state"] == "silent" and status["age_seconds"] == 3 * 86400
    status = additions.agent_status(HOST, 2, [agent(last_seen=NOW + timedelta(seconds=1))], at=NOW)
    assert status["age_seconds"] is None


def test_registration_after_baseline_does_not_invent_historical_status():
    assert additions.agent_status(HOST, 2, [agent(created_at=NOW + timedelta(days=1))], at=NOW)["state"] == "unknown"
    assert additions.agent_status(HOST, 2, [agent(bound_at=NOW + timedelta(days=1))], at=NOW)["state"] == "unknown"
    assert additions.agent_status(HOST, 2, [], at="")["state"] == "unknown"


def test_multiple_instances_use_the_latest_present_signal_and_confirmed_removal():
    removed = agent(removal_state="state_cleaned", removed_at=NOW - timedelta(hours=1))
    assert additions.agent_status(HOST, 2, [removed], at=NOW)["state"] == "absent"
    assert additions.agent_status(HOST, 2, [removed], at=NOW - timedelta(days=1))["state"] == "installed"
    live = agent(last_seen=NOW - timedelta(minutes=1))
    assert additions.agent_status(HOST, 2, [removed, live], at=NOW)["age_seconds"] == 60
    assert additions.agent_status(HOST, 2, [agent(last_seen=NOW - timedelta(days=3)), live], at=NOW)["state"] == "installed"


def test_dns_requires_observed_agent_source_and_date():
    raw = {"ip_addresses": ["192.0.2.1"], "evidence": {"network_sources": {"dns_addresses": {
        "status": "observed", "observed_at": NOW.isoformat()}}}}
    assert additions.dns_observation(raw)["addresses"] == ["192.0.2.1"]
    raw["evidence"]["network_sources"]["dns_addresses"]["status"] = "failed"
    assert additions.dns_observation(raw)["addresses"] == []
    assert additions.dns_observation({"ip_addresses": ["192.0.2.1"]})["observed_at_utc"] is None


def test_computer_inventory_exposes_dated_dns_and_live_registry(monkeypatch):
    monkeypatch.setattr(additions, "load_agents", lambda ids: [agent()])
    monkeypatch.setattr(computers, "get_computers_v6_report", lambda **kwargs: {
        "state": "available", "items": [{**HOST, "ip_addresses": ["192.0.2.1"], "evidence": {
            "network_sources": {"dns_addresses": {"status": "observed", "observed_at": NOW.isoformat()}}}}]})
    item = computers._query(QueryContext({}, {}, domain_ids=[2], tab="computers"))["items"][0]
    assert item["dns_ip"]["addresses"] == ["192.0.2.1"]
    assert item["sli_agent"]["version"] == "1.2.3"


def test_no_agent_count_new_and_silent_are_distinct():
    old = computer(1, sli_agent={"state": "absent"})
    new = computer(2, sli_agent={"state": "absent"})
    silent = computer(3, sli_agent={"state": "silent"})
    result = rows("computers", [bundle([old, new, silent], [old], [old])], since=NOW.isoformat())
    check = by_key(result, "no_sli_agent")
    assert check["total"] == 2 and check["new_count"] == 1 and check["severity"] == "medium"
    assert check["change"] is None
    check = by_key(rows("computers", [bundle([computer()])]), "no_sli_agent")
    assert check["total"] is None and check["new_count"] is None


def test_check_preview_keeps_dns_provenance():
    obj = review_checks._computer({"objectGuid": GUID, "ipv4s": ["192.0.2.1"], "sources": {
        "dns": {"status": "observed", "observed_at": NOW.isoformat()}}})
    assert obj["dns_ip"]["addresses"] == ["192.0.2.1"]


def test_check_query_enriches_current_and_comparable_baselines(monkeypatch):
    baseline = computer(1)
    monkeypatch.setattr(review_checks, "load_snapshots", lambda *args: [bundle([baseline, computer(2)], [baseline], [baseline])])
    monkeypatch.setattr(review_checks, "previous_login", lambda principal: NOW.isoformat())
    monkeypatch.setattr(review_checks, "load_events", lambda *args: ([], False))
    monkeypatch.setattr(additions, "load_agents", lambda ids: [])
    data = review_checks.query(computers.REPORT, QueryContext({}, {}, domain_ids=[1]), "computers")
    check = by_key(data, "no_sli_agent")
    assert check["total"] == 2 and check["new_count"] == 1
    assert check["objects"][0]["sli_agent"]["state"] == "absent"


def test_last_workplace_uses_sid_domain_and_interactive_projection(monkeypatch):
    seen = []
    def read(sql, params, **kwargs):
        seen.append((sql, params))
        return [{"domain_id": 2, "sid": "synthetic-sid", "computer_name": "synthetic-host",
                 "computer_object_guid": GUID, "observed_at_utc": NOW.isoformat(), "logon_type": "10"}]
    monkeypatch.setattr(additions, "query_rows_bounded", read)
    population = [{"entityId": 1, "domainId": 2, "sid": "synthetic-sid"},
                  {"entityId": 3, "domainId": 3, "sid": "synthetic-sid"}]
    result = additions.last_workplaces(population, [2])
    assert list(result) == [1] and result[1]["kind"] == "rdp"
    assert "f.logon_type in ('2','10','11')" in seen[0][0]
    assert seen[0][1][:2] == ([2], [2])
    assert additions.last_workplaces([population[0], {**population[0], "entityId": 2}], [2]) == {}


def test_optional_reader_failure_is_unknown_without_private_errors(monkeypatch):
    def fail(*args, **kwargs):
        raise RuntimeError("synthetic private database detail")
    monkeypatch.setattr(additions, "query_rows_bounded", fail)
    assert additions.load_agents([2]) is None
    assert additions.last_workplaces([{"sid": "synthetic-sid"}], [2]) == {}


def test_registry_uses_the_granted_provenance_view_instead_of_private_identifiers(monkeypatch):
    seen = []
    def read(sql, params, **kwargs):
        seen.append((sql, params))
        return []
    monkeypatch.setattr(additions, "query_rows_bounded", read)
    assert additions.load_agents([2]) == []
    sql, params = seen[0]
    assert "core_entity_identifiers" not in sql
    assert "core_entity_scope_resources" in sql
    assert "r.plugin_id='sli.workstations'" in sql
    assert "r.source_instance_id=agent.host_id::text" in sql
    assert "r.resolution='resolved'" in sql
    assert "a.source_entity_id=r.entity_id" in sql
    assert "having count(distinct computer_entity_id)=1" in sql
    assert params == ([2], [2])


def test_last_workplace_field_requires_both_security_and_technical():
    column = next(column for column in users.REPORT.columns if column.key == "last_workplace")
    assert column.field_categories == frozenset({"security", "technical"})


def test_native_workplaces_reuse_grants_and_choose_newest_source(monkeypatch):
    from server.sli.plugins.workstations.scope import WorkstationScopeAdapter
    calls = []
    monkeypatch.setattr(WorkstationScopeAdapter, "agent_keys", lambda self, decision, key, action, fields: (
        calls.append((key, action, fields)) or ("synthetic-agent",)))
    def read(sql, params, **kwargs):
        native = "ad_report_native_workplaces" in sql
        if native:
            assert params[:3] == (["synthetic-agent"], [2], [2])
        return [{"domain_id": 2, "sid": "synthetic-sid", "computer_name": "synthetic-native" if native else "synthetic-ad",
                 "computer_id": 7, "computer_object_guid": GUID, "logon_type": "2" if native else "10",
                 "observed_at_utc": (NOW + timedelta(minutes=1) if native else NOW).isoformat()}]
    monkeypatch.setattr(additions, "query_rows_bounded", read)
    found = additions.last_workplaces([{"entityId": 1, "domainId": 2, "sid": "synthetic-sid"}], [2], context=QueryContext({}, {}))
    assert found[1]["computer"] == "synthetic-native" and found[1]["kind"] == "local"
    assert calls[0][:2] == ("workstations.logons", "view")


def test_native_reader_without_workstation_grant_cannot_read_database():
    assert additions._native_workplaces(QueryContext({}, {}), [2], ["synthetic-sid"]) == []


@pytest.mark.parametrize("fields,visible", [({"identity_basic", "security"}, False),
                                          ({"identity_basic", "technical"}, False),
                                          ({"identity_basic", "security", "technical"}, True)])
def test_last_workplace_metadata_is_projected_by_atomic_field_grant(monkeypatch, fields, visible):
    decision = access(grant(fields, ids=(2,)), key=users.REPORT_KEY)
    payload, status = call(monkeypatch, users.REPORT, decision).sent[-1]
    assert status == 200
    assert any(column["key"] == "last_workplace" for column in payload["columns"]) is visible
    current = {"metadata": {"observed_at": NOW.isoformat(), "collection_status": "complete"},
               "users": [{"id": "synthetic-user", "entityId": 1, "domainId": 2, "sid": "synthetic-sid",
                          "samAccountName": "synthetic-account", "displayName": "Synthetic account", "enabled": True}]}
    monkeypatch.setattr(users, "_snapshots", lambda *args, **kwargs: {"state": "ok", "current": current})
    monkeypatch.setattr(users.ad_hygiene_policy, "thresholds", lambda: {"password_age": 365, "inactivity": 90})
    monkeypatch.setattr(users.ad_service_exceptions, "configured", lambda: {})
    calls = []
    def workplaces(population, ids, **kwargs):
        calls.append(ids)
        return {1: {"computer": "synthetic-host", "at_utc": NOW.isoformat(), "kind": "rdp"}}
    monkeypatch.setattr(additions, "last_workplaces", workplaces)
    data, status = call(monkeypatch, users.REPORT, decision, "/data", {"tab": ["all"], "account_state": ["enabled"], "domain_id": ["2"]}).sent[-1]
    if "security" not in fields:
        assert status == 403 and not calls
        return
    assert status == 200
    assert bool(calls) is visible
    assert (bool(data["items"]) and "last_workplace" in data["items"][0]) is visible

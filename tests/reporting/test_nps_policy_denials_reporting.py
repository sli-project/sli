from datetime import datetime, timedelta, timezone

import pytest

from server.sli.reports import nps_policy_denials_reporting as nps


START = datetime(2026, 10, 1, tzinfo=timezone.utc)
END = START + timedelta(days=7)


def fact(event_id, *, denied=True, policy="policy-a", nas="nas-a", reason="16", account="account-a", previous=False):
    return {
        "source_event_id": event_id, "normalized_event_id": f"fact-{event_id}",
        "occurred_at_utc": START - timedelta(days=1) if previous else START,
        "semantic_type": nps.DENIED if denied else nps.ALLOWED,
        "facts_json": {"network_policy": policy, "nas_identifier": nas, "reason_code": reason,
                       "authentication_type": "method-a", "authentication_provider": "provider-a"},
        "roles_json": {"affected_entity": account},
        "quality_json": {"identity_roles": {"affected_entity": {"state": "resolved", "provisional": False}}},
    }


def compose(current, previous=(), **filters):
    return nps.compose_policy_denials(current, previous, start=START, end=END, **filters)


def test_decisions_share_and_unknown_identities_are_separate():
    payload = compose([fact(1), fact(2, denied=False), fact(3, account=None), fact(4, policy=None, reason=None)])
    assert payload["metrics"]["allowed"] == 1
    assert payload["metrics"]["denied"] == 3
    assert payload["metrics"]["denial_share"] == 75
    assert payload["metrics"]["affected_accounts"] == 1
    assert payload["metrics"]["unknown_identity_denials"] == 1
    assert payload["metrics"]["missing_policy"] == 1
    assert payload["metrics"]["missing_reason"] == 1
    assert len(payload["items"]) == 2
    assert [row["event_id"] for row in payload["events"]] == [6273, 6272, 6273, 6273]
    assert payload["coverage"]["current"]["source_completeness"] == "not_proven"


def test_growth_compares_equal_windows_and_counts_policy_nas_totals():
    payload = compose([fact(1), fact(2), fact(3, reason="36")], [fact(4, previous=True)])
    row = next(row for row in payload["items"] if row["reason_code"] == "16")
    assert row["previous_denied"] == 1
    assert row["growth"] == 1
    assert row["first_denial_utc"] == row["last_denial_utc"]
    assert payload["metrics"]["growing_policies"] == 1
    assert payload["metrics"]["growing_nas"] == 1
    assert payload["coverage"]["previous"]["from_utc"] == "2026-09-24T00:00:00Z"


def test_minimums_filter_groups_without_redefining_decision_share():
    payload = compose([fact(1), fact(2, denied=False), fact(3, policy="policy-b")], min_decisions=2, min_growth=1)
    assert len(payload["items"]) == 1
    assert payload["items"][0]["decisions"] == 2
    assert payload["items"][0]["denial_share"] == 50
    assert payload["metrics"]["denied"] == 2


def test_truncation_suppresses_growth_and_labels_sample():
    payload = compose([fact(1)], previous_truncated=True)
    assert payload["items"][0]["growth"] is None
    assert payload["metrics"]["growing_policies"] is None
    assert payload["coverage"]["previous"]["state"] == "truncated"
    assert compose([fact(1)], current_truncated=True)["coverage"]["current"]["state"] == "truncated"
    assert compose([fact(1)], previous_truncated=True, min_growth=1)["items"] == []


def test_provisional_accounts_never_inflate_distinct_accounts():
    row = fact(1)
    row["quality_json"]["identity_roles"]["affected_entity"]["provisional"] = True
    payload = compose([row])
    assert payload["metrics"]["affected_accounts"] == 0
    assert payload["items"][0]["unknown_identity_denials"] == 1


def test_duplicate_replay_facts_cannot_silently_double_counts():
    with pytest.raises(ValueError, match="duplicate_source_event"):
        compose([fact(1), fact(1)])


def test_previous_only_and_reasonless_groups_remain_distinct():
    payload = compose([fact(1, reason=None), fact(2, reason="16")], [fact(3, previous=True, policy="old-policy")])
    assert len(payload["items"]) == 2
    assert {row["reason_code"] for row in payload["items"]} == {None, "16"}
    assert payload["metrics"]["growing_policies"] == 1


def test_provider_is_part_of_the_slice():
    other = fact(2)
    other["facts_json"]["authentication_provider"] = "provider-b"
    assert len(compose([fact(1), other])["items"]) == 2


def test_domain_options_never_read_without_a_report_grant(monkeypatch):
    from server.sli.reporting.v2.reports import nps_policy_denials as tabs

    monkeypatch.setattr(tabs, "connect", lambda: pytest.fail("unauthorized catalogue read"))
    assert tabs.domain_options({}) == []


def test_domain_options_keep_nps_domains_without_accounting(monkeypatch):
    from server.sli.reporting.v2.reports import nps_policy_denials as tabs

    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def execute(self, sql, params):
            assert "limit 256" in sql and params == ([7, 8],)

        def fetchall(self):
            return [{"id": 7, "fqdn": "domain-a"}, {"id": 8, "fqdn": "domain-b"}]

    class Connection(Cursor):
        def cursor(self):
            return Cursor()

    monkeypatch.setattr(tabs, "connect", Connection)
    monkeypatch.setattr(tabs, "resolve_domain_scope", lambda *_: [7, 8])
    monkeypatch.setattr(tabs, "_read_access_allowed", lambda _access, domain_id: domain_id == 7)
    assert tabs.domain_options({}) == [{"value": "7", "label": "domain-a"}]


def test_denied_access_never_reads_facts(monkeypatch):
    monkeypatch.setattr(nps, "_read_access_allowed", lambda *_: False)
    monkeypatch.setattr(nps, "connect", lambda: pytest.fail("unauthorized read"))
    assert nps.get_policy_denials({}, source_domain_id=7, time_from=START.isoformat(), time_to=END.isoformat())["state"] == "not_authorized"


def test_domain_grant_and_event_access_are_both_required(monkeypatch):
    calls = []
    monkeypatch.setattr(nps, "_read_windows", lambda domain, *_: calls.append(domain) or ([], [], False, False))
    access = {"capabilities": ["events.view"], "reports": [{
        "report_key": "vpn.audit", "allowed": True, "allowed_actions": ["view"],
        "grants": [{"allowed_actions": ["view"], "scope": {"kind": "domain", "ids": [7]}, "field_categories": []}],
    }]}
    options = {"time_from": START.isoformat(), "time_to": END.isoformat()}
    assert nps.get_policy_denials(access, source_domain_id=7, **options)["state"] == "partial"
    assert nps.get_policy_denials(access, source_domain_id=8, **options)["state"] == "not_authorized"
    assert nps.get_policy_denials({**access, "capabilities": []}, source_domain_id=7, **options)["state"] == "not_authorized"
    assert calls == [7]


@pytest.mark.parametrize("days", [0, 32])
def test_reader_rejects_unbounded_period(monkeypatch, days):
    monkeypatch.setattr(nps, "connect", lambda: pytest.fail("invalid window read"))
    with pytest.raises(ValueError):
        nps.get_policy_denials({}, source_domain_id=7, time_from=START.isoformat(), time_to=(START + timedelta(days=days)).isoformat())


def test_reader_uses_retained_domain_latest_version_and_bound_filters(monkeypatch):
    calls = []

    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def execute(self, sql, params=()):
            calls.append((sql, params))

        def fetchall(self):
            return [fact(1)] if len([sql for sql, _ in calls if "select n." in sql]) == 1 else []

    class Connection(Cursor):
        def cursor(self):
            return Cursor()

    monkeypatch.setattr(nps, "connect", Connection)
    monkeypatch.setattr(nps, "_read_access_allowed", lambda *_: True)
    payload = nps.get_policy_denials({}, source_domain_id=7, time_from=START.isoformat(), time_to=END.isoformat(), policy="policy-a", method="method-a")
    assert payload["metrics"]["denied"] == 1
    queries = [(sql, params) for sql, params in calls if "select n." in sql]
    assert len(queries) == 2
    for sql, params in queries:
        assert "source_identity_json->>'domain_id'" in sql
        assert "events_v2_core" not in sql
        assert "not exists" in sql and "newer.source_event_id=n.source_event_id" in sql
        assert "newer.processing_status" not in sql  # A failed replay must not resurrect old facts.
        assert "limit %s" in sql and params[-1] == nps.MAX_FACTS + 1
        assert "policy-a" in params and "method-a" in params
        assert "policy-a" not in sql
    assert queries[1][1][2:4] == (START - (END - START), START)


def test_plugin_tabs_do_not_read_accounting(monkeypatch):
    from server.sli.reporting.v2.definition import QueryContext
    from server.sli.reporting.v2.reports import vpn_connections

    monkeypatch.setattr(vpn_connections, "get_vpn_connections_report", lambda *_a, **_k: pytest.fail("Accounting read"))
    monkeypatch.setattr(nps, "_read_access_allowed", lambda *_: True)
    monkeypatch.setattr(nps, "_read_windows", lambda *_a, **_k: ([fact(1)], [], False, False))
    context = QueryContext(access={}, params={"domain": "7", "period": {"from_utc": START.isoformat(), "to_utc": END.isoformat()}}, domain_ids=[7], tab="policy_denials",
                           action="view", cursor=None, limit=100, timezone="UTC")
    result = vpn_connections._query(context)
    assert result["collections"]["policy_denials"][0]["denied"] == 1
    assert result["branches"]["policy_denials"]["state"] == "partial"
    assert result["metrics"][0]["key"] == "nps_allowed"
    assert result["collections"].get("daily") is None


@pytest.mark.parametrize("tab", ["policy_denials", "policy_denials_growth", "policy_denials_events"])
@pytest.mark.parametrize("days", [7, 31, 32, 90])
def test_policy_api_bounds_historical_period_at_its_selected_end(monkeypatch, tab, days):
    from server.api.routes import reports_v2
    from server.sli.reporting.v2.reports import vpn_connections

    end = START + timedelta(days=days)
    expected_start = max(START, end - timedelta(days=31))
    calls = []

    def read(domain, start, stop, _filters):
        calls.append((domain, start, stop))
        return [{**fact(1), "occurred_at_utc": start}], [], False, False

    monkeypatch.setattr(nps, "_read_access_allowed", lambda *_: True)
    monkeypatch.setattr(nps, "_read_windows", read)
    monkeypatch.setattr(vpn_connections, "_domain_options", lambda _access: [])
    monkeypatch.setattr(vpn_connections, "get_vpn_connections_report", lambda *_a, **_k: pytest.fail("Accounting read"))
    responses = []

    class Handler:
        def _access_decision(self):
            return {"reports": [{"report_key": "vpn.audit", "allowed": True}]}

        def _send_json(self, payload, status=200):
            responses.append((payload, int(status)))

    assert reports_v2.try_handle_get(Handler(), "/api/v2/reports/vpn.connections/data", {
        "domain": ["7"], "tab": [tab], "period": ["custom"],
        "from": [START.isoformat()], "to": [end.isoformat()], "tz": ["UTC"],
    })
    payload, status = responses[0]
    assert status == 200
    assert calls == [(7, expected_start, end)]
    assert payload["state"] == payload["branches"][tab]["state"] == "partial"
    assert payload["collections"][tab]
    assert payload["window"]["from_utc"] == nps.format_iso(expected_start)
    assert payload["window"]["to_utc_exclusive"] == nps.format_iso(end)
    assert payload["window"]["nps_period_clamped"] is (days > 31)
    assert payload["coverage"]["previous"]["from_utc"] == nps.format_iso(expected_start - (end - expected_start))
    assert "6272" not in " ".join(note["text"] for note in payload["limitations"])


@pytest.mark.parametrize("tab", ["policy_denials", "policy_denials_growth", "policy_denials_events"])
def test_policy_tabs_accept_90_day_preset(monkeypatch, tab):
    from server.sli.reporting.v2.definition import QueryContext, resolve_period
    from server.sli.reporting.v2.reports import vpn_connections

    period = resolve_period({"period": "90d"}, timezone_name="UTC", max_days=90, now=END)
    calls = []
    monkeypatch.setattr(nps, "_read_access_allowed", lambda *_: True)
    monkeypatch.setattr(nps, "_read_windows", lambda domain, start, end, _filters: calls.append((start, end)) or ([], [], False, False))
    context = QueryContext({}, {"domain": "7", "period": period}, [7], "view", None, 100, "UTC", tab=tab)
    payload = vpn_connections._query(context)
    assert calls == [(END - timedelta(days=31), END)]
    assert payload["state"] == "partial"
    assert payload["window"]["nps_period_clamped"] is True

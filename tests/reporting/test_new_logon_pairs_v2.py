from __future__ import annotations

from datetime import datetime, timedelta, timezone
from http import HTTPStatus

import pytest

from server.api.routes import reports_v2 as routes
from server.sli.reporting.v2 import registry
from server.sli.reporting.v2.definition import QueryContext, parse_params
from server.sli.reporting.v2.reports import new_logon_pairs as report
from server.sli.reports import new_logon_pairs_reporting as engine

START = datetime(2026, 10, 6, tzinfo=timezone.utc)
END = START + timedelta(days=1)
BASELINE = START - timedelta(days=30)
INDEX = {
    "names": {"pc-1": {"guid-1"}, "pc-2": {"guid-2"}}, "ips": {},
    "computers": {f"guid-{i}": {"computer_object_guid": f"guid-{i}", "computer_name": f"PC-{i}"} for i in (1, 2)},
}
ACCOUNTS = {"user-1": False, "user-2": False, "service-1": True}


def event(event_id, user="user-1", computer="PC-1", *, at=START, sid=None, logon_type="3", domain_id=7):
    return {"id": event_id, "event_id": 4624, "server_id": 10, "domain_id": domain_id,
            "channel": "Security", "time_created_utc": at.isoformat(), "target_domain_name": "TEST",
            "target_user_name": user, "target_user_sid": sid or ("S-1-5-21-1-2-3-1001" if user == "user-1" else "S-1-5-21-1-2-3-1002"),
            "workstation_name": computer, "computer": "DC-1", "logon_type": logon_type}


def compute(baseline=(), period=(), covered=True):
    return engine.compute_pairs(list(baseline), list(period), baseline_start=BASELINE, start=START, end=END,
                                index=INDEX, accounts=ACCOUNTS, baseline_covered=covered)


def access(*, fields=(report.FIELD_CATEGORY,), scope=None, allowed=True, actions=("view",)):
    return {"reports": [{"report_key": "ad.computer-logons", "allowed": allowed,
        "allowed_actions": list(actions), "grants": [{"field_categories": list(fields),
        "allowed_actions": list(actions), "scope": scope or {"kind": "domain", "ids": [7]}}]}]}


def context(**changes):
    params, _ = parse_params(report.REPORT, {}, now=END)
    values = {"access": access(), "params": params, "limit": 50}
    values.update(changes)
    return QueryContext(**values)


def fake_sources(monkeypatch, *, baseline=(), period=(), covered=True, truncated=False, partial=False,
                 baseline_truncated=None, period_truncated=None, period_covered=True, facts_incomplete=False):
    monkeypatch.setattr(report, "logon_domain_scope", lambda *args: [7])
    monkeypatch.setattr(engine, "load_context", lambda domain: {
        "index": INDEX, "accounts": ACCOUNTS, "server_ids": [10], "partial": partial,
        "computers": {"guid-1": {"entity_id": 101}, "guid-2": {"entity_id": 102}},
    })
    monkeypatch.setattr(engine, "load_history", lambda *args: {"baseline": list(baseline), "period": list(period),
        "baseline_covered": covered, "history_from_utc": BASELINE.isoformat(), "history_to_utc": END.isoformat(),
        "baseline_truncated": truncated if baseline_truncated is None else baseline_truncated,
        "period_truncated": truncated if period_truncated is None else period_truncated,
        "period_covered": period_covered, "facts_incomplete": facts_incomplete, "truncated": truncated})
    monkeypatch.setattr(engine, "user_entities", lambda *args: {"s-1-5-21-1-2-3-1001": 201})


def test_new_user_new_pair_and_known_pair():
    prior = event(1, at=START - timedelta(days=2))
    rows = compute([prior], [event(2), event(3, computer="PC-2"), event(4, user="user-2")])["items"]
    assert len(rows) == 2
    assert {(row["user"], row["novelty"], row["prior_user_logon"]) for row in rows} == {
        ("TEST\\user-1", "new_pair", "yes"), ("TEST\\user-2", "new_user", "no")}


def test_exact_sid_survives_account_rename_and_distinguishes_recreated_account():
    prior = event(1, at=START - timedelta(days=1))
    renamed = event(2, user="user-2", sid=prior["target_user_sid"])
    recreated = event(3, sid="S-1-5-21-1-2-3-1003")
    rows = compute([prior], [renamed, recreated])["items"]
    assert len(rows) == 1
    assert rows[0]["novelty"] == "new_user"


def test_no_baseline_never_claims_novelty_but_excludes_proven_known_pairs():
    rows = compute([event(1, at=START - timedelta(days=1))], [event(2), event(3, computer="PC-2"), event(4, user="user-2")], False)["items"]
    assert len(rows) == 2
    assert {row["novelty"] for row in rows} == {"no_baseline"}
    assert {row["prior_user_logon"] for row in rows} == {"yes", "unknown"}


def test_any_prior_user_logon_is_recorded_even_when_computer_is_unresolved():
    data = compute([event(1, computer="UNRESOLVED", at=START - timedelta(days=1))], [event(2)])
    assert data["items"][0]["prior_user_logon"] == "yes"
    assert data["items"][0]["novelty"] == "no_baseline"
    assert data["incomplete"]


def test_half_open_windows_first_seen_count_types_sources_and_duplicate_events():
    later = event(2, at=START + timedelta(hours=2), logon_type="10")
    later["computer"] = "DC-2"
    earlier = event(3)
    data = compute([event(1, at=BASELINE - timedelta(microseconds=1))],
        [later, earlier, earlier, event(4, at=END)])
    row = data["items"][0]
    assert row["count"] == 2
    assert row["first_seen"] == START.isoformat()
    assert row["source_event_id"] == 3
    assert row["logon_types"] == ["10", "3"]
    assert row["sources"] == ["DC-1", "DC-2"]
    assert row["novelty"] == "new_user"
    assert not compute([event(1, at=BASELINE)], [earlier])["items"]


def test_system_service_and_unknown_accounts_do_not_become_new_users():
    rows = [event(1, user="service-1"), event(2, user="SYSTEM", sid="S-1-5-18"),
            event(3, user="device$"), event(4, user="unclassified"), event(5)]
    data = compute(period=rows)
    assert len(data["items"]) == 1
    assert data["items"][0]["novelty"] == "no_baseline"
    missing_sid = event(6)
    missing_sid["target_user_sid"] = None
    assert compute(period=[missing_sid])["items"][0]["novelty"] == "no_baseline"


@pytest.mark.parametrize("covered,truncated,partial", [(False, False, False), (True, True, False), (True, False, True)])
@pytest.mark.parametrize("has_events", [False, True])
def test_partial_report_including_empty_result_does_not_assert_new(monkeypatch, covered, truncated, partial, has_events):
    fake_sources(monkeypatch, period=[event(1)] if has_events else [], covered=covered, truncated=truncated, partial=partial)
    data = report.REPORT.query(context())
    assert data["state"] == "partial"
    if has_events:
        assert data["items"][0]["novelty"] == "no_baseline"
        assert data["items"][0]["prior_user_logon"] == "unknown"
    else:
        assert not data["items"]
    assert not data["coverage"]["baseline_covered"]
    assert data["coverage"]["history_from_utc"] == BASELINE.isoformat()
    assert any(item["code"] == ("novelty_unverified" if covered else "no_baseline") for item in data["limitations"])


@pytest.mark.parametrize("has_events,expected", [(True, "ok"), (False, "empty")])
def test_fully_covered_comparison_keeps_completed_state(monkeypatch, has_events, expected):
    fake_sources(monkeypatch, period=[event(1)] if has_events else [])
    data = report.REPORT.query(context())
    assert data["state"] == expected
    assert data["coverage"]["baseline_covered"]
    assert not any(item["code"] == "no_baseline" for item in data["limitations"])
    assert any(item["code"] == "observations" for item in data["limitations"])
    if has_events:
        assert data["items"][0]["novelty"] == "new_user"
        assert data["items"][0]["prior_user_logon"] == "no"


def test_unresolved_baseline_identity_keeps_no_baseline_visible(monkeypatch):
    fake_sources(monkeypatch, baseline=[event(1, computer="UNRESOLVED", at=START - timedelta(days=1))], period=[event(2)])
    data = report.REPORT.query(context())
    assert data["state"] == "partial"
    assert not data["coverage"]["baseline_covered"]
    assert data["items"][0]["novelty"] == "no_baseline"
    assert data["items"][0]["prior_user_logon"] == "yes"
    assert {item["code"] for item in data["limitations"]} >= {"novelty_unverified", "identity_incomplete"}


def test_defaults_custom_baseline_filters_links_and_pagination_pin_window(monkeypatch):
    fake_sources(monkeypatch, period=[event(1), event(2, computer="PC-2", at=START + timedelta(hours=1))])
    params, _ = parse_params(report.REPORT, {}, now=END)
    assert params["baseline_days"] == 30
    assert params["period"]["preset"] == "24h"
    data = report.REPORT.query(context(limit=1))
    assert data["state"] == "ok" and data["has_more"]
    assert data["items"][0]["computer_entity_id"] == 101
    assert data["items"][0]["user_entity_id"] == 201
    advanced, _ = parse_params(report.REPORT, {}, now=END + timedelta(hours=1))
    next_page = report.REPORT.query(context(params=advanced, cursor=data["next_cursor"], limit=1))
    assert next_page["window"] == data["window"]
    assert next_page["items"][0]["computer_entity_id"] == 102
    assert not next_page["has_more"]
    params, _ = parse_params(report.REPORT, {"period": ["7d"], "baseline_days": ["14"], "q": ["pc-2"]}, now=END)
    assert report.REPORT.query(context(params=params))["items"][0]["computer"] == "PC-2"
    with pytest.raises(ValueError, match="invalid_cursor"):
        report.REPORT.query(context(params=params, cursor=data["next_cursor"]))
    params["baseline_days"] = 366
    with pytest.raises(ValueError, match="baseline_days"):
        report.REPORT.query(context(params=params))


@pytest.mark.parametrize("reader", ["logon_domain_scope", "load_context", "load_history"])
def test_history_or_context_failure_is_error_not_empty(monkeypatch, reader):
    fake_sources(monkeypatch)
    def unavailable(*args):
        error = report.InventoryUnavailableError if reader == "logon_domain_scope" else RuntimeError
        raise error("test_history_unavailable")
    monkeypatch.setattr(report if reader == "logon_domain_scope" else engine, reader, unavailable)
    data = report.REPORT.query(context())
    assert data["state"] == "error" and not data["items"]
    expected = {"logon_domain_scope": "domain_context_unavailable",
                "load_context": "context_read_failed", "load_history": "history_read_failed"}
    assert data["limitations"][0]["code"] == expected[reader]
    assert "test_history_unavailable" not in str(data)
    assert data["limitations"][0]["text"]


@pytest.mark.parametrize("decision", [access(allowed=False), access(fields=()), access(scope={"kind": "domain", "ids": [8]}),
                                      access(scope={"kind": "server", "ids": [10]}), access(actions=("export",))])
def test_api_denies_ineligible_logon_grants_before_reading_history(monkeypatch, decision):
    from server.sli.reporting.v2.reports import computer_logons
    monkeypatch.setattr(computer_logons, "resolve_report_domain_id", lambda: 7)
    def forbidden(*args):
        pytest.fail("denied request reached history")
    monkeypatch.setattr(engine, "load_context", forbidden)
    class Handler:
        def _access_decision(self):
            return decision
        def _send_json(self, payload, status=HTTPStatus.OK):
            self.payload, self.status = payload, status
    handler = Handler()
    assert routes.try_handle_get(handler, "/api/v2/reports/ad.new-logon-pairs/data", {})
    assert handler.status == HTTPStatus.FORBIDDEN
    assert handler.payload["error"] in {"report_access_denied", "report_scope_not_executable", "report_field_categories_not_allowed"}


def test_registry_reuses_logon_access_and_ad_navigation():
    catalog = registry.catalog(access())
    item = next(item for item in catalog["items"] if item["key"] == "ad.new-logon-pairs")
    assert item["owner_id"] == "sli.ad" and item["navigation_section"] == "active-directory"
    assert item["executable"]
    sections = catalog["navigation"]["sections"]
    entry = next(entry for section in sections for group in section["groups"] for entry in group["entries"] if entry["id"] == "new-logon-pairs-report")
    assert entry["path"] == "/report/ad.new-logon-pairs"
    assert entry["reports"] == ["ad.computer-logons"]


@pytest.mark.parametrize("scope", [{"kind": "all"}, {"kind": "domain", "ids": [7, 8]}])
def test_api_reads_only_the_server_resolved_domain(monkeypatch, scope):
    from server.sli.reporting.v2.reports import computer_logons
    fake_sources(monkeypatch, period=[event(1)])
    monkeypatch.setattr(report, "logon_domain_scope", computer_logons.logon_domain_scope)
    monkeypatch.setattr(computer_logons, "resolve_report_domain_id", lambda: 7)
    seen = []
    fake_history = engine.load_history
    def read(domain, servers, baseline_start, start, end):
        seen.append((domain, servers))
        return fake_history(domain, servers, baseline_start, start, end)
    monkeypatch.setattr(engine, "load_history", read)
    class Handler:
        def _access_decision(self):
            return access(scope=scope)
        def _send_json(self, payload, status=HTTPStatus.OK):
            self.payload, self.status = payload, status
    handler = Handler()
    assert routes.try_handle_get(handler, "/api/v2/reports/ad.new-logon-pairs/data",
        {"period": ["custom"], "from": [START.isoformat()], "to": [END.isoformat()]})
    assert handler.status == HTTPStatus.OK
    assert handler.payload["state"] == "ok"
    assert seen == [(7, [10])]


@pytest.mark.parametrize("late_source,truncated", [(False, False), (True, False), (False, True)])
def test_clickhouse_reader_scopes_published_history_and_verifies_facts(monkeypatch, late_source, truncated):
    monkeypatch.setattr(engine.history, "primary_read_enabled", lambda: True)
    monkeypatch.setattr(engine.history, "configured_read_port", lambda: 8123)
    monkeypatch.setattr(engine, "MAX_EVENTS", 1)
    calls = []
    def rows(port, sql, *, query_params):
        calls.append((sql, query_params))
        if "GROUP BY" in sql:
            return [{"server_id": 10, "first_utc": "2026-09-01 00:00:00.000000", "last_utc": "2026-10-07 00:00:00.000000"},
                    {"server_id": 11, "first_utc": "2026-10-05 00:00:00.000000" if late_source else "2026-09-01 00:00:00.000000", "last_utc": "2026-10-07 00:00:00.000000"}]
        return [{"event_db_id": 1}, {"event_db_id": 2}] if truncated else [{"event_db_id": 1}]
    monkeypatch.setattr(engine.history, "_rows", rows)
    verified = []
    def facts(port, ids):
        verified.extend(ids)
        return {value: event(value) for value in ids}
    monkeypatch.setattr(engine.history, "read_published_events_many", facts)
    data = engine.load_history(7, [10, 11], BASELINE, START, END)
    assert data["baseline_covered"] is (not late_source and not truncated)
    assert data["truncated"] is truncated
    assert data["history_from_utc"] == "2026-09-01T00:00:00+00:00"
    assert verified == [1, 1]
    for sql, params in calls:
        assert "published_batches" in sql and "JSONExtractInt(core_json, 'domain_id')" in sql
        assert "server_id IN {servers:Array(UInt64)}" in sql
        assert params["domain"] == "7" and params["servers"] == "[10, 11]"


def test_clickhouse_is_mandatory_without_hot_fallback(monkeypatch):
    monkeypatch.setattr(engine.history, "primary_read_enabled", lambda: False)
    with pytest.raises(RuntimeError, match="history_unavailable"):
        engine.load_history(7, [10], BASELINE, START, END)


@pytest.mark.parametrize("has_events", [False, True])
@pytest.mark.parametrize("baseline_truncated,period_truncated", [(True, False), (False, True)])
def test_each_truncated_window_is_identified_without_losing_partial_rows(monkeypatch, has_events, baseline_truncated, period_truncated):
    fake_sources(monkeypatch, period=[event(1)] if has_events else [], truncated=True,
                 baseline_truncated=baseline_truncated, period_truncated=period_truncated)
    data = report._query(context())
    assert data["state"] == "partial"
    assert data["coverage"]["baseline_truncated"] is baseline_truncated
    assert data["coverage"]["period_truncated"] is period_truncated
    assert data["coverage"]["history_to_utc"] == END.isoformat()
    assert len(data["items"]) == int(has_events)
    if has_events:
        assert data["items"][0]["novelty"] == "no_baseline"


def test_missing_current_window_has_a_specific_explanation(monkeypatch):
    fake_sources(monkeypatch, period_covered=False)
    data = report._query(context())
    assert data["state"] == "partial" and not data["items"]
    assert data["coverage"]["baseline_history_covered"] is True
    assert data["coverage"]["period_covered"] is False
    assert "period_missing" in {item["code"] for item in data["limitations"]}


def test_partial_current_window_keeps_verified_comparisons_against_a_complete_baseline(monkeypatch):
    fake_sources(monkeypatch, period=[event(1)], period_covered=False)
    data = report._query(context())
    assert data["state"] == "partial"
    assert data["coverage"]["baseline_covered"] is True
    assert data["items"][0]["novelty"] == "new_user"
    assert "no_baseline" not in {item["code"] for item in data["limitations"]}


def test_dropped_published_facts_cannot_establish_novelty(monkeypatch):
    monkeypatch.setattr(engine.history, "primary_read_enabled", lambda: True)
    monkeypatch.setattr(engine.history, "configured_read_port", lambda: 8123)
    monkeypatch.setattr(engine.history, "_rows", lambda port, sql, **kwargs: [
        {"server_id": 10, "first_utc": "2026-09-01 00:00:00.000000", "last_utc": "2026-10-07 00:00:00.000000"}
    ] if "GROUP BY" in sql else [{"event_db_id": 1}])
    monkeypatch.setattr(engine.history, "read_published_events_many", lambda *_args: {})
    raw = engine.load_history(7, [10], BASELINE, START, END)
    assert raw["facts_incomplete"] and not raw["baseline_covered"] and not raw["period_covered"]
    fake_sources(monkeypatch, period=[event(1)], facts_incomplete=True)
    data = report._query(context())
    assert data["state"] == "partial"
    assert data["items"][0]["novelty"] == "no_baseline"
    assert "facts_incomplete" in {item["code"] for item in data["limitations"]}



@pytest.mark.parametrize('reader,reason,expected', [
    ('load_context', 'what_where_when_users_snapshot_unavailable', 'users_context_missing'),
    ('load_history', 'logon_history_unavailable', 'history_not_enabled'),
    ('load_history', 'history_clickhouse_credentials_missing', 'history_not_configured'),
    ('load_history', 'history_clickhouse_port_invalid', 'history_not_configured'),
    ('load_history', 'published_history_event_mismatch', 'history_verification_failed'),
    ('load_history', 'private endpoint and credentials', 'history_read_failed'),
])
def test_source_failure_has_safe_actionable_reason(monkeypatch, reader, reason, expected):
    fake_sources(monkeypatch)
    def fail(*args):
        raise RuntimeError(reason)
    monkeypatch.setattr(engine, reader, fail)
    data = report.REPORT.query(context())
    assert data['state'] == 'error' and not data['items']
    assert data['limitations'][0]['code'] == expected
    assert 'private endpoint' not in str(data)


def test_empty_retained_history_is_explicit_not_an_unavailable_error(monkeypatch):
    fake_sources(monkeypatch, covered=False)
    original = engine.load_history
    def empty(*args):
        return {**original(*args), 'history_from_utc': None, 'history_to_utc': None}
    monkeypatch.setattr(engine, 'load_history', empty)
    data = report.REPORT.query(context())
    assert data['state'] == 'empty' and not data['items']
    assert not data['coverage']['baseline_covered']
    assert 'history_empty' in {item['code'] for item in data['limitations']}


def test_permission_error_is_not_disguised_as_history_failure(monkeypatch):
    fake_sources(monkeypatch)
    def denied(*args):
        raise PermissionError('report_access_denied')
    monkeypatch.setattr(engine, 'load_history', denied)
    with pytest.raises(PermissionError):
        report.REPORT.query(context())


@pytest.mark.parametrize('reader', ['load_context', 'load_history'])
def test_timeout_and_cancellation_reasons_do_not_expose_exception_text(monkeypatch, reader):
    from psycopg.errors import QueryCanceled
    from server.sli.core.database import QueryTimeoutError
    for error, expected in [(QueryCanceled('private SQL'), 'read_cancelled'),
                            (QueryTimeoutError('private SQL', timeout_ms=100), 'read_timeout')]:
        fake_sources(monkeypatch)
        def fail(*args):
            raise error
        monkeypatch.setattr(engine, reader, fail)
        data = report.REPORT.query(context())
        assert data['state'] == 'error'
        assert data['limitations'][0]['code'] == ('context_' + expected if reader == 'load_context' else expected)
        assert 'private SQL' not in str(data)


def test_invalid_history_port_is_configuration_error_without_exposing_value(monkeypatch):
    real_history = engine.load_history
    fake_sources(monkeypatch)
    monkeypatch.setattr(engine, 'load_history', real_history)
    monkeypatch.setenv('ADLOG_HISTORY_READ_MODE', 'primary')
    monkeypatch.setenv('ADLOG_HISTORY_CLICKHOUSE_PORT', 'synthetic-invalid-port')
    data = report.REPORT.query(context())
    assert data['state'] == 'error' and not data['items']
    assert data['limitations'][0]['code'] == 'history_not_configured'
    assert 'synthetic-invalid-port' not in str(data)

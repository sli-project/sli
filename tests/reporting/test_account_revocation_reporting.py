from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from psycopg import errors

from server.sli.reporting.v2.definition import QueryContext, parse_params
from server.sli.reporting.v2.reports import security_events
from server.sli.reports import account_revocation_reporting as reporting

START = datetime(2026, 10, 1, tzinfo=timezone.utc)
SID = "S-1-5-21-100-200-300-1001"


def event(identifier, code, minute, **fields):
    return {"event_db_id": identifier, "domain_id": 7, "event_id": code,
            "time_created_utc": START + timedelta(minutes=minute),
            "target_user_sid": SID, "target_user_name": "account-a",
            "subject_user_sid": SID, "subject_user_name": "account-a",
            "normalized_event_id": str(identifier), "processing_status": "normalized",
            "semantic_type": reporting.EXPECTED_TYPES[code], "source": "source-a", "logon_type": "3", **fields}


def session(identifier="session-a", **fields):
    return {"session_row_id": identifier, "domain_id": 7, "target_user_sid": SID,
            "started_at_utc": START - timedelta(minutes=10),
            "last_observed_at_utc": START + timedelta(minutes=20), "stopped_at_utc": None,
            "completeness": "missing_stop", **fields}


def shape(events, sessions=(), **filters):
    return reporting.shape_candidates(events, sessions, start=START, end=START + timedelta(hours=1),
                                      follow_minutes=60, **filters)[0]


def access(domain=7, *, fields=("security", "technical", "raw_evidence"), capabilities=("events.view",)):
    return {"platform_owner": False, "capabilities": list(capabilities), "capability_policies": [],
            "reports": [{"report_key": "security.events.chains", "allowed": True, "allowed_actions": ["view"],
                         "grants": [{"allowed_actions": ["view"], "field_categories": list(fields),
                                     "scope": {"kind": "domain", "ids": [domain]}}]}]}


def arguments(**overrides):
    return {"domain_id": 7, "time_from": START.isoformat(), "time_to": (START + timedelta(hours=1)).isoformat(),
            "limit": 100, **overrides}


class FakeCursor:
    def __init__(self, batches=(), *, relation=True, accounting_error=None):
        self.batches = iter(batches)
        self.calls = []
        self.relation = relation
        self.accounting_error = accounting_error

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        pass

    def cursor(self):
        return self

    def execute(self, sql, params=None):
        self.calls.append((sql, params))
        if self.accounting_error and "session.*,alias" in sql:
            raise self.accounting_error()

    def fetchall(self):
        return next(self.batches)

    def fetchone(self):
        return {"relation": self.relation}


def test_disable_delete_authentication_and_reenable_are_candidates_with_evidence():
    rows = shape([event(1, 4725, 0), event(2, 4624, 1), event(3, 6272, 5), event(4, 4722, 3),
                  event(5, 4726, 10), event(6, 4624, 12), event(2, 4624, 1)])
    assert len(rows) == 3
    assert [row["activity_type"] for row in rows] == ["logon", "nps_allow", "logon"]
    assert [row["disable_code"] for row in rows] == [4725, 4725, 4726]
    assert rows[0]["evidence"] == [1, 2, 4] and rows[1]["evidence"] == [1, 3, 4]
    assert rows[0]["reenable_relation"] == "after_activity"
    assert rows[1]["reenable_relation"] == "before_activity"
    assert rows[0]["delay_seconds"] == 60 and rows[0]["clock_quality"] == "uncertain"
    assert rows[2]["reenabled_at"] is None and rows[2]["reenable_relation"] == "not_observed"
    assert all(row["qualification"] == "candidate" and row["quality"] == "exact_sid" for row in rows)
    assert len({row["candidate_key"] for row in rows}) == 3


def test_nps_matches_subject_sid_and_never_target_or_name():
    rows = shape([event(1, 4725, 0), event(2, 6272, 5, target_user_sid=SID + "9"),
                  event(3, 6272, 6, subject_user_sid=SID + "9"), event(4, 4624, 7, target_user_sid=SID + "9"),
                  event(5, 4624, 8, domain_id=8)])
    assert len(rows) == 1 and rows[0]["activity_event"] == 2


@pytest.mark.parametrize("sid", [None, "-", "S-1-0-0", "S-1-5-21-invalid", "invalid"])
def test_unknown_identities_remain_separate_without_correlated_activity(sid):
    rows = shape([event(1, 4725, 0, target_user_sid=sid), event(2, 4726, 5, target_user_sid=sid),
                  event(3, 4624, 6, target_user_sid=sid), event(4, 6272, 7, subject_user_sid=sid)])
    assert len(rows) == 4 and len({row["candidate_key"] for row in rows}) == 4
    assert all(row["quality"] == "unknown_sid" and row["activity_type"] == "insufficient" for row in rows)
    assert all(len(row["evidence"]) == 1 for row in rows)
    assert shape([event(1, 4725, 0, target_user_sid=sid)], exact_only=True) == []


def test_time_window_is_strict_and_latest_disable_is_used_once():
    rows = shape([event(1, 4725, -1), event(2, 4725, 0), event(3, 4624, 0), event(4, 4624, 60),
                  event(5, 4726, 10), event(6, 4624, 11), event(7, 4725, 60), event(8, 4624, 70)])
    assert [(row["disable_event"], row["activity_event"]) for row in rows] == [(5, 6), (5, 4)]
    assert shape([event(1, 4725, 0), event(2, 4624, 60)]) == []
    rows = shape([event(1, 4725, 0), event(2, 4722, 5), event(3, 4624, 5)])
    assert rows[0]["reenable_relation"] == "same_time"


@pytest.mark.parametrize("fields", [{"processing_status": "ignored"}, {"processing_status": None},
                                    {"semantic_type": "unknown"}])
def test_missing_or_ignored_current_semantics_never_correlates(fields):
    assert shape([event(1, 4725, 0, **fields), event(2, 4624, 1)])[0]["activity_type"] == "insufficient"
    row = shape([event(1, 4725, 0), event(2, 4624, 1, **fields)])[0]
    assert row["disable_event"] is None and row["quality"] == "partial"


def test_accounting_continuation_is_distinct_from_authentication_and_requires_observed_span():
    rows = shape([event(1, 4725, 0), event(2, 4624, 5)], [session(), session(),
                 session("new", started_at_utc=START + timedelta(minutes=1)),
                 session("missing-start", started_at_utc=None),
                 session("stopped", stopped_at_utc=START), session("other", target_user_sid=SID + "9"),
                 session("different-domain", domain_id=8)])
    assert [row["activity_type"] for row in rows] == ["logon", "vpn_continuation"]
    row = rows[1]
    assert row["activity_event"] is None and row["evidence"] == [1, "session-a"]
    assert row["session_started_at"] == "2026-09-30T23:50:00Z"
    assert row["session_completeness"] == "missing_stop"
    assert row["source"] == "RADIUS Accounting"
    assert shape([event(1, 4725, 0)], [session(last_observed_at_utc=START)]) == []


@pytest.mark.parametrize("filters,expected", [
    ({"account": "ACCOUNT-A"}, 1), ({"account": SID.lower()}, 1), ({"account": "other"}, 0),
    ({"source": "SOURCE-A"}, 1), ({"source": "other"}, 0),
    ({"activity_type": "logon"}, 1), ({"activity_type": "nps_allow"}, 0),
    ({"minimum_delay": 301}, 0), ({"minimum_delay": 300}, 1), ({"exact_only": True}, 1),
])
def test_filters_apply_to_candidate_rows(filters, expected):
    assert len(shape([event(1, 4725, 0), event(2, 4624, 5)], **filters)) == expected


def test_truncation_does_not_turn_an_exact_sid_into_unknown_identity():
    row = shape([event(1, 4725, 0), event(2, 4624, 5)], truncated=True, exact_only=True)[0]
    assert row["quality"] == "partial" and row["sid"] == SID.lower()


def test_sql_caps_indexed_source_before_join_and_pins_unique_current_semantics(monkeypatch):
    monkeypatch.setattr(reporting, "MAX_SOURCE_ROWS", 1)
    cur = FakeCursor([[event(1, 4725, 0), event(2, 4726, 1)]])
    rows, cut = reporting._read_events(cur, domain_id=7, start=START, end=START + timedelta(hours=1), event_ids=[4725, 4726])
    assert len(rows) == 1 and cut
    sql, params = cur.calls[0]
    assert sql.index("limit %s") < sql.index("left join normalized_events")
    assert "event.domain_id=%s and event.event_id=any(%s)" in sql
    assert "event.time_created_utc>=%s and event.time_created_utc<%s" in sql
    assert "normalized.semantic_contract_version=%s" in sql
    assert "normalized.normalizer_id=%s and normalized.normalizer_version=%s" in sql
    assert "processing_status='normalized'" not in sql
    assert params[:2] == [7, [4725, 4726]] and params[6] == 2
    assert params[-3:] == [reporting.SEMANTIC_CONTRACT_VERSION, reporting.NORMALIZER_ID, reporting.NORMALIZER_VERSION]
    assert "server.role='domain_controller'" not in sql


@pytest.mark.parametrize("decision", [{}, access(8), access(capabilities=()), access(fields=("security",))])
def test_denies_before_database_read(monkeypatch, decision):
    monkeypatch.setattr(reporting.security, "_connect", lambda: pytest.fail("unauthorized database read"))
    assert reporting.get_account_revocation(decision, **arguments()) == {"state": "denied", "rows": []}


@pytest.mark.parametrize("overrides", [{"time_to": START.isoformat()}, {"time_to": (START + timedelta(days=32)).isoformat()},
                                    {"follow_minutes": 1441}, {"follow_minutes": 0}, {"minimum_delay": -1},
                                    {"limit": 501}, {"domain_id": 0}, {"activity_type": "unknown"}, {"action": "delete"}])
def test_invalid_bounds_rejected_before_read(monkeypatch, overrides):
    monkeypatch.setattr(reporting.security, "_connect", lambda: pytest.fail("invalid database read"))
    with pytest.raises(ValueError):
        reporting.get_account_revocation(access(), **arguments(**overrides))


def test_service_read_bounds_coverage_and_filtered_metrics(monkeypatch):
    cur = FakeCursor([[event(1, 4725, 0)], [event(4, 4722, 3)], [event(2, 4624, 1), event(3, 6272, 5)], [session()]])
    monkeypatch.setattr(reporting.security, "_connect", lambda: cur)
    raw = reporting.get_account_revocation(access(), **arguments(limit=1))
    assert raw["state"] == "partial" and raw["coverage"]["rows_truncated"]
    assert raw["filtered_count"] == 3 and len(raw["rows"]) == 1
    assert raw["totals"] == {"logon_accounts": 1, "nps_allows": 1, "vpn_sessions": 1, "insufficient": 0}
    assert raw["coverage"]["accounting_state"] == "available" and raw["coverage"]["completeness"] == "not_proven"
    reads = [(sql, params) for sql, params in cur.calls if params]
    assert [params[1] for _, params in reads[:3]] == [[4725, 4726], [4722], [4624, 6272]]
    assert reads[0][1][3] == START + timedelta(hours=1)
    assert reads[2][1][3] == START + timedelta(hours=25)
    sql, params = reads[-1]
    assert "alias.domain_id=%s and alias.alias_type='object_sid'" in sql and "alias.normalized_value=any(%s)" in sql
    assert "session.entity_id=alias.entity_id" in sql and "session.domain_id=alias.domain_id" in sql
    assert "session.started_at_utc<%s and session.last_observed_at_utc>%s" in sql and "limit %s" in sql
    assert params[:2] == [7, [SID.lower()]]
    assert raw["window"]["idea_key"] == "security.account-revocation"


@pytest.mark.parametrize("error", [errors.UndefinedTable, errors.UndefinedColumn, errors.InsufficientPrivilege])
def test_optional_accounting_failure_preserves_authentication(monkeypatch, error):
    cur = FakeCursor([[event(1, 4725, 0)], [], [event(2, 4624, 1)]], accounting_error=error)
    monkeypatch.setattr(reporting.security, "_connect", lambda: cur)
    raw = reporting.get_account_revocation(access(), **arguments())
    assert raw["state"] == "partial" and raw["rows"][0]["activity_type"] == "logon"
    assert raw["coverage"]["accounting_state"] == "unavailable"
    assert cur.calls[-2:] == [("rollback to savepoint revocation_accounting", None), ("release savepoint revocation_accounting", None)]


def test_empty_and_missing_accounting_do_not_claim_absence(monkeypatch):
    monkeypatch.setattr(reporting.security, "_connect", lambda: FakeCursor([[], [], []]))
    raw = reporting.get_account_revocation(access(), **arguments())
    assert raw["state"] == "empty" and raw["coverage"]["completeness"] == "not_proven"
    assert raw["coverage"]["accounting_state"] == "not_checked"
    monkeypatch.setattr(reporting.security, "_connect", lambda: FakeCursor([[event(1, 4725, 0)], [], []], relation=None))
    raw = reporting.get_account_revocation(access(), **arguments())
    assert raw["state"] == "partial" and raw["coverage"]["accounting_state"] == "unavailable"


def test_source_and_output_caps_are_explicit(monkeypatch):
    monkeypatch.setattr(reporting, "MAX_SOURCE_ROWS", 1)
    monkeypatch.setattr(reporting.security, "_connect", lambda: FakeCursor([
        [event(1, 4725, 0), event(2, 4725, 1)], [], [event(3, 4624, 5)], []]))
    raw = reporting.get_account_revocation(access(), **arguments())
    assert raw["coverage"]["source_truncated"] and raw["rows"][0]["quality"] == "partial"
    rows, cut = reporting.shape_candidates([event(1, 4725, 0)], [session(), session("second")],
                                          start=START, end=START + timedelta(hours=1), follow_minutes=60)
    assert len(rows) == 1 and cut


def test_tab_dispatch_metadata_and_denial_use_existing_report(monkeypatch):
    params, paging = parse_params(security_events.REPORT, {
        "domain": ["7"], "tab": ["account-revocation"], "period": ["custom"],
        "from": [START.isoformat()], "to": [(START + timedelta(hours=1)).isoformat()],
    }, now=START)
    assert params["revocation_window"] == "1440" and params.get("minimum_delay", 0) == 0
    monkeypatch.setattr(security_events, "get_security_events_report", lambda *_args, **_kwargs: pytest.fail("main query"))
    monkeypatch.setattr(security_events, "_domain_options", lambda _access: [])
    monkeypatch.setattr(reporting.security, "_connect", lambda: FakeCursor([[event(1, 4725, 0)], [], [event(2, 4624, 5)], []]))
    context = QueryContext(access=access(), params=params, domain_ids=None, action="view", cursor=None,
                           limit=100, timezone="UTC", tab=paging["tab"])
    raw = security_events._query(context)
    assert raw["report_key"] == "security.events.chains" and raw["items"] == []
    assert raw["collections"]["account_revocation"][0]["qualification"] == "candidate"
    assert len(raw["metrics"]) == 4 and len(raw["limitations"]) == 4
    tab = next(view for view in security_events.REPORT.views if view.key == "account-revocation")
    assert tab.kind == "table" and tab.source == "account_revocation"
    assert {column.key for column in tab.columns if column.link} == {"disable_event", "activity_event", "reenable_event"}
    assert next(column for column in tab.columns if column.key == "sid").optional
    assert security_events.REPORT.access.scope == "delegated"
    denied_context = QueryContext(access={}, params=params, domain_ids=None, action="view", cursor=None,
                                  limit=100, timezone="UTC", tab=paging["tab"])
    assert security_events._query(denied_context)["state"] == "denied"

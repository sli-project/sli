"""Security-action filters must not scan event history before reading a page."""
from __future__ import annotations

import pytest

from server.sli.reporting.v2.definition import QueryContext
from server.sli.reporting.v2.reports import security_events
from server.sli.reports import security_event_reporting as engine
from tests.reporting.test_security_event_reporting import _event, _report_access


class DomainCursor:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        pass

    def execute(self, sql, params):
        assert "select id, fqdn from domains" in sql
        self.ids = params[0]

    def fetchall(self):
        return [{"id": domain_id, "fqdn": f"domain{domain_id}.example.test"} for domain_id in self.ids]

    def cursor(self):
        return self


@pytest.fixture
def metadata(monkeypatch):
    monkeypatch.setattr(engine, "_read_security_event_domain_batch", lambda **_kwargs: [7, 8, 9])
    monkeypatch.setattr(security_events, "connect", DomainCursor)

    def archive_probe(domain_id):
        if domain_id == 7:
            return True
        raise TimeoutError("synthetic private archive probe detail")

    monkeypatch.setattr(engine, "_has_security_event_source", archive_probe)


def test_options_do_not_probe_event_history_and_keep_all_authorized_domains(metadata):
    access = _report_access()
    access["reports"][0]["grants"][0]["scope"]["ids"] = [7, 8]
    assert security_events._domain_options(access) == [
        {"value": "7", "label": "domain7.example.test"},
        {"value": "8", "label": "domain8.example.test"},
    ]


@pytest.mark.parametrize("missing", ["capability", "field", "report"])
def test_options_still_require_full_read_authorization(metadata, missing):
    access = _report_access()
    if missing == "capability":
        access["capabilities"] = []
    elif missing == "field":
        access["reports"][0]["grants"][0]["field_categories"] = ["technical"]
    else:
        access["reports"] = []
    assert security_events._domain_options(access) == []


@pytest.mark.parametrize("domain_id", [7, None])
@pytest.mark.parametrize("observed", [False, True])
def test_page_and_coverage_are_independent_of_option_source_probes(metadata, monkeypatch, domain_id, observed):
    access = _report_access()
    access["reports"][0]["grants"][0]["scope"]["ids"] = [7, 8]
    calls = []

    def read_page(**kwargs):
        calls.append(kwargs["domain_id"])
        return ([_event(1, 4624, 5, domain_id=7)] if observed else []), {"history_event_present": True}, False

    monkeypatch.setattr(engine, "_read_security_events_page", read_page)
    monkeypatch.setattr(engine, "get_v2_event_details_by_ids", lambda _ids: {1: {"event_data": {}}})
    context = QueryContext(access=access, params={"domain": domain_id, "period": {
        "from_utc": "2026-09-01T10:00:00Z", "to_utc": "2026-09-01T11:00:00Z",
    }})
    payload = security_events._query(context)
    assert calls == [domain_id if domain_id is not None else [7, 8]]
    assert payload["state"] == ("ok" if observed else "partial")
    assert payload["coverage"]["source_completeness"] == "not_proven"
    assert [item["event_db_id"] for item in payload["items"]] == ([1] if observed else [])


def test_failed_scope_discovery_is_not_silently_hidden(metadata, monkeypatch):
    def failed(**_kwargs):
        raise TimeoutError("synthetic metadata failure")

    monkeypatch.setattr(engine, "_read_security_event_domain_batch", failed)
    with pytest.raises(TimeoutError):
        security_events._domain_options(_report_access())


@pytest.mark.parametrize("count", [0, 101, 10_000, 10_001])
def test_metadata_enumeration_is_bounded_without_silently_truncating(monkeypatch, count):
    access = _report_access()
    access["reports"][0]["grants"][0]["scope"] = {"kind": "all"}
    calls = []

    def domains(*, after_domain_id, limit):
        calls.append((after_domain_id, limit))
        return list(range(after_domain_id + 1, min(after_domain_id + limit, count) + 1))

    monkeypatch.setattr(engine, "_read_security_event_domain_batch", domains)
    monkeypatch.setattr(security_events, "connect", DomainCursor)
    monkeypatch.setattr(engine, "_has_security_event_source", lambda *_: pytest.fail("event probe"))
    if count > engine.DISCOVERY_SCAN_LIMIT:
        with pytest.raises(ValueError, match="security_events_source_discovery_scan_limit"):
            security_events._domain_options(access)
    else:
        assert len(security_events._domain_options(access)) == count
    assert len(calls) <= 40
    assert all(limit == 256 for _, limit in calls)


def test_explicit_unauthorized_domain_does_not_fall_back(metadata, monkeypatch):
    monkeypatch.setattr(engine, "_read_security_events_page", lambda **_: pytest.fail("unauthorized read"))
    context = QueryContext(access=_report_access(), params={"domain": 9, "period": {
        "from_utc": "2026-09-01T10:00:00Z", "to_utc": "2026-09-01T11:00:00Z",
    }})
    assert security_events._query(context)["state"] == "denied"
    context.params["domain"] = -1
    with pytest.raises(ValueError, match="security_events_domain_invalid"):
        security_events._query(context)


def test_selected_scope_read_failure_is_not_converted_to_success(metadata, monkeypatch):
    def failed(**_kwargs):
        raise TimeoutError("synthetic selected source failure")

    monkeypatch.setattr(engine, "_read_security_events_page", failed)
    context = QueryContext(access=_report_access(), params={"domain": 7, "period": {
        "from_utc": "2026-09-01T10:00:00Z", "to_utc": "2026-09-01T11:00:00Z",
    }})
    with pytest.raises(TimeoutError):
        security_events._query(context)

from datetime import datetime, timedelta, timezone

import pytest

from server.sli.reports import ad_snapshot_change_reporting as reporting
from server.sli.storage import ad_snapshot_change_history as history
from server.sli.reporting.v2.definition import QueryContext, parse_params
from server.sli.reporting.v2.reports import ad_state, gpo

NOW = datetime(2026, 10, 7, tzinfo=timezone.utc)
START = NOW - timedelta(days=90)
PERIOD = {"from_utc": START.isoformat(), "to_utc": NOW.isoformat()}


def confirmation(manifest="current", previous="previous", stamp=NOW, *, domain=1, family="users_v2", state="complete"):
    return {"manifest_id": manifest, "previous_manifest_id": previous, "observed_at": stamp,
            "domain_id": domain, "family": family, "coverage_state": state, "batch_id": "a" * 64,
            "record_count": 0, "records_sha256": history._hash([])}


def test_coverage_starts_later_partial_pair_and_missing_domain_are_explicit():
    rows = [confirmation(stamp=NOW - timedelta(days=2), state="partial")]
    coverage = reporting.coverage_state(rows, domains=[1, 2], families=("users_v2",),
                                        start=START, end=NOW, cutoff=NOW - timedelta(days=365))
    assert coverage["state"] == "partial"
    assert set(coverage["reasons"]) == {
        "history_starts_later", "history_ends_earlier", "partial_snapshot_pair", "history_not_collected"}


def test_complete_empty_history_is_distinct_from_missing_or_expired_history():
    rows = [confirmation(manifest="previous", previous="baseline", stamp=NOW - timedelta(hours=12)), confirmation()]
    start = NOW - timedelta(hours=12)
    assert reporting.coverage_state(rows, domains=[1], families=("users_v2",),
                                    start=start, end=NOW, cutoff=NOW - timedelta(days=365))["state"] == "complete"
    partial = reporting.coverage_state(rows, domains=[1], families=("users_v2",),
                                       start=START, end=NOW, cutoff=NOW - timedelta(days=7))
    assert "outside_retention" in partial["reasons"]
    rows[-1]["previous_manifest_id"] = "missing"
    assert "history_gap" in reporting.coverage_state(rows, domains=[1], families=("users_v2",),
                start=START, end=NOW, cutoff=NOW - timedelta(days=365))["reasons"]


@pytest.fixture
def reader(monkeypatch):
    monkeypatch.setattr(reporting.platform_settings, "get_setting", lambda *_: "365")
    monkeypatch.setattr(history.ch, "configured_read_port", lambda: 8123)
    monkeypatch.setattr(history.ch, "_rows", lambda *a, **kw: [])


def test_reader_uses_only_authorized_confirmed_batches_inside_requested_period(reader, monkeypatch):
    calls = []
    change = {"object_id": "synthetic-1", "object_type": "ad_user", "field": "enabled", "kind": "attribute_changed"}
    batch = [{"record_id": history._hash(["a" * 64, change]), "payload_json": history._json(change)}]
    row = {**confirmation(stamp=NOW - timedelta(days=60)), "record_count": 1,
           "records_sha256": history._hash([(batch[0]["record_id"], batch[0]["payload_json"])])}
    def query(sql, params, **kw):
        calls.append(params)
        return [row]
    monkeypatch.setattr(reporting.database, "query_rows_bounded", query)
    monkeypatch.setattr(history.ch, "_rows", lambda *a, **kw: batch)
    raw = reporting.read_changes(domain_ids=[1], families=("users_v2",), period=PERIOD, now=NOW)
    assert calls[0][:2] == ([1], ["users_v2"])
    assert raw["items"][0]["object_id"] == "synthetic-1"
    assert raw["state"] == "partial"
    monkeypatch.setattr(history.ch, "_rows", lambda *a, **kw: [])
    assert reporting.read_changes(domain_ids=[1], families=("users_v2",), period=PERIOD, now=NOW)["state"] == "unavailable"


def test_denied_domain_scope_never_reads_any_database(reader, monkeypatch):
    monkeypatch.setattr(reporting.database, "query_rows_bounded", lambda *a, **kw: pytest.fail("scope widened"))
    assert reporting.read_changes(domain_ids=[], families=("gpo_v2",), period=PERIOD, now=NOW)["items"] == []


def test_records_outside_period_or_current_retention_are_not_loaded(reader, monkeypatch):
    rows = [confirmation(stamp=START - timedelta(days=1)), confirmation(stamp=NOW)]
    monkeypatch.setattr(reporting.database, "query_rows_bounded", lambda *a, **kw: rows)
    def read(port, sql, **kw):
        assert "LIMIT 0" in sql  # Health probe only; no eligible batch.
        return []
    monkeypatch.setattr(history.ch, "_rows", read)
    assert reporting.read_changes(domain_ids=[1], families=("users_v2",), period=PERIOD, now=NOW)["items"] == []
    monkeypatch.setattr(reporting.platform_settings, "get_setting", lambda *_: "7")
    rows[:] = [confirmation(stamp=NOW - timedelta(days=8))]
    assert reporting.read_changes(domain_ids=[1], families=("users_v2",), period=PERIOD, now=NOW)["items"] == []


def test_unreachable_clickhouse_is_unavailable_even_for_confirmed_empty_period(reader, monkeypatch):
    monkeypatch.setattr(reporting.database, "query_rows_bounded", lambda *a, **kw: [confirmation()])
    monkeypatch.setattr(history.ch, "_rows", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("transport_failed")))
    assert reporting.read_changes(domain_ids=[1], families=("users_v2",), period=PERIOD, now=NOW)["state"] == "unavailable"


@pytest.mark.parametrize("domains", [[1], None])
def test_history_not_yet_collected_is_not_an_empty_or_partial_period(reader, monkeypatch, domains):
    monkeypatch.setattr(reporting.database, "query_rows", lambda *a, **kw: [])
    monkeypatch.setattr(reporting.database, "query_rows_bounded", lambda *a, **kw: [])
    raw = reporting.read_changes(domain_ids=domains, families=("gpo_v2",), period=PERIOD, now=NOW)
    assert raw["state"] == "not_collected"
    assert raw["coverage"]["state"] == "not_collected"
    assert raw["coverage"]["reasons"] == ["history_not_collected"]


def test_gpo_history_starting_later_keeps_partial_state_and_limitation(reader, monkeypatch):
    monkeypatch.setattr(reporting.database, "query_rows_bounded", lambda *a, **kw: [
        confirmation(stamp=NOW - timedelta(days=2), family="gpo_v2")])
    payload = gpo.REPORT.query(QueryContext({}, {"period": PERIOD}, domain_ids=[1], tab="changes"))
    assert payload["state"] == "partial"
    assert "history_starts_later" in payload["coverage"]["reasons"]
    assert any(item["code"] == "history_starts_later" and item["text"] for item in payload["limitations"])


@pytest.mark.parametrize("module,error", [
    (ad_state, "active_directory_history_not_exportable"), (gpo, "gpo_history_not_exportable"),
])
@pytest.mark.parametrize("reader_state,expected,limitation", [
    ("unavailable", "error", "history_unavailable"),
    ("not_collected", "not_collected", "history_not_collected"),
])
def test_history_reports_use_shared_states_and_reject_unavailable_exports(
        monkeypatch, module, error, reader_state, expected, limitation):
    monkeypatch.setattr(reporting, "read_changes", lambda **kw: {
        "state": reader_state, "items": [], "coverage": {"state": reader_state}, "truncated": False,
    })
    context = QueryContext({}, {"period": PERIOD}, domain_ids=[1], tab="changes")
    payload = module.REPORT.query(context)
    assert payload["state"] == expected
    assert payload["limitations"][0]["code"] == limitation
    assert payload["limitations"][0]["text"]
    if reader_state == "unavailable":
        with pytest.raises(ValueError, match=error):
            module.REPORT.export_csv(context)
    else:
        assert module.REPORT.export_csv(context)[1] == {"rows": 0, "truncated": False}


def test_ad_membership_history_requires_privilege_category_in_same_domain_grant():
    from server.sli.reporting.v2.access import ReportAccess

    decision = {"reports": [{"report_key": "ad.state", "allowed": True,
        "allowed_actions": ["view"], "grants": [{
            "field_categories": ["identity_basic", "technical", "security"],
            "scope": {"kind": "domain", "ids": [1]}, "allowed_actions": ["view"]}]}]}
    access = ReportAccess(ad_state.REPORT, decision, "view")
    with pytest.raises(PermissionError, match="report_field_categories_not_allowed"):
        access.validate_request({}, {"tab": "changes"})


@pytest.mark.parametrize("module,families", [(ad_state, ("users_v2", "computers_v6")), (gpo, ("gpo_v2",))])
def test_report_changes_support_long_custom_period_and_export_partial_state(module, families, monkeypatch):
    query = {"period": ["custom"], "from": [START.isoformat()], "to": [NOW.isoformat()]}
    if module is ad_state:
        query.update({"domain": ["1"], "row_id": ["1:synthetic-control"]})
    params, _ = parse_params(module.REPORT, query)
    if module is ad_state:
        assert params["domain"] == 1
        assert params["row_id"] == "1:synthetic-control"
    assert params["period"]["from_utc"].startswith(START.strftime("%Y-%m-%d"))
    context = QueryContext(access={}, params=params, domain_ids=[1], tab="changes")
    def read(**kw):
        assert kw["families"] == families
        assert kw["domain_ids"] == [1]
        return {"state": "partial", "items": [], "coverage": {"state": "partial"}, "truncated": False}
    monkeypatch.setattr(reporting, "read_changes", read)
    raw = module.REPORT.query(context)
    assert raw["state"] == "partial"
    assert raw["limitations"][0]["code"] == "history_partial"
    assert raw["window"]["from_utc"] == params["period"]["from_utc"]
    assert module.REPORT.export_csv(context)[1] == {"rows": 0, "truncated": False}

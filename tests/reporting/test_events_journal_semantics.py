"""The actual journal adapter must humanize only admitted exact evidence."""
from unittest.mock import patch
from types import SimpleNamespace

from server.sli.reporting.v2.reports import events_journal as report
from server.sli.core.messages import response_messages


def context():
    return SimpleNamespace(limit=50, cursor=None, params={"period": {"from_utc": "2026-10-01T00:00:00Z", "to_utc": "2026-10-02T00:00:00Z"}},
        access={"platform_owner": True, "reports": [{"report_key": "events.explorer", "allowed": True,
            "grants": [{"scope": {"kind": "all"}, "allowed_actions": ["view"],
                        "field_categories": ["raw_evidence", "technical", "security"]}]}]})


def test_actual_journal_shows_7036_catalogue_title_not_code():
    visible = {"id": 5, "event_id": 7036, "channel": "System", "subject_user_name": None, "target_user_name": None}
    evidence = {**visible, "provider_name": "Service Control Manager", "server_id": 1, "domain_id": 2}
    with patch.object(report, "execute_report", return_value={"state": "available", "items": [visible]}), \
         patch.object(report, "query_rows_bounded", return_value=[evidence], create=True):
        body = report._query(context())
    row = body["items"][0]
    assert row["title_text"] == "Изменение состояния службы"
    assert row["participant"] == "Не определён по доступным данным"
    assert "provider_name" not in row
    assert "server_id" not in row and "domain_id" not in row
    assert row["id"] == 5 and row["event_id"] == 7036


def test_journal_localizes_derived_labels_but_not_observed_names():
    source = {"id": 5, "event_id": 7036, "channel": "System", "provider_name": "Service Control Manager", "server_id": 1, "domain_id": 2}
    with patch.object(report, "query_rows_bounded", return_value=[source]):
        titles = report._source_titles([source], context().access)
    row = report._row({"id": 5, "event_id": 7036, "channel": "System"}, titles)
    body = response_messages({"report_key": "events.journal", "items": [row]}, "en")
    assert body["items"][0]["title_text"] == "Service state changed"
    assert body["items"][0]["participant"] == "Not identified in available data"
    row = report._row({"target_user_name": "Администратор"})
    assert response_messages({"report_key": "events.journal", "items": [row]}, "en")["items"][0]["participant"] == "Администратор"


def test_wrong_missing_provider_or_mismatched_tuple_stays_unknown():
    visible = {"id": 5, "event_id": 7036, "channel": "System"}
    base = {**visible, "provider_name": "Service Control Manager", "server_id": 1, "domain_id": 2}
    for changes in ({"provider_name": "Other provider"}, {"provider_name": None}, {"provider_name": " "},
                    {"id": 99}, {"event_id": 4624}, {"channel": "Security"}, {"domain_id": None}):
        with patch.object(report, "query_rows_bounded", return_value=[{**base, **changes}]):
            assert report._source_titles([visible], context().access) == {}, changes


def test_hidden_source_fields_are_not_recovered_or_combined_across_rows():
    for items in ([{"id": 5, "event_id": 7036}], [{"id": 5, "channel": "System"}],
                  [{"event_id": 7036, "channel": "System"}],
                  [{"id": 5, "event_id": 7036}, {"id": 5, "channel": "System"}], []):
        with patch.object(report, "query_rows_bounded") as query:
            assert report._source_titles(items, context().access) == {}
            query.assert_not_called()


def test_exact_resource_denies_and_split_grants_prevent_semantic_disclosure():
    visible = {"id": 5, "event_id": 7036, "channel": "System"}
    source = {**visible, "provider_name": "Service Control Manager", "server_id": 1, "domain_id": 2}
    caps = ["field.security", "field.technical", "field.raw_evidence", "evidence.exact"]
    for denied in caps:
        access = context().access
        access["platform_owner"] = False
        access["capabilities"] = caps
        access["capability_policies"] = [{"capability_key": denied, "valid": True, "effect": "deny", "scope": {"kind": "domain", "ids": [2]}}]
        with patch.object(report, "query_rows_bounded", return_value=[source]):
            assert report._source_titles([visible], access) == {}, denied
    for grants in ([{"scope": {"kind": "domain", "ids": [99]}, "allowed_actions": ["view"], "field_categories": ["security", "technical", "raw_evidence"]}],
                   [{"scope": {"kind": "all"}, "allowed_actions": ["view"], "field_categories": [category]} for category in ("security", "technical", "raw_evidence")]):
        access = context().access
        access["reports"][0]["grants"] = grants
        with patch.object(report, "query_rows_bounded", return_value=[source]):
            assert report._source_titles([visible], access) == {}


def test_bounded_enrichment_reads_only_current_page_and_never_invents_actor():
    visible = {"id": 5, "event_id": 7036, "channel": "System"}
    with patch.object(report, "query_rows_bounded", return_value=[]) as query:
        assert report._source_titles([visible, visible], context().access) == {}
    assert query.call_args.args[1] == ([5], 1)
    assert "where event.id=any(?)" in query.call_args.args[0]
    assert query.call_args.kwargs["statement_timeout_ms"] == 3000
    row = report._row({**visible, "subject_user_name": " - ", "target_user_name": "—"})
    assert row["participant"] == "Не определён по доступным данным" and row["on_behalf"] is None


def test_non_owner_scoped_exact_evidence_can_read_title_but_missing_right_cannot():
    visible = {"id": 5, "event_id": 7036, "channel": "System"}
    source = {**visible, "provider_name": "Service Control Manager", "server_id": 1, "domain_id": 2}
    access = context().access
    access["platform_owner"] = False
    access["reports"][0]["grants"][0]["scope"] = {"kind": "domain", "ids": [2]}
    access["capability_policies"] = [{"capability_key": cap, "valid": True, "effect": "allow", "scope": {"kind": "domain", "ids": [2]}}
                                    for cap in ("field.security", "field.technical", "field.raw_evidence", "evidence.exact")]
    with patch.object(report, "query_rows_bounded", return_value=[source]):
        assert report._source_titles([visible], access)[(5, 7036, "System")]["text"] == "Изменение состояния службы"
        access["capability_policies"] = access["capability_policies"][:-1]
        assert report._source_titles([visible], access) == {}


def test_title_lookup_timeout_keeps_authorized_row_with_unknown_title():
    visible = {"id": 5, "event_id": 7036, "channel": "System"}
    with patch.object(report, "execute_report", return_value={"state": "available", "items": [visible], "next_cursor": "next", "has_more": True}), \
         patch.object(report, "query_rows_bounded", side_effect=report.QueryTimeoutError("bounded timeout", timeout_ms=3000)):
        body = report._query(context())
    assert body["items"][0]["title_text"] == "неизвестный тип события"
    assert body["items"][0]["id"] == 5
    assert body["has_more"] is True and body["next_cursor"] == "next"

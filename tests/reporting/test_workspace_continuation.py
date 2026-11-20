"""Bounded continuation contracts, using fakes instead of runtime storage."""
from http import HTTPStatus

import pytest

from server.sli.events import event_relations
from server.sli.reporting import ui_workspace
from server.sli.semantic import semantic_workspace


def test_relation_cursor_uses_exact_delta_and_id_on_both_evidence_keys(monkeypatch):
    calls = []

    def query(sql, params, **kwargs):
        if "base_event.id = ?" in sql:
            return [{"server_id": 7, "time_created_utc": "2026-10-01T00:00:00Z",
                     "logon_id": "0x123", "task_name": "synthetic-task"}]
        calls.append((sql, params))
        return [{"related_event_db_id": n, "time_delta_seconds": "1.000001"} for n in (5, 4, 3)]

    monkeypatch.setattr(event_relations, "query_rows_bounded", query)
    first = event_relations._v2_relations_response(1, 2)
    assert first["next_cursor"]
    calls.clear()
    event_relations._v2_relations_response(1, 2, cursor=first["next_cursor"])
    assert len(calls) == 2
    for sql, params in calls:
        assert "-other_event.id) >" in sql
        assert "1.000001" in params
        assert -4 in params
        assert params[-1] == 3
        assert "offset" not in sql.lower()
    with pytest.raises(ValueError, match="invalid_cursor"):
        event_relations._v2_relations_response(2, 2, cursor=first["next_cursor"])


def test_workspace_continuation_preserves_filtering_and_authorizes_before_hydration(monkeypatch):
    monkeypatch.setattr(ui_workspace, "get_event_detail_report_data", lambda **kw: {"items": [
        {"id": 1, "event_id": 4624, "time_created_utc": "2026-10-01T00:00:00Z", "event_data": {}}]})
    relation_calls, hydrated = [], []

    def relations(event_id, **kwargs):
        relation_calls.append(kwargs)
        return {"items": [{"related_event_db_id": 2 if "cursor" not in kwargs else 3}],
                "truncated": "cursor" not in kwargs, "next_cursor": "relation-next" if "cursor" not in kwargs else None}

    def details(ids, **kw):
        hydrated.extend(ids)
        return {n: {"id": n, "event_id": 4624, "time_created_utc": "2026-10-01T00:00:00Z", "event_data": {}} for n in ids}

    monkeypatch.setattr(ui_workspace, "get_event_relations", relations)
    monkeypatch.setattr(ui_workspace, "get_event_details_by_ids", details)
    first = ui_workspace.get_investigations_workspace_data(q=None, event_db_id=1, related_event_allowed=lambda n: False)
    assert first["summary"]["has_more"]
    assert hydrated == []
    second = ui_workspace.get_investigations_workspace_data(q=None, event_db_id=1, cursor=first["next_cursor"], related_event_allowed=lambda n: n == 3)
    assert relation_calls[-1]["cursor"] == "relation-next"
    assert hydrated == [3]
    assert [n["event_db_id"] for n in second["timeline"]] == [3]
    assert second["next_cursor"] is None
    with pytest.raises(ValueError, match="invalid_cursor"):
        ui_workspace.get_investigations_workspace_data(q=None, event_db_id=1, time_from="2026-10-01", cursor=first["next_cursor"])


def scenario_row(n, evidence=()):
    return {"scenario_id": f"00000000-0000-0000-0000-{n:012d}", "scenario_kind": "synthetic",
            "result_class": "security_incident", "scenario_status": "open", "partition_key": "synthetic",
            "title": "Synthetic", "explanation": "Synthetic", "risk_class": "low", "updated_at": "2026-10-01T00:00:00Z",
            "evidence": list(evidence)}


def test_scenarios_and_evidence_have_bounded_keyset_continuation(monkeypatch):
    calls = []
    monkeypatch.setattr(semantic_workspace, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(semantic_workspace, "_execution_contract", lambda **kw: ({}, 29))
    evidence = [{"normalized_event_id": f"00000000-0000-0000-0000-{n:012d}", "event_db_id": n, "evidence_order": 1} for n in range(1, 7)]

    def query(sql, params, **kwargs):
        calls.append((sql, params))
        return [scenario_row(2, evidence), scenario_row(1)]

    monkeypatch.setattr(semantic_workspace, "query_rows_bounded", query)
    first = semantic_workspace.get_semantic_scenarios_workspace_data(limit=1)
    assert first["next_cursor"]
    item = first["items"][0]
    assert len(item["evidence"]) == 5
    assert item["evidence_has_more"]
    semantic_workspace.get_semantic_scenarios_workspace_data(limit=1, cursor=first["next_cursor"])
    assert "(scenario.updated_at, scenario.scenario_id) <" in calls[-1][0]
    assert calls[-1][1][-1] == 2
    semantic_workspace.get_semantic_scenarios_workspace_data(scenario_id=item["scenario_id"], evidence_cursor=item["evidence_next_cursor"])
    assert "(item.evidence_order, item.normalized_event_id) >" in calls[-1][0]
    assert "limit 6" in calls[-1][0]
    assert "offset" not in calls[-1][0].lower()
    with pytest.raises(ValueError, match="invalid_cursor"):
        semantic_workspace.get_semantic_scenarios_workspace_data(status="resolved", cursor=first["next_cursor"])
    with pytest.raises(ValueError, match="invalid_cursor"):
        semantic_workspace.get_semantic_scenarios_workspace_data(scenario_id=scenario_row(1)["scenario_id"], evidence_cursor=item["evidence_next_cursor"])


def test_investigation_api_forwards_cursor_and_serializes_it(monkeypatch):
    from server.api.routes import investigations

    class Handler:
        def _send_json(self, payload, status=HTTPStatus.OK):
            self.payload, self.status = payload, status

    handler = Handler()
    captured = []
    monkeypatch.setattr(investigations, "_event_resources", lambda *args: [])
    monkeypatch.setattr(investigations, "_require_investigation_access", lambda *args: True)
    monkeypatch.setattr(investigations, "get_investigations_workspace_data", lambda **kw: captured.append(kw) or {
        "query": "", "scope": "all", "state": "ok", "summary": {"events_returned": 0, "has_more": True,
        "attention_level": "unknown", "story": "", "why_it_matters": ""}, "timeline": [], "findings": [],
        "next_checks": [], "limits": {}, "next_cursor": "next-page"})
    investigations._handle_v1_investigations_api(handler, {"event_db_id": ["1"], "cursor": ["previous-page"]})
    assert captured[0]["cursor"] == "previous-page"
    assert handler.payload["next_cursor"] == "next-page"
    assert handler.status == HTTPStatus.OK


def test_semantic_api_keeps_continuation_fields_and_forwards_both_cursors(monkeypatch):
    from server.api.routes import semantic

    calls, sent = [], []

    class Handler:
        def _send_json(self, payload, status=HTTPStatus.OK):
            sent.append((payload, status))

    def read(**kwargs):
        calls.append(kwargs)
        row = scenario_row(1)
        row.update({"first_seen_utc": "2026-10-01T00:00:00Z", "last_seen_utc": "2026-10-01T00:00:00Z"})
        item = semantic_workspace._scenario_item(row)
        item.update({"evidence_has_more": True, "evidence_next_cursor": "evidence-next"})
        return {"generated_at_utc": "2026-10-01T00:00:00Z", "state": "available", "items": [item],
                "has_more": True, "next_cursor": "scenario-next", "filters": {}, "limits": {},
                "execution": {"state": "active", "schema_state": "ready", "feature_chain": {},
                              "worker": {"state": "running", "status": "running"}, "finding_path_live": False}}

    monkeypatch.setattr(semantic, "get_semantic_scenarios_workspace_data", read)
    semantic._handle_v1_semantic_scenarios_api(Handler(), {"cursor": ["previous-list"]})
    assert calls[0]["cursor"] == "previous-list"
    assert sent[0][0]["next_cursor"] == "scenario-next"
    assert sent[0][0]["items"][0]["evidence_next_cursor"] == "evidence-next"
    semantic._handle_v1_semantic_scenarios_api(Handler(), {
        "scenario_id": [scenario_row(1)["scenario_id"]], "evidence_cursor": ["previous-evidence"]})
    assert calls[-1]["evidence_cursor"] == "previous-evidence"
    assert calls[-1]["scenario_id"] == scenario_row(1)["scenario_id"]


def test_all_seventy_evidences_are_read_once_with_tied_order_values(monkeypatch):
    monkeypatch.setattr(semantic_workspace, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(semantic_workspace, "_execution_contract", lambda **kw: ({}, 29))
    evidence = [{"normalized_event_id": f"00000000-0000-0000-0000-{n:012d}", "event_db_id": n,
                 "evidence_order": 1} for n in range(1, 71)]

    def query(sql, params, **kwargs):
        after_id = params[1] if "(item.evidence_order, item.normalized_event_id) >" in sql else ""
        assert "limit 6" in sql
        return [scenario_row(1, [row for row in evidence if row["normalized_event_id"] > after_id][:6])]

    monkeypatch.setattr(semantic_workspace, "query_rows_bounded", query)
    page = semantic_workspace.get_semantic_scenarios_workspace_data()["items"][0]
    ids = [row["event_db_id"] for row in page["evidence"]]
    for _ in range(13):
        assert page["evidence_next_cursor"]
        page = semantic_workspace.get_semantic_scenarios_workspace_data(
            scenario_id=page["scenario_id"], evidence_cursor=page["evidence_next_cursor"])["items"][0]
        ids.extend(row["event_db_id"] for row in page["evidence"])
    assert ids == list(range(1, 71))
    assert page["evidence_next_cursor"] is None
    assert page["evidence_has_more"] is False


def test_scenario_list_reads_beyond_thirty_with_tied_timestamps(monkeypatch):
    monkeypatch.setattr(semantic_workspace, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(semantic_workspace, "_execution_contract", lambda **kw: ({}, 29))
    rows = [scenario_row(n) for n in range(35, 0, -1)]

    def query(sql, params, **kwargs):
        assert params[-1] == 31
        after_id = params[-2] if "(scenario.updated_at, scenario.scenario_id) <" in sql else None
        return [row for row in rows if after_id is None or row["scenario_id"] < after_id][:31]

    monkeypatch.setattr(semantic_workspace, "query_rows_bounded", query)
    first = semantic_workspace.get_semantic_scenarios_workspace_data()
    second = semantic_workspace.get_semantic_scenarios_workspace_data(cursor=first["next_cursor"])
    assert [row["scenario_id"] for row in first["items"] + second["items"]] == [row["scenario_id"] for row in rows]
    assert second["has_more"] is False
    assert second["next_cursor"] is None


def test_metadata_only_evidence_continuation_keeps_the_exact_authorization_guard(monkeypatch):
    monkeypatch.setattr(semantic_workspace, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(semantic_workspace, "_execution_contract", lambda **kw: ({}, 29))
    row = scenario_row(1, [{"normalized_event_id": f"00000000-0000-0000-0000-{n:012d}",
                            "event_db_id": n, "evidence_order": n} for n in range(1, 7)])
    calls = []

    def query(sql, params, **kwargs):
        calls.append((sql, params))
        return [row]

    monkeypatch.setattr(semantic_workspace, "query_rows_bounded", query)
    first = semantic_workspace.get_semantic_scenarios_workspace_data(
        event_item_ids=[row["scenario_id"]], authorized_evidence_ids=list(range(1, 7)), metadata_only=True)
    item = first["items"][0]
    assert item["evidence_next_cursor"]
    assert item["partition_key"] == ""
    semantic_workspace.get_semantic_scenarios_workspace_data(scenario_id=row["scenario_id"],
        evidence_cursor=item["evidence_next_cursor"], event_item_ids=[row["scenario_id"]],
        authorized_evidence_ids=list(range(1, 7)), metadata_only=True)
    assert "guard_event.source_event_id = any(?::bigint[])" in calls[-1][0]
    assert list(range(1, 7)) in calls[-1][1]


def test_case_list_api_uses_the_same_number_as_the_case_response(monkeypatch):
    from server.api.routes import investigations

    class Handler:
        def _send_json(self, payload, status=HTTPStatus.OK):
            self.payload = payload

    monkeypatch.setattr(investigations, "_require_investigation_module", lambda *args: True)
    monkeypatch.setattr(investigations, "list_cases", lambda **kw: [{"id": 1, "public_id": "00000000-0000-0000-0000-000000000101"}])
    monkeypatch.setattr(investigations, "_case_resources_batch", lambda *args: {})
    monkeypatch.setattr(investigations, "_investigation_access_decision", lambda *args: {"allowed": True})
    handler = Handler()
    investigations._handle_v1_investigation_cases_api(handler, {})
    assert handler.payload["items"][0]["case_number"] == "INV-0000001"


def test_case_response_has_short_number_and_keeps_uuid_for_internal_identity():
    from server.sli.reporting.ui_api_models import InvestigationCaseResponse

    result = InvestigationCaseResponse(id=1, public_id="00000000-0000-0000-0000-000000000101",
        title="Synthetic", status="open", created_by="synthetic", created_at="2026-10-01T00:00:00Z",
        updated_at="2026-10-01T00:00:00Z").model_dump(mode="json")
    assert result["case_number"] == "INV-0000001"
    assert result["public_id"] == "00000000-0000-0000-0000-000000000101"


@pytest.mark.parametrize("cursor", ["", "garbage", "a" * 2049, "W10"])
def test_invalid_cursor_never_reaches_storage(monkeypatch, cursor):
    monkeypatch.setattr(event_relations, "_require_v2_relations_route", lambda *args: None)
    monkeypatch.setattr(event_relations, "query_rows_bounded", lambda *args, **kw: pytest.fail("invalid cursor read"))
    with pytest.raises(ValueError, match="invalid_cursor"):
        event_relations.get_event_relations(1, cursor=cursor)

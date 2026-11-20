"""Exact-event semantic lookup must not turn membership metadata into a grant."""
from http import HTTPStatus

import pytest


def test_semantic_read_responses_accept_investigation_runtime_mode():
    """Removing the admitted read-only mode must not turn both event lookups into HTTP 500."""
    from server.sli.reporting.ui_api_models import SemanticActionsResponse, SemanticScenariosResponse

    common = {
        "generated_at_utc": "2026-09-13T21:45:58Z",
        "execution": {
            "state": "active",
            "schema_state": "ready",
            "runtime_mode": "investigation-v1",
            "feature_chain": {"normalization": True, "assembly": True, "correlation": True},
            "worker": {"state": "idle", "status": "production_sleep", "runtime_mode": "investigation-v1"},
            "finding_path_live": False,
        },
        "state": "empty",
        "items": [],
        "has_more": False,
        "filters": {},
        "limits": {},
    }

    for response_type in (SemanticActionsResponse, SemanticScenariosResponse):
        response = response_type(**common)
        assert response.execution.runtime_mode == "investigation-v1"


def test_actions_preflight_uses_exact_normalized_proof_and_exclusive_bounds(monkeypatch):
    from server.sli.semantic import semantic_workspace as workspace

    monkeypatch.setattr(workspace, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(workspace, "_execution_contract", lambda **_kw: ({"schema_state": "ready"}, 29))
    calls = []

    def rows(sql, params, **_kw):
        calls.append((sql, params))
        return [{"item_id": "00000000-0000-0000-0000-000000000101", "evidence_event_ids": [41, 42]}]

    monkeypatch.setattr(workspace, "query_rows_bounded", rows)
    preflight = workspace.get_semantic_actions_event_preflight(
        event_db_id=41, time_from="2026-09-10", time_to="2026-09-10", timezone_name="UTC",
    )

    assert preflight["state"] == "ready"
    assert preflight["resource_event_ids"] == [41, 42]
    assert "anchor.source_event_id = ?" in calls[0][0]
    assert "anchor.occurred_at_utc >= ?" in calls[0][0]
    assert calls[0][1][:3] == (41, "2026-09-10T00:00:00Z", "2026-09-11T00:00:00Z")


def test_scoped_denial_after_metadata_preflight_is_not_found_and_never_reads_payload(monkeypatch):
    from server.api.http_server import RequestHandler
    from server.api.routes import semantic

    handler = object.__new__(RequestHandler)
    handler._effective_access_cache = {
        "capabilities": ["semantic.review", "evidence.exact", "field.security"],
        "resource_bound_capabilities": [],
        "capability_policies": [{
            "capability_key": "semantic.review", "effect": "deny",
            "scope": {"kind": "server", "ids": [9]}, "valid": True,
        }],
    }
    sent = []
    handler._send_json = lambda payload, status=HTTPStatus.OK: sent.append((payload, status))
    monkeypatch.setattr(semantic, "get_semantic_actions_event_preflight", lambda **_kw: {
        "state": "ready", "resource_event_ids": [41, 42],
    })
    monkeypatch.setattr(semantic, "event_resource_group", lambda event_id, **kw: [{"kind": "server", "id": 7 if event_id == 41 else 9}])
    monkeypatch.setattr(semantic, "get_semantic_actions_workspace_data", lambda **_kw: (_ for _ in ()).throw(AssertionError("payload read")))

    semantic._handle_v1_semantic_actions_api(handler, {"event_db_id": ["41"]})

    assert sent == [({"error": "not_found"}, HTTPStatus.NOT_FOUND)]


def test_unavailable_preflight_does_not_publish_partial_items(monkeypatch):
    from server.api.http_server import RequestHandler
    from server.api.routes import semantic

    handler = object.__new__(RequestHandler)
    handler._effective_access_cache = {"capabilities": ["semantic.review", "evidence.exact", "field.security"]}
    sent = []
    handler._send_json = lambda payload, status=HTTPStatus.OK: sent.append((payload, status))
    monkeypatch.setattr(semantic, "event_resource_group", lambda *a, **kw: [{"kind": "server", "id": 7}])
    monkeypatch.setattr(semantic, "get_semantic_scenarios_event_preflight", lambda **_kw: {
        "state": "unavailable", "resource_event_ids": [], "reason": "evidence_unavailable",
        "execution": {"state": "enabled_without_worker", "runtime_mode": "facts-v1"},
    })
    monkeypatch.setattr(semantic, "get_semantic_scenarios_workspace_data", lambda **_kw: (_ for _ in ()).throw(AssertionError("payload read")))

    semantic._handle_v1_semantic_scenarios_api(handler, {"event_db_id": ["41"]})

    assert sent[0][0]["state"] == "unavailable"
    assert sent[0][0]["items"] == []
    assert sent[0][0]["limits"]["coverage_state"] == "unavailable"
    assert sent[0][0]["execution"]["state"] == "enabled_without_worker"
    assert not sent[0][0]["generated_at_utc"].startswith("1970")


def test_malformed_exact_event_filter_never_falls_back_to_global_workspace(monkeypatch):
    from server.api.routes import semantic

    sent = []
    handler = type("Handler", (), {"_send_json": lambda _self, payload, status=400: sent.append((payload, status))})()
    monkeypatch.setattr(semantic, "get_semantic_actions_workspace_data", lambda **_kw: (_ for _ in ()).throw(AssertionError("broad read")))

    with pytest.raises(Exception, match="invalid_event_db_id"):
        semantic._handle_v1_semantic_actions_api(handler, {"event_db_id": ["1.0"]})
    assert sent == []


def test_event_filtered_items_mark_hidden_payload_fields():
    from server.sli.semantic.semantic_workspace import metadata_only_action_item, metadata_only_scenario_item

    action = metadata_only_action_item({"canonical_action_id": "a", "attributes_json": {"secret": "no"}})
    scenario = metadata_only_scenario_item({"scenario_id": "s", "strict_keys_json": {"secret": "no"}, "confidence_factors_json": {"secret": "no"}})

    assert action["attributes"] == {}
    assert action["payload_state"] == "metadata_only"
    assert scenario["strict_keys"] == scenario["confidence_factors"] == {}
    assert scenario["payload_state"] == "metadata_only"


def test_metadata_scenario_cannot_retain_identity_text_or_analyst_notes():
    from server.sli.semantic.semantic_workspace import metadata_only_scenario_item
    row = {key: "sensitive-identity" for key in (
        "title", "explanation", "partition_key", "strict_keys", "confidence_factors",
        "completeness_snapshot", "latest_review", "future_private_field")}
    row.update({"scenario_id": "s", "scenario_kind": "kind", "status": "open"})
    result = metadata_only_scenario_item(row)
    assert "sensitive-identity" not in str(result)
    assert result["scenario_id"] == "s"
    assert result["payload_state"] == "metadata_only"


@pytest.mark.parametrize("evidence", [list(range(1, 66)), [41, None], [41, -1]])
def test_preflight_refuses_overbound_or_incomplete_evidence_before_authorization(monkeypatch, evidence):
    from server.sli.semantic import semantic_workspace as workspace
    monkeypatch.setattr(workspace, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(workspace, "_execution_contract", lambda **kw: ({"schema_state": "ready"}, 29))
    monkeypatch.setattr(workspace, "query_rows_bounded", lambda *args, **kwargs: [{"item_id": "a", "evidence_event_ids": evidence}])
    result = workspace.get_semantic_actions_event_preflight(event_db_id=41)
    assert result["state"] == "unavailable"
    assert result["resource_event_ids"] == []


@pytest.mark.parametrize("kind,forbidden", [
    ("actions", ["action.attributes_json"]),
    ("scenarios", ["scenario.title", "scenario.explanation", "scenario.partition_key", "scenario.strict_keys_json", "scenario.confidence_factors_json", "review.rationale", "result.completeness_snapshot_json"]),
])
def test_exact_metadata_query_excludes_hidden_columns_and_rechecks_all_proof(monkeypatch, kind, forbidden):
    from server.sli.semantic import semantic_workspace as workspace
    monkeypatch.setattr(workspace, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(workspace, "_execution_contract", lambda **kw: ({"analyst_review_schema_ready": True, "conclusion_completeness_schema_ready": True}, 29))
    queries = []
    monkeypatch.setattr(workspace, "query_rows_bounded", lambda sql, params, **kw: queries.append((sql, params)) or [])
    reader = getattr(workspace, f"get_semantic_{kind}_workspace_data")
    reader(event_item_ids=["00000000-0000-0000-0000-000000000101"], metadata_only=True, authorized_evidence_ids=[41, 42])
    sql, params = queries[0]
    assert all(column not in sql for column in forbidden)
    assert "not exists" in sql.lower()
    assert "guard_event.source_event_id" in sql
    assert [41, 42] in params
    if kind == "scenarios":
        assert "result.conclusion_state" in sql


def test_denied_anchor_cannot_probe_semantic_metadata_or_limits(monkeypatch):
    from server.api.routes import semantic
    class Handler:
        storage_route_authorization = None
        def _access_decision(self):
            return {"capabilities": ["semantic.review", "evidence.exact", "field.security"],
                    "capability_policies": [{"capability_key": "evidence.exact", "effect": "deny", "valid": True, "scope": {"kind": "server", "ids": [9]}}]}
        def _send_json(self, payload, status=200):
            self.result = (payload, status)
    handler = Handler()
    monkeypatch.setattr(semantic, "event_resource_group", lambda *a, **kw: [{"kind": "server", "id": 9}])
    monkeypatch.setattr(semantic, "get_semantic_actions_event_preflight", lambda **kw: pytest.fail("denied metadata read"))
    semantic._handle_v1_semantic_actions_api(handler, {"event_db_id": ["41"]})
    assert handler.result == ({"error": "not_found"}, HTTPStatus.NOT_FOUND)


def test_duplicate_time_filter_is_not_silently_narrowed_to_first_value(monkeypatch):
    from server.api.routes import semantic
    handler = type("Handler", (), {"_access_decision": lambda self: pytest.fail("ambiguous context reached authorization")})()
    with pytest.raises(Exception, match="invalid_semantic_context"):
        semantic._handle_v1_semantic_actions_api(handler, {"event_db_id": ["41"], "time_from": ["2026-09-10", "2026-09-11"]})

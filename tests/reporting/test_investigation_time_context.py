"""An exact evidence anchor must not silently discard the selected time window."""
import pytest

from server.sli.reporting import ui_workspace
from server.sli.core.time_contract import TimeRangeError


def test_entity_security_interpretation_reuses_authorized_readers_with_exact_window(monkeypatch):
    from server.api.routes import entities

    reader = getattr(entities, "entity_security_interpretation", None)
    assert callable(reader)
    calls: list[tuple[str, dict]] = []

    def actions(access, **kwargs):
        calls.append(("actions", kwargs))
        return {"state": "available", "items": [{"event_db_id": 517548, "event_id": 4722}]}

    def relations(access, **kwargs):
        calls.append(("relations", kwargs))
        return {"state": "available", "items": [{"candidate_id": "saved-relation"}]}

    monkeypatch.setattr(entities, "get_security_events_report", actions, raising=False)
    monkeypatch.setattr(entities, "get_semantic_relations", relations, raising=False)
    result = reader(
        {"reports": []}, entity_id=5632, domain_id=7,
        time_from_utc="2026-09-11T10:20:30.123456Z",
        time_to_utc_exclusive="2026-09-11T11:20:30.987654Z",
        timezone_name="Asia/Bangkok", limit=50,
    )

    assert result == {
        "security_actions_state": "available",
        "security_actions": [{"event_db_id": 517548, "event_id": 4722}],
        "semantic_relations_state": "available",
        "semantic_relations": [{"candidate_id": "saved-relation"}],
    }
    assert calls == [
        ("actions", {
            "source_domain_id": 7, "time_from": "2026-09-11T10:20:30.123456Z",
            "time_to": "2026-09-11T11:20:30.987654Z", "timezone_name": "Asia/Bangkok",
            "limit": 50, "entity_id": 5632,
        }),
        ("relations", {
            "domain_id": 7, "time_from": "2026-09-11T10:20:30.123456Z",
            "time_to": "2026-09-11T11:20:30.987654Z", "timezone_name": "Asia/Bangkok",
            "limit": 50, "entity_id": 5632,
        }),
    ]


def test_entity_security_interpretation_fails_closed_for_denied_or_partial_reader_results(monkeypatch):
    from server.api.routes import entities

    monkeypatch.setattr(entities, "get_security_events_report", lambda *_args, **_kwargs: {
        "state": "not_authorized", "items": [{"event_db_id": 517548}], "total": 1,
    })
    monkeypatch.setattr(entities, "get_semantic_relations", lambda *_args, **_kwargs: {
        "state": "partially_authorized", "items": [{"candidate_id": "must-not-leak"}], "count": 1,
    })

    result = entities.entity_security_interpretation(
        {"reports": []}, entity_id=5632, domain_id=7,
        time_from_utc="2026-09-11T10:20:30.123456Z",
        time_to_utc_exclusive="2026-09-11T11:20:30.987654Z",
        timezone_name="Asia/Bangkok", limit=50,
    )

    assert result == {
        "security_actions_state": "not_authorized", "security_actions": [],
        "semantic_relations_state": "partially_authorized", "semantic_relations": [],
    }
    assert "total" not in result
    assert "count" not in result


def test_entity_history_preserves_scope_without_hidden_candidate_count(monkeypatch):
    monkeypatch.setattr(ui_workspace, "resolve_storage_route", lambda **kw: {"route": "v2"})
    monkeypatch.setattr(ui_workspace, "_get_entity_evidence_event_rows", lambda **kw: [
        {"event_db_id": n} for n in range(1, ui_workspace.INVESTIGATION_TIMELINE_LIMIT + 2)
    ])
    monkeypatch.setattr(ui_workspace, "get_event_details_by_ids", lambda ids, **kw: {
        n: {"id": n, "event_id": 4624, "time_created_utc": "2026-09-10T00:00:00Z", "event_data": {}} for n in ids
    })
    result = ui_workspace.get_investigations_workspace_data(q=None, entity_id=42, scope="all",
        entity_evidence_allowed=lambda n: n == 1)
    assert result["scope"] == "all"
    assert result["summary"]["has_more"] is False
    assert len(result["timeline"]) == 1


@pytest.mark.parametrize("event_id", [0, -1, "", "wrong", "1.2", 1.2, True, "1e2", "9007199254740992"])
def test_invalid_exact_anchor_never_falls_back_to_general_search(monkeypatch, event_id):
    monkeypatch.setattr(ui_workspace, "resolve_storage_route", lambda **kw: pytest.fail("general search boundary"))
    monkeypatch.setattr(ui_workspace, "get_event_detail_report_data", lambda **kw: pytest.fail("invalid anchor read"))
    with pytest.raises(ValueError, match="invalid_event_db_id"):
        ui_workspace.get_investigations_workspace_data(q="user", event_db_id=event_id)


@pytest.mark.parametrize("entity_id", [0, -1, "", "wrong", "1.2", 1.2, True, "1e2", "9007199254740992"])
def test_invalid_exact_entity_never_falls_back_or_reads_evidence(monkeypatch, entity_id):
    monkeypatch.setattr(ui_workspace, "resolve_storage_route", lambda **kw: pytest.fail("storage route"))
    monkeypatch.setattr(ui_workspace, "_get_entity_evidence_event_rows", lambda **kw: pytest.fail("entity evidence"))
    with pytest.raises(ValueError, match="invalid_entity_id"):
        ui_workspace.get_investigations_workspace_data(q="name-must-not-be-used", entity_id=entity_id)


def test_exact_entity_history_preflights_each_proof_before_metadata_and_ignores_name_query(monkeypatch):
    candidates = [
        {"event_db_id": 22, "server_id": 7, "domain_id": 1, "channel": "Security"},
        {"event_db_id": 21, "server_id": 7, "domain_id": 1, "channel": "Security"},
    ]
    checked: list[int] = []
    metadata_ids: list[int] = []
    monkeypatch.setattr(ui_workspace, "resolve_storage_route", lambda **_kw: {"route": "v2"})

    def evidence_rows(**kwargs):
        assert kwargs["entity_id"] == 55
        assert kwargs["time_from_utc"] == "2026-09-10T00:00:00Z"
        assert kwargs["time_to_utc_exclusive"] == "2026-09-11T00:00:00Z"
        if kwargs.get("id_only") is True:
            assert kwargs["limit"] == ui_workspace.INVESTIGATION_TIMELINE_LIMIT + 1
            return candidates
        assert kwargs["event_db_ids"] == [22, 21]
        assert kwargs["field_projection"] == "security_history"
        assert kwargs["limit"] == 2
        metadata_ids.extend(kwargs["event_db_ids"])
        return [
            {
                "event_db_id": event_db_id,
                "event_id": 4624,
                "time_created_utc": f"2026-09-10T0{event_db_id - 20}:00:00Z",
                "server": "dc.example.invalid",
                "channel": "Security",
                "subject_user_name": "operator",
                "target_user_name": "alice",
            }
            for event_db_id in kwargs["event_db_ids"]
        ]

    monkeypatch.setattr(ui_workspace, "_get_entity_evidence_event_rows", evidence_rows)

    def allowed(event_db_id: int) -> bool:
        checked.append(event_db_id)
        return True

    monkeypatch.setattr(
        ui_workspace,
        "get_event_details_by_ids",
        lambda *_args, **_kwargs: pytest.fail("entity history must not hydrate archive payload"),
    )
    result = ui_workspace.get_investigations_workspace_data(
        q="name-must-not-be-used", entity_id=55,
        time_from="2026-09-10", time_to="2026-09-10", timezone_name="UTC",
        entity_evidence_allowed=allowed,
    )

    assert result["query"] == ""
    assert result["anchor_event_db_id"] is None
    assert result["context"]["entity_id"] == 55
    assert [item["event_db_id"] for item in result["timeline"]] == [22, 21]
    assert checked == [22, 21]
    assert metadata_ids == [22, 21]
    assert result["limits"]["full_history"] is False
    assert result["limits"]["coverage"] == "bounded_exact_entity_evidence"
    assert all("причин" in item["inclusion_reason"].lower() for item in result["timeline"])


def test_entity_id_only_reader_resolves_exact_identity_and_never_selects_payload(monkeypatch):
    calls = []
    monkeypatch.setattr(ui_workspace, "is_postgres_runtime_db", lambda: True)

    def query(sql, params, **kwargs):
        calls.append((sql, params, kwargs))
        return []

    monkeypatch.setattr(ui_workspace, "query_rows_bounded", query)
    assert ui_workspace._get_entity_evidence_event_rows(
        entity_id=55, limit=101, before_time_utc=None, before_event_db_id=None,
        time_from_utc="2026-09-10T00:00:00Z", time_to_utc_exclusive="2026-09-11T00:00:00Z",
        id_only=True,
    ) == []
    sql, params, kwargs = calls[0]
    assert "resolve_entity_identity_v2(?)" in sql
    normalized_sql = " ".join(sql.split()).lower()
    assert "with ordered_candidates as" in normalized_sql
    assert "select distinct event.id" in normalized_sql
    assert "event.time_created_utc as sort_time_utc" in normalized_sql
    assert "select event_db_id, server_id, domain_id, channel from ordered_candidates" in normalized_sql
    assert "server.hostname" not in sql
    assert "record_xml" not in normalized_sql
    assert "message_text" not in normalized_sql
    assert "event_data_json" not in normalized_sql
    assert params == (55, "2026-09-10T00:00:00Z", "2026-09-11T00:00:00Z", 101)
    assert kwargs["statement_timeout_ms"] == 3000


@pytest.fixture
def anchored_sources(monkeypatch):
    base = {"id": 10, "event_id": 4720, "time_created_utc": "2026-09-10T00:00:00Z",
            "server": "dc.example.invalid", "channel": "Security", "event_data": {}}
    monkeypatch.setattr(ui_workspace, "get_event_detail_report_data", lambda **kw: {"items": [base]})
    monkeypatch.setattr(ui_workspace, "get_event_relations", lambda *a, **kw: {"items": [
        {"related_event_db_id": 11, "reason": "within window"},
        {"related_event_db_id": 12, "reason": "outside window"},
        {"related_event_db_id": 13, "reason": "unknown time"},
    ]})
    monkeypatch.setattr(ui_workspace, "get_event_details_by_ids", lambda *a, **kw: {
        11: {**base, "id": 11, "time_created_utc": "2026-09-10T01:00:00Z"},
        12: {**base, "id": 12, "time_created_utc": "2026-09-11T00:00:00Z"},
        13: {**base, "id": 13, "time_created_utc": None},
    })


def test_anchor_honors_exclusive_window_and_reports_unknown_time(anchored_sources):
    result = ui_workspace.get_investigations_workspace_data(
        q=None, event_db_id=10, time_from="2026-09-10", time_to="2026-09-10", timezone_name="UTC")
    assert [row["event_db_id"] for row in result["timeline"]] == [11, 10]
    assert result["context"]["time_to_utc_exclusive"] == "2026-09-11T00:00:00Z"
    assert result["limits"]["events_with_unknown_time"] == 1
    assert result["context"]["anchor_in_window"] is True


def test_anchor_outside_window_is_explicit_not_silently_reinserted(anchored_sources):
    result = ui_workspace.get_investigations_workspace_data(
        q=None, event_db_id=10, time_from="2026-09-10T01:00:00Z", time_to="2026-09-10T02:00:00Z")
    assert [row["event_db_id"] for row in result["timeline"]] == [11]
    assert result["context"]["anchor_in_window"] is False


def test_invalid_window_fails_before_loading_anchor(monkeypatch):
    monkeypatch.setattr(ui_workspace, "get_event_detail_report_data", lambda **kw: pytest.fail("source read"))
    with pytest.raises(TimeRangeError, match="empty_or_reversed_time_range"):
        ui_workspace.get_investigations_workspace_data(q=None, event_db_id=10,
            time_from="2026-09-12", time_to="2026-09-10")


def test_local_dates_normalize_once(anchored_sources):
    result = ui_workspace.get_investigations_workspace_data(q=None, event_db_id=10,
        time_from="2026-09-10", time_to="2026-09-10", timezone_name="Asia/Bangkok")
    assert result["context"]["time_from_utc"] == "2026-09-09T17:00:00Z"
    assert result["context"]["time_to_utc_exclusive"] == "2026-09-10T17:00:00Z"


def test_related_scope_is_checked_before_event_payload_read(anchored_sources, monkeypatch):
    checked = []
    loaded = []

    def allowed(event_id):
        checked.append(event_id)
        return event_id == 11

    def load(event_ids, **kwargs):
        loaded.extend(event_ids)
        return {11: {"id": 11, "event_id": 4720,
                     "time_created_utc": "2026-09-10T01:00:00Z", "event_data": {}}}

    monkeypatch.setattr(ui_workspace, "get_event_details_by_ids", load)
    result = ui_workspace.get_investigations_workspace_data(
        q=None, event_db_id=10, related_event_allowed=allowed)
    assert checked == [11, 12, 13]
    assert loaded == [11]
    assert {row["event_db_id"] for row in result["timeline"]} == {10, 11}
    assert "outside window" not in str(result)
    assert "unknown time" not in str(result)


@pytest.mark.parametrize("denial", ["report_scope", "capability_scope", "missing"])
def test_http_related_scope_never_reaches_payload_loader(anchored_sources, monkeypatch, denial):
    from server.api.http_server import RequestHandler
    from server.api.routes import investigations as routes
    from server.sli.semantic.investigation_cases import InvestigationCaseError

    handler = object.__new__(RequestHandler)
    handler._effective_access_cache = {
        "capabilities": ["investigations.view"],
        "resource_bound_capabilities": [],
        "capability_policies": ([{"capability_key": "investigations.view", "effect": "deny",
                                  "scope": {"kind": "server", "ids": [9]}, "valid": True}]
                                if denial == "capability_scope" else []),
        "reports": [{"report_key": "investigations.workspace", "allowed": True,
                     "allowed_actions": ["view"], "grants": [{
                         "scope": {"kind": "server", "ids": [7, 9] if denial == "capability_scope" else [7]},
                         "allowed_actions": ["view"], "field_categories": ["security"]}]}],
    }
    sent = []
    handler._send_json = lambda payload, status=200: sent.append((payload, status))

    def resources(event_id):
        if event_id not in (10, 11) and denial == "missing":
            raise InvestigationCaseError("not_found", "unavailable")
        return [{"kind": "server", "id": 7 if event_id in (10, 11) else 9}]

    def load(event_ids, **kwargs):
        assert event_ids == [11], "denied related event reached payload read"
        return {11: {"id": 11, "event_id": 4720,
                     "time_created_utc": "2026-09-10T01:00:00Z", "event_data": {}}}

    monkeypatch.setattr(routes, "event_resource_group", resources)
    monkeypatch.setattr(ui_workspace, "get_event_details_by_ids", load)
    routes._handle_v1_investigations_api(handler, {"event_db_id": ["10"]})
    assert len(sent) == 1
    payload, status = sent[0]
    assert status == 200
    assert {row["event_db_id"] for row in payload["timeline"]} == {10, 11}


def test_http_entity_history_authorizes_each_exact_proof_before_payload(monkeypatch):
    from server.api.http_server import RequestHandler
    from server.api.routes import investigations as routes

    handler = object.__new__(RequestHandler)
    handler._effective_access_cache = {
        "capabilities": ["objects.view", "investigations.view", "evidence.exact", "field.security"],
        "resource_bound_capabilities": [],
        "reports": [{"report_key": "investigations.workspace", "allowed": True,
                     "allowed_actions": ["view"], "grants": [{
                         "scope": {"kind": "server", "ids": [7]},
                         "allowed_actions": ["view"], "field_categories": ["security"]}]}],
    }
    sent = []
    handler._send_json = lambda payload, status=200: sent.append((payload, status))
    monkeypatch.setattr(ui_workspace, "resolve_storage_route", lambda **_kw: {"route": "v2"})
    monkeypatch.setattr(ui_workspace, "_get_entity_evidence_event_rows", lambda **_kw: [
        {"event_db_id": 12, "time_created_utc": "2026-09-10T02:00:00Z"},
        {"event_db_id": 11, "time_created_utc": "2026-09-10T01:00:00Z"},
    ])
    monkeypatch.setattr(routes, "event_resource_group", lambda event_id: [{"kind": "server", "id": 7 if event_id == 11 else 9}])

    def load(event_db_ids, **_kwargs):
        assert event_db_ids == [11], "out-of-scope proof reached payload hydration"
        return {11: {"id": 11, "event_id": 4624, "time_created_utc": "2026-09-10T01:00:00Z", "event_data": {}}}

    monkeypatch.setattr(ui_workspace, "get_event_details_by_ids", load)
    routes._handle_v1_investigations_api(handler, {"entity_id": ["55"], "q": ["name-must-not-be-used"]})

    assert len(sent) == 1
    payload, status = sent[0]
    assert status == 200
    assert payload["query"] == ""
    assert payload["context"]["entity_id"] == 55
    assert [item["event_db_id"] for item in payload["timeline"]] == [11]


def test_http_entity_history_reuses_alias_evidence_from_security_report_owner(monkeypatch):
    """The card and investigation must agree on exact SID-backed security evidence."""
    from server.api.http_server import RequestHandler
    from server.api.routes import investigations as routes

    handler = object.__new__(RequestHandler)
    handler._effective_access_cache = {
        "capabilities": ["objects.view", "investigations.view", "evidence.exact", "field.security"],
        "resource_bound_capabilities": [],
        "reports": [{"report_key": "investigations.workspace", "allowed": True,
                     "allowed_actions": ["view"], "grants": [{
                         "scope": {"kind": "server", "ids": [7]},
                         "allowed_actions": ["view"], "field_categories": ["security"]}]}],
    }
    sent = []
    handler._send_json = lambda payload, status=200: sent.append((payload, status))
    monkeypatch.setattr(ui_workspace, "resolve_storage_route", lambda **_kw: {"route": "v2"})

    calls: list[tuple[str, object]] = []

    def evidence_rows(**kwargs):
        if kwargs.get("id_only"):
            pytest.fail("bounded runtime path must use security candidate IDs")
        calls.append(("metadata", list(kwargs["event_db_ids"])))
        assert kwargs.get("preauthorized_exact_event_ids") is True
        return [{
            "event_db_id": 11, "event_id": 4740,
            "time_created_utc": "2026-09-10T01:00:00.123456Z",
            "server": "DC1", "channel": "Security",
            "provider_name": "Microsoft-Windows-Security-Auditing",
            "subject_user_name": "DC1$", "target_user_name": "supervisorks",
        }]

    monkeypatch.setattr(ui_workspace, "_get_entity_evidence_event_rows", evidence_rows)

    def alias_candidates(**kwargs):
        calls.append(("alias", kwargs))
        return {
            "state": "available", "has_more": False,
            "items": [{"event_db_id": 11}],
        }

    monkeypatch.setattr(routes, "_entity_security_event_candidates", lambda _handler, **kwargs: alias_candidates(**kwargs), raising=False)
    monkeypatch.setattr(routes, "event_resource_group", lambda _event_id: [{"kind": "server", "id": 7}])

    routes._handle_v1_investigations_api(handler, {
        "entity_id": ["55"], "scope": ["all"],
        "time_from": ["2026-09-10T00:00:00.123001Z"],
        "time_to": ["2026-09-11T00:00:00.123999Z"],
        "timezone": ["Asia/Bangkok"],
    })

    assert sent[0][1] == 200
    assert [item["event_db_id"] for item in sent[0][0]["timeline"]] == [11]
    assert "SID" in sent[0][0]["timeline"][0]["inclusion_reason"]
    assert calls[0][0] == "alias"
    assert calls[0][1] == {
        "entity_id": 55,
        "time_from_utc": "2026-09-10T00:00:00.123001Z",
        "time_to_utc_exclusive": "2026-09-11T00:00:00.123999Z",
        "timezone_name": "Asia/Bangkok",
        "limit": ui_workspace.INVESTIGATION_TIMELINE_LIMIT + 1,
    }
    assert calls[1] == ("metadata", [11])


def test_entity_security_candidate_reader_checks_object_and_investigation_scope(monkeypatch):
    from server.api.routes import investigations as routes

    access = {"actor": "reader"}
    handler = type("Handler", (), {"_access_decision": lambda _self: access})()
    monkeypatch.setattr(routes, "get_entity_workspace_resource_preflight", lambda **_kwargs: {
        "id": 55, "domain_id": 1, "server_id": 7,
    })
    capability_calls = []
    monkeypatch.setattr(
        routes,
        "capability_decision_for_resource_groups",
        lambda supplied, capability, **kwargs: (
            capability_calls.append((supplied, capability, kwargs)) or {"allowed": True}
        ),
    )
    monkeypatch.setattr(
        routes, "_investigation_access_decision",
        lambda _handler, action, capability, groups: {
            "allowed": action == "view" and capability == "investigations.view" and bool(groups)
        },
    )
    report_calls = []
    expected = {"state": "available", "items": [{"event_db_id": 11}], "has_more": False}
    monkeypatch.setattr(
        routes, "get_security_event_candidate_ids",
        lambda supplied, **kwargs: report_calls.append((supplied, kwargs)) or expected,
    )

    result = routes._entity_security_event_candidates(
        handler,
        entity_id=55,
        time_from_utc="2026-09-10T00:00:00.123001Z",
        time_to_utc_exclusive="2026-09-11T00:00:00.123999Z",
        timezone_name="Asia/Bangkok",
        limit=101,
    )

    assert result is expected
    assert capability_calls[0][1] == "objects.view"
    assert report_calls == [(access, {
        "source_domain_id": 1,
        "time_from": "2026-09-10T00:00:00.123001Z",
        "time_to": "2026-09-11T00:00:00.123999Z",
        "timezone_name": "Asia/Bangkok",
        "limit": 101,
        "entity_id": 55,
    })]


def test_entity_security_candidate_reader_does_not_query_report_when_object_denied(monkeypatch):
    from server.api.routes import investigations as routes

    handler = type("Handler", (), {"_access_decision": lambda _self: {"actor": "reader"}})()
    monkeypatch.setattr(routes, "get_entity_workspace_resource_preflight", lambda **_kwargs: {
        "id": 55, "domain_id": 1, "server_id": 7,
    })
    monkeypatch.setattr(
        routes, "capability_decision_for_resource_groups", lambda *_args, **_kwargs: {"allowed": False},
    )
    monkeypatch.setattr(
        routes, "get_security_event_candidate_ids",
        lambda *_args, **_kwargs: pytest.fail("denied object reached the security-report reader"),
    )

    result = routes._entity_security_event_candidates(
        handler,
        entity_id=55,
        time_from_utc="2026-09-10T00:00:00Z",
        time_to_utc_exclusive="2026-09-11T00:00:00Z",
        timezone_name="UTC",
        limit=101,
    )

    assert result == {"state": "not_authorized", "items": [], "has_more": False}


def test_http_entity_without_permitted_proof_is_not_found_before_payload(monkeypatch):
    from server.api.http_server import RequestHandler
    from server.api.routes import investigations as routes

    handler = object.__new__(RequestHandler)
    handler._effective_access_cache = {
        "capabilities": ["objects.view", "investigations.view", "evidence.exact", "field.security"],
        "resource_bound_capabilities": [],
        "reports": [{"report_key": "investigations.workspace", "allowed": True,
                     "allowed_actions": ["view"], "grants": [{
                         "scope": {"kind": "server", "ids": [7]},
                         "allowed_actions": ["view"], "field_categories": ["security"]}]}],
    }
    sent = []
    handler._send_json = lambda payload, status=200: sent.append((payload, status))
    monkeypatch.setattr(ui_workspace, "resolve_storage_route", lambda **_kw: {"route": "v2"})
    monkeypatch.setattr(
        routes, "_entity_security_event_candidates",
        lambda _handler, **_kwargs: {
            "state": "available", "items": [{"event_db_id": 12}], "has_more": False,
        },
    )
    monkeypatch.setattr(
        ui_workspace, "_get_entity_evidence_event_rows",
        lambda **_kw: pytest.fail("denied exact proof reached metadata"),
    )
    monkeypatch.setattr(routes, "event_resource_group", lambda _event_id: [{"kind": "server", "id": 9}])
    monkeypatch.setattr(ui_workspace, "get_event_details_by_ids", lambda *_a, **_kw: pytest.fail("payload hydration"))

    routes._handle_v1_investigations_api(handler, {
        "entity_id": ["55"],
        "time_from": ["2026-09-10T00:00:00Z"],
        "time_to": ["2026-09-11T00:00:00Z"],
    })

    assert len(sent) == 1 and sent[0][1] == 200  # пустая история, не 404 (нет оракула прав)
    assert sent[0][0]["timeline"] == [] and sent[0][0]["summary"]["events_returned"] == 0


def test_http_entity_rejects_malformed_id_before_access_or_evidence_lookup():
    from http import HTTPStatus
    from server.api.http_server import RequestHandler
    from server.api.routes import investigations as routes

    handler = object.__new__(RequestHandler)
    handler._access_decision = lambda: pytest.fail("access lookup")
    sent = []
    handler._send_json = lambda payload, status=200: sent.append((payload, status))

    routes._handle_v1_investigations_api(handler, {"entity_id": [" "]})

    assert sent == [({"error": "invalid_entity_id"}, HTTPStatus.BAD_REQUEST)]


def test_http_entity_requires_security_field_grant_before_payload(monkeypatch):
    from server.api.http_server import RequestHandler
    from server.api.routes import investigations as routes

    handler = object.__new__(RequestHandler)
    handler._effective_access_cache = {
        "capabilities": ["objects.view", "investigations.view", "evidence.exact", "field.security"],
        "resource_bound_capabilities": [],
        "reports": [{"report_key": "investigations.workspace", "allowed": True,
                     "allowed_actions": ["view"], "grants": [{
                         "scope": {"kind": "server", "ids": [7]},
                         "allowed_actions": ["view"], "field_categories": ["technical"]}]}],
    }
    sent = []
    handler._send_json = lambda payload, status=200: sent.append((payload, status))
    monkeypatch.setattr(ui_workspace, "resolve_storage_route", lambda **_kw: {"route": "v2"})
    monkeypatch.setattr(
        routes, "_entity_security_event_candidates",
        lambda _handler, **_kwargs: {
            "state": "available", "items": [{"event_db_id": 11}], "has_more": False,
        },
    )
    monkeypatch.setattr(
        ui_workspace, "_get_entity_evidence_event_rows",
        lambda **_kw: pytest.fail("denied security field reached metadata"),
    )
    monkeypatch.setattr(routes, "event_resource_group", lambda _event_id: [{"kind": "server", "id": 7}])
    monkeypatch.setattr(ui_workspace, "get_event_details_by_ids", lambda *_a, **_kw: pytest.fail("payload hydration"))

    routes._handle_v1_investigations_api(handler, {
        "entity_id": ["55"],
        "time_from": ["2026-09-10T00:00:00Z"],
        "time_to": ["2026-09-11T00:00:00Z"],
    })

    assert len(sent) == 1 and sent[0][1] == 200  # пустая история, не 404 (нет оракула прав)
    assert sent[0][0]["timeline"] == [] and sent[0][0]["summary"]["events_returned"] == 0

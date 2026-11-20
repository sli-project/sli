from __future__ import annotations

from datetime import datetime, timezone
from http import HTTPStatus
from pathlib import Path
from types import SimpleNamespace
from zoneinfo import ZoneInfo

import pytest


def test_overview_contract_adapts_cached_snapshot_without_refresh(monkeypatch) -> None:
    from server.sli.reporting import ui_workspace

    calls: list[bool] = []
    monkeypatch.setattr(ui_workspace, "build_dashboard_snapshot", lambda: calls.append(True) or {
        "generated_at_utc": "2026-07-16T04:00:00Z", "status": "ok",
        "diagnostics": {"response_model": "fresh_cache", "stale": False, "failures": []},
        "events_summary": {"total_events": 10, "estimated": True, "security_24h_summary": {"important_total": 2}},
        "entity_summary": {"total_entities": 3, "estimated": True},
        "findings": {"items": [{"id": 7, "title": "Check", "severity": "high", "status": "new", "evidence_count": 1}]},
        "sources": {"items": [{"hostname": "DC1", "is_active": 1}]},
    })
    monkeypatch.setattr(ui_workspace, "get_sources", lambda: [
        {
            "hostname": "DC1", "is_active": 1, "fqdn": None,
            "os_name": None, "os_version": None, "ip_addresses": [],
        },
    ])

    data = ui_workspace.get_overview_workspace_data()

    assert calls == [True]
    assert data["metrics"] == {"events_total": 10, "events_estimated": True, "entities_total": 3, "entities_estimated": True, "important_recent": 2, "sources_total": 1}
    assert data["alerts"] == [{"id": 7, "title": "Check", "severity": "high", "status": "new", "actor": None, "target": None, "source": None, "last_seen_utc": None, "evidence_count": 1, "assigned_to": None, "updated_at": None, "event_db_id": None}]
    assert data["limits"]["full_history"] is False


def test_overview_enriches_old_cached_source_contract_and_deduplicates_inventory(monkeypatch) -> None:
    from server.sli.reporting import ui_workspace

    monkeypatch.setattr(ui_workspace, "build_dashboard_snapshot", lambda: {
        "generated_at_utc": "2026-07-24T01:00:00Z", "status": "ok",
        "diagnostics": {}, "events_summary": {}, "entity_summary": {},
        "findings": {"items": []},
        "sources": {"items": [{"hostname": "DC1", "role": "domain_controller", "is_active": True}]},
        "collector_health": {"items": []},
    })
    monkeypatch.setattr(ui_workspace, "get_sources", lambda: [
        {
            "hostname": "DC1", "role": "domain_controller", "is_active": True,
            "fqdn": None, "os_name": None, "os_version": None,
            "ip_addresses": ["192.0.2.19"],
        },
        {
            "hostname": "dc1", "role": "domain_controller", "is_active": True,
            "fqdn": None, "os_name": None, "os_version": None,
            "ip_addresses": ["192.0.2.19"],
        },
    ])

    data = ui_workspace.get_overview_workspace_data()

    assert data["metrics"]["sources_total"] == 1
    assert data["sources"][0]["hostname"] == "DC1"
    assert data["sources"][0]["ip_addresses"] == ["192.0.2.19"]


def test_overview_response_keeps_source_inventory_and_freshness_fields() -> None:
    from server.sli.reporting.ui_api_models import OverviewSource

    payload = OverviewSource(
        hostname="DC1",
        role="domain_controller",
        active=True,
        registered=True,
        ip_addresses=["192.0.2.19"],
        collection_state="lagging",
        collection_label="есть задержка проверки",
        last_successful_collection_utc="2026-07-24T01:00:00Z",
        last_event_time_utc="2026-07-24T00:59:00Z",
        channels_total=6,
    ).model_dump(mode="json")

    assert payload["ip_addresses"] == ["192.0.2.19"]
    assert payload["registered"] is True
    assert payload["collection_state"] == "lagging"
    assert payload["channels_total"] == 6


def test_overview_includes_observed_source_when_inventory_is_empty(monkeypatch) -> None:
    from server.sli.reporting import ui_workspace

    monkeypatch.setattr(ui_workspace, "build_dashboard_snapshot", lambda: {
        "generated_at_utc": "2026-07-23T04:00:00Z", "status": "ok",
        "diagnostics": {}, "events_summary": {}, "entity_summary": {},
        "findings": {"items": []}, "sources": {"items": []},
        "collector_health": {"items": [{
            "server": "DC2", "channel": "Security",
            "last_successful_collection_utc": "2026-07-23T03:58:00Z",
            "last_event_time_utc": "2026-07-23T03:57:00Z",
            "last_status": "completed",
        }]},
    })

    data = ui_workspace.get_overview_workspace_data()

    assert data["metrics"]["sources_total"] == 1
    assert data["sources"][0]["hostname"] == "DC2"
    assert data["sources"][0]["registered"] is False
    assert data["sources"][0]["active"] is None
    assert data["sources"][0]["channels_total"] == 1
    assert data["sources"][0]["last_successful_collection_utc"] == "2026-07-23T03:58:00Z"


def test_overview_reads_bounded_source_inventory_while_snapshot_is_warming(monkeypatch) -> None:
    from server.sli.reporting import ui_workspace

    monkeypatch.setattr(ui_workspace, "build_dashboard_snapshot", lambda: {
        "status": "warming",
        "diagnostics": {"request_model": "startup_warming_response"},
        "events_summary": {}, "entity_summary": {}, "findings": {"items": []},
        "sources": {"items": []}, "collector_health": {"items": []},
    })
    monkeypatch.setattr(ui_workspace, "get_sources", lambda: [
        {"hostname": "DC2", "role": "domain_controller", "is_active": True},
    ])
    monkeypatch.setattr(ui_workspace, "get_collector_health", lambda: {
        "status": "ok",
        "items": [{
            "server": "DC2",
            "channel": "Security",
            "last_successful_collection_utc": "2026-07-23T03:58:00Z",
            "last_event_time_utc": "2026-07-23T03:57:00Z",
            "last_status": "completed",
        }],
    })

    data = ui_workspace.get_overview_workspace_data()

    assert data["metrics"]["sources_total"] == 1
    assert data["sources"][0]["hostname"] == "DC2"
    assert data["sources"][0]["role"] == "domain_controller"
    assert data["sources"][0]["active"] is True
    assert data["collection_freshness"]["state"] in {"current", "lagging", "stale"}


def test_overview_activity_uses_hourly_and_daily_bucket_contracts(monkeypatch) -> None:
    from server.sli.reporting import ui_workspace

    monkeypatch.setattr(ui_workspace, "build_dashboard_snapshot", lambda: {
        "generated_at_utc": "2026-07-17T04:00:00Z",
        "status": "ok",
        "diagnostics": {},
        "events_summary": {},
        "entity_summary": {},
        "findings": {"items": []},
        "sources": {"items": []},
    })
    bucket_counts: list[int] = []

    def activity(**kwargs):
        bucket_counts.append(kwargs["bucket_count"])
        return {"available": True, "exact": True, "reason": None, "items": []}

    monkeypatch.setattr(ui_workspace, "get_overview_activity", activity)

    one_day = ui_workspace.get_overview_workspace_data(
        time_from="2026-07-16T04:00:00Z", time_to="2026-07-17T04:00:00Z"
    )
    seven_days = ui_workspace.get_overview_workspace_data(
        time_from="2026-07-10T04:00:00Z", time_to="2026-07-17T04:00:00Z"
    )

    assert one_day["activity"]["period_label"] == "24 часа"
    assert seven_days["activity"]["period_label"] == "7 дней"
    assert bucket_counts == [24, 7]


def test_overview_collection_freshness_distinguishes_partial_and_total_failure() -> None:
    from server.sli.sources.collector_health import summarize_collection_freshness

    now = datetime(2026, 7, 17, 4, 0, tzinfo=timezone.utc)

    def item(last_check: str, status: str = "completed", channel: str = "Security") -> dict[str, object]:
        return {
            "server": "DC1", "channel": channel,
            "last_successful_collection_utc": last_check,
            "last_event_time_utc": "2026-07-16T18:00:00Z",
            "last_status": status,
        }

    assert summarize_collection_freshness([item("2026-07-17T03:57:00Z")], now=now)["state"] == "current"
    assert summarize_collection_freshness([item("2026-07-17T03:48:00Z")], now=now)["state"] == "lagging"
    assert summarize_collection_freshness([item("2026-07-17T03:39:00Z")], now=now)["state"] == "stale"
    assert summarize_collection_freshness([item("2026-07-17T03:57:00Z", "failed")], now=now)["state"] == "error"
    partial = summarize_collection_freshness(
        [
            item("2026-07-17T03:57:00Z"),
            item("2026-07-17T03:57:00Z", "failed", channel="DNS Server"),
        ],
        now=now,
    )
    assert partial["state"] == "partial"
    assert partial["label"] == "Частичный сбор"
    assert partial["channels_failed"] == 1

    all_channels = [
        item("2026-07-17T03:59:00Z"),
        item("2026-07-17T03:30:00Z", channel="Directory Service"),
    ]
    assert summarize_collection_freshness(all_channels, now=now)["state"] == "stale"
    assert summarize_collection_freshness(all_channels, now=now)["worst_event_lag_minutes"] == 600


def test_v1_event_filter_invalid_paging_values_are_safe() -> None:
    from server.api.routes.events import _event_search_filters

    filters = _event_search_filters({"limit": ["not-a-number"], "offset": ["broken"]})

    assert filters["limit"] == 200
    assert filters["offset"] == 0


def test_v1_event_filter_forwards_semantic_fields() -> None:
    from server.api.routes.events import _event_search_filters

    filters = _event_search_filters({
        "provider": ["Microsoft-Windows-Security-Auditing"],
        "subject": ["alice"],
        "target": ["server-01"],
    })

    assert filters["provider"] == "Microsoft-Windows-Security-Auditing"
    assert filters["subject"] == "alice"
    assert filters["target"] == "server-01"


def test_v1_event_contract_normalizes_postgres_datetime_to_utc() -> None:
    from server.sli.reporting.ui_api_models import EventListResponse

    payload = EventListResponse(items=[{
        "id": 17,
        "event_id": 4624,
        "time_created_utc": datetime(2026, 7, 16, 20, 30, 15, tzinfo=ZoneInfo("Asia/Novosibirsk")),
    }]).model_dump(mode="json")

    assert payload["items"][0]["time_created_utc"] == "2026-07-16T13:30:15Z"


def test_investigation_without_exact_anchor_is_refused() -> None:
    """Storage V2 is the only route (plan 6.5): no free-text-only investigation reader."""
    from server.sli.reporting import ui_workspace
    from server.sli.storage.runtime_storage import StorageRouteAuthorizationError

    for query in ("", "alice"):
        with pytest.raises(StorageRouteAuthorizationError, match="storage_v2_investigation_requires_exact_event_id"):
            ui_workspace.get_investigations_workspace_data(q=query)


def test_investigation_uncatalogued_timeline_row_validates_as_unknown(monkeypatch) -> None:
    from server.sli.reporting import ui_workspace
    from server.sli.reporting.ui_api_models import InvestigationsWorkspaceResponse

    base = {
        "id": 11, "event_id": 999999, "time_created_utc": "2026-07-16T00:00:00Z",
        "server": "DC1", "channel": "Unknown", "provider_name": "Unknown", "event_data": {},
    }
    monkeypatch.setattr(ui_workspace, "get_event_detail_report_data", lambda **_kwargs: {"items": [base]})
    monkeypatch.setattr(ui_workspace, "get_event_relations", lambda *_args, **_kwargs: {"items": []})
    monkeypatch.setattr(ui_workspace, "get_event_details_by_ids", lambda _ids: {})

    payload = InvestigationsWorkspaceResponse(
        **ui_workspace.get_investigations_workspace_data(q="alice", event_db_id=11)
    )

    assert payload.timeline[0].catalogued is False
    assert payload.timeline[0].assessment_confidence.value == "unknown"


def test_anchored_investigation_batch_loads_related_evidence_once(monkeypatch) -> None:
    from server.sli.reporting import ui_workspace

    base = {
        "id": 10, "event_id": 4720, "time_created_utc": "2026-07-16T00:00:00Z",
        "server": "DC1", "channel": "Security", "provider_name": "Microsoft-Windows-Security-Auditing",
        "event_data": {},
    }
    detail_calls: list[int] = []
    batch_calls: list[list[int]] = []
    monkeypatch.setattr(
        ui_workspace,
        "get_event_detail_report_data",
        lambda **kwargs: detail_calls.append(int(kwargs["event_db_id"])) or {"items": [base]},
    )
    monkeypatch.setattr(ui_workspace, "get_event_relations", lambda *_args, **_kwargs: {"items": [
        {"related_event_db_id": 12, "reason": "newer"},
        {"related_event_db_id": 11, "reason": "older"},
        {"related_event_db_id": 12, "reason": "duplicate relation"},
        {"related_event_db_id": None, "reason": "invalid"},
    ]})

    def fake_batch(ids):
        batch_calls.append(list(ids))
        return {
            11: {**base, "id": 11, "event_id": 4624, "time_created_utc": "2026-07-16T00:01:00Z"},
            12: {**base, "id": 12, "event_id": 4672, "time_created_utc": "2026-07-16T00:02:00Z"},
        }

    monkeypatch.setattr(ui_workspace, "get_event_details_by_ids", fake_batch)

    data = ui_workspace.get_investigations_workspace_data(q="alice", event_db_id=10)

    assert detail_calls == [10]
    assert batch_calls == [[12, 11, 12]]
    assert [item["event_db_id"] for item in data["timeline"]] == [12, 12, 11, 10]
    assert data["timeline"][0]["inclusion_reason"] == "newer"
    assert data["timeline"][1]["inclusion_reason"] == "duplicate relation"
    assert data["limits"]["relations"] == 40


def test_event_details_by_ids_uses_one_v2_batch_and_deduplicates(monkeypatch) -> None:
    from server.sli.events import event_details

    calls: list[list[int]] = []

    def fake_batch(ids):
        calls.append(list(ids))
        return {event_id: {"id": event_id, "event_id": 4624} for event_id in ids}

    monkeypatch.setattr(event_details, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(event_details, "_get_v2_event_details_by_ids", fake_batch)

    result = event_details.get_event_details_by_ids([3, 2, 3])

    assert calls == [[3, 2]]
    assert list(result) == [3, 2]
    assert result[3]["id"] == 3


def test_entities_contract_rejects_unsupported_backend(monkeypatch) -> None:
    from server.sli.reporting.ui_workspace import get_entities_workspace_data

    monkeypatch.setattr("server.sli.reporting.ui_workspace.is_postgres_runtime_db", lambda: False)
    with pytest.raises(RuntimeError, match="PostgreSQL/Storage V2"):
        get_entities_workspace_data(limit=2)


def test_entities_workspace_applies_type_filters_and_returns_global_counts(monkeypatch) -> None:
    from server.sli.reporting import ui_workspace

    calls: list[tuple[str, tuple[object, ...]]] = []

    def fake_query(sql, params=()):
        normalized = " ".join(sql.split()).lower()
        calls.append((normalized, tuple(params)))
        if "group by entity_type.value" in normalized:
            return [
                {"entity_type": "auth_session", "entity_count": 932_374},
                {"entity_type": "ad_user", "entity_count": 1_100},
                {"entity_type": "ad_computer", "entity_count": 526},
            ]
        return [{
            "id": 1472, "entity_type": "ad_user", "natural_key": "sam:alice",
            "display_name": "Alice", "first_seen_utc": None, "last_seen_utc": None,
            "latest_state_status": None, "latest_state_summary": None,
            "latest_state_observed_at_utc": None, "latest_state_event_db_id": None,
        }]

    monkeypatch.setattr(ui_workspace, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(ui_workspace, "query_rows", fake_query)

    result = ui_workspace.get_entities_workspace_data(
        entity_types=("ad_user", "ad_computer"),
        exclude_entity_types=("auth_session",),
        limit=50,
    )

    assert [item["type"] for item in result["items"]] == ["ad_user"]
    assert result["filters"] == {
        "entity_types": ["ad_user", "ad_computer"],
        "exclude_entity_types": ["auth_session"],
    }
    assert result["type_counts_scope"] == "all_entities"
    assert result["total_entities"] == 934_000
    assert result["type_counts"][0] == {"entity_type": "auth_session", "count": 932_374}
    assert "entity_type.value = any(?)" in calls[1][0]
    assert "not (entity_type.value = any(?))" in calls[1][0]
    assert calls[1][1] == (["ad_user", "ad_computer"], ["auth_session"], 51)


def test_entities_workspace_rejects_unknown_type(monkeypatch) -> None:
    from server.sli.reporting import ui_workspace

    monkeypatch.setattr(ui_workspace, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(ui_workspace, "query_rows", lambda *_args, **_kwargs: [
        {"entity_type": "ad_user", "entity_count": 1}
    ])

    with pytest.raises(ui_workspace.EntityTypeFilterError) as exc:
        ui_workspace.get_entities_workspace_data(
            entity_types=("invented",)
        )

    assert exc.value.unknown_types == ["invented"]


def test_v1_workspace_handlers_serialize_typed_payloads(monkeypatch) -> None:
    from server.api.routes import entities as routes_entities
    from server.api.routes import workspace as routes_workspace

    handler = SimpleNamespace()
    captured: dict[str, object] = {}
    handler._send_json = lambda payload, status=HTTPStatus.OK: captured.update(payload=payload, status=status)
    monkeypatch.setattr(routes_workspace, "get_overview_workspace_data", lambda **_kwargs: {
        "generated_at_utc": None, "status": "warming",
        "data_state": {"cache": "warming", "stale": False, "failures": []},
        "metrics": {"events_total": 0, "events_estimated": False, "entities_total": 0, "entities_estimated": False, "important_recent": 0, "sources_total": 0},
        "alerts": [], "sources": [],
        "collection_freshness": {
            "state": "partial",
            "label": "Частичный сбор",
            "worst_lag_minutes": None,
            "latest_event_utc": None,
            "collection_error": True,
            "channels_failed": 1,
            "channels_total": 2,
            "channels_checked": 2,
        },
        "collection_progress": {},
        "activity": {"period_label": "24 часа", "time_from_utc": "2026-07-16T00:00:00Z", "time_to_utc": "2026-07-17T00:00:00Z", "selected_source": None, "available": False, "exact": False, "reason": "test", "items": []},
        "limits": {},
    })
    routes_workspace._handle_v1_overview_api(handler)
    assert captured["status"] == HTTPStatus.OK
    assert captured["payload"]["collection_freshness"]["state"] == "partial"
    assert captured["payload"]["collection_freshness"]["channels_failed"] == 1
    assert captured["payload"]["activity"]["period_label"] == "24 часа"

    monkeypatch.setattr(routes_entities, "get_entities_workspace_data", lambda **kwargs: {"query": kwargs["q"] or "", "state": "empty", "items": [], "has_more": False, "limits": {"items": kwargs["limit"]}})
    routes_entities._handle_v1_entities_api(handler, {"q": ["alice"], "limit": ["not-a-number"]})
    assert captured["payload"]["query"] == "alice"
    assert captured["payload"]["limits"]["items"] == 50


def test_entity_detail_route_scopes_object_and_each_evidence_before_metadata_read(monkeypatch) -> None:
    from server.api.routes import entities as routes_entities

    handler = SimpleNamespace()
    handler._send_json = lambda payload, status=HTTPStatus.OK: None
    handler._access_decision = lambda: {"capabilities": ["objects.view", "evidence.exact"]}
    monkeypatch.setattr(
        routes_entities, "get_entity_workspace_resource_preflight",
        lambda **_kwargs: {"id": 7, "entity_type": "ad_user", "domain_id": 1, "server_id": 7},
    )

    def decision(_access, capability, *, resource_groups):
        resources = resource_groups[0]
        server_ids = {item.get("id") for item in resources if item.get("kind") == "server"}
        return {"allowed": capability == "objects.view" or (7 in server_ids and capability in {"evidence.exact", "field.security", "field.technical"})}

    monkeypatch.setattr(routes_entities, "capability_decision_for_resource_groups", decision)
    observed: dict[str, object] = {}

    def detail(**kwargs):
        observed.update(kwargs)
        projector = kwargs["event_evidence_projection"]
        observed["allowed_projection"] = projector({"event_db_id": 10, "server_id": 7, "domain_id": 1, "channel": "Security"})
        observed["denied_projection"] = projector({"event_db_id": 11, "server_id": 9, "domain_id": 1, "channel": "Security"})
        observed["ad_context"] = kwargs["ad_context_projection"]({
            "entity_id": 7, "resolution": "shared_entity_id", "returned_count": 2,
            "bounded": True, "items": [
                {
                    "context_kind": "entity", "context_evidence_id": 1,
                    "integrity_sha256": "hidden", "subject_entity_id": 7,
                    "attributes": {"identity": {"object_sid": "S-1"}, "attributes": {"enabled": True, "unknown_secret": "hidden"}},
                },
                {"context_kind": "relation", "related_entity_id": 8, "attributes": {"membership_type": "direct"}},
            ],
        })
        return {
            "entity": {"id": 7, "type": "ad_user", "natural_key": "u", "display_name": "U"},
            "current_states": [], "ad_context": {"entity_id": 7, "resolution": "not_observed", "items": [], "returned_count": 0, "bounded": True},
            "events": [], "has_more": False, "limits": {},
        }

    monkeypatch.setattr(routes_entities, "get_entity_workspace_detail_data", detail)
    routes_entities._handle_v1_entity_by_id_api(handler, "/api/v1/entities/7", {})

    assert observed["allowed_projection"] == "full"
    assert observed["denied_projection"] is None
    assert observed["ad_context"]["returned_count"] == 1
    assert observed["ad_context"]["items"][0]["attributes"] == {
        "enabled": True, "object_sid": "S-1",
    }
    assert "integrity_sha256" not in observed["ad_context"]["items"][0]


def test_entity_detail_route_hides_a_scoped_denial_as_not_found(monkeypatch) -> None:
    from server.api.routes import entities as routes_entities

    captured: dict[str, object] = {}
    handler = SimpleNamespace()
    handler._send_json = lambda payload, status=HTTPStatus.OK: captured.update(payload=payload, status=status)
    handler._access_decision = lambda: {"capabilities": ["objects.view"]}
    monkeypatch.setattr(
        routes_entities, "get_entity_workspace_resource_preflight",
        lambda **_kwargs: {"id": 7, "entity_type": "ad_user", "domain_id": 1, "server_id": 7},
    )
    monkeypatch.setattr(
        routes_entities, "capability_decision_for_resource_groups",
        lambda *_args, **_kwargs: {"allowed": False},
    )
    monkeypatch.setattr(
        routes_entities, "get_entity_workspace_detail_data",
        lambda **_kwargs: pytest.fail("denied object must not be hydrated"),
    )

    routes_entities._handle_v1_entity_by_id_api(handler, "/api/v1/entities/7", {})

    assert captured == {
        "payload": {"error": "entity_not_found", "entity_id": 7},
        "status": HTTPStatus.NOT_FOUND,
    }


def test_entity_detail_event_uses_subject_label_and_keeps_event_id_as_technical_detail() -> None:
    from server.sli.reporting.ui_workspace import _entity_detail_event_item

    item = _entity_detail_event_item({
        "event_db_id": 517548,
        "event_id": 4740,
        "time_created_utc": "2026-09-11T10:20:30Z",
        "server": "DC1",
        "channel": "Security",
        "provider_name": "Microsoft-Windows-Security-Auditing",
        "link_role": "target",
        "confidence": 1,
        "subject_user_name": "operator",
        "target_user_name": "alice",
        "_field_projection": "full",
    })

    assert item["label"] == "Учетная запись заблокирована"
    assert item["event_id"] == 4740


def test_entities_handler_parses_multiple_types_and_rejects_unknown(monkeypatch) -> None:
    from server.api.routes import entities as routes_entities

    handler = SimpleNamespace()
    captured: dict[str, object] = {}
    handler._send_json = lambda payload, status=HTTPStatus.OK: captured.update(payload=payload, status=status)
    observed: dict[str, object] = {}

    def fake_workspace(**kwargs):
        observed.update(kwargs)
        return {
            "query": "", "state": "empty", "items": [], "has_more": False,
            "filters": {
                "entity_types": list(kwargs["entity_types"]),
                "exclude_entity_types": list(kwargs["exclude_entity_types"]),
            },
            "type_counts": [], "type_counts_scope": "all_entities",
            "total_entities": 0, "limits": {"items": kwargs["limit"]},
        }

    monkeypatch.setattr(routes_entities, "get_entities_workspace_data", fake_workspace)
    routes_entities._handle_v1_entities_api(handler, {
        "entity_type": ["ad_user,ad_computer"],
        "exclude_entity_type": ["auth_session", "log_source"],
    })
    assert observed["entity_types"] == ("ad_user", "ad_computer")
    assert observed["exclude_entity_types"] == ("auth_session", "log_source")
    assert captured["status"] == HTTPStatus.OK

    monkeypatch.setattr(
        routes_entities,
        "get_entities_workspace_data",
        lambda **_kwargs: (_ for _ in ()).throw(routes_entities.EntityTypeFilterError(["invented"])),
    )
    routes_entities._handle_v1_entities_api(handler, {"entity_type": ["invented"]})
    assert captured == {
        "payload": {"error": "unknown_entity_type", "unknown_types": ["invented"]},
        "status": HTTPStatus.BAD_REQUEST,
    }


def test_entity_detail_contract_rejects_unsupported_backend(monkeypatch) -> None:
    from server.sli.reporting import ui_workspace

    monkeypatch.setattr(ui_workspace, "is_postgres_runtime_db", lambda: False)
    with pytest.raises(RuntimeError, match="PostgreSQL/Storage V2"):
        ui_workspace.get_entity_workspace_detail_data(entity_id=1, limit=1)


def test_entity_detail_keeps_object_available_when_evidence_read_times_out(monkeypatch) -> None:
    from server.sli.reporting import ui_workspace
    from server.sli.core.database import QueryTimeoutError

    monkeypatch.setattr(ui_workspace, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(ui_workspace, "query_rows", lambda *_args, **_kwargs: [{
        "id": 1472, "entity_type": "asset", "natural_key": "node", "display_name": "Узел",
        "first_seen_utc": None, "last_seen_utc": None, "latest_state_status": None,
        "latest_state_summary": None, "latest_state_observed_at_utc": None,
        "latest_state_event_db_id": None,
    }])
    monkeypatch.setattr(ui_workspace, "_get_current_entity_states", lambda **_kwargs: [])
    monkeypatch.setattr(ui_workspace, "_get_entity_evidence_event_rows", lambda **_kwargs: (_ for _ in ()).throw(
        QueryTimeoutError("slow evidence", timeout_ms=3000)
    ))
    monkeypatch.setattr("server.ad_context.integration.get_runtime_entity_context_evidence", lambda *_args, **_kwargs: {
        "entity_id": 1472, "resolution": "not_observed", "returned_count": 0, "bounded": True, "items": [],
    })

    result = ui_workspace.get_entity_workspace_detail_data(entity_id=1472, limit=30)

    assert result is not None
    assert result["entity"]["type"] == "asset"
    assert result["current_states_state"] == "available"
    assert result["ad_context_state"] == "available"
    assert result["events"] == []
    assert result["events_state"] == "temporarily_unavailable"
    assert result["has_more"] is False


def test_entity_detail_keeps_object_available_when_supplemental_sections_time_out(monkeypatch) -> None:
    from server.sli.reporting import ui_workspace
    from server.sli.core.database import QueryTimeoutError

    monkeypatch.setattr(ui_workspace, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(ui_workspace, "query_rows", lambda *_args, **_kwargs: [{
        "id": 1472, "entity_type": "asset", "natural_key": "node", "display_name": "Узел",
        "first_seen_utc": None, "last_seen_utc": None, "latest_state_status": None,
        "latest_state_summary": None, "latest_state_observed_at_utc": None,
        "latest_state_event_db_id": None,
    }])
    timeout = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        QueryTimeoutError("supplemental timeout", timeout_ms=3000)
    )
    monkeypatch.setattr(ui_workspace, "_get_current_entity_states", timeout)
    monkeypatch.setattr(ui_workspace, "_get_entity_evidence_event_rows", lambda **_kwargs: [])
    monkeypatch.setattr("server.ad_context.integration.get_runtime_entity_context_evidence", timeout)

    result = ui_workspace.get_entity_workspace_detail_data(
        entity_id=1472, limit=30
    )

    assert result is not None
    assert result["current_states"] == []
    assert result["current_states_state"] == "temporarily_unavailable"
    assert result["ad_context"] == {
        "entity_id": 1472, "resolution": "temporarily_unavailable", "items": [],
        "returned_count": 0, "bounded": True,
    }
    assert result["ad_context_state"] == "temporarily_unavailable"
    assert result["events_state"] == "available"


def test_entity_detail_filters_each_exact_event_before_metadata_hydration(monkeypatch) -> None:
    from server.sli.reporting import ui_workspace

    monkeypatch.setattr(ui_workspace, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(ui_workspace, "query_rows", lambda *_args, **_kwargs: [{
        "id": 7, "entity_type": "ad_user", "natural_key": "account",
        "display_name": "Allowed object", "first_seen_utc": None,
        "last_seen_utc": None, "latest_state_status": None,
        "latest_state_summary": None, "latest_state_observed_at_utc": None,
        "latest_state_event_db_id": None,
    }])
    monkeypatch.setattr(ui_workspace, "_get_current_entity_states", lambda **_kwargs: [])
    monkeypatch.setattr(
        "server.ad_context.integration.get_runtime_entity_context_evidence",
        lambda *_args, **_kwargs: {
            "entity_id": 7, "resolution": "not_observed", "returned_count": 0,
            "bounded": True, "items": [],
        },
    )
    calls: list[dict[str, object]] = []

    def evidence_rows(**kwargs):
        calls.append(kwargs)
        if kwargs.get("id_only", False):
            return [
                {"event_db_id": 11, "server_id": 7, "domain_id": 1, "channel": "Security"},
                {"event_db_id": 12, "server_id": 9, "domain_id": 2, "channel": "Security"},
            ]
        assert kwargs["event_db_ids"] == [11]
        return [{
            "event_db_id": 11, "event_id": 4624,
            "time_created_utc": "2026-09-10T01:00:00Z", "server": "allowed.example.invalid",
            "channel": "Security", "provider_name": "Microsoft-Windows-Security-Auditing",
            "link_role": "subject", "confidence": 1.0,
            "subject_user_name": "alice", "target_user_name": None,
        }]

    monkeypatch.setattr(ui_workspace, "_get_entity_evidence_event_rows", evidence_rows)
    result = ui_workspace.get_entity_workspace_detail_data(
        entity_id=7,
        limit=30,
        event_evidence_allowed=lambda candidate: int(candidate["event_db_id"]) == 11,
    )

    assert [item["event_db_id"] for item in result["events"]] == [11]
    assert [bool(call.get("id_only", False)) for call in calls] == [True, False]


def test_entity_detail_keeps_has_more_when_scope_filter_exhausts_candidate_window(monkeypatch) -> None:
    """A denied newest candidate cannot make a bounded history look complete."""
    from server.sli.reporting import ui_workspace

    monkeypatch.setattr(ui_workspace, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(ui_workspace, "query_rows", lambda *_args, **_kwargs: [{
        "id": 7, "entity_type": "ad_user", "natural_key": "account",
        "display_name": "Allowed object", "first_seen_utc": None,
        "last_seen_utc": None, "latest_state_status": None,
        "latest_state_summary": None, "latest_state_observed_at_utc": None,
        "latest_state_event_db_id": None,
    }])
    monkeypatch.setattr(ui_workspace, "_get_current_entity_states", lambda **_kwargs: [])
    monkeypatch.setattr(
        "server.ad_context.integration.get_runtime_entity_context_evidence",
        lambda *_args, **_kwargs: {
            "entity_id": 7, "resolution": "not_observed", "returned_count": 0,
            "bounded": True, "items": [],
        },
    )

    candidates = [
        {
            "event_db_id": event_db_id,
            "time_created_utc": f"2026-09-10T00:00:{event_db_id:02d}Z",
            "server_id": 7,
            "domain_id": 1,
            "channel": "Security",
        }
        for event_db_id in range(31, 0, -1)
    ]

    def evidence_rows(**kwargs):
        if kwargs.get("id_only", False):
            return candidates
        assert kwargs["event_db_ids"] == list(range(30, 0, -1))
        return [{
            "event_db_id": event_db_id,
            "event_id": 4624,
            "time_created_utc": f"2026-09-10T00:00:{event_db_id:02d}Z",
            "server": "allowed.example.invalid",
            "channel": "Security",
            "provider_name": "Microsoft-Windows-Security-Auditing",
            "link_role": "subject",
            "confidence": 1.0,
            "subject_user_name": "alice",
            "target_user_name": None,
        } for event_db_id in range(30, 0, -1)]

    monkeypatch.setattr(ui_workspace, "_get_entity_evidence_event_rows", evidence_rows)
    result = ui_workspace.get_entity_workspace_detail_data(
        entity_id=7,
        limit=30,
        event_evidence_allowed=lambda candidate: int(candidate["event_db_id"]) != 31,
    )

    assert [item["event_db_id"] for item in result["events"]] == list(range(30, 0, -1))
    assert result["has_more"] is True
    assert result["next_cursor"] == {
        "time_utc": "2026-09-10T00:00:01Z",
        "event_db_id": 1,
    }


def test_entity_evidence_id_preflight_keeps_security_time_internal_to_postgres_ordering(monkeypatch) -> None:
    """The outer preflight DTO omits security time, while PostgreSQL can still order it."""
    from server.sli.reporting import ui_workspace

    captured: dict[str, str] = {}
    monkeypatch.setattr(ui_workspace, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(
        ui_workspace,
        "query_rows_bounded",
        lambda sql, *_args, **_kwargs: captured.setdefault("sql", sql) and [],
    )

    ui_workspace._get_entity_evidence_event_rows(
        entity_id=7,
        limit=31,
        before_time_utc=None,
        before_event_db_id=None,
        id_only=True,
    )

    normalized = " ".join(captured["sql"].lower().split())
    assert "with ordered_candidates as" in normalized
    assert "select distinct event.id as event_db_id, event.server_id, server.domain_id, channel.value as channel, event.time_created_utc as sort_time_utc" in normalized
    assert "order by event.time_created_utc desc, event.id desc limit ?" in normalized
    assert "select event_db_id, server_id, domain_id, channel from ordered_candidates order by sort_time_utc desc, event_db_id desc" in normalized


def test_entity_detail_keeps_existing_evidence_gate_with_field_projection(monkeypatch) -> None:
    """An additive field projection cannot turn a denied proof into metadata."""
    from server.sli.reporting import ui_workspace

    monkeypatch.setattr(ui_workspace, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(ui_workspace, "query_rows", lambda *_args, **_kwargs: [{
        "id": 7, "entity_type": "ad_user", "natural_key": "account",
        "display_name": "Allowed object", "first_seen_utc": None,
        "last_seen_utc": None, "latest_state_status": None,
        "latest_state_summary": None, "latest_state_observed_at_utc": None,
        "latest_state_event_db_id": None,
    }])
    monkeypatch.setattr(ui_workspace, "_get_current_entity_states", lambda **_kwargs: [])
    monkeypatch.setattr(
        "server.ad_context.integration.get_runtime_entity_context_evidence",
        lambda *_args, **_kwargs: {
            "entity_id": 7, "resolution": "not_observed", "returned_count": 0,
            "bounded": True, "items": [],
        },
    )
    monkeypatch.setattr(
        ui_workspace,
        "_get_entity_evidence_event_rows",
        lambda **kwargs: [{
            "event_db_id": 12, "server_id": 9, "domain_id": 2, "channel": "Security",
        }] if kwargs.get("id_only", False) else pytest.fail("denied proof must not be hydrated"),
    )

    result = ui_workspace.get_entity_workspace_detail_data(
        entity_id=7,
        limit=30,
        event_evidence_allowed=lambda _candidate: False,
        event_evidence_projection=lambda _candidate: "full",
    )

    assert result["events"] == []
    assert result["events_state"] == "forbidden"


def test_entity_current_states_use_bounded_postgres_projection(monkeypatch) -> None:
    from server.sli.reporting import ui_workspace

    calls: list[tuple[str, tuple[object, ...], int]] = []

    def fake_query(sql, params, *, statement_timeout_ms):
        calls.append((" ".join(sql.split()).lower(), tuple(params), statement_timeout_ms))
        return [{
            "state_type": "account.access", "status": "locked", "projection_status": "normal",
            "observed_at_utc": "2026-07-18T13:08:19Z", "evidence_event_db_id": 5427398,
            "rule_id": "account-locked-4740", "rule_version": "entity-state-1.0",
            "summary": "Блокировка учётной записи",
        }]

    monkeypatch.setattr(ui_workspace, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(ui_workspace, "query_rows_bounded", fake_query)

    states = ui_workspace._get_current_entity_states(entity_id=2481902)

    assert states == [{
        "state_type": "account.access", "status": "locked", "projection_status": "normal",
        "observed_at_utc": "2026-07-18T13:08:19Z", "evidence_event_db_id": 5427398,
        "rule_id": "account-locked-4740", "rule_version": "entity-state-1.0",
        "summary": "Блокировка учётной записи",
    }]
    assert len(calls) == 1
    assert "from entity_state_current current" in calls[0][0]
    assert "left join entity_states history" in calls[0][0]
    assert calls[0][1] == (2481902, ui_workspace.ENTITY_CURRENT_STATE_LIMIT)
    assert calls[0][2] == 3000


def test_entity_current_states_reject_non_postgres_backend(monkeypatch) -> None:
    from server.sli.reporting import ui_workspace

    monkeypatch.setattr(ui_workspace, "is_postgres_runtime_db", lambda: False)

    with pytest.raises(RuntimeError, match="require PostgreSQL runtime"):
        ui_workspace._get_current_entity_states(entity_id=1)


def test_entity_evidence_uses_storage_v2_blocks_in_postgres(monkeypatch) -> None:
    from server.sli.reporting import ui_workspace

    calls: list[tuple[str, tuple[object, ...], int]] = []

    def fake_query(sql, params, *, statement_timeout_ms):
        calls.append((" ".join(sql.split()).lower(), tuple(params), statement_timeout_ms))
        return [{"event_db_id": 5427398, "event_id": 4740}]

    monkeypatch.setattr(ui_workspace, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(ui_workspace, "query_rows_bounded", fake_query)

    rows = ui_workspace._get_entity_evidence_event_rows(
        entity_id=2481902,
        limit=6,
        before_time_utc="2026-07-18T13:08:19Z",
        before_event_db_id=5427398,
    )

    assert rows == [{"event_db_id": 5427398, "event_id": 4740}]
    assert len(calls) == 1
    assert "from event_entity_link_blocks_v2 block" in calls[0][0]
    assert "cross join lateral unnest" in calls[0][0]
    assert "from event_entity_links" not in calls[0][0]
    assert calls[0][1] == (2481902, "2026-07-18T13:08:19Z", "2026-07-18T13:08:19Z", 5427398, 6)
    assert calls[0][2] == 3000


def test_entity_detail_handler_rejects_invalid_and_returns_not_found(monkeypatch) -> None:
    from server.api.routes import entities as routes_entities

    handler = SimpleNamespace()
    captured: dict[str, object] = {}
    handler._send_json = lambda payload, status=HTTPStatus.OK: captured.update(payload=payload, status=status)
    routes_entities._handle_v1_entity_by_id_api(handler, "/api/v1/entities/not-a-number", {})
    assert captured == {"payload": {"error": "invalid_entity_id"}, "status": HTTPStatus.BAD_REQUEST}

    monkeypatch.setattr(routes_entities, "get_entity_workspace_detail_data", lambda **_kwargs: None)
    monkeypatch.setattr(routes_entities, "get_entity_workspace_resource_preflight", lambda **_kwargs: None)
    routes_entities._handle_v1_entity_by_id_api(handler, "/api/v1/entities/42", {})
    assert captured == {"payload": {"error": "entity_not_found", "entity_id": 42}, "status": HTTPStatus.NOT_FOUND}


def test_entity_detail_handler_serializes_existing_entity_with_ad_context(monkeypatch) -> None:
    from server.api.routes import entities as routes_entities

    handler = SimpleNamespace()
    captured: dict[str, object] = {}
    handler._send_json = lambda payload, status=HTTPStatus.OK: captured.update(payload=payload, status=status)
    handler._access_decision = lambda: {"platform_owner": True}
    monkeypatch.setattr(
        routes_entities,
        "get_entity_workspace_resource_preflight",
        lambda **_kwargs: {
            "id": 1472, "entity_type": "asset", "domain_id": 1, "server_id": 1,
        },
    )
    monkeypatch.setattr(routes_entities, "get_entity_workspace_detail_data", lambda **_kwargs: {
        "entity": {
            "id": 1472, "type": "asset", "natural_key": "node", "display_name": "Узел",
            "first_seen_utc": None, "last_seen_utc": None, "latest_state": None,
        },
        "current_states": [],
        "current_states_state": "available",
        "ad_context": {
            "entity_id": 1472, "resolution": "not_observed", "items": [],
            "returned_count": 0, "bounded": True,
        },
        "ad_context_state": "available",
        "events": [],
        "events_state": "forbidden",
        "events_scope_filtered": True,
        "has_more": False,
        "next_cursor": None,
        "limits": {"events": 50},
    })

    routes_entities._handle_v1_entity_by_id_api(handler, "/api/v1/entities/1472", {})

    assert captured["status"] == HTTPStatus.OK
    assert captured["payload"]["entity"]["id"] == 1472
    assert captured["payload"]["ad_context"]["resolution"] == "not_observed"
    assert captured["payload"]["events_scope_filtered"] is True
    assert captured["payload"]["events_state"] == "forbidden"


def test_entity_detail_handler_forwards_exact_bounded_time_context(monkeypatch) -> None:
    from server.api.routes import entities as routes_entities

    handler = SimpleNamespace()
    captured: dict[str, object] = {}
    handler._send_json = lambda payload, status=HTTPStatus.OK: captured.update(payload=payload, status=status)
    handler._access_decision = lambda: {"platform_owner": True}
    monkeypatch.setattr(
        routes_entities, "get_entity_workspace_resource_preflight",
        lambda **_kwargs: {"id": 1472, "entity_type": "asset", "domain_id": 1, "server_id": 1},
    )
    handler._access_decision = lambda: {"platform_owner": True}
    monkeypatch.setattr(
        routes_entities, "get_entity_workspace_resource_preflight",
        lambda **_kwargs: {"id": 1472, "entity_type": "asset", "domain_id": 1, "server_id": 1},
    )
    monkeypatch.setattr(
        routes_entities,
        "entity_security_interpretation",
        lambda _access, **_kwargs: {
            "security_actions_state": "available",
            "security_actions": [],
            "semantic_relations_state": "available",
            "semantic_relations": [],
        },
    )

    def detail(**kwargs):
        captured["kwargs"] = kwargs
        return {
            "entity": {
                "id": 1472, "type": "ad_user", "natural_key": "user", "display_name": "User",
                "first_seen_utc": None, "last_seen_utc": None, "latest_state": None,
            },
            "current_states": [], "current_states_state": "available",
            "ad_context": {
                "entity_id": 1472, "resolution": "not_observed", "items": [],
                "returned_count": 0, "bounded": True,
            },
            "ad_context_state": "available", "events": [], "events_state": "available",
            "events_scope_filtered": False, "has_more": False, "next_cursor": None,
            "context": {
                "time_from_utc": kwargs["time_from_utc"],
                "time_to_utc_exclusive": kwargs["time_to_utc_exclusive"],
                "timezone": kwargs["timezone_name"],
            },
            "limits": {"events": 50},
        }

    monkeypatch.setattr(routes_entities, "get_entity_workspace_detail_data", detail)
    routes_entities._handle_v1_entity_by_id_api(handler, "/api/v1/entities/1472", {
        "time_from": ["2026-09-10T12:00:00.123456Z"],
        "time_to": ["2026-09-11T12:00:00.654321Z"],
        "timezone": ["Asia/Bangkok"],
    })

    assert captured["status"] == HTTPStatus.OK
    kwargs = captured["kwargs"]
    assert kwargs["time_from_utc"] == "2026-09-10T12:00:00.123456Z"
    assert kwargs["time_to_utc_exclusive"] == "2026-09-11T12:00:00.654321Z"
    assert kwargs["timezone_name"] == "Asia/Bangkok"


def test_entity_detail_handler_rejects_partial_or_wide_time_context(monkeypatch) -> None:
    from server.api.routes import entities as routes_entities

    handler = SimpleNamespace()
    captured: dict[str, object] = {}
    handler._send_json = lambda payload, status=HTTPStatus.OK: captured.update(payload=payload, status=status)
    handler._access_decision = lambda: {"platform_owner": True}
    monkeypatch.setattr(
        routes_entities, "get_entity_workspace_resource_preflight",
        lambda **_kwargs: {"id": 1472, "entity_type": "ad_user", "domain_id": 1, "server_id": 1},
    )
    monkeypatch.setattr(
        routes_entities, "get_entity_workspace_detail_data",
        lambda **_kwargs: pytest.fail("invalid time context must fail before data read"),
    )

    routes_entities._handle_v1_entity_by_id_api(handler, "/api/v1/entities/1472", {
        "time_from": ["2026-09-10T00:00:00Z"],
    })
    assert captured == {
        "payload": {"error": "entity_time_context_requires_both_bounds"},
        "status": HTTPStatus.BAD_REQUEST,
    }

    captured.clear()
    routes_entities._handle_v1_entity_by_id_api(handler, "/api/v1/entities/1472", {
        "time_from": ["2026-08-01T00:00:00Z"],
        "time_to": ["2026-09-10T00:00:00Z"],
        "timezone": ["UTC"],
    })
    assert captured == {
        "payload": {"error": "entity_time_context_period_too_wide"},
        "status": HTTPStatus.BAD_REQUEST,
    }


def test_event_entities_bigint_id_is_preserved_in_block_lookup(monkeypatch) -> None:
    from server.sli.reporting import ui_workspace, ui_workspace_events

    event_id = 2_147_483_648
    calls = []

    def query(sql, params=(), **kwargs):
        calls.append((sql, params))
        return [{"present": 1}] if "from events_v2_core" in sql else []

    monkeypatch.setattr(ui_workspace, "resolve_storage_route", lambda **kwargs: None)
    monkeypatch.setattr(ui_workspace, "is_postgres_runtime_db", lambda *args: True)
    monkeypatch.setattr(ui_workspace, "primary_read_enabled", lambda: False)
    monkeypatch.setattr(ui_workspace, "query_rows_bounded", query)
    result = ui_workspace_events.get_event_entities_data(event_db_id=event_id)
    assert result["event_db_id"] == event_id
    assert result["event_found"] is True
    assert "array[?]::bigint[]" in calls[1][0]
    assert calls[1][1][:4] == (event_id,) * 4


def test_v4_workspace_route_serializes_only_authorized_recent_objects(monkeypatch) -> None:
    """Exercise the real workspace builder and DTO at the API adapter boundary."""
    from server.api.routes import workspace as route
    from server.sli.reporting import reporting_v4

    access = {
        "capabilities": ["workspace.view", "objects.view", "field.technical"],
        "capability_policies": [
            {"capability_key": "objects.view", "effect": "deny", "valid": True,
             "scope": {"kind": "server", "ids": [22]}},
            {"capability_key": "field.technical", "effect": "deny", "valid": True,
             "scope": {"kind": "domain", "ids": [11]}},
        ],
        "reports": [], "subject": {"login": "synthetic"}, "packages": [],
        "groups": [], "explicit_denies": {},
    }
    rows = [
        {"id": 99999, "object_type": "account", "display_name": "DENIED_IDENTITY_SENTINEL",
         "natural_key": "TECHNICAL_SENTINEL", "domain_id": 11, "server_id": 22},
        {"id": 8, "object_type": "account", "display_name": "",
         "natural_key": "TECHNICAL_SENTINEL", "domain_id": 11, "server_id": 23},
    ]
    monkeypatch.setattr(reporting_v4, "query_rows_bounded", lambda *_args, **_kwargs: rows)
    monkeypatch.setattr(reporting_v4, "_workspace_focus_metrics", lambda *_args: [])
    monkeypatch.setattr(route, "get_v4_workspace", reporting_v4.workspace)
    responses = []
    handler = SimpleNamespace(
        _principal=None, _access_decision=lambda: access,
        _send_json=lambda payload: responses.append(payload),
    )
    route._handle_v4_workspace_api(handler)

    assert len(responses) == 1
    assert responses[0]["recent_objects"] == [{
        "object_type": "account", "object_id": "8", "display_name": "8",
        "natural_key": None, "observed_at_utc": None, "source": "Storage V2",
    }]
    assert "DENIED_IDENTITY_SENTINEL" not in str(responses[0])
    assert "TECHNICAL_SENTINEL" not in str(responses[0])

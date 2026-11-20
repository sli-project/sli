from __future__ import annotations

from typing import Any

import pytest

from server.ad_context import integration
from server.sli.access import object_facade_v4
from server.sli.reporting import ui_workspace


def _entity_resource_preflight(*_args: Any, **_kwargs: Any) -> list[dict[str, Any]]:
    return [{"id": 7, "entity_type": "ad_user", "domain_id": 1, "server_id": 7}]


def test_runtime_ad_context_uses_shared_entity_id_before_alias_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed = {
        "entity_id": 41,
        "items": [{"source_section": "gpo_governance"}],
        "returned_count": 1,
        "bounded": True,
    }
    monkeypatch.setattr(
        integration,
        "get_entity_context_evidence",
        lambda entity_id, **_kwargs: {**observed, "entity_id": entity_id},
    )
    monkeypatch.setattr(
        integration,
        "query_rows_bounded",
        lambda *_args, **_kwargs: pytest.fail("alias fallback must not run"),
    )

    result = integration.get_runtime_entity_context_evidence(41)

    assert result["resolution"] == "shared_entity_id"
    assert result["ad_context_entity_id"] == 41
    assert result["items"] == observed["items"]


def test_ad_only_gpo_does_not_claim_storage_v2_provenance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed_at = "2026-07-26T11:08:44+07:00"
    monkeypatch.setattr(object_facade_v4, "ensure_access_schema", lambda: None)
    monkeypatch.setattr(
        object_facade_v4,
        "get_entity_workspace_resource_preflight",
        lambda **_kwargs: {"id": 41, "entity_type": "gpo", "domain_id": 1, "server_id": None},
    )
    monkeypatch.setattr(
        object_facade_v4,
        "get_entity_workspace_detail_data",
        lambda **_kwargs: {
            "entity": {
                "id": 41,
                "type": "gpo",
                "display_name": "Действующая политика",
                "natural_key": "ad:domain:guid",
            },
            "ad_context": {
                "resolution": "shared_entity_id",
                "items": [{
                    "context_kind": "entity",
                    "observed_at_utc": observed_at,
                    "attributes": {},
                }],
            },
            "events": [],
            "events_state": "available",
            "has_more": False,
            "current_states": [],
        },
    )

    def rows(sql: str, *_args: Any, **_kwargs: Any) -> list[dict[str, Any]]:
        if "storage_v2_observed_at_utc" in sql:
            return [{
                "domain_id": 1,
                "server_id": None,
                "storage_v2_observed_at_utc": None,
            }]
        return []

    monkeypatch.setattr(object_facade_v4, "query_rows_bounded", rows)
    access = {
        "capabilities": [
            "objects.view",
            "field.identity_basic",
            "field.security",
            "field.technical",
        ],
    }

    result = object_facade_v4.object_detail(
        None,
        object_type="gpo",
        object_id="41",
        access=access,
    )

    assert result["provenance"] == [{
        "source": "AD Context",
        "observed_at_utc": observed_at,
        "freshness": "observed",
    }]


def test_dual_source_entity_reports_both_observed_sources(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage_at = "2026-07-26T11:00:00+07:00"
    context_at = "2026-07-26T11:08:44+07:00"
    monkeypatch.setattr(object_facade_v4, "ensure_access_schema", lambda: None)
    monkeypatch.setattr(
        object_facade_v4,
        "get_entity_workspace_resource_preflight",
        lambda **_kwargs: {"id": 42, "entity_type": "ad_user", "domain_id": 1, "server_id": 2},
    )
    monkeypatch.setattr(
        object_facade_v4,
        "get_entity_workspace_detail_data",
        lambda **_kwargs: {
            "entity": {
                "id": 42,
                "type": "ad_user",
                "display_name": "Рабочая учётная запись",
                "natural_key": "domain\\account",
            },
            "ad_context": {
                "resolution": "shared_entity_id",
                "items": [{
                    "context_kind": "entity",
                    "observed_at_utc": context_at,
                    "attributes": {},
                }],
            },
            "events": [],
            "events_state": "available",
            "has_more": False,
            "current_states": [],
        },
    )

    def rows(sql: str, *_args: Any, **_kwargs: Any) -> list[dict[str, Any]]:
        if "storage_v2_observed_at_utc" in sql:
            return [{
                "domain_id": 1,
                "server_id": 2,
                "storage_v2_observed_at_utc": storage_at,
            }]
        return []

    monkeypatch.setattr(object_facade_v4, "query_rows_bounded", rows)
    access = {
        "capabilities": [
            "objects.view",
            "field.identity_basic",
            "field.security",
            "field.technical",
        ],
    }

    result = object_facade_v4.object_detail(
        None,
        object_type="ad_user",
        object_id="42",
        access=access,
    )

    assert [item["source"] for item in result["provenance"]] == [
        "Storage V2",
        "AD Context",
    ]


def test_object_scope_denial_happens_before_detail_hydration_and_type_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Removing the preflight would read a hidden entity before returning 404."""
    monkeypatch.setattr(ui_workspace, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(ui_workspace, "query_rows_bounded", _entity_resource_preflight)
    monkeypatch.setattr(
        object_facade_v4,
        "get_entity_workspace_detail_data",
        lambda **_kwargs: pytest.fail("hidden entity detail must not be hydrated"),
    )
    access = {
        "capabilities": ["objects.view"],
        "capability_policies": [{
            "capability_key": "objects.view", "effect": "deny",
            "scope": {"kind": "server", "ids": [7]}, "valid": True,
        }],
    }

    with pytest.raises(ValueError, match="object_not_found"):
        object_facade_v4.object_detail(
            None, object_type="computer", object_id="7", access=access,
        )


@pytest.mark.parametrize(
    ("denied_capability", "expected_projection", "expected_event"),
    [
        (
            "field.technical",
            "security_metadata",
            {
                "event_db_id": 12,
                "event_id": 4624,
                "time_utc": "2026-09-10T01:00:00Z",
                "server": "foreign.example.invalid",
                "channel": "Security",
                "label": "Успешный вход",
            },
        ),
        (
            "field.security",
            "technical",
            {
                "event_db_id": 12,
                "server": "foreign.example.invalid",
                "channel": "Security",
                "provider_name": "Microsoft-Windows-Security-Auditing",
                "link_role": "subject",
                "confidence": 1.0,
            },
        ),
    ],
)
def test_object_detail_projects_each_event_before_protected_metadata_read(
    monkeypatch: pytest.MonkeyPatch,
    denied_capability: str,
    expected_projection: str,
    expected_event: dict[str, object],
) -> None:
    """An entity-A grant must not hydrate fields denied on proof B."""
    monkeypatch.setattr(object_facade_v4, "ensure_access_schema", lambda: None)
    monkeypatch.setattr(
        object_facade_v4,
        "get_entity_workspace_resource_preflight",
        lambda **_kwargs: {"id": 7, "entity_type": "ad_user", "domain_id": 1, "server_id": 7},
    )
    monkeypatch.setattr(ui_workspace, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(ui_workspace, "query_rows", lambda *_args, **_kwargs: [{
        "id": 7, "entity_type": "ad_user", "natural_key": "account",
        "display_name": "Allowed entity", "first_seen_utc": None,
        "last_seen_utc": None, "latest_state_status": None,
        "latest_state_summary": None, "latest_state_observed_at_utc": None,
        "latest_state_event_db_id": None,
    }])
    monkeypatch.setattr(ui_workspace, "_get_current_entity_states", lambda **_kwargs: [])
    monkeypatch.setattr(
        "server.ad_context.integration.get_runtime_entity_context_evidence",
        lambda *_args, **_kwargs: {
            "entity_id": 7, "resolution": "not_observed", "items": [],
            "returned_count": 0, "bounded": True,
        },
    )

    candidate = {
        "event_db_id": 12,
        "time_created_utc": "2026-09-10T01:00:00Z",
        "server_id": 9,
        "domain_id": 2,
        "channel": "Security",
    }

    def evidence_rows(**kwargs: Any) -> list[dict[str, Any]]:
        if kwargs.get("id_only", False):
            return [candidate]
        assert kwargs["event_db_ids"] == [12]
        # The selected owner query must be chosen before any denied field can
        # be hydrated.  Returning only its allowed columns catches a fallback
        # to the old full projection.
        assert kwargs.get("field_projection") == expected_projection
        if expected_projection == "security_metadata":
            return [{
                "event_db_id": 12, "event_id": 4624,
                "time_created_utc": "2026-09-10T01:00:00Z",
                "server": "foreign.example.invalid", "channel": "Security",
            }]
        return [{
            "event_db_id": 12, "server": "foreign.example.invalid", "channel": "Security",
            "provider_name": "Microsoft-Windows-Security-Auditing",
            "link_role": "subject", "confidence": 1.0,
        }]

    monkeypatch.setattr(ui_workspace, "_get_entity_evidence_event_rows", evidence_rows)
    monkeypatch.setattr(
        object_facade_v4,
        "query_rows_bounded",
        lambda sql, *_args, **_kwargs: [{
            "domain_id": 1, "server_id": 7, "storage_v2_observed_at_utc": None,
        }] if "storage_v2_observed_at_utc" in sql else [],
    )
    access = {
        "capabilities": ["objects.view", "evidence.exact", "field.technical", "field.security"],
        "capability_policies": [{
            "capability_key": denied_capability,
            "effect": "deny",
            "scope": {"kind": "server", "ids": [9]},
            "valid": True,
        }],
    }

    result = object_facade_v4.object_detail(
        None, object_type="ad_user", object_id="7", access=access,
    )

    assert result["events"] == [expected_event]


@pytest.mark.parametrize("display_name", ["Shared display name", ""])
def test_object_findings_do_not_use_name_collision_as_identity(
    monkeypatch: pytest.MonkeyPatch, display_name: str,
) -> None:
    """Restoring the display-name OR would return the foreign finding fixture."""
    monkeypatch.setattr(ui_workspace, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(ui_workspace, "query_rows_bounded", _entity_resource_preflight)
    monkeypatch.setattr(object_facade_v4, "ensure_access_schema", lambda: None)
    monkeypatch.setattr(
        object_facade_v4,
        "get_entity_workspace_detail_data",
        lambda **_kwargs: {
            "entity": {"id": 7, "type": "ad_user", "display_name": display_name},
            "ad_context": {"resolution": "not_observed", "items": []},
            "events": [], "events_state": "available", "has_more": False,
            "current_states": [],
        },
    )

    foreign_finding = {
        "id": 99, "title": "Foreign", "severity": "high", "status": "new",
        "summary": "not in entity 7", "last_seen_utc": "2026-09-10T00:00:00Z",
        "evidence_event_id": 42,
    }

    def rows(sql: str, *_args: Any, **_kwargs: Any) -> list[dict[str, Any]]:
        if "storage_v2_observed_at_utc" in sql:
            return [{"domain_id": 1, "server_id": 7, "storage_v2_observed_at_utc": None}]
        if "findings_active" in sql:
            return [foreign_finding] if "lower(coalesce(link.display_name,''))" in sql else []
        return []

    monkeypatch.setattr(object_facade_v4, "query_rows_bounded", rows)
    result = object_facade_v4.object_detail(
        None,
        object_type="ad_user",
        object_id="7",
        access={"capabilities": ["objects.view", "field.security"]},
    )

    assert result["findings"] == []

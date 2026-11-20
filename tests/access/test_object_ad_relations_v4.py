from __future__ import annotations

from typing import Any

import pytest

from server.sli.access import object_facade_v4
from server.sli.access.entity_access_projection import project_ad_context


def _relation(section: str, group_id: int, name: str) -> dict[str, Any]:
    return {
        "context_evidence_id": group_id,
        "context_kind": "relation",
        "source_section": section,
        "related_entity_id": group_id,
        "related_display_name": name,
        "current": True,
        "observed_at_utc": "2026-10-02T12:00:00Z",
        "attributes": {"source_section": section, "membership_type": "direct", "record_key": "k"},
    }


def _detail_with(items: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch, capabilities: list[str]) -> dict[str, Any]:
    monkeypatch.setattr(object_facade_v4, "ensure_access_schema", lambda: None)
    monkeypatch.setattr(
        object_facade_v4, "get_entity_workspace_resource_preflight",
        lambda **_kwargs: {"id": 7, "entity_type": "ad_user", "domain_id": 1, "server_id": 7},
    )
    monkeypatch.setattr(
        object_facade_v4, "get_entity_workspace_detail_data",
        lambda **_kwargs: {
            "entity": {"id": 7, "type": "ad_user", "display_name": "Demo", "natural_key": "sid:7"},
            "ad_context": {"resolution": "shared_entity_id", "items": items},
            "events": [], "events_state": "available", "has_more": False, "current_states": [],
        },
    )
    monkeypatch.setattr(
        object_facade_v4, "query_rows_bounded",
        lambda sql, *_a, **_k: [{"domain_id": 1, "server_id": 7, "storage_v2_observed_at_utc": None}]
        if "storage_v2_observed_at_utc" in sql else [],
    )
    return object_facade_v4.object_detail(
        None, object_type="ad_user", object_id="7", access={"capabilities": capabilities},
    )


ITEMS = [
    _relation("privileged_membership", 11, "Admins"),
    _relation("vpn_membership", 12, "VPN Users"),
]


def test_groups_reader_receives_group_relations_but_not_privileged_ones(monkeypatch: pytest.MonkeyPatch) -> None:
    """objects.groups without objects.privileges used to get no relation at all."""
    result = _detail_with(ITEMS, monkeypatch, ["objects.view", "objects.groups", "field.identity_basic"])

    names = [item["related_display_name"] for item in result["directory_context"]["items"]]
    assert names == ["VPN Users"]
    assert result["directory_context"]["items"][0]["relation_class"] == "vpn"
    assert any(tab["id"] == "groups" and tab["available"] for tab in result["tabs"])


def test_privilege_reader_receives_both_classes_without_technical_section(monkeypatch: pytest.MonkeyPatch) -> None:
    """The collection section is technical; the class must survive its removal."""
    result = _detail_with(
        ITEMS, monkeypatch,
        ["objects.view", "objects.privileges", "field.privilege", "field.identity_basic"],
    )

    items = result["directory_context"]["items"]
    assert {item["related_display_name"]: item["relation_class"] for item in items} == {
        "Admins": "privileged", "VPN Users": "vpn",
    }
    assert all("source_section" not in item for item in items)


def test_relation_class_is_derived_only_for_relations() -> None:
    projected = project_ad_context(
        {"items": [
            _relation("directory_group_graph", 13, "Plain"),
            {"context_kind": "entity", "source_section": "directory_accounts", "attributes": {}},
        ]},
        capabilities={"field.identity_basic"}, include_relations=True,
    )

    assert projected["items"][0]["relation_class"] == "group"
    assert "relation_class" not in projected["items"][1]

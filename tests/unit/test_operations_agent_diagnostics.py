"""Operations keeps retired server history separate from live agent health."""
from datetime import datetime, timedelta, timezone

import pytest

from server.sli.reporting import ui_operations as ops

NOW = datetime(2026, 10, 19, tzinfo=timezone.utc)


@pytest.mark.parametrize("enabled,event_days,check_days,inserted,unused", [
    (False, 8, 8, 0, True), (False, 8, 7, 0, False),
    (False, 1, 8, 0, False), (False, 8, 1, 0, False),
    (False, 8, 8, 1, False), (True, 8, 8, 0, False),
])
def test_only_retired_sources_without_recent_data_are_unused(enabled, event_days, check_days, inserted, unused):
    channel = {"server": "fixture-node", "last_status": "access_denied",
               "last_event_time_utc": (NOW - timedelta(days=event_days)).isoformat(),
               "last_successful_collection_utc": (NOW - timedelta(days=check_days)).isoformat(),
               "inserted_24h": inserted}
    result = ops._legacy_source_usage({"items": [channel]}, {"operational_collection_enabled": enabled}, now=NOW)
    assert (result["items"][0].get("usage_state") == "unused") is unused
    assert "usage_state" not in channel
    assert result["items"][0]["last_status"] == "access_denied"


@pytest.mark.parametrize("state", ["current", "partial", "error", "unavailable"])
def test_overview_exposes_same_agent_health_as_readiness_even_when_server_is_blocked(monkeypatch, state):
    health = {"state": state, "items": [], "active_agents": 0, "current_agents": 0, "checked_at_utc": NOW.isoformat()}
    monkeypatch.setattr(ops, "get_agent_collection_health", lambda: health)
    monkeypatch.setattr(ops, "get_collector_health", lambda: {"items": []})
    monkeypatch.setattr(ops, "get_collection_runtime_status", lambda: {"collection_enabled": False,
                                                                      "collection_block_reason": "access_denied"})
    monkeypatch.setattr(ops, "get_runtime_workers_overview", lambda: {"items": []})
    monkeypatch.setattr(ops, "get_postgres_operations_status", lambda **kw: {})
    monkeypatch.setattr(ops, "get_operations_storage_summary", lambda pg: {})
    monkeypatch.setattr(ops, "_event_catalog_completeness_view", lambda: {})
    monkeypatch.setattr(ops, "_radius_vpn_operations_view", lambda: {})
    assert ops.get_operations_overview()["agent_collection"] == ops.get_platform_readiness()["agent_collection"] == health



@pytest.mark.parametrize("state", ["current", "partial", "error", "unknown", "unavailable"])
def test_setup_collection_projects_the_same_public_health_as_operations(monkeypatch, state):
    from server.sli.agents import collection_health
    from server.sli.core import setup_status

    health = {"state": state, "items": [], "active_agents": 0, "current_agents": 0,
              "checked_at_utc": NOW.isoformat()}
    monkeypatch.setattr(collection_health, "get_agent_collection_health", lambda **kwargs: {**health, "_setup_bindings": []})
    monkeypatch.setattr(ops, "get_agent_collection_health", lambda: health)
    monkeypatch.setattr(setup_status, "_report_domain", lambda: None)
    monkeypatch.setattr(setup_status, "_domains", lambda: [])
    monkeypatch.setattr(setup_status, "_domain_controllers", lambda: {"items": [], "source": "none"})
    monkeypatch.setattr(setup_status, "_sources", lambda: [])
    monkeypatch.setattr(ops, "get_collector_health", lambda: {"items": []})
    monkeypatch.setattr(ops, "get_collection_runtime_status", lambda: {"collection_enabled": False,
                                                                      "collection_block_reason": "access_denied"})
    monkeypatch.setattr(ops, "get_runtime_workers_overview", lambda: {"items": []})
    monkeypatch.setattr(ops, "get_postgres_operations_status", lambda **kw: {})
    monkeypatch.setattr(ops, "get_operations_storage_summary", lambda pg: {})
    monkeypatch.setattr(ops, "_event_catalog_completeness_view", lambda: {})
    monkeypatch.setattr(ops, "_radius_vpn_operations_view", lambda: {})
    setup = setup_status.build_setup_status()
    assert setup["agent_collection"] == ops.get_operations_overview()["agent_collection"] == health
    step = next(item for item in setup["steps"] if item["id"] == "first-collection")
    assert step["state"] == ("done" if state == "current" else "unavailable" if state in ("unknown", "unavailable") else "todo")
    assert setup["collection"]["block_reason"] is None

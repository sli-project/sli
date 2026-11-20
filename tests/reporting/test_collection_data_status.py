"""Collection status projections use fake channels, without storage reads."""
from datetime import datetime, timezone

from server.sli.reporting.ui_workspace_overview import _overview_sources
from server.sli.sources.collector_health import _operations_slo


def test_overview_keeps_channel_reason_and_independent_clocks():
    checked = datetime.now(timezone.utc).isoformat()
    channels = [{"server": "fixture-node", "channel": "Security", "last_status": "access_denied",
                 "backend_reason": "windows_event_log_access_denied", "last_successful_collection_utc": checked,
                 "last_event_time_utc": "2020-01-01T00:00:00Z"}]
    source = _overview_sources([], channels)[0]
    assert source["collection_state"] == "error"
    assert source["channels"][0]["channel"] == "Security"
    assert source["channels"][0]["failure_reason"] == "windows_event_log_access_denied"
    assert source["last_successful_collection_utc"] == checked.replace("+00:00", "Z")
    assert source["last_event_time_utc"] == "2020-01-01T00:00:00Z"
    from server.sli.reporting.ui_api_models import OverviewSource

    serialized = OverviewSource(**source).model_dump(mode="json")
    assert serialized["channels"][0]["failure_reason"] == "windows_event_log_access_denied"
    assert serialized["channels"][0]["last_event_time_utc"] == "2020-01-01T00:00:00Z"


def test_security_check_slo_does_not_use_last_event_age():
    checked = datetime.now(timezone.utc).isoformat()
    items = [{"channel": "Security", "last_status": "completed", "lag_minutes": 99999,
              "last_successful_collection_utc": checked},
             {"channel": "Security", "last_status": "failed", "lag_minutes": 0,
              "last_successful_collection_utc": checked},
             {"channel": "Security", "last_status": "completed", "lag_minutes": 0},
             {"channel": "System", "last_successful_collection_utc": checked}]
    slo = _operations_slo(items, {}, {})
    assert slo["security_channels"] == 3
    assert slo["freshness_current"] == 1
    assert slo["freshness_breached"] == 1
    assert slo["freshness_unknown"] == 1
    assert slo["basis"] == "last_successful_collection"


def test_channel_health_preserves_failure_reason_and_last_success(monkeypatch):
    from server.sli.core import postgres_runtime_pipeline
    from server.sli.sources import collector_health

    checked = datetime.now(timezone.utc).isoformat()
    monkeypatch.setattr(collector_health, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(collector_health, "_collection_state_rows", lambda: [{
        "server_hostname": "fixture-node", "channel": "Security",
        "last_successful_collection_utc": checked, "last_event_time_utc": "2020-01-01T00:00:00Z",
    }])
    monkeypatch.setattr(collector_health, "_db_history_stats_pg", lambda **kwargs: {
        ("fixture-node", "Security"): {"last_status": "access_denied", "backend_reason": "windows_event_log_access_denied"},
    })
    monkeypatch.setattr(collector_health, "_parse_log_stats", lambda *args, **kwargs: {})
    monkeypatch.setattr(postgres_runtime_pipeline, "get_cursor_audit_overview_pg", lambda **kwargs: {})
    monkeypatch.setattr(collector_health, "_safe_post_collection_overview", lambda **kwargs: {})
    monkeypatch.setattr(collector_health, "_safe_runtime_collection_history", lambda **kwargs: {})
    monkeypatch.setattr(collector_health, "_safe_storage_v2_outbox", lambda **kwargs: {})
    monkeypatch.setattr(collector_health, "log_event", lambda *args, **kwargs: None)
    channel = collector_health.get_collector_health()["items"][0]
    assert channel["collection_state"] == "error"
    assert channel["failure_reason"] == "windows_event_log_access_denied"
    assert channel["last_successful_collection_utc"] == checked
    assert channel["last_event_time_utc"] == "2020-01-01T00:00:00Z"


def test_workspace_preserves_runtime_block_when_snapshot_channels_are_old(monkeypatch):
    from server.sli.reporting import ui_workspace
    from server.sli.reporting.ui_api_models import OverviewWorkspaceResponse

    checked = datetime.now(timezone.utc).isoformat()
    collector = {"items": [{"server": "fixture-node", "channel": "Security", "last_status": "completed",
                            "last_successful_collection_utc": checked, "last_event_time_utc": "2020-01-01T00:00:00Z"}]}
    monkeypatch.setattr(ui_workspace, "build_dashboard_snapshot", lambda: {"collector_health": collector})
    monkeypatch.setattr(ui_workspace, "get_collector_health", lambda: collector)
    monkeypatch.setattr(ui_workspace, "get_runtime_workers_overview", lambda: {"items": []})
    monkeypatch.setattr(ui_workspace, "get_collection_runtime_status", lambda: {
        "collection_enabled": False, "collection_block_reason": "windows_event_log_access_denied",
        "collection_block": {"first_seen_at": "2026-10-01T00:00:00Z"},
    })
    monkeypatch.setattr(ui_workspace, "get_overview_activity", lambda **kwargs: {"available": False, "exact": False, "items": []})
    payload = OverviewWorkspaceResponse(**ui_workspace.get_overview_workspace_data()).model_dump(mode="json")
    assert payload["sources"][0]["channels"][0]["channel"] == "Security"
    assert payload["collection_progress"]["status"] == "blocked"
    assert payload["collection_progress"]["block_reason"] == "windows_event_log_access_denied"
    assert payload["collection_progress"]["blocked_since_utc"] == "2026-10-01T00:00:00Z"

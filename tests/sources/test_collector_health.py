from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from tests.support.pg_fake import FakePgStore


def _seed_security_event(store: FakePgStore) -> None:
    store.add_event(
        event_id=4624, time=datetime.now(timezone.utc).isoformat(), record_id=9001, computer='DC1',
        subject='svc_backup', subject_domain=None, target='svc_backup', target_domain=None,
        ip='192.0.2.2', logon_id='0xabc',
        event_data={"LogonType": "10", "IpAddress": "192.0.2.2"},
    )


def test_collector_health_detects_partial_timeout_and_repeated_backlog(monkeypatch, tmp_path: Path) -> None:
    from server.sli.sources import collector_health
    from server.sli.core import postgres_runtime_pipeline
    from server.sli.sources.collector_health import get_collector_health, render_collector_health_report

    log_path = tmp_path / "adlog-monitor.log"
    now = datetime.now(timezone.utc).isoformat()

    def fake_query_rows(sql: str, params: tuple = ()):
        normalized = " ".join(sql.split())
        if "from collection_channel_state" in normalized:
            return [{
                "server_hostname": "DC1", "channel": "Security", "archive_start_utc": now,
                "last_collection_start_utc": now, "last_successful_collection_utc": now,
                "last_event_time_utc": now, "last_event_record_id": 9001, "backfill_completed": True,
                "updated_at": now, "event_count": 1, "latest_event_time_utc": now,
                "latest_event_record_id": 9001, "current_limit": 500, "recovery_mode": False,
                "last_action": None, "adaptive_last_status": None, "last_lag_minutes": None,
            }]
        return []

    monkeypatch.setattr(collector_health, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(collector_health, "query_rows", fake_query_rows)
    monkeypatch.setattr(collector_health, "get_post_collection_overview", lambda *, limit=10: {"backend": "postgres", "status": "ok", "summary": {}, "items": []})
    monkeypatch.setattr(postgres_runtime_pipeline, "get_cursor_audit_overview_pg", lambda *, limit=30: {"summary": {}, "latest": [], "recent": []})
    monkeypatch.setattr(collector_health, "_safe_runtime_collection_history", lambda *, backend: {"status": "unavailable", "items": []})
    monkeypatch.setattr(collector_health, "_safe_storage_v2_outbox", lambda *, backend: {"status": "unavailable", "batches": 0, "events": 0, "states": {}})
    record = {
        "ts": now,
        "level": "ERROR",
        "component": "collector",
        "event": "server_collection_failed",
        "server": "DC1",
        "stdout_tail": "Timed out channel: Security after 300s partial_count=10\nSecurity.jsonl: inserted=0, skipped=900\n",
    }
    log_path.write_text(json.dumps(record, ensure_ascii=False) + "\n", encoding="utf-8")

    data = get_collector_health(log_path=log_path)
    security = [item for item in data["items"] if item["server"] == "DC1" and item["channel"] == "Security"][0]
    assert security["partial_timeouts_24h"] == 1
    assert security["last_partial_count"] == 10
    assert "possible repeated backlog read" in security["warnings"]

    html = render_collector_health_report(data)
    assert "Состояние сбора по каналам" in html
    assert "DC1" in html


def test_collector_health_rejects_non_postgres_backend(monkeypatch, tmp_path: Path) -> None:
    import pytest

    from server.sli.sources import collector_health

    monkeypatch.setattr(collector_health, "is_postgres_runtime_db", lambda: False)
    with pytest.raises(RuntimeError, match="PostgreSQL-only"):
        collector_health.get_collector_health(log_path=tmp_path / "missing.log")


def test_event_detail_investigation_links_from_one_storage_v2_event(monkeypatch) -> None:
    from server.sli.events import event_details

    monkeypatch.setattr(event_details, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(event_details, "log_event", lambda *_a, **_k: None)
    monkeypatch.setattr(event_details, "_get_v2_event_detail_by_id", lambda filters, **_kwargs: {
        "id": filters["event_db_id"], "server": "DC1", "channel": "Security", "event_id": 4624,
        "event_record_id": 1, "time_created_utc": "2026-07-07T10:00:00Z", "subject_user_name": "svc_backup",
        "target_user_name": "svc_backup", "logon_id": "0xabc", "event_data_json": "{}",
    })
    data = event_details.get_event_detail_report_data(event_db_id=5)
    assert data["total"] == 1
    assert data["items"][0]["logon_id"] == "0xabc"
    html = event_details.render_event_detail_report(data)
    assert "Тот же LogonId" in html
    assert "Соседние события ±15 минут" in html

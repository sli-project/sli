from __future__ import annotations

import time
from pathlib import Path


def _patch_snapshot_dependencies(monkeypatch, module, *, delay: float = 0.0, fail: str | None = None):
    calls: dict[str, int] = {}

    def item(name, value):
        def fn(*args, **kwargs):
            calls[name] = calls.get(name, 0) + 1
            if delay:
                time.sleep(delay)
            if fail == name:
                raise RuntimeError(f"{name} failed")
            return value
        return fn

    monkeypatch.setattr(module, "get_dashboard_event_summary", item("events_summary", {"total_events": 10, "by_channel": [], "by_server": []}))
    monkeypatch.setattr(module, "get_dashboard_entity_summary", item("entity_summary", {"total_entities": 5, "total_event_entity_links": 8}))
    monkeypatch.setattr(module, "get_collector_health", item("collector_health", {"summary": {}, "items": []}))
    monkeypatch.setattr(module, "get_sources", item("sources", []))
    monkeypatch.setattr(module, "get_findings_dashboard_data", item("findings", {"items": []}))
    monkeypatch.setattr(module, "list_ai_runs", item("ai_runs", {"items": []}))
    monkeypatch.setattr(module, "list_jobs", item("jobs", []))
    monkeypatch.setattr(module, "list_reports", item("reports", []))
    monkeypatch.setattr(module, "get_role_views_data", item("role_views", {"views": []}))
    monkeypatch.setattr(module, "get_scheduler_runtime_status", lambda: {})
    monkeypatch.setattr(module, "get_collection_runtime_status", lambda: {})
    monkeypatch.setattr(module, "active_backend", lambda: "postgres")
    monkeypatch.setattr(module, "_archive_status_payload", item("archive_status", {"archive_start_utc": None, "channel_states": [], "backend": "postgres"}))
    return calls


def test_dashboard_components_run_in_parallel(monkeypatch):
    from server.sli.reporting import dashboard_snapshot as module

    _patch_snapshot_dependencies(monkeypatch, module, delay=0.08)
    module.clear_dashboard_snapshot_cache()
    started = time.perf_counter()
    result = module.build_dashboard_snapshot(force=True)
    elapsed = time.perf_counter() - started

    assert result["status"] == "ok"
    assert elapsed < 0.45
    assert result["diagnostics"]["request_model"] == "parallel_bounded_snapshot"


def test_dashboard_returns_partial_payload_when_one_component_fails(monkeypatch):
    from server.sli.reporting import dashboard_snapshot as module

    _patch_snapshot_dependencies(monkeypatch, module, fail="entity_summary")
    module.clear_dashboard_snapshot_cache()
    result = module.build_dashboard_snapshot(force=True)

    assert result["status"] == "partial"
    assert "entity_summary" in result["diagnostics"]["failures"]
    assert result["entity_summary"]["status"] == "unavailable"
    assert result["events_summary"]["total_events"] == 10


def test_timed_out_dashboard_component_is_not_started_twice(monkeypatch):
    from threading import Event
    from server.sli.reporting import dashboard_snapshot as module

    _patch_snapshot_dependencies(monkeypatch, module)
    release = Event()
    calls = {"events": 0}

    def blocked_events(**_kwargs):
        calls["events"] += 1
        release.wait(timeout=2)
        return {"total_events": 1, "by_channel": [], "by_server": []}

    monkeypatch.setattr(module, "get_dashboard_event_summary", blocked_events)
    monkeypatch.setattr(module, "_snapshot_timeout_seconds", lambda: 0.01)
    monkeypatch.setattr(module, "_component_timeout_seconds", lambda: 0.01)
    module._COMPONENT_FLIGHTS.clear()
    try:
        first = module._build_dashboard_snapshot()
        second = module._build_dashboard_snapshot()
        assert first["status"] == "partial"
        assert second["status"] == "partial"
        assert calls["events"] == 1
    finally:
        release.set()
        for future in list(module._COMPONENT_FLIGHTS.values()):
            future.result(timeout=2)
        module._COMPONENT_FLIGHTS.clear()


def test_expired_dashboard_cache_is_served_while_refresh_starts(monkeypatch):
    from server.sli.reporting import dashboard_snapshot as module

    module.clear_dashboard_snapshot_cache()
    cached = {
        "status": "ok",
        "diagnostics": {"total_duration_ms": 12},
        "events_summary": {"total_events": 9},
    }
    with module._CACHE_LOCK:
        module._CACHE["payload"] = cached
        module._CACHE["created_monotonic"] = time.monotonic() - 30
        module._CACHE["refreshing"] = False
    monkeypatch.setattr(module, "warm_dashboard_snapshot_async", lambda: True)

    result = module.build_dashboard_snapshot()
    assert result["status"] == "stale"
    assert result["events_summary"]["total_events"] == 9
    assert result["diagnostics"]["cache_hit"] is True
    assert result["diagnostics"]["stale"] is True
    assert result["diagnostics"]["refreshing"] is True


def test_empty_preloaded_role_data_does_not_trigger_duplicate_queries(monkeypatch):
    from server.sli.access import role_views as module

    def forbidden(*args, **kwargs):
        raise AssertionError("preloaded empty value must not be recomputed")

    monkeypatch.setattr(module, "get_event_summary", forbidden)
    monkeypatch.setattr(module, "get_entity_summary", forbidden)
    monkeypatch.setattr(module, "get_collector_health", forbidden)
    monkeypatch.setattr(module, "get_system_health", forbidden)
    monkeypatch.setattr(module, "get_findings_data", forbidden)
    monkeypatch.setattr(module, "list_ai_runs", forbidden)
    monkeypatch.setattr(module, "get_sources", forbidden)

    result = module.get_role_views_data(
        preloaded={
            "events": {},
            "entities": {},
            "collector": {},
            "system": {},
            "findings": {},
            "ai_runs": {},
            "sources": [],
        }
    )
    assert len(result["views"]) == 3


def test_findings_dashboard_uses_two_queries_without_n_plus_one(monkeypatch):
    from server.sli.semantic import findings as module

    calls: list[str] = []

    def fake_query(sql, params=()):
        calls.append(" ".join(sql.split()).lower())
        if "group by severity" in sql.lower():
            return [{"severity": "high", "status": "new", "count": 1}]
        return [{"id": 1, "severity": "high", "status": "new"}]

    monkeypatch.setattr(module, "query_rows", fake_query)
    monkeypatch.setattr(module, "is_postgres_runtime_db", lambda: True)
    result = module.get_findings_dashboard_data(limit=50)

    assert result["details_included"] is False
    assert len(calls) == 2
    assert not any("finding_evidence" in sql or "finding_entities" in sql or "finding_status_history" in sql for sql in calls)


def test_postgres_collector_state_query_does_not_scan_events(monkeypatch):
    from server.sli.sources import collector_health as module

    seen: list[str] = []

    def fake_query(sql, params=()):
        seen.append(" ".join(sql.split()).lower())
        return []

    monkeypatch.setattr(module, "query_rows", fake_query)
    assert module._collection_state_rows() == []
    assert len(seen) == 1
    assert "from events" not in seen[0]
    assert "collector_channel_runs" in seen[0]


def test_postgres_collector_history_is_loaded_with_one_query(monkeypatch):
    from server.sli.sources import collector_health as module
    from datetime import datetime, timezone

    calls = 0

    def fake_query(sql, params=()):
        nonlocal calls
        calls += 1
        return [{"server": "DC1", "channel": "Security", "inserted": 10, "skipped": 1, "last_status": "completed"}]

    monkeypatch.setattr(module, "query_rows", fake_query)
    result = module._db_history_stats_pg(now=datetime.now(timezone.utc))
    assert calls == 1
    assert result[("DC1", "Security")]["last_status"] == "completed"


def test_collector_health_deduplicates_server_case_by_latest_state() -> None:
    from server.sli.sources import collector_health as module

    stale = {
        "server_hostname": "dc1",
        "channel": "Security",
        "last_successful_collection_utc": "2026-08-14T23:43:32+00:00",
        "updated_at": "2026-08-14T23:43:33+00:00",
    }
    current = {
        "server_hostname": "DC1",
        "channel": "Security",
        "last_successful_collection_utc": "2026-08-25T23:38:46+00:00",
        "updated_at": "2026-08-25T23:38:47+00:00",
    }

    assert module._latest_state_rows_by_case_identity([stale, current]) == [current]


def test_dashboard_fast_module_avoids_unbounded_event_counts():
    text = Path("server/sli/reporting/dashboard_fast.py").read_text(encoding="utf-8").lower()
    assert "pg_stat_user_tables" in text
    assert "raw_log_files" in text
    assert "order by id desc" in text
    assert "select count(*) as count from events" not in text


def test_server_starts_background_dashboard_warmup():
    text = Path("server/api/http_server.py").read_text(encoding="utf-8")
    assert "warm_dashboard_snapshot_async()" in text
    assert "warm_system_health_storage_async()" in text


class _ScriptedCursor:
    """Answers the recent-link queries: anchors by offset, then role counts."""

    def __init__(self, anchors: dict[int, int | None], role_counts: list[list[dict]]) -> None:
        self.anchors, self.role_counts, self.statements = anchors, list(role_counts), []
        self._next: object = None

    def execute(self, sql, params=()):
        text = " ".join(str(sql).split()).lower()
        self.statements.append((text, tuple(params)))
        if text.startswith("select id from events_v2_core order by id desc offset"):
            anchor = self.anchors.get(params[0])
            self._next = {"id": anchor} if anchor is not None else None
        else:
            self._next = self.role_counts.pop(0)

    def fetchone(self):
        return self._next

    def fetchall(self):
        return self._next


def test_recent_v2_link_roles_reads_blocks_and_widens_until_the_sample_is_full() -> None:
    from server.sli.reporting import dashboard_fast

    cursor = _ScriptedCursor(
        anchors={9: 900, 39: 600},
        role_counts=[[{"link_role": "target", "count": 4}], [{"link_role": "target", "count": 7}, {"link_role": "actor", "count": 3}]],
    )
    rows = dashboard_fast._recent_v2_link_roles(cursor, 10)

    assert rows == [{"link_role": "target", "count": 7}, {"link_role": "actor", "count": 3}]
    link_queries = [(sql, params) for sql, params in cursor.statements if "event_entity_link_blocks_v2 block" in sql]
    assert [params for _, params in link_queries] == [(900, 900, 10), (600, 600, 10)]
    assert all("event_entity_links_v2" not in sql for sql, _ in link_queries)
    assert all("block.last_event_id >= %s" in sql for sql, _ in link_queries)


def test_recent_v2_link_roles_stops_when_every_event_is_covered() -> None:
    from server.sli.reporting import dashboard_fast

    cursor = _ScriptedCursor(anchors={}, role_counts=[[{"link_role": "context", "count": 2}]])
    assert dashboard_fast._recent_v2_link_roles(cursor, 10) == [{"link_role": "context", "count": 2}]
    assert cursor.statements[-1][1] == (0, 0, 10)

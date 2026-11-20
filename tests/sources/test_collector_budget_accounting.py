from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from server.sli.sources import collector_adaptive, collector_health
from tests.sources.test_collector_adaptive import _plan_from_pg_state, _record_runs_pg


@pytest.fixture
def fast_recovery(monkeypatch):
    for name, value in {
        "SECURITY_FAST_RECOVERY": True,
        "SECURITY_DEFAULT_LIMIT": 20_000,
        "SECURITY_MIN_LIMIT": 100,
        "SECURITY_MAX_LIMIT": 50_000,
    }.items():
        monkeypatch.setattr(collector_adaptive, name, value)


@pytest.mark.parametrize("status", ["timeout", "partial_timeout"])
@pytest.mark.parametrize("ceiling", [20_000, 500, 100, 50])
def test_persisted_timeout_backoff_survives_next_plan(monkeypatch, fast_recovery, status, ceiling):
    limit = ceiling
    for _ in range(3):
        cursor = _record_runs_pg(
            monkeypatch,
            {"channel": "Security", "status": status, "max_events": limit, "count": 10},
            inserted=10,
            job_id=42,
        )
        saved = next(params for sql, params in cursor.executed if "insert into collector_adaptive_state" in sql)
        state = dict(zip(
            ("server", "channel", "current_limit", "consecutive_completed", "recovery_mode", "last_status", "last_lag_minutes", "last_action", "updated_at"),
            saved,
        ))
        plan = _plan_from_pg_state(monkeypatch, security_lag_minutes=180, adaptive_state=state)
        expected = max(100, limit // 2)
        assert state["current_limit"] == expected
        assert plan.security_limit == expected
        assert plan.channel_limits["Security"] == expected
        assert plan.recovery_mode is True
        limit = min(ceiling, plan.security_limit)
        assert limit <= ceiling


@pytest.mark.parametrize("state,lag,expected", [
    (None, 180, 20_000),
    ({"current_limit": 500, "recovery_mode": False}, 180, 20_000),
    ({"current_limit": 500, "recovery_mode": True}, 180, 500),
    ({"current_limit": 500, "recovery_mode": True}, None, 500),
    ({"current_limit": 500, "recovery_mode": True}, 2, 500),
    ({"current_limit": 30_000, "recovery_mode": True}, 180, 30_000),
])
def test_recovery_initialization_entry_and_established_limits(monkeypatch, fast_recovery, state, lag, expected):
    plan = _plan_from_pg_state(monkeypatch, security_lag_minutes=lag, adaptive_state=state)
    assert plan.security_limit == expected
    assert plan.recovery_mode is (lag != 2)


def _slo_from_stats(stats, now, *, stale=0):
    items = [
        {"server": server, "channel": channel, "last_successful_collection_utc": now.isoformat(), **values}
        for (server, channel), values in stats.items()
    ]
    summary = collector_health._summary(items)
    summary["stale_post_collection"] = stale
    return collector_health._operations_slo(items, summary, {"summary": {"queued": 2}}), summary


@pytest.mark.parametrize("stale", [0, 3])
@pytest.mark.parametrize("source", ["database", "log_fallback"])
@pytest.mark.parametrize("partial,full,system", [(1, 0, 0), (1, 1, 7), (0, 0, 7), (0, 0, 0)])
def test_security_budget_counts_inclusive_timeouts_once(monkeypatch, tmp_path, source, partial, full, system, stale):
    now = datetime.now(timezone.utc)
    monkeypatch.setenv("ADLOG_COLLECTION_INTERVAL_SECONDS", "600")
    rows = [
        {"server": "DC1", "channel": channel, "timeouts_24h": total, "partial_timeouts_24h": partial_count, "last_status": "completed"}
        for channel, total, partial_count in [("Security", partial + full, partial), ("System", system, system)]
    ]
    if source == "database":
        def query(sql, params):
            assert "status in ('timeout', 'partial_timeout')" in sql
            assert "status = 'partial_timeout'" in sql
            assert params == ((now - timedelta(hours=24)).isoformat(),)
            return rows
        monkeypatch.setattr(collector_health, "query_rows", query)
        stats = collector_health._db_history_stats_pg(now=now)
    else:
        lines = []
        for row in rows:
            channel = row["channel"]
            for index in range(row["timeouts_24h"]):
                suffix = " partial_count=10" if index < row["partial_timeouts_24h"] else ""
                lines.append(f"Timed out channel: {channel} after 300s{suffix}")
            lines.append(f"Completed channel: {channel} count=0")
        path = tmp_path / "collector.log"
        path.write_text(json.dumps({"ts": now.isoformat(), "server": "DC1", "stdout_tail": "\n".join(lines)}))
        parsed = collector_health._parse_log_stats(path, now=now)
        stats = {key: collector_health._merge_stats({}, value) for key, value in parsed.items()}
    slo, summary = _slo_from_stats(stats, now, stale=stale)
    assert summary["timeouts_24h"] == partial + full + system
    assert summary["partial_timeouts_24h"] == partial + system
    assert slo["timeouts_24h"] == summary["timeouts_24h"]
    assert slo["stale_post_collection"] == stale
    budget = slo["error_budget"]
    assert budget["method"] == "scheduled_security_checks_model"
    assert budget["expected_security_checks"] == 144
    assert budget["allowed_errors"] == 1
    assert budget["consumed_errors"] == partial + full
    assert budget["remaining_errors"] == max(0, 1 - partial - full)
    assert budget["consumed_percent"] == 100 * (partial + full)
    assert budget["status"] == ("exhausted" if partial + full > 1 else "attention" if partial + full else "available")
    assert slo["status"] == ("attention" if partial + full + system + stale else "met")


def test_slo_without_security_observations_does_not_consume_other_channel_errors():
    now = datetime.now(timezone.utc)
    slo, _ = _slo_from_stats({("DC1", "System"): {"timeouts_24h": 8, "partial_timeouts_24h": 3}}, now)
    assert slo["status"] == "unknown"
    assert slo["error_budget"]["expected_security_checks"] == 0
    assert slo["error_budget"]["consumed_errors"] is None
    assert slo["error_budget"]["remaining_errors"] is None
    assert slo["error_budget"]["allowed_errors"] == 0
    assert slo["error_budget"]["status"] == "unknown"


@pytest.mark.parametrize("value", [None, -1, "bad", True, 1.5, float("nan"), float("inf"), "01", "-1", "1.5"])
def test_invalid_security_counter_has_unknown_budget(value):
    now = datetime.now(timezone.utc)
    items = [{"channel": "Security", "last_successful_collection_utc": now.isoformat(), "timeouts_24h": value}]
    budget = collector_health._operations_slo(items, {}, {})["error_budget"]
    assert budget["status"] == "unknown"
    assert budget["expected_security_checks"] > 0
    assert budget["allowed_errors"] >= 1
    for field in ("consumed_errors", "remaining_errors", "consumed_percent"):
        assert budget[field] is None


@pytest.mark.parametrize("value", [0, 1, "0", "1"])
def test_valid_security_counter_remains_known(value):
    items = [{"channel": "Security", "timeouts_24h": value}]
    budget = collector_health._operations_slo(items, {}, {})["error_budget"]
    assert budget["consumed_errors"] == int(value)
    assert budget["status"] != "unknown"


def test_missing_security_counter_is_not_zero():
    budget = collector_health._operations_slo([{"channel": "Security"}], {}, {})["error_budget"]
    assert budget["status"] == "unknown"
    assert budget["consumed_errors"] is None


@pytest.mark.parametrize("source", ["sql_zero", "sql_missing", "sql_invalid", "log_completed", "log_import_only", "log_missing", "log_undated"])
def test_health_preserves_counter_availability(monkeypatch, tmp_path, source):
    from server.sli.core import postgres_runtime_pipeline

    now = datetime.now(timezone.utc)
    state = {"server_hostname": "DC1", "channel": "Security", "last_successful_collection_utc": now.isoformat()}
    def query(sql, params=()):
        if "from collection_channel_state" in sql:
            return [state]
        if source == "sql_zero":
            return [{"server": "DC1", "channel": "Security", "timeouts_24h": 0, "partial_timeouts_24h": 0}]
        if source in {"sql_missing", "sql_invalid"}:
            return [{"server": "DC1", "channel": "Security", "timeouts_24h": None if source == "sql_missing" else "bad"}]
        return []
    monkeypatch.setattr(collector_health, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(collector_health, "query_rows", query)
    monkeypatch.setattr(collector_health, "log_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(collector_health, "get_post_collection_overview", lambda **kwargs: {"summary": {}, "items": []})
    monkeypatch.setattr(postgres_runtime_pipeline, "get_cursor_audit_overview_pg", lambda **kwargs: {"latest": []})
    monkeypatch.setattr(collector_health, "_safe_runtime_collection_history", lambda **kwargs: {})
    monkeypatch.setattr(collector_health, "_safe_storage_v2_outbox", lambda **kwargs: {})
    path = tmp_path / "collector.log"
    if source.startswith("log_") and source != "log_missing":
        message = "Security.jsonl: inserted=3, skipped=0" if source == "log_import_only" else "Completed channel: Security count=0"
        path.write_text(json.dumps({"server": "DC1", "message": message, "ts": None if source == "log_undated" else now.isoformat()}))
    health = collector_health.get_collector_health(log_path=path)
    known = source in {"sql_zero", "log_completed"}
    assert health["items"][0]["timeouts_24h"] == 0  # Existing display counter.
    assert health["items"][0]["timeouts_24h_available"] is known
    assert health["operations_slo"]["error_budget"]["status"] == ("available" if known else "unknown")
    assert health["operations_slo"]["error_budget"]["consumed_errors"] == (0 if known else None)


def test_known_database_zero_is_not_replaced_with_fallback_timeouts():
    primary = {"timeouts_24h": 0, "partial_timeouts_24h": 0, "timeouts_24h_available": True}
    fallback = {"timeouts_24h": 3, "partial_timeouts_24h": 2, "timeouts_24h_available": True}
    assert collector_health._merge_stats(primary, fallback) == primary


def test_missing_database_counter_uses_known_log_counter_as_one_source():
    primary = {"timeouts_24h": 0, "partial_timeouts_24h": 0, "timeouts_24h_available": False}
    fallback = {"timeouts_24h": 3, "partial_timeouts_24h": 2, "timeouts_24h_available": True}
    assert collector_health._merge_stats(primary, fallback) == fallback


def test_partial_security_telemetry_cannot_increase_budget():
    items = [{"channel": "Security", "timeouts_24h": 2}, {"channel": "Security", "timeouts_24h": 0, "timeouts_24h_available": False}]
    budget = collector_health._operations_slo(items, {}, {})["error_budget"]
    assert budget["status"] == "unknown"
    assert budget["consumed_errors"] is None
    assert budget["remaining_errors"] is None

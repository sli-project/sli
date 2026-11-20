from __future__ import annotations

from datetime import datetime, timezone

from server.sli.sources.collector_health import (
    _adaptive_action_label,
    _display_status,
    _event_observation_label,
    _event_observation_severity,
    _operations_slo,
    render_collector_health_report,
)


def test_quiet_non_security_channel_is_not_reported_as_stale_after_successful_poll() -> None:
    assert _event_observation_label(
        "Microsoft-Windows-PowerShell/Operational", "completed", 662, 7, False
    ) == "новых событий не обнаружено"
    assert _event_observation_severity(
        "Microsoft-Windows-PowerShell/Operational", "completed", 662, 7, False
    ) == "good"


def test_security_event_lag_remains_visible_after_successful_poll() -> None:
    assert _event_observation_label("Security", "completed", 90, 3, False) == "события отстают"
    assert _event_observation_severity("Security", "completed", 90, 3, False) == "high"


def test_collector_health_uses_human_status_for_security_recovery() -> None:
    assert _display_status("Security", "completed", 475, True) == "сбор завершён, данные ещё догоняются"
    assert _display_status("System", "stale", 240, False) == "данные устарели"


def test_collector_health_translates_adaptive_action_and_header_time() -> None:
    data = {
        "generated_at_utc": "2026-07-07T09:31:07.803468+00:00",
        "summary": {"channels_total": 1, "security_high": 1, "security_warn": 0, "timeouts_24h": 0, "partial_timeouts_24h": 0},
        "items": [
            {
                "server": "DC1",
                "channel": "Security",
                "last_status": "completed",
                "display_status": "сбор завершён, данные ещё догоняются",
                "severity": "high",
                "last_successful_collection_utc": "2026-07-07T09:13:51.7450727Z",
                "last_event_time_utc": "2026-07-07T01:35:21.2535660Z",
                "last_event_record_id": 3404147052,
                "lag_minutes": 475,
                "timeouts_24h": 0,
                "partial_timeouts_24h": 0,
                "last_partial_count": 0,
                "inserted_skipped_ratio": "43000/0",
                "warnings": ["Security lag > 2h"],
                "adaptive_limit": 5000,
                "adaptive_action": "keep:completed_streak; 5000->5000; recovery=on",
                "recovery_mode": True,
            }
        ],
    }

    html = render_collector_health_report(data)

    assert "07.07.2026 09:31:07 UTC" in html
    assert "2026-07-07T09:31:07.803468+00:00" not in html
    assert "сбор завершён, данные ещё догоняются" in html
    assert "лимит сохранен: серия успешных сборов; 5000 → 5000; восстановление включено" in html


def test_adaptive_action_label_handles_raw_technical_value() -> None:
    assert _adaptive_action_label("decrease_limit:skipped_gt_inserted_x2; 1000->500; recovery=on") == (
        "лимит уменьшен: много повторно прочитанных событий; 1000 → 500; восстановление включено"
    )


def test_operations_slo_separates_successful_collection_from_stale_security_data() -> None:
    slo = _operations_slo(
        [
            {"channel": "Security", "lag_minutes": 170, "last_successful_collection_utc": datetime.now(timezone.utc).isoformat()},
            {"channel": "Security", "lag_minutes": 11, "last_successful_collection_utc": "2020-01-01T00:00:00Z"},
        ],
        {"timeouts_24h": 0, "partial_timeouts_24h": 0, "stale_post_collection": 0},
        {"summary": {}},
    )

    assert slo["status"] == "breached"
    assert slo["freshness_current"] == 1
    assert slo["freshness_breached"] == 1
    assert slo["warning_minutes"] == 5
    assert slo["breach_minutes"] == 20


def test_collector_health_report_explains_the_slo_baseline_in_plain_language() -> None:
    html = render_collector_health_report(
        {
            "summary": {},
            "items": [],
            "post_collection": {},
            "operations_slo": {
                "status": "attention",
                "label": "Требует внимания",
                "security_channels": 2,
                "freshness_current": 1,
                "freshness_warning": 1,
                "freshness_breached": 0,
                "freshness_unknown": 0,
                "warning_minutes": 30,
                "breach_minutes": 120,
                "timeouts_24h": 0,
                "partial_timeouts_24h": 0,
                "stale_post_collection": 0,
            },
        }
    )

    assert "Работа сбора и свежесть данных" in html
    assert "Проверка каналов Security задерживается" in html
    assert "Security: актуальная проверка (до 30 мин.)" in html


def test_collector_health_report_shows_durable_worker_history() -> None:
    html = render_collector_health_report(
        {
            "summary": {}, "items": [], "post_collection": {}, "operations_slo": {},
            "runtime_history": {"status": "ok", "items": [{
                "status": "running", "phase": "collection", "worker_id": "collection-dc1",
                "started_at": "2026-07-16T00:00:00Z", "max_events_per_channel": 50000,
                "servers_json": ["DC1", "DC2"], "duration_ms": None,
            }]},
        }
    )

    assert "Независимый worker сбора" in html
    assert "50000" in html
    assert "История хранится в PostgreSQL" in html


def test_collector_health_report_shows_v2_outbox_without_calling_it_a_dc_failure() -> None:
    html = render_collector_health_report(
        {
            "summary": {}, "items": [], "post_collection": {}, "operations_slo": {},
            "storage_v2_outbox": {"status": "ok", "events": 43_000, "batches": 86, "states": {"leased": {"events": 500}}},
        }
    )

    assert "Очередь архивирования V2" in html
    assert "не блокирует успешный сбор" in html
    assert "43,000" in html


def test_report_time_parser_accepts_postgres_datetime_values() -> None:
    from server.sli.reports.analysis import _duration_hint

    first = datetime(2026, 7, 17, 10, 0, tzinfo=timezone.utc)
    last = datetime(2026, 7, 17, 11, 5, tzinfo=timezone.utc)

    assert _duration_hint({"first_event": first, "last_event": last}) == "1ч 5м"

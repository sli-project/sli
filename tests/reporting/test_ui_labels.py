from server.sli.reporting.ui_labels import (
    channel_label,
    entity_role_label,
    entity_type_label,
    event_id_label,
    field_label,
    severity_label,
    status_label,
    translate_warning,
)
from server.sli.sources.collector_health import render_collector_health_report


def test_core_labels_are_russian_by_default():
    assert status_label("completed") == "завершено"
    assert status_label("partial_timeout") == "частичный сбор по таймауту"
    assert severity_label("high") == "высокий"
    assert entity_role_label("actor") == "кто выполнил действие"
    assert entity_type_label("user") == "учетная запись"
    assert channel_label("Security", with_original=True) == "Безопасность (Security)"
    assert field_label("subject") == "Инициатор"
    assert event_id_label(4740) == "Event ID 4740: Учетная запись заблокирована"
    assert event_id_label(4740, lang="en", prefix=False) == "Account locked out"
    assert translate_warning("possible repeated backlog read") == "возможно повторное чтение backlog"


def test_collector_health_report_uses_human_readable_labels():
    html = render_collector_health_report({
        "generated_at_utc": "2026-07-07T10:00:00+00:00",
        "summary": {"channels_total": 1, "security_high": 1, "security_warn": 0, "timeouts_24h": 1, "partial_timeouts_24h": 1},
        "items": [{
            "server": "DC1",
            "channel": "Security",
            "last_status": "partial_timeout",
            "severity": "high",
            "last_successful_collection_utc": "2026-07-07T09:00:00+00:00",
            "last_event_time_utc": "2026-07-07T08:00:00+00:00",
            "last_event_record_id": 123,
            "lag_minutes": 120,
            "timeouts_24h": 1,
            "partial_timeouts_24h": 1,
            "last_partial_count": 50,
            "inserted_skipped_ratio": "50/10",
            "warnings": ["channel timeout", "Security lag > 30m"],
            "adaptive_limit": 300,
            "adaptive_action": "partial_timeout",
            "recovery_mode": True,
        }],
    })
    assert "Безопасность (Security)" in html
    assert "частичный сбор по таймауту" in html
    assert "высокий" in html
    assert "таймаут канала" in html
    assert "Отставание" in html

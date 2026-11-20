from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from scripts.maintenance.bundle_common import assess_recent_internal_errors
from server.sli.ops import diagnostics_report


NOW = datetime(2026, 7, 17, 2, 0, tzinfo=timezone.utc)


def _line(ts: datetime, **fields: object) -> str:
    return json.dumps({"ts": ts.isoformat(), **fields})


def test_old_internal_error_does_not_raise_warning() -> None:
    result = assess_recent_internal_errors(
        _line(NOW - timedelta(minutes=31), level="ERROR"),
        now=NOW,
    )
    assert result["active"] is False
    assert result["active_count"] == 0


def test_fresh_internal_error_fails_closed() -> None:
    result = assess_recent_internal_errors(
        _line(NOW - timedelta(minutes=2), level="ERROR"),
        now=NOW,
    )
    assert result["active"] is True
    assert result["active_count"] == 1


def test_fresh_self_healing_warning_is_not_reported_as_active_error() -> None:
    result = assess_recent_internal_errors(
        _line(NOW - timedelta(minutes=2), level="WARNING", event="log_rotation_skipped"),
        now=NOW,
    )
    assert result["active"] is False
    assert result["ignored_non_error_count"] == 1


def test_malformed_internal_error_fails_closed() -> None:
    result = assess_recent_internal_errors("not-json", now=NOW)
    assert result["active"] is True
    assert result["malformed_count"] == 1


def test_later_successful_collection_recovers_same_scope() -> None:
    error = _line(
        NOW - timedelta(minutes=10),
        level="ERROR",
        component="pycollector",
        event="channel_failed",
        server="DC1",
        channel="Security",
    )
    recovery = _line(
        NOW - timedelta(minutes=5),
        level="INFO",
        component="performance",
        event="stage_completed",
        stage="evt_next_read",
        status="completed",
        server="DC1",
        channel="Security",
    )
    result = assess_recent_internal_errors(error, activity_text=recovery, now=NOW)
    assert result["active"] is False
    assert result["recovered_count"] == 1


def test_success_from_other_server_does_not_hide_fresh_error() -> None:
    error = _line(NOW - timedelta(minutes=10), level="ERROR", server="DC1")
    recovery = _line(
        NOW - timedelta(minutes=5),
        event="import_completed",
        status="completed",
        server="DC2",
    )
    result = assess_recent_internal_errors(error, activity_text=recovery, now=NOW)
    assert result["active"] is True


def test_diagnostics_overview_ignores_old_jsonl_tail(tmp_path, monkeypatch) -> None:
    (tmp_path / "internal-errors.log").write_text(
        _line(datetime.now(timezone.utc) - timedelta(hours=1), level="ERROR") + "\n",
        encoding="utf-8",
    )
    (tmp_path / "adlog-monitor.log").write_text("", encoding="utf-8")
    monkeypatch.setattr(diagnostics_report, "LOG_DIR", tmp_path)

    result = diagnostics_report.get_diagnostics_overview(run_checks=False)

    assert result["status"] == "ok"
    assert result["warnings"] == []
    assert result["internal_errors"]["active"] is False

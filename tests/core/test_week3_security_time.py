from __future__ import annotations

import subprocess
from datetime import datetime, timezone
from types import SimpleNamespace


def test_collector_history_stores_cursor_strategy_and_mode(monkeypatch) -> None:
    from server.sli.sources import collector_adaptive
    from server.sli.core import postgres_runtime_pipeline

    executed: list[tuple[str, tuple]] = []

    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def execute(self, sql, params=()):
            executed.append((" ".join(sql.split()).lower(), params))

        def fetchone(self):
            return None

    class Conn:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def cursor(self):
            return Cursor()

    monkeypatch.setattr(postgres_runtime_pipeline, "connect", lambda: Conn())
    monkeypatch.setattr(postgres_runtime_pipeline, "log_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(collector_adaptive, "log_event", lambda *args, **kwargs: None)

    postgres_runtime_pipeline.record_collector_channel_runs_pg(
        server="DC1",
        summary={
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "collection_mode": "per_channel_record_id",
            "requested_collection_mode": "recovery",
            "channels": [{
                "channel": "Security",
                "status": "completed",
                "count": 0,
                "max_events": 500,
                "timeout_seconds": 900,
                "started_at": datetime.now(timezone.utc).isoformat(),
                "cursor_strategy": "time_window_fallback",
                "cursor_fallback_reason": "latest_record_id_before_saved_cursor",
            }],
        },
        import_stats={"Security": {"inserted": 0, "skipped": 0}},
        job_id=11,
    )

    runs = [params for sql, params in executed if "insert into collector_channel_runs" in sql]
    assert len(runs) == 1
    assert runs[0][1:3] == ("DC1", "Security")
    assert runs[0][25:29] == (
        "per_channel_record_id",
        "recovery",
        "time_window_fallback",
        "latest_record_id_before_saved_cursor",
    )


def test_runner_uses_recovery_mode_and_skips_message_by_default(monkeypatch) -> None:
    import server.jobs.collector as collector

    captured: dict[str, list[str]] = {}

    monkeypatch.setattr(collector, "resolve_domain_controller_connect_address", lambda server: server)
    monkeypatch.setattr(
        collector,
        "get_adaptive_plan_for_server",
        lambda server: SimpleNamespace(
            channels=["Security"],
            channel_limits={"Security": 500},
            channel_timeouts={"Security": 900},
            recovery_mode=True,
            reason="security_lag>60m",
        ),
    )
    monkeypatch.delenv("ADLOG_COLLECT_MESSAGE", raising=False)
    monkeypatch.delenv("ADLOG_COLLECTION_MODE", raising=False)

    def fake_run(command, timeout_seconds, *, server, job_id, env=None):
        captured["command"] = command
        return subprocess.CompletedProcess(command, 0, "ok", "")

    monkeypatch.setattr(collector, "_run_subprocess_live", fake_run)

    collector._run_single_server_collection("DC1", 1, 500, job_id=123)

    command = captured["command"]
    assert command[command.index("--collection-mode") + 1] == "recovery"
    assert command[command.index("--collect-message") + 1] == "false"
    assert command[command.index("--channels") + 1] == "Security"


def test_time_format_supports_local_context_and_offsets() -> None:
    from server.sli.core.time_format import format_event_time, format_event_time_with_context, format_report_time

    assert format_event_time("2026-07-07T02:34:28.9127653+03:00") == "06.07.2026 23:34:28 UTC"
    assert format_report_time("2026-07-07T02:34:28.9127653Z", timezone_name="Europe/Moscow") == "07.07.2026 05:34:28 Europe/Moscow"
    context = format_event_time_with_context("2026-07-07T02:34:28Z", timezone_name="Europe/Moscow", mode="local")
    assert context["display"] == "07.07.2026 05:34:28 Europe/Moscow"
    assert context["tooltip"] == "2026-07-07T02:34:28Z"


def test_snapshot_lint_flags_visible_iso_but_allows_tooltip_context() -> None:
    from scripts.maintenance.export_report_snapshots import _warnings_for_text

    tooltip_only = '<td title="2026-07-07T02:34:28Z">07.07.2026 02:34:28 UTC</td>'
    visible = '<td>2026-07-07T02:34:28Z</td>'

    assert "найден сырой ISO timestamp" not in _warnings_for_text(tooltip_only, 200, len(tooltip_only))
    assert "найден сырой ISO timestamp" in _warnings_for_text(visible, 200, len(visible))

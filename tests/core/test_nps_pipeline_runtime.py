"""NPS pipeline must preserve DC defaults and never claim truncated coverage."""
import sys
import os
import re
from pathlib import Path

import pytest

from server.sli.core import postgres_runtime_pipeline as pipeline
from tests.migrations.test_storage_v2_fresh_bootstrap import disposable_pg  # Reuse owned UUID-DB fixture.


@pytest.mark.parametrize("status,continuity,want", [
    ("completed", {"query_exhausted": True, "generation_stable_during_read": True, "truncated": False}, True),
    ("completed", {"query_exhausted": False, "generation_stable_during_read": True, "truncated": True}, False),
    ("completed", {"query_exhausted": True, "generation_stable_during_read": False, "truncated": False}, False),
    ("completed", {}, False),
    ("partial_timeout", {"query_exhausted": True, "generation_stable_during_read": True, "truncated": False}, False),
])
def test_filtered_backfill_requires_exhausted_stable_query(status, continuity, want):
    check = getattr(pipeline, "_channel_backfill_completed", None)
    assert callable(check), "filtered backfill completeness gate missing"
    assert check({"status": status, "continuity": continuity}, require_query_exhaustion=True) is want


def test_dc_backfill_default_is_unchanged():
    check = getattr(pipeline, "_channel_backfill_completed", None)
    assert callable(check), "filtered backfill completeness gate missing"
    assert check({"status": "completed"}, require_query_exhaustion=False) is True


def test_nps_pilot_has_distinct_admission_without_dc_endpoint_lookup(monkeypatch):
    import scripts.run_dc_log_pilot as pilot
    import server.sli.sources.ad_source_auth as ad_auth

    class Admitted(Exception):
        pass

    monkeypatch.setattr(ad_auth, "resolve_ad_source_endpoint", lambda *a, **kw: pytest.fail("NPS used DC endpoint boundary"))
    monkeypatch.setattr(pilot, "choose_collector_backend", lambda backend: (_ for _ in ()).throw(Admitted()))
    monkeypatch.setattr(sys, "argv", ["pilot", "--nps-continuous", "--server", "radius01.example.test",
        "--connect-address", "radius01.example.test", "--channels", "Security", "--collector-backend", "python",
        "--ad-source-credential-mode", "dpapi_current_user", "--event-ids-json", "[6272,6273]",
        "--start-time-utc", "2026-09-10T14:00:00Z", "--end-time-utc", "2026-09-10T15:00:00Z",
        "--archive", "--use-record-id-cursor", "true", "--adaptive-state-mode", "observe",
        "--collect-message", "false", "--max-events-per-channel", "50000",
        "--channel-timeout-seconds", "60", "--command-timeout-seconds", "90"])
    with pytest.raises(Admitted):
        pilot.main()


def test_nps_archive_record_without_generation_uses_canonical_time_plan(monkeypatch):
    """Never send an invalid cursor-only pair or manufacture a generation."""
    import scripts.run_dc_log_pilot as pilot
    import server.sli.core.postgres_runtime_pipeline as runtime_pipeline
    import server.source_packs.nps_eventlog_runtime as nps_runtime

    class CommandBuilt(Exception):
        pass

    captured = {}
    monkeypatch.setattr(nps_runtime, "resolve_nps_eventlog_endpoint", lambda *a, **k: "radius01.example.test")
    monkeypatch.setattr(pilot, "choose_collector_backend", lambda _backend: ("python", "test"))
    monkeypatch.setattr(pilot, "runtime_db_backend", lambda: "postgres")
    monkeypatch.setattr(pilot, "resolve_postgres_source_identity", lambda **_: ("example.test", "example.test"))
    monkeypatch.setattr(pilot, "validate_adapter_for_channels", lambda *_: [])
    monkeypatch.setattr(runtime_pipeline, "get_collection_plan_for_server_pg", lambda *_args, **_kwargs: {
        "Security": {
            "start_time_utc": "2026-08-01T00:00:00Z",
            "after_record_id": 5603344,
            "channel_generation_identity": None,
        },
    })
    def capture_command(request):
        captured["request"] = request
        raise CommandBuilt()
    monkeypatch.setattr(
        pilot, "build_windows_eventlog_command",
        capture_command,
    )
    monkeypatch.setattr(sys, "argv", [
        "pilot", "--nps-continuous", "--server", "radius01.example.test",
        "--connect-address", "radius01.example.test", "--channels", "Security",
        "--collector-backend", "python", "--ad-source-credential-mode", "dpapi_current_user",
        "--event-ids-json", "[6272,6273]", "--start-time-utc", "2026-08-01T00:00:00Z",
        "--end-time-utc", "2026-09-10T15:00:00Z", "--archive", "--use-record-id-cursor", "true",
        "--adaptive-state-mode", "observe", "--collect-message", "false",
        "--max-events-per-channel", "50000", "--channel-timeout-seconds", "60",
        "--command-timeout-seconds", "90",
    ])

    with pytest.raises(CommandBuilt):
        pilot.main()

    request = captured["request"]
    assert request.channel_after_record_ids == {}
    assert request.channel_cursor_generations == {}
    assert request.channel_start_times == {"Security": "2026-08-01T00:00:00Z"}
    assert request.start_time_utc == "2026-08-01T00:00:00Z"


def test_filtered_cursor_sql_branches_on_disposable_postgres(disposable_pg, monkeypatch):
    """Catch SQL parameter/order mistakes in normal, empty, reset and rollback branches."""
    import psycopg
    from psycopg.rows import dict_row
    conn = disposable_pg
    schema = Path("config/postgres_schema_v8.sql").read_text(encoding="utf-8")
    for table in ("collection_channel_state", "collector_cursor_audit"):
        statement = re.search(r"create table if not exists " + table + r" \(.*?\n\);", schema, re.S)
        assert statement
        conn.execute(statement.group(0))
    conn.execute("ALTER TABLE collection_channel_state ADD COLUMN channel_generation_identity text")
    conn.commit()
    monkeypatch.setattr(pipeline, "connect", lambda: psycopg.connect(
        os.environ["SLI_TEST_ADMIN_DSN"], dbname=conn.info.dbname,
        row_factory=dict_row, connect_timeout=5, options="-c statement_timeout=5000 -c lock_timeout=2000"))
    stamp = "2026-09-10T14:00:00+00:00"
    monkeypatch.setattr(pipeline, "_ensure_archive_start_pg", lambda: stamp)
    for case, old, candidate, want in [("new", None, 10, 10), ("empty", None, None, None),
                                      ("reset", 20, 8, 8), ("rollback", 20, 8, 20),
                                      ("complete_to_truncated", 10, 20, 20)]:
        conn.execute("DELETE FROM collector_cursor_audit")
        conn.execute("DELETE FROM collection_channel_state")
        if old is not None:
            conn.execute("INSERT INTO collection_channel_state(server_hostname,channel,archive_start_utc,last_event_record_id,channel_generation_identity) VALUES ('nps.test.invalid','Security',%s,%s,'generation-a')", (stamp, old))
            if case == "complete_to_truncated":
                conn.execute("UPDATE collection_channel_state SET backfill_completed=true")
        conn.commit()
        item = {"channel": "Security", "status": "completed", "count": int(candidate is not None),
                "batch_max_record_id": candidate, "start_time_utc": stamp,
                "channel_generation_identity": "generation-b" if case == "reset" else "generation-a",
                "continuity": {"query_exhausted": False, "generation_stable_during_read": True, "truncated": True}}
        if case == "reset":
            item.update(cursor_strategy="time_window_fallback", cursor_fallback_reason="channel_generation_changed",
                        channel_latest_record_id_before_read=8)
        monkeypatch.setattr(pipeline, "_latest_event_for_channel_pg", lambda *a, value=candidate: (
            {"event_record_id": value, "time_created_utc": stamp} if value is not None else {}))
        pipeline.update_collection_state_from_summary_pg(
            server="nps.test.invalid", collection_start_utc=stamp,
            summary={"finished_at": stamp, "channels": [item]},
            import_stats={"Security": {"inserted": int(candidate is not None), "skipped": 0}},
            trace_id="isolated-" + case, require_query_exhaustion=True,
        )
        row = conn.execute("SELECT last_event_record_id,backfill_completed FROM collection_channel_state").fetchone()
        assert row["last_event_record_id"] == want, case
        assert row["backfill_completed"] is False, case
        assert conn.execute("SELECT count(*) AS n FROM collector_cursor_audit").fetchone()["n"] == 1
        conn.commit()

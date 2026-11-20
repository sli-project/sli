from __future__ import annotations

from scripts.run_dc_log_pilot import summarize_channel_status


def test_partial_timeout_counts_as_collected_warning_not_failed() -> None:
    status = summarize_channel_status(
        {
            "channels": [
                {"channel": "Security", "status": "partial_timeout", "count": 10, "error": "timeout with partial data"},
                {"channel": "System", "status": "completed", "count": 2, "error": None},
            ]
        }
    )

    assert status["channels_completed"] == 1
    assert status["channels_partial"] == 1
    assert status["channels_failed"] == 0
    assert status["channels_timeout"] == 1
    assert status["events_collected"] == 12
    assert status["all_failed"] is False
    assert status["partial_failed"] is False
    assert status["partial_warning"] is True


def test_partial_timeout_advances_archive_watermark(monkeypatch) -> None:
    """PostgreSQL path: a partial_timeout with imported events moves the cursor forward.

    Successful-collection time stays unset and backfill stays incomplete.
    """
    from server.sli.core import postgres_runtime_pipeline as module

    class Cursor:
        def __init__(self) -> None:
            self.executed: list[tuple[str, tuple]] = []
            self.last = ""
            self.state_reads = 0

        def execute(self, sql, params=()):
            self.last = " ".join(sql.split()).lower()
            self.executed.append((self.last, params))

        def fetchone(self):
            if "from collection_channel_state" in self.last:
                self.state_reads += 1
                record = 100 if self.state_reads == 1 else 200
                return {"last_event_record_id": record, "last_event_time_utc": "2026-07-07T04:05:00+00:00"}
            if "from events_v2_core e" in self.last:
                return {"event_record_id": 200, "time_created_utc": "2026-07-07T04:05:00+00:00"}
            return None

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    cursor = Cursor()

    class Conn:
        def cursor(self):
            return cursor

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    monkeypatch.setattr(module, "connect", lambda: Conn())
    monkeypatch.setattr(module, "_ensure_archive_start_pg", lambda: "2026-07-01T00:00:00+00:00")
    monkeypatch.setattr(module, "log_event", lambda *args, **kwargs: None)

    module.update_collection_state_from_summary_pg(
        server="DC1",
        collection_start_utc="2026-07-07T04:00:00+00:00",
        summary={
            "finished_at": "2026-07-07T04:06:00+00:00",
            "channels": [
                {
                    "channel": "Security",
                    "status": "partial_timeout",
                    "count": 1,
                    "batch_max_record_id": 200,
                    "start_time_utc": "2026-07-07T04:00:00+00:00",
                    "error": "Channel timed out after 120 seconds; 1 partial events were saved.",
                }
            ],
        },
        import_stats={"Security": {"inserted": 1, "skipped": 0}},
    )

    upserts = [params for sql, params in cursor.executed if "insert into collection_channel_state" in sql]
    assert len(upserts) == 1
    params = upserts[0]
    assert params[4] is None  # last_successful_collection_utc
    assert params[5] == "2026-07-07T04:05:00+00:00"  # last_event_time_utc
    assert params[6] == 200  # last_event_record_id
    assert params[7] is False  # backfill_completed
    audit = next(params for sql, params in cursor.executed if "insert into collector_cursor_audit" in sql)
    assert audit[13] == "committed"
    assert str(audit[14]).startswith("partial_import_committed")

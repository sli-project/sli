from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path


def test_migration_033_is_append_only_local_and_fail_closed() -> None:
    forward = Path("config/postgres_migrations/033_semantic_calibration_reviews.sql").read_text(encoding="utf-8").lower()
    rollback = Path("config/postgres_migrations/033_semantic_calibration_reviews.rollback.sql").read_text(encoding="utf-8").lower()
    assert "version=32 and name='runtime_worker_heartbeats'" in forward
    assert "pg_has_role(session_user, 'adlog_storage_owner', 'member')" in forward
    assert "set local role adlog_storage_owner" in forward
    assert "semantic_scenario_reviews" in forward
    assert "review_request_id uuid not null unique" in forward
    assert "scenario_snapshot_sha256" in forward
    assert "before update or delete" in forward
    assert "grant select,insert" in forward
    assert "values (33,'semantic_calibration_reviews')" in forward
    assert "rollback 033 refused" in rollback
    assert "pg_has_role(session_user, 'adlog_storage_owner', 'member')" in rollback
    assert "set local role adlog_storage_owner" in rollback
    for forbidden in ("insert into events_v2_core", "insert into findings", "update findings", "delete from findings", "collection_channel_state", "update runtime_worker_heartbeats"):
        assert forbidden not in forward


def test_review_summary_is_honest_until_decisive_sample_exists() -> None:
    from server.sli.semantic.semantic_reviews import summarize_review_labels

    empty = summarize_review_labels([], schema_ready=True)
    assert empty["state"] == "not_measurable"
    assert empty["rate_percent"] is None

    small = summarize_review_labels([
        {"verdict": "confirmed_security", "item_count": 7},
        {"verdict": "false_positive", "item_count": 2},
        {"verdict": "benign_expected", "item_count": 3},
    ], schema_ready=True)
    assert small["state"] == "insufficient_sample"
    assert small["decisive_labels"] == 9
    assert small["reviewed_scenarios"] == 12
    assert small["rate_percent"] == 22.22

    measured = summarize_review_labels([
        {"verdict": "confirmed_security", "item_count": 8},
        {"verdict": "false_positive", "item_count": 2},
    ], schema_ready=True)
    assert measured["state"] == "measured"
    assert measured["rate_percent"] == 20.0


def test_control_health_uses_local_collection_age_not_event_age() -> None:
    from server.sli.semantic.semantic_control_health import _as_utc_datetime, classify_collection_coverage

    now = datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc)
    assert classify_collection_coverage(now - timedelta(minutes=5), observed_at_utc=now) == (
        "complete", "successful_collection_inside_attention_budget", 5,
    )
    assert classify_collection_coverage(now - timedelta(minutes=45), observed_at_utc=now)[0] == "partial"
    assert classify_collection_coverage(now - timedelta(minutes=180), observed_at_utc=now)[0] == "unavailable"
    assert classify_collection_coverage(None, observed_at_utc=now)[0] == "unavailable"
    assert _as_utc_datetime("2026-07-19T12:00:00Z") == now


def test_control_health_records_assessment_time_separately_from_collection_time() -> None:
    from server.sli.semantic.semantic_control_health import (
        record_current_security_control_health,
    )

    collected_at = datetime(2026, 7, 19, 10, 0, tzinfo=timezone.utc)
    assessed_at = datetime(2026, 7, 19, 12, 0, 0, 123456, tzinfo=timezone.utc)

    class Cursor:
        rowcount = 0

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, _sql, _params):
            return None

        def fetchall(self):
            return [
                {
                    "server_hostname": "DC1",
                    "channel": "Security",
                    "last_successful_collection_utc": collected_at,
                    "last_event_time_utc": collected_at,
                    "last_event_record_id": 1,
                    "backfill_completed": True,
                }
            ]

    class Connection:
        def cursor(self):
            return Cursor()

        def rollback(self):
            return None

    result = record_current_security_control_health(
        execute=False,
        connection=Connection(),
        observed_at_utc=assessed_at,
    )
    item = result["items"][0]
    assert item["observed_at_utc"] == assessed_at.replace(microsecond=0)
    assert collected_at.isoformat() in item["source_reference"]


def test_review_api_and_ui_keep_scenario_assessment_immutable() -> None:
    api = Path("server/api/routes/semantic.py").read_text(encoding="utf-8")
    repository = Path("server/sli/semantic/semantic_reviews.py").read_text(encoding="utf-8")
    # UI text lives in the page or, after localization, in the Russian dictionary.
    frontend = Path("frontend/src/app/scenarios.tsx").read_text(encoding="utf-8") + Path(
        "frontend/src/i18n/ru.ts"
    ).read_text(encoding="utf-8")
    assert 'path.startswith("/api/v1/semantic/scenarios/") and path.endswith("/review")' in api
    assert '_authorize_mutation(required_role="viewer")' in api
    assert "insert into semantic_scenario_reviews" in repository.lower()
    assert "update semantic_security_scenarios" not in repository.lower()
    assert "append-only" in frontend
    assert "scenario_snapshot_sha256" in repository

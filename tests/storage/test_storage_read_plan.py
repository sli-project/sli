from datetime import datetime, timedelta, timezone

import pytest

from server.sli.storage.storage_policy import StoragePolicy, plan_storage_read


NOW = datetime(2026, 7, 28, 12, 0, tzinfo=timezone.utc)


def test_90_day_session_analytics_is_split_between_hot_and_warm() -> None:
    plan = plan_storage_read(
        query_kind="session_analytics",
        time_from_utc=NOW - timedelta(days=90),
        time_to_utc=NOW,
        now_utc=NOW,
        policy=StoragePolicy(db_retention_days=7, warm_retention_days=365),
        warm_read_enabled=True,
        warm_available=True,
    )

    assert plan.complete is True
    assert plan.blockers == ()
    assert [
        (segment.tier, segment.representation, segment.time_from_utc, segment.time_to_utc)
        for segment in plan.segments
    ] == [
        (
            "clickhouse_warm",
            "session",
            NOW - timedelta(days=90),
            NOW - timedelta(days=7),
        ),
        (
            "postgres_hot",
            "atomic_event",
            NOW - timedelta(days=7),
            NOW,
        ),
    ]


def test_warm_read_is_disabled_by_default_and_fails_closed() -> None:
    plan = plan_storage_read(
        query_kind="session_analytics",
        time_from_utc=NOW - timedelta(days=30),
        time_to_utc=NOW,
        now_utc=NOW,
        warm_available=True,
    )

    assert plan.complete is False
    assert plan.blockers == ("warm_read_disabled",)
    assert plan.segments[0].tier == "clickhouse_warm"
    assert plan.segments[0].ready is False


def test_atomic_evidence_never_uses_session_only_warm_tier() -> None:
    plan = plan_storage_read(
        query_kind="atomic_evidence",
        time_from_utc=NOW - timedelta(days=90),
        time_to_utc=NOW,
        now_utc=NOW,
        warm_read_enabled=True,
        warm_available=True,
        archive_available=True,
    )

    assert plan.complete is True
    assert [segment.tier for segment in plan.segments] == [
        "canonical_archive",
        "postgres_hot",
    ]
    assert plan.segments[0].representation == "full_payload"
    assert plan.segments[0].time_to_utc == NOW - timedelta(days=7)


def test_no_archive_descriptor_reports_derived_only_without_raw_link() -> None:
    plan = plan_storage_read(
        query_kind="atomic_evidence",
        time_from_utc=NOW - timedelta(days=30),
        time_to_utc=NOW,
        now_utc=NOW,
        warm_read_enabled=True,
        warm_available=True,
        descriptor_source="sli.windows.ad-dc",
        descriptor_stream="Security",
        descriptor_event_key="4624",
    )

    assert plan.complete is False
    assert plan.segments[0].availability == "derived_only_available"
    assert plan.segments[0].source_link is None
    assert plan.blockers == ("atomic_evidence_unavailable_derived_only",)


def test_session_analytics_older_than_365_days_requires_archive() -> None:
    plan = plan_storage_read(
        query_kind="session_analytics",
        time_from_utc=NOW - timedelta(days=400),
        time_to_utc=NOW,
        now_utc=NOW,
        warm_read_enabled=True,
        warm_available=True,
        archive_available=False,
    )

    assert plan.complete is False
    assert plan.blockers == ("canonical_archive_unavailable",)
    assert [segment.tier for segment in plan.segments] == [
        "canonical_archive",
        "clickhouse_warm",
        "postgres_hot",
    ]
    assert plan.segments[0].time_to_utc == NOW - timedelta(days=365)
    assert plan.segments[1].time_to_utc == NOW - timedelta(days=7)


def test_read_plan_rejects_ambiguous_time_and_invalid_windows() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        plan_storage_read(
            query_kind="atomic_evidence",
            time_from_utc=datetime(2026, 7, 1),
            time_to_utc=NOW,
            now_utc=NOW,
        )

    with pytest.raises(ValueError, match="greater than"):
        plan_storage_read(
            query_kind="atomic_evidence",
            time_from_utc=NOW - timedelta(days=30),
            time_to_utc=NOW,
            now_utc=NOW,
            policy=StoragePolicy(db_retention_days=7, warm_retention_days=7),
        )

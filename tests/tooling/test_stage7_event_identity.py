from datetime import datetime, timezone

import pytest

from scripts.maintenance.stage7_event_identity import (
    event_uid,
    initial_log_epoch_uid,
    initial_source_instance_uid,
    stream_uid,
)


def _identity() -> dict[str, str]:
    source = initial_source_instance_uid(
        domain_sid="S-1-5-21-1-2-3",
        server_fqdn="dc.example.test",
    )
    stream = stream_uid(source_instance_uid=source, stream_key="Security")
    epoch = initial_log_epoch_uid(
        stream_uid_value=stream,
        first_event_record_id=1,
        first_event_time_utc="2026-07-27T00:00:00Z",
    )
    return {"source": source, "stream": stream, "epoch": epoch}


def test_replay_produces_the_same_portable_event_uid() -> None:
    identity = _identity()
    arguments = {
        "source_instance_uid": identity["source"],
        "stream_uid_value": identity["stream"],
        "log_epoch_uid": identity["epoch"],
        "event_record_id": 42,
        "event_time_utc": "2026-07-27T01:02:03Z",
        "normalized_sha256": "ab" * 32,
    }

    assert event_uid(**arguments) == event_uid(
        **{**arguments, "event_time_utc": "2026-07-27T08:02:03+07:00"}
    )


def test_new_log_epoch_changes_uid_even_when_record_number_is_reused() -> None:
    identity = _identity()
    next_epoch = initial_log_epoch_uid(
        stream_uid_value=identity["stream"],
        first_event_record_id=1,
        first_event_time_utc="2026-07-28T00:00:00Z",
    )
    common = {
        "source_instance_uid": identity["source"],
        "stream_uid_value": identity["stream"],
        "event_record_id": 42,
        "event_time_utc": "2026-07-28T01:02:03Z",
        "normalized_sha256": "cd" * 32,
    }

    assert event_uid(log_epoch_uid=identity["epoch"], **common) != event_uid(
        log_epoch_uid=next_epoch,
        **common,
    )


def test_event_uid_is_deterministic_for_identical_identity_inputs() -> None:
    identity = _identity()

    # Pure helper coverage only: no source UUID is persisted or retrieved here.
    # This does not establish source identity persistence across display rename.
    first = event_uid(
        source_instance_uid=identity["source"],
        stream_uid_value=identity["stream"],
        log_epoch_uid=identity["epoch"],
        event_record_id=7,
        event_time_utc="2026-07-27T03:00:00Z",
        normalized_sha256="ef" * 32,
    )
    repeated = event_uid(
        source_instance_uid=identity["source"],
        stream_uid_value=identity["stream"],
        log_epoch_uid=identity["epoch"],
        event_record_id=7,
        event_time_utc="2026-07-27T03:00:00Z",
        normalized_sha256="ef" * 32,
    )

    assert first == repeated


def test_legacy_domain_fqdn_can_seed_once_when_sid_is_not_collected() -> None:
    value = initial_source_instance_uid(
        domain_fqdn="example.test",
        server_fqdn="dc.example.test",
    )

    assert value == initial_source_instance_uid(
        domain_fqdn="EXAMPLE.TEST",
        server_fqdn="DC.EXAMPLE.TEST",
    )


@pytest.mark.parametrize(
    ("raw_time", "postgres_time"),
    [
        (
            "2026-07-25T17:18:43.5167198Z",
            datetime(2026, 7, 25, 17, 18, 43, 516720, tzinfo=timezone.utc),
        ),
        (
            "2026-07-25T17:18:43.4385953Z",
            datetime(2026, 7, 25, 17, 18, 43, 438595, tzinfo=timezone.utc),
        ),
        (
            "2026-07-25T17:18:46.9251665Z",
            datetime(2026, 7, 25, 17, 18, 46, 925166, tzinfo=timezone.utc),
        ),
        (
            "2026-07-25T17:18:46.9251675Z",
            datetime(2026, 7, 25, 17, 18, 46, 925168, tzinfo=timezone.utc),
        ),
        (
            "2026-07-26T00:18:43.5167198+07:00",
            datetime(2026, 7, 25, 17, 18, 43, 516720, tzinfo=timezone.utc),
        ),
        (
            "2026-07-25T23:59:59.9999995Z",
            datetime(2026, 7, 26, 0, 0, 0, tzinfo=timezone.utc),
        ),
    ],
    ids=[
        "round-up",
        "round-down",
        "half-even-down",
        "half-even-up",
        "offset",
        "day-rollover",
    ],
)
def test_windows_timestamp_rounds_like_postgresql(
    raw_time: str,
    postgres_time: datetime,
) -> None:
    identity = _identity()
    common = {
        "source_instance_uid": identity["source"],
        "stream_uid_value": identity["stream"],
        "log_epoch_uid": identity["epoch"],
        "event_record_id": 42,
        "normalized_sha256": "ab" * 32,
    }

    assert event_uid(event_time_utc=raw_time, **common) == event_uid(
        event_time_utc=postgres_time,
        **common,
    )

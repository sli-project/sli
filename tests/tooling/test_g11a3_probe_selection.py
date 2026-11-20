from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from scripts.maintenance.stage9_g11a3_probe_orchestrator import (
    AccountingObservation,
    NpsObservation,
    ProbeStopError,
)
from scripts.maintenance.stage9_g11a3_probe_selection import (
    select_accounting_lifecycle,
    select_nps_match,
)


UTC = timezone.utc
BASE_TIME = datetime(2026, 8, 11, 12, 0, tzinfo=UTC)


def _accounting(
    packet_type: str,
    *,
    session: str = "fixture-session-a",
    nas: str = "fixture-nas-a",
    observed_at: datetime = BASE_TIME,
    class_attribute: str = "fixture-class-a",
    digest_character: str = "a",
) -> AccountingObservation:
    return AccountingObservation(
        packet_type=packet_type,
        observed_at_utc=observed_at,
        class_attribute=class_attribute,
        account_session_id=session,
        nas_identity=nas,
        canonical_record_sha256=digest_character * 64,
        principal_observation=(
            "example.test/Users/fixture-user"
            if packet_type == "access_accept"
            else ""
        ),
    )


def _lifecycle(
    *,
    session: str = "fixture-session-a",
    nas: str = "fixture-nas-a",
    class_attribute: str = "fixture-class-a",
    digest_characters: tuple[str, str, str] = ("a", "b", "c"),
) -> tuple[AccountingObservation, AccountingObservation, AccountingObservation]:
    return (
        _accounting(
            "access_accept",
            session=f"nps-{session}",
            nas=f"nps-{nas}",
            class_attribute=class_attribute,
            digest_character=digest_characters[0],
        ),
        _accounting(
            "start",
            session=session,
            nas=nas,
            observed_at=BASE_TIME + timedelta(minutes=1),
            class_attribute=class_attribute,
            digest_character=digest_characters[1],
        ),
        _accounting(
            "stop",
            session=session,
            nas=nas,
            observed_at=BASE_TIME + timedelta(minutes=2),
            class_attribute=class_attribute,
            digest_character=digest_characters[2],
        ),
    )


def test_lifecycle_selection_is_order_independent_and_uses_lowest_selector() -> None:
    lifecycle_a = _lifecycle()
    lifecycle_b = _lifecycle(
        session="fixture-session-b",
        nas="fixture-nas-b",
        class_attribute="fixture-class-b",
        digest_characters=("d", "e", "f"),
    )
    observations = (*lifecycle_b, *lifecycle_a)

    selected = select_accounting_lifecycle(observations)
    reversed_selected = select_accounting_lifecycle(tuple(reversed(observations)))

    assert selected.start.account_session_id == "fixture-session-a"
    assert selected.access_accept.account_session_id == (
        "nps-fixture-session-a"
    )
    assert selected.selector_sha256 == (
        "46288813ab2ab5551b5d955e675f94cbec956363d79e26391a7d63e08428096c"
    )
    assert reversed_selected.selector_sha256 == selected.selector_sha256
    assert selected.nps_window_start_utc == BASE_TIME - timedelta(minutes=10)
    assert selected.nps_window_end_utc == BASE_TIME + timedelta(minutes=10)


def test_lifecycle_selection_accepts_timezone_aware_sample_after_v1_day() -> None:
    shift = timedelta(days=2)
    lifecycle = tuple(
        AccountingObservation(
            packet_type=item.packet_type,
            observed_at_utc=item.observed_at_utc + shift,
            class_attribute=item.class_attribute,
            account_session_id=item.account_session_id,
            nas_identity=item.nas_identity,
            canonical_record_sha256=item.canonical_record_sha256,
            principal_observation=item.principal_observation,
        )
        for item in _lifecycle()
    )

    selected = select_accounting_lifecycle(lifecycle)

    assert selected.access_accept.observed_at_utc == BASE_TIME + shift
    assert selected.nps_window_start_utc == BASE_TIME + shift - timedelta(minutes=10)


@pytest.mark.parametrize("missing_packet", ["access_accept", "start", "stop"])
def test_incomplete_lifecycle_stops(missing_packet: str) -> None:
    observations = tuple(
        item for item in _lifecycle() if item.packet_type != missing_packet
    )

    with pytest.raises(ProbeStopError, match="no_complete_accounting_lifecycle"):
        select_accounting_lifecycle(observations)


@pytest.mark.parametrize("duplicate_packet", ["start", "stop"])
def test_duplicate_required_packet_is_ambiguous(duplicate_packet: str) -> None:
    lifecycle = _lifecycle()
    duplicate = next(
        item for item in lifecycle if item.packet_type == duplicate_packet
    )

    with pytest.raises(ProbeStopError, match="accounting_lifecycle_ambiguous"):
        select_accounting_lifecycle((*lifecycle, duplicate))


def test_required_packet_class_drift_stops() -> None:
    access_accept, start, stop = _lifecycle()
    drifted_stop = _accounting(
        "stop",
        observed_at=stop.observed_at_utc,
        class_attribute="fixture-class-drifted",
        digest_character="c",
    )

    with pytest.raises(ProbeStopError, match="accounting_lifecycle_class_mismatch"):
        select_accounting_lifecycle((access_accept, start, drifted_stop))


def test_invalid_required_canonical_digest_stops() -> None:
    access_accept, start, stop = _lifecycle()
    invalid_start = _accounting(
        "start",
        observed_at=start.observed_at_utc,
        digest_character="not-hex",
    )

    with pytest.raises(ProbeStopError, match="canonical_digest_invalid"):
        select_accounting_lifecycle((access_accept, invalid_start, stop))


def test_equal_lowest_selectors_stop_fail_closed() -> None:
    lifecycle_a = _lifecycle()
    lifecycle_b = _lifecycle(
        session="fixture-session-b",
        nas="fixture-nas-b",
        class_attribute="fixture-class-b",
    )

    with pytest.raises(ProbeStopError, match="accounting_lifecycle_tied"):
        select_accounting_lifecycle((*lifecycle_a, *lifecycle_b))


def _nps(
    *,
    event_id: int = 6272,
    observed_at: datetime = BASE_TIME,
    session: str = "fixture-session-a",
    nas: str = "fixture-nas-a",
    subject_sid: str = "S-1-fixture-subject",
    record_id: str = "fixture-record-a",
) -> NpsObservation:
    return NpsObservation(
        event_id=event_id,
        observed_at_utc=observed_at,
        record_id=record_id,
        subject_sid=subject_sid,
        account_session_id=session,
        nas_identity=nas,
    )


def test_nps_match_uses_resolved_sid_when_session_and_nas_values_differ() -> None:
    lifecycle = select_accounting_lifecycle(_lifecycle())
    matching_6272 = _nps(
        session="different-nps-session-id",
        nas="different-nps-nas",
    )

    assert select_nps_match(
        lifecycle,
        (matching_6272,),
        subject_sid="S-1-fixture-subject",
    ) is matching_6272


@pytest.mark.parametrize(
    "observation_overrides",
    [
        {"event_id": 6273},
        {"observed_at": BASE_TIME - timedelta(minutes=10, microseconds=1)},
        {"observed_at": BASE_TIME + timedelta(minutes=10, microseconds=1)},
        {"subject_sid": "S-1-fixture-other"},
    ],
)
def test_nps_non_match_stops_as_missing(
    observation_overrides: dict[str, object],
) -> None:
    lifecycle = select_accounting_lifecycle(_lifecycle())
    observation = _nps(**observation_overrides)

    with pytest.raises(ProbeStopError, match="nps_exact_match_missing"):
        select_nps_match(
            lifecycle,
            (observation,),
            subject_sid="S-1-fixture-subject",
        )


def test_nps_window_boundaries_are_inclusive() -> None:
    lifecycle = select_accounting_lifecycle(_lifecycle())
    at_start = _nps(observed_at=BASE_TIME - timedelta(minutes=10))
    at_end = _nps(
        observed_at=BASE_TIME + timedelta(minutes=10),
        record_id="fixture-record-b",
    )

    assert select_nps_match(
        lifecycle, (at_start,), subject_sid="S-1-fixture-subject"
    ) is at_start
    assert select_nps_match(
        lifecycle, (at_end,), subject_sid="S-1-fixture-subject"
    ) is at_end


def test_duplicate_exact_nps_match_is_ambiguous() -> None:
    lifecycle = select_accounting_lifecycle(_lifecycle())

    with pytest.raises(ProbeStopError, match="nps_exact_match_ambiguous"):
        select_nps_match(
            lifecycle,
            (_nps(), _nps(record_id="fixture-record-b")),
            subject_sid="S-1-fixture-subject",
        )


def test_reused_exact_class_across_complete_lifecycles_stops() -> None:
    lifecycle_a = _lifecycle()
    lifecycle_b = _lifecycle(
        session="fixture-session-b",
        nas="fixture-nas-b",
        class_attribute="fixture-class-a",
        digest_characters=("d", "e", "f"),
    )

    with pytest.raises(ProbeStopError, match="accounting_class_binding_ambiguous"):
        select_accounting_lifecycle((*lifecycle_a, *lifecycle_b))

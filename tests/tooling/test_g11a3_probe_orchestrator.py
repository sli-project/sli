from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json

import pytest

from scripts.maintenance import stage9_g11a3_probe_orchestrator as orchestrator
from scripts.maintenance.stage9_g11a3_probe_orchestrator import (
    AccountingObservation,
    AdVpnRecord,
    NpsObservation,
    ProbePreflight,
    ProbeRequest,
    run_probe,
)


UTC = timezone.utc


def test_accounting_first_plan_and_source_contract_are_versioned() -> None:
    assert orchestrator.PLAN_ID == "G11A3-PROBE-CLOSED-GENERATION-V4"
    assert orchestrator.SOURCE_CONTRACT_IDS == {
        "ad": "ad.accounts.vpn",
        "nps": "radius.nps.eventlog.6272.accounting-anchored",
        "accounting": "radius.accounting.start-interim-stop",
    }


def _sha(character: str) -> str:
    return character * 64


def _request() -> ProbeRequest:
    observed_at = datetime(2026, 8, 11, 12, 0, tzinfo=UTC)
    return ProbeRequest(
        approved_identity=r"EXAMPLE\operator",
        preflight=ProbePreflight(
            identity=r"EXAMPLE\operator",
            source_subscription_disabled=True,
            no_temporary_login=True,
            no_worker_started=True,
            no_cursor_movement=True,
        ),
        ad_records=(AdVpnRecord(
            subject_sid="S-1-fixture-a",
            immutable_object_id="fixture-object-a",
            enabled=True,
            object_class="user",
            vpn_member=True,
            lookup_principal_observation="example.test/Users/fixture-a",
        ),),
        nps_events=(
            NpsObservation(
                event_id=6272,
                observed_at_utc=observed_at,
                record_id="fixture-nps-a",
                subject_sid="S-1-fixture-a",
                account_session_id="different-nps-session-a",
                nas_identity="different-nps-nas-a",
            ),
            NpsObservation(
                event_id=6272,
                observed_at_utc=observed_at + timedelta(minutes=1),
                record_id="fixture-nps-b",
                subject_sid="S-1-fixture-b",
                account_session_id="different-nps-session-b",
                nas_identity="different-nps-nas-b",
            ),
        ),
        accounting_observations=(
            AccountingObservation(
                packet_type="access_accept",
                observed_at_utc=observed_at,
                class_attribute="fixture-class-a",
                account_session_id="different-access-accept-session-a",
                nas_identity="different-access-accept-nas-a",
                canonical_record_sha256=_sha("a"),
                principal_observation="example.test/Users/fixture-a",
            ),
            AccountingObservation(
                packet_type="start",
                observed_at_utc=observed_at + timedelta(seconds=5),
                class_attribute="fixture-class-a",
                account_session_id="fixture-session-a",
                nas_identity="fixture-nas-a",
                canonical_record_sha256=_sha("b"),
            ),
            AccountingObservation(
                packet_type="stop",
                observed_at_utc=observed_at + timedelta(minutes=2),
                class_attribute="fixture-class-a",
                account_session_id="fixture-session-a",
                nas_identity="fixture-nas-a",
                canonical_record_sha256=_sha("c"),
            ),
            AccountingObservation(
                packet_type="access_accept",
                observed_at_utc=observed_at + timedelta(minutes=1),
                class_attribute="fixture-class-b",
                account_session_id="different-access-accept-session-b",
                nas_identity="different-access-accept-nas-b",
                canonical_record_sha256=_sha("d"),
                principal_observation="example.test/Users/fixture-b",
            ),
            AccountingObservation(
                packet_type="start",
                observed_at_utc=observed_at + timedelta(minutes=1, seconds=5),
                class_attribute="fixture-class-b",
                account_session_id="fixture-session-b",
                nas_identity="fixture-nas-b",
                canonical_record_sha256=_sha("e"),
            ),
            AccountingObservation(
                packet_type="stop",
                observed_at_utc=observed_at + timedelta(minutes=3),
                class_attribute="fixture-class-b",
                account_session_id="fixture-session-b",
                nas_identity="fixture-nas-b",
                canonical_record_sha256=_sha("f"),
            ),
        ),
        accounting_files=1,
        accounting_bytes=1024,
        accounting_candidates=2,
        elapsed_seconds=1,
        source_timezone_offset_minutes=420,
        selected_nps_record_id="fixture-nps-a",
        selected_accounting_record_sha256s=(
            _sha("a"),
            _sha("b"),
            _sha("c"),
        ),
        postflight_attestation=orchestrator.ProbePostflightAttestation(
            performed=True,
            identity_reverified=True,
            database_rechecked=True,
            cursor_unchanged=True,
        ),
    )


def test_probe_validates_selected_bundle_independently_of_fixture_order() -> None:
    request = _request()
    reversed_request = ProbeRequest(
        **{
            **request.__dict__,
            "ad_records": tuple(reversed(request.ad_records)),
            "nps_events": tuple(reversed(request.nps_events)),
            "accounting_observations": tuple(
                reversed(request.accounting_observations)
            ),
        }
    )

    result = run_probe(request)

    assert result == run_probe(reversed_request)
    assert result["terminal_quality_state"] == "proven"
    assert set(result) == {
        "plan_id",
        "source_contract_ids",
        "counts",
        "cap_and_timeout_flags",
        "provenance_digests",
        "exact_link_bools",
        "terminal_quality_state",
        "stop_reason",
        "postflight_attestation",
    }
    assert result["stop_reason"] == "none"
    assert result["postflight_attestation"] == {
        "performed": True,
        "identity_reverified": True,
        "database_rechecked": True,
        "cursor_unchanged": True,
    }
    assert result["exact_link_bools"] == {
        "ad_sid_to_vpn_membership": True,
        "nps_subject_sid_to_ad_sid": True,
        "access_accept_class_to_start_stop": True,
    }
    encoded = json.dumps(result, sort_keys=True)
    for raw_value in (
        "S-1-fixture-a",
        "fixture-nps-a",
        "fixture-class-a",
        "fixture-session-a",
        "fixture-nas-a",
        "fixture-object-a",
        "example.test/Users/fixture-a",
        _sha("a"),
        _sha("b"),
        _sha("c"),
    ):
        assert raw_value not in encoded
        assert raw_value not in repr(request)


@pytest.mark.parametrize(
    "stop_reason",
    (
        "no_complete_accounting_lifecycle",
        "nps_collect_exception",
        "nps_empty_result",
    ),
)
def test_probe_reports_allowlisted_stop_reason_and_packet_counts(
    stop_reason: str,
) -> None:
    request = _request()
    stopped = ProbeRequest(
        **{
            **request.__dict__,
            "stop_reason": stop_reason,
        }
    )

    result = run_probe(stopped)

    assert result["terminal_quality_state"] == "stopped"
    assert result["stop_reason"] == stop_reason
    assert result["counts"] == {
        "ad_records_supplied": 1,
        "nps_events_supplied": 2,
        "accounting_records_supplied": 6,
        "accounting_access_accepts_supplied": 2,
        "accounting_starts_supplied": 2,
        "accounting_interims_supplied": 0,
        "accounting_stops_supplied": 2,
        "accounting_files": 1,
        "accounting_bytes": 1024,
        "accounting_candidates": 2,
    }


def test_probe_never_serializes_unapproved_stop_reason_text() -> None:
    request = _request()
    private_reason = "private-class-and-session-detail"
    stopped = ProbeRequest(
        **{**request.__dict__, "stop_reason": private_reason}
    )

    result = run_probe(stopped)

    assert result["stop_reason"] == "probe_stopped"
    assert private_reason not in json.dumps(result, sort_keys=True)


def test_probe_proves_timezone_aware_sample_after_v1_day() -> None:
    request = _request()
    shift = timedelta(days=2)
    shifted = ProbeRequest(
        **{
            **request.__dict__,
            "nps_events": tuple(
                NpsObservation(
                    event_id=item.event_id,
                    observed_at_utc=item.observed_at_utc + shift,
                    record_id=item.record_id,
                    subject_sid=item.subject_sid,
                    account_session_id=item.account_session_id,
                    nas_identity=item.nas_identity,
                )
                for item in request.nps_events
            ),
            "accounting_observations": tuple(
                AccountingObservation(
                    packet_type=item.packet_type,
                    observed_at_utc=item.observed_at_utc + shift,
                    class_attribute=item.class_attribute,
                    account_session_id=item.account_session_id,
                    nas_identity=item.nas_identity,
                    canonical_record_sha256=item.canonical_record_sha256,
                    principal_observation=item.principal_observation,
                )
                for item in request.accounting_observations
            ),
        }
    )

    result = run_probe(shifted)

    assert result["terminal_quality_state"] == "proven"
    assert result["counts"]["accounting_records_in_sample"] == 6
    assert "accounting_records_in_window" not in result["counts"]


def test_probe_rejects_extra_nps_event_outside_selected_sample_window() -> None:
    request = _request()
    extra = NpsObservation(
        event_id=6272,
        observed_at_utc=(
            request.accounting_observations[0].observed_at_utc
            + timedelta(minutes=11)
        ),
        record_id="fixture-nps-outside",
        subject_sid="S-1-fixture-outside",
        account_session_id="fixture-session-outside",
        nas_identity="fixture-nas-outside",
    )
    rejected = ProbeRequest(
        **{
            **request.__dict__,
            "nps_events": (*request.nps_events, extra),
        }
    )

    result = run_probe(rejected)

    assert result["terminal_quality_state"] == "stopped"
    assert result["provenance_digests"] == {}


def test_probe_returns_stopped_state_on_identity_mismatch() -> None:
    request = _request()
    rejected = ProbeRequest(
        **{**request.__dict__, "preflight": ProbePreflight(
            identity="fixture-wrong-identity",
            source_subscription_disabled=True,
            no_temporary_login=True,
            no_worker_started=True,
            no_cursor_movement=True,
        )}
    )

    assert run_probe(rejected)["terminal_quality_state"] == "stopped"


def test_probe_rejects_6273_with_false_links_and_no_digest() -> None:
    request = _request()
    rejected = ProbeRequest(
        **{
            **request.__dict__,
            "nps_events": (
                NpsObservation(
                    **{
                        **vars(request.nps_events[0]),
                        "event_id": 6273,
                    }
                ),
            ),
        }
    )

    result = run_probe(rejected)

    assert result["terminal_quality_state"] == "stopped"
    assert result["exact_link_bools"] == {
        "ad_sid_to_vpn_membership": False,
        "nps_subject_sid_to_ad_sid": False,
        "access_accept_class_to_start_stop": False,
    }
    assert result["provenance_digests"] == {}


def test_probe_returns_stopped_state_when_access_accept_bridge_is_ambiguous() -> None:
    request = _request()
    duplicate = AccountingObservation(
        packet_type="access_accept",
        observed_at_utc=datetime(2026, 8, 11, 12, 0, tzinfo=UTC),
        class_attribute="fixture-class-a",
        account_session_id="fixture-session-a",
        nas_identity="fixture-nas-a",
        canonical_record_sha256=_sha("9"),
    )
    rejected = ProbeRequest(
        **{
            **request.__dict__,
            "accounting_observations": (
                *request.accounting_observations,
                duplicate,
            ),
        }
    )

    assert run_probe(rejected)["terminal_quality_state"] == "stopped"


def test_probe_rejects_second_lifecycle_reusing_selected_exact_class() -> None:
    request = _request()
    conflicting = tuple(
        AccountingObservation(
            packet_type=item.packet_type,
            observed_at_utc=item.observed_at_utc + timedelta(minutes=4),
            class_attribute="fixture-class-a",
            account_session_id="fixture-session-conflict",
            nas_identity="fixture-nas-conflict",
            canonical_record_sha256=_sha(character),
            principal_observation=(
                "example.test/Users/fixture-conflict"
                if item.packet_type == "access_accept"
                else ""
            ),
        )
        for item, character in zip(
            request.accounting_observations[:3], ("7", "8", "9"), strict=True
        )
    )
    rejected = ProbeRequest(
        **{
            **request.__dict__,
            "accounting_observations": (
                *request.accounting_observations,
                *conflicting,
            ),
        }
    )

    assert run_probe(rejected)["terminal_quality_state"] == "stopped"


def test_probe_stops_when_selected_nps_marker_is_changed() -> None:
    request = _request()
    rejected = ProbeRequest(
        **{**request.__dict__, "selected_nps_record_id": "fixture-nps-b"}
    )

    assert run_probe(rejected)["terminal_quality_state"] == "stopped"


def test_probe_stops_when_selected_accounting_marker_is_changed() -> None:
    request = _request()
    rejected = ProbeRequest(
        **{
            **request.__dict__,
            "selected_accounting_record_sha256s": (
                _sha("d"),
                _sha("e"),
                _sha("f"),
            ),
        }
    )

    assert run_probe(rejected)["terminal_quality_state"] == "stopped"


def test_probe_returns_stopped_state_when_a_bound_is_exceeded() -> None:
    request = _request()
    rejected = ProbeRequest(
        **{**request.__dict__, "accounting_files": 2}
    )

    assert run_probe(rejected)["terminal_quality_state"] == "stopped"


def test_probe_rejects_ad_input_outside_the_selected_sid() -> None:
    request = _request()
    rejected = ProbeRequest(
        **{
            **request.__dict__,
            "ad_records": (
                *request.ad_records,
                AdVpnRecord(
                    subject_sid="S-1-unselected-fixture",
                    immutable_object_id="fixture-object-unselected",
                    enabled=True,
                    object_class="user",
                    vpn_member=True,
                    lookup_principal_observation=(
                        "example.test/Users/unselected"
                    ),
                ),
            ),
        }
    )

    assert run_probe(rejected)["terminal_quality_state"] == "stopped"

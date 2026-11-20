"""Pure, fixture-safe implementation of the bounded G11A3 probe contract.

The module has no network, filesystem, database, subprocess, worker, or
credential behaviour. A future, separately authorized launcher may provide
bounded source observations to ``run_probe``; this module only validates and
correlates those already in-memory values and returns redacted aggregates.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import re
from typing import Any, Mapping, Sequence


PLAN_ID = "G11A3-PROBE-CLOSED-GENERATION-V4"
WINDOW_START_UTC = datetime(2026, 8, 11, tzinfo=timezone.utc)
WINDOW_END_UTC = datetime(2026, 8, 12, tzinfo=timezone.utc)
SOURCE_CONTRACT_IDS = {
    "ad": "ad.accounts.vpn",
    "nps": "radius.nps.eventlog.6272.accounting-anchored",
    "accounting": "radius.accounting.start-interim-stop",
}
MAX_NPS_EVENTS = 500
MAX_ACCOUNTING_FILES = 1
MAX_ACCOUNTING_RECORDS = 400
MAX_ACCOUNTING_BYTES = 262_144
MAX_ACCOUNTING_CANDIDATES = 20
MAX_RUNTIME_SECONDS = 75
SOURCE_UTC_OFFSET_MINUTES = 420
NPS_TO_ACCOUNTING_PADDING = timedelta(seconds=600)
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ACCOUNTING_STOP_REASONS = frozenset(
    {
        "access_accept_identity_missing",
        "accounting_class_binding_ambiguous",
        "accounting_lifecycle_ambiguous",
        "accounting_lifecycle_class_mismatch",
        "accounting_lifecycle_order_invalid",
        "accounting_lifecycle_tied",
        "accounting_required_field_missing",
        "accounting_timestamp_invalid",
        "canonical_digest_invalid",
        "no_complete_accounting_lifecycle",
        "nps_collect_exception",
        "nps_empty_result",
        "unexpected_accounting_packet",
    }
)


class ProbeStopError(ValueError):
    """Private control flow; only allowlisted codes may be serialized."""

    def __init__(self, code: str, quality_state: str = "stopped") -> None:
        self.code = code
        self.quality_state = quality_state
        super().__init__(code)


@dataclass(frozen=True)
class ProbePreflight:
    identity: str = field(repr=False)
    source_subscription_disabled: bool
    no_temporary_login: bool
    no_worker_started: bool
    no_cursor_movement: bool


@dataclass(frozen=True)
class ProbePostflightAttestation:
    performed: bool = False
    identity_reverified: bool = False
    database_rechecked: bool = False
    cursor_unchanged: bool = False


@dataclass(frozen=True)
class AdVpnRecord:
    subject_sid: str = field(repr=False)
    immutable_object_id: str = field(repr=False)
    enabled: bool
    object_class: str = field(repr=False)
    vpn_member: bool
    lookup_principal_observation: str = field(default="", repr=False)


@dataclass(frozen=True)
class NpsObservation:
    event_id: int
    observed_at_utc: datetime = field(repr=False)
    record_id: str = field(repr=False)
    subject_sid: str = field(repr=False)
    account_session_id: str = field(repr=False)
    nas_identity: str = field(repr=False)


@dataclass(frozen=True)
class AccountingObservation:
    packet_type: str
    observed_at_utc: datetime = field(repr=False)
    class_attribute: str = field(repr=False)
    account_session_id: str = field(repr=False)
    nas_identity: str = field(repr=False)
    canonical_record_sha256: str = field(repr=False)
    principal_observation: str = field(default="", repr=False)


@dataclass(frozen=True)
class ProbeRequest:
    approved_identity: str = field(repr=False)
    preflight: ProbePreflight
    ad_records: Sequence[AdVpnRecord]
    nps_events: Sequence[NpsObservation]
    accounting_observations: Sequence[AccountingObservation]
    accounting_files: int
    accounting_bytes: int
    accounting_candidates: int
    elapsed_seconds: int | float
    source_timezone_offset_minutes: int
    nps_event_cap_reached: bool = False
    accounting_candidate_cap_reached: bool = False
    accounting_record_cap_reached: bool = False
    accounting_byte_cap_reached: bool = False
    stop_reason: str = field(default="", repr=False)
    selected_nps_record_id: str = field(default="", repr=False)
    selected_accounting_record_sha256s: tuple[str, str, str] = field(
        default=(), repr=False
    )
    postflight_attestation: ProbePostflightAttestation = field(
        default_factory=ProbePostflightAttestation
    )


def run_probe(request: ProbeRequest) -> dict[str, Any]:
    """Return only the approved redacted terminal result for in-memory input."""

    try:
        return _run_probe(request)
    except ProbeStopError as exc:
        return _terminal_result(
            quality_state=exc.quality_state,
            stop_reason=_safe_stop_reason(exc.code),
            counts=_safe_counts(request),
            flags={
                "nps_event_cap_reached": bool(request.nps_event_cap_reached),
                "accounting_candidate_cap_reached": bool(
                    request.accounting_candidate_cap_reached
                ),
                "accounting_record_cap_reached": bool(
                    request.accounting_record_cap_reached
                ),
                "accounting_byte_cap_reached": bool(
                    request.accounting_byte_cap_reached
                ),
                "runtime_timeout": float(request.elapsed_seconds)
                > MAX_RUNTIME_SECONDS,
            },
            links=_false_links(),
            digests={},
            postflight=request.postflight_attestation,
        )


def _run_probe(request: ProbeRequest) -> dict[str, Any]:
    _validate_preflight(request)
    _validate_bounds(request)
    if request.stop_reason:
        raise ProbeStopError(request.stop_reason)
    if int(request.source_timezone_offset_minutes) != SOURCE_UTC_OFFSET_MINUTES:
        raise ProbeStopError("source_timezone_not_accepted", "unavailable")

    nps_events = tuple(request.nps_events)
    accounting = tuple(request.accounting_observations)
    for item in (*nps_events, *accounting):
        _require_timezone(item.observed_at_utc)
    if not nps_events and not accounting:
        raise ProbeStopError("no_observations", "empty")
    if not nps_events or not accounting:
        raise ProbeStopError("source_leg_unavailable", "unavailable")

    nps_6272 = tuple(item for item in nps_events if item.event_id == 6272)
    if any(item.event_id != 6272 for item in nps_events):
        raise ProbeStopError("unexpected_nps_event")
    if not nps_6272:
        raise ProbeStopError("no_access_accept", "empty")

    if any(
        item.packet_type not in {"access_accept", "start", "interim", "stop"}
        for item in accounting
    ):
        raise ProbeStopError("unexpected_accounting_packet")
    selected = _validated_selected_candidate(request, nps_6272, accounting)
    ad = _validated_ad_record(
        request.ad_records,
        selected["subject_sid"],
        selected["principal_observation"],
    )
    provenance = _provenance_digest(selected, ad)
    return _terminal_result(
        quality_state="proven",
        stop_reason="none",
        counts={
            **_safe_counts(request),
            "nps_events_in_window": len(nps_events),
            "nps_6272_in_window": len(nps_6272),
            "accounting_records_in_sample": len(accounting),
            "complete_candidates": 1,
        },
        flags={
            "nps_event_cap_reached": False,
            "accounting_candidate_cap_reached": False,
            "accounting_record_cap_reached": False,
            "accounting_byte_cap_reached": False,
            "runtime_timeout": False,
        },
        links={
            "ad_sid_to_vpn_membership": True,
            "nps_subject_sid_to_ad_sid": True,
            "access_accept_class_to_start_stop": True,
        },
        digests={"provenance_bundle_sha256": provenance},
        postflight=request.postflight_attestation,
    )


def _validate_preflight(request: ProbeRequest) -> None:
    approved_identity = str(request.approved_identity).strip()
    preflight = request.preflight
    if (
        not approved_identity
        or str(preflight.identity).casefold() != approved_identity.casefold()
    ):
        raise ProbeStopError("identity_mismatch")
    if not all(
        (
            preflight.source_subscription_disabled,
            preflight.no_temporary_login,
            preflight.no_worker_started,
            preflight.no_cursor_movement,
        )
    ):
        raise ProbeStopError("local_state_not_safe")
    postflight = request.postflight_attestation
    if not all(
        (
            postflight.performed,
            postflight.identity_reverified,
            postflight.database_rechecked,
            postflight.cursor_unchanged,
        )
    ):
        raise ProbeStopError("postflight_not_proven")


def _validate_bounds(request: ProbeRequest) -> None:
    if (
        len(request.nps_events) > MAX_NPS_EVENTS
        or len(request.accounting_observations) > MAX_ACCOUNTING_RECORDS
        or int(request.accounting_files) > MAX_ACCOUNTING_FILES
        or int(request.accounting_bytes) > MAX_ACCOUNTING_BYTES
        or int(request.accounting_candidates) > MAX_ACCOUNTING_CANDIDATES
        or float(request.elapsed_seconds) > MAX_RUNTIME_SECONDS
        or request.nps_event_cap_reached
        or request.accounting_candidate_cap_reached
        or request.accounting_record_cap_reached
        or request.accounting_byte_cap_reached
    ):
        raise ProbeStopError("limit_exceeded")
    if min(
        int(request.accounting_files),
        int(request.accounting_bytes),
        int(request.accounting_candidates),
    ) < 0 or float(request.elapsed_seconds) < 0:
        raise ProbeStopError("invalid_bound_input")


def _validated_selected_candidate(
    request: ProbeRequest,
    nps_6272: Sequence[NpsObservation],
    accounting: Sequence[AccountingObservation],
) -> Mapping[str, Any]:
    selected_hashes = tuple(
        str(value).casefold()
        for value in request.selected_accounting_record_sha256s
    )
    selected_nps_record_id = str(request.selected_nps_record_id)
    if len(selected_hashes) != 3 or not selected_nps_record_id:
        raise ProbeStopError("selected_candidate_missing")
    for value in selected_hashes:
        _required_hash(value)

    required = tuple(
        tuple(
            item
            for item in accounting
            if item.packet_type == packet_type
            and item.canonical_record_sha256.casefold() == selected_hash
        )
        for packet_type, selected_hash in zip(
            ("access_accept", "start", "stop"),
            selected_hashes,
            strict=True,
        )
    )
    if any(len(matches) != 1 for matches in required):
        raise ProbeStopError("selected_candidate_ambiguous")
    access_accept, start, stop = (matches[0] for matches in required)
    if tuple(
        item.canonical_record_sha256.casefold()
        for item in (access_accept, start, stop)
    ) != selected_hashes:
        raise ProbeStopError("selected_candidate_mismatch")
    if (
        not access_accept.class_attribute
        or not access_accept.principal_observation.strip()
        or start.class_attribute != access_accept.class_attribute
        or stop.class_attribute != access_accept.class_attribute
        or not _same_accounting_session(start, stop)
        or not (
            access_accept.observed_at_utc
            <= start.observed_at_utc
            <= stop.observed_at_utc
        )
    ):
        raise ProbeStopError("selected_candidate_mismatch")
    if sum(
        item.packet_type == "access_accept"
        and item.class_attribute == access_accept.class_attribute
        for item in accounting
    ) != 1:
        raise ProbeStopError("selected_candidate_ambiguous")

    if any(
        abs(event.observed_at_utc - access_accept.observed_at_utc)
        > NPS_TO_ACCOUNTING_PADDING
        for event in nps_6272
    ):
        raise ProbeStopError("nps_event_outside_selected_window")

    nps_matches = tuple(
        event
        for event in nps_6272
        if event.record_id == selected_nps_record_id
        and abs(event.observed_at_utc - access_accept.observed_at_utc)
        <= NPS_TO_ACCOUNTING_PADDING
    )
    if len(nps_matches) != 1:
        raise ProbeStopError("selected_candidate_ambiguous")
    event = nps_matches[0]
    if not event.subject_sid:
        raise ProbeStopError("selected_candidate_mismatch")
    return {
        "subject_sid": event.subject_sid,
        "principal_observation": access_accept.principal_observation,
        "nps_record_id": event.record_id,
        "access_accept": access_accept,
        "start": start,
        "stop": stop,
    }


def _validated_ad_record(
    records: Sequence[AdVpnRecord], subject_sid: str,
    principal_observation: str,
) -> AdVpnRecord:
    if len(records) != 1:
        raise ProbeStopError("ad_scope_not_single_selected_sid")
    matches = [item for item in records if item.subject_sid == subject_sid]
    if len(matches) != 1:
        raise ProbeStopError("ad_identity_not_unique")
    record = matches[0]
    if not (
        record.enabled
        and record.vpn_member
        and record.object_class.casefold() == "user"
        and record.immutable_object_id
        and record.lookup_principal_observation == principal_observation
    ):
        raise ProbeStopError("ad_vpn_membership_not_proven")
    return record


def _same_accounting_session(
    left: AccountingObservation, right: AccountingObservation,
) -> bool:
    return (
        bool(left.account_session_id)
        and left.account_session_id == right.account_session_id
        and bool(left.nas_identity)
        and left.nas_identity.casefold() == right.nas_identity.casefold()
    )


def _require_timezone(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ProbeStopError("timestamp_timezone_required")


def _provenance_digest(
    candidate: Mapping[str, Any], ad: AdVpnRecord,
) -> str:
    access_accept = candidate["access_accept"]
    start = candidate["start"]
    stop = candidate["stop"]
    return _sha(
        {
            "ad_immutable_object_id": ad.immutable_object_id,
            "ad_subject_sid": candidate["subject_sid"],
            "accounting_access_accept_sha256": (
                access_accept.canonical_record_sha256
            ),
            "accounting_start_sha256": start.canonical_record_sha256,
            "accounting_stop_sha256": stop.canonical_record_sha256,
            "nps_record_id": candidate["nps_record_id"],
            "source_contract_ids": SOURCE_CONTRACT_IDS,
        }
    )


def _terminal_result(
    *,
    quality_state: str,
    stop_reason: str,
    counts: Mapping[str, int],
    flags: Mapping[str, bool],
    links: Mapping[str, bool],
    digests: Mapping[str, str],
    postflight: ProbePostflightAttestation,
) -> dict[str, Any]:
    return {
        "plan_id": PLAN_ID,
        "source_contract_ids": dict(SOURCE_CONTRACT_IDS),
        "counts": dict(counts),
        "cap_and_timeout_flags": dict(flags),
        "provenance_digests": dict(digests),
        "exact_link_bools": dict(links),
        "terminal_quality_state": quality_state,
        "stop_reason": stop_reason,
        "postflight_attestation": {
            "performed": bool(postflight.performed),
            "identity_reverified": bool(postflight.identity_reverified),
            "database_rechecked": bool(postflight.database_rechecked),
            "cursor_unchanged": bool(postflight.cursor_unchanged),
        },
    }


def _safe_counts(request: ProbeRequest) -> dict[str, int]:
    packet_counts = {
        packet_type: sum(
            item.packet_type == packet_type
            for item in request.accounting_observations
        )
        for packet_type in ("access_accept", "start", "interim", "stop")
    }
    return {
        "ad_records_supplied": len(request.ad_records),
        "nps_events_supplied": len(request.nps_events),
        "accounting_records_supplied": len(request.accounting_observations),
        "accounting_access_accepts_supplied": packet_counts["access_accept"],
        "accounting_starts_supplied": packet_counts["start"],
        "accounting_interims_supplied": packet_counts["interim"],
        "accounting_stops_supplied": packet_counts["stop"],
        "accounting_files": int(request.accounting_files),
        "accounting_bytes": int(request.accounting_bytes),
        "accounting_candidates": int(request.accounting_candidates),
    }


def _safe_stop_reason(value: str) -> str:
    candidate = str(value or "").strip()
    if candidate in _SAFE_ACCOUNTING_STOP_REASONS:
        return candidate
    return "probe_stopped"


def _false_links() -> dict[str, bool]:
    return {
        "ad_sid_to_vpn_membership": False,
        "nps_subject_sid_to_ad_sid": False,
        "access_accept_class_to_start_stop": False,
    }


def _required_hash(value: str) -> None:
    if _HEX64.fullmatch(str(value).casefold()) is None:
        raise ProbeStopError("canonical_digest_invalid")


def _sha(value: Mapping[str, Any]) -> str:
    return sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

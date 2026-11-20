"""Pure Accounting lifecycle and exact NPS selection for G11A-3."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import re
from typing import Sequence

from scripts.maintenance.stage9_g11a3_probe_orchestrator import (
    AccountingObservation,
    NpsObservation,
    ProbeStopError,
)


NPS_WINDOW_PADDING = timedelta(minutes=10)
_ALLOWED_ACCOUNTING_PACKETS = frozenset(
    {"access_accept", "start", "interim", "stop"}
)
_REQUIRED_LIFECYCLE_PACKETS = ("start", "stop")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class AccountingLifecycle:
    access_accept: AccountingObservation
    start: AccountingObservation
    stop: AccountingObservation
    selector_sha256: str = field(repr=False)

    @property
    def nps_window_start_utc(self) -> datetime:
        return self.access_accept.observed_at_utc - NPS_WINDOW_PADDING

    @property
    def nps_window_end_utc(self) -> datetime:
        return self.access_accept.observed_at_utc + NPS_WINDOW_PADDING


def select_accounting_lifecycle(
    observations: Sequence[AccountingObservation],
) -> AccountingLifecycle:
    """Select the unique lowest-digest complete Accounting lifecycle."""

    access_accepts: dict[str, list[AccountingObservation]] = {}
    groups: dict[tuple[str, str], list[AccountingObservation]] = {}
    for observation in observations:
        if observation.packet_type not in _ALLOWED_ACCOUNTING_PACKETS:
            raise ProbeStopError("unexpected_accounting_packet")
        _require_accounting_timestamp(observation.observed_at_utc)
        if not observation.class_attribute:
            raise ProbeStopError("accounting_lifecycle_class_mismatch")
        digest = observation.canonical_record_sha256.casefold()
        if _HEX64.fullmatch(digest) is None:
            raise ProbeStopError("canonical_digest_invalid")
        if observation.packet_type == "access_accept":
            if not observation.principal_observation.strip():
                raise ProbeStopError("access_accept_identity_missing")
            access_accepts.setdefault(observation.class_attribute, []).append(
                observation
            )
            continue
        if (
            not observation.account_session_id.strip()
            or not observation.nas_identity.strip()
        ):
            raise ProbeStopError("accounting_required_field_missing")
        groups.setdefault(
            (
                observation.account_session_id,
                observation.nas_identity.casefold(),
            ),
            [],
        ).append(observation)

    candidates: list[AccountingLifecycle] = []
    for group in groups.values():
        lifecycle_packets = {
            packet_type: tuple(
                item for item in group if item.packet_type == packet_type
            )
            for packet_type in _REQUIRED_LIFECYCLE_PACKETS
        }
        if any(len(items) > 1 for items in lifecycle_packets.values()):
            raise ProbeStopError("accounting_lifecycle_ambiguous")
        if any(not items for items in lifecycle_packets.values()):
            continue

        start = lifecycle_packets["start"][0]
        stop = lifecycle_packets["stop"][0]
        matching_accepts = tuple(access_accepts.get(start.class_attribute, ()))
        if len(matching_accepts) > 1:
            raise ProbeStopError("accounting_class_binding_ambiguous")
        if not matching_accepts:
            continue
        access_accept = matching_accepts[0]
        required = (access_accept, start, stop)
        if len({item.class_attribute for item in required}) != 1:
            raise ProbeStopError("accounting_lifecycle_class_mismatch")
        if not (
            access_accept.observed_at_utc
            <= start.observed_at_utc
            <= stop.observed_at_utc
        ):
            raise ProbeStopError("accounting_lifecycle_order_invalid")

        digests = tuple(
            item.canonical_record_sha256.casefold() for item in required
        )
        selector_payload = {
            "access_accept_sha256": digests[0],
            "start_sha256": digests[1],
            "stop_sha256": digests[2],
        }
        selector = sha256(
            json.dumps(
                selector_payload,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        candidates.append(
            AccountingLifecycle(
                access_accept=access_accept,
                start=start,
                stop=stop,
                selector_sha256=selector,
            )
        )

    class_counts: dict[str, int] = {}
    for candidate in candidates:
        class_value = candidate.access_accept.class_attribute
        class_counts[class_value] = class_counts.get(class_value, 0) + 1
    if any(count > 1 for count in class_counts.values()):
        raise ProbeStopError("accounting_class_binding_ambiguous")
    if not candidates:
        raise ProbeStopError("no_complete_accounting_lifecycle")
    candidates.sort(key=lambda candidate: candidate.selector_sha256)
    if (
        len(candidates) > 1
        and candidates[0].selector_sha256 == candidates[1].selector_sha256
    ):
        raise ProbeStopError("accounting_lifecycle_tied")
    return candidates[0]


def select_nps_match(
    lifecycle: AccountingLifecycle,
    observations: Sequence[NpsObservation],
    *,
    subject_sid: str,
) -> NpsObservation:
    """Return one `6272` for the AD-resolved exact SID in the narrow window."""

    selected_sid = str(subject_sid or "").strip()
    if not selected_sid:
        raise ProbeStopError("nps_exact_match_missing", "unavailable")

    matches = tuple(
        observation
        for observation in observations
        if observation.event_id == 6272
        and _inside_inclusive_window(
            observation.observed_at_utc,
            lifecycle.nps_window_start_utc,
            lifecycle.nps_window_end_utc,
        )
        and observation.subject_sid == selected_sid
    )
    if not matches:
        raise ProbeStopError("nps_exact_match_missing", "unavailable")
    if len(matches) > 1:
        raise ProbeStopError("nps_exact_match_ambiguous")
    return matches[0]


def _require_accounting_timestamp(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ProbeStopError("accounting_timestamp_invalid")


def _inside_inclusive_window(
    value: datetime,
    start: datetime,
    end: datetime,
) -> bool:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ProbeStopError("nps_timestamp_invalid")
    normalized = value.astimezone(timezone.utc)
    return start <= normalized <= end

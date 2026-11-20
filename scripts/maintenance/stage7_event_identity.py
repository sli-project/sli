"""Pure identity helpers for the stage 7 benchmark corpus.

This module is not wired into production runtime.  It defines the portable
identity that all isolated storage candidates must reproduce.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
import uuid


SOURCE_NAMESPACE = uuid.UUID("00000000-0000-4000-8000-000000000032")
STREAM_NAMESPACE = uuid.UUID("00000000-0000-4000-8000-000000000040")
EPOCH_NAMESPACE = uuid.UUID("00000000-0000-4000-8000-000000000061")
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
ISO_FRACTION_RE = re.compile(
    r"^(?P<seconds>.+[T ]\d{2}:\d{2}:\d{2})"
    r"\.(?P<fraction>\d+)"
    r"(?P<timezone>Z|[+-]\d{2}:?\d{2})$",
    re.IGNORECASE,
)


def _normalized_text(value: str, *, field: str) -> str:
    normalized = str(value or "").strip().casefold()
    if not normalized:
        raise ValueError(f"{field} is required")
    return normalized


def _utc_timestamp(value: str | datetime) -> str:
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value).strip()
        fraction_match = ISO_FRACTION_RE.fullmatch(text)
        if fraction_match and len(fraction_match.group("fraction")) > 6:
            timezone_text = fraction_match.group("timezone")
            if timezone_text.casefold() == "z":
                timezone_text = "+00:00"
            parsed = datetime.fromisoformat(
                fraction_match.group("seconds") + timezone_text
            )
            fraction = fraction_match.group("fraction")
            microseconds = int(fraction[:6])
            discarded = fraction[6:]
            round_up = (
                discarded[0] > "5"
                or (
                    discarded[0] == "5"
                    and (
                        any(digit != "0" for digit in discarded[1:])
                        or microseconds % 2 == 1
                    )
                )
            )
            if round_up:
                microseconds += 1
            if microseconds == 1_000_000:
                parsed += timedelta(seconds=1)
                microseconds = 0
            parsed = parsed.replace(microsecond=microseconds)
        else:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("event_time_utc must be timezone-aware")
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds")


def initial_source_instance_uid(
    *,
    server_fqdn: str,
    domain_sid: str | None = None,
    domain_fqdn: str | None = None,
) -> str:
    """Seed a source UUID once; later metadata enrichment keeps that UUID."""

    identity_kind = "domain_sid" if str(domain_sid or "").strip() else "domain_fqdn"
    identity_value = domain_sid if identity_kind == "domain_sid" else domain_fqdn
    seed = json.dumps(
        {
            "contract": "sli-source-instance-v1",
            "domain_identity_kind": identity_kind,
            "domain_identity": _normalized_text(
                str(identity_value or ""),
                field=identity_kind,
            ),
            "server_fqdn": _normalized_text(server_fqdn, field="server_fqdn"),
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return str(uuid.uuid5(SOURCE_NAMESPACE, seed))


def stream_uid(*, source_instance_uid: str, stream_key: str) -> str:
    source_uid = str(uuid.UUID(str(source_instance_uid)))
    seed = f"sli-stream-v1:{source_uid}:{_normalized_text(stream_key, field='stream_key')}"
    return str(uuid.uuid5(STREAM_NAMESPACE, seed))


def initial_log_epoch_uid(
    *,
    stream_uid_value: str,
    first_event_record_id: int,
    first_event_time_utc: str | datetime,
) -> str:
    """Seed the current epoch once; a proven channel reset creates a new UUID."""

    if int(first_event_record_id) < 0:
        raise ValueError("first_event_record_id must be non-negative")
    stream = str(uuid.UUID(str(stream_uid_value)))
    seed = (
        f"sli-log-epoch-v1:{stream}:{int(first_event_record_id)}:"
        f"{_utc_timestamp(first_event_time_utc)}"
    )
    return str(uuid.uuid5(EPOCH_NAMESPACE, seed))


def event_uid(
    *,
    source_instance_uid: str,
    stream_uid_value: str,
    log_epoch_uid: str,
    event_record_id: int,
    event_time_utc: str | datetime,
    normalized_sha256: str,
) -> str:
    if int(event_record_id) < 0:
        raise ValueError("event_record_id must be non-negative")
    digest = str(normalized_sha256).strip().casefold()
    if not SHA256_RE.fullmatch(digest):
        raise ValueError("normalized_sha256 must contain 64 hexadecimal characters")
    identity = {
        "contract": "sli-event-v1",
        "source_instance_uid": str(uuid.UUID(str(source_instance_uid))),
        "stream_uid": str(uuid.UUID(str(stream_uid_value))),
        "log_epoch_uid": str(uuid.UUID(str(log_epoch_uid))),
        "event_record_id": int(event_record_id),
        "event_time_utc": _utc_timestamp(event_time_utc),
        "normalized_sha256": digest,
    }
    encoded = json.dumps(
        identity,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sli-event-v1:" + hashlib.sha256(encoded).hexdigest()

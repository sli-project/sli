from __future__ import annotations

import csv
from datetime import datetime, timezone
from io import StringIO

import pytest

from server.source_packs.radius.accounting import DATABASE_COMPATIBLE_COLUMNS
from server.source_packs.radius.session_rebind import (
    ImmutableStoredRadiusObservation,
    RadiusSessionRebindError,
    VerifiedRadiusEvidence,
    build_rebound_radius_projection,
)


def _line(**values: str) -> str:
    row = [""] * len(DATABASE_COMPATIBLE_COLUMNS)
    row[DATABASE_COMPATIBLE_COLUMNS.index("ServiceName")] = "NPS"
    row[DATABASE_COMPATIBLE_COLUMNS.index("Record-Date")] = "08/11/2026"
    for name, value in values.items():
        row[DATABASE_COMPATIBLE_COLUMNS.index(name)] = value
    output = StringIO()
    csv.writer(output, lineterminator="").writerow(row)
    return output.getvalue()


def _evidence(uid: str, **values: str) -> VerifiedRadiusEvidence:
    from hashlib import sha256

    record = _line(**values)
    return VerifiedRadiusEvidence(uid, record, sha256(record.encode()).hexdigest())


def test_rebind_rebuilds_session_with_current_v2_entity_identity() -> None:
    accept = _evidence(
        "11111111-1111-1111-1111-111111111111",
        **{
            "Packet-Type": "2",
            "Fully-Qualified-Distinguished-Name": "CN=User,DC=example,DC=invalid",
            "Class": "opaque-class",
            "Record-Time": "12:00:00",
        },
    )
    start = _evidence(
        "22222222-2222-2222-2222-222222222222",
        **{
            "Packet-Type": "4",
            "Class": "opaque-class",
            "Acct-Status-Type": "1",
            "Acct-Session-Id": "session-1",
            "NAS-Identifier": "gateway",
            "Record-Time": "12:01:00",
        },
    )
    stop = _evidence(
        "33333333-3333-3333-3333-333333333333",
        **{
            "Packet-Type": "4",
            "Class": "opaque-class",
            "Acct-Status-Type": "2",
            "Acct-Session-Id": "session-1",
            "NAS-Identifier": "gateway",
            "Record-Time": "12:10:00",
        },
    )
    stored = (
        ImmutableStoredRadiusObservation(
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            start.evidence_uid,
            "start",
            "ready",
            datetime(2026, 8, 11, 5, 1, tzinfo=timezone.utc),
            start.canonical_record_sha256,
        ),
        ImmutableStoredRadiusObservation(
            "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            stop.evidence_uid,
            "stop",
            "ready",
            datetime(2026, 8, 11, 5, 10, tzinfo=timezone.utc),
            stop.canonical_record_sha256,
        ),
    )

    result = build_rebound_radius_projection(
        evidence_records=(accept, start, stop),
        stored_observations=stored,
        source_instance_id="radius.example.invalid",
        organization_fqdn="example.invalid",
        source_timezone_id="N. Central Asia Standard Time",
        source_utc_offset_minutes=420,
        exact_lookup=lambda organization, dn: (
            "entity:901"
            if organization == "example.invalid"
            and dn == "CN=User,DC=example,DC=invalid"
            else None
        ),
    )

    assert result.input_observations == 2
    assert result.exact_ready_observations == 2
    assert len(result.sessions) == 1
    assert result.sessions[0].exact_principal_key == "entity:901"
    assert result.sessions[0].completeness == "complete"
    assert result.sessions[0].observation_count == 2


def test_rebind_rejects_evidence_hash_drift() -> None:
    item = _evidence(
        "22222222-2222-2222-2222-222222222222",
        **{
            "Packet-Type": "4",
            "Class": "opaque-class",
            "Acct-Status-Type": "1",
            "Acct-Session-Id": "session-1",
            "NAS-Identifier": "gateway",
            "Record-Time": "12:01:00",
        },
    )
    stored = ImmutableStoredRadiusObservation(
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        item.evidence_uid,
        "start",
        "ready",
        datetime(2026, 8, 11, 5, 1, tzinfo=timezone.utc),
        "f" * 64,
    )

    with pytest.raises(RadiusSessionRebindError, match="rebind_evidence_hash_mismatch"):
        build_rebound_radius_projection(
            evidence_records=(item,),
            stored_observations=(stored,),
            source_instance_id="radius.example.invalid",
            organization_fqdn="example.invalid",
            source_timezone_id="N. Central Asia Standard Time",
            source_utc_offset_minutes=420,
            exact_lookup=lambda _organization, _dn: None,
        )

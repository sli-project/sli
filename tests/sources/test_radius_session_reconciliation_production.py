from __future__ import annotations

import csv
from datetime import datetime, timezone
from io import StringIO

import pytest

from server.source_packs.radius.accounting import DATABASE_COMPATIBLE_COLUMNS
from server.source_packs.radius.session_reconciliation_production import (
    ImmutableTerminalObservation,
    RadiusSessionReconciliationProductionError,
    VerifiedEvidenceRecord,
    build_exact_reconciliation_batch,
)
from server.source_packs.radius.session_reconciliation import (
    build_reconciliation_attempts,
)


def _line(**values: str) -> str:
    row = [""] * len(DATABASE_COMPATIBLE_COLUMNS)
    row[DATABASE_COMPATIBLE_COLUMNS.index("ServiceName")] = "NPS"
    row[DATABASE_COMPATIBLE_COLUMNS.index("Record-Date")] = "08/11/2026"
    row[DATABASE_COMPATIBLE_COLUMNS.index("Record-Time")] = "12:00:00"
    for name, value in values.items():
        row[DATABASE_COMPATIBLE_COLUMNS.index(name)] = value
    output = StringIO()
    csv.writer(output, lineterminator="").writerow(row)
    return output.getvalue()


def test_exact_batch_uses_access_accept_class_and_preserves_terminal_fact() -> None:
    accept = VerifiedEvidenceRecord(
        evidence_uid="11111111-1111-1111-1111-111111111111",
        canonical_record=_line(
            **{
                "Packet-Type": "2",
                "Fully-Qualified-Distinguished-Name": "CN=User,DC=example,DC=invalid",
                "Class": "opaque-class",
            }
        ),
    )
    accounting = VerifiedEvidenceRecord(
        evidence_uid="22222222-2222-2222-2222-222222222222",
        canonical_record=_line(
            **{
                "Packet-Type": "4",
                "Class": "opaque-class",
                "Acct-Status-Type": "1",
                "Acct-Session-Id": "opaque-session",
                "NAS-Identifier": "vpn-gateway",
            }
        ),
    )
    observation = ImmutableTerminalObservation(
        observation_id="33333333-3333-3333-3333-333333333333",
        evidence_uid=accounting.evidence_uid,
        lifecycle_event="start",
        timestamp_state="ready",
        observed_at_utc=datetime(2026, 8, 11, 5, tzinfo=timezone.utc),
    )

    result = build_exact_reconciliation_batch(
        evidence_records=(accept, accounting),
        terminal_observations=(observation,),
        source_instance_id="radius.example.invalid",
        organization_fqdn="example.invalid",
        source_timezone_id="N. Central Asia Standard Time",
        source_utc_offset_minutes=420,
        exact_lookup=lambda organization, dn: (
            "entity:101"
            if organization == "example.invalid"
            and dn == "CN=User,DC=example,DC=invalid"
            else None
        ),
    )

    proposal = result.proposals[observation.observation_id]
    assert result.access_accept_count == 1
    assert result.unresolved_access_accept_count == 0
    assert result.reconciled_count == 1
    assert proposal.exact_principal_key == "entity:101"
    assert proposal.session_identity_key.startswith("radius-session:")
    assert result.candidates[0].evidence_uid == accounting.evidence_uid


def test_exact_batch_keeps_missing_class_candidate_still_unresolved() -> None:
    accounting = VerifiedEvidenceRecord(
        evidence_uid="22222222-2222-2222-2222-222222222222",
        canonical_record=_line(
            **{
                "Packet-Type": "4",
                "Class": "missing-class",
                "Acct-Status-Type": "1",
                "Acct-Session-Id": "opaque-session",
                "NAS-Identifier": "vpn-gateway",
            }
        ),
    )
    observation = ImmutableTerminalObservation(
        observation_id="33333333-3333-3333-3333-333333333333",
        evidence_uid=accounting.evidence_uid,
        lifecycle_event="start",
        timestamp_state="ready",
        observed_at_utc=datetime(2026, 8, 11, 5, tzinfo=timezone.utc),
    )

    result = build_exact_reconciliation_batch(
        evidence_records=(accounting,),
        terminal_observations=(observation,),
        source_instance_id="radius.example.invalid",
        organization_fqdn="example.invalid",
        source_timezone_id="N. Central Asia Standard Time",
        source_utc_offset_minutes=420,
        exact_lookup=lambda _organization, _dn: None,
    )
    attempts = build_reconciliation_attempts(
        result.candidates,
        result.proposals,
        evidence_corpus_sha256=result.evidence_corpus_sha256,
        resolver_contract_id="resolver-v1",
    )

    assert len(result.candidates) == 1
    assert result.proposals == {}
    assert result.reconciled_count == 0
    assert len(attempts) == 1
    assert attempts[0].outcome == "still_unresolved"


def test_exact_batch_rejects_one_class_with_conflicting_exact_principals() -> None:
    first = VerifiedEvidenceRecord(
        evidence_uid="11111111-1111-1111-1111-111111111111",
        canonical_record=_line(
            **{
                "Packet-Type": "2",
                "Fully-Qualified-Distinguished-Name": "CN=First,DC=example,DC=invalid",
                "Class": "conflicting-class",
            }
        ),
    )
    second = VerifiedEvidenceRecord(
        evidence_uid="22222222-2222-2222-2222-222222222222",
        canonical_record=_line(
            **{
                "Packet-Type": "2",
                "Fully-Qualified-Distinguished-Name": "CN=Second,DC=example,DC=invalid",
                "Class": "conflicting-class",
            }
        ),
    )
    accounting = VerifiedEvidenceRecord(
        evidence_uid="33333333-3333-3333-3333-333333333333",
        canonical_record=_line(
            **{
                "Packet-Type": "4",
                "Class": "conflicting-class",
                "Acct-Status-Type": "1",
                "Acct-Session-Id": "opaque-session",
                "NAS-Identifier": "vpn-gateway",
            }
        ),
    )
    observation = ImmutableTerminalObservation(
        observation_id="44444444-4444-4444-4444-444444444444",
        evidence_uid=accounting.evidence_uid,
        lifecycle_event="start",
        timestamp_state="ready",
        observed_at_utc=datetime(2026, 8, 11, 5, tzinfo=timezone.utc),
    )

    with pytest.raises(
        RadiusSessionReconciliationProductionError,
        match="production_reconciliation_class_identity_conflict",
    ):
        build_exact_reconciliation_batch(
            evidence_records=(first, second, accounting),
            terminal_observations=(observation,),
            source_instance_id="radius.example.invalid",
            organization_fqdn="example.invalid",
            source_timezone_id="N. Central Asia Standard Time",
            source_utc_offset_minutes=420,
            exact_lookup=lambda _organization, distinguished_name: (
                "entity:101"
                if distinguished_name.startswith("CN=First")
                else "entity:202"
            ),
        )

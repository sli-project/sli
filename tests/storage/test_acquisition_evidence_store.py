from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from uuid import UUID

import pytest

from server.sli.storage.acquisition_evidence_store import (
    AcquisitionEvidenceError,
    AcquisitionEvidenceIdentity,
    AcquisitionEvidenceStore,
)
from server.source_packs.radius.accounting import DATABASE_COMPATIBLE_COLUMNS
from server.source_packs.radius.accounting_evidence import (
    RadiusEvidenceBridgeError,
    publish_radius_batch_evidence,
)
from server.source_packs.radius.accounting_postgres import (
    _validate_batch,
    load_postgres_contract,
)
from server.source_packs.radius.accounting_runtime_contract import (
    initial_cursor,
    plan_batch,
)


CURSOR_EPOCH = UUID("00000000-0000-4000-8000-000000000042")


def _identity(*, ordinal: int = 0) -> AcquisitionEvidenceIdentity:
    return AcquisitionEvidenceIdentity(
        source_instance_id="radius-fixture-1",
        stream_id="radius-accounting",
        transport_binding="nps-database-compatible-log",
        cursor_epoch=CURSOR_EPOCH,
        file_generation="in-20260730",
        cursor_start_byte_offset=100,
        batch_record_ordinal=ordinal,
    )


def _line(*, packet_type: str, status: str = "") -> str:
    row = [""] * len(DATABASE_COMPATIBLE_COLUMNS)
    index = {
        name: position
        for position, name in enumerate(DATABASE_COMPATIBLE_COLUMNS)
    }
    values = {
        "ComputerName": "NPS01",
        "ServiceName": "IAS",
        "Record-Date": "07/30/2026",
        "Record-Time": "15:00:00",
        "Packet-Type": packet_type,
        "Fully-Qualified-Distinguished-Name": (
            "example.test/Users/sample.user"
        ),
        "Class": "opaque-class",
        "NAS-Identifier": "VPN-GW-01",
        "Acct-Status-Type": status,
        "Acct-Session-Id": "opaque-session",
    }
    for name, value in values.items():
        row[index[name]] = value
    return ",".join(row)


def _plan(records: list[str]):
    cursor = initial_cursor(
        source_instance_id="radius-fixture-1",
        transport_binding="nps-database-compatible-log",
        file_generation="in-20260730",
    )
    return plan_batch(
        cursor=cursor,
        class_cache={},
        file_generation=cursor.file_generation,
        start_offset=0,
        end_offset=200,
        lines=records,
        identity_resolver=lambda _: "sid:S-1-5-21-100000003-200000003-300000003-1101",
        batch_observed_at_utc=datetime(
            2026, 7, 30, 8, 0, tzinfo=timezone.utc
        ),
        source_timezone_id="N. Central Asia Standard Time",
        source_utc_offset_minutes=420,
    )


def test_evidence_publish_is_deterministic_verified_and_payload_safe(
    tmp_path: Path,
) -> None:
    store = AcquisitionEvidenceStore(tmp_path.resolve())
    record = _line(packet_type="4", status="1")
    digest = sha256(record.encode("utf-8")).hexdigest()

    first = store.publish_canonical_record(
        identity=_identity(),
        canonical_record=record,
        canonical_record_sha256=digest,
    )
    second = store.publish_canonical_record(
        identity=_identity(),
        canonical_record=record,
        canonical_record_sha256=digest,
    )

    assert first.evidence_uid == second.evidence_uid
    assert first.object_reference == second.object_reference
    assert first.object_sha256 == second.object_sha256 == digest
    assert store.read_verified(second) == record
    assert record not in repr(first)
    assert len(list((tmp_path / "published").rglob("*.record"))) == 1


def test_evidence_identity_cannot_be_reused_for_different_bytes(
    tmp_path: Path,
) -> None:
    store = AcquisitionEvidenceStore(tmp_path.resolve())
    first_record = _line(packet_type="4", status="1")
    second_record = _line(packet_type="4", status="2")
    first = store.publish_canonical_record(
        identity=_identity(),
        canonical_record=first_record,
        canonical_record_sha256=sha256(
            first_record.encode("utf-8")
        ).hexdigest(),
    )
    with pytest.raises(
        AcquisitionEvidenceError,
        match="evidence_identity_conflict",
    ):
        store.publish_canonical_record(
            identity=_identity(),
            canonical_record=second_record,
            canonical_record_sha256=sha256(
                second_record.encode("utf-8")
            ).hexdigest(),
        )
    assert store.read_verified(first) == first_record


def test_readback_ignores_forged_external_object_path(tmp_path: Path) -> None:
    store = AcquisitionEvidenceStore(tmp_path.resolve())
    record = _line(packet_type="2")
    publication = store.publish_canonical_record(
        identity=_identity(),
        canonical_record=record,
        canonical_record_sha256=sha256(record.encode("utf-8")).hexdigest(),
    )
    forged = replace(
        publication,
        object_path=tmp_path.parent / "outside-sensitive-file",
    )
    assert store.read_verified(forged) == record


def test_evidence_store_rejects_oversize_utf8_without_partial_file(
    tmp_path: Path,
) -> None:
    store = AcquisitionEvidenceStore(
        tmp_path.resolve(),
        maximum_object_bytes=64,
    )
    record = "я" * 40
    with pytest.raises(
        AcquisitionEvidenceError,
        match="evidence_object_too_large",
    ):
        store.publish_canonical_record(
            identity=_identity(),
            canonical_record=record,
            canonical_record_sha256=sha256(
                record.encode("utf-8")
            ).hexdigest(),
        )
    assert not list((tmp_path / "staging").rglob("*.partial"))


def test_radius_bridge_produces_exact_postgres_manifest_inputs(
    tmp_path: Path,
) -> None:
    records = [
        _line(packet_type="2"),
        _line(packet_type="4", status="1"),
    ]
    plan = _plan(records)
    evidence = publish_radius_batch_evidence(
        AcquisitionEvidenceStore(tmp_path.resolve()),
        cursor_epoch=CURSOR_EPOCH,
        plan=plan,
        canonical_records=records,
    )

    _validate_batch(plan, evidence, load_postgres_contract())
    assert [item.canonical_record_sha256 for item in evidence] == list(
        plan.evidence_sha256
    )
    assert all(
        item.object_reference.startswith("evidence:acquisition.radius.")
        for item in evidence
    )


def test_radius_bridge_rejects_missing_or_extra_records(tmp_path: Path) -> None:
    records = [_line(packet_type="4", status="1")]
    plan = _plan(records)
    with pytest.raises(
        RadiusEvidenceBridgeError,
        match="evidence_record_count_mismatch",
    ):
        publish_radius_batch_evidence(
            AcquisitionEvidenceStore(tmp_path.resolve()),
            cursor_epoch=CURSOR_EPOCH,
            plan=plan,
            canonical_records=[],
        )

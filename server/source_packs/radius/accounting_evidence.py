"""Evidence-first bridge for one already-read RADIUS Accounting batch.

This module has no source reader, database connection, cursor mutation or
runtime entry point.  It publishes exact canonical records to the core evidence
store and returns the verified references expected by the PostgreSQL boundary.
"""
from __future__ import annotations

from typing import Iterable
from uuid import UUID

from server.sli.storage.acquisition_evidence_store import (
    AcquisitionEvidenceIdentity,
    AcquisitionEvidenceStore,
)
from server.source_packs.radius.accounting_postgres import RadiusEvidenceObject
from server.source_packs.radius.accounting_runtime_contract import RadiusBatchPlan


class RadiusEvidenceBridgeError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def publish_radius_batch_evidence(
    store: AcquisitionEvidenceStore,
    *,
    cursor_epoch: UUID,
    plan: RadiusBatchPlan,
    canonical_records: Iterable[str],
) -> tuple[RadiusEvidenceObject, ...]:
    records = tuple(canonical_records)
    if len(records) != len(plan.evidence_sha256):
        raise RadiusEvidenceBridgeError("evidence_record_count_mismatch")
    if not records:
        raise RadiusEvidenceBridgeError("evidence_batch_empty")
    publications = []
    for ordinal, (record, digest) in enumerate(
        zip(records, plan.evidence_sha256, strict=True)
    ):
        publication = store.publish_canonical_record(
            identity=AcquisitionEvidenceIdentity(
                source_instance_id=plan.current_cursor.source_instance_id,
                stream_id=plan.current_cursor.stream_id,
                transport_binding=plan.current_cursor.transport_binding,
                cursor_epoch=cursor_epoch,
                file_generation=plan.next_cursor.file_generation,
                cursor_start_byte_offset=plan.current_cursor.byte_offset,
                batch_record_ordinal=ordinal,
            ),
            canonical_record=record,
            canonical_record_sha256=digest,
        )
        publications.append(
            RadiusEvidenceObject(
                evidence_uid=publication.evidence_uid,
                canonical_record_sha256=publication.canonical_record_sha256,
                object_reference=publication.object_reference,
                object_sha256=publication.object_sha256,
                object_size_bytes=publication.object_size_bytes,
                verified_at_utc=publication.verified_at_utc,
            )
        )
    return tuple(publications)

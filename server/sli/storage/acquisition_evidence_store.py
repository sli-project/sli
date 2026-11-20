"""Core-owned immutable evidence objects for acquisition transports.

The store persists the exact canonical record bytes before PostgreSQL commits
the durable manifest, fan-out outbox and cursor.  It does not contact a source,
authorize product reads, mutate a cursor or remove orphaned objects.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from uuid import UUID, uuid5

from server.sli.storage.atomic_object_store import (
    AtomicObjectError,
    AtomicObjectIntegrityError,
    AtomicObjectStore,
)


EVIDENCE_NAMESPACE = UUID("00000000-0000-4000-8000-000000000066")
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_REFERENCE = re.compile(r"^evidence:acquisition\.radius\.([0-9a-f]{32})$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class AcquisitionEvidenceError(ValueError):
    """Safe closed-code failure; never includes evidence payload."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class AcquisitionEvidenceIdentity:
    source_instance_id: str
    stream_id: str
    transport_binding: str
    cursor_epoch: UUID
    file_generation: str
    cursor_start_byte_offset: int
    batch_record_ordinal: int


@dataclass(frozen=True)
class AcquisitionEvidencePublication:
    evidence_uid: UUID
    canonical_record_sha256: str
    object_reference: str
    object_sha256: str
    object_size_bytes: int
    verified_at_utc: datetime
    object_path: Path = field(repr=False)


class AcquisitionEvidenceStore:
    """Publish and verify exact canonical records below an explicit root."""

    def __init__(self, root: Path, *, maximum_object_bytes: int = 65_536) -> None:
        self.root = Path(root)
        self.maximum_object_bytes = int(maximum_object_bytes)
        if self.maximum_object_bytes < 1:
            raise AcquisitionEvidenceError("evidence_maximum_size_invalid")
        try:
            self._objects = AtomicObjectStore(self.root)
        except AtomicObjectError as exc:
            raise AcquisitionEvidenceError("evidence_root_invalid") from exc

    def publish_canonical_record(
        self,
        *,
        identity: AcquisitionEvidenceIdentity,
        canonical_record: str,
        canonical_record_sha256: str,
    ) -> AcquisitionEvidencePublication:
        normalized = self._identity(identity)
        expected = str(canonical_record_sha256 or "").casefold()
        if _SHA256.fullmatch(expected) is None:
            raise AcquisitionEvidenceError("canonical_record_sha256_invalid")
        if not isinstance(canonical_record, str) or not canonical_record:
            raise AcquisitionEvidenceError("canonical_record_required")
        if "\x00" in canonical_record or "\r" in canonical_record or "\n" in canonical_record:
            raise AcquisitionEvidenceError("canonical_record_must_be_single_text_record")
        payload = canonical_record.encode("utf-8")
        if len(payload) > self.maximum_object_bytes:
            raise AcquisitionEvidenceError("evidence_object_too_large")
        if sha256(payload).hexdigest() != expected:
            raise AcquisitionEvidenceError("canonical_record_sha256_mismatch")

        evidence_uid = self.evidence_uid(normalized)
        uid_hex = evidence_uid.hex
        relative_name = f"acquisition-radius/{uid_hex[:2]}/{uid_hex}.record"
        try:
            prepared = self._objects.prepare(
                relative_name,
                payload,
                expected_sha256=expected,
            )
            path = self._objects.publish(prepared)
            self._objects.verify(prepared)
        except AtomicObjectIntegrityError as exc:
            raise AcquisitionEvidenceError("evidence_identity_conflict") from exc
        except AtomicObjectError as exc:
            raise AcquisitionEvidenceError("evidence_publication_failed") from exc
        return AcquisitionEvidencePublication(
            evidence_uid=evidence_uid,
            canonical_record_sha256=expected,
            object_reference=f"evidence:acquisition.radius.{uid_hex}",
            object_sha256=prepared.sha256,
            object_size_bytes=prepared.size_bytes,
            verified_at_utc=datetime.now(timezone.utc),
            object_path=path,
        )

    def read_verified(
        self,
        publication: AcquisitionEvidencePublication,
    ) -> str:
        match = _REFERENCE.fullmatch(publication.object_reference)
        if match is None or match.group(1) != publication.evidence_uid.hex:
            raise AcquisitionEvidenceError("evidence_reference_invalid")
        if publication.object_size_bytes > self.maximum_object_bytes:
            raise AcquisitionEvidenceError("evidence_object_too_large")
        relative_name = (
            f"acquisition-radius/{publication.evidence_uid.hex[:2]}/"
            f"{publication.evidence_uid.hex}.record"
        )
        try:
            payload = self._objects.read_verified(
                relative_name,
                expected_sha256=publication.object_sha256,
                expected_size_bytes=publication.object_size_bytes,
            )
        except (OSError, AtomicObjectError) as exc:
            raise AcquisitionEvidenceError("evidence_readback_failed") from exc
        if len(payload) != publication.object_size_bytes:
            raise AcquisitionEvidenceError("evidence_size_mismatch")
        if sha256(payload).hexdigest() != publication.canonical_record_sha256:
            raise AcquisitionEvidenceError("canonical_record_sha256_mismatch")
        try:
            return payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise AcquisitionEvidenceError("evidence_utf8_invalid") from exc

    @staticmethod
    def evidence_uid(identity: AcquisitionEvidenceIdentity) -> UUID:
        normalized = AcquisitionEvidenceStore._identity(identity)
        material = json.dumps(
            {
                "batch_record_ordinal": normalized.batch_record_ordinal,
                "cursor_epoch": str(normalized.cursor_epoch),
                "cursor_start_byte_offset": normalized.cursor_start_byte_offset,
                "file_generation": normalized.file_generation,
                "source_instance_id": normalized.source_instance_id,
                "stream_id": normalized.stream_id,
                "transport_binding": normalized.transport_binding,
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        return uuid5(EVIDENCE_NAMESPACE, material)

    @staticmethod
    def _identity(
        identity: AcquisitionEvidenceIdentity,
    ) -> AcquisitionEvidenceIdentity:
        values = {
            "source_instance_id": identity.source_instance_id,
            "stream_id": identity.stream_id,
            "transport_binding": identity.transport_binding,
            "file_generation": identity.file_generation,
        }
        normalized: dict[str, str] = {}
        for name, value in values.items():
            text = str(value or "").strip()
            if _TOKEN.fullmatch(text) is None:
                raise AcquisitionEvidenceError(f"{name}_invalid")
            normalized[name] = text
        if not isinstance(identity.cursor_epoch, UUID):
            raise AcquisitionEvidenceError("cursor_epoch_invalid")
        start = int(identity.cursor_start_byte_offset)
        ordinal = int(identity.batch_record_ordinal)
        if start < 0:
            raise AcquisitionEvidenceError("cursor_start_byte_offset_invalid")
        if ordinal < 0:
            raise AcquisitionEvidenceError("batch_record_ordinal_invalid")
        return AcquisitionEvidenceIdentity(
            source_instance_id=normalized["source_instance_id"],
            stream_id=normalized["stream_id"],
            transport_binding=normalized["transport_binding"],
            cursor_epoch=identity.cursor_epoch,
            file_generation=normalized["file_generation"],
            cursor_start_byte_offset=start,
            batch_record_ordinal=ordinal,
        )

"""Atomic archive publication and verified lookup for Storage V2.

The filesystem and PostgreSQL cannot share one transaction.  This module makes
that boundary explicit: a block is written and verified locally, registered as
staging, atomically renamed on the same volume, and only then marked published.
Only published blocks may be served.
"""
from __future__ import annotations

import gzip
import json
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Protocol, Sequence

from server.sli.storage.atomic_object_store import (
    AtomicObjectError,
    AtomicObjectIntegrityError,
    AtomicObjectStore,
    sha256_hex,
)
from server.sli.storage.storage_v2_models import canonical_json_bytes

ARCHIVE_STATES = ("staging", "verified", "published", "quarantined")
ARCHIVE_KINDS = ("event", "link_detail", "entity_detail")


class ArchiveError(RuntimeError):
    pass


class ArchiveIntegrityError(ArchiveError):
    pass


class ArchiveBlockUnavailableError(FileNotFoundError, KeyError):
    """No published source; retain KeyError compatibility for semantic hydration."""


class ArchiveObjectUnavailableError(ArchiveIntegrityError):
    """The archive object path is refused before any read (outside the root).

    The object is never opened, so nothing forged can be returned; callers may
    degrade to the verified PostgreSQL core. Hash/identity mismatches stay plain
    ``ArchiveIntegrityError`` and keep failing closed.
    """


@dataclass(frozen=True)
class ArchiveBlock:
    archive_set_id: str
    archive_kind: str
    format_version: int
    block_index: int
    first_event_id: int
    last_event_id: int
    row_count: int
    raw_bytes: int
    compressed_bytes: int
    raw_sha256: str
    archive_sha256: str
    object_location: str
    state: str = "staging"
    created_at: str = ""
    verified_at: str | None = None
    published_at: str | None = None
    quarantine_reason: str | None = None

    @property
    def identity(self) -> tuple[str, str, int]:
        return self.archive_set_id, self.archive_kind, self.block_index

    def public_dict(self) -> dict[str, Any]:
        return {
            "archive_set_id": self.archive_set_id,
            "archive_kind": self.archive_kind,
            "format_version": self.format_version,
            "block_index": self.block_index,
            "first_event_id": self.first_event_id,
            "last_event_id": self.last_event_id,
            "row_count": self.row_count,
            "raw_bytes": self.raw_bytes,
            "compressed_bytes": self.compressed_bytes,
            "raw_sha256": self.raw_sha256,
            "archive_sha256": self.archive_sha256,
            "object_location": self.object_location,
            "state": self.state,
            "created_at": self.created_at,
            "verified_at": self.verified_at,
            "published_at": self.published_at,
            "quarantine_reason": self.quarantine_reason,
        }


class ArchiveManifestStore(Protocol):
    def ensure_set(self, archive_set_id: str, archive_kind: str, first_event_id: int, last_event_id: int, expected_rows: int, format_version: int) -> None: ...
    def get(self, identity: tuple[str, str, int]) -> ArchiveBlock | None: ...
    def stage(self, block: ArchiveBlock) -> ArchiveBlock: ...
    def mark_published(self, identity: tuple[str, str, int]) -> ArchiveBlock: ...
    def quarantine(self, identity: tuple[str, str, int], reason: str) -> ArchiveBlock: ...
    def find_published(self, archive_kind: str, event_id: int) -> ArchiveBlock | None: ...
    def find_published_many(
        self, archive_kind: str, event_ids: Sequence[int], limit: int
    ) -> list[ArchiveBlock]: ...
    def find_published_range(
        self, archive_kind: str, min_event_id: int, max_event_id: int, limit: int
    ) -> list[ArchiveBlock]: ...


class InMemoryArchiveManifestStore:
    """Deterministic manifest store used by source-only tests and simulations."""

    def __init__(self) -> None:
        self._sets: dict[str, dict[str, Any]] = {}
        self._blocks: dict[tuple[str, str, int], ArchiveBlock] = {}

    def ensure_set(self, archive_set_id: str, archive_kind: str, first_event_id: int, last_event_id: int, expected_rows: int, format_version: int) -> None:
        existing = self._sets.get(archive_set_id)
        payload = {"archive_kind": archive_kind, "first_event_id": int(first_event_id), "last_event_id": int(last_event_id), "expected_rows": int(expected_rows), "format_version": int(format_version), "state": "staging"}
        contract = {key: value for key, value in payload.items() if key != "state"}
        if existing is not None:
            existing_contract = {key: value for key, value in existing.items() if key != "state"}
            if existing_contract != contract:
                raise ArchiveIntegrityError("archive set identity was reused with a different contract")
            return
        self._sets[archive_set_id] = payload

    def get(self, identity: tuple[str, str, int]) -> ArchiveBlock | None:
        return self._blocks.get(identity)

    def stage(self, block: ArchiveBlock) -> ArchiveBlock:
        existing = self._blocks.get(block.identity)
        if existing and existing.state == "quarantined":
            raise ArchiveIntegrityError("quarantined archive identity cannot be restaged")
        if existing and existing.archive_sha256 != block.archive_sha256:
            raise ArchiveIntegrityError("archive identity already exists with a different SHA-256")
        staged = replace(block, state="staging")
        self._blocks[block.identity] = staged
        return staged

    def mark_published(self, identity: tuple[str, str, int]) -> ArchiveBlock:
        block = self._blocks[identity]
        if block.state == "quarantined":
            raise ArchiveIntegrityError("quarantined archive block cannot be published")
        published = replace(
            block,
            state="published",
            verified_at=block.verified_at or _utc_now(),
            published_at=_utc_now(),
            quarantine_reason=None,
        )
        self._blocks[identity] = published
        self._sets[published.archive_set_id]["state"] = "published"
        return published

    def quarantine(self, identity: tuple[str, str, int], reason: str) -> ArchiveBlock:
        block = self._blocks[identity]
        quarantined = replace(block, state="quarantined", quarantine_reason=reason)
        self._blocks[identity] = quarantined
        self._sets[quarantined.archive_set_id]["state"] = "quarantined"
        return quarantined

    def find_published(self, archive_kind: str, event_id: int) -> ArchiveBlock | None:
        matches = [
            block
            for block in self._blocks.values()
            if block.archive_kind == archive_kind
            and block.state == "published"
            and block.first_event_id <= event_id <= block.last_event_id
        ]
        if not matches:
            return None
        matches.sort(key=lambda item: (item.first_event_id, item.block_index), reverse=True)
        return matches[0]

    def find_published_many(
        self, archive_kind: str, event_ids: Sequence[int], limit: int
    ) -> list[ArchiveBlock]:
        blocks: dict[tuple[str, str, int], ArchiveBlock] = {}
        for event_id in dict.fromkeys(int(value) for value in event_ids if int(value) > 0):
            block = self.find_published(archive_kind, event_id)
            if block is not None:
                blocks[block.identity] = block
            if len(blocks) >= int(limit):
                break
        return list(blocks.values())

    def find_published_range(
        self, archive_kind: str, min_event_id: int, max_event_id: int, limit: int
    ) -> list[ArchiveBlock]:
        matches = [
            block
            for block in self._blocks.values()
            if block.archive_kind == archive_kind
            and block.state == "published"
            and block.last_event_id >= int(min_event_id)
            and block.first_event_id <= int(max_event_id)
        ]
        matches.sort(
            key=lambda item: (
                item.first_event_id,
                item.last_event_id,
                item.archive_set_id,
                item.block_index,
            )
        )
        return matches[: int(limit)]

    def blocks(self) -> list[ArchiveBlock]:
        return sorted(self._blocks.values(), key=lambda item: item.identity)

    def archive_set(self, archive_set_id: str) -> Mapping[str, Any]:
        return dict(self._sets[archive_set_id])


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(data: bytes) -> str:
    return sha256_hex(data).upper()


def _gzip_deterministic(raw: bytes) -> bytes:
    return gzip.compress(raw, compresslevel=6, mtime=0)


class ArchivePublisher:
    def __init__(self, root: Path, manifest: ArchiveManifestStore) -> None:
        self.root = Path(root)
        if not self.root.is_absolute():
            raise ArchiveError("archive root must be absolute")
        self.manifest = manifest
        try:
            self._objects = AtomicObjectStore(self.root)
        except AtomicObjectError as exc:
            raise ArchiveError(str(exc)) from exc
        self.staging = self._objects.staging
        self.published = self._objects.published
        self.quarantine_dir = self._objects.quarantine

    def publish_rows(
        self,
        *,
        archive_set_id: str,
        archive_kind: str,
        block_index: int,
        rows: Sequence[Mapping[str, Any]],
        event_id_field: str = "id",
        format_version: int = 1,
    ) -> ArchiveBlock:
        if archive_kind not in ARCHIVE_KINDS:
            raise ArchiveError(f"unsupported archive kind: {archive_kind}")
        if not rows:
            raise ArchiveError("archive block cannot be empty")
        try:
            uuid.UUID(str(archive_set_id))
        except ValueError as exc:
            raise ArchiveError("archive_set_id must be a UUID") from exc

        ordered = sorted(
            rows,
            key=lambda item: (
                int(item[event_id_field]),
                canonical_json_bytes(dict(item)),
            ),
        )
        ids = [int(item[event_id_field]) for item in ordered]
        if archive_kind == "event" and len(ids) != len(set(ids)):
            raise ArchiveError("event archive block contains duplicate event identifiers")
        raw = b"".join(
            canonical_json_bytes({"kind": archive_kind, "row": dict(row)}) + b"\n"
            for row in ordered
        )
        compressed = _gzip_deterministic(raw)
        raw_sha = _sha256(raw)
        archive_sha = _sha256(compressed)
        filename = (
            f"{archive_kind}-{archive_set_id}-{block_index:08d}-"
            f"{ids[0]}-{ids[-1]}-{archive_sha[:16]}.jsonl.gz"
        )
        final_path = self.published / filename
        identity = (str(archive_set_id), archive_kind, int(block_index))

        self.manifest.ensure_set(str(archive_set_id), archive_kind, ids[0], ids[-1], len(ordered), int(format_version))
        existing = self.manifest.get(identity)
        if existing is not None:
            if existing.state == "quarantined":
                raise ArchiveIntegrityError(
                    "quarantined archive identity requires explicit operator recovery"
                )
            if existing.archive_sha256 != archive_sha:
                raise ArchiveIntegrityError("retry produced a different archive SHA-256")
            if existing.state == "published":
                self.verify_file(existing)
                return existing
            if final_path.exists():
                candidate = replace(existing, object_location=str(final_path))
                self.verify_file(candidate)
                return self.manifest.mark_published(identity)

        try:
            prepared = self._objects.prepare(
                filename,
                compressed,
                expected_sha256=archive_sha,
            )
        except AtomicObjectIntegrityError as exc:
            raise ArchiveIntegrityError(str(exc)) from exc
        except AtomicObjectError as exc:
            raise ArchiveError(str(exc)) from exc

        restored = gzip.decompress(prepared.readable_path.read_bytes())
        if _sha256(restored) != raw_sha or restored != raw:
            raise ArchiveIntegrityError("archive round-trip verification failed")

        block = ArchiveBlock(
            archive_set_id=str(archive_set_id),
            archive_kind=archive_kind,
            format_version=int(format_version),
            block_index=int(block_index),
            first_event_id=ids[0],
            last_event_id=ids[-1],
            row_count=len(ordered),
            raw_bytes=len(raw),
            compressed_bytes=len(compressed),
            raw_sha256=raw_sha,
            archive_sha256=archive_sha,
            object_location=str(final_path),
            state="staging",
            created_at=_utc_now(),
            verified_at=_utc_now(),
        )
        self.manifest.stage(block)
        try:
            self._objects.publish(prepared)
        except AtomicObjectIntegrityError as exc:
            raise ArchiveIntegrityError(str(exc)) from exc
        except AtomicObjectError as exc:
            raise ArchiveError(str(exc)) from exc
        try:
            published = self.manifest.mark_published(identity)
        except Exception:
            # The immutable file is safe; a retry can verify and complete manifest publication.
            raise
        self.verify_file(published)
        return published

    def verify_file(self, block: ArchiveBlock) -> None:
        path = Path(block.object_location)
        if block.state != "published" and not path.exists():
            raise ArchiveIntegrityError("archive file is not published")
        if not path.is_file():
            raise ArchiveIntegrityError("archive file is missing")
        compressed = path.read_bytes()
        if len(compressed) != block.compressed_bytes or _sha256(compressed) != block.archive_sha256:
            raise ArchiveIntegrityError("archive compressed SHA-256 mismatch")
        raw = gzip.decompress(compressed)
        if len(raw) != block.raw_bytes or _sha256(raw) != block.raw_sha256:
            raise ArchiveIntegrityError("archive raw SHA-256 mismatch")


class ArchiveReader:
    def __init__(self, manifest: ArchiveManifestStore, archive_root: Path | None = None) -> None:
        self.manifest = manifest
        self.archive_root = Path(archive_root).resolve() if archive_root is not None else None

    def read_event(self, *, archive_kind: str, event_id: int) -> Mapping[str, Any]:
        rows = self.read_rows_for_event(archive_kind=archive_kind, event_id=event_id)
        if archive_kind != "event":
            raise ArchiveIntegrityError(
                "read_event is only valid for canonical event archives; use read_rows_for_event"
            )
        if len(rows) != 1:
            raise ArchiveIntegrityError(
                f"event archive contains {len(rows)} rows for unique event {event_id}"
            )
        return rows[0]

    def read_rows_for_event(self, *, archive_kind: str, event_id: int) -> list[Mapping[str, Any]]:
        block = self.manifest.find_published(archive_kind, int(event_id))
        if block is None:
            # No published source is an availability failure. A missing row
            # inside a verified block remains a KeyError and fails closed.
            raise ArchiveBlockUnavailableError(f"published archive block not found for event {event_id}")
        if block.state != "published":
            raise ArchiveIntegrityError("only published archive blocks are readable")
        raw = self._read_verified_block(block)
        matches: list[Mapping[str, Any]] = []
        for line in raw.splitlines():
            payload = json.loads(line.decode("utf-8"))
            row = payload.get("row") or {}
            candidate = row.get("id", row.get("event_id"))
            if int(candidate) == int(event_id):
                matches.append(row)
        if not matches:
            raise KeyError(f"event {event_id} was not found inside its archive block")
        return matches

    def read_block_rows(self, block: ArchiveBlock) -> list[Mapping[str, Any]]:
        """Read and verify every row from one explicitly published manifest block."""
        raw = self._read_verified_block(block)
        rows: list[Mapping[str, Any]] = []
        for line in raw.splitlines():
            payload = json.loads(line.decode("utf-8"))
            if payload.get("kind") != block.archive_kind or not isinstance(payload.get("row"), Mapping):
                raise ArchiveIntegrityError("archive row envelope does not match its manifest kind")
            rows.append(payload["row"])
        if len(rows) != block.row_count:
            raise ArchiveIntegrityError("archive row count does not match its manifest")
        return rows

    def read_entity_details_many(
        self,
        entity_ids: Iterable[int],
        *,
        max_blocks: int = 8,
    ) -> dict[int, Mapping[str, Any]]:
        """Hydrate entity details through published manifest blocks with a hard block bound."""
        requested = {int(value) for value in entity_ids}
        if not requested:
            return {}
        if not 1 <= int(max_blocks) <= 64:
            raise ValueError("entity archive max_blocks must be between 1 and 64")
        blocks = self.manifest.find_published_range(
            "entity_detail",
            min(requested),
            max(requested),
            int(max_blocks) + 1,
        )
        if len(blocks) > int(max_blocks):
            raise ArchiveIntegrityError("entity archive hydration exceeds bounded block limit")
        hydrated: dict[int, Mapping[str, Any]] = {}
        for block in blocks:
            for row in self.read_block_rows(block):
                entity_id = int(row["id"])
                if entity_id in requested:
                    hydrated[entity_id] = row
        missing = sorted(requested - hydrated.keys())
        if missing:
            raise KeyError(f"entity archive is missing requested identities: {missing[:5]}")
        return hydrated

    def read_link_details_many(
        self,
        event_ids: Iterable[int],
        *,
        max_blocks: int = 8,
    ) -> dict[int, list[Mapping[str, Any]]]:
        """Hydrate link details for many events while reading each block once."""
        requested = {int(value) for value in event_ids}
        if not requested:
            return {}
        if not 1 <= int(max_blocks) <= 64:
            raise ValueError("link detail archive max_blocks must be between 1 and 64")
        blocks = self.manifest.find_published_range(
            "link_detail",
            min(requested),
            max(requested),
            int(max_blocks) + 1,
        )
        if len(blocks) > int(max_blocks):
            raise ArchiveIntegrityError(
                "link detail archive hydration exceeds bounded block limit"
            )
        hydrated: dict[int, list[Mapping[str, Any]]] = {}
        for block in blocks:
            for row in self.read_block_rows(block):
                event_id = int(row["event_id"])
                if event_id in requested:
                    hydrated.setdefault(event_id, []).append(row)
        return hydrated

    def read_events_many(
        self,
        event_ids: Iterable[int],
        *,
        max_blocks: int = 8,
    ) -> dict[int, Mapping[str, Any]]:
        """Hydrate unique canonical events while reading each block once."""

        requested = {int(value) for value in event_ids}
        if not requested:
            return {}
        if not 1 <= int(max_blocks) <= 64:
            raise ValueError("event archive max_blocks must be between 1 and 64")
        blocks = self.manifest.find_published_range(
            "event",
            min(requested),
            max(requested),
            int(max_blocks) + 1,
        )
        if len(blocks) > int(max_blocks):
            raise ArchiveIntegrityError(
                "event archive hydration exceeds bounded block limit"
            )
        hydrated: dict[int, Mapping[str, Any]] = {}
        for block in blocks:
            for row in self.read_block_rows(block):
                event_id = int(row["id"])
                if event_id not in requested:
                    continue
                if event_id in hydrated:
                    raise ArchiveIntegrityError(
                        f"event archive contains duplicate event {event_id}"
                    )
                hydrated[event_id] = row
        missing = sorted(requested - hydrated.keys())
        if missing:
            raise KeyError(
                f"event archive is missing requested identities: {missing[:5]}"
            )
        return hydrated

    def search_events(
        self,
        *,
        term: str,
        min_event_id: int,
        max_event_id: int,
        max_blocks: int = 8,
        max_results: int = 100,
        fields: Sequence[str] = ("message_text", "event_data_json", "record_xml"),
    ) -> list[Mapping[str, Any]]:
        """Literal case-insensitive search over a strictly bounded archive range."""

        needle = str(term).strip().casefold()
        if len(needle) < 2:
            raise ValueError("archive search term must contain at least two characters")
        start, end = int(min_event_id), int(max_event_id)
        if start < 0 or end < start:
            raise ValueError("archive search requires a valid event id range")
        if not 1 <= int(max_blocks) <= 64:
            raise ValueError("archive search max_blocks must be between 1 and 64")
        if not 1 <= int(max_results) <= 1000:
            raise ValueError("archive search max_results must be between 1 and 1000")
        selected_fields = tuple(str(field) for field in fields)
        allowed_fields = {"message_text", "event_data_json", "record_xml"}
        if not selected_fields or not set(selected_fields).issubset(allowed_fields):
            raise ValueError("archive search fields are outside the approved payload contract")

        blocks = self.manifest.find_published_range("event", start, end, int(max_blocks) + 1)
        if len(blocks) > int(max_blocks):
            raise ValueError(
                "archive search range spans more than max_blocks; narrow the event range"
            )
        matches: dict[int, Mapping[str, Any]] = {}
        identities: dict[int, bytes] = {}
        for block in blocks:
            raw = self._read_verified_block(block)
            for line in raw.splitlines():
                payload = json.loads(line.decode("utf-8"))
                row = payload.get("row") or {}
                event_id = int(row.get("id"))
                if not start <= event_id <= end:
                    continue
                identity = canonical_json_bytes(row)
                existing_identity = identities.get(event_id)
                if existing_identity is not None and existing_identity != identity:
                    raise ArchiveIntegrityError(
                        f"published archives disagree for event {event_id}"
                    )
                identities[event_id] = identity
                haystack = "\n".join(
                    json.dumps(row.get(field), ensure_ascii=False, sort_keys=True)
                    if isinstance(row.get(field), (Mapping, list))
                    else str(row.get(field) or "")
                    for field in selected_fields
                ).casefold()
                if needle not in haystack:
                    continue
                matches[event_id] = row
        return [matches[event_id] for event_id in sorted(matches, reverse=True)[: int(max_results)]]

    def _read_verified_block(self, block: ArchiveBlock) -> bytes:
        if block.state != "published":
            raise ArchiveIntegrityError("only published archive blocks are readable")
        path = Path(block.object_location).resolve()
        if self.archive_root is not None:
            try:
                path.relative_to(self.archive_root)
            except ValueError as exc:
                raise ArchiveObjectUnavailableError("archive object is outside the configured root") from exc
        compressed = path.read_bytes()
        if len(compressed) != block.compressed_bytes or _sha256(compressed) != block.archive_sha256:
            raise ArchiveIntegrityError("archive compressed SHA-256 mismatch")
        raw = gzip.decompress(compressed)
        if len(raw) != block.raw_bytes or _sha256(raw) != block.raw_sha256:
            raise ArchiveIntegrityError("archive raw SHA-256 mismatch")
        return raw

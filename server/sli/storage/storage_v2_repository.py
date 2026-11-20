"""Storage V2 repository contracts and dormant PostgreSQL implementation.

No connection is opened at import time.  The PostgreSQL adapter receives an
already-created connection factory so canary launchers retain full control over
credentials, transaction boundaries, statement timeouts and rollback.
"""
from __future__ import annotations

import copy
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from time import sleep as _sleep
from typing import Any, Protocol

from server.sli.storage.storage_v2_archive import (
    ArchiveBlock,
    ArchiveIntegrityError,
    ArchiveManifestStore,
)
from server.sli.storage.storage_v2_link_blocks import (
    LinkBlock,
    LinkBlockError,
    append_link_block_tail,
    rebuild_link_block_suffix,
)
from server.sli.storage.storage_v2_models import (
    PROCESS_ACTIVITY_FACT_COLUMNS,
    EntityCoreV2,
    EventCoreV2,
    EventFactsV2,
    LinkCoreV2,
    parse_utc_timestamp,
)
from server.sli.storage.storage_v2_repository_columns import (  # noqa: F401
    ADDITIVE_EVENT_FACT_COLUMNS,
    ENTITY_V2_WRITE_COLUMNS,
    EVENT_FACTS_V2_WRITE_COLUMNS,
    EVENT_V2_WRITE_COLUMNS,
    _matches_event_replay,
    _matches_raw_file_reservation,
    _normalized_historical_fact_values,
    _postgres_jsonb,
    _schema_compatible_fact_columns,
    _validated_write_columns,
    events_by_id,
)
from server.sli.storage.storage_v2_repository_models import (  # noqa: F401
    DICTIONARY_TABLES,
    BackfillCheckpoint,
    BackfillChunkAudit,
    OutboxItem,
    _checkpoint_from_row,
    _outbox_from_row,
    _resolve_link_cores,
    _resolved_link_core,
    core_chunk_digest,
)


class SourceEventIdentityConflict(RuntimeError):
    """An immutable source key has a different retained representation."""

    def __init__(self, ordinal: int, *, published: bool = False, detail: str | None = None):
        self.ordinal = ordinal
        self.detail = detail
        self.reason = ("published_source_event_hash_mismatch" if published
                       else "source_event_allocation_hash_mismatch")
        prefix = "published " if published else ""
        super().__init__(f"{prefix}source event allocation hash mismatch at ordinal {ordinal}")


def _read_link_block_tails(cur, entity_ids: Sequence[int]) -> dict[int, LinkBlock]:
    # One backward primary-key lookup per entity, rather than reading every
    # historical block (including its arrays) before DISTINCT can discard it.
    cur.execute(
        "select tail.* from unnest(%s::integer[]) wanted(entity_id) "
        "cross join lateral (select entity_id,block_no,first_event_id,last_event_id,"
        "event_ids,role_ids,identity_sha256 from event_entity_link_blocks_v2 "
        "where entity_id=wanted.entity_id order by block_no desc limit 1) tail "
        "order by tail.entity_id", (list(entity_ids),),
    )
    tails = {}
    for row in cur.fetchall():
        event_ids = tuple(int(value) for value in row["event_ids"])
        if (not event_ids or int(row["first_event_id"]) != event_ids[0]
                or int(row["last_event_id"]) != event_ids[-1]):
            raise RuntimeError("stored link block first/last range mismatch")
        tails[int(row["entity_id"])] = LinkBlock(
            entity_id=int(row["entity_id"]), block_no=int(row["block_no"]),
            event_ids=event_ids, role_ids=tuple(int(value) for value in row["role_ids"]),
            identity_sha256=bytes(row["identity_sha256"]),
        )
    return tails


def _retry_lock_not_available(
    operation: Callable[[], Any],
    *,
    attempts: int = 3,
    sleep: Callable[[float], None] = _sleep,
) -> Any:
    """Retry one fresh transaction only for PostgreSQL lock timeout 55P03."""
    bounded_attempts = max(1, min(int(attempts), 5))
    for attempt in range(1, bounded_attempts + 1):
        try:
            return operation()
        except Exception as exc:
            if getattr(exc, "sqlstate", None) != "55P03" or attempt >= bounded_attempts:
                raise
            sleep(0.1 * attempt)
    raise AssertionError("unreachable lock retry state")




class StorageV2Repository(Protocol):
    def supports_process_activity_facts(self, *, cur: Any = None) -> bool: ...
    def dictionary_id(self, kind: str, value: str | None) -> int | None: ...
    def reserve_event_identities(
        self, events: Sequence[Mapping[str, Any]]
    ) -> list[Mapping[str, Any]]: ...
    def reserve_entity_identities(
        self, entities: Sequence[Mapping[str, Any]]
    ) -> list[Mapping[str, Any]]: ...
    def reserve_raw_log_file(
        self, *, server_id: int, log_source_id: int, file_path: str,
        sha256: str, size_bytes: int, file_format: str = "jsonl"
    ) -> Mapping[str, Any]: ...
    def get_checkpoint(self, worker_name: str) -> BackfillCheckpoint: ...
    def acquire_checkpoint(self, worker_name: str, token: str, lease_seconds: int) -> BackfillCheckpoint: ...
    def renew_checkpoint_lease(self, worker_name: str, token: str, lease_seconds: int) -> bool: ...
    def initialize_high_watermark(self, worker_name: str, token: str, high_watermark_event_id: int) -> BackfillCheckpoint: ...
    def fail_checkpoint(self, worker_name: str, token: str, error: str) -> BackfillCheckpoint: ...
    def complete_checkpoint(self, worker_name: str, token: str) -> BackfillCheckpoint: ...
    def write_verified_rows(
        self,
        *,
        cur: Any,
        events: Sequence[EventCoreV2],
        facts: Sequence[EventFactsV2],
        entities: Sequence[EntityCoreV2],
        links: Sequence[LinkCoreV2],
        verified_archive_links: Sequence[LinkCoreV2],
        source_sha256: bytes,
    ) -> bytes: ...
    def write_verified_chunk(
        self,
        *,
        worker_name: str,
        lease_token: str,
        high_watermark_event_id: int,
        start_event_id: int,
        end_event_id: int,
        next_chunk_size: int,
        events: Sequence[EventCoreV2],
        facts: Sequence[EventFactsV2],
        entities: Sequence[EntityCoreV2],
        links: Sequence[LinkCoreV2],
        verified_archive_links: Sequence[LinkCoreV2],
        source_rows: int,
        source_link_rows: int,
        source_sha256: bytes,
        archive_event_set_id: str,
        archive_link_set_id: str | None,
    ) -> BackfillCheckpoint: ...
    def enqueue_outbox(
        self,
        *,
        batch_id: str,
        first_event_id: int,
        last_event_id: int,
        event_count: int,
        event_ids: Sequence[int],
        identity_sha256: bytes,
    ) -> OutboxItem: ...
    def claim_outbox(self, token: str, lease_seconds: int) -> OutboxItem | None: ...
    def renew_outbox_lease(self, item_id: int, token: str, lease_seconds: int) -> bool: ...
    def complete_outbox(self, item_id: int, token: str) -> OutboxItem: ...
    def fail_outbox(self, item_id: int, token: str, error: str, retry_seconds: int) -> OutboxItem: ...
    def existing_published_source_event_ids(self, events: Sequence[Mapping[str, Any]]) -> set[int]: ...
    def record_shadow(self, payload: Mapping[str, Any]) -> None: ...


class InMemoryStorageV2Repository:
    """Transactional in-memory model for restart, idempotency and failure tests."""

    def __init__(self) -> None:
        self.dictionaries: dict[str, dict[str, int]] = {kind: {} for kind in DICTIONARY_TABLES}
        self.events: dict[int, EventCoreV2] = {}
        self.event_facts: dict[int, EventFactsV2] = {}
        self.entities: dict[int, EntityCoreV2] = {}
        self.links: dict[tuple[int, int, int], LinkCoreV2] = {}
        self.checkpoints: dict[str, BackfillCheckpoint] = {}
        self.outbox: dict[int, OutboxItem] = {}
        self.outbox_by_batch: dict[str, int] = {}
        self.shadow_results: list[dict[str, Any]] = []
        self.chunk_audits: list[BackfillChunkAudit] = []
        self._next_outbox_id = 1
        self.fail_next_chunk_write = False

    def supports_process_activity_facts(self, *, cur: Any = None) -> bool:
        return True

    def dictionary_id(self, kind: str, value: str | None) -> int | None:
        if value in (None, ""):
            return None
        if kind not in self.dictionaries:
            raise KeyError(f"unsupported dictionary kind: {kind}")
        text = str(value)
        mapping = self.dictionaries[kind]
        if text not in mapping:
            mapping[text] = len(mapping) + 1
        return mapping[text]

    def get_checkpoint(self, worker_name: str) -> BackfillCheckpoint:
        if worker_name not in self.checkpoints:
            self.checkpoints[worker_name] = BackfillCheckpoint(worker_name=worker_name)
        return self.checkpoints[worker_name]

    def acquire_checkpoint(self, worker_name: str, token: str, lease_seconds: int) -> BackfillCheckpoint:
        current = self.get_checkpoint(worker_name)
        now = datetime.now(timezone.utc)
        if current.lease_token and current.lease_until and current.lease_until > now and current.lease_token != token:
            raise RuntimeError("backfill checkpoint is leased by another worker")
        updated = replace(
            current,
            state="running",
            lease_token=token,
            lease_until=now + timedelta(seconds=max(1, lease_seconds)),
            last_error=None,
        )
        self.checkpoints[worker_name] = updated
        return updated

    def renew_checkpoint_lease(self, worker_name: str, token: str, lease_seconds: int) -> bool:
        """Extend an already-held checkpoint lease; a no-op (returns False) once lost.

        A best-effort heartbeat, not a correctness gate: the actual writes in
        write_verified_chunk/complete_checkpoint/fail_checkpoint independently
        re-check the lease token and fail loudly on mismatch regardless of
        whether renewal happened. This only prevents the lease from expiring
        out from under a worker that is still alive and making progress.
        """
        current = self.checkpoints.get(worker_name)
        if current is None or current.lease_token != token:
            return False
        updated = replace(current, lease_until=datetime.now(timezone.utc) + timedelta(seconds=max(1, lease_seconds)))
        self.checkpoints[worker_name] = updated
        return True

    def initialize_high_watermark(self, worker_name: str, token: str, high_watermark_event_id: int) -> BackfillCheckpoint:
        current = self.get_checkpoint(worker_name)
        if current.lease_token != token:
            raise RuntimeError("checkpoint lease token mismatch")
        requested = int(high_watermark_event_id)
        if current.high_watermark_event_id is not None and current.high_watermark_event_id != requested:
            return current
        updated = replace(current, high_watermark_event_id=requested)
        self.checkpoints[worker_name] = updated
        return updated

    def fail_checkpoint(self, worker_name: str, token: str, error: str) -> BackfillCheckpoint:
        current = self.get_checkpoint(worker_name)
        if current.lease_token != token:
            raise RuntimeError("checkpoint lease token mismatch")
        updated = replace(current, state="failed", lease_token=None, lease_until=None, last_error=str(error)[:2000])
        self.checkpoints[worker_name] = updated
        return updated

    def complete_checkpoint(self, worker_name: str, token: str) -> BackfillCheckpoint:
        current = self.get_checkpoint(worker_name)
        if current.lease_token != token:
            raise RuntimeError("checkpoint lease token mismatch")
        updated = replace(current, state="completed", lease_token=None, lease_until=None, last_error=None)
        self.checkpoints[worker_name] = updated
        return updated

    def write_verified_chunk(
        self,
        *,
        worker_name: str,
        lease_token: str,
        high_watermark_event_id: int,
        start_event_id: int,
        end_event_id: int,
        next_chunk_size: int,
        events: Sequence[EventCoreV2],
        facts: Sequence[EventFactsV2],
        entities: Sequence[EntityCoreV2],
        links: Sequence[LinkCoreV2],
        verified_archive_links: Sequence[LinkCoreV2],
        source_rows: int,
        source_link_rows: int,
        source_sha256: bytes,
        archive_event_set_id: str,
        archive_link_set_id: str | None,
    ) -> BackfillCheckpoint:
        current = self.get_checkpoint(worker_name)
        if current.lease_token != lease_token:
            raise RuntimeError("checkpoint lease token mismatch")
        snapshot = (
            copy.deepcopy(self.events), copy.deepcopy(self.event_facts), copy.deepcopy(self.entities),
            copy.deepcopy(self.links), copy.deepcopy(self.chunk_audits), current
        )
        try:
            for item in events:
                event_id = int(item.values["id"])
                existing = self.events.get(event_id)
                if existing and existing.source_core_sha256 != item.source_core_sha256:
                    raise RuntimeError(f"event {event_id} idempotency hash mismatch")
                self.events[event_id] = item
            for item in facts:
                event_id = int(item.values["event_id"])
                if event_id not in self.events:
                    raise RuntimeError(f"event facts {event_id} has no V2 core row")
                existing = self.event_facts.get(event_id)
                if existing and existing.source_facts_sha256 != item.source_facts_sha256:
                    raise RuntimeError(f"event facts {event_id} idempotency hash mismatch")
                self.event_facts[event_id] = item
            for item in entities:
                entity_id = int(item.values["id"])
                existing = self.entities.get(entity_id)
                if existing:
                    existing_identity = (
                        existing.values.get("entity_type_id"),
                        existing.values.get("natural_key"),
                    )
                    incoming_identity = (
                        item.values.get("entity_type_id"),
                        item.values.get("natural_key"),
                    )
                    if existing_identity != incoming_identity:
                        raise RuntimeError(f"entity {entity_id} identity mismatch")
                self.entities[entity_id] = item
            for item in links:
                key = (int(item.values["event_id"]), int(item.values["entity_id"]), int(item.values["role_id"]))
                existing = self.links.get(key)
                if existing and existing.source_core_sha256 != item.source_core_sha256:
                    raise RuntimeError(f"link {key} idempotency hash mismatch")
                self.links[key] = item
            if self.fail_next_chunk_write:
                self.fail_next_chunk_write = False
                raise RuntimeError("injected chunk transaction failure")
            target_sha256 = core_chunk_digest(
                [self.events[int(item.values["id"])] for item in events],
                [self.entities[int(item.values["id"])] for item in entities],
                list(verified_archive_links),
                [self.event_facts[int(item.values["event_id"])] for item in facts],
            )
            if target_sha256 != bytes(source_sha256):
                raise RuntimeError("verified chunk semantic hash mismatch")
            self.chunk_audits.append(BackfillChunkAudit(
                worker_name=worker_name,
                chunk_start_event_id=int(start_event_id),
                chunk_end_event_id=int(end_event_id),
                source_event_rows=int(source_rows),
                target_event_rows=len(events),
                source_link_rows=int(source_link_rows),
                target_link_rows=len(links),
                source_sha256=bytes(source_sha256),
                target_sha256=target_sha256,
                archive_event_set_id=str(archive_event_set_id),
                archive_link_set_id=str(archive_link_set_id) if archive_link_set_id else None,
            ))
            updated = replace(
                current,
                high_watermark_event_id=int(high_watermark_event_id),
                last_verified_event_id=int(end_event_id),
                chunk_size=int(next_chunk_size),
                state="ready",
                lease_token=None,
                lease_until=None,
                source_rows=current.source_rows + int(source_rows),
                target_rows=current.target_rows + len(events),
                last_error=None,
            )
            self.checkpoints[worker_name] = updated
            return updated
        except Exception:
            (
                self.events, self.event_facts, self.entities, self.links,
                self.chunk_audits, self.checkpoints[worker_name],
            ) = snapshot
            raise

    def enqueue_outbox(
        self,
        *,
        batch_id: str,
        first_event_id: int,
        last_event_id: int,
        event_count: int,
        event_ids: Sequence[int],
        identity_sha256: bytes,
    ) -> OutboxItem:
        ordered_ids = tuple(int(value) for value in event_ids)
        if not ordered_ids or tuple(sorted(set(ordered_ids))) != ordered_ids:
            raise ValueError("outbox event_ids must be sorted and unique")
        if len(ordered_ids) != int(event_count):
            raise ValueError("outbox event_count does not match event_ids")
        if ordered_ids[0] != int(first_event_id) or ordered_ids[-1] != int(last_event_id):
            raise ValueError("outbox range does not match event_ids")
        existing_id = self.outbox_by_batch.get(batch_id)
        if existing_id is not None:
            existing = self.outbox[existing_id]
            if existing.identity_sha256 != identity_sha256 or existing.event_ids != ordered_ids:
                raise RuntimeError("outbox batch id was reused with a different identity hash")
            return existing
        item = OutboxItem(
            id=self._next_outbox_id,
            batch_id=str(batch_id),
            first_event_id=int(first_event_id),
            last_event_id=int(last_event_id),
            event_count=int(event_count),
            event_ids=ordered_ids,
            identity_sha256=bytes(identity_sha256),
            available_at=datetime.now(timezone.utc),
        )
        self._next_outbox_id += 1
        self.outbox[item.id] = item
        self.outbox_by_batch[item.batch_id] = item.id
        return item

    def claim_outbox(self, token: str, lease_seconds: int) -> OutboxItem | None:
        now = datetime.now(timezone.utc)
        eligible = [
            item for item in self.outbox.values()
            if (
                (item.state in {"pending", "failed"} and item.available_at <= now)
                or (item.state == "leased" and (item.lease_until is None or item.lease_until <= now))
            )
        ]
        if not eligible:
            return None
        item = min(eligible, key=lambda value: value.id)
        leased = replace(
            item,
            state="leased",
            attempt_count=item.attempt_count + 1,
            lease_token=token,
            lease_until=now + timedelta(seconds=max(1, lease_seconds)),
        )
        self.outbox[item.id] = leased
        return leased

    def renew_outbox_lease(self, item_id: int, token: str, lease_seconds: int) -> bool:
        """Extend an already-held outbox lease; a no-op (returns False) once lost.

        Same best-effort contract as renew_checkpoint_lease -- complete_outbox/
        fail_outbox independently re-check the lease token regardless.
        """
        item = self.outbox.get(int(item_id))
        if item is None or item.state != "leased" or item.lease_token != token:
            return False
        renewed = replace(item, lease_until=datetime.now(timezone.utc) + timedelta(seconds=max(1, lease_seconds)))
        self.outbox[item.id] = renewed
        return True

    def complete_outbox(self, item_id: int, token: str) -> OutboxItem:
        item = self.outbox[int(item_id)]
        if item.state == "completed":
            return item
        if item.lease_token != token:
            raise RuntimeError("outbox lease token mismatch")
        completed = replace(item, state="completed", lease_token=None, lease_until=None, last_error=None)
        self.outbox[item.id] = completed
        return completed

    def fail_outbox(self, item_id: int, token: str, error: str, retry_seconds: int) -> OutboxItem:
        item = self.outbox[int(item_id)]
        if item.lease_token != token:
            raise RuntimeError("outbox lease token mismatch")
        failed = replace(
            item,
            state="failed",
            lease_token=None,
            lease_until=None,
            last_error=str(error)[:2000],
            available_at=datetime.now(timezone.utc) + timedelta(seconds=max(1, retry_seconds)),
        )
        self.outbox[item.id] = failed
        return failed

    def existing_published_source_event_ids(self, events: Sequence[Mapping[str, Any]]) -> set[int]:
        # The in-memory adapter stores a single authoritative copy per test
        # event id; its normal unit paths never have staging-id replays.
        return set()

    def record_shadow(self, payload: Mapping[str, Any]) -> None:
        self.shadow_results.append(dict(payload))


class PostgresArchiveManifestStore(ArchiveManifestStore):
    """Manifest adapter using a caller-owned connection factory."""

    def __init__(self, connect: Callable[[], Any]) -> None:
        self._connect = connect

    @staticmethod
    def _from_row(row: Mapping[str, Any]) -> ArchiveBlock:
        return ArchiveBlock(
            archive_set_id=str(row["archive_set_id"]),
            archive_kind=str(row["archive_kind"]),
            format_version=int(row["format_version"]),
            block_index=int(row["block_index"]),
            first_event_id=int(row["first_event_id"]),
            last_event_id=int(row["last_event_id"]),
            row_count=int(row["row_count"]),
            raw_bytes=int(row["raw_bytes"]),
            compressed_bytes=int(row["compressed_bytes"]),
            raw_sha256=bytes(row["raw_sha256"]).hex().upper(),
            archive_sha256=bytes(row["archive_sha256"]).hex().upper(),
            object_location=str(row["object_location"]),
            state=str(row["state"]),
            created_at=str(row["created_at"]),
            verified_at=str(row["verified_at"]) if row.get("verified_at") else None,
            published_at=str(row["published_at"]) if row.get("published_at") else None,
            quarantine_reason=row.get("quarantine_reason"),
        )

    def ensure_set(self, archive_set_id: str, archive_kind: str, first_event_id: int, last_event_id: int, expected_rows: int, format_version: int) -> None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                insert into storage_v2_archive_sets(archive_set_id,archive_kind,format_version,source_min_event_id,source_max_event_id,expected_rows,state)
                values (%s,%s,%s,%s,%s,%s,'staging')
                on conflict(archive_set_id) do update set archive_set_id=excluded.archive_set_id
                returning archive_kind,format_version,source_min_event_id,source_max_event_id,expected_rows
                """,
                (archive_set_id,archive_kind,int(format_version),int(first_event_id),int(last_event_id),int(expected_rows)),
            )
            row = cur.fetchone()
            expected = (archive_kind,int(format_version),int(first_event_id),int(last_event_id),int(expected_rows))
            actual = (str(row["archive_kind"]),int(row["format_version"]),int(row["source_min_event_id"]),int(row["source_max_event_id"]),int(row["expected_rows"]))
            if actual != expected:
                raise RuntimeError("archive set identity conflict")

    def get(self, identity: tuple[str, str, int]) -> ArchiveBlock | None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "select * from storage_v2_archive_blocks where archive_set_id=%s and archive_kind=%s and block_index=%s",
                identity,
            )
            row = cur.fetchone()
        return self._from_row(row) if row else None

    def stage(self, block: ArchiveBlock) -> ArchiveBlock:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                insert into storage_v2_archive_blocks(
                    archive_set_id,archive_kind,format_version,block_index,first_event_id,last_event_id,
                    row_count,raw_bytes,compressed_bytes,raw_sha256,archive_sha256,object_location,
                    state,created_at,verified_at
                ) values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'staging',%s,%s)
                on conflict(archive_set_id,archive_kind,block_index) do update set
                    raw_bytes=excluded.raw_bytes,compressed_bytes=excluded.compressed_bytes,
                    raw_sha256=excluded.raw_sha256,archive_sha256=excluded.archive_sha256,
                    object_location=excluded.object_location,verified_at=excluded.verified_at
                where storage_v2_archive_blocks.archive_sha256=excluded.archive_sha256
                returning *
                """,
                (
                    block.archive_set_id, block.archive_kind, block.format_version, block.block_index,
                    block.first_event_id, block.last_event_id, block.row_count, block.raw_bytes,
                    block.compressed_bytes, bytes.fromhex(block.raw_sha256), bytes.fromhex(block.archive_sha256),
                    block.object_location, block.created_at, block.verified_at,
                ),
            )
            row = cur.fetchone()
            if not row:
                raise RuntimeError("archive manifest identity conflict")
        return self._from_row(row)

    def mark_published(self, identity: tuple[str, str, int]) -> ArchiveBlock:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                update storage_v2_archive_blocks
                set state='published',published_at=coalesce(published_at,now()),quarantine_reason=null
                where archive_set_id=%s and archive_kind=%s and block_index=%s
                  and state in ('staging','verified','published')
                returning *
                """,
                identity,
            )
            row = cur.fetchone()
            if not row:
                raise ArchiveIntegrityError("archive block is missing or quarantined")
            cur.execute(
                """
                update storage_v2_archive_sets
                set state='published',verified_at=coalesce(verified_at,now()),
                    published_at=coalesce(published_at,now())
                where archive_set_id=%s
                """,
                (identity[0],),
            )
        return self._from_row(row)

    def quarantine(self, identity: tuple[str, str, int], reason: str) -> ArchiveBlock:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                update storage_v2_archive_blocks
                set state='quarantined',quarantine_reason=%s
                where archive_set_id=%s and archive_kind=%s and block_index=%s
                returning *
                """,
                (str(reason)[:2000], *identity),
            )
            row = cur.fetchone()
            if not row:
                raise KeyError(identity)
            cur.execute(
                "update storage_v2_archive_sets set state='quarantined' where archive_set_id=%s",
                (identity[0],),
            )
        return self._from_row(row)

    def find_published(self, archive_kind: str, event_id: int) -> ArchiveBlock | None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                select * from storage_v2_archive_blocks
                where archive_kind=%s and state='published' and first_event_id<=%s and last_event_id>=%s
                order by first_event_id desc,block_index desc limit 1
                """,
                (archive_kind, int(event_id), int(event_id)),
            )
            row = cur.fetchone()
        return self._from_row(row) if row else None

    def find_published_many(
        self, archive_kind: str, event_ids: Sequence[int], limit: int
    ) -> list[ArchiveBlock]:
        unique_ids = list(dict.fromkeys(int(value) for value in event_ids if int(value) > 0))
        if not unique_ids or int(limit) <= 0:
            return []
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                with requested(event_id, ordinal) as (
                    select event_id, ordinal
                    from unnest(%s::bigint[]) with ordinality as requested(event_id, ordinal)
                )
                select distinct on (requested.ordinal) archive_block.*
                from requested
                join storage_v2_archive_blocks archive_block
                  on archive_block.archive_kind=%s
                 and archive_block.state='published'
                 and archive_block.first_event_id<=requested.event_id
                 and archive_block.last_event_id>=requested.event_id
                order by requested.ordinal, archive_block.first_event_id desc, archive_block.block_index desc
                """,
                (unique_ids, archive_kind),
            )
            rows = cur.fetchall()
        blocks: dict[tuple[str, str, int], ArchiveBlock] = {}
        for row in rows:
            block = self._from_row(row)
            blocks[block.identity] = block
            if len(blocks) >= int(limit):
                break
        return list(blocks.values())

    def find_published_range(
        self, archive_kind: str, min_event_id: int, max_event_id: int, limit: int
    ) -> list[ArchiveBlock]:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                select * from storage_v2_archive_blocks
                where archive_kind=%s and state='published'
                  and last_event_id>=%s and first_event_id<=%s
                order by first_event_id, last_event_id, archive_set_id, block_index
                limit %s
                """,
                (archive_kind, int(min_event_id), int(max_event_id), int(limit)),
            )
            rows = cur.fetchall()
        return [self._from_row(row) for row in rows]




class PostgresStorageV2Repository:
    """Parameterized SQL adapter.  It never creates a connection on its own."""

    def __init__(
        self,
        connect: Callable[[], Any],
        *,
        failpoint: Callable[[str], None] | None = None,
        semantic_publisher: (
            Callable[[Any, Sequence[int]], Mapping[str, Any]] | None
        ) = None,
    ) -> None:
        self._connect = connect
        self._failpoint = failpoint
        self._semantic_publisher = semantic_publisher
        self._dictionary_ids: dict[tuple[str, str], int] = {}

    def supports_process_activity_facts(self, *, cur: Any = None) -> bool:
        """Read the actual schema once per batch, using the ingest transaction.

        No migration or long-lived capability cache: the next batch observes an
        admitted migration, while missing base columns and partial 089 fail closed.
        """
        if cur is None:
            with self._connect() as conn, conn.cursor() as own_cur:
                return self.supports_process_activity_facts(cur=own_cur)
        cur.execute(
            "select column_name from information_schema.columns "
            "where table_schema=current_schema() and table_name='event_facts_v2'"
        )
        available = {str(row["column_name"]) for row in cur.fetchall()}
        missing = EVENT_FACTS_V2_WRITE_COLUMNS - available
        if missing - PROCESS_ACTIVITY_FACT_COLUMNS:
            raise RuntimeError(f"event facts schema mismatch; missing={sorted(missing)}")
        present_process = PROCESS_ACTIVITY_FACT_COLUMNS & available
        if present_process and present_process != PROCESS_ACTIVITY_FACT_COLUMNS:
            raise RuntimeError("event facts schema mismatch; partial migration 089")
        return bool(present_process)

    def dictionary_id(self, kind: str, value: str | None) -> int | None:
        if value in (None, ""):
            return None
        table = DICTIONARY_TABLES.get(kind)
        if table is None:
            raise KeyError(f"unsupported dictionary kind: {kind}")
        normalized = str(value)
        cache_key = (kind, normalized)
        cached = self._dictionary_ids.get(cache_key)
        if cached is not None:
            return cached
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(f"select id from {table} where value=%s", (normalized,))
            row = cur.fetchone()
            if row is None:
                cur.execute(
                    f"insert into {table}(value) values (%s) "
                    "on conflict(value) do nothing returning id",
                    (normalized,),
                )
                row = cur.fetchone()
                if row is None:
                    cur.execute(f"select id from {table} where value=%s", (normalized,))
                    row = cur.fetchone()
            if row is None:
                raise RuntimeError(f"dictionary identity unresolved: {kind}")
            dictionary_id = int(row["id"])
        self._dictionary_ids[cache_key] = dictionary_id
        return dictionary_id

    def dictionary_maps(self, values: Mapping[str, set[str]]) -> dict[str, dict[str, int]]:
        """Resolve a publication's dictionaries with one committed connection."""
        missing = {}
        for kind, items in values.items():
            if kind not in DICTIONARY_TABLES:
                raise KeyError(f"unsupported dictionary kind: {kind}")
            pending = sorted(value for value in items if (kind, value) not in self._dictionary_ids)
            if pending:
                missing[kind] = pending
        resolved = {}
        if missing:
            with self._connect() as conn, conn.cursor() as cur:
                for kind, items in missing.items():
                    table = DICTIONARY_TABLES[kind]
                    cur.execute(f"select value,id from {table} where value=any(%s::text[])", (items,))
                    found = {str(row["value"]): int(row["id"]) for row in cur.fetchall()}
                    absent = [value for value in items if value not in found]
                    if absent:
                        cur.execute(f"insert into {table}(value) select unnest(%s::text[]) "
                                    "on conflict(value) do nothing", (absent,))
                        # A concurrent insert can win ON CONFLICT. Read its ID
                        # in a fresh statement, under the normal READ COMMITTED policy.
                        cur.execute(f"select value,id from {table} where value=any(%s::text[])", (absent,))
                        found.update({str(row["value"]): int(row["id"]) for row in cur.fetchall()})
                    if set(found) != set(items):
                        raise RuntimeError(f"dictionary identity unresolved: {kind}")
                    resolved.update({(kind, value): identity for value, identity in found.items()})
            # Never cache IDs from a transaction whose commit failed.
            self._dictionary_ids.update(resolved)
        return {kind: {value: self._dictionary_ids[kind, value] for value in sorted(items)}
                for kind, items in values.items()}

    def reserve_event_identities(
        self, events: Sequence[Mapping[str, Any]], *, read_only: bool = False
    ) -> list[Mapping[str, Any]]:
        if not events:
            return []

        def _hash(value: Any) -> bytes:
            raw = bytes.fromhex(str(value)) if isinstance(value, str) else bytes(value)
            if len(raw) != 32:
                raise ValueError("source event allocation hash must be 32 bytes")
            return raw

        insert_one = "(%s::bigint,%s::integer,%s::bigint,%s::timestamptz,%s::bytea)"
        lookup_one = "(%s::integer,%s::bigint,%s::integer,%s::bigint,%s::timestamptz,%s::bytea)"
        insert_params: list[Any] = []
        lookup_params: list[Any] = []
        expected_hashes: dict[int, bytes] = {}
        for ordinal, event in enumerate(events):
            normalized_hash = _hash(event["normalized_hash"])
            # Native Windows fractions must use the same exact decimal
            # rounding as event_core_from_v1, before PostgreSQL sees them.
            values = (
                int(event["server_id"]), int(event["channel_id"]),
                int(event["event_record_id"]), parse_utc_timestamp(event["time_created_utc"]), normalized_hash,
            )
            insert_params.extend(values)
            lookup_params.extend((ordinal, *values))
            expected_hashes[ordinal] = normalized_hash
        with self._connect() as conn, conn.cursor() as cur:
            if not read_only:
                cur.execute(
                    f"""
                    with wanted(server_id,channel_id,event_record_id,time_created_utc,normalized_hash)
                    as (values {','.join([insert_one] * len(events))})
                    insert into storage_v2_event_identity_allocations(
                        server_id,channel_id,event_record_id,time_created_utc,normalized_hash
                    ) select wanted.* from wanted where not exists (
                        select 1 from events_v2_core core where core.server_id=wanted.server_id
                        and core.channel_id=wanted.channel_id and core.event_record_id=wanted.event_record_id
                        and core.time_created_utc=wanted.time_created_utc)
                    on conflict(server_id,channel_id,event_record_id,time_created_utc) do nothing
                    """,
                    tuple(insert_params),
                )
            presence_filter = "" if read_only else "where core.id is not null or allocation.id is not null"
            cur.execute(
                f"""
                with wanted(ordinal,server_id,channel_id,event_record_id,time_created_utc,normalized_hash)
                as (values {','.join([lookup_one] * len(events))})
                select wanted.ordinal,coalesce(core.id,allocation.id) as id,
                       coalesce(core.normalized_hash,allocation.normalized_hash) as normalized_hash,
                       allocation.normalized_hash as allocated_hash,
                       core.id is not null as published,core.normalized_hash as core_hash
                from wanted
                left join storage_v2_event_identity_allocations allocation
                  on allocation.server_id=wanted.server_id
                 and allocation.channel_id=wanted.channel_id
                 and allocation.event_record_id=wanted.event_record_id
                 and allocation.time_created_utc=wanted.time_created_utc
                -- Previously rounded reservations can differ from their
                -- published core by 1 us. The immutable source key and hash
                -- resolve that core without rewriting either retained row.
                left join events_v2_core core on core.server_id=wanted.server_id
                 and core.channel_id=wanted.channel_id and core.event_record_id=wanted.event_record_id
                 and core.time_created_utc=wanted.time_created_utc
                {presence_filter}
                order by wanted.ordinal
                """,
                tuple(lookup_params),
            )
            rows = list(cur.fetchall() or [])
            if len(rows) != len(events):
                raise RuntimeError("source event allocation readback is incomplete")
            checked_sources = {}
            for row in sorted(rows, key=lambda item: int(item["id"] or 0)):
                ordinal = int(row["ordinal"])
                source = events[ordinal].get("source_row")
                if source is not None:
                    from server.sli.storage.event_source_identity import (
                        RepresentationConflict,
                        preferred_representation,
                    )
                    from server.sli.storage.event_source_representation import (
                        reconcile_representation,
                    )

                    try:
                        row["source_row"] = (reconcile_representation(
                            cur, self._connect, row, source, persist=not read_only)
                            if row["id"] is not None else preferred_representation(source, source))
                        key = tuple(events[ordinal][field] for field in (
                            "server_id", "channel_id", "event_record_id", "time_created_utc"))
                        if key in checked_sources:
                            row["source_row"] = preferred_representation(checked_sources[key], row["source_row"])
                        checked_sources[key] = row["source_row"]
                    except RepresentationConflict as exc:
                        raise SourceEventIdentityConflict(ordinal, published=bool(row.get("published")),
                                                          detail=exc.reason) from None
                    continue
                allocated_hash = bytes(row["normalized_hash"])
                if allocated_hash != expected_hashes[ordinal] or (
                    row.get("allocated_hash") is not None
                    and bytes(row["allocated_hash"]) != expected_hashes[ordinal]
                ):
                    raise SourceEventIdentityConflict(ordinal)
                if row.get("published") and bytes(row.get("core_hash") or b"") != allocated_hash:
                    raise SourceEventIdentityConflict(ordinal, published=True)
        return rows

    def reserve_entity_identities(
        self, entities: Sequence[Mapping[str, Any]]
    ) -> list[Mapping[str, Any]]:
        if not entities:
            return []
        insert_one = "(%s::integer,%s::text)"
        lookup_one = "(%s::integer,%s::integer,%s::text)"
        insert_params: list[Any] = []
        lookup_params: list[Any] = []
        for ordinal, entity in enumerate(entities):
            values = (int(entity["entity_type_id"]), str(entity["natural_key"]))
            insert_params.extend(values)
            lookup_params.extend((ordinal, *values))
        def reserve() -> list[Mapping[str, Any]]:
            with self._connect() as conn, conn.cursor() as cur:
                cur.execute(
                    f"""
                    insert into storage_v2_entity_identity_allocations(entity_type_id,natural_key)
                    values {','.join([insert_one] * len(entities))}
                    on conflict(entity_type_id,natural_key) do nothing
                    """,
                    tuple(insert_params),
                )
                cur.execute(
                    f"""
                    with wanted(ordinal,entity_type_id,natural_key)
                    as (values {','.join([lookup_one] * len(entities))})
                    select wanted.ordinal,allocation.id,core.id is not null as published
                    from wanted
                    join storage_v2_entity_identity_allocations allocation
                      on allocation.entity_type_id=wanted.entity_type_id
                     and allocation.natural_key=wanted.natural_key
                    left join entities_v2 core on core.id=allocation.id
                    order by wanted.ordinal
                    """,
                    tuple(lookup_params),
                )
                return list(cur.fetchall() or [])

        rows = _retry_lock_not_available(reserve)
        if len(rows) != len(entities):
            raise RuntimeError("source entity allocation readback is incomplete")
        return rows

    def reserve_raw_log_file(
        self,
        *,
        server_id: int,
        log_source_id: int,
        file_path: str,
        sha256: str,
        size_bytes: int,
        file_format: str = "jsonl",
    ) -> Mapping[str, Any]:
        digest = str(sha256).strip().lower()
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise ValueError("raw file reservation requires a final SHA-256 digest")
        identity = (int(server_id), int(log_source_id), str(file_path))
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "select pg_advisory_xact_lock(hashtext(%s))",
                (f"storage-v2-raw-file:{identity[0]}:{identity[1]}:{digest}",),
            )
            cur.execute(
                """
                select id,server_id,log_source_id,file_path,sha256,imported_at
                from raw_log_files
                where file_path=%s or (server_id=%s and log_source_id=%s and sha256=%s)
                order by case when file_path=%s then 0 else 1 end
                limit 1
                """,
                (identity[2], identity[0], identity[1], digest, identity[2]),
            )
            row = cur.fetchone()
            if row is None:
                cur.execute(
                    """
                    insert into raw_log_files(
                        collection_run_id,server_id,log_source_id,file_path,file_format,
                        sha256,size_bytes,event_count
                    ) values (null,%s,%s,%s,%s,%s,%s,0)
                    on conflict(server_id,log_source_id,sha256) do nothing
                    """,
                    (identity[0], identity[1], identity[2], str(file_format), digest, int(size_bytes)),
                )
                cur.execute(
                    """
                    select id,server_id,log_source_id,file_path,sha256,imported_at
                    from raw_log_files
                    where server_id=%s and log_source_id=%s and sha256=%s
                    """,
                    (identity[0], identity[1], digest),
                )
                row = cur.fetchone()
            if row is None or not _matches_raw_file_reservation(
                row,
                server_id=identity[0],
                log_source_id=identity[1],
                sha256=digest,
            ):
                raise RuntimeError("raw file identity conflict")
        return row

    def get_checkpoint(self, worker_name: str) -> BackfillCheckpoint:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                insert into storage_v2_backfill_checkpoints(worker_name) values (%s)
                on conflict(worker_name) do nothing
                """,
                (worker_name,),
            )
            cur.execute("select * from storage_v2_backfill_checkpoints where worker_name=%s", (worker_name,))
            row = cur.fetchone()
        return _checkpoint_from_row(row)

    def acquire_checkpoint(self, worker_name: str, token: str, lease_seconds: int) -> BackfillCheckpoint:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                insert into storage_v2_backfill_checkpoints(worker_name) values (%s)
                on conflict(worker_name) do nothing
                """,
                (worker_name,),
            )
            cur.execute(
                """
                update storage_v2_backfill_checkpoints
                set state='running',lease_token=%s,lease_until=now()+(%s * interval '1 second'),last_error=null,updated_at=now()
                where worker_name=%s and (lease_until is null or lease_until<=now() or lease_token=%s)
                returning *
                """,
                (token, int(lease_seconds), worker_name, token),
            )
            row = cur.fetchone()
            if not row:
                raise RuntimeError("backfill checkpoint is leased by another worker")
        return _checkpoint_from_row(row)

    def renew_checkpoint_lease(self, worker_name: str, token: str, lease_seconds: int) -> bool:
        """Extend an already-held checkpoint lease; a no-op (returns False) once lost.

        A best-effort heartbeat, not a correctness gate: the actual writes in
        write_verified_chunk/complete_checkpoint/fail_checkpoint independently
        re-check the lease token (with a row lock) and fail loudly on
        mismatch regardless of whether renewal happened. This only prevents
        the lease from expiring out from under a worker that is still alive
        and making progress on one long-running chunk.
        """
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                update storage_v2_backfill_checkpoints
                set lease_until=now()+(%s * interval '1 second'),updated_at=now()
                where worker_name=%s and lease_token=%s and state='running'
                returning worker_name
                """,
                (int(lease_seconds), worker_name, token),
            )
            return cur.fetchone() is not None

    def initialize_high_watermark(self, worker_name: str, token: str, high_watermark_event_id: int) -> BackfillCheckpoint:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                update storage_v2_backfill_checkpoints
                set high_watermark_event_id=coalesce(high_watermark_event_id,%s),updated_at=now()
                where worker_name=%s and lease_token=%s returning *
                """,
                (int(high_watermark_event_id), worker_name, token),
            )
            row = cur.fetchone()
            if not row:
                raise RuntimeError("checkpoint lease token mismatch")
        return _checkpoint_from_row(row)

    def fail_checkpoint(self, worker_name: str, token: str, error: str) -> BackfillCheckpoint:
        return self._update_checkpoint_state(worker_name, token, "failed", error)

    def complete_checkpoint(self, worker_name: str, token: str) -> BackfillCheckpoint:
        return self._update_checkpoint_state(worker_name, token, "completed", None)

    def _update_checkpoint_state(self, worker_name: str, token: str, state: str, error: str | None) -> BackfillCheckpoint:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                update storage_v2_backfill_checkpoints
                set state=%s,lease_token=null,lease_until=null,last_error=%s,updated_at=now()
                where worker_name=%s and lease_token=%s returning *
                """,
                (state, str(error)[:2000] if error else None, worker_name, token),
            )
            row = cur.fetchone()
            if not row:
                raise RuntimeError("checkpoint lease token mismatch")
        return _checkpoint_from_row(row)

    def write_verified_rows(
        self, *, cur: Any, events: Sequence[EventCoreV2], facts: Sequence[EventFactsV2],
        entities: Sequence[EntityCoreV2], links: Sequence[LinkCoreV2],
        verified_archive_links: Sequence[LinkCoreV2], source_sha256: bytes,
    ) -> bytes:
        """Write and verify one canonical V2 row set on the caller transaction."""
        source_sha256 = bytes(source_sha256)
        if core_chunk_digest(events, entities, links, facts) != source_sha256:
            raise RuntimeError("source chunk semantic hash mismatch")
        if (
            core_chunk_digest(events, entities, verified_archive_links, facts)
            != source_sha256
        ):
            raise RuntimeError("verified archive semantic hash mismatch")
        cur.execute(
            "select to_regprocedure('resolve_entity_identity_v2(integer)') "
            "is not null as available"
        )
        identity_resolver_available = bool(cur.fetchone()["available"])
        if identity_resolver_available:
            # Merge and canonical writes share this transaction lock.  It
            # must be acquired before entity upserts take row locks, or a
            # writer-first/merge-first deadlock is possible.
            cur.execute(
                "select pg_advisory_xact_lock(hashtext('entity_identity_merge_r7'))"
            )
        for item in events:
            values = dict(item.values)
            values["source_core_sha256"] = item.source_core_sha256
            columns = _validated_write_columns(values, EVENT_V2_WRITE_COLUMNS, "event")
            cur.execute(
                f"insert into events_v2_core({','.join(columns)}) values ({','.join(['%s'] * len(columns))}) "
                "on conflict do nothing returning id",
                tuple(values[column] for column in columns),
            )
            if not cur.fetchone():
                # The outbox is at-least-once.  A completed archive can be
                # replayed after a process stop, so check the immutable
                # primary id and the source-key constraint explicitly.
                # A matching hash is safe; any other collision remains a
                # hard failure rather than being silently discarded.
                cur.execute(
                    "select id,source_core_sha256 from events_v2_core where id=%s "
                    "or (server_id=%s and channel_id=%s and event_record_id=%s and time_created_utc=%s) "
                    "order by id",
                    (
                        int(values["id"]), int(values["server_id"]),
                        int(values["channel_id"]), int(values["event_record_id"]),
                        values["time_created_utc"],
                    ),
                )
                existing = cur.fetchall()
                if len(existing) != 1 or not _matches_event_replay(existing[0], values):
                    raise RuntimeError(f"event {values['id']} idempotency identity or hash mismatch")
        fact_columns_available: set[str] = set()
        if facts:
            cur.execute(
                "select column_name from information_schema.columns "
                "where table_schema=current_schema() and table_name='event_facts_v2'"
            )
            fact_columns_available = {
                str(row["column_name"]) for row in cur.fetchall()
            }
        for item in facts:
            values = dict(item.values)
            values["source_facts_sha256"] = item.source_facts_sha256
            values = _normalized_historical_fact_values(values)
            columns = _schema_compatible_fact_columns(values, fact_columns_available)
            assignments = ",".join(
                f"{column}=excluded.{column}"
                for column in columns if column != "event_id"
            )
            cur.execute(
                f"insert into event_facts_v2({','.join(columns)}) values ({','.join(['%s'] * len(columns))}) "
                f"on conflict(event_id) do update set {assignments} "
                f"where event_facts_v2.source_facts_sha256=excluded.source_facts_sha256 "
                f"returning event_id",
                tuple(values[column] for column in columns),
            )
            if not cur.fetchone():
                raise RuntimeError(
                    f"event facts {values['event_id']} idempotency hash mismatch"
                )
        for item in entities:
            values = dict(item.values)
            values["source_core_sha256"] = item.source_core_sha256
            columns = _validated_write_columns(values, ENTITY_V2_WRITE_COLUMNS, "entity")
            assignments = ",".join(f"{column}=excluded.{column}" for column in columns if column != "id")
            cur.execute(
                f"insert into entities_v2({','.join(columns)}) values ({','.join(['%s'] * len(columns))}) "
                f"on conflict(id) do update set {assignments} "
                f"where entities_v2.entity_type_id=excluded.entity_type_id "
                f"and entities_v2.natural_key=excluded.natural_key returning id",
                tuple(values[column] for column in columns),
            )
            if not cur.fetchone():
                raise RuntimeError(f"entity {values['id']} identity mismatch")
            if item.details_json is not None:
                cur.execute(
                    """
                    insert into entity_details_v2(entity_id,attributes_json,source_details_sha256)
                    values (%s,%s,%s)
                    on conflict(entity_id) do update set
                      attributes_json=excluded.attributes_json,source_details_sha256=excluded.source_details_sha256
                    returning entity_id
                    """,
                    (item.values["id"], _postgres_jsonb(item.details_json), item.source_details_sha256),
                )
                if not cur.fetchone():
                    raise RuntimeError(f"entity {item.values['id']} details hash mismatch")
            else:
                cur.execute("delete from entity_details_v2 where entity_id=%s", (item.values["id"],))
        source_entity_ids = sorted({
            int(item.values["entity_id"]) for item in links
        })
        entity_mapping = {entity_id: entity_id for entity_id in source_entity_ids}
        if identity_resolver_available and source_entity_ids:
            cur.execute(
                "select source.entity_id as source_entity_id,"
                "resolve_entity_identity_v2(source.entity_id) as target_entity_id "
                "from unnest(%s::integer[]) source(entity_id) "
                "order by source.entity_id",
                (source_entity_ids,),
            )
            entity_mapping = {
                int(row["source_entity_id"]): int(row["target_entity_id"])
                for row in cur.fetchall()
            }
            if set(entity_mapping) != set(source_entity_ids):
                raise RuntimeError("identity resolver returned an incomplete mapping")
        resolved_links = _resolve_link_cores(links, entity_mapping)
        link_rows = [
            {
                "event_id": int(item.values["event_id"]),
                "entity_id": int(item.values["entity_id"]),
                "role_id": int(item.values["role_id"]),
            }
            for item in resolved_links
        ]
        resolution_applied = any(
            source_id != target_id
            for source_id, target_id in entity_mapping.items()
        )
        affected_entity_ids = sorted({int(row["entity_id"]) for row in link_rows})
        link_event_ids = sorted({int(row["event_id"]) for row in link_rows})
        if affected_entity_ids:
            # Entity row locks serialize the first block write too; SELECT FOR UPDATE
            # on an empty block set alone would not prevent concurrent block_no=0 writes.
            cur.execute(
                "select id from entities_v2 where id=any(%s) order by id for update",
                (affected_entity_ids,),
            )
            locked_entity_ids = {int(row["id"]) for row in cur.fetchall()}
            if locked_entity_ids != set(affected_entity_ids):
                missing = sorted(set(affected_entity_ids) - locked_entity_ids)
                raise RuntimeError(f"link block has orphan entity ids: {missing[:10]}")
        if link_event_ids:
            cur.execute("select id from events_v2_core where id=any(%s)", (link_event_ids,))
            stored_event_ids = {int(row["id"]) for row in cur.fetchall()}
            if stored_event_ids != set(link_event_ids):
                missing = sorted(set(link_event_ids) - stored_event_ids)
                raise RuntimeError(f"link block has orphan event ids: {missing[:10]}")
        expected_link_identities = {
            (int(row["event_id"]), int(row["entity_id"]), int(row["role_id"]))
            for row in link_rows
        }
        if len(expected_link_identities) != len(link_rows):
            raise RuntimeError("duplicate link identity in verified chunk")
        existing_chunk_identities: set[tuple[int, int, int]] = set()
        if link_event_ids:
            cur.execute(
                "select expanded.event_id,block.entity_id,expanded.role_id "
                "from event_entity_link_blocks_v2 block "
                "cross join lateral unnest(block.event_ids,block.role_ids) "
                "expanded(event_id,role_id) "
                "where block.first_event_id<=%s and block.last_event_id>=%s "
                "and expanded.event_id=any(%s)",
                (max(link_event_ids), min(link_event_ids), link_event_ids),
            )
            existing_chunk_identities = {
                (int(row["event_id"]), int(row["entity_id"]), int(row["role_id"]))
                for row in cur.fetchall()
            } & expected_link_identities
        # A tail chunk can legitimately overlap a previously completed
        # outbox canary.  Existing identities are a verified subset of
        # this chunk, so rebuild/index only the still-new identities.
        # Any identity outside the source set is checked later by the
        # exact semantic-hash verification.
        new_link_rows = [
            row for row in link_rows
            if (row["event_id"], row["entity_id"], row["role_id"])
            not in existing_chunk_identities
        ]
        if affected_entity_ids and new_link_rows:
            tails = _read_link_block_tails(cur, affected_entity_ids)
            rows_by_entity: dict[int, list[dict[str, int]]] = {}
            for row in new_link_rows:
                rows_by_entity.setdefault(int(row["entity_id"]), []).append(row)
            # Replay-only entities remain locked, but have no blocks to append.
            for entity_id in sorted(rows_by_entity):
                tail = tails.get(entity_id)
                try:
                    changed_blocks = append_link_block_tail(tail, rows_by_entity[entity_id])
                except LinkBlockError as exc:
                    if "late or replayed" not in str(exc):
                        raise
                    # Late packets affect only the suffix beginning with
                    # their first event. Preserve the historical prefix.
                    first_event_id = min(int(row["event_id"]) for row in rows_by_entity[entity_id])
                    cur.execute(
                        "select min(block_no) as first_block from event_entity_link_blocks_v2 "
                        "where entity_id=%s and last_event_id>=%s",
                        (entity_id, first_event_id),
                    )
                    first_block = cur.fetchone()["first_block"]
                    if first_block is None:
                        raise LinkBlockError("late link has no affected block")
                    cur.execute(
                        "select entity_id,block_no,first_event_id,last_event_id,event_ids,role_ids,identity_sha256 "
                        "from event_entity_link_blocks_v2 where entity_id=%s and block_no>=%s "
                        "order by block_no for update",
                        (entity_id, first_block),
                    )
                    suffix_rows = cur.fetchall()
                    existing = [
                        LinkBlock(int(row["entity_id"]), int(row["block_no"]),
                                  tuple(row["event_ids"]), tuple(row["role_ids"]), bytes(row["identity_sha256"]))
                        for row in suffix_rows
                    ]
                    if any(block.first_event_id != row["first_event_id"] or block.last_event_id != row["last_event_id"]
                           for block, row in zip(existing, suffix_rows)):
                        raise LinkBlockError("link block bounds mismatch")
                    changed_blocks = rebuild_link_block_suffix(existing, rows_by_entity[entity_id])
                    cur.execute("delete from event_entity_link_blocks_v2 where entity_id=%s and block_no>=%s",
                                (entity_id, first_block))
                    for block in changed_blocks:
                        cur.execute(
                            "insert into event_entity_link_blocks_v2("
                            "entity_id,block_no,first_event_id,last_event_id,event_ids,role_ids,identity_sha256"
                            ") values (%s,%s,%s,%s,%s,%s,%s)",
                            (
                                block.entity_id, block.block_no, block.first_event_id,
                                block.last_event_id, list(block.event_ids),
                                list(block.role_ids), block.identity_sha256,
                            ),
                        )
                    continue
                if tail is not None and changed_blocks[0] != tail:
                    replacement = changed_blocks[0]
                    cur.execute(
                        "update event_entity_link_blocks_v2 set "
                        "first_event_id=%s,last_event_id=%s,event_ids=%s,role_ids=%s,identity_sha256=%s "
                        "where entity_id=%s and block_no=%s and identity_sha256=%s returning block_no",
                        (
                            replacement.first_event_id, replacement.last_event_id,
                            list(replacement.event_ids), list(replacement.role_ids),
                            replacement.identity_sha256, tail.entity_id, tail.block_no,
                            tail.identity_sha256,
                        ),
                    )
                    if not cur.fetchone():
                        raise RuntimeError("link block tail changed concurrently")
                insert_from = 1 if tail is not None else 0
                for block in changed_blocks[insert_from:]:
                    cur.execute(
                        "insert into event_entity_link_blocks_v2("
                        "entity_id,block_no,first_event_id,last_event_id,event_ids,role_ids,identity_sha256"
                        ") values (%s,%s,%s,%s,%s,%s,%s)",
                        (
                            block.entity_id, block.block_no, block.first_event_id,
                            block.last_event_id, list(block.event_ids),
                            list(block.role_ids), block.identity_sha256,
                        ),
                    )
        event_ids = [int(item.values["id"]) for item in events]
        fact_ids = [int(item.values["event_id"]) for item in facts]
        entity_ids = [int(item.values["id"]) for item in entities]
        cur.execute(
            "select id,source_core_sha256 from events_v2_core where id=any(%s) order by id",
            (event_ids,),
        )
        target_events = [EventCoreV2(values={"id": int(row["id"])}, source_core_sha256=bytes(row["source_core_sha256"])) for row in cur.fetchall()]
        if entity_ids:
            cur.execute(
                "select e.id,e.source_core_sha256,d.source_details_sha256 "
                "from entities_v2 e left join entity_details_v2 d on d.entity_id=e.id "
                "where e.id=any(%s) order by e.id",
                (entity_ids,),
            )
            target_entities = [
                EntityCoreV2(
                    values={"id": int(row["id"])},
                    source_core_sha256=bytes(row["source_core_sha256"]),
                    details_json=None,
                    source_details_sha256=(
                        bytes(row["source_details_sha256"])
                        if row.get("source_details_sha256") is not None else None
                    ),
                )
                for row in cur.fetchall()
            ]
        else:
            target_entities = []
        if event_ids:
            cur.execute(
                "select expanded.event_id,block.entity_id,expanded.role_id "
                "from event_entity_link_blocks_v2 block "
                "cross join lateral unnest(block.event_ids,block.role_ids) "
                "expanded(event_id,role_id) "
                "where block.first_event_id<=%s and block.last_event_id>=%s "
                "and expanded.event_id=any(%s) "
                "order by expanded.event_id,block.entity_id,expanded.role_id",
                (max(event_ids), min(event_ids), event_ids),
            )
            stored_link_identities = {
                (int(row["event_id"]), int(row["entity_id"]), int(row["role_id"]))
                for row in cur.fetchall()
            }
            expected_link_identities = {
                (
                    int(item.values["event_id"]),
                    int(item.values["entity_id"]),
                    int(item.values["role_id"]),
                )
                for item in resolved_links
            }
            if stored_link_identities != expected_link_identities:
                raise RuntimeError("verified chunk link identity mismatch")
            archive_link_identities = {
                (int(item.values["event_id"]), int(item.values["entity_id"]), int(item.values["role_id"]))
                for item in verified_archive_links
            }
            source_link_identities = {
                (
                    int(item.values["event_id"]),
                    int(item.values["entity_id"]),
                    int(item.values["role_id"]),
                )
                for item in links
            }
            if archive_link_identities != source_link_identities:
                raise RuntimeError("published archive link identity mismatch")
            target_links = resolved_links
        else:
            target_links = []
        if fact_ids:
            cur.execute(
                "select event_id,source_facts_sha256 from event_facts_v2 "
                "where event_id=any(%s) order by event_id",
                (fact_ids,),
            )
            target_facts = [
                EventFactsV2(
                    values={"event_id": int(row["event_id"])},
                    source_facts_sha256=bytes(row["source_facts_sha256"]),
                )
                for row in cur.fetchall()
            ]
        else:
            target_facts = []
        target_sha256 = core_chunk_digest(
            target_events, target_entities, target_links, target_facts
        )
        if not resolution_applied and target_sha256 != source_sha256:
            raise RuntimeError("verified chunk semantic hash mismatch")
        if resolution_applied and target_sha256 == source_sha256:
            raise RuntimeError("resolved canonical target hash did not change")
        if (
            len(target_events) != len(events)
            or len(target_facts) != len(facts)
            or len(target_links) != len(links)
        ):
            raise RuntimeError("verified chunk row-count mismatch")
        if self._semantic_publisher is not None and event_ids:
            self._semantic_publisher(cur, event_ids)
        if self._failpoint is not None:
            self._failpoint("after_verified_chunk_rows")
        return target_sha256

    def write_verified_chunk(self, **kwargs: Any) -> BackfillCheckpoint:
        worker_name = str(kwargs["worker_name"])
        lease_token = str(kwargs["lease_token"])
        events: Sequence[EventCoreV2] = kwargs["events"]
        facts: Sequence[EventFactsV2] = kwargs["facts"]
        entities: Sequence[EntityCoreV2] = kwargs["entities"]
        links: Sequence[LinkCoreV2] = kwargs["links"]
        verified_archive_links: Sequence[LinkCoreV2] = kwargs["verified_archive_links"]
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("select pg_current_wal_lsn() as lsn, clock_timestamp() as started_at")
            metrics_start = cur.fetchone()
            cur.execute("select lease_token from storage_v2_backfill_checkpoints where worker_name=%s for update", (worker_name,))
            row = cur.fetchone()
            if not row or str(row["lease_token"]) != lease_token:
                raise RuntimeError("checkpoint lease token mismatch")
            source_sha256 = bytes(kwargs["source_sha256"])
            target_sha256 = self.write_verified_rows(
                cur=cur, events=events, facts=facts, entities=entities, links=links,
                verified_archive_links=verified_archive_links, source_sha256=source_sha256,
            )
            cur.execute(
                "select pg_wal_lsn_diff(pg_current_wal_lsn(),%s) as wal_bytes, "
                "greatest(0,extract(epoch from (clock_timestamp()-%s))*1000)::bigint as duration_ms",
                (metrics_start["lsn"], metrics_start["started_at"]),
            )
            metrics = cur.fetchone()
            cur.execute(
                """
                insert into storage_v2_backfill_chunks(
                    worker_name,chunk_start_event_id,chunk_end_event_id,source_event_rows,target_event_rows,
                    source_link_rows,target_link_rows,source_sha256,target_sha256,archive_event_set_id,
                    archive_link_set_id,wal_bytes,duration_ms,status
                ) values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'verified')
                on conflict(worker_name,chunk_start_event_id,chunk_end_event_id) do update set
                    source_event_rows=excluded.source_event_rows,target_event_rows=excluded.target_event_rows,
                    source_link_rows=excluded.source_link_rows,target_link_rows=excluded.target_link_rows,
                    source_sha256=excluded.source_sha256,target_sha256=excluded.target_sha256,
                    archive_event_set_id=excluded.archive_event_set_id,archive_link_set_id=excluded.archive_link_set_id,
                    wal_bytes=excluded.wal_bytes,duration_ms=excluded.duration_ms,status='verified',completed_at=now()
                where storage_v2_backfill_chunks.source_sha256=excluded.source_sha256
                  and storage_v2_backfill_chunks.target_sha256=excluded.target_sha256
                returning worker_name
                """,
                (
                    worker_name,int(kwargs["start_event_id"]),int(kwargs["end_event_id"]),
                    int(kwargs["source_rows"]),len(events),int(kwargs["source_link_rows"]),len(links),
                    source_sha256,target_sha256,kwargs["archive_event_set_id"],
                    kwargs.get("archive_link_set_id"),int(metrics["wal_bytes"] or 0),int(metrics["duration_ms"] or 0),
                ),
            )
            if not cur.fetchone():
                raise RuntimeError("backfill chunk audit identity/hash conflict")
            cur.execute(
                """
                update storage_v2_backfill_checkpoints set
                    high_watermark_event_id=%s,last_verified_event_id=%s,chunk_size=%s,
                    source_rows=source_rows+%s,target_rows=target_rows+%s,state='ready',
                    lease_token=null,lease_until=null,updated_at=now()
                where worker_name=%s and lease_token=%s returning *
                """,
                (
                    int(kwargs["high_watermark_event_id"]), int(kwargs["end_event_id"]),
                    int(kwargs["next_chunk_size"]), int(kwargs["source_rows"]), len(events),
                    worker_name, lease_token,
                ),
            )
            checkpoint_row = cur.fetchone()
            if not checkpoint_row:
                raise RuntimeError("checkpoint lease token mismatch")
        return _checkpoint_from_row(checkpoint_row)

    def enqueue_outbox(self, **kwargs: Any) -> OutboxItem:
        ordered_ids = tuple(int(value) for value in kwargs["event_ids"])
        if not ordered_ids or tuple(sorted(set(ordered_ids))) != ordered_ids:
            raise ValueError("outbox event_ids must be sorted and unique")
        if len(ordered_ids) != int(kwargs["event_count"]):
            raise ValueError("outbox event_count does not match event_ids")
        if ordered_ids[0] != int(kwargs["first_event_id"]) or ordered_ids[-1] != int(kwargs["last_event_id"]):
            raise ValueError("outbox range does not match event_ids")
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                insert into storage_v2_outbox(batch_id,first_event_id,last_event_id,event_count,event_ids,identity_sha256)
                values (%s,%s,%s,%s,%s,%s)
                on conflict(batch_id) do update set batch_id=excluded.batch_id
                returning *
                """,
                (
                    kwargs["batch_id"], kwargs["first_event_id"], kwargs["last_event_id"],
                    kwargs["event_count"], list(ordered_ids), kwargs["identity_sha256"],
                ),
            )
            row = cur.fetchone()
            row_ids = tuple(int(value) for value in row["event_ids"])
            if bytes(row["identity_sha256"]) != bytes(kwargs["identity_sha256"]) or row_ids != ordered_ids:
                raise RuntimeError("outbox batch id was reused with a different identity hash")
        return _outbox_from_row(row)

    def claim_outbox(self, token: str, lease_seconds: int) -> OutboxItem | None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                with candidate as (
                    select id from storage_v2_outbox
                    where (
                        (state in ('pending','failed') and available_at<=now())
                        or (state='leased' and (lease_until is null or lease_until<=now()))
                    )
                    order by id for update skip locked limit 1
                )
                update storage_v2_outbox o set state='leased',attempt_count=attempt_count+1,
                    lease_token=%s,lease_until=now()+(%s * interval '1 second')
                from candidate where o.id=candidate.id returning o.*
                """,
                (token, int(lease_seconds)),
            )
            row = cur.fetchone()
        return _outbox_from_row(row) if row else None

    def renew_outbox_lease(self, item_id: int, token: str, lease_seconds: int) -> bool:
        """Extend an already-held outbox lease; a no-op (returns False) once lost.

        Same best-effort contract as renew_checkpoint_lease -- complete_outbox/
        fail_outbox independently re-check the lease token regardless.
        """
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                update storage_v2_outbox
                set lease_until=now()+(%s * interval '1 second')
                where id=%s and lease_token=%s and state='leased'
                returning id
                """,
                (int(lease_seconds), int(item_id), token),
            )
            return cur.fetchone() is not None

    def complete_outbox(self, item_id: int, token: str) -> OutboxItem:
        return self._update_outbox(item_id, token, completed=True, error=None, retry_seconds=0)

    def fail_outbox(self, item_id: int, token: str, error: str, retry_seconds: int) -> OutboxItem:
        return self._update_outbox(item_id, token, completed=False, error=error, retry_seconds=retry_seconds)

    def existing_published_source_event_ids(self, events: Sequence[Mapping[str, Any]]) -> set[int]:
        """Return staging IDs whose immutable source event already exists in V2.

        V1 staging rows are intentionally cleaned after a successful V2
        publication.  A DC may later replay the same source record, producing
        a new staging id.  The source key plus normalized hash proves it is
        already published; a different hash stays an integrity error.
        """
        if not events:
            return set()
        values_sql = ",".join(["(%s::bigint,%s::bigint,%s::text,%s::bigint,%s::text,%s::text)"] * len(events))
        params: list[Any] = []
        for event in events:
            params.extend((
                int(event["id"]), int(event["server_id"]), str(event["channel"]),
                int(event["event_record_id"]), parse_utc_timestamp(event["time_created_utc"]),
                str(event["normalized_hash"]),
            ))
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                f"""
                with wanted(staging_id,server_id,channel,event_record_id,time_created_utc,normalized_hash) as
                (values {values_sql})
                select w.staging_id, encode(v.normalized_hash,'hex') as stored_hash
                from wanted w
                join storage_v2_channel c on c.value=w.channel
                join events_v2_core v on v.server_id=w.server_id and v.channel_id=c.id
                  and v.event_record_id=w.event_record_id
                  and v.time_created_utc=w.time_created_utc::timestamptz
                """,
                tuple(params),
            )
            rows = cur.fetchall()
        duplicate_ids: set[int] = set()
        for row in rows:
            if str(row["stored_hash"]).lower() != str(events_by_id(events)[int(row["staging_id"])]["normalized_hash"]).lower():
                raise RuntimeError(f"published source event hash mismatch for staging event {row['staging_id']}")
            duplicate_ids.add(int(row["staging_id"]))
        return duplicate_ids

    def _update_outbox(self, item_id: int, token: str, *, completed: bool, error: str | None, retry_seconds: int) -> OutboxItem:
        with self._connect() as conn, conn.cursor() as cur:
            if completed:
                cur.execute(
                    """
                    update storage_v2_outbox set state='completed',completed_at=now(),lease_token=null,lease_until=null,last_error=null
                    where id=%s and (lease_token=%s or state='completed') returning *
                    """,
                    (int(item_id), token),
                )
            else:
                cur.execute(
                    """
                    update storage_v2_outbox set state='failed',available_at=now()+(%s * interval '1 second'),
                        lease_token=null,lease_until=null,last_error=%s
                    where id=%s and lease_token=%s returning *
                    """,
                    (int(retry_seconds), str(error)[:2000], int(item_id), token),
                )
            row = cur.fetchone()
            if not row:
                raise RuntimeError("outbox lease token mismatch")
        return _outbox_from_row(row)

    def record_shadow(self, payload: Mapping[str, Any]) -> None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                insert into storage_v2_shadow_results(
                    query_kind,sample_key_sha256,v1_result_sha256,v2_result_sha256,
                    identity_match,count_match,v1_duration_ms,v2_duration_ms,mismatch_summary
                ) values (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                (
                    payload["query_kind"], payload["sample_key_sha256"], payload["v1_result_sha256"],
                    payload["v2_result_sha256"], payload["identity_match"], payload["count_match"],
                    payload["v1_duration_ms"], payload["v2_duration_ms"], payload.get("mismatch_summary"),
                ),
            )

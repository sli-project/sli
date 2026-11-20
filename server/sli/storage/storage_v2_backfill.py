"""Restartable Storage V2 backfill and outbox workers.

The implementation is dormant until a later canary explicitly supplies a
source, repository and protected archive root.  It never opens PostgreSQL at
import time and never advances a checkpoint before archive publication and the
V2 transaction are both verified.
"""
from __future__ import annotations

import hashlib
import threading
import uuid
from dataclasses import dataclass
from time import monotonic
from typing import Any, Callable, Mapping, Protocol, Sequence

from server.sli.storage.storage_v2_archive import ArchivePublisher, ArchiveReader
from server.sli.storage.storage_v2_models import (
    LINK_DETAIL_COLUMNS,
    EntityCoreV2,
    EventCoreV2,
    EventFactsV2,
    LinkCoreV2,
    entity_core_from_v1,
    event_core_from_v1,
    event_facts_from_v1,
    link_core_from_v1,
    link_core_from_archive,
    parse_utc_timestamp,
    semantic_sequence_sha256,
)
from server.sli.storage.storage_v2_repository import (
    BackfillCheckpoint, OutboxItem, StorageV2Repository, core_chunk_digest,
)


@dataclass(frozen=True)
class SourceBatch:
    events: tuple[Mapping[str, Any], ...]
    entities: tuple[Mapping[str, Any], ...]
    links: tuple[Mapping[str, Any], ...]

    @property
    def first_event_id(self) -> int:
        return min(int(item["id"]) for item in self.events)

    @property
    def last_event_id(self) -> int:
        return max(int(item["id"]) for item in self.events)


class BackfillSource(Protocol):
    def max_event_id(self) -> int: ...
    def fetch_batch(self, *, after_event_id: int, through_event_id: int, limit: int) -> SourceBatch: ...
    def fetch_outbox_batch(self, item: OutboxItem) -> SourceBatch: ...


@dataclass(frozen=True)
class BackfillRunResult:
    status: str
    worker_name: str
    high_watermark_event_id: int
    start_event_id: int | None
    end_event_id: int | None
    source_events: int
    source_entities: int
    source_links: int
    next_chunk_size: int
    duration_ms: int
    archive_event_set_id: str | None = None
    archive_link_set_id: str | None = None
    checkpoint_state: str = "ready"
    error: str | None = None

    def public_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "worker_name": self.worker_name,
            "high_watermark_event_id": self.high_watermark_event_id,
            "start_event_id": self.start_event_id,
            "end_event_id": self.end_event_id,
            "source_events": self.source_events,
            "source_entities": self.source_entities,
            "source_links": self.source_links,
            "next_chunk_size": self.next_chunk_size,
            "duration_ms": self.duration_ms,
            "archive_event_set_id": self.archive_event_set_id,
            "archive_link_set_id": self.archive_link_set_id,
            "checkpoint_state": self.checkpoint_state,
            "error": self.error,
            "payload_content_persisted": False,
        }


@dataclass(frozen=True)
class DirectBatchResult:
    batch_identity: str
    first_event_id: int
    last_event_id: int
    event_count: int
    entity_count: int
    link_count: int
    archive_event_set_id: str | None
    archive_link_set_id: str | None
    source_sha256: bytes
    target_sha256: bytes


class LeaseLostError(RuntimeError):
    """Raised when a lease is proven lost -- not merely unconfirmed.

    ``renew(...) -> bool`` returning ``False`` is the repository explicitly
    reporting "this token no longer holds the lease", as opposed to an
    exception (a transient DB/network hiccup, which proves nothing either
    way). Only the former is treated as proof of loss.
    """


class LeaseHeartbeat:
    """Periodically renews a single held lease while it is being used.

    A held lease (outbox row or backfill checkpoint) is claimed once, up
    front, for a fixed `lease_seconds` window. The work done under that
    lease -- fetch source rows, transform, publish archive blocks, verify
    and write one chunk -- is one continuous unit with no internal
    checkpoint of its own to renew against (see run_backfill_once: it does
    exactly one fetch/transform/publish/write per call, not a loop). Without
    a heartbeat, a chunk that legitimately takes longer than `lease_seconds`
    (a large chunk, a slow disk, a loaded database) would have its lease
    expire while the worker is still actively making progress, and a second
    claimant could then legally re-claim the same row.

    Renewal success is *not* what correctness depends on -- the hard
    invariant is that the caller's own `lease_seconds` is sized (by the
    caller, e.g. the production batch worker) to outlive the longest
    possible lifetime of the process using it, so an item's lease cannot
    legally expire while a process that could still be processing it is
    still alive, even if this heartbeat never renews at all. Renewal is
    purely an optimization that lets recovery happen sooner than that
    worst-case bound in the common case where the process is healthy.

    That said, a renewal is not *ignored* either. Two distinct outcomes are
    told apart:

    - `self._renew()` raises -- a transient failure (network blip, DB
      hiccup) that proves nothing about lease ownership one way or the
      other. Absorbed silently; the next interval tries again.
    - `self._renew()` returns `False` -- the repository has explicitly
      confirmed the token no longer holds the lease. This is proof of loss,
      not noise: the heartbeat stops trying (there is nothing left to renew)
      and latches `lost`. `check()` raises `LeaseLostError` from that point
      on, so a caller that checks before its next state-changing step
      (archive publish, chunk write, outbox/checkpoint completion) cannot
      keep acting as the legitimate owner after the loss is known --
      without needing to interrupt whatever line of work was already
      in flight when the loss was discovered.

    Every write that actually matters (write_verified_chunk,
    complete_checkpoint, complete_outbox, fail_checkpoint, fail_outbox)
    still independently re-checks the lease token at the database and
    raises if it no longer matches, regardless of this class. `check()` is
    an earlier, cheaper backstop in front of that, not a replacement for it.
    """

    def __init__(self, renew: Callable[[], bool], *, lease_seconds: int, interval_seconds: float | None = None) -> None:
        self._renew = renew
        # Renew at roughly a third of the lease window, so a single missed
        # or slow renewal attempt still leaves margin before expiry.
        self._interval = interval_seconds if interval_seconds is not None else max(1.0, lease_seconds / 3.0)
        self._stop = threading.Event()
        self._lost = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def lost(self) -> bool:
        return self._lost.is_set()

    def check(self) -> None:
        """Raise LeaseLostError if a renewal has proven the lease is gone.

        Call this immediately before a state-changing step (archive
        publish, chunk write, outbox/checkpoint completion) so a worker
        that has already been told it lost ownership cannot proceed as if
        it still held it.
        """
        if self._lost.is_set():
            raise LeaseLostError("lease was proven lost by a failed renewal")

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def _run(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                renewed = self._renew()
            except Exception:
                # Transient: proves nothing about ownership either way.
                # The write-time lease-token checks are the real gate; try
                # again next interval.
                continue
            if not renewed:
                # Proven lost -- nothing left to renew, and nothing further
                # should proceed believing this token still owns the lease.
                self._lost.set()
                return


def adaptive_chunk_size(current: int, duration_seconds: float, *, target_seconds: float = 30.0) -> int:
    current = max(5_000, min(int(current), 50_000))
    if duration_seconds <= 0:
        return current
    ratio = target_seconds / duration_seconds
    bounded_ratio = max(0.5, min(ratio, 2.0))
    proposed = int(round(current * bounded_ratio / 1000.0) * 1000)
    return max(5_000, min(proposed, 50_000))


def _dictionary_maps(repository: StorageV2Repository, batch: SourceBatch) -> dict[str, dict[str, int]]:
    values: dict[str, set[str]] = {
        "provider": set(), "channel": set(), "computer": set(), "keywords": set(),
        "domain": set(), "role": set(), "extracted_from": set(), "entity_type": set(),
    }
    for row in batch.events:
        mapping = {
            "provider": row.get("provider_name"), "channel": row.get("channel"),
            "computer": row.get("computer"), "keywords": row.get("keywords"),
        }
        for kind, value in mapping.items():
            if value not in (None, ""):
                values[kind].add(str(value))
        for field in ("subject_domain_name", "target_domain_name"):
            if row.get(field) not in (None, ""):
                values["domain"].add(str(row[field]))
    for row in batch.entities:
        if row.get("entity_type") not in (None, ""):
            values["entity_type"].add(str(row["entity_type"]))
    for row in batch.links:
        if row.get("link_role") not in (None, ""):
            values["role"].add(str(row["link_role"]))
        if row.get("extracted_from") not in (None, ""):
            values["extracted_from"].add(str(row["extracted_from"]))
    bulk_lookup = getattr(repository, "dictionary_maps", None)
    if callable(bulk_lookup):
        return bulk_lookup(values)
    result: dict[str, dict[str, int]] = {}
    for kind, items in values.items():
        result[kind] = {
            value: int(repository.dictionary_id(kind, value))
            for value in sorted(items)
        }
    return result


def transform_batch_with_facts(
    repository: StorageV2Repository,
    batch: SourceBatch,
    *,
    cur: Any = None,
) -> tuple[
    list[EventCoreV2], list[EventFactsV2], list[EntityCoreV2],
    list[LinkCoreV2], list[dict[str, Any]],
]:
    include_process_activity = repository.supports_process_activity_facts(cur=cur)
    dictionaries = _dictionary_maps(repository, batch)
    events = [event_core_from_v1(row, dictionaries) for row in batch.events]
    facts = [
        item for row in batch.events
        if (item := event_facts_from_v1(
            row, include_process_activity=include_process_activity,
        )) is not None
    ]
    entities = [
        entity_core_from_v1(row, dictionaries["entity_type"][str(row["entity_type"])])
        for row in batch.entities
    ]
    links: list[LinkCoreV2] = []
    link_details: list[dict[str, Any]] = []
    for row in batch.links:
        role_id = dictionaries["role"][str(row["link_role"])]
        extracted = row.get("extracted_from")
        extracted_id = dictionaries["extracted_from"].get(str(extracted)) if extracted not in (None, "") else None
        transformed = link_core_from_v1(row, role_id, extracted_id)
        links.append(transformed)
        if transformed.details is not None:
            link_details.append(dict(transformed.details))
    return events, facts, entities, links, link_details


def transform_batch(
    repository: StorageV2Repository,
    batch: SourceBatch,
) -> tuple[list[EventCoreV2], list[EntityCoreV2], list[LinkCoreV2], list[dict[str, Any]]]:
    """Backward-compatible transform contract used by accepted implementation tests."""

    events, _facts, entities, links, link_details = transform_batch_with_facts(
        repository, batch
    )
    return events, entities, links, link_details


def _archive_set_id(worker_name: str, kind: str, first_event_id: int, last_event_id: int) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"adlog:{worker_name}:{kind}:{first_event_id}:{last_event_id}"))


def publish_direct_batch(
    *,
    batch_identity: str,
    batch: SourceBatch,
    repository: StorageV2Repository,
    publisher: ArchivePublisher | None,
    cur: Any,
    compatibility_mirror: Callable[[Any, SourceBatch], None] | None = None,
) -> DirectBatchResult:
    """Publish and write one importer batch through the canonical V2 path.

    A None publisher writes only the verified PostgreSQL core and facts.
    Legacy archive publishers retain deterministic objects and verification
    before the caller's PostgreSQL transaction.
    """
    identity = str(batch_identity).strip()
    if not identity:
        raise ValueError("direct batch identity is required")
    event_ids = [int(row["id"]) for row in batch.events]
    if not event_ids:
        raise ValueError("direct batch cannot be empty")
    if len(event_ids) != len(set(event_ids)):
        raise ValueError("direct batch event ids must be unique")

    first_id, last_id = min(event_ids), max(event_ids)
    events, facts, entities, links, link_details = transform_batch_with_facts(
        repository, batch, cur=cur
    )
    source_sha256 = core_chunk_digest(events, entities, links, facts)
    worker_identity = f"direct:{identity}"
    event_set: str | None = None
    link_set: str | None = None
    # Reconstruct link cores from the attested source details on the no-archive
    # path. The repository still verifies semantic hashes and persisted rows.
    verified_archive_links = [link_core_from_archive(row) for row in link_details]
    if publisher is not None:
        event_set = _archive_set_id(worker_identity, "event", first_id, last_id)
        publisher.publish_rows(
            archive_set_id=event_set,
            archive_kind="event",
            block_index=0,
            rows=batch.events,
            event_id_field="id",
        )
        verified_archive_links = []
        if link_details:
            link_set = _archive_set_id(worker_identity, "link_detail", first_id, last_id)
            link_block = publisher.publish_rows(
                archive_set_id=link_set,
                archive_kind="link_detail",
                block_index=0,
                rows=link_details,
                event_id_field="event_id",
            )
            archive_rows = ArchiveReader(publisher.manifest, publisher.root).read_block_rows(
                link_block
            )
            verified_archive_links = [link_core_from_archive(row) for row in archive_rows]

    target_sha256 = repository.write_verified_rows(
        cur=cur,
        events=events,
        facts=facts,
        entities=entities,
        links=links,
        verified_archive_links=verified_archive_links,
        source_sha256=source_sha256,
    )
    if compatibility_mirror is not None:
        compatibility_mirror(cur, batch)
    return DirectBatchResult(
        batch_identity=identity,
        first_event_id=first_id,
        last_event_id=last_id,
        event_count=len(events),
        entity_count=len(entities),
        link_count=len(links),
        archive_event_set_id=event_set,
        archive_link_set_id=link_set,
        source_sha256=source_sha256,
        target_sha256=target_sha256,
    )


def run_backfill_once(
    *,
    worker_name: str,
    source: BackfillSource,
    repository: StorageV2Repository,
    publisher: ArchivePublisher,
    lease_seconds: int = 300,
    ownership_check: Callable[[], None] | None = None,
) -> BackfillRunResult:
    """``ownership_check``, when given, is consulted alongside this call's own
    checkpoint-lease heartbeat before every state-changing step (archive
    publish, chunk write). It exists for a caller whose own ownership is a
    *separate* lease this call knows nothing about -- e.g. run_outbox_once
    passes its outbox-lease heartbeat's own ``check`` here, so a backfill
    running on behalf of an outbox item that has already proven it lost
    that item's lease cannot keep publishing/writing under its own,
    independently still-valid checkpoint lease. It raises the same way
    ``LeaseHeartbeat.check()`` does (typically ``LeaseLostError``); the
    checkpoint lease's own protection is unaffected either way.
    """
    started = monotonic()
    token = str(uuid.uuid4())
    checkpoint: BackfillCheckpoint | None = None
    high_watermark = 0
    heartbeat = LeaseHeartbeat(
        lambda: repository.renew_checkpoint_lease(worker_name, token, lease_seconds),
        lease_seconds=lease_seconds,
    )

    def _check_ownership() -> None:
        heartbeat.check()
        if ownership_check is not None:
            ownership_check()

    heartbeat.start()
    try:
        checkpoint = repository.acquire_checkpoint(worker_name, token, lease_seconds)
        high_watermark = int(checkpoint.high_watermark_event_id or 0)
        if checkpoint.high_watermark_event_id is None:
            checkpoint = repository.initialize_high_watermark(
                worker_name, token, int(source.max_event_id())
            )
        high_watermark = int(checkpoint.high_watermark_event_id or 0)
        batch = source.fetch_batch(
            after_event_id=checkpoint.last_verified_event_id,
            through_event_id=high_watermark,
            limit=checkpoint.chunk_size,
        )
        if not batch.events:
            completed = repository.complete_checkpoint(worker_name, token)
            return BackfillRunResult(
                status="completed",
                worker_name=worker_name,
                high_watermark_event_id=high_watermark,
                start_event_id=None,
                end_event_id=None,
                source_events=0,
                source_entities=0,
                source_links=0,
                next_chunk_size=completed.chunk_size,
                duration_ms=int((monotonic() - started) * 1000),
                checkpoint_state=completed.state,
            )

        first_id, last_id = batch.first_event_id, batch.last_event_id
        events, facts, entities, links, link_details = transform_batch_with_facts(
            repository, batch
        )
        # Fail closed before the first state-changing step (event archive
        # publish) if a renewal (or the caller's own separate ownership,
        # via ownership_check) has already proven ownership is gone.
        _check_ownership()
        event_set = _archive_set_id(worker_name, "event", first_id, last_id)
        publisher.publish_rows(
            archive_set_id=event_set,
            archive_kind="event",
            block_index=0,
            rows=batch.events,
            event_id_field="id",
        )
        link_set: str | None = None
        verified_archive_links: list[LinkCoreV2] = []
        if link_details:
            # Re-check between the two publications: event archive publish
            # above can itself take real time, and link archive publish is
            # its own separate state-changing step that must not start on
            # ownership already known to be gone when it finished.
            _check_ownership()
            link_set = _archive_set_id(worker_name, "link_detail", first_id, last_id)
            link_block = publisher.publish_rows(
                archive_set_id=link_set,
                archive_kind="link_detail",
                block_index=0,
                rows=link_details,
                event_id_field="event_id",
            )
            archive_rows = ArchiveReader(
                publisher.manifest, publisher.root
            ).read_block_rows(link_block)
            verified_archive_links = [link_core_from_archive(row) for row in archive_rows]

        elapsed = monotonic() - started
        next_size = adaptive_chunk_size(checkpoint.chunk_size, elapsed)
        # Same check immediately before the chunk commit -- whichever
        # publish step ran last above can take real time too.
        _check_ownership()
        updated = repository.write_verified_chunk(
            worker_name=worker_name,
            lease_token=token,
            high_watermark_event_id=high_watermark,
            start_event_id=first_id,
            end_event_id=last_id,
            next_chunk_size=next_size,
            events=events,
            facts=facts,
            entities=entities,
            links=links,
            verified_archive_links=verified_archive_links,
            source_rows=len(batch.events),
            source_link_rows=len(batch.links),
            source_sha256=core_chunk_digest(events, entities, links, facts),
            archive_event_set_id=event_set,
            archive_link_set_id=link_set,
        )
        return BackfillRunResult(
            status="ok",
            worker_name=worker_name,
            high_watermark_event_id=high_watermark,
            start_event_id=first_id,
            end_event_id=last_id,
            source_events=len(batch.events),
            source_entities=len(batch.entities),
            source_links=len(batch.links),
            next_chunk_size=updated.chunk_size,
            duration_ms=int((monotonic() - started) * 1000),
            archive_event_set_id=event_set,
            archive_link_set_id=link_set,
            checkpoint_state=updated.state,
        )
    except Exception as exc:
        next_chunk_size = checkpoint.chunk_size if checkpoint is not None else 25_000
        checkpoint_state = checkpoint.state if checkpoint is not None else "unacquired"
        failure_text = f"{type(exc).__name__}: {exc}"
        if checkpoint is not None:
            try:
                failed = repository.fail_checkpoint(worker_name, token, str(exc))
                next_chunk_size = failed.chunk_size
                checkpoint_state = failed.state
            except Exception as checkpoint_exc:
                failure_text += (
                    f"; checkpoint_failure={type(checkpoint_exc).__name__}: {checkpoint_exc}"
                )
        return BackfillRunResult(
            status="failed",
            worker_name=worker_name,
            high_watermark_event_id=high_watermark,
            start_event_id=None,
            end_event_id=None,
            source_events=0,
            source_entities=0,
            source_links=0,
            next_chunk_size=next_chunk_size,
            duration_ms=int((monotonic() - started) * 1000),
            checkpoint_state=checkpoint_state,
            error=failure_text,
        )
    finally:
        heartbeat.stop()


def enqueue_collector_batch(
    repository: StorageV2Repository,
    *,
    batch_id: str,
    event_ids: Sequence[int],
) -> OutboxItem:
    """Create only an identity outbox row; event payload never enters the outbox."""
    ordered = sorted({int(value) for value in event_ids})
    if not ordered:
        raise ValueError("collector batch cannot be empty")
    digest = hashlib.sha256(",".join(str(value) for value in ordered).encode("ascii")).digest()
    return repository.enqueue_outbox(
        batch_id=batch_id,
        first_event_id=ordered[0],
        last_event_id=ordered[-1],
        event_count=len(ordered),
        event_ids=ordered,
        identity_sha256=digest,
    )


def _without_source_event_ids(batch: SourceBatch, event_ids: set[int]) -> SourceBatch:
    """Remove already-published staging copies while preserving related rows."""
    events = tuple(event for event in batch.events if int(event["id"]) not in event_ids)
    retained_ids = {int(event["id"]) for event in events}
    links = tuple(link for link in batch.links if int(link["event_id"]) in retained_ids)
    entity_ids = {int(link["entity_id"]) for link in links}
    return SourceBatch(
        events,
        tuple(entity for entity in batch.entities if int(entity["id"]) in entity_ids),
        links,
    )


def _deduplicate_source_events(batch: SourceBatch) -> tuple[SourceBatch, set[int]]:
    """Keep one exact source event when a single V1 batch contains a replay.

    V2 identifies a source record by server/channel/EventRecordID/time. V1
    staging may contain two textual representations of the same timestamp.
    They are safe to coalesce only when their normalized event hash agrees.
    """
    kept: dict[tuple[int, str, int, str], Mapping[str, Any]] = {}
    duplicate_ids: set[int] = set()
    for event in batch.events:
        timestamp = parse_utc_timestamp(event.get("time_created_utc"))
        key = (
            int(event["server_id"]), str(event["channel"]), int(event["event_record_id"]),
            timestamp.isoformat(timespec="microseconds"),
        )
        previous = kept.get(key)
        if previous is None:
            kept[key] = event
            continue
        if str(previous.get("normalized_hash", "")).lower() != str(event.get("normalized_hash", "")).lower():
            raise RuntimeError(f"source replay hash mismatch inside outbox batch for event {event['id']}")
        duplicate_ids.add(int(event["id"]))
    if not duplicate_ids:
        return batch, duplicate_ids
    return _without_source_event_ids(batch, duplicate_ids), duplicate_ids


def run_outbox_once(
    *,
    source: BackfillSource,
    repository: StorageV2Repository,
    publisher: ArchivePublisher,
    lease_seconds: int = 300,
    retry_seconds: int = 60,
) -> dict[str, Any]:
    token = str(uuid.uuid4())
    item = repository.claim_outbox(token, lease_seconds)
    if item is None:
        return {"status": "idle", "payload_content_persisted": False}
    heartbeat = LeaseHeartbeat(
        lambda: repository.renew_outbox_lease(item.id, token, lease_seconds),
        lease_seconds=lease_seconds,
    )
    heartbeat.start()
    try:
        batch = source.fetch_outbox_batch(item)
        actual_ids = sorted(int(row["id"]) for row in batch.events)
        if not actual_ids or actual_ids[0] != item.first_event_id or actual_ids[-1] != item.last_event_id:
            raise RuntimeError("outbox source range mismatch")
        actual_digest = hashlib.sha256(",".join(str(value) for value in actual_ids).encode("ascii")).digest()
        if actual_digest != item.identity_sha256 or len(actual_ids) != item.event_count:
            raise RuntimeError("outbox identity hash mismatch")
        already_published = repository.existing_published_source_event_ids(batch.events)
        if already_published:
            batch = _without_source_event_ids(batch, already_published)
        batch, repeated_inside_batch = _deduplicate_source_events(batch)
        already_published = set(already_published) | repeated_inside_batch
        if not batch.events:
            heartbeat.check()
            repository.complete_outbox(item.id, token)
            return {
                "status": "ok",
                "outbox_id": item.id,
                "batch_id": item.batch_id,
                "events": item.event_count,
                "already_published_events": len(already_published),
                "payload_content_persisted": False,
            }
        # Tail processing uses a dedicated deterministic worker name and the
        # same restartable path. The nested call has its own, independent
        # checkpoint lease -- but it is still doing this work *because* this
        # outbox item authorizes it, so it must also stop at the next
        # state-changing step (not just this outer call, later, at
        # complete_outbox) the moment this item's own lease is proven lost.
        result = run_backfill_once(
            worker_name=f"outbox-{item.batch_id}",
            source=_SingleBatchSource(batch),
            repository=repository,
            publisher=publisher,
            lease_seconds=lease_seconds,
            ownership_check=heartbeat.check,
        )
        if result.status not in {"ok", "completed"}:
            raise RuntimeError(result.error or "outbox backfill failed")
        # The inner run_backfill_once call above can take real time under
        # its own (separate) checkpoint lease; re-check this item's own
        # outbox lease immediately before the outer commit.
        heartbeat.check()
        repository.complete_outbox(item.id, token)
        return {
            "status": "ok",
            "outbox_id": item.id,
            "batch_id": item.batch_id,
            "events": item.event_count,
            "already_published_events": len(already_published),
            "backfill": result.public_dict(),
            "payload_content_persisted": False,
        }
    except Exception as exc:
        failure_text = f"{type(exc).__name__}: {exc}"
        try:
            repository.fail_outbox(item.id, token, str(exc), retry_seconds)
        except Exception as fail_exc:
            # The lease may itself be why this failed (a lost lease makes
            # fail_outbox's own token check raise too) -- record that
            # without letting it crash the whole batch, exactly like
            # run_backfill_once already tolerates fail_checkpoint failing.
            failure_text += f"; outbox_failure={type(fail_exc).__name__}: {fail_exc}"
        return {
            "status": "failed",
            "outbox_id": item.id,
            "batch_id": item.batch_id,
            "error": failure_text,
            "payload_content_persisted": False,
        }
    finally:
        heartbeat.stop()


class _SingleBatchSource:
    def __init__(self, batch: SourceBatch) -> None:
        self.batch = batch
        self._served = False

    def max_event_id(self) -> int:
        return self.batch.last_event_id

    def fetch_batch(self, *, after_event_id: int, through_event_id: int, limit: int) -> SourceBatch:
        if self._served or after_event_id >= self.batch.last_event_id:
            return SourceBatch((), (), ())
        self._served = True
        return self.batch

    def fetch_outbox_batch(self, item: OutboxItem) -> SourceBatch:
        return self.batch

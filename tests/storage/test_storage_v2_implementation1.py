from __future__ import annotations

import inspect
import json
import threading
import uuid
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import ClassVar

import pytest

from server.sli.storage import storage_v2_backfill, storage_v2_repository
from server.sli.storage.storage_v2_archive import (
    ArchiveIntegrityError,
    ArchivePublisher,
    ArchiveReader,
    InMemoryArchiveManifestStore,
)
from server.sli.storage.storage_v2_backfill import (
    LeaseHeartbeat,
    LeaseLostError,
    SourceBatch,
    adaptive_chunk_size,
    enqueue_collector_batch,
    run_backfill_once,
    run_outbox_once,
)
from server.sli.storage.storage_v2_config import (
    StorageV2ConfigurationError,
    load_storage_v2_settings,
)
from server.sli.storage.storage_v2_models import (
    LinkCoreV2,
    StorageV2DataError,
    canonical_json_bytes,
    event_facts_from_v1,
    identity_capacity_status,
    link_core_from_v1,
    sha256_bytes,
)
from server.sli.storage.storage_v2_repository import (
    InMemoryStorageV2Repository,
    PostgresArchiveManifestStore,
    PostgresStorageV2Repository,
    _matches_event_replay,
    _matches_raw_file_reservation,
    _resolve_link_cores,
    _retry_lock_not_available,
    core_chunk_digest,
)

ROOT = Path(__file__).resolve().parents[2]


class _HeartbeatTicks:
    """Release one heartbeat interval at a time, independent of wall time."""

    def __init__(self) -> None:
        self.condition = threading.Condition()
        self.intervals: list[float] = []
        self.pending = False
        self.stopped = False
        self.finished = False

    def wait(self, interval: float) -> bool:
        with self.condition:
            self.intervals.append(interval)
            self.condition.notify_all()
            self.condition.wait_for(lambda: self.pending or self.stopped)
            self.pending = False
            return self.stopped

    def set(self) -> None:
        with self.condition:
            self.stopped = True
            self.condition.notify_all()

    def finish(self) -> None:
        with self.condition:
            self.finished = True
            self.condition.notify_all()

    def tick(self) -> None:
        with self.condition:
            assert self.condition.wait_for(lambda: self.intervals or self.finished, timeout=5)
            assert not self.finished, "heartbeat exited before the requested renewal"
            previous = len(self.intervals)
            self.pending = True
            self.condition.notify_all()
            assert self.condition.wait_for(
                lambda: len(self.intervals) > previous or self.finished, timeout=5,
            ), "heartbeat did not finish the requested renewal"


@pytest.fixture
def heartbeat_clock(monkeypatch):
    class ControlledHeartbeat(LeaseHeartbeat):
        instances: ClassVar[list[ControlledHeartbeat]] = []

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._stop = _HeartbeatTicks()
            self.instances.append(self)

        def _run(self):
            try:
                super()._run()
            finally:
                self._stop.finish()

        def tick(self):
            self._stop.tick()

    monkeypatch.setattr(storage_v2_backfill, "LeaseHeartbeat", ControlledHeartbeat)
    yield ControlledHeartbeat
    for heartbeat in ControlledHeartbeat.instances:
        heartbeat.stop()
        assert heartbeat._thread is None or not heartbeat._thread.is_alive()


@pytest.fixture
def lease_clock(monkeypatch):
    class Clock(datetime):
        current = datetime(2026, 1, 1, tzinfo=timezone.utc)

        @classmethod
        def now(cls, tz=None):
            assert tz is timezone.utc
            return cls.current

        @classmethod
        def advance(cls, seconds):
            cls.current += timedelta(seconds=seconds)

    monkeypatch.setattr(storage_v2_repository, "datetime", Clock)
    return Clock


def test_lock_not_available_retries_only_the_bounded_transaction() -> None:
    class LockNotAvailableForTest(RuntimeError):
        sqlstate = "55P03"

    calls = 0
    delays: list[float] = []

    def operation() -> str:
        nonlocal calls
        calls += 1
        if calls < 3:
            raise LockNotAvailableForTest("lock timeout")
        return "reserved"

    assert _retry_lock_not_available(operation, sleep=delays.append) == "reserved"
    assert calls == 3
    assert delays == [0.1, 0.2]


def test_lock_retry_does_not_hide_other_database_errors() -> None:
    calls = 0

    def operation() -> None:
        nonlocal calls
        calls += 1
        raise RuntimeError("foreign key violation")

    with pytest.raises(RuntimeError, match="foreign key violation"):
        _retry_lock_not_available(operation, sleep=lambda _delay: None)
    assert calls == 1


def test_outbox_reclaims_an_expired_lease() -> None:
    repository = InMemoryStorageV2Repository()
    item = repository.enqueue_outbox(
        batch_id=str(uuid.uuid4()), first_event_id=1, last_event_id=1,
        event_count=1, event_ids=[1], identity_sha256=b"x" * 32,
    )
    leased = repository.claim_outbox("dead-worker", 60)
    assert leased is not None
    repository.outbox[item.id] = replace(
        leased, lease_until=datetime.now(timezone.utc) - timedelta(seconds=1),
    )

    reclaimed = repository.claim_outbox("replacement-worker", 60)

    assert reclaimed is not None
    assert reclaimed.id == item.id
    assert reclaimed.lease_token == "replacement-worker"
    assert reclaimed.attempt_count == 2


def test_postgres_outbox_claim_query_includes_expired_leases() -> None:
    source = inspect.getsource(PostgresStorageV2Repository.claim_outbox)
    assert "state='leased'" in source
    assert "lease_until is null or lease_until<=now()" in source


def test_postgres_direct_event_identity_reservation_is_durable_and_hash_checked() -> None:
    source = inspect.getsource(PostgresStorageV2Repository.reserve_event_identities)

    assert "insert into storage_v2_event_identity_allocations" in source
    assert "on conflict(server_id,channel_id,event_record_id,time_created_utc) do nothing" in source
    assert "left join events_v2_core" in source
    assert "raise SourceEventIdentityConflict(ordinal)" in source


def test_postgres_direct_entity_identity_reservation_is_durable() -> None:
    source = inspect.getsource(PostgresStorageV2Repository.reserve_entity_identities)

    assert "insert into storage_v2_entity_identity_allocations" in source
    assert "on conflict(entity_type_id,natural_key) do nothing" in source


def test_postgres_direct_raw_file_reservation_uses_final_digest_and_stable_timestamp() -> None:
    source = inspect.getsource(PostgresStorageV2Repository.reserve_raw_log_file)

    assert "insert into raw_log_files" in source
    assert "collection_run_id" in source
    assert "null" in source
    assert "on conflict(server_id,log_source_id,sha256) do nothing" in source
    assert "raw file identity conflict" in source
    assert "imported_at" in source
    assert "storage-v2-raw-file:{identity[0]}:{identity[1]}:{digest}" in source


def test_raw_file_reservation_reuses_same_content_from_a_new_transient_path() -> None:
    row = {
        "server_id": 1,
        "log_source_id": 2,
        "file_path": r"C:\\old\\Security.jsonl",
        "sha256": "a" * 64,
    }

    assert _matches_raw_file_reservation(
        row,
        server_id=1,
        log_source_id=2,
        sha256="a" * 64,
    )


def test_raw_file_reservation_rejects_same_path_with_different_content() -> None:
    row = {
        "server_id": 1,
        "log_source_id": 2,
        "file_path": r"C:\\pilot\\Security.jsonl",
        "sha256": "a" * 64,
    }

    assert not _matches_raw_file_reservation(
        row,
        server_id=1,
        log_source_id=2,
        sha256="b" * 64,
    )


def test_pre89_event_facts_omit_only_null_process_activity_columns() -> None:
    values = {column: None for column in storage_v2_repository.EVENT_FACTS_V2_WRITE_COLUMNS}
    values["event_id"] = 1
    values["source_facts_sha256"] = b"x" * 32
    available = set(storage_v2_repository.EVENT_FACTS_V2_WRITE_COLUMNS) - set(
        storage_v2_repository.PROCESS_ACTIVITY_FACT_COLUMNS
    )

    columns = storage_v2_repository._schema_compatible_fact_columns(values, available)

    assert not set(columns) & set(storage_v2_repository.PROCESS_ACTIVITY_FACT_COLUMNS)
    assert "source_facts_sha256" in columns


def test_pre89_event_facts_reject_non_null_process_activity_payload() -> None:
    values = {column: None for column in storage_v2_repository.EVENT_FACTS_V2_WRITE_COLUMNS}
    values["event_id"] = 1
    values["source_facts_sha256"] = b"x" * 32
    values["process_parent_id"] = "400"
    available = set(storage_v2_repository.EVENT_FACTS_V2_WRITE_COLUMNS) - set(
        storage_v2_repository.PROCESS_ACTIVITY_FACT_COLUMNS
    )

    with pytest.raises(RuntimeError, match="migration 089"):
        storage_v2_repository._schema_compatible_fact_columns(values, available)


def test_pre89_transform_omits_process_activity_values_before_hashing() -> None:
    row = _event(1)
    row.update({
        "channel": "Security",
        "event_id": 4688,
        "provider_name": "Microsoft-Windows-Security-Auditing",
        "event_data_json": json.dumps({
            "NewProcessId": "0x1000",
            "CreatorProcessId": "0x400",
            "CommandLine": "process.exe --exact",
            "SubjectUserSid": "S-1-5-21-7-1001",
            "SubjectUserName": "operator",
            "SubjectDomainName": "EXAMPLE",
            "SubjectLogonId": "0xabc",
        }),
    })

    facts = event_facts_from_v1(row, include_process_activity=False)

    assert facts is not None
    assert all(
        facts.values[column] is None
        for column in storage_v2_repository.PROCESS_ACTIVITY_FACT_COLUMNS
    )
    full_facts = event_facts_from_v1(row)
    assert full_facts is not None
    assert full_facts.values["process_user_name"] == "operator"
    assert facts.source_facts_sha256 != full_facts.source_facts_sha256
    hash_values = {
        key: value for key, value in facts.values.items()
        if key not in {
            "account_target_sid", "account_target_name", "account_name_before",
            "account_name_after", "membership_member_sid", "membership_member_name",
        } or value is not None
    }
    assert facts.source_facts_sha256 == sha256_bytes(canonical_json_bytes(hash_values))


@pytest.mark.parametrize("with_migration", [False, True])
def test_fact_schema_capability_uses_caller_cursor_without_connecting(with_migration) -> None:
    available = set(storage_v2_repository.EVENT_FACTS_V2_WRITE_COLUMNS)
    if not with_migration:
        available -= storage_v2_repository.PROCESS_ACTIVITY_FACT_COLUMNS

    class Cursor:
        def execute(self, sql):
            assert "information_schema.columns" in sql
            assert "event_facts_v2" in sql

        def fetchall(self):
            return [{"column_name": name} for name in available]

    repository = PostgresStorageV2Repository(lambda: pytest.fail("unexpected connection"))
    assert repository.supports_process_activity_facts(cur=Cursor()) is with_migration
    if not with_migration:
        available.add("process_user_name")
        with pytest.raises(RuntimeError, match="partial migration 089"):
            repository.supports_process_activity_facts(cur=Cursor())
        available.remove("process_user_name")
    available.discard("message_sample")
    with pytest.raises(RuntimeError, match="schema mismatch"):
        repository.supports_process_activity_facts(cur=Cursor())


@pytest.mark.parametrize("event_id", [6272, 6273])
def test_pre89_projection_keeps_nps_replay_hash_unchanged(event_id: int) -> None:
    row = _event(1)
    row.update(
        event_id=event_id, provider_name="Microsoft-Windows-Security-Auditing",
        event_data_json=json.dumps({"AuthenticationServer": "nps.example.invalid"}),
    )
    before = event_facts_from_v1(row)
    assert before is not None
    assert event_facts_from_v1(row, include_process_activity=False) == before


@pytest.mark.parametrize("direct", [False, True])
@pytest.mark.parametrize("with_migration", [False, True])
def test_schema_aware_ingest_preserves_full_archive_and_replay(
    tmp_path: Path, direct: bool, with_migration: bool,
) -> None:
    row = _event(1)
    row.update(event_id=4688, event_data_json=json.dumps({
        "NewProcessId": "0x1000", "SubjectUserName": "operator",
    }))
    cursor = object()

    class Repository(InMemoryStorageV2Repository):
        def supports_process_activity_facts(self, *, cur=None):
            assert cur is (cursor if direct else None)
            return with_migration

        def write_verified_rows(self, *, cur, facts, source_sha256, **_kwargs):
            assert cur is cursor
            for fact in facts:
                event_id = int(fact.values["event_id"])
                old = self.event_facts.get(event_id)
                assert old is None or old == fact
                self.event_facts[event_id] = fact
            return source_sha256

    repository = Repository()
    manifest = InMemoryArchiveManifestStore()
    publisher = ArchivePublisher(tmp_path, manifest)
    batch = SourceBatch((row,), (), ())
    for _ in range(2):
        if direct:
            result = storage_v2_backfill.publish_direct_batch(
                batch_identity="pre89-replay", batch=batch, repository=repository,
                publisher=publisher, cur=cursor,
            )
            assert result.source_sha256 == result.target_sha256
        else:
            result = run_backfill_once(
                worker_name="pre89-replay", source=MemorySource([row], [], []),
                repository=repository, publisher=publisher,
            )
            assert result.status in {"completed", "ok"}
    facts = repository.event_facts[1]
    assert facts.values["process_user_name"] == ("operator" if with_migration else None)
    expected = event_facts_from_v1(row, include_process_activity=with_migration)
    assert facts == expected
    blocks = manifest.find_published_range("event", 1, 1, 10)
    assert len(blocks) == 1
    archived = ArchiveReader(manifest, tmp_path).read_block_rows(blocks[0])
    assert archived[0]["event_data_json"] == row["event_data_json"]


def test_pre89_event_facts_reject_any_other_missing_schema_column() -> None:
    values = {column: None for column in storage_v2_repository.EVENT_FACTS_V2_WRITE_COLUMNS}
    values["event_id"] = 1
    values["source_facts_sha256"] = b"x" * 32
    available = set(storage_v2_repository.EVENT_FACTS_V2_WRITE_COLUMNS) - {"account_target_sid"}

    with pytest.raises(RuntimeError, match="schema mismatch"):
        storage_v2_repository._schema_compatible_fact_columns(values, available)


def test_historical_event_facts_default_only_additive_missing_columns_to_null() -> None:
    values = {column: None for column in storage_v2_repository.EVENT_FACTS_V2_WRITE_COLUMNS}
    values["event_id"] = 1
    values["source_facts_sha256"] = b"x" * 32
    historical = {
        key: value
        for key, value in values.items()
        if key not in storage_v2_repository.ADDITIVE_EVENT_FACT_COLUMNS
    }

    normalized = storage_v2_repository._normalized_historical_fact_values(historical)

    assert set(normalized) == set(storage_v2_repository.EVENT_FACTS_V2_WRITE_COLUMNS)
    assert all(normalized[column] is None for column in storage_v2_repository.ADDITIVE_EVENT_FACT_COLUMNS)
    with pytest.raises(RuntimeError, match="write-column contract mismatch"):
        storage_v2_repository._normalized_historical_fact_values(
            {key: value for key, value in historical.items() if key != "message_sample"}
        )
    assert "_normalized_historical_fact_values" in inspect.getsource(
        PostgresStorageV2Repository.write_verified_rows
    )


def test_lease_heartbeat_renews_periodically_while_active(heartbeat_clock) -> None:
    """The heartbeat itself: a live worker keeps calling renew() on a cadence,
    and stops promptly once told to -- independent of any repository."""
    calls: list[int] = []
    heartbeat = heartbeat_clock(
        lambda: (calls.append(1) or True),
        lease_seconds=1, interval_seconds=0.02,
    )
    heartbeat.start()
    for _ in range(3):
        heartbeat.tick()
    assert calls == [1, 1, 1]
    assert heartbeat._stop.intervals == [0.02] * 4
    heartbeat.stop()
    # No further renewals after stop() returns -- the thread actually exited.
    assert not heartbeat._thread.is_alive()
    assert calls == [1, 1, 1]


def test_lease_heartbeat_renewal_failure_does_not_raise(heartbeat_clock) -> None:
    """A renewal that merely *raises* (transient DB/network hiccup) proves
    nothing about ownership either way -- absorbed silently, tried again
    next interval, and never latches `lost`."""
    attempts: list[int] = []

    def broken_renew() -> bool:
        attempts.append(1)
        raise RuntimeError("connection lost")

    heartbeat = heartbeat_clock(broken_renew, lease_seconds=1, interval_seconds=0.02)
    heartbeat.start()
    for _ in range(3):
        heartbeat.tick()
    heartbeat.stop()  # must not raise, and must still join promptly
    assert attempts == [1, 1, 1]
    assert not heartbeat._thread.is_alive()
    assert heartbeat.lost is False
    heartbeat.check()  # must not raise -- a mere exception is not proof of loss


def test_lease_heartbeat_marks_lease_lost_when_renewal_returns_false(heartbeat_clock) -> None:
    """A renewal that returns False -- not an exception -- is the
    repository explicitly confirming the token no longer holds the lease.
    That is proof of loss: the heartbeat must latch it, stop trying to
    renew (there is nothing left to renew), and check() must raise from
    that point on so a caller cannot keep acting as the legitimate owner."""
    attempts: list[int] = []

    def losing_renew() -> bool:
        attempts.append(1)
        return False

    heartbeat = heartbeat_clock(losing_renew, lease_seconds=1, interval_seconds=0.02)
    heartbeat.start()
    heartbeat.tick()
    heartbeat._thread.join(timeout=5)

    assert not heartbeat._thread.is_alive()
    assert heartbeat.lost is True
    with pytest.raises(LeaseLostError):
        heartbeat.check()
    # The loop must stop calling renew once loss is proven -- no point
    # renewing a lease that is already confirmed gone.
    assert attempts == [1], "must not keep calling renew() after loss is latched"


def test_outbox_item_processing_slower_than_raw_lease_still_completes(
    tmp_path: Path, heartbeat_clock, lease_clock,
) -> None:
    """R03 (A): renewal protects in-flight work beyond the original lease."""

    renewals: list[datetime] = []
    real_renew = InMemoryStorageV2Repository.renew_outbox_lease

    class ObservedRepository(InMemoryStorageV2Repository):
        def renew_outbox_lease(self, item_id, token, lease_seconds):
            ok = real_renew(self, item_id, token, lease_seconds)
            if ok:
                renewals.append(lease_clock.now(timezone.utc))
            return ok

    class SlowSource(MemorySource):
        def fetch_outbox_batch(self, item):
            original_expiry = repository.outbox[item.id].lease_until
            for _ in range(3):
                lease_clock.advance(0.75)
                heartbeat_clock.instances[0].tick()
            assert lease_clock.now(timezone.utc) > original_expiry
            assert repository.claim_outbox("thief", 1) is None
            return super().fetch_outbox_batch(item)

    source = SlowSource([_event(1)], [_entity(1)], [_link(1, 1)])
    repository = ObservedRepository()
    item = enqueue_collector_batch(repository, batch_id=str(uuid.uuid4()), event_ids=[1])
    publisher = ArchivePublisher(tmp_path.resolve(), InMemoryArchiveManifestStore())

    result = run_outbox_once(
        source=source, repository=repository, publisher=publisher, lease_seconds=1,
    )

    assert len(renewals) == 3
    assert result["status"] == "ok"
    assert repository.outbox[item.id].state == "completed"


def test_outbox_lease_is_not_reclaimable_while_a_live_worker_is_processing(
    heartbeat_clock, lease_clock,
) -> None:
    """R03, at the repository layer: while LeaseHeartbeat is actively
    renewing, a second claim_outbox for the same item must keep failing to
    find it eligible, even after the item's original raw lease window has
    elapsed on the controlled clock."""
    repository = InMemoryStorageV2Repository()
    item = repository.enqueue_outbox(
        batch_id=str(uuid.uuid4()), first_event_id=1, last_event_id=1,
        event_count=1, event_ids=[1], identity_sha256=b"x" * 32,
    )
    token = "live-worker"
    claimed = repository.claim_outbox(token, 1)  # raw lease: 1 second
    assert claimed is not None

    heartbeat = heartbeat_clock(
        lambda: repository.renew_outbox_lease(item.id, token, 1),
        lease_seconds=1, interval_seconds=0.05,
    )
    heartbeat.start()
    try:
        # Advance past the original lease, renewing before each expiry.
        for _ in range(3):
            lease_clock.advance(0.75)
            heartbeat.tick()
        assert lease_clock.now(timezone.utc) > claimed.lease_until
        second_claim = repository.claim_outbox("second-worker", 1)
        assert second_claim is None, "a live, renewing worker's lease must not be reclaimable"
    finally:
        heartbeat.stop()

    # Once the heartbeat genuinely stops (worker "dies"), the lease is a
    # plain unrenewed timestamp again and becomes reclaimable after it
    # elapses -- same self-healing contract as before this fix (R04).
    lease_clock.advance(1.2)
    reclaimed = repository.claim_outbox("cleanup-worker", 60)
    assert reclaimed is not None
    assert reclaimed.id == item.id
    assert reclaimed.lease_token == "cleanup-worker"


def test_outbox_lease_with_no_heartbeat_expires_and_self_heals_like_before(tmp_path: Path) -> None:
    """R04: a worker that dies before ever renewing (crashed immediately
    after claim, or -- equivalently -- never started a heartbeat at all)
    must still self-heal exactly like the pre-existing reclaim contract:
    the lease is a plain timestamp with nothing keeping it alive."""
    repository = InMemoryStorageV2Repository()
    item = repository.enqueue_outbox(
        batch_id=str(uuid.uuid4()), first_event_id=1, last_event_id=1,
        event_count=1, event_ids=[1], identity_sha256=b"x" * 32,
    )
    dead = repository.claim_outbox("dead-before-first-heartbeat", 60)
    assert dead is not None
    # No LeaseHeartbeat ever started for this claim -- simulates a crash
    # between claim_outbox and the point run_outbox_once would have
    # started renewal. Force the lease into the past exactly like the
    # pre-existing expired-lease test does.
    repository.outbox[item.id] = replace(
        dead, lease_until=datetime.now(timezone.utc) - timedelta(seconds=1),
    )

    reclaimed = repository.claim_outbox("replacement-worker", 60)
    assert reclaimed is not None
    assert reclaimed.lease_token == "replacement-worker"
    assert reclaimed.attempt_count == 2


def test_outbox_failure_after_heartbeat_renewal_still_retries_cleanly(
    tmp_path: Path, heartbeat_clock, lease_clock,
) -> None:
    """R05 (E): at-least-once/retry semantics are unchanged by the
    heartbeat -- an item that fails partway through, genuinely *after* at
    least one real renewal already happened, still ends up failed/retryable
    with no stray lease, exactly as it would with the heartbeat absent."""

    renewals: list[datetime] = []
    real_renew = InMemoryStorageV2Repository.renew_outbox_lease

    class ObservedRepository(InMemoryStorageV2Repository):
        def renew_outbox_lease(self, item_id, token, lease_seconds):
            ok = real_renew(self, item_id, token, lease_seconds)
            if ok:
                renewals.append(lease_clock.now(timezone.utc))
            return ok

    class SlowThenBrokenSource(MemorySource):
        def fetch_outbox_batch(self, item):
            lease_clock.advance(0.75)
            heartbeat_clock.instances[0].tick()
            raise RuntimeError("source became unavailable mid-fetch")

    source = SlowThenBrokenSource([_event(1)], [_entity(1)], [_link(1, 1)])
    repository = ObservedRepository()
    item = enqueue_collector_batch(repository, batch_id=str(uuid.uuid4()), event_ids=[1])
    publisher = ArchivePublisher(tmp_path.resolve(), InMemoryArchiveManifestStore())

    result = run_outbox_once(
        source=source, repository=repository, publisher=publisher,
        lease_seconds=1, retry_seconds=5,
    )

    assert len(renewals) == 1
    assert result["status"] == "failed"
    failed_item = repository.outbox[item.id]
    assert failed_item.state == "failed"
    assert failed_item.lease_token is None
    assert failed_item.lease_until is None
    assert failed_item.available_at == lease_clock.now(timezone.utc) + timedelta(seconds=5)


def test_backfill_fails_closed_before_publish_when_checkpoint_lease_is_proven_lost(
    tmp_path: Path, heartbeat_clock,
) -> None:
    """B: once this worker's own heartbeat renewal proves (returns False,
    because another token now legitimately holds the checkpoint) that the
    lease is gone, no further state-changing work may happen as this
    worker -- not only the pre-existing final write-time token check inside
    write_verified_chunk, but the earlier, cheaper check before archive
    publish even starts. Proven with a publish-call spy that must never
    fire once loss is proven, mid-fetch."""

    publish_calls: list[str] = []
    real_publish_rows = ArchivePublisher.publish_rows

    class WatchedPublisher(ArchivePublisher):
        def publish_rows(self, **kwargs):
            publish_calls.append(str(kwargs.get("archive_set_id")))
            return real_publish_rows(self, **kwargs)

    class SlowSource(MemorySource):
        def fetch_batch(self, **kwargs):
            steal_lease()
            heartbeat_clock.instances[0].tick()
            assert heartbeat_clock.instances[0].lost
            return super().fetch_batch(**kwargs)

    source = SlowSource([_event(1)], [_entity(1)], [_link(1, 1)])
    repository = InMemoryStorageV2Repository()
    publisher = WatchedPublisher(tmp_path.resolve(), InMemoryArchiveManifestStore())
    worker_name = "backfill-lease-loss-test"

    def steal_lease() -> None:
        current = repository.checkpoints[worker_name]
        repository.checkpoints[worker_name] = replace(
            current,
            lease_token="a-different-worker",
            lease_until=datetime.now(timezone.utc) + timedelta(seconds=60),
        )

    result = run_backfill_once(
        worker_name=worker_name, source=source, repository=repository,
        publisher=publisher, lease_seconds=1,
    )

    assert result.status == "failed"
    assert "lease" in (result.error or "").lower()
    assert publish_calls == [], "archive publish must never happen once this worker's own lease is proven lost"
    # Ownership genuinely now belongs to the other token -- not silently
    # reset to unowned.
    assert repository.checkpoints[worker_name].lease_token == "a-different-worker"


def test_outbox_fails_closed_before_early_complete_when_lease_is_proven_lost(
    tmp_path: Path, heartbeat_clock,
) -> None:
    """B, outbox lease: the early-exit path (every event already published
    elsewhere -- nothing left to backfill) still must not call
    complete_outbox as this worker once its own outbox lease is proven
    lost, even though there is no archive publish step to skip here."""

    class SlowAlreadyPublishedRepository(InMemoryStorageV2Repository):
        def existing_published_source_event_ids(self, events):
            steal_lease()
            heartbeat_clock.instances[0].tick()
            assert heartbeat_clock.instances[0].lost
            return {int(row["id"]) for row in events}

    source = MemorySource([_event(1)], [_entity(1)], [_link(1, 1)])
    repository = SlowAlreadyPublishedRepository()
    item = enqueue_collector_batch(repository, batch_id=str(uuid.uuid4()), event_ids=[1])
    publisher = ArchivePublisher(tmp_path.resolve(), InMemoryArchiveManifestStore())

    def steal_lease() -> None:
        current = repository.outbox[item.id]
        repository.outbox[item.id] = replace(
            current,
            lease_token="a-different-worker",
            lease_until=datetime.now(timezone.utc) + timedelta(seconds=60),
        )

    result = run_outbox_once(
        source=source, repository=repository, publisher=publisher, lease_seconds=1,
    )

    assert result["status"] == "failed"
    assert "lease" in result["error"].lower()
    assert repository.outbox[item.id].lease_token == "a-different-worker"


def test_outbox_ownership_loss_stops_the_nested_backfill_before_its_own_publish(
    tmp_path: Path, heartbeat_clock,
) -> None:
    """Ownership boundary: run_outbox_once() owns the outbox item, but the
    nested run_backfill_once() it calls for tail processing has its own,
    completely separate checkpoint lease. This proves the two are no
    longer independent from the outbox item's point of view: the outbox
    lease is stolen mid-flight (during the outer fetch, before the nested
    backfill even starts), while the nested backfill's own checkpoint
    lease is never touched at all -- acquired fresh, still perfectly
    valid. Without threading the outer ownership through, the nested
    backfill would have no way to know its own checkpoint lease is not
    the whole story, and would go on to publish anyway. The publish-call
    spy proves it does not."""

    publish_calls: list[str] = []
    real_publish_rows = ArchivePublisher.publish_rows

    class WatchedPublisher(ArchivePublisher):
        def publish_rows(self, **kwargs):
            publish_calls.append(str(kwargs.get("archive_set_id")))
            return real_publish_rows(self, **kwargs)

    class SlowSource(MemorySource):
        def fetch_outbox_batch(self, item):
            steal_outbox_lease()
            heartbeat_clock.instances[0].tick()
            assert heartbeat_clock.instances[0].lost
            return super().fetch_outbox_batch(item)

    source = SlowSource([_event(1)], [_entity(1)], [_link(1, 1)])
    repository = InMemoryStorageV2Repository()
    item = enqueue_collector_batch(repository, batch_id=str(uuid.uuid4()), event_ids=[1])
    publisher = WatchedPublisher(tmp_path.resolve(), InMemoryArchiveManifestStore())

    def steal_outbox_lease() -> None:
        current = repository.outbox[item.id]
        repository.outbox[item.id] = replace(
            current,
            lease_token="a-different-worker",
            lease_until=datetime.now(timezone.utc) + timedelta(seconds=60),
        )

    result = run_outbox_once(
        source=source, repository=repository, publisher=publisher, lease_seconds=1,
    )

    assert result["status"] == "failed"
    assert "lease" in result["error"].lower()
    assert publish_calls == [], (
        "the nested backfill must not publish once the outbox item's own "
        "ownership is proven lost, even though its own checkpoint lease "
        "was acquired fresh and never touched"
    )
    # The checkpoint itself really was untouched -- it just never got far
    # enough to matter, not because someone else grabbed it too.
    checkpoint = repository.checkpoints.get(f"outbox-{item.batch_id}")
    assert checkpoint is not None
    assert checkpoint.state == "failed"


def test_checkpoint_ownership_loss_between_two_publications_stops_the_second(
    tmp_path: Path, heartbeat_clock,
) -> None:
    """Ownership boundary: run_backfill_once() does at least three separate
    state-changing steps -- event archive publish, link archive publish,
    and the verified chunk write. The pre-existing checks bracketed only
    the first and the last. This proves the gap in between is closed too:
    ownership is proven lost while the (slow) event archive publish is
    still in flight, and the link archive publish that would otherwise
    follow it must not start, even though it is a distinct step from the
    chunk write that was already checked before this fix."""

    publish_calls: list[str] = []
    real_publish_rows = ArchivePublisher.publish_rows

    class SlowFirstPublisher(ArchivePublisher):
        def publish_rows(self, **kwargs):
            kind = str(kwargs.get("archive_kind"))
            publish_calls.append(kind)
            if kind == "event":
                steal_checkpoint_lease()
                heartbeat_clock.instances[0].tick()
                assert heartbeat_clock.instances[0].lost
            return real_publish_rows(self, **kwargs)

    source = MemorySource([_event(1)], [_entity(1)], [_link(1, 1)])
    repository = InMemoryStorageV2Repository()
    publisher = SlowFirstPublisher(tmp_path.resolve(), InMemoryArchiveManifestStore())
    worker_name = "checkpoint-between-publications-test"

    def steal_checkpoint_lease() -> None:
        current = repository.checkpoints[worker_name]
        repository.checkpoints[worker_name] = replace(
            current,
            lease_token="a-different-worker",
            lease_until=datetime.now(timezone.utc) + timedelta(seconds=60),
        )

    result = run_backfill_once(
        worker_name=worker_name, source=source, repository=repository,
        publisher=publisher, lease_seconds=1,
    )

    assert result.status == "failed"
    assert "lease" in (result.error or "").lower()
    assert publish_calls == ["event"], (
        "the link archive publish must not start once ownership is proven "
        "lost between the two publications, even though the event archive "
        "publish that preceded it was allowed to finish"
    )


def _event(index: int) -> dict:
    return {
        "id": index,
        "raw_log_file_id": 1,
        "server_id": 1,
        "domain_id": 1,
        "site_id": 1,
        "log_source_id": 1,
        "event_record_id": 10_000 + index,
        "event_id": 4624,
        "version": 0,
        "level": 0,
        "task": 12544,
        "opcode": 0,
        "keywords": "0x8020000000000000",
        "provider_name": "Microsoft-Windows-Security-Auditing",
        "provider_guid": None,
        "channel": "Security",
        "computer": "DC1.host13.example.invalid",
        "time_created_utc": f"2026-07-13T10:00:{index % 60:02d}.1234567Z",
        "time_created_local": None,
        "record_xml": f"<Event><Id>{index}</Id></Event>",
        "message_text": None,
        "event_data_json": json.dumps({"TargetUserName": f"user-{index % 3}"}),
        "subject_user_sid": "S-1-5-18",
        "subject_user_name": "SYSTEM",
        "subject_domain_name": "EXAMPLE",
        "target_user_sid": f"S-1-5-21-{index}",
        "target_user_name": f"user-{index % 3}",
        "target_domain_name": "EXAMPLE",
        "ip_address": "192.0.2.2",
        "workstation_name": "WS1",
        "logon_id": hex(index),
        "correlation_id": None,
        "normalized_at": "2026-07-13T10:01:00+00:00",
        "normalized_hash": f"{index:064x}"[-64:],
    }


def _entity(index: int) -> dict:
    return {
        "id": index,
        "entity_type": "account",
        "natural_key": f"example\\user-{index}",
        "display_name": f"user-{index}",
        "domain_id": 1,
        "server_id": 1,
        "first_seen_utc": "2026-07-13T10:00:00Z",
        "last_seen_utc": "2026-07-13T10:05:00Z",
        "attributes_json": json.dumps({"sid": f"S-1-5-21-{index}"}),
    }


def _link(event_id: int, entity_id: int) -> dict:
    return {
        "event_id": event_id,
        "entity_id": entity_id,
        "link_role": "target",
        "confidence": 1.0,
        "evidence_json": json.dumps({"field": "TargetUserName"}),
        "extracted_from": "event_data_json",
        "attributes_json": "{}",
        "created_at": "2026-07-13T10:05:00Z",
    }


def test_direct_batch_reuses_archive_and_cursor_writer_before_compatibility_mirror(
    tmp_path: Path,
) -> None:
    order: list[str] = []

    class ObservedPublisher(ArchivePublisher):
        def publish_rows(self, **kwargs):
            order.append(f"archive:{kwargs['archive_kind']}")
            return super().publish_rows(**kwargs)

    class Repository(InMemoryStorageV2Repository):
        def __init__(self) -> None:
            self.dictionaries: dict[tuple[str, str], int] = {}

        def dictionary_id(self, kind: str, value: str) -> int:
            key = (kind, value)
            self.dictionaries.setdefault(key, len(self.dictionaries) + 1)
            return self.dictionaries[key]

        def write_verified_rows(self, **kwargs) -> bytes:
            order.append("write:v2")
            assert kwargs["cur"] is cursor
            assert kwargs["source_sha256"] == core_chunk_digest(
                kwargs["events"], kwargs["entities"], kwargs["links"], kwargs["facts"]
            )
            return kwargs["source_sha256"]

    cursor = object()
    manifest = InMemoryArchiveManifestStore()
    publisher = ObservedPublisher(tmp_path.resolve(), manifest)
    batch = SourceBatch((_event(1),), (_entity(1),), (_link(1, 1),))

    result = storage_v2_backfill.publish_direct_batch(
        batch_identity="collection-1:dc1:security:1",
        batch=batch,
        repository=Repository(),
        publisher=publisher,
        cur=cursor,
        compatibility_mirror=lambda _cur, _batch: order.append("mirror:v1"),
    )

    assert order == ["archive:event", "archive:link_detail", "write:v2", "mirror:v1"]
    assert result.event_count == 1
    assert result.entity_count == 1
    assert result.link_count == 1
    assert [block.state for block in manifest.blocks()] == ["published", "published"]


@pytest.mark.parametrize("with_links", [False, True])
def test_direct_agent_batch_writes_verified_core_without_archive(with_links):
    class Repository(InMemoryStorageV2Repository):
        def write_verified_rows(self, *, cur, **rows):
            # Use the transactional fake's real hash and replay checks.
            self.acquire_checkpoint("fixture-direct", "fixture-lease", 60)
            self.write_verified_chunk(
                worker_name="fixture-direct", lease_token="fixture-lease", high_watermark_event_id=1,
                start_event_id=1, end_event_id=1, next_chunk_size=1,
                source_rows=len(rows["events"]), source_link_rows=len(rows["links"]),
                archive_event_set_id="", archive_link_set_id=None, **rows)
            return self.chunk_audits[-1].target_sha256

    repository = Repository()
    batch = SourceBatch((_event(1),), (_entity(1),), (_link(1, 1),) if with_links else ())
    result = storage_v2_backfill.publish_direct_batch(
        batch_identity="fixture-agent-packet", batch=batch,
        repository=repository, publisher=None, cur=object())
    assert result.event_count == 1 and result.entity_count == 1
    assert result.link_count == int(with_links)
    assert result.archive_event_set_id is None and result.archive_link_set_id is None
    assert result.source_sha256 == result.target_sha256
    assert len(repository.events) == 1
    assert len(repository.links) == int(with_links)
    replay = storage_v2_backfill.publish_direct_batch(
        batch_identity="fixture-agent-packet", batch=batch,
        repository=repository, publisher=None, cur=object())
    assert replay.source_sha256 == result.source_sha256
    assert len(repository.events) == 1 and len(repository.links) == int(with_links)


class MemorySource:
    def __init__(self, events: list[dict], entities: list[dict], links: list[dict]) -> None:
        self.events = events
        self.entities = entities
        self.links = links

    def max_event_id(self) -> int:
        return max(row["id"] for row in self.events)

    def fetch_batch(self, *, after_event_id: int, through_event_id: int, limit: int) -> SourceBatch:
        selected = [row for row in self.events if after_event_id < row["id"] <= through_event_id][:limit]
        ids = {row["id"] for row in selected}
        links = [row for row in self.links if row["event_id"] in ids]
        entity_ids = {row["entity_id"] for row in links}
        entities = [row for row in self.entities if row["id"] in entity_ids]
        return SourceBatch(tuple(selected), tuple(entities), tuple(links))

    def fetch_outbox_batch(self, item) -> SourceBatch:
        requested = set(item.event_ids)
        selected = [row for row in self.events if row["id"] in requested]
        links = [row for row in self.links if row["event_id"] in requested]
        entity_ids = {row["entity_id"] for row in links}
        entities = [row for row in self.entities if row["id"] in entity_ids]
        return SourceBatch(tuple(selected), tuple(entities), tuple(links))


def test_feature_flags_read_storage_v2_and_invalid_values_are_explicit() -> None:
    """Reads are always Storage V2 (plan 6.5); publication stays off until configured."""
    settings = load_storage_v2_settings({})
    assert settings.read_mode == "v2"
    assert settings.write_mode == "v1"
    assert settings.valid is True

    rejected = load_storage_v2_settings({"ADLOG_STORAGE_READ_MODE": "magic"})
    assert rejected.valid is False
    assert rejected.read_mode == "v2"
    assert rejected.write_mode == "v1"
    assert "fail-closed" in rejected.diagnostics[0]
    with pytest.raises(StorageV2ConfigurationError):
        load_storage_v2_settings({"ADLOG_STORAGE_WRITE_MODE": "magic"}, strict=True)


def test_shadow_requires_only_a_positive_sample_rate() -> None:
    settings = load_storage_v2_settings({
        "ADLOG_STORAGE_READ_MODE": "shadow",
        "ADLOG_STORAGE_WRITE_MODE": "v1",
        "ADLOG_STORAGE_V2_SHADOW_SAMPLE_RATE": "0.25",
    })
    assert settings.shadow_read_enabled is True
    with pytest.raises(StorageV2ConfigurationError, match="positive sample rate"):
        load_storage_v2_settings({"ADLOG_STORAGE_READ_MODE": "shadow"}, strict=True)


def test_v2_writes_do_not_require_filesystem_configuration() -> None:
    settings = load_storage_v2_settings({
        "ADLOG_STORAGE_READ_MODE": "v2",
        "ADLOG_STORAGE_WRITE_MODE": "v2",
    }, strict=True)
    assert settings.valid is True
    assert settings.v2_read_enabled is True
    assert settings.v2_primary_write_enabled is True
    assert settings.public_dict() == {
        "read_mode": "v2", "write_mode": "v2", "shadow_sample_rate": 0.0,
        "valid": True, "diagnostics": [],
    }


def test_migrations_are_source_only_versioned_and_do_not_modify_v1_rows() -> None:
    migration_dir = ROOT / "config/postgres_migrations"
    for version, name in ((9, "storage_v2_foundation"), (10, "storage_v2_backfill_support"), (11, "storage_v2_runtime_routing")):
        text = (migration_dir / f"{version:03d}_{name}.sql").read_text(encoding="utf-8").lower()
        assert f"values ({version}, '{name}')" in text
        assert "update events set" not in text
        assert "delete from events" not in text
        assert "alter table events " not in text
        assert (migration_dir / f"{version:03d}_{name}.rollback.sql").is_file()
    schema = (ROOT / "config/postgres_schema.sql").read_text(encoding="utf-8")
    assert "(9, 'storage_v2_foundation')" not in schema
    roles = (migration_dir / "storage_v2_roles.sql").read_text(encoding="utf-8").lower()
    assert "adlog_storage_migrator nologin nosuperuser nocreatedb nobypassrls" in roles
    assert "adlog_storage_drill nologin nosuperuser createdb nobypassrls" in roles
    assert "adlog_storage_worker nologin nosuperuser nocreatedb nobypassrls" in roles
    assert "password" not in roles
    assert "grant usage, create on schema public to adlog_storage_owner" in roles
    assert "grant select, insert, update, delete on table schema_migrations to adlog_storage_owner" in roles
    assert "grant usage, select on sequence schema_migrations_id_seq to adlog_storage_owner" in roles
    assert "grant select on table events, observed_entities, event_entity_links to adlog_storage_owner" in roles
    for version in (9, 10, 11):
        migration = (migration_dir / next(path.name for path in migration_dir.glob(f"{version:03d}_*.sql") if ".rollback." not in path.name)).read_text(encoding="utf-8").lower()
        assert "set local role adlog_storage_owner" in migration
    migration10 = (migration_dir / "010_storage_v2_backfill_support.sql").read_text(encoding="utf-8").lower()
    assert "grant select on table events, observed_entities, event_entity_links to adlog_storage_worker" in roles
    assert "storage_v2_outbox_id_seq, storage_v2_shadow_results_id_seq" in migration10
    assert "all sequences in schema public" not in migration10
    assert "event_ids bigint[] not null" in migration10
    assert "cardinality(event_ids) = event_count" in migration10
    assert "storage_v2_outbox_range_unique" not in migration10
    migration11 = (migration_dir / "011_storage_v2_runtime_routing.sql").read_text(encoding="utf-8").lower()
    assert "grant usage, select on sequence storage_v2_outbox_id_seq, storage_v2_shadow_results_id_seq to adlog_user" in migration11


def test_archive_publish_is_deterministic_idempotent_and_exact(tmp_path: Path) -> None:
    manifest = InMemoryArchiveManifestStore()
    publisher = ArchivePublisher(tmp_path.resolve(), manifest)
    set_id = str(uuid.uuid4())
    rows = [_event(2), _event(1)]
    first = publisher.publish_rows(archive_set_id=set_id, archive_kind="event", block_index=0, rows=rows)
    second = publisher.publish_rows(archive_set_id=set_id, archive_kind="event", block_index=0, rows=rows)
    assert first.archive_sha256 == second.archive_sha256
    assert first.state == second.state == "published"
    assert manifest.archive_set(set_id)["state"] == "published"
    restored = ArchiveReader(manifest).read_event(archive_kind="event", event_id=2)
    assert restored["record_xml"] == rows[0]["record_xml"]


def test_archive_retry_after_manifest_publish_failure_completes_existing_file(tmp_path: Path) -> None:
    class FailOnceStore(InMemoryArchiveManifestStore):
        def __init__(self) -> None:
            super().__init__()
            self.failed = False

        def mark_published(self, identity):
            if not self.failed:
                self.failed = True
                raise RuntimeError("injected manifest commit failure")
            return super().mark_published(identity)

    store = FailOnceStore()
    publisher = ArchivePublisher(tmp_path.resolve(), store)
    set_id = str(uuid.uuid4())
    with pytest.raises(RuntimeError, match="manifest"):
        publisher.publish_rows(archive_set_id=set_id, archive_kind="event", block_index=0, rows=[_event(1)])
    block = publisher.publish_rows(archive_set_id=set_id, archive_kind="event", block_index=0, rows=[_event(1)])
    assert block.state == "published"
    assert len(list((tmp_path / "published").glob("*.gz"))) == 1


def test_link_detail_archive_allows_multiple_rows_for_one_event(tmp_path: Path) -> None:
    store = InMemoryArchiveManifestStore()
    publisher = ArchivePublisher(tmp_path.resolve(), store)
    rows = [
        {"event_id": 1, "entity_id": 10, "link_role": "target"},
        {"event_id": 1, "entity_id": 11, "link_role": "subject"},
    ]
    block = publisher.publish_rows(
        archive_set_id=str(uuid.uuid4()), archive_kind="link_detail", block_index=0,
        rows=rows, event_id_field="event_id",
    )
    assert block.row_count == 2
    assert block.first_event_id == block.last_event_id == 1


def test_link_detail_archive_is_deterministic_for_equal_event_ids_and_reads_all_rows(tmp_path: Path) -> None:
    rows = [
        {"event_id": 1, "entity_id": 11, "link_role": "subject"},
        {"event_id": 1, "entity_id": 10, "link_role": "target"},
    ]
    first_store = InMemoryArchiveManifestStore()
    second_store = InMemoryArchiveManifestStore()
    first = ArchivePublisher((tmp_path / "first").resolve(), first_store).publish_rows(
        archive_set_id=str(uuid.uuid4()), archive_kind="link_detail", block_index=0,
        rows=rows, event_id_field="event_id",
    )
    second = ArchivePublisher((tmp_path / "second").resolve(), second_store).publish_rows(
        archive_set_id=str(uuid.uuid4()), archive_kind="link_detail", block_index=0,
        rows=list(reversed(rows)), event_id_field="event_id",
    )
    assert first.raw_sha256 == second.raw_sha256
    assert first.archive_sha256 == second.archive_sha256
    reader = ArchiveReader(first_store)
    restored = reader.read_rows_for_event(archive_kind="link_detail", event_id=1)
    assert {(row["entity_id"], row["link_role"]) for row in restored} == {
        (10, "target"), (11, "subject"),
    }
    with pytest.raises(ArchiveIntegrityError, match="read_event is only valid"):
        reader.read_event(archive_kind="link_detail", event_id=1)


def test_quarantined_archive_identity_is_terminal_without_operator_recovery(tmp_path: Path) -> None:
    store = InMemoryArchiveManifestStore()
    publisher = ArchivePublisher(tmp_path.resolve(), store)
    set_id = str(uuid.uuid4())
    published = publisher.publish_rows(
        archive_set_id=set_id, archive_kind="event", block_index=0, rows=[_event(1)]
    )
    quarantined = store.quarantine(published.identity, "operator review required")
    assert quarantined.state == "quarantined"
    with pytest.raises(ArchiveIntegrityError, match="operator recovery"):
        publisher.publish_rows(
            archive_set_id=set_id, archive_kind="event", block_index=0, rows=[_event(1)]
        )
    with pytest.raises(ArchiveIntegrityError, match="cannot be published"):
        store.mark_published(published.identity)
    with pytest.raises(KeyError, match="published archive block not found"):
        ArchiveReader(store).read_rows_for_event(archive_kind="event", event_id=1)


def test_postgres_manifest_missing_or_quarantined_block_raises_domain_error() -> None:
    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def execute(self, *_args):
            return None

        def fetchone(self):
            return None

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def cursor(self):
            return Cursor()

    store = PostgresArchiveManifestStore(Connection)
    with pytest.raises(ArchiveIntegrityError, match="missing or quarantined"):
        store.mark_published((str(uuid.uuid4()), "event", 0))


def test_backfill_failure_does_not_advance_checkpoint_and_retry_is_idempotent(tmp_path: Path) -> None:
    source = MemorySource([_event(1), _event(2)], [_entity(1), _entity(2)], [_link(1, 1), _link(2, 2)])
    repository = InMemoryStorageV2Repository()
    repository.fail_next_chunk_write = True
    publisher = ArchivePublisher(tmp_path.resolve(), InMemoryArchiveManifestStore())

    failed = run_backfill_once(worker_name="main", source=source, repository=repository, publisher=publisher)
    assert failed.status == "failed"
    assert repository.get_checkpoint("main").last_verified_event_id == 0
    assert repository.events == {}

    retried = run_backfill_once(worker_name="main", source=source, repository=repository, publisher=publisher)
    assert retried.status == "ok"
    assert repository.get_checkpoint("main").last_verified_event_id == 2
    assert set(repository.events) == {1, 2}
    assert len(repository.chunk_audits) == 1
    assert repository.chunk_audits[0].source_sha256 == repository.chunk_audits[0].target_sha256
    assert repository.chunk_audits[0].source_link_rows == 2

    completed = run_backfill_once(worker_name="main", source=source, repository=repository, publisher=publisher)
    assert completed.status == "completed"


def test_backfill_semantic_hash_uses_rows_read_from_published_archive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = MemorySource([_event(1)], [_entity(1)], [_link(1, 1)])
    repository = InMemoryStorageV2Repository()
    publisher = ArchivePublisher(tmp_path.resolve(), InMemoryArchiveManifestStore())
    original = ArchiveReader.read_block_rows

    def altered_archive_rows(self: ArchiveReader, block):
        rows = [dict(row) for row in original(self, block)]
        rows[0]["confidence"] = 0.25
        return rows

    monkeypatch.setattr(ArchiveReader, "read_block_rows", altered_archive_rows)
    result = run_backfill_once(
        worker_name="archive-proof", source=source,
        repository=repository, publisher=publisher,
    )
    assert result.status == "failed"
    assert "semantic hash mismatch" in (result.error or "")
    assert repository.events == {}


def test_backfill_high_watermark_is_persisted_before_a_failed_chunk(tmp_path: Path) -> None:
    source = MemorySource([_event(1), _event(2)], [_entity(1), _entity(2)], [_link(1, 1), _link(2, 2)])
    repository = InMemoryStorageV2Repository()
    repository.fail_next_chunk_write = True
    publisher = ArchivePublisher(tmp_path.resolve(), InMemoryArchiveManifestStore())

    failed = run_backfill_once(worker_name="stable", source=source, repository=repository, publisher=publisher)
    assert failed.status == "failed"
    assert repository.get_checkpoint("stable").high_watermark_event_id == 2

    source.events.append(_event(3))
    source.entities.append(_entity(3))
    source.links.append(_link(3, 3))
    retried = run_backfill_once(worker_name="stable", source=source, repository=repository, publisher=publisher)
    assert retried.status == "ok"
    assert set(repository.events) == {1, 2}
    assert repository.get_checkpoint("stable").high_watermark_event_id == 2


def test_backfill_lease_conflict_returns_bounded_failure_without_overwriting_owner(tmp_path: Path) -> None:
    source = MemorySource([_event(1)], [_entity(1)], [_link(1, 1)])
    repository = InMemoryStorageV2Repository()
    repository.acquire_checkpoint("leased", "owner-token", 3600)
    publisher = ArchivePublisher(tmp_path.resolve(), InMemoryArchiveManifestStore())
    result = run_backfill_once(
        worker_name="leased", source=source, repository=repository, publisher=publisher
    )
    assert result.status == "failed"
    assert result.checkpoint_state == "unacquired"
    assert "leased by another worker" in (result.error or "")
    assert repository.get_checkpoint("leased").lease_token == "owner-token"


def test_backfill_preserves_original_error_when_checkpoint_failure_cannot_be_recorded(tmp_path: Path) -> None:
    class BrokenFailureRepository(InMemoryStorageV2Repository):
        def fail_checkpoint(self, worker_name: str, token: str, error: str):
            raise RuntimeError("checkpoint store unavailable")

    class BrokenSource(MemorySource):
        def max_event_id(self) -> int:
            raise RuntimeError("source unavailable")

    repository = BrokenFailureRepository()
    source = BrokenSource([_event(1)], [_entity(1)], [_link(1, 1)])
    publisher = ArchivePublisher(tmp_path.resolve(), InMemoryArchiveManifestStore())
    result = run_backfill_once(
        worker_name="broken", source=source, repository=repository, publisher=publisher
    )
    assert result.status == "failed"
    assert "source unavailable" in (result.error or "")
    assert "checkpoint store unavailable" in (result.error or "")


def test_backfill_source_failure_returns_failed_result_without_unbound_watermark(tmp_path: Path) -> None:
    class BrokenSource(MemorySource):
        def max_event_id(self) -> int:
            raise RuntimeError("source unavailable")

    source = BrokenSource([_event(1)], [_entity(1)], [_link(1, 1)])
    repository = InMemoryStorageV2Repository()
    publisher = ArchivePublisher(tmp_path.resolve(), InMemoryArchiveManifestStore())

    result = run_backfill_once(worker_name="broken", source=source, repository=repository, publisher=publisher)
    assert result.status == "failed"
    assert result.high_watermark_event_id == 0
    assert "source unavailable" in (result.error or "")
    assert repository.get_checkpoint("broken").state == "failed"


def test_adaptive_chunk_bounds() -> None:
    assert adaptive_chunk_size(25_000, 60) == 12_000
    assert adaptive_chunk_size(25_000, 5) == 50_000
    assert adaptive_chunk_size(5_000, 600) == 5_000


def test_outbox_contains_only_identity_and_retries_without_cursor_semantics(tmp_path: Path) -> None:
    source = MemorySource([_event(1), _event(2)], [_entity(1), _entity(2)], [_link(1, 1), _link(2, 2)])
    repository = InMemoryStorageV2Repository()
    item = enqueue_collector_batch(repository, batch_id=str(uuid.uuid4()), event_ids=[1, 2])
    serialized = repr(item)
    assert "record_xml" not in serialized and "event_data_json" not in serialized
    assert item.event_ids == (1, 2)
    publisher = ArchivePublisher(tmp_path.resolve(), InMemoryArchiveManifestStore())
    result = run_outbox_once(source=source, repository=repository, publisher=publisher)
    assert result["status"] == "ok"
    assert repository.outbox[item.id].state == "completed"


def test_postgres_v2_replay_requires_same_primary_id_and_exact_hash() -> None:
    values = {"id": 42, "source_core_sha256": b"a" * 32}
    assert _matches_event_replay({"id": 42, "source_core_sha256": b"a" * 32}, values)
    assert not _matches_event_replay({"id": 43, "source_core_sha256": b"a" * 32}, values)
    assert not _matches_event_replay({"id": 42, "source_core_sha256": b"b" * 32}, values)


def test_outbox_repository_rejects_unsorted_or_inconsistent_exact_ids() -> None:
    repository = InMemoryStorageV2Repository()
    with pytest.raises(ValueError, match="sorted and unique"):
        repository.enqueue_outbox(
            batch_id=str(uuid.uuid4()), first_event_id=1, last_event_id=3,
            event_count=2, event_ids=[3, 1], identity_sha256=b"x" * 32,
        )
    with pytest.raises(ValueError, match="event_count"):
        repository.enqueue_outbox(
            batch_id=str(uuid.uuid4()), first_event_id=1, last_event_id=3,
            event_count=3, event_ids=[1, 3], identity_sha256=b"x" * 32,
        )
    assert repository.outbox == {}


def test_link_transform_rejects_missing_created_at_to_keep_retries_deterministic() -> None:
    row = _link(1, 1)
    row.pop("created_at")
    with pytest.raises(StorageV2DataError, match="created_at"):
        link_core_from_v1(row, role_id=1, extracted_from_id=1)


def test_outbox_preserves_exact_non_contiguous_event_ids(tmp_path: Path) -> None:
    source = MemorySource(
        [_event(1), _event(2), _event(3)],
        [_entity(1), _entity(2), _entity(3)],
        [_link(1, 1), _link(2, 2), _link(3, 3)],
    )
    repository = InMemoryStorageV2Repository()
    item = enqueue_collector_batch(repository, batch_id=str(uuid.uuid4()), event_ids=[3, 1, 3])
    assert item.event_ids == (1, 3)
    publisher = ArchivePublisher(tmp_path.resolve(), InMemoryArchiveManifestStore())

    result = run_outbox_once(source=source, repository=repository, publisher=publisher)
    assert result["status"] == "ok"
    assert set(repository.events) == {1, 3}
    assert 2 not in repository.events


def test_entity_state_can_advance_without_being_treated_as_identity_conflict(tmp_path: Path) -> None:
    first_entity = _entity(1)
    source = MemorySource([_event(1)], [first_entity], [_link(1, 1)])
    repository = InMemoryStorageV2Repository()
    publisher = ArchivePublisher(tmp_path.resolve(), InMemoryArchiveManifestStore())
    first = run_backfill_once(worker_name="entity-update-1", source=source, repository=repository, publisher=publisher)
    assert first.status == "ok"

    updated_entity = dict(first_entity)
    updated_entity["display_name"] = "User One"
    updated_entity["last_seen_utc"] = "2026-07-13T11:05:00Z"
    updated_entity["attributes_json"] = json.dumps({"sid": "S-1-5-21-1", "enabled": True})
    second_source = MemorySource([_event(2)], [updated_entity], [_link(2, 1)])
    second = run_backfill_once(worker_name="entity-update-2", source=second_source, repository=repository, publisher=publisher)
    assert second.status == "ok"
    stored = repository.entities[1]
    assert stored.values["display_name"] == "User One"
    assert stored.details_json == {"sid": "S-1-5-21-1", "enabled": True}


def test_entity_details_participate_in_chunk_semantic_digest() -> None:
    repository = InMemoryStorageV2Repository()
    source = MemorySource([_event(1)], [_entity(1)], [_link(1, 1)])
    batch = source.fetch_batch(after_event_id=0, through_event_id=1, limit=10)
    from server.sli.storage.storage_v2_backfill import transform_batch
    from server.sli.storage.storage_v2_repository import core_chunk_digest

    events, entities, links, _ = transform_batch(repository, batch)
    original = core_chunk_digest(events, entities, links)
    modified = list(entities)
    modified[0] = type(entities[0])(
        values=entities[0].values,
        source_core_sha256=entities[0].source_core_sha256,
        details_json={"sid": "changed"},
        source_details_sha256=b"x" * 32,
    )
    assert core_chunk_digest(events, modified, links) != original


def test_postgres_adapter_uses_parameterized_values_and_allowlisted_identifiers() -> None:
    source = inspect.getsource(PostgresStorageV2Repository)
    assert "DICTIONARY_TABLES.get(kind)" in source
    assert "values (%s)" in source
    assert "for update skip locked" in source.lower()
    assert "like '" not in source.lower()
    assert "_validated_write_columns" in source
    assert "returning id" in source
    assert "idempotency hash mismatch" in source
    assert "initialize_high_watermark" in source
    assert source.count("from event_entity_link_blocks_v2 block") >= 2
    assert source.count("block.first_event_id<=%s and block.last_event_id>=%s") >= 2
    assert "from event_entity_links_v2 where event_id=any" not in source
    assert source.index("pg_advisory_xact_lock") < source.index("for item in events")
    assert "resolve_entity_identity_v2(source.entity_id)" in source


def test_dictionary_lookup_does_not_write_lock_existing_immutable_value() -> None:
    statements: list[str] = []

    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, sql, params):
            statements.append(" ".join(str(sql).split()).lower())
            assert params == ("account",)

        def fetchone(self):
            return {"id": 23}

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def cursor(self):
            return Cursor()

    repository = PostgresStorageV2Repository(lambda: Connection())

    assert repository.dictionary_id("entity_type", "account") == 23
    assert repository.dictionary_id("entity_type", "account") == 23
    assert len(statements) == 1
    assert statements[0].startswith("select id from storage_v2_entity_type")
    assert "insert" not in statements[0]


def test_resolved_link_keeps_source_evidence_and_changes_canonical_digest() -> None:
    values = {
        "event_id": 100,
        "entity_id": 10,
        "role_id": 1,
        "confidence": 1.0,
        "extracted_from_id": 1,
        "created_at": datetime(2026, 8, 2, tzinfo=timezone.utc),
    }
    source_link = LinkCoreV2(
        values=values,
        source_core_sha256=sha256_bytes(canonical_json_bytes(values)),
        details={"entity_id": 10, "source": "archive"},
    )

    resolved = _resolve_link_cores([source_link], {10: 20})[0]

    assert source_link.values["entity_id"] == 10
    assert source_link.details == {"entity_id": 10, "source": "archive"}
    assert resolved.values["entity_id"] == 20
    assert resolved.details == {"entity_id": 20, "source": "archive"}
    assert resolved.source_core_sha256 != source_link.source_core_sha256
    assert core_chunk_digest([], [], [resolved]) != core_chunk_digest(
        [], [], [source_link]
    )


def test_resolved_link_collision_fails_closed() -> None:
    def link(entity_id: int) -> LinkCoreV2:
        values = {
            "event_id": 100,
            "entity_id": entity_id,
            "role_id": 1,
            "confidence": 1.0,
            "extracted_from_id": 1,
            "created_at": datetime(2026, 8, 2, tzinfo=timezone.utc),
        }
        return LinkCoreV2(
            values=values,
            source_core_sha256=sha256_bytes(canonical_json_bytes(values)),
            details=None,
        )

    with pytest.raises(RuntimeError, match="resolved link identity collision"):
        _resolve_link_cores([link(10), link(20)], {10: 20, 20: 20})


def test_identity_capacity_monitor_warns_before_int32_exhaustion() -> None:
    ok = identity_capacity_status(max_event_id=10, max_entity_id=20, max_retained_reference_id=30)
    assert ok.status == "ok"
    assert ok.public_dict()["remaining_ids"] > 0
    warning = identity_capacity_status(
        max_event_id=10,
        max_entity_id=2_000_000_000,
        max_retained_reference_id=30,
    )
    assert warning.status == "warning"
    blocked = identity_capacity_status(
        max_event_id=10,
        max_entity_id=2_147_483_648,
        max_retained_reference_id=30,
    )
    assert blocked.status == "blocked"


class _VerifiedLinkCursor:
    """In-memory SQL boundary; block construction and verification stay real."""

    def __init__(self, existing):
        from server.sli.storage.storage_v2_link_blocks import build_link_blocks

        self.blocks = {(b.entity_id, b.block_no): b for b in build_link_blocks(existing)}
        self.events = {}
        self.rows = []
        self.lock_sets = []
        self.changed_entities = []

    def execute(self, sql, params=()):
        sql = " ".join(sql.split())
        self.rows = []
        if "to_regprocedure" in sql:
            self.rows = [{"available": False}]
        elif sql.startswith("insert into events_v2_core("):
            columns = sql.split("(", 1)[1].split(")", 1)[0].split(",")
            row = dict(zip(columns, params))
            if row["id"] not in self.events:
                self.events[row["id"]] = row
                self.rows = [{"id": row["id"]}]
        elif sql.startswith("select id from entities_v2"):
            self.lock_sets.append(list(params[0]))
            self.rows = [{"id": value} for value in params[0]]
        elif sql.startswith("select id from events_v2_core"):
            self.rows = [{"id": value} for value in params[0] if value in self.events]
        elif sql.startswith("select id,source_core_sha256 from events_v2_core"):
            ids = params[0] if isinstance(params[0], list) else [params[0]]
            self.rows = [self.events[value] for value in ids if value in self.events]
        elif sql.startswith("select expanded.event_id"):
            self.rows = [
                {"event_id": event_id, "entity_id": block.entity_id, "role_id": role_id}
                for block in self.blocks.values()
                for event_id, role_id in zip(block.event_ids, block.role_ids)
                if event_id in params[2]
            ]
        elif sql.startswith("select tail.*"):
            for entity_id in params[0]:
                blocks = [b for b in self.blocks.values() if b.entity_id == entity_id]
                if blocks:
                    b = max(blocks, key=lambda b: b.block_no)
                    self.rows.append({
                        "entity_id": b.entity_id, "block_no": b.block_no,
                        "event_ids": b.event_ids, "role_ids": b.role_ids,
                        "first_event_id": b.first_event_id, "last_event_id": b.last_event_id,
                        "identity_sha256": b.identity_sha256,
                    })
        elif sql.startswith("insert into event_entity_link_blocks_v2("):
            entity, number, first, last, events, roles, digest = params
            assert self.lock_sets and entity in self.lock_sets[-1]
            assert (entity, number) not in self.blocks
            self.blocks[entity, number] = storage_v2_repository.LinkBlock(
                entity, number, tuple(events), tuple(roles), digest,
            )
            assert (first, last) == (events[0], events[-1])
            self.changed_entities.append(entity)
        elif sql.startswith("update event_entity_link_blocks_v2 set"):
            first, last, events, roles, digest, entity, number, old_digest = params
            assert self.blocks[entity, number].identity_sha256 == old_digest
            self.blocks[entity, number] = storage_v2_repository.LinkBlock(
                entity, number, tuple(events), tuple(roles), digest,
            )
            assert (first, last) == (events[0], events[-1])
            self.changed_entities.append(entity)
            self.rows = [{"block_no": number}]
        else:
            raise AssertionError(f"Unexpected SQL: {sql}")

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows


@pytest.mark.parametrize("existing_indices,new_entities,second_entity", [
    ([], [7, 8], 8), ([0, 1], [], 8), ([0], [8], 8), ([1], [7], 8),
    ([0], [7], 7),
])
def test_verified_rows_mixed_entity_replay_preserves_full_lock_set(
    existing_indices, new_entities, second_entity,
):
    from server.sli.storage.storage_v2_models import EventCoreV2

    links = [link_core_from_v1(_link(i, e), role_id=1, extracted_from_id=1)
             for i, e in [(1, 7), (2, second_entity)]]
    events = [EventCoreV2(
        values={**dict.fromkeys(storage_v2_repository.EVENT_V2_WRITE_COLUMNS - {"source_core_sha256"}),
                "id": i, "server_id": 1, "channel_id": 1, "event_record_id": i,
                "time_created_utc": datetime(2026, 8, 1, tzinfo=timezone.utc)},
        source_core_sha256=bytes([i]) * 32,
    ) for i in (1, 2)]
    cursor = _VerifiedLinkCursor([links[i].values for i in existing_indices])
    repository = PostgresStorageV2Repository(lambda: pytest.fail("unexpected connection"))
    digest = core_chunk_digest(events, [], links)
    args = dict(cur=cursor, events=events, entities=[], facts=[], links=links,
                verified_archive_links=links, source_sha256=digest)

    assert repository.write_verified_rows(**args) == digest
    lock_set = sorted({7, second_entity})
    assert cursor.lock_sets == [lock_set]
    assert cursor.changed_entities == new_entities
    blocks = dict(cursor.blocks)
    assert {(e, b.entity_id, r) for b in blocks.values()
            for e, r in zip(b.event_ids, b.role_ids)} == {(1, 7, 1), (2, second_entity, 1)}
    assert repository.write_verified_rows(**args) == digest
    assert cursor.blocks == blocks
    assert cursor.lock_sets == [lock_set, lock_set]
    assert cursor.changed_entities == new_entities

    with pytest.raises(RuntimeError, match="source chunk semantic hash mismatch"):
        repository.write_verified_rows(**{**args, "source_sha256": b"x" * 32})
    with pytest.raises(RuntimeError, match="verified archive semantic hash mismatch"):
        repository.write_verified_rows(**{**args, "verified_archive_links": links[:1]})
    assert cursor.blocks == blocks

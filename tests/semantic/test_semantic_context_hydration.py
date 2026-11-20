from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import uuid

import pytest

from server.sli.semantic.semantic_context import hydrate_dispatch_context
from server.sli.semantic.semantic_correlation_repository import CorrelationRuleDefinition
from server.sli.semantic.semantic_dispatch import compile_correlation_rule, match_compiled_rule
from server.sli.semantic.semantic_dispatch_repository import load_dispatch_work_item
from server.sli.semantic.semantic_processing import NormalizedEvent
from server.sli.storage.storage_v2_archive import (
    ArchivePublisher,
    ArchiveReader,
    InMemoryArchiveManifestStore,
)
from server.source_packs.registry import semantic_event_identities_for_types


NOW = datetime(2026, 7, 29, 10, 0, tzinfo=timezone.utc)


def test_source_pack_compiles_exact_context_identity_from_projection() -> None:
    identities = semantic_event_identities_for_types(
        [
            "authentication.session.created",
            "audit.policy.changed",
        ]
    )
    by_type = {identity.semantic_type: identity for identity in identities}
    session = by_type["authentication.session.created"]
    assert session.source == "sli.windows.ad-dc"
    assert session.stream == "Security"
    assert session.event_key == "4624"
    assert session.provider_name == "Microsoft-Windows-Security-Auditing"
    assert session.noise_class == "context"
    assert session.noise_catalog_version
    assert by_type["audit.policy.changed"].noise_class == "signal"


class ContextCursor:
    def __init__(self, rows: list[dict[str, object]]) -> None:
        self.rows = rows
        self.sql = ""
        self.params: tuple[object, ...] = ()

    def execute(self, sql: str, params: tuple[object, ...]) -> None:
        self.sql = " ".join(sql.split()).lower()
        self.params = params

    def fetchall(self) -> list[dict[str, object]]:
        return list(self.rows)


class ContextArchive:
    def __init__(self, payloads: dict[int, dict[str, object]]) -> None:
        self.payloads = payloads
        self.requests: list[tuple[set[int], int]] = []

    def read_events_many(
        self, event_ids, *, max_blocks: int
    ) -> dict[int, dict[str, object]]:
        requested = {int(value) for value in event_ids}
        self.requests.append((requested, max_blocks))
        return {event_id: self.payloads[event_id] for event_id in requested}


def test_context_hydration_is_exact_bounded_and_persists_no_job(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    summary = {
        "id": 7,
        "server_id": 3,
        "domain_id": 1,
        "log_source_id": 2,
        "event_id": 4624,
        "time_created_utc": NOW,
        "normalized_hash": b"x" * 32,
        "correlation_id": None,
        "migrated_at": NOW,
        "provider_name": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "computer": "DC3",
    }
    archive = ContextArchive(
        {
            7: {
                "id": 7,
                "server_id": 3,
                "domain_id": 1,
                "log_source_id": 2,
                "event_id": 4624,
                "time_created_utc": NOW.isoformat(),
                "event_data_json": {},
            }
        }
    )
    normalized = NormalizedEvent(
        source_event_id=7,
        semantic_type="authentication.session.created",
        occurred_at_utc=NOW,
        roles={"source_host": "3"},
        facts={},
        quality={},
        semantic_sha256="7" * 64,
    )
    persisted: list[int] = []
    monkeypatch.setattr(
        "server.sli.semantic.semantic_context.normalize_semantic_source_payload",
        lambda payload: normalized,
    )
    monkeypatch.setattr(
        "server.sli.semantic.semantic_context.persist_normalized_event",
        lambda _cur, *, event, source_identity: (
            persisted.append(event.source_event_id)
            if source_identity["id"] == event.source_event_id
            else None
        ),
    )
    cur = ContextCursor([summary])

    count = hydrate_dispatch_context(
        cur,
        archive=archive,  # type: ignore[arg-type]
        semantic_types=("authentication.session.created",),
        join_roles=("source_host", "affected_entity"),
        trigger_roles={
            "source_host": "3",
            "affected_entity": "S-1-5-21-7",
        },
        partition_key="3",
        start_utc=NOW,
        end_utc=NOW,
    )

    assert count == 1
    assert persisted == [7]
    assert archive.requests == [({7}, 8)]
    assert "lower(channel.value)=lower(%s)" in cur.sql
    assert "lower(coalesce(provider.value,''))=lower(%s)" in cur.sql
    assert "core.target_user_sid" in cur.sql
    assert "lower(case when nullif(btrim(core.target_user_sid)" in cur.sql
    assert "stored_noise_catalog_version" in cur.sql
    assert "normalized.source_event_id is null" in cur.sql
    assert cur.params[3:6] == (3, NOW, NOW)
    assert cur.params[-1] == 256


def test_context_hydration_fails_before_archive_on_unbounded_result() -> None:
    rows = [{"id": value} for value in range(5001)]
    archive = ContextArchive({})
    with pytest.raises(RuntimeError, match="exceeds matcher bound"):
        hydrate_dispatch_context(
            ContextCursor(rows),
            archive=archive,  # type: ignore[arg-type]
            semantic_types=("authentication.session.created",),
            join_roles=("source_host",),
            trigger_roles={"source_host": "3"},
            partition_key="3",
            start_utc=NOW,
            end_utc=NOW,
        )
    assert archive.requests == []


def test_failed_then_successful_rule_uses_context_without_a_context_job(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    definition = {
        "type": "all_of",
        "inputs": [
            "authentication.session.failed",
            "authentication.session.created",
        ],
        "join_roles": ["source_host", "affected_entity"],
        "window_seconds": 300,
        "output_relation_kind": "authentication.failed_then_succeeded",
        "confidence": "medium",
        "explanation": "A successful session followed failures for the same account.",
    }
    source_rule = CorrelationRuleDefinition(
        rule_id="failed-then-success",
        rule_version=1,
        rule_kind="all_of",
        definition=definition,
    )
    compiled = compile_correlation_rule(source_rule)

    class LoadCursor:
        def __init__(self) -> None:
            self.sql = ""
            self.params = ()

        def execute(self, sql: str, params) -> None:
            self.sql = " ".join(sql.split()).lower()
            self.params = params

        def fetchone(self):
            if "from semantic_correlation_dispatch_jobs job" in self.sql:
                return {
                    "job_id": "job-1",
                    "lease_token": "lease-1",
                    "is_late": False,
                    "partition_key": "3",
                    "occurred_at_utc": NOW,
                    "source_event_id": 10,
                    "semantic_contract_version": 1,
                    "normalizer_id": "windows-event-normalizer",
                    "normalizer_version": "1",
                    "trigger_roles_json": {
                        "source_host": "3",
                        "affected_entity": "S-1-5-21-7",
                    },
                    "rule_id": source_rule.rule_id,
                    "rule_version": source_rule.rule_version,
                    "rule_kind": source_rule.rule_kind,
                    "lifecycle_status": "test",
                    "definition_json": definition,
                    "definition_sha256": source_rule.definition_sha256,
                }
            return None

        def fetchall(self):
            if "from normalized_events" not in self.sql:
                return []
            return [
                {
                    "source_event_id": 10,
                    "semantic_type": "authentication.session.failed",
                    "occurred_at_utc": NOW,
                    "roles_json": {
                        "source_host": "3",
                        "affected_entity": "S-1-5-21-7",
                    },
                    "facts_json": {},
                    "quality_json": {},
                    "semantic_sha256": bytes.fromhex("1" * 64),
                },
                {
                    "source_event_id": 11,
                    "semantic_type": "authentication.session.created",
                    "occurred_at_utc": NOW + timedelta(minutes=1),
                    "roles_json": {
                        "source_host": "3",
                        "affected_entity": "S-1-5-21-7",
                    },
                    "facts_json": {},
                    "quality_json": {},
                    "semantic_sha256": bytes.fromhex("2" * 64),
                },
            ]

    hydrated: list[tuple[str, ...]] = []
    monkeypatch.setattr(
        "server.sli.semantic.semantic_dispatch_repository.hydrate_dispatch_context",
        lambda _cur, **kwargs: hydrated.append(tuple(kwargs["semantic_types"])) or 1,
    )
    cur = LoadCursor()
    work = load_dispatch_work_item(
        cur,
        job_id="job-1",
        lease_token="lease-1",
        archive=object(),  # type: ignore[arg-type]
    )
    relations = match_compiled_rule(work.rule, work.events)

    assert hydrated == [compiled.input_types]
    assert "roles_json @> %s::jsonb" in cur.sql
    assert "cross join lateral" in cur.sql
    assert cur.params[-1] == 256
    assert len(relations) == 1
    assert relations[0].source_event_ids == (10, 11)


def test_bulk_event_archive_reads_blocks_once_and_rejects_missing(
    tmp_path: Path,
) -> None:
    store = InMemoryArchiveManifestStore()
    publisher = ArchivePublisher(tmp_path.resolve(), store)
    publisher.publish_rows(
        archive_set_id=str(uuid.uuid4()),
        archive_kind="event",
        block_index=0,
        rows=[
            {"id": 1, "event_id": 4624},
            {"id": 2, "event_id": 4672},
        ],
    )
    reader = ArchiveReader(store)
    assert set(reader.read_events_many([2, 1], max_blocks=1)) == {1, 2}
    with pytest.raises(KeyError, match="missing requested identities"):
        reader.read_events_many([1, 3], max_blocks=1)

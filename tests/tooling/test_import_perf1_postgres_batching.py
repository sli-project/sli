from __future__ import annotations

import importlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


module = importlib.import_module("scripts.import.import_event_jsonl_to_postgres")


class FakeCursor:
    def __init__(self) -> None:
        self.events: dict[tuple[str, int, str], int] = {}
        self.entities: dict[tuple[str, str], int] = {}
        self._rows: list[dict] = []
        self.execute_count = 0
        self.event_insert_calls = 0
        self.event_lookup_calls = 0
        self.entity_upsert_calls = 0
        self.entity_update_calls = 0
        self.link_insert_calls = 0
        self.links_params = 0

    def execute(self, sql: str, params=()) -> None:
        self.execute_count += 1
        normalized = " ".join(sql.lower().split())
        values = list(params)
        self._rows = []
        if "insert into events(" in normalized and "returning id, channel, event_record_id, time_created_utc" in normalized:
            self.event_insert_calls += 1
            width = len(module.EVENT_COLUMNS)
            for offset in range(0, len(values), width):
                item = values[offset : offset + width]
                key = module._event_key(item[13], item[5], item[15])
                if key in self.events:
                    continue
                event_id = len(self.events) + 1
                self.events[key] = event_id
                self._rows.append(
                    {
                        "id": event_id,
                        "channel": item[13],
                        "event_record_id": item[5],
                        "time_created_utc": item[15],
                    }
                )
            return
        if normalized.startswith("with wanted(channel, event_record_id, time_created_utc)"):
            self.event_lookup_calls += 1
            for offset in range(0, len(values) - 1, 3):
                key = module._event_key(values[offset], values[offset + 1], values[offset + 2])
                event_id = self.events.get(key)
                if event_id is not None:
                    self._rows.append(
                        {
                            "id": event_id,
                            "channel": values[offset],
                            "event_record_id": values[offset + 1],
                            "time_created_utc": values[offset + 2],
                        }
                    )
            return
        if "insert into observed_entities(" in normalized and "returning id, entity_type, natural_key" in normalized:
            self.entity_upsert_calls += 1
            for offset in range(0, len(values), 8):
                entity_type, natural_key = str(values[offset]), str(values[offset + 1])
                key = (entity_type, natural_key)
                entity_id = self.entities.setdefault(key, len(self.entities) + 1)
                self._rows.append({"id": entity_id, "entity_type": entity_type, "natural_key": natural_key})
            return
        if normalized.startswith("update observed_entities as target set"):
            self.entity_update_calls += 1
            return
        if "insert into event_entity_links(" in normalized:
            self.link_insert_calls += 1
            self.links_params += len(values) // 7
            return
        raise AssertionError(f"Unexpected SQL in fake cursor: {normalized[:160]}")

    def fetchall(self):
        return list(self._rows)


def _row(record_id: int, *, time_created: str | None = None) -> dict:
    return {
        "record_id": record_id,
        "event_id": 4624,
        "version": 0,
        "level": 0,
        "task": 0,
        "opcode": 0,
        "keywords": "0x0",
        "provider_name": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "machine_name": "DC1.example.invalid",
        "time_created": time_created or f"2026-07-11T00:00:{record_id % 60:02d}.0000000Z",
        "xml": "",
        "message": None,
    }


def test_direct_event_source_row_is_complete_and_retry_deterministic() -> None:
    row = _row(17)
    event_data = {"TargetUserName": "alice"}

    first = module.build_direct_event_source_row(
        event_db_id=101,
        raw_log_file_id=11,
        server_id=12,
        domain_id=13,
        site_id=14,
        log_source_id=15,
        normalized_at="2026-08-26T00:00:00+00:00",
        row=row,
        event_data=event_data,
    )
    replay = module.build_direct_event_source_row(
        event_db_id=101,
        raw_log_file_id=11,
        server_id=12,
        domain_id=13,
        site_id=14,
        log_source_id=15,
        normalized_at="2026-08-26T00:00:00+00:00",
        row=row,
        event_data=event_data,
    )

    assert first == replay
    assert first["id"] == 101
    assert first["event_record_id"] == 17
    assert first["computer"] == "DC1.example.invalid"
    assert first["normalized_at"] == "2026-08-26T00:00:00+00:00"
    assert json.loads(first["event_data_json"])["TargetUserName"] == "alice"
    assert len(first["normalized_hash"]) == 64


def test_direct_file_digest_rejects_content_changed_after_reservation() -> None:
    with pytest.raises(RuntimeError, match="changed during direct import"):
        module.verify_direct_file_digest("a" * 64, "b" * 64)


def test_source_capture_rows_use_v2_core_for_direct_route() -> None:
    class Cursor:
        def __init__(self):
            self.sql = ""

        def execute(self, sql, params=()):
            self.sql = " ".join(sql.lower().split())
            assert params == (17,)

        def fetchall(self):
            return []

    cur = Cursor()
    assert module._source_capture_rows(
        cur, raw_log_file_id=17, storage_route="v2",
    ) == []
    assert "events_v2_core" in cur.sql
    assert "from events " not in cur.sql


def test_direct_raw_finalize_never_repairs_v1_event_references() -> None:
    class Cursor:
        def __init__(self):
            self.statements = []
            self.rows = iter((
                {"id": 17, "sha256": "pending:test"},
                {"id": 18},
            ))

        def execute(self, sql, params=()):
            self.statements.append(" ".join(sql.lower().split()))

        def fetchone(self):
            return next(self.rows)

    cur = Cursor()
    with pytest.raises(RuntimeError, match="direct raw log reservation"):
        module.finalize_raw_log_file(
            cur,
            raw_log_file_id=17,
            server_id=1,
            log_source_id=2,
            sha256_value="a" * 64,
            rows_count=1,
            repair_v1_references=False,
        )
    assert not any("update events" in sql for sql in cur.statements)


def test_direct_event_ids_reuse_verified_v2_source_identity_and_allocate_only_missing() -> None:
    first = _row(1)
    second = _row(2)
    reserved: list[dict] = []

    class Repository:
        def reserve_event_identities(self, events):
            reserved.extend(dict(item) for item in events)
            return [
                {"ordinal": 0, "id": 50, "published": True},
                {"ordinal": 1, "id": 101, "published": False},
            ]

    result = module.resolve_direct_event_ids(
        repository=Repository(),
        server_id=7,
        channel_ids={"Security": 3},
        items=[(first, {}), (second, {})],
    )

    assert [(item[0], item[1]) for item in result] == [(50, False), (101, True)]
    assert [item["channel_id"] for item in reserved] == [3, 3]
    assert [item["normalized_hash"] for item in reserved] == [
        module.event_normalized_hash(first), module.event_normalized_hash(second)
    ]


def test_direct_entity_ids_merge_existing_v2_history_and_allocate_only_missing() -> None:
    existing = module.EntityState(
        entity_type="account",
        natural_key="example\\alice",
        display_name="Alice",
        domain_id=7,
        server_id=None,
        first_seen="2026-08-26T00:00:00+00:00",
        last_seen="2026-08-26T00:00:00+00:00",
        attributes_json=json.dumps({"current": True}),
    )
    new = module.EntityState(
        entity_type="account",
        natural_key="example\\bob",
        display_name="Bob",
        domain_id=7,
        server_id=None,
        first_seen="2026-08-26T00:01:00+00:00",
        last_seen="2026-08-26T00:01:00+00:00",
        attributes_json="{}",
    )

    class Repository:
        def dictionary_id(self, kind: str, value: str) -> int:
            assert kind == "entity_type"
            assert value == "account"
            return 9

        def reserve_entity_identities(self, entities):
            assert entities == [
                {"entity_type_id": 9, "natural_key": "example\\alice"},
                {"entity_type_id": 9, "natural_key": "example\\bob"},
            ]
            return [
                {"ordinal": 0, "id": 50, "published": True},
                {"ordinal": 1, "id": 101, "published": False},
            ]

    class Cursor:
        def __init__(self) -> None:
            self.rows: list[dict] = []

        def execute(self, sql: str, params=()) -> None:
            normalized = " ".join(sql.lower().split())
            if normalized.startswith("with wanted(ordinal,id)"):
                self.rows = [
                    {
                        "ordinal": 0,
                        "id": 50,
                        "display_name": "Alice old",
                        "domain_id": 7,
                        "server_id": None,
                        "first_seen_utc": "2026-07-01T00:00:00+00:00",
                        "last_seen_utc": "2026-07-02T00:00:00+00:00",
                        "attributes_json": {"old": True},
                    },
                    {"ordinal": 1, "id": None},
                ]
                return
            raise AssertionError(normalized)

        def fetchall(self):
            return list(self.rows)

    module.assign_direct_entity_ids(
        Cursor(),
        states=[existing, new],
        repository=Repository(),
        resolve_identity_merges=False,
    )

    assert existing.entity_id == existing.effective_entity_id == 50
    assert existing.first_seen == "2026-07-01T00:00:00+00:00"
    assert existing.last_seen == "2026-08-26T00:00:00+00:00"
    assert json.loads(existing.attributes_json) == {"current": True}
    assert new.entity_id == new.effective_entity_id == 101


def test_direct_source_batch_uses_one_extractor_result_for_v2_archive_and_links() -> None:
    row = _row(17)
    event_data = {"TargetUserName": "alice"}
    state = module.EntityState(
        entity_type="account",
        natural_key="example\\alice",
        display_name="Alice",
        domain_id=7,
        server_id=None,
        first_seen=row["time_created"],
        last_seen=row["time_created"],
        attributes_json=json.dumps({"sid": "S-1-5-21-1"}),
        entity_id=201,
        effective_entity_id=201,
    )
    link = {
        "entity_type": "account",
        "natural_key": "example\\alice",
        "link_role": "target",
        "confidence": 1.0,
        "evidence": {"field": "TargetUserName"},
        "extracted_from": "event_data",
        "attributes": {"sid": "S-1-5-21-1"},
    }

    batch = module.build_direct_source_batch(
        event_results=[(101, True, row, event_data)],
        pending=[(101, ("account", "example\\alice"), link)],
        entity_cache={("account", "example\\alice"): state},
        raw_log_file_id=11,
        server_id=12,
        domain_id=13,
        site_id=14,
        log_source_id=15,
        normalized_at="2026-08-26T00:00:00+00:00",
    )

    assert [item["id"] for item in batch.events] == [101]
    assert [item["id"] for item in batch.entities] == [201]
    assert batch.links == ({
        "event_id": 101,
        "entity_id": 201,
        "link_role": "target",
        "confidence": 1.0,
        "evidence_json": json.dumps({"field": "TargetUserName"}, ensure_ascii=False),
        "extracted_from": "event_data",
        "attributes_json": json.dumps({"sid": "S-1-5-21-1"}, ensure_ascii=False, sort_keys=True),
        "created_at": "2026-08-26T00:00:00+00:00",
    },)


def test_v2_projection_schema_gate_fails_before_import_rows() -> None:
    class GateCursor:
        def execute(self, _sql, _params=()):
            return None

        def fetchone(self):
            return {"jobs_ready": False, "current_ready": False, "migration_ready": False}

    try:
        module.require_entity_state_projection_schema(GateCursor())
    except RuntimeError as exc:
        assert "requires accepted migration 019 before import" in str(exc)
    else:
        raise AssertionError("missing migration must fail closed")


def test_import_refuses_without_recorded_storage_v2_admission(monkeypatch, tmp_path: Path) -> None:
    """Storage V2 is the only store (plan 6.5): no admission, nothing is read or written."""
    path = tmp_path / "Security.jsonl"
    path.write_text(json.dumps(_row(1)), encoding="utf-8")
    monkeypatch.setattr(module, "iter_jsonl", lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("rows read")))
    with pytest.raises(RuntimeError, match="storage_v2_admission_required"):
        module.import_file(
            object(), path, collection_run_id=1, server_id=2, domain_id=3, site_id=4,
            commit_direct_metadata=lambda: None,
        )


def test_direct_runtime_refuses_a_v1_compatibility_mirror(monkeypatch) -> None:
    """The V1 mirror wrote relations migration 097 dropped; that route is refused."""
    monkeypatch.setattr(module, "is_controller_authorization", lambda _authorization: True)
    with pytest.raises(RuntimeError, match="unsupported authorized direct route"):
        module.authorized_direct_import_runtime(
            authorization=SimpleNamespace(route="v2_primary_compat"), repository=object(),
            publisher=object(), connect_factory=object, normalized_at="now",
        )

def test_direct_publication_excludes_already_published_overlap_events() -> None:
    replay = (10, False, {"record_id": 100}, {})
    new = (11, True, {"record_id": 101}, {})

    assert module._direct_publication_results([replay, new]) == [new]
    assert module._direct_publication_results([replay]) == []


def test_authorized_direct_import_publishes_v2_without_v1_or_outbox(monkeypatch, tmp_path: Path) -> None:
    path = tmp_path / "Security.jsonl"
    path.write_text(json.dumps(_row(1)), encoding="utf-8")
    calls: list[str] = []

    class Repository:
        def reserve_raw_log_file(self, **kwargs):
            assert calls == ["metadata_commit"]
            calls.append("reserve")
            assert kwargs["sha256"] == module.sha256_file(path)
            return {"id": 11, "imported_at": "2026-08-26T00:00:00+00:00"}

        def dictionary_id(self, kind, value):
            assert (kind, value) == ("channel", "Security")
            return 3

        def reserve_event_identities(self, events):
            assert len(events) == 1
            return [{"ordinal": 0, "id": 101, "published": False}]

    worker_cur = object()

    class WorkerCursorContext:
        def __enter__(self):
            return worker_cur

        def __exit__(self, *_args):
            return False

    class WorkerConnection:
        def __enter__(self):
            calls.append("worker_connect")
            return self

        def __exit__(self, *_args):
            return False

        def cursor(self):
            return WorkerCursorContext()

    repository = Repository()
    runtime = module.DirectImportRuntime(
        repository=repository,
        publisher=object(),
        connect_factory=WorkerConnection,
        normalized_at="unused",
        compatibility_mirror=None,
        _seal=module._DIRECT_RUNTIME_SEAL,
    )
    monkeypatch.setattr(module, "get_log_source", lambda *_args: 15)
    monkeypatch.setattr(module, "require_entity_state_projection_schema", lambda *_args: calls.append("schema"))
    monkeypatch.setattr(module, "_collect_links_for_batch", lambda *_args, **_kwargs: [])
    def finalize_raw_log_file(*_args, **kwargs):
        assert kwargs["collection_run_id"] == 1
        return 11

    monkeypatch.setattr(module, "finalize_raw_log_file", finalize_raw_log_file)
    monkeypatch.setattr(module, "_persist_source_capture_continuity", lambda *_args, **_kwargs: True)

    def publish_direct_batch(**kwargs):
        calls.append("publish")
        assert kwargs["cur"] is worker_cur
        batch = kwargs["batch"]
        assert batch.events[0]["id"] == 101
        assert batch.events[0]["raw_log_file_id"] == 11
        assert batch.events[0]["normalized_at"] == "2026-08-26T00:00:00+00:00"
        return SimpleNamespace(event_count=1)

    monkeypatch.setattr(module, "publish_direct_batch", publish_direct_batch, raising=False)
    inserted, skipped, profile = module.import_file(
        object(), path, collection_run_id=1, server_id=2, domain_id=3, site_id=4,
        direct_runtime=runtime,
        commit_direct_metadata=lambda: calls.append("metadata_commit"),
    )

    assert (inserted, skipped) == (1, 0)
    assert calls == ["metadata_commit", "reserve", "schema", "worker_connect", "publish"]
    assert profile["storage_v2_outbox_events"] == 0
    assert profile["source_capture_continuity_persisted"] is True


def test_import_profile_parser(tmp_path: Path):
    runner = importlib.import_module("scripts.run_dc_log_pilot")
    payload = {
        "package_type": "POSTGRES_IMPORT_PROFILE",
        "summary": {"rows": 10000, "stage_ms": {"event_batches": 1200}},
    }
    parsed = runner.parse_import_profile("noise\nimport_profile=" + json.dumps(payload) + "\ntotal_inserted=1, total_skipped=0")
    assert parsed == payload

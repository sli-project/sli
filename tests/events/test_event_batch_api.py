from __future__ import annotations

from http import HTTPStatus
from types import SimpleNamespace

import pytest


def test_batch_event_ids_are_exact_deduplicated_and_capped() -> None:
    from server.api.routes.events import _batch_event_db_ids

    values = ["3,2,3,0,-1,not-an-id", *(str(value) for value in range(4, 150))]
    result = _batch_event_db_ids({"event_db_id": values})

    assert result[:3] == [3, 2, 4]
    assert len(result) == 100
    assert len(result) == len(set(result))
    assert all(value > 0 for value in result)


def test_batch_event_api_preserves_requested_order_and_marks_missing(monkeypatch) -> None:
    from server.api.routes import events as routes_events

    captured: list[tuple[dict, HTTPStatus]] = []
    monkeypatch.setattr(routes_events, "get_event_details_by_ids", lambda ids: {
        7: {"id": 7, "event_id": 4624},
        9: {"id": 9, "event_id": 4625},
    })
    monkeypatch.setattr("server.sli.semantic.event_card_semantics.build_event_card", lambda item: {"title": f"Event {item['id']}"})
    handler = SimpleNamespace()
    handler._send_json = lambda payload, status=HTTPStatus.OK: captured.append((payload, status))
    handler._require_capability = lambda capability: capability == "evidence.exact"

    routes_events._handle_events_batch_api(handler, {"event_db_id": ["9,8,7"]})

    payload, status = captured[0]
    assert status == HTTPStatus.OK
    assert [item["event_db_id"] for item in payload["items"]] == [9, 7]
    assert payload["requested_event_db_ids"] == [9, 8, 7]
    assert payload["missing_event_db_ids"] == [8]
    assert payload["limit"] == 100


def test_batch_event_api_requires_at_least_one_valid_id() -> None:
    from server.api.routes import events as routes_events

    captured: list[tuple[dict, HTTPStatus]] = []
    handler = SimpleNamespace()
    handler._send_json = lambda payload, status=HTTPStatus.OK: captured.append((payload, status))
    handler._require_capability = lambda capability: capability == "evidence.exact"

    routes_events._handle_events_batch_api(handler, {"event_db_id": ["bad,0"]})

    assert captured == [({"error": "event_db_id_required"}, HTTPStatus.BAD_REQUEST)]


def test_v2_event_batch_reads_only_archive_blocks_for_exact_requested_ids(monkeypatch) -> None:
    from server.sli.events import event_details

    blocks = {
        10: SimpleNamespace(identity=("set-a", "event", 0), event_id=10),
        1_000_000: SimpleNamespace(identity=("set-z", "event", 0), event_id=1_000_000),
    }

    class ExactManifest:
        def __init__(self) -> None:
            self.requests: list[tuple[str, list[int], int]] = []

        def find_published_many(self, archive_kind: str, event_ids: list[int], limit: int):
            self.requests.append((archive_kind, event_ids, limit))
            return [blocks[event_id] for event_id in event_ids if event_id in blocks][:limit]

        def find_published_range(self, *_args, **_kwargs):
            raise AssertionError("a sparse exact-ID batch must not scan the intervening archive range")

    class ExactArchive:
        def read_block_rows(self, block):
            return [{"id": block.event_id}]

    manifest = ExactManifest()
    monkeypatch.setattr(event_details, "query_rows_bounded", lambda *_args, **_kwargs: [
        {"id": 10, "server": "dc-a"},
        {"id": 1_000_000, "server": "dc-z"},
    ])
    monkeypatch.setattr(event_details, "PostgresArchiveManifestStore", lambda _connect: manifest)
    monkeypatch.setattr(event_details, "ArchiveReader", lambda _manifest: ExactArchive())
    monkeypatch.setattr(event_details.StorageV2RuntimeReader, "_verify_core_identity", lambda *_args: None)
    monkeypatch.setattr(event_details, "_normalize_event_detail_row", lambda payload: payload)
    monkeypatch.setattr("server.sli.core.postgres_runtime_pipeline.connect", lambda: None)

    result = event_details._get_v2_event_details_by_ids([10, 1_000_000])

    assert manifest.requests == [("event", [10, 1_000_000], 17)]
    assert result == {
        10: {"id": 10, "server": "dc-a"},
        1_000_000: {"id": 1_000_000, "server": "dc-z"},
    }


def test_v2_event_batch_keeps_independent_archive_block_limit(monkeypatch) -> None:
    from server.sli.events import event_details

    summaries = [{"id": event_id, "server": "dc"} for event_id in range(1, 101)]
    blocks = [SimpleNamespace(identity=(f"set-{event_id}", "event", 0), event_id=event_id) for event_id in range(1, 18)]

    class BoundedManifest:
        def find_published_many(self, archive_kind: str, event_ids: list[int], limit: int):
            assert archive_kind == "event"
            assert event_ids == list(range(1, 101))
            assert limit == 17
            return blocks

    monkeypatch.setattr(event_details, "query_rows_bounded", lambda *_args, **_kwargs: summaries)
    monkeypatch.setattr(event_details, "PostgresArchiveManifestStore", lambda _connect: BoundedManifest())
    monkeypatch.setattr(event_details, "ArchiveReader", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("archive must not be read past the block limit")))
    monkeypatch.setattr("server.sli.core.postgres_runtime_pipeline.connect", lambda: None)

    with pytest.raises(event_details.ArchiveIntegrityError, match="bounded block limit"):
        event_details._get_v2_event_details_by_ids(list(range(1, 101)))


def test_postgres_manifest_bulk_lookup_uses_one_query_and_deduplicates_blocks() -> None:
    from server.sli.storage.storage_v2_repository import PostgresArchiveManifestStore

    def row(archive_set_id: str, first_event_id: int, last_event_id: int) -> dict:
        return {
            "archive_set_id": archive_set_id, "archive_kind": "event", "format_version": 1,
            "block_index": 0, "first_event_id": first_event_id, "last_event_id": last_event_id,
            "row_count": last_event_id - first_event_id + 1, "raw_bytes": 100,
            "compressed_bytes": 50, "raw_sha256": b"r" * 32, "archive_sha256": b"a" * 32,
            "object_location": f"{archive_set_id}.jsonl.gz", "state": "published",
            "created_at": "2026-09-13T00:00:00Z", "verified_at": "2026-09-13T00:00:01Z",
            "published_at": "2026-09-13T00:00:02Z", "quarantine_reason": None,
        }

    executed: list[tuple[str, tuple]] = []
    connect_count = 0

    class Cursor:
        def __enter__(self): return self
        def __exit__(self, *_args): return None
        def execute(self, sql: str, params: tuple): executed.append((sql, params))
        def fetchall(self): return [row("set-a", 1, 100), row("set-a", 1, 100), row("set-z", 1_000_000, 1_000_100)]

    class Connection:
        def __enter__(self): return self
        def __exit__(self, *_args): return None
        def cursor(self): return Cursor()

    def connect():
        nonlocal connect_count
        connect_count += 1
        return Connection()

    blocks = PostgresArchiveManifestStore(connect).find_published_many("event", [1, 2, 1_000_000], 16)

    assert connect_count == 1
    assert len(executed) == 1
    assert "unnest(%s::bigint[]) with ordinality" in executed[0][0]
    assert executed[0][1] == ([1, 2, 1_000_000], "event")
    assert [block.archive_set_id for block in blocks] == ["set-a", "set-z"]

"""A missing archive block degrades to the verified core; an altered one still fails closed."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from server.sli.events import event_details
from server.sli.storage.storage_v2_archive import ArchiveIntegrityError, ArchiveReader
from server.sli.storage.storage_v2_runtime import StorageV2RuntimeReader


def _patch(monkeypatch: pytest.MonkeyPatch, failure: Exception) -> None:
    class Reader:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def event_details(self, _event_id: int):
            raise failure

        def event_summary(self, event_id: int):
            return {"id": event_id, "event_id": 4624, "server_id": 3, "time_created_utc": "2026-09-15T03:30:57Z"}

    monkeypatch.setattr(event_details, "_v2_detail_route_selected", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(event_details, "primary_read_enabled", lambda: False)
    monkeypatch.setattr(event_details, "StorageV2RuntimeReader", Reader)
    monkeypatch.setattr(event_details, "PostgresStorageV2ReadStore", lambda *_args: None)
    monkeypatch.setattr(event_details, "ArchiveReader", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(event_details, "PostgresArchiveManifestStore", lambda *_args: None)
    monkeypatch.setattr(event_details, "query_rows", lambda *_args, **_kwargs: [{"server": "DC1"}])
    monkeypatch.setattr(event_details, "log_event", lambda *_args, **_kwargs: None)


def test_missing_archive_block_serves_the_verified_core_and_says_so(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, FileNotFoundError("block.jsonl.gz"))
    row = event_details._get_v2_event_detail_by_id({"event_db_id": 8211084})
    assert row["id"] == 8211084 and row["server"] == "DC1"
    assert row["source_payload_state"] == "archive_unavailable"


def test_unpublished_archive_block_serves_the_verified_core(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, AssertionError("real reader required"))
    summary = {"id": 7, "event_id": 4625, "server_id": 3, "time_created_utc": "2026-10-09T10:00:00Z"}
    monkeypatch.setattr(event_details, "StorageV2RuntimeReader", StorageV2RuntimeReader)
    monkeypatch.setattr(event_details, "PostgresStorageV2ReadStore",
                        lambda *_args: SimpleNamespace(get_event_summary=lambda _id: summary))
    monkeypatch.setattr(event_details, "ArchiveReader",
                        lambda *_args: ArchiveReader(SimpleNamespace(find_published=lambda *_args: None)))

    row = event_details._get_v2_event_detail_by_id({"event_db_id": 7})

    assert row["id"] == 7 and row["server"] == "DC1"
    assert row["source_payload_state"] == "archive_unavailable"
    assert "event_data" not in row


def test_missing_core_still_fails_without_archive_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, AssertionError("real reader required"))
    monkeypatch.setattr(event_details, "StorageV2RuntimeReader", StorageV2RuntimeReader)
    monkeypatch.setattr(event_details, "PostgresStorageV2ReadStore",
                        lambda *_args: SimpleNamespace(get_event_summary=lambda _id: None))
    monkeypatch.setattr(event_details, "ArchiveReader",
                        lambda *_args: SimpleNamespace(read_event=lambda **_kwargs: pytest.fail("core must be verified first")))

    with pytest.raises(KeyError, match="V2 event core not found"):
        event_details._get_v2_event_detail_by_id({"event_db_id": 7})


def test_missing_row_inside_published_block_still_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, KeyError("event not found inside its published archive block"))
    with pytest.raises(KeyError, match="inside its published archive block"):
        event_details._get_v2_event_detail_by_id({"event_db_id": 7})


def _patch_history(monkeypatch: pytest.MonkeyPatch, summary) -> None:
    _patch(monkeypatch, FileNotFoundError("x"))
    monkeypatch.setattr(event_details, "primary_read_enabled", lambda: True)
    monkeypatch.setattr(
        event_details, "PostgresStorageV2ReadStore",
        lambda *_args: SimpleNamespace(get_event_summary=lambda _id: summary),
    )

    def refuse(*_args, **_kwargs):
        raise ConnectionRefusedError("history store down")

    monkeypatch.setattr(event_details, "_history_payload", refuse)


def test_unreachable_history_store_degrades_to_the_verified_core(monkeypatch: pytest.MonkeyPatch) -> None:
    summary = {"id": 8211084, "event_id": 4624, "server_id": 3, "time_created_utc": "2020-01-01T00:00:00Z"}
    _patch_history(monkeypatch, summary)
    row = event_details._get_v2_event_detail_by_id({"event_db_id": 8211084})
    assert row["server"] == "DC1" and row["source_payload_state"] == "archive_unavailable"


def test_unreachable_history_store_without_core_still_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_history(monkeypatch, None)
    with pytest.raises(ConnectionRefusedError):
        event_details._get_v2_event_detail_by_id({"event_db_id": 8211084})


def test_altered_archive_still_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, ArchiveIntegrityError("identity mismatch"))
    with pytest.raises(ArchiveIntegrityError):
        event_details._get_v2_event_detail_by_id({"event_db_id": 8211084})

"""Event hydration degrades to the verified PostgreSQL core; tampering still fails closed."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from server.sli.events import event_details
from server.sli.storage.storage_v2_archive import (
    ArchiveIntegrityError,
    ArchiveObjectUnavailableError,
    ArchiveReader,
)

COLD = "2020-01-01T00:00:00Z"
HOT = "2026-09-15T03:30:57Z"


def _summary(event_id: int, created: str) -> dict:
    return {"id": event_id, "event_id": 4624, "server_id": 3, "server": "DC1", "time_created_utc": created}


def _patch(monkeypatch: pytest.MonkeyPatch, summaries, *, history: bool, read_rows=None, read_history=None) -> None:
    monkeypatch.setattr(event_details, "query_rows_bounded", lambda *_a, **_k: summaries)
    monkeypatch.setattr(event_details, "primary_read_enabled", lambda: history)
    monkeypatch.setattr(event_details, "configured_read_port", lambda: 1)
    monkeypatch.setattr(event_details, "_history_is_cold", lambda row: str(row["time_created_utc"]).startswith("2020"))
    monkeypatch.setattr(event_details, "log_event", lambda *_a, **_k: None)
    monkeypatch.setattr(
        event_details, "PostgresArchiveManifestStore",
        lambda *_a: SimpleNamespace(find_published_many=lambda *_x: [object()]),
    )

    class Reader:
        def __init__(self, *_a, **_k) -> None:
            pass

        def read_block_rows(self, _block):
            if isinstance(read_rows, Exception):
                raise read_rows
            return read_rows or []

    monkeypatch.setattr(event_details, "ArchiveReader", Reader)
    if read_history is not None:
        def history_reader(*_a, **_k):
            raise read_history

        monkeypatch.setattr(event_details, "read_published_events_many", history_reader)


def test_history_store_down_serves_core_for_each_event(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, [_summary(1, COLD), _summary(2, COLD)], history=True, read_history=ConnectionRefusedError("down"))
    result = event_details._get_v2_event_details_by_ids([1, 2])
    assert set(result) == {1, 2}
    assert all(item["source_payload_state"] == "archive_unavailable" for item in result.values())


def test_history_store_down_without_core_still_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, [_summary(1, COLD)], history=True, read_history=ConnectionRefusedError("down"))
    with pytest.raises(ConnectionRefusedError):
        event_details._get_v2_event_details_by_ids([1, 2])


@pytest.mark.parametrize(
    "failure", [FileNotFoundError("block"), ArchiveObjectUnavailableError("outside the configured root")],
)
def test_missing_or_refused_archive_block_serves_core(monkeypatch: pytest.MonkeyPatch, failure: Exception) -> None:
    _patch(monkeypatch, [_summary(5, HOT)], history=False, read_rows=failure)
    result = event_details._get_v2_event_details_by_ids([5])
    assert result[5]["source_payload_state"] == "archive_unavailable"


def test_altered_archive_block_still_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, [_summary(5, HOT)], history=False, read_rows=ArchiveIntegrityError("sha mismatch"))
    with pytest.raises(ArchiveIntegrityError):
        event_details._get_v2_event_details_by_ids([5])


def test_single_card_path_outside_root_degrades_to_core(monkeypatch: pytest.MonkeyPatch) -> None:
    class Reader:
        def __init__(self, *_a, **_k) -> None:
            pass

        def event_details(self, _id):
            raise ArchiveObjectUnavailableError("archive object is outside the configured root")

        def event_summary(self, event_id):
            return _summary(event_id, HOT)

    monkeypatch.setattr(event_details, "_v2_detail_route_selected", lambda *_a, **_k: True)
    monkeypatch.setattr(event_details, "primary_read_enabled", lambda: False)
    monkeypatch.setattr(event_details, "StorageV2RuntimeReader", Reader)
    monkeypatch.setattr(event_details, "PostgresStorageV2ReadStore", lambda *_a: None)
    monkeypatch.setattr(event_details, "ArchiveReader", lambda *_a, **_k: None)
    monkeypatch.setattr(event_details, "PostgresArchiveManifestStore", lambda *_a: None)
    monkeypatch.setattr(event_details, "query_rows", lambda *_a, **_k: [{"server": "DC1"}])
    monkeypatch.setattr(event_details, "log_event", lambda *_a, **_k: None)
    row = event_details._get_v2_event_detail_by_id({"event_db_id": 7})
    assert row["source_payload_state"] == "archive_unavailable" and row["server"] == "DC1"


def test_archive_reader_refuses_foreign_path_without_reading(tmp_path: Path) -> None:
    outside = tmp_path / "outside.gz"
    outside.write_bytes(b"x")
    reader = ArchiveReader.__new__(ArchiveReader)
    reader.archive_root = (tmp_path / "root").resolve()
    block = SimpleNamespace(state="published", object_location=str(outside))
    with pytest.raises(ArchiveObjectUnavailableError):
        reader._read_verified_block(block)

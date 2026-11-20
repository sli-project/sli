from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.maintenance.stage7_control_d_prime_benchmark import (
    FramedArchiveBuilder,
    FramedArchiveReader,
    _minimum_recent_blocks,
    _select_variant,
)


def _line(event_id: int) -> bytes:
    return (
        json.dumps(
            {"kind": "event", "row": {"id": event_id, "value": f"v{event_id}"}},
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )


def test_framed_archive_reads_one_verified_event(tmp_path: Path) -> None:
    data = tmp_path / "events.frames"
    index = tmp_path / "events.idx"
    builder = FramedArchiveBuilder(
        data_path=data,
        index_path=index,
        target_rows=2,
    )
    for event_id in (10, 11, 15, 20, 21):
        builder.add(event_id, _line(event_id))
    evidence = builder.finish()

    assert evidence["frame_count"] == 3
    assert evidence["event_rows"] == 5
    with FramedArchiveReader(data, index) as reader:
        assert reader.read_event(15) == {"id": 15, "value": "v15"}
        with pytest.raises(KeyError):
            reader.read_event(14)


def test_framed_archive_rejects_non_monotonic_ids(tmp_path: Path) -> None:
    builder = FramedArchiveBuilder(
        data_path=tmp_path / "events.frames",
        index_path=tmp_path / "events.idx",
        target_rows=2,
    )
    builder.add(10, _line(10))
    with pytest.raises(RuntimeError, match="strictly ordered"):
        builder.add(10, _line(10))
    builder.finish()


def test_minimum_recent_blocks_stops_after_required_rows() -> None:
    assert _minimum_recent_blocks([20, 80, 512]) == 2
    assert _minimum_recent_blocks([100]) == 1
    with pytest.raises(RuntimeError):
        _minimum_recent_blocks([30, 40])


def test_selection_prioritizes_storage_after_minimum_speed_gate() -> None:
    variants = [
        {
            "id": "fast-large",
            "semantic_parity": True,
            "storage": {"event_archive_and_index_bytes": 1200},
            "event_detail_benchmark": {"warm_p95_ms": 2, "cold_p95_ms": 20},
        },
        {
            "id": "compact",
            "semantic_parity": True,
            "storage": {"event_archive_and_index_bytes": 1000},
            "event_detail_benchmark": {"warm_p95_ms": 20, "cold_p95_ms": 200},
        },
        {
            "id": "too-slow",
            "semantic_parity": True,
            "storage": {"event_archive_and_index_bytes": 800},
            "event_detail_benchmark": {"warm_p95_ms": 30, "cold_p95_ms": 200},
        },
    ]

    selected = _select_variant(
        variants,
        warm_limit_ms=25,
        cold_limit_ms=250,
    )

    assert selected is not None
    assert selected["id"] == "compact"

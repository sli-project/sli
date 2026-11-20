"""Collector interface and one-shot host (ADR 0012 point 3, plugin_architecture_v2 boundary)."""

from __future__ import annotations

from pathlib import Path

import pytest

from server.source_packs import registry
from server.source_packs.collector_contract import (
    CollectResult,
    FileLineCollector,
    MemoryCursorStore,
    RawEvent,
    load_collector,
    parse_collector_spec,
    run_collector_once,
)
from server.source_packs.examples import linux_auth
from server.source_packs.normalizers import get_source_normalizer

FIXTURE = Path(__file__).parent.parent / "fixtures" / "linux_auth" / "auth.log.txt"


def test_collector_spec_is_validated_not_started() -> None:
    spec = parse_collector_spec({"kind": "file", "entry": "server.source_packs.examples.linux_auth:auth_log_collector", "schedule": "*/5 * * * *"})
    assert spec.kind == "file" and spec.schedule == "*/5 * * * *"
    assert parse_collector_spec(None) is None
    with pytest.raises(ValueError, match="kind"):
        parse_collector_spec({"kind": "stream", "entry": "server.source_packs.x:y"})
    with pytest.raises(ValueError, match="not allowed"):
        parse_collector_spec({"kind": "pull", "entry": "subprocess:run"})


def test_file_collector_reads_complete_lines_after_the_offset(tmp_path: Path) -> None:
    path = tmp_path / "log.txt"
    path.write_bytes(b"one\ntwo\nthree\npartial")
    collector = FileLineCollector(path=path)
    first = collector.collect(None, 2)
    assert [event.payload["line"] for event in first.events] == ["one", "two"] and first.has_more
    second = collector.collect(first.next_cursor, 10)
    assert [event.payload["line"] for event in second.events] == ["three"] and not second.has_more
    with path.open("ab") as handle:
        handle.write(b" line\n")
    assert [event.payload["line"] for event in collector.collect(second.next_cursor, 10).events] == ["partial line"]


class _Fixed:
    def __init__(self, events: list[RawEvent], cursor: str) -> None:
        self.events, self.cursor = events, cursor

    def collect(self, cursor: str | None, limit: int) -> CollectResult:
        return CollectResult(events=tuple(self.events[:limit]), next_cursor=self.cursor)


def test_host_moves_the_cursor_only_after_the_sink_accepts_and_skips_duplicates() -> None:
    events = [RawEvent("1", {"a": 1}), RawEvent("2", {"a": 1}), RawEvent("3", {"a": 2})]
    cursors = MemoryCursorStore()
    stored: list[RawEvent] = []

    def failing(_pack: str, _batch: list[RawEvent]) -> int:
        raise RuntimeError("storage unavailable")

    with pytest.raises(RuntimeError):
        run_collector_once("p", _Fixed(events, "3"), cursors, failing)
    assert cursors.get("p") is None

    report = run_collector_once("p", _Fixed(events, "3"), cursors, lambda _pack, batch: stored.extend(batch) or len(batch))
    assert (report.received, report.accepted, report.duplicates, report.cursor_after) == (3, 2, 1, "3")
    assert [event.position for event in stored] == ["1", "3"]


def test_reference_pack_collects_and_normalizes_through_its_manifest() -> None:
    pack = registry._load_manifest(Path("config/source_packs/examples/linux_auth.json"))
    collector = load_collector(pack.collector, path=str(FIXTURE), year=2026, timezone="UTC")
    stored: list[RawEvent] = []
    report = run_collector_once(pack.pack_id, collector, MemoryCursorStore(), lambda _pack, batch: stored.extend(batch) or len(batch), limit=100)
    expected = [line for line in FIXTURE.read_text(encoding="utf-8").splitlines() if linux_auth.parse_line(line, 2026, "UTC")]
    assert report.accepted == len(stored) == len(expected) and not report.has_more
    normalizer = get_source_normalizer(pack.normalizer_id)
    facts = [normalizer.event_facts(row=event.payload, event_data=event.payload) for event in stored]
    assert all(isinstance(item, dict) for item in facts)
    assert pack.public_dict()["collector"]["kind"] == "file"

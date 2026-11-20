"""Collector interface of a source pack (ADR 0012 point 3) and a one-shot host.

The design boundary of ``config/plugin_architecture_v2.json`` holds: the core
owns the cursor, evidence is accepted before the cursor moves, and nothing here
starts, schedules or keeps contacting a source. ``run_collector_once`` is an
explicit, bounded, operator-invoked pass; autostart and continuous source
contact still require a separate owner decision.
"""

from __future__ import annotations

import hashlib
import importlib
import json
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol

from server.source_packs.normalizers import ALLOWED_ENTRY_PREFIXES

CollectorKind = Literal["pull", "push", "file"]
MAX_BATCH = 10_000


@dataclass(frozen=True)
class RawEvent:
    """One source record before normalization; ``position`` is source-native."""

    position: str
    payload: Mapping[str, Any]

    def fingerprint(self) -> str:
        canonical = json.dumps(self.payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class CollectResult:
    events: tuple[RawEvent, ...]
    #: Opaque cursor after the last returned event; the host persists it.
    next_cursor: str | None
    has_more: bool = False


class Collector(Protocol):
    """``collect(cursor, limit)``: events after ``cursor``, at most ``limit``."""

    def collect(self, cursor: str | None, limit: int) -> CollectResult: ...


@dataclass(frozen=True)
class CollectorSpec:
    kind: CollectorKind
    entry: str
    #: Declared only; nothing schedules it (autostart needs an owner decision).
    schedule: str | None = None


def parse_collector_spec(value: Any) -> CollectorSpec | None:
    """Validates a manifest ``collector`` object without importing or starting it."""
    if value in (None, {}):
        return None
    if not isinstance(value, Mapping):
        raise ValueError("collector must be an object")  # noqa: TRY004 - a manifest error, reported like the others
    kind = str(value.get("kind") or "").strip()
    if kind not in ("pull", "push", "file"):
        raise ValueError(f"collector kind is not supported: {kind or '—'}")
    entry = str(value.get("entry") or "").strip()
    module_name, _, attribute = entry.partition(":")
    if not module_name or not attribute or not module_name.startswith(ALLOWED_ENTRY_PREFIXES):
        raise ValueError(f"collector entry is not allowed: {entry}")
    schedule = str(value.get("schedule") or "").strip() or None
    return CollectorSpec(kind=kind, entry=entry, schedule=schedule)  # type: ignore[arg-type]


def load_collector(spec: CollectorSpec, **options: Any) -> Collector:
    """Instantiates the collector class named by the manifest with explicit options."""
    module_name, _, attribute = spec.entry.partition(":")
    factory = getattr(importlib.import_module(module_name), attribute)
    collector = factory(**options)
    if not callable(getattr(collector, "collect", None)):
        raise TypeError(f"collector {spec.entry} has no collect(cursor, limit)")
    return collector


class CursorStore(Protocol):
    def get(self, pack_id: str) -> str | None: ...
    def set(self, pack_id: str, cursor: str | None) -> None: ...


@dataclass
class MemoryCursorStore:
    values: dict[str, str | None] = field(default_factory=dict)

    def get(self, pack_id: str) -> str | None:
        return self.values.get(pack_id)

    def set(self, pack_id: str, cursor: str | None) -> None:
        self.values[pack_id] = cursor


#: Accepts evidence (already de-duplicated) and returns how many were stored.
EvidenceSink = Callable[[str, list[RawEvent]], int]


@dataclass(frozen=True)
class RunReport:
    pack_id: str
    received: int
    accepted: int
    duplicates: int
    cursor_before: str | None
    cursor_after: str | None
    has_more: bool


def run_collector_once(
    pack_id: str,
    collector: Collector,
    cursors: CursorStore,
    sink: EvidenceSink,
    *,
    seen: set[str] | None = None,
    limit: int = 1_000,
) -> RunReport:
    """One explicit bounded pass: collect → de-duplicate → sink → then move the cursor.

    If the sink raises, the cursor is not advanced, so the next pass re-reads
    the same events (at-least-once; the fingerprint makes the retry safe).
    """
    if not 1 <= limit <= MAX_BATCH:
        raise ValueError("collector limit out of bounds")
    before = cursors.get(pack_id)
    result = collector.collect(before, limit)
    if len(result.events) > limit:
        raise ValueError("collector returned more events than requested")
    known = seen if seen is not None else set()
    fresh: list[RawEvent] = []
    for event in result.events:
        mark = event.fingerprint()
        if mark in known:
            continue
        known.add(mark)
        fresh.append(event)
    accepted = sink(pack_id, fresh) if fresh else 0
    cursors.set(pack_id, result.next_cursor if result.next_cursor is not None else before)
    return RunReport(
        pack_id=pack_id, received=len(result.events), accepted=accepted, duplicates=len(result.events) - len(fresh),
        cursor_before=before, cursor_after=cursors.get(pack_id), has_more=result.has_more,
    )


@dataclass
class FileLineCollector:
    """``file`` collector: reads lines of one explicitly given file after a byte offset.

    The path comes from the operator's request, never from the manifest, and
    only complete lines are returned (a trailing partial line waits).
    """

    path: Path
    parse: Callable[[str], Mapping[str, Any] | None] | None = None

    def collect(self, cursor: str | None, limit: int) -> CollectResult:
        offset = int(cursor or 0)
        events: list[RawEvent] = []
        with Path(self.path).open("rb") as handle:
            handle.seek(offset)
            while len(events) < limit:
                line = handle.readline()
                if not line or not line.endswith(b"\n"):
                    break
                position = offset
                offset += len(line)
                text = line.decode("utf-8", errors="replace").rstrip("\r\n")
                payload = self.parse(text) if self.parse else {"line": text}
                if payload is not None:
                    events.append(RawEvent(position=str(position), payload=dict(payload)))
            more = bool(handle.readline())
        return CollectResult(events=tuple(events), next_cursor=str(offset), has_more=more)


def collect_all(collector: Collector, cursor: str | None = None, *, limit: int = 1_000, max_batches: int = 100) -> Iterable[RawEvent]:
    """Test/diagnostic helper: drains a collector in bounded batches."""
    for _ in range(max_batches):
        result = collector.collect(cursor, limit)
        yield from result.events
        cursor = result.next_cursor
        if not result.has_more:
            return

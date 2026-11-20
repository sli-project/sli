"""Bounded TEST-only history evaluation with caller-owned checkpoints/results.

Readers are injected, authorized, read-only adapters over retained evidence, not
connections to agents or runtime writers. They must enforce the supplied read
timeout/byte limit and return stable, increasing positions within a fixed
snapshot. This module has no database, scheduler, admission or finding writes.
Checkpoints are trusted worker state, never a client-supplied authorization.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import time
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Protocol

from server.sli.sigma.compiler import CompiledRule
from server.sli.sigma.matcher import MATCHER_VERSION, MatchLimits, match_rule
from server.sli.sigma.windows_mapping import EventScope, MappedWindowsEvent

HISTORY_VERSION = "sli.sigma.history.v1"
_STORES = frozenset({"core_event", "core_history", "workstation_observation", "workstation_history", "file_audit"})
_STATUSES = ("scanned", "evaluable", "matched", "suppressed", "unknown", "skipped")
_SHA256 = re.compile(r"[0-9a-f]{64}")


def _digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True,
                                     separators=(",", ":"), default=str).encode()).hexdigest()


def _aware(value):
    return isinstance(value, datetime) and value.utcoffset() is not None


@dataclass(frozen=True, repr=False)
class HistoryPartition:
    """One source/storage/UTC-day block and its pinned snapshot high watermark."""

    scope: EventScope
    storage_kind: str
    start: datetime
    end: datetime
    snapshot: str
    high_watermark: int

    def __post_init__(self):
        if (not isinstance(self.scope, EventScope) or self.storage_kind not in _STORES
                or not _aware(self.start) or not _aware(self.end)
                or not self.start < self.end <= self.start.astimezone(timezone.utc).replace(
                    hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
                or not isinstance(self.snapshot, str) or not 0 < len(self.snapshot) <= 256
                or type(self.high_watermark) is not int or not 0 <= self.high_watermark < 2**63):
            raise ValueError("sigma_history_partition_invalid")

    @property
    def key(self):
        return _digest(asdict(self))


@dataclass(frozen=True, repr=False)
class HistoryRequest:
    job_id: str
    rules: tuple[CompiledRule, ...]
    partitions: tuple[HistoryPartition, ...]
    manifest_sha256: str
    match_limits: MatchLimits = MatchLimits()

    def __post_init__(self):
        if (not isinstance(self.job_id, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", self.job_id)
                or type(self.rules) is not tuple or not 1 <= len(self.rules) <= 25
                or any(not isinstance(rule, CompiledRule) for rule in self.rules)
                or len({rule.rule_id for rule in self.rules}) != len(self.rules)
                or type(self.partitions) is not tuple or not 1 <= len(self.partitions) <= 256
                or any(not isinstance(part, HistoryPartition) for part in self.partitions)
                or len({part.key for part in self.partitions}) != len(self.partitions)
                or max(part.end for part in self.partitions) - min(part.start for part in self.partitions)
                > timedelta(days=7)
                or not isinstance(self.manifest_sha256, str) or not _SHA256.fullmatch(self.manifest_sha256)
                or not isinstance(self.match_limits, MatchLimits)):
            raise ValueError("sigma_history_request_invalid")
        # Overlapping copies must not inflate counts. Pick one storage routing
        # per source/day; crossing the hot/cold boundary belongs to that reader.
        for index, part in enumerate(self.partitions):
            for other in self.partitions[:index]:
                if part.scope == other.scope and part.start < other.end and other.start < part.end:
                    raise ValueError("sigma_history_partition_overlap")

    @property
    def key(self):
        return _digest({"version": HISTORY_VERSION, "matcher": MATCHER_VERSION,
                        "job": self.job_id, "manifest": self.manifest_sha256,
                        "plans": [rule.plan_sha256 for rule in self.rules],
                        "partitions": [part.key for part in self.partitions],
                        "match_limits": asdict(self.match_limits)})


@dataclass(frozen=True)
class HistoryBudget:
    """Per invocation limits; a partial job resumes in another bounded slice."""

    max_rows: int = 1000
    max_bytes: int = 16 * 1024 * 1024
    max_event_bytes: int = 1024 * 1024
    max_evaluations: int = 25_000
    max_seconds: float = 30.0
    max_cpu_seconds: float = 10.0
    read_timeout_seconds: float = 2.0
    # Lifetime dedup/checkpoint/sample bounds keep repeated slices bounded too.
    max_job_rows: int = 100_000
    max_samples: int = 100

    def __post_init__(self):
        maxima = {"max_rows": 10_000, "max_bytes": 64 * 1024 * 1024,
                  "max_event_bytes": 4 * 1024 * 1024, "max_evaluations": 250_000,
                  "max_seconds": 60, "max_cpu_seconds": 60, "read_timeout_seconds": 10,
                  "max_job_rows": 100_000, "max_samples": 1000}
        for name, maximum in maxima.items():
            value = getattr(self, name)
            if name.endswith("seconds"):
                valid = type(value) in (float, int) and math.isfinite(value)
            else:
                valid = type(value) is int
            if not valid or not 0 < value <= maximum:
                raise ValueError("sigma_history_budget_invalid")


@dataclass(frozen=True, repr=False)
class HistoryEvidenceRef:
    storage_kind: str
    native_id: str
    sha256: str

    def __post_init__(self):
        if (self.storage_kind not in _STORES or not isinstance(self.native_id, str)
                or not 0 < len(self.native_id) <= 256
                or not isinstance(self.sha256, str) or not _SHA256.fullmatch(self.sha256)):
            raise ValueError("sigma_history_reference_invalid")


@dataclass(frozen=True, repr=False)
class HistoryRecord:
    position: int
    ref: HistoryEvidenceRef
    scope: EventScope
    occurred_at: datetime
    event: MappedWindowsEvent | None
    # Fixed quality codes from the admitted adapter/gate, never payload text.
    quality_reasons: tuple[str, ...] = ()


class HistoryReader(Protocol):
    def read_one(self, partition: HistoryPartition, *, after: int, max_bytes: int,
                 timeout_seconds: float) -> HistoryRecord | None:
        """SELECT-only; None proves exhaustion through the pinned watermark.

        Limit allocation before decoding; enforce snapshot, source, interval,
        cancellation-compatible timeout and authorization in the store as well.
        Raise PermissionError on access denial; never return substitute sources.
        """
        ...


@dataclass(frozen=True)
class HistoryCounts:
    partition_key: str
    rule_id: str
    scanned: int = 0
    evaluable: int = 0
    matched: int = 0
    suppressed: int = 0  # No overlays/admission in this stage.
    unknown: int = 0
    skipped: int = 0
    reasons: tuple[tuple[str, int], ...] = ()
    unknown_fields: tuple[tuple[str, str, int], ...] = ()
    first_occurred_at: str | None = None
    last_occurred_at: str | None = None


@dataclass(frozen=True, repr=False)
class HistorySample:
    partition_key: str
    rule_id: str
    ref: HistoryEvidenceRef
    replay_sha256: str


@dataclass(frozen=True)
class HistoryCheckpoint:
    request_sha256: str
    partition_index: int = 0
    after: int = 0
    rows_read: int = 0
    bytes_read: int = 0
    deduplicated: int = 0
    seen: tuple[str, ...] = field(default=(), repr=False)
    counts: tuple[HistoryCounts, ...] = ()
    samples: tuple[HistorySample, ...] = field(default=(), repr=False)


@dataclass(frozen=True)
class HistoryResult:
    status: str
    reason: str
    checkpoint: HistoryCheckpoint = field(repr=False)
    request: HistoryRequest = field(repr=False)
    mode: str = field(default="test", init=False)

    def manifest(self):
        """Separate TEST output: hashes/refs/counters, never raw mapped fields."""
        data = {"status": self.status, "reason": self.reason, "mode": self.mode,
                "version": HISTORY_VERSION, "checkpoint": asdict(self.checkpoint),
                "manifest_sha256": self.request.manifest_sha256,
                "matcher_version": MATCHER_VERSION,
                "rules": [{"rule_id": rule.rule_id, "plan_sha256": rule.plan_sha256,
                           "source_sha256": rule.source_sha256, "upstream_commit": rule.upstream_commit,
                           "compiler_version": rule.compiler_version, "mapping_version": rule.mapping_version}
                          for rule in self.request.rules],
                "partitions": [{"key": part.key, "scope_sha256": _digest(asdict(part.scope)),
                                "storage_kind": part.storage_kind, "start": part.start.isoformat(),
                                "end": part.end.isoformat(), "snapshot_sha256": _digest(part.snapshot),
                                "high_watermark": part.high_watermark}
                               for part in self.request.partitions]}
        for row in data["checkpoint"]["counts"]:
            scanned, evaluable = row["scanned"], row["evaluable"]
            row["evaluable_percent"] = 100 * evaluable / scanned if scanned else None
            row["matches_per_1000_evaluable"] = 1000 * row["matched"] / evaluable if evaluable else None
        # Checksum the actual serialized checkpoint, including derived counters.
        data["checkpoint_sha256"] = _digest(data["checkpoint"])
        return data


class _Stop(Exception):
    def __init__(self, status, reason):
        self.status, self.reason = status, reason


def _record_size(record, partition, after):
    if (type(record) is not HistoryRecord or type(record.position) is not int
            or not after < record.position <= partition.high_watermark
            or not isinstance(record.ref, HistoryEvidenceRef) or record.ref.storage_kind != partition.storage_kind
            or record.scope != partition.scope or not _aware(record.occurred_at)
            or not partition.start <= record.occurred_at < partition.end
            or type(record.quality_reasons) is not tuple or len(record.quality_reasons) > 32
            or any(not isinstance(code, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code)
                   for code in record.quality_reasons)):
        raise _Stop("failed", "reader_contract_invalid")
    event = record.event
    if event is not None:
        if (not isinstance(event, MappedWindowsEvent) or event.identity.scope != partition.scope
                or datetime.fromisoformat(event.identity.occurred_at.replace("Z", "+00:00")) != record.occurred_at):
            raise _Stop("failed", "reader_contract_invalid")
        payload = {"fields": dict(event.fields), "unavailable": dict(event.unavailable),
                   "identity": asdict(event.identity)}
    else:
        payload = None
    return len(json.dumps([asdict(record.ref), payload, record.quality_reasons], ensure_ascii=True).encode())


def _applicable(rule, event):
    if rule.logsource == "process_creation":
        return (event.identity.channel == "Security" and event.identity.event_id == 4688
                and event.identity.provider_name == "Microsoft-Windows-Security-Auditing")
    return event.identity.channel.casefold() == rule.logsource


def _count(previous, *, status, reasons, stamp, unknown_fields):
    reasons_count = dict(previous.reasons)
    for reason in reasons:
        reasons_count[reason] = reasons_count.get(reason, 0) + 1
    fields_count = {(name, reason): count for name, reason, count in previous.unknown_fields}
    for name, reason in unknown_fields:
        fields_count[name, reason] = fields_count.get((name, reason), 0) + 1
    updates = {name: getattr(previous, name) for name in _STATUSES}
    updates["scanned"] += 1
    if status in ("matched", "not_matched"):
        updates["evaluable"] += 1
        updates["matched"] += status == "matched"
    else:
        updates["skipped" if status == "skipped" else "unknown"] += 1
    return replace(previous, **updates, reasons=tuple(sorted(reasons_count.items())),
                   unknown_fields=tuple((name, reason, count) for (name, reason), count in sorted(fields_count.items())),
                   first_occurred_at=min(previous.first_occurred_at or stamp, stamp),
                   last_occurred_at=max(previous.last_occurred_at or stamp, stamp))


def run_history_job(request: HistoryRequest, reader: HistoryReader, *,
                    authorized: Callable[[HistoryPartition], bool],
                    cancelled: Callable[[], bool] = lambda: False,
                    budget: HistoryBudget = HistoryBudget(),
                    checkpoint: HistoryCheckpoint | None = None,
                    save_checkpoint: Callable[[HistoryCheckpoint], None] = lambda state: None) -> HistoryResult:
    """Run/resume one bounded slice, committing progress only after a whole row.

    ``save_checkpoint`` atomically persists this TEST-only state, including its
    results; failures leave the last acknowledged checkpoint intact. One worker
    owns a job at a time. The caller must retain/save the returned checkpoint
    even on partial/cancelled/failed, and recheck rights before exposing output.
    No runtime cursor, receipt, rule policy, risk or finding writer is accepted.
    """
    empty = HistoryCheckpoint(request.key)
    state = empty if checkpoint is None else checkpoint
    if (not isinstance(state, HistoryCheckpoint) or state.request_sha256 != request.key
            or not 0 <= state.partition_index <= len(request.partitions)
            or not 0 <= state.rows_read <= budget.max_job_rows or len(state.seen) > budget.max_job_rows
            or len(state.samples) > budget.max_samples or state.after < 0
            or state.partition_index < len(request.partitions)
            and state.after > request.partitions[state.partition_index].high_watermark):
        raise ValueError("sigma_history_checkpoint_mismatch")
    wall_start, cpu_start = time.monotonic(), time.process_time()
    rows = byte_count = evaluations = 0
    seen = set(state.seen)
    counts = {(row.partition_key, row.rule_id): row for row in state.counts}

    def check():
        if cancelled():
            raise _Stop("cancelled", "cancel_requested")
        if time.monotonic() - wall_start >= budget.max_seconds:
            raise _Stop("partial", "time_budget")
        if time.process_time() - cpu_start >= budget.max_cpu_seconds:
            raise _Stop("partial", "cpu_budget")

    def access():
        # Check the entire scope before loading/returning any prior sample refs.
        try:
            if any(authorized(part) is not True for part in request.partitions):
                raise PermissionError
        except Exception:
            raise PermissionError from None

    def result(status, reason):
        try:
            access()
        except PermissionError:
            return HistoryResult("failed", "permission_denied", empty, request)
        return HistoryResult(status, reason, state, request)

    def commit(candidate):
        nonlocal state
        access()
        save_checkpoint(candidate)
        state = candidate

    def finish_partition(part):
        # Empty sources remain visible with zero scanned and undefined rates.
        # Exhausting a snapshot is not evidence that its audit was collected.
        finished_counts = dict(counts)
        for rule in request.rules:
            key = (part.key, rule.rule_id)
            finished_counts.setdefault(key, HistoryCounts(*key))
        commit(replace(state, partition_index=state.partition_index + 1, after=0,
                       counts=tuple(finished_counts[key] for key in sorted(finished_counts))))
        counts.update(finished_counts)

    try:
        access()
        while state.partition_index < len(request.partitions):
            check()
            access()
            part = request.partitions[state.partition_index]
            if state.after == part.high_watermark:
                finish_partition(part)
                continue
            if rows >= budget.max_rows:
                raise _Stop("partial", "row_budget")
            if state.rows_read >= budget.max_job_rows:
                raise _Stop("partial", "job_row_budget")
            if evaluations + len(request.rules) > budget.max_evaluations:
                raise _Stop("partial", "evaluation_budget")
            remaining_bytes = budget.max_bytes - byte_count
            if remaining_bytes <= 0:
                raise _Stop("partial", "byte_budget")
            remaining_time = budget.max_seconds - (time.monotonic() - wall_start)
            record = reader.read_one(part, after=state.after,
                                     max_bytes=min(budget.max_event_bytes, remaining_bytes),
                                     timeout_seconds=min(budget.read_timeout_seconds, remaining_time))
            check()
            access()
            if record is None:
                finish_partition(part)
                continue
            size = _record_size(record, part, state.after)
            if size > budget.max_event_bytes:
                raise _Stop("failed", "event_byte_budget")
            if size > remaining_bytes:
                raise _Stop("partial", "byte_budget")
            rows += 1
            byte_count += size
            # Scope and storage kind are part of identity. Never coerce WS IDs
            # into core integer IDs or merge refs from unrelated stores.
            identity = _digest([asdict(part.scope), asdict(record.ref)])
            candidate = replace(state, after=record.position, rows_read=state.rows_read + 1,
                                bytes_read=state.bytes_read + size)
            if identity in seen:
                commit(replace(candidate, deduplicated=state.deduplicated + 1))
                continue
            row_counts = dict(counts)
            samples = list(state.samples)
            stamp = record.occurred_at.astimezone(timezone.utc).isoformat()
            for rule in request.rules:
                check()
                evaluations += 1
                reasons, replay = (), ""
                if record.event is None or record.quality_reasons:
                    status, reasons = "not_evaluable", record.quality_reasons or ("payload_unavailable",)
                elif record.event.mapping_version != rule.mapping_version:
                    status, reasons = "not_evaluable", ("mapping_version_mismatch",)
                elif not _applicable(rule, record.event):
                    status = "skipped"
                else:
                    remaining = budget.max_seconds - (time.monotonic() - wall_start)
                    # Keep limits/hash stable across retries. Reserve the full
                    # matcher timeout instead of changing its replay identity.
                    if remaining < request.match_limits.timeout_seconds:
                        raise _Stop("partial", "time_budget")
                    match = match_rule(rule, record.event.fields, unavailable=record.event.unavailable,
                                       limits=request.match_limits)
                    status, reasons, replay = match.status, match.reasons, match.replay_sha256
                key = (part.key, rule.rule_id)
                unknown_fields = []
                if status == "not_evaluable" and record.event is not None:
                    for name in rule.required_fields:
                        if name in record.event.unavailable:
                            # Adapter diagnostics are not copied into exports.
                            unknown_fields.append((name, "field_unavailable"))
                        elif name not in record.event.fields:
                            unknown_fields.append((name, "field_missing"))
                        elif record.event.fields[name] is None:
                            unknown_fields.append((name, "field_null"))
                row_counts[key] = _count(row_counts.get(key, HistoryCounts(*key)),
                                         status=status, reasons=reasons, stamp=stamp, unknown_fields=unknown_fields)
                if status == "matched" and len(samples) < budget.max_samples:
                    samples.append(HistorySample(part.key, rule.rule_id, record.ref, replay))
            check()
            candidate = replace(candidate, seen=tuple(sorted(seen | {identity})),
                                counts=tuple(row_counts[key] for key in sorted(row_counts)), samples=tuple(samples))
            commit(candidate)
            seen.add(identity)
            counts = row_counts
        access()
        return result("completed", "snapshot_exhausted")
    except PermissionError:
        # Do not expose even previously authorized refs after access is revoked.
        return HistoryResult("failed", "permission_denied", empty, request)
    except _Stop as stop:
        return result(stop.status, stop.reason)
    except TimeoutError:
        return result("partial", "read_timeout")
    except Exception:
        # Store/parser exceptions may contain source payloads or credentials.
        return result("failed", "history_job_failed")


def write_history_result(result: HistoryResult, output_directory: Path) -> Path:
    """Export a new, explicit evaluation artifact; refuse existing paths.

    The caller chooses a dedicated directory outside runtime storage. Creating
    it exclusively prevents overwriting an earlier run or production artifact.
    A failed write leaves no terminal result.json, never a false completed file.
    """
    output_directory = Path(output_directory)
    output_directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    temporary = output_directory / "result.pending"
    final = output_directory / "result.json"
    with temporary.open("x", encoding="utf-8") as stream:
        json.dump(result.manifest(), stream, sort_keys=True, ensure_ascii=True, indent=2)
        stream.write("\n")
    temporary.replace(final)
    return final


def read_history_checkpoint(result_path: Path) -> HistoryCheckpoint:
    """Restore trusted worker state from an exported TEST artifact, not a client.

    The checksum detects incomplete/corrupt copies; it is not authorization or a
    signature. run_history_job binds it again to the entire request and rights.
    """
    try:
        with Path(result_path).open("rb") as stream:
            raw = stream.read(32 * 1024 * 1024 + 1)
        if len(raw) > 32 * 1024 * 1024:
            raise ValueError
        document = json.loads(raw)
        data = document["checkpoint"]
        if (document["version"] != HISTORY_VERSION or document["mode"] != "test"
                or _digest(data) != document["checkpoint_sha256"]):
            raise ValueError
        counts = []
        for row in data["counts"]:
            values = {key: value for key, value in row.items()
                      if key not in ("evaluable_percent", "matches_per_1000_evaluable")}
            values["reasons"] = tuple(tuple(reason) for reason in values["reasons"])
            values["unknown_fields"] = tuple(tuple(reason) for reason in values["unknown_fields"])
            counts.append(HistoryCounts(**values))
        samples = tuple(HistorySample(**{**row, "ref": HistoryEvidenceRef(**row["ref"])})
                        for row in data["samples"])
        return HistoryCheckpoint(**{**data, "seen": tuple(data["seen"]),
                                    "counts": tuple(counts), "samples": samples})
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        raise ValueError("sigma_history_checkpoint_invalid") from None

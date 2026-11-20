#!/usr/bin/env python3
"""Isolated full-corpus benchmark for stage 7 CONTROL D'.

The command never changes PostgreSQL or the published Storage V2 archive. It
streams the verified event archive into temporary independently readable gzip
frames, measures their real size and detail latency, and removes the temporary
files after writing compact JSON evidence.
"""
from __future__ import annotations

import argparse
from bisect import bisect_right
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import gzip
import hashlib
import json
import math
from pathlib import Path
import struct
import sys
import tempfile
import time
from typing import Any, BinaryIO, Iterable


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.maintenance.stage7_control_benchmark import (  # noqa: E402
    _connect as _connect,
    _exported_snapshot,
    _snapshot_source,
    _run_snapshot,
    _normalize_timeline,
    TIMELINE_CONTRACT_VERSION,
    _digest_rows,
    _load_contract,
    _p95,
    _query_seeds,
    _relation_sizes,
)


INDEX_MAGIC = b"SLIDP001"
INDEX_VERSION = 1
INDEX_HEADER = struct.Struct(">8sIIQ")
INDEX_ENTRY = struct.Struct(">QQQQQI32s32s")


@dataclass(frozen=True)
class FrameEntry:
    first_event_id: int
    last_event_id: int
    offset: int
    compressed_bytes: int
    raw_bytes: int
    row_count: int
    raw_sha256: bytes
    compressed_sha256: bytes

    def to_evidence(self) -> dict[str, Any]:
        result = asdict(self)
        result["raw_sha256"] = self.raw_sha256.hex()
        result["compressed_sha256"] = self.compressed_sha256.hex()
        return result


class FramedArchiveBuilder:
    """Write deterministic independent gzip members and a fixed-size index."""

    def __init__(
        self,
        *,
        data_path: Path,
        index_path: Path,
        target_rows: int,
        compresslevel: int = 6,
    ) -> None:
        if target_rows < 1:
            raise ValueError("target_rows must be positive")
        self.data_path = Path(data_path)
        self.index_path = Path(index_path)
        self.target_rows = int(target_rows)
        self.compresslevel = int(compresslevel)
        self._data: BinaryIO = self.data_path.open("wb")
        self._lines: list[bytes] = []
        self._first_event_id: int | None = None
        self._last_event_id: int | None = None
        self._entries: list[FrameEntry] = []
        self._sequence_sha256 = hashlib.sha256()
        self._row_count = 0
        self._closed = False

    def add(self, event_id: int, envelope_line: bytes) -> None:
        if self._closed:
            raise RuntimeError("builder is already closed")
        event_id = int(event_id)
        if self._last_event_id is not None and event_id <= self._last_event_id:
            raise RuntimeError("event archive must be strictly ordered by id")
        if not envelope_line.endswith(b"\n"):
            envelope_line += b"\n"
        if self._first_event_id is None:
            self._first_event_id = event_id
        self._last_event_id = event_id
        self._lines.append(envelope_line)
        self._sequence_sha256.update(envelope_line)
        self._row_count += 1
        if len(self._lines) >= self.target_rows:
            self._flush()

    def _flush(self) -> None:
        if not self._lines:
            return
        raw = b"".join(self._lines)
        compressed = gzip.compress(
            raw,
            compresslevel=self.compresslevel,
            mtime=0,
        )
        offset = self._data.tell()
        self._data.write(compressed)
        self._entries.append(
            FrameEntry(
                first_event_id=int(self._first_event_id),
                last_event_id=int(self._last_event_id),
                offset=int(offset),
                compressed_bytes=len(compressed),
                raw_bytes=len(raw),
                row_count=len(self._lines),
                raw_sha256=hashlib.sha256(raw).digest(),
                compressed_sha256=hashlib.sha256(compressed).digest(),
            )
        )
        self._lines.clear()
        self._first_event_id = None
        self._last_event_id = None

    def finish(self) -> dict[str, Any]:
        if self._closed:
            raise RuntimeError("builder is already closed")
        self._flush()
        self._data.flush()
        self._data.close()
        self._closed = True
        with self.index_path.open("wb") as index:
            index.write(
                INDEX_HEADER.pack(
                    INDEX_MAGIC,
                    INDEX_VERSION,
                    INDEX_ENTRY.size,
                    len(self._entries),
                )
            )
            for entry in self._entries:
                index.write(
                    INDEX_ENTRY.pack(
                        entry.first_event_id,
                        entry.last_event_id,
                        entry.offset,
                        entry.compressed_bytes,
                        entry.raw_bytes,
                        entry.row_count,
                        entry.raw_sha256,
                        entry.compressed_sha256,
                    )
                )
        return {
            "target_rows_per_frame": self.target_rows,
            "frame_count": len(self._entries),
            "event_rows": self._row_count,
            "event_sequence_sha256": self._sequence_sha256.hexdigest(),
            "data_bytes": self.data_path.stat().st_size,
            "index_bytes": self.index_path.stat().st_size,
            "archive_and_index_bytes": (
                self.data_path.stat().st_size + self.index_path.stat().st_size
            ),
            "first_frame": (
                self._entries[0].to_evidence() if self._entries else None
            ),
            "last_frame": (
                self._entries[-1].to_evidence() if self._entries else None
            ),
        }


class FramedArchiveReader:
    """Read and verify one independent frame without decoding neighbours."""

    def __init__(self, data_path: Path, index_path: Path) -> None:
        self._data = Path(data_path).open("rb")
        self._entries = self._read_index(Path(index_path))
        self._first_ids = [entry.first_event_id for entry in self._entries]

    @staticmethod
    def _read_index(path: Path) -> list[FrameEntry]:
        raw = path.read_bytes()
        if len(raw) < INDEX_HEADER.size:
            raise RuntimeError("D-prime index header is missing")
        magic, version, entry_size, count = INDEX_HEADER.unpack_from(raw)
        if (
            magic != INDEX_MAGIC
            or version != INDEX_VERSION
            or entry_size != INDEX_ENTRY.size
        ):
            raise RuntimeError("D-prime index contract mismatch")
        expected_size = INDEX_HEADER.size + int(count) * INDEX_ENTRY.size
        if len(raw) != expected_size:
            raise RuntimeError("D-prime index size mismatch")
        entries: list[FrameEntry] = []
        offset = INDEX_HEADER.size
        for _ in range(int(count)):
            values = INDEX_ENTRY.unpack_from(raw, offset)
            entries.append(FrameEntry(*values))
            offset += INDEX_ENTRY.size
        return entries

    def read_event(self, event_id: int) -> dict[str, Any]:
        event_id = int(event_id)
        position = bisect_right(self._first_ids, event_id) - 1
        if position < 0:
            raise KeyError(event_id)
        entry = self._entries[position]
        if event_id > entry.last_event_id:
            raise KeyError(event_id)
        self._data.seek(entry.offset)
        compressed = self._data.read(entry.compressed_bytes)
        if (
            len(compressed) != entry.compressed_bytes
            or hashlib.sha256(compressed).digest() != entry.compressed_sha256
        ):
            raise RuntimeError("D-prime compressed frame integrity mismatch")
        raw = gzip.decompress(compressed)
        if (
            len(raw) != entry.raw_bytes
            or hashlib.sha256(raw).digest() != entry.raw_sha256
        ):
            raise RuntimeError("D-prime raw frame integrity mismatch")
        matches: list[dict[str, Any]] = []
        for line in raw.splitlines():
            envelope = json.loads(line)
            if envelope.get("kind") != "event":
                raise RuntimeError("D-prime frame contains a non-event envelope")
            row = envelope.get("row")
            if not isinstance(row, dict):
                raise RuntimeError("D-prime frame event row is malformed")
            if int(row["id"]) == event_id:
                matches.append(row)
        if len(matches) != 1:
            raise KeyError(event_id)
        return matches[0]

    def close(self) -> None:
        self._data.close()

    def __enter__(self) -> "FramedArchiveReader":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def _source_event_blocks(conn: Any) -> list[dict[str, Any]]:
    with conn.cursor() as cur:
        cur.execute(
            """
            select first_event_id,last_event_id,row_count,raw_bytes,
                   compressed_bytes,raw_sha256,archive_sha256,object_location
            from storage_v2_archive_blocks
            where archive_kind='event' and state='published'
            order by first_event_id,last_event_id,archive_set_id,block_index
            """
        )
        return [dict(row) for row in cur.fetchall()]


def _stream_source_into_builders(
    source_blocks: Iterable[dict[str, Any]],
    builders: list[FramedArchiveBuilder],
) -> dict[str, Any]:
    sequence = hashlib.sha256()
    event_rows = 0
    previous_event_id: int | None = None
    source_compressed_bytes = 0
    source_raw_bytes = 0
    source_block_count = 0
    for block in source_blocks:
        path = Path(str(block["object_location"]))
        compressed = path.read_bytes()
        if (
            len(compressed) != int(block["compressed_bytes"])
            or hashlib.sha256(compressed).digest()
            != bytes(block["archive_sha256"])
        ):
            raise RuntimeError(f"source archive integrity mismatch:{path.name}")
        raw = gzip.decompress(compressed)
        if (
            len(raw) != int(block["raw_bytes"])
            or hashlib.sha256(raw).digest() != bytes(block["raw_sha256"])
        ):
            raise RuntimeError(f"source archive raw integrity mismatch:{path.name}")
        block_rows = 0
        for line in raw.splitlines(keepends=True):
            envelope = json.loads(line)
            if envelope.get("kind") != "event":
                raise RuntimeError("source event archive kind mismatch")
            row = envelope.get("row")
            if not isinstance(row, dict):
                raise RuntimeError("source event archive row is malformed")
            event_id = int(row["id"])
            if previous_event_id is not None and event_id <= previous_event_id:
                raise RuntimeError("source event archive order mismatch")
            previous_event_id = event_id
            if not line.endswith(b"\n"):
                line += b"\n"
            sequence.update(line)
            for builder in builders:
                builder.add(event_id, line)
            event_rows += 1
            block_rows += 1
        if block_rows != int(block["row_count"]):
            raise RuntimeError("source event archive row count mismatch")
        source_compressed_bytes += len(compressed)
        source_raw_bytes += len(raw)
        source_block_count += 1
    return {
        "source_event_blocks": source_block_count,
        "source_event_rows": event_rows,
        "source_event_raw_bytes": source_raw_bytes,
        "source_event_compressed_bytes": source_compressed_bytes,
        "event_sequence_sha256": sequence.hexdigest(),
    }


def _measure_detail(
    *,
    data_path: Path,
    index_path: Path,
    event_id: int,
    expected_semantic_sha256: str,
    independent_runs: int,
    warmups: int,
    measured: int,
) -> dict[str, Any]:
    cold_samples: list[float] = []
    warm_samples: list[float] = []
    for _run in range(independent_runs):
        started = time.perf_counter()
        reader = FramedArchiveReader(data_path, index_path)
        row = reader.read_event(event_id)
        cold_samples.append((time.perf_counter() - started) * 1000)
        if _digest_rows([row]) != expected_semantic_sha256:
            raise RuntimeError("D-prime event detail semantic mismatch")
        for _ in range(warmups):
            reader.read_event(event_id)
        for _ in range(measured):
            started = time.perf_counter()
            row = reader.read_event(event_id)
            warm_samples.append((time.perf_counter() - started) * 1000)
            if _digest_rows([row]) != expected_semantic_sha256:
                raise RuntimeError("D-prime event detail semantic mismatch")
        reader.close()
    return {
        "cold_sample_count": len(cold_samples),
        "cold_p50_ms": sorted(cold_samples)[len(cold_samples) // 2],
        "cold_p95_ms": _p95(cold_samples),
        "warm_sample_count": len(warm_samples),
        "warm_p50_ms": sorted(warm_samples)[len(warm_samples) // 2],
        "warm_p95_ms": _p95(warm_samples),
        "warm_max_ms": max(warm_samples),
        "semantic_sha256": expected_semantic_sha256,
        "cold_cache_control": (
            "new reader and index load per independent run; OS cache not flushed"
        ),
    }


def _minimum_recent_blocks(cardinalities: list[int], required: int = 100) -> int:
    accumulated = 0
    for index, cardinality in enumerate(cardinalities, start=1):
        accumulated += int(cardinality)
        if accumulated >= int(required):
            return index
    raise RuntimeError("entity timeline cannot supply required rows")


def _measure_bounded_entity_timeline(
    *,
    connect,
    entity_id: int,
    expected_semantic_sha256: str,
    independent_runs: int,
    warmups: int,
    measured: int,
) -> dict[str, Any]:
    # Expand all blocks before limiting: a 64-block shortcut cannot prove the
    # top-100 boundary when one event has links spanning blocks/roles.
    sql = """
        select expanded.event_id,expanded.role_id
        from event_entity_link_blocks_v2 block
        cross join lateral unnest(block.event_ids,block.role_ids)
            expanded(event_id,role_id)
        where block.entity_id=%s
        order by expanded.event_id desc,expanded.role_id asc
        limit 100
    """
    with connect() as conn, conn.cursor() as cur:
        cur.execute(sql, (int(entity_id),))
        reference_rows = _normalize_timeline([dict(row) for row in cur.fetchall()])
    if _digest_rows(reference_rows) != expected_semantic_sha256:
        raise RuntimeError("D-prime timeline preflight differs from fresh D")
    samples: list[float] = []
    result_identity: tuple[int, str] | None = None
    for _run in range(independent_runs):
        with connect() as conn, conn.cursor() as cur:
            for _ in range(warmups):
                cur.execute(sql, (int(entity_id),))
                cur.fetchall()
            for _ in range(measured):
                started = time.perf_counter()
                cur.execute(sql, (int(entity_id),))
                rows = [dict(row) for row in cur.fetchall()]
                elapsed_ms = (time.perf_counter() - started) * 1000
                rows = _normalize_timeline(rows)
                samples.append(elapsed_ms)
                identity = (len(rows), _digest_rows(rows))
                if result_identity not in (None, identity):
                    raise RuntimeError("D-prime entity timeline is non-deterministic")
                result_identity = identity
    if result_identity is None or result_identity[1] != expected_semantic_sha256:
        raise RuntimeError("D-prime entity timeline semantic mismatch")
    return {
        "query_strategy": "all_matching_blocks_expand_then_limit",
        "sample_count": len(samples),
        "p50_ms": sorted(samples)[len(samples) // 2],
        "p95_ms": _p95(samples),
        "max_ms": max(samples),
        "result_rows": result_identity[0],
        "semantic_sha256": result_identity[1],
        "timeline_contract_version": TIMELINE_CONTRACT_VERSION,
        "entity_id": int(entity_id),
    }


def _select_variant(
    variants: list[dict[str, Any]],
    *,
    warm_limit_ms: float,
    cold_limit_ms: float,
) -> dict[str, Any] | None:
    eligible = [
        variant
        for variant in variants
        if variant["event_detail_benchmark"]["warm_p95_ms"] <= warm_limit_ms
        and variant["event_detail_benchmark"]["cold_p95_ms"] <= cold_limit_ms
        and variant["semantic_parity"] is True
        # Rank only owned, measured framing bytes. The unbound PostgreSQL
        # component is common to every variant and is not an acceptance metric.
        and type(variant["storage"].get("event_archive_and_index_bytes")) is int
        and variant["storage"]["event_archive_and_index_bytes"] > 0
    ]
    if not eligible:
        return None
    return min(
        eligible,
        key=lambda item: (
            item["storage"]["event_archive_and_index_bytes"],
            float(item["event_detail_benchmark"]["warm_p95_ms"]),
            str(item["id"]),
        ),
    )


def _detail_latency_limits(contract: dict[str, Any]) -> tuple[float, float]:
    point = contract["query_classes"]["point"]
    if "event_detail_archive_lookup" not in point["workloads"]:
        raise ValueError("event detail is not assigned to point query class")
    limits = []
    for key in ("warm_p95_ms_max", "cold_p95_ms_max"):
        value = point[key]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"invalid point latency limit:{key}")
        if not math.isfinite(value) or value <= 0:
            raise ValueError(f"invalid point latency limit:{key}")
        limits.append(float(value))
    return limits[0], limits[1]


def run(frame_rows: list[int]) -> dict[str, Any]:
    _detail_latency_limits(_load_contract())
    with _exported_snapshot(_snapshot_source()) as (connect, receipt):
        return _run_candidate(frame_rows, connect, receipt)


def _run_candidate(frame_rows: list[int], connect, receipt) -> dict[str, Any]:
    contract = _load_contract()
    performance = contract["performance_gates"]
    warm_limit_ms, cold_limit_ms = _detail_latency_limits(contract)
    expected_events = int(contract["canonical_corpus"]["events"])
    baseline_path = ROOT / "artifacts/stage7/evidence/control-d-readonly-baseline.json"
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    expected_detail_hash = str(
        baseline["event_detail_benchmark"]["semantic_sha256"]
    )
    baseline_timeline = baseline["query_benchmarks"]["entity_timeline"]
    if baseline_timeline.get("timeline_contract_version") != TIMELINE_CONTRACT_VERSION:
        raise RuntimeError("D-prime requires a fresh versioned D timeline baseline")
    expected_timeline_hash = str(baseline_timeline["semantic_sha256"])

    # A saved versioned baseline is compatible input, never proof of today's source.
    # Re-measure D against the exact same exported snapshot before using its hashes.
    fresh_baseline = _run_snapshot(connect, receipt)
    if baseline.get("corpus") != fresh_baseline["corpus"]:
        raise RuntimeError("D-prime saved baseline corpus differs from measured snapshot")
    expected_detail_hash = fresh_baseline["event_detail_benchmark"]["semantic_sha256"]
    expected_timeline_hash = fresh_baseline["query_benchmarks"]["entity_timeline"]["semantic_sha256"]
    baseline_timeline = fresh_baseline["query_benchmarks"]["entity_timeline"]

    with connect() as conn:
        source_blocks = _source_event_blocks(conn)
        relation_sizes = _relation_sizes(conn)
        seeds = _query_seeds(conn)
        if int(baseline_timeline["entity_id"]) != int(seeds["entity_id"]):
            raise RuntimeError("D-prime timeline seed differs from D baseline")
        with conn.cursor() as cur:
            cur.execute(
                """
                select archive_kind,coalesce(sum(compressed_bytes),0)::bigint
                           as compressed_bytes
                from storage_v2_archive_blocks
                where state='published'
                group by archive_kind
                """
            )
            archive_bytes_by_kind = {
                str(row["archive_kind"]): int(row["compressed_bytes"])
                for row in cur.fetchall()
            }

    temp_root = ROOT / "artifacts" / "stage7" / "tmp"
    temp_root.mkdir(parents=True, exist_ok=True)
    variants: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="control-d-prime-", dir=temp_root) as tmp:
        work = Path(tmp)
        builders: list[FramedArchiveBuilder] = []
        paths: dict[int, tuple[Path, Path]] = {}
        for rows in sorted(set(int(value) for value in frame_rows)):
            data_path = work / f"events-{rows}.frames"
            index_path = work / f"events-{rows}.idx"
            paths[rows] = (data_path, index_path)
            builders.append(
                FramedArchiveBuilder(
                    data_path=data_path,
                    index_path=index_path,
                    target_rows=rows,
                )
            )
        source = _stream_source_into_builders(source_blocks, builders)
        if source["source_event_rows"] != expected_events:
            raise RuntimeError("D-prime source corpus count mismatch")
        build_by_rows = {
            builder.target_rows: builder.finish() for builder in builders
        }
        for rows in sorted(build_by_rows):
            build = build_by_rows[rows]
            if (
                build["event_rows"] != expected_events
                or build["event_sequence_sha256"]
                != source["event_sequence_sha256"]
            ):
                raise RuntimeError("D-prime framed corpus identity mismatch")
            data_path, index_path = paths[rows]
            detail = _measure_detail(
                data_path=data_path,
                index_path=index_path,
                event_id=int(seeds["detail_event_id"]),
                expected_semantic_sha256=expected_detail_hash,
                independent_runs=int(performance["independent_runs"]),
                warmups=int(performance["warmup_runs_per_query"]),
                measured=int(performance["measured_runs_per_query"]),
            )
            event_archive_bytes = int(build["archive_and_index_bytes"])
            unchanged_link_archive_bytes = int(
                archive_bytes_by_kind.get("link_detail", 0)
            )
            current_live = int(
                relation_sizes["candidate_d_projected_live_bytes"]
            )
            projected_live = (
                current_live
                - int(source["source_event_compressed_bytes"])
                + event_archive_bytes
            )
            variants.append(
                {
                    "id": f"D-prime-{rows}",
                    "target_rows_per_frame": rows,
                    "build": build,
                    "storage": {
                        "event_archive_and_index_bytes": event_archive_bytes,
                        "unchanged_link_archive_bytes": (
                            unchanged_link_archive_bytes
                        ),
                        "projected_live_bytes": projected_live,
                        "postgresql_physical_size_scope": relation_sizes["postgresql_physical_size_scope"],
                        "full_managed_storage_bytes": None,
                        "full_managed_storage_status": (
                            "pending selected-variant backup restore measurement"
                        ),
                    },
                    "event_detail_benchmark": detail,
                    "semantic_parity": True,
                }
            )

        timeline = _measure_bounded_entity_timeline(
            connect=connect,
            entity_id=int(seeds["entity_id"]),
            expected_semantic_sha256=expected_timeline_hash,
            independent_runs=int(performance["independent_runs"]),
            warmups=int(performance["warmup_runs_per_query"]),
            measured=int(performance["measured_runs_per_query"]),
        )
        selected = _select_variant(
            variants,
            warm_limit_ms=warm_limit_ms,
            cold_limit_ms=cold_limit_ms,
        )

    return {
        "status": (
            "measured_provisional_frame_variant_pending_full_managed_storage"
            if selected is not None
            else "measured_query_evidence_pending_isolated_storage"
        ),
        "candidate": "D-prime",
        "mode": "isolated_temporary_full_corpus",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "priority_order": [
            "complete_and_restorable",
            "minimum_full_managed_storage",
            "minimum_viable_performance",
            "operational_complexity",
        ],
        "source": source,
        "snapshot": receipt,
            "postgresql_physical_size_scope": relation_sizes["postgresql_physical_size_scope"],
        "corpus": fresh_baseline["corpus"],
        "reference_control_timeline": baseline_timeline,
        "variants": variants,
        "bounded_entity_timeline": timeline,
        "selected_variant": selected["id"] if selected else None,
        "selection_scope": "provisional_private_framing_only",
        "architecture_acceptance": False,
        "selection_basis": (
            "minimum measured private event archive and index bytes among "
            "semantically matching variants passing detail latency gates; "
            "shared PostgreSQL physical bytes are excluded, total storage remains pending"
        ),
        "pending_gates": [
            "isolated PostgreSQL physical-size measurement bound to verified corpus",
            "selected variant empty restore and full checksum readback",
            "completed backup bytes",
            "independent recovery-copy bytes",
            "measured peak restore temporary bytes",
            "report/access parity",
            "sustained ingest throughput",
        ],
        "temporary_benchmark_files_removed": True,
        "production_mutated": False,
        "collection_started": False,
        "event_payloads_in_evidence": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Измерить изолированный CONTROL D′ на полном корпусе."
    )
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--frame-rows",
        default="512,2048,8192",
        help="Размеры независимо читаемых кадров через запятую.",
    )
    args = parser.parse_args()
    frame_rows = [
        int(value.strip())
        for value in str(args.frame_rows).split(",")
        if value.strip()
    ]
    if not frame_rows:
        raise SystemExit("Не задан ни один размер кадра.")
    result = run(frame_rows)
    output = (ROOT / args.output).resolve()
    output.relative_to(ROOT.resolve())
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, default=str) + "\n",
        encoding="utf-8",
    )
    print(
        "CONTROL D-prime измерен без изменений production; "
        f"вариантов: {len(result['variants'])}; "
        f"предварительный формат кадров: {result['selected_variant'] or 'нет'}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

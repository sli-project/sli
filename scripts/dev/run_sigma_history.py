"""Evaluate the pinned 25-rule profile sequentially on an authorized LAB copy.

The copy is a caller-owned, bounded export of retained evidence, outside git.
Its checksum is supplied separately by the operator. No database connection,
source collection, runtime cursor, admission or finding writer is available.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import signal
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from scripts.dev.compile_sigma_profile import compile_profile
from scripts.dev.verify_sigma_package import CONFIG
from server.sli.sigma.history_job import (
    HistoryBudget,
    HistoryEvidenceRef,
    HistoryPartition,
    HistoryRecord,
    HistoryRequest,
    run_history_job,
)
from server.sli.sigma.windows_mapping import EventScope, SigmaMappingError, map_windows_event

COPY_VERSION = "sli.sigma.lab-copy.v1"
MAX_COPY_BYTES = 32 * 1024 * 1024
MAX_ROWS = 1000
MAX_XML_BYTES = 512 * 1024


class LabCopyError(ValueError):
    """Fixed diagnostics only; never include source values or paths."""


def _stamp(value):
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if stamp.utcoffset() is None:
        raise ValueError
    return stamp


class LabCopyReader:
    """Immutable in-memory copy, verified in full before any rule is evaluated."""

    def __init__(self, path: Path, expected_sha256: str):
        try:
            with path.open("rb") as stream:
                raw = stream.read(MAX_COPY_BYTES + 1)
            if (len(raw) > MAX_COPY_BYTES or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256)
                    or hashlib.sha256(raw).hexdigest() != expected_sha256):
                raise ValueError
            document = json.loads(raw)
            if document["version"] != COPY_VERSION or not 1 <= len(document["partitions"]) <= 256:
                raise ValueError
            _stamp(document["exported_at"])
            self.exported_at = document["exported_at"]
            self.sha256 = expected_sha256
            partitions, records = [], {}
            total = 0
            for block in document["partitions"]:
                # Stage 08 reads a core-event export only. WS references must
                # use their immutable observation reader, never integer IDs.
                if block["storage_kind"] != "core_event":
                    raise ValueError
                scope = EventScope(**block["scope"])
                part = HistoryPartition(scope, block["storage_kind"], _stamp(block["start"]),
                                        _stamp(block["end"]), expected_sha256, block["high_watermark"])
                rows = block["records"]
                total += len(rows)
                if total > MAX_ROWS or len(rows) != part.high_watermark or part.key in records:
                    raise ValueError
                mapped = []
                for position, row in enumerate(rows, 1):
                    native_id, digest = row["native_id"], row["sha256"]
                    if (not isinstance(native_id, str) or not re.fullmatch(r"[1-9][0-9]{0,18}", native_id)
                            or int(native_id) >= 2**63):
                        raise ValueError
                    ref = HistoryEvidenceRef("core_event", native_id, digest)
                    stamp = _stamp(row["occurred_at"])
                    if not part.start <= stamp < part.end:
                        raise ValueError
                    xml = row["source_xml"]
                    event, reasons = None, ()
                    if xml is None:
                        reasons = ("payload_unavailable",)
                    else:
                        if (not isinstance(xml, str) or len(xml.encode()) > MAX_XML_BYTES
                                or hashlib.sha256(xml.encode()).hexdigest() != digest):
                            raise ValueError
                        try:
                            event = map_windows_event(xml, scope=scope)
                        except SigmaMappingError as error:
                            reasons = (("mapping_schema_unsupported" if str(error) == "sigma_event_schema_unsupported"
                                        else "mapping_unavailable"),)
                        if event is not None and _stamp(event.identity.occurred_at) != stamp:
                            raise ValueError
                    mapped.append(HistoryRecord(position, ref, scope, stamp, event, reasons))
                partitions.append(part)
                records[part.key] = tuple(mapped)
            if not total:
                raise ValueError
            self.partitions = tuple(partitions)
            self._records = records
        except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
            raise LabCopyError("sigma_lab_copy_invalid") from None

    def read_one(self, partition, *, after, max_bytes, timeout_seconds):
        if partition not in self.partitions:
            raise PermissionError
        rows = self._records[partition.key]
        return rows[after] if after < len(rows) else None


def evaluate_copy(reader, compilation, *, cancelled=lambda: False, max_slices=20):
    if type(max_slices) is not int or not 1 <= max_slices <= 20:
        raise LabCopyError("sigma_lab_slice_budget_invalid")
    if compilation.unsupported or len(compilation.compiled) != 25:
        raise LabCopyError("sigma_lab_profile_incomplete")
    request = HistoryRequest("sigma-stage08", compilation.compiled, reader.partitions,
                             hashlib.sha256((CONFIG / "lock.json").read_bytes()).hexdigest())
    budget = HistoryBudget(max_rows=100, max_evaluations=2500, max_job_rows=MAX_ROWS, max_samples=10)
    checkpoint = None
    for _ in range(max_slices):
        result = run_history_job(request, reader, authorized=lambda part: part in reader.partitions,
                                 cancelled=cancelled, budget=budget, checkpoint=checkpoint)
        if result.status != "partial" or result.checkpoint == checkpoint:
            return result
        checkpoint = result.checkpoint
    return result


def write_copy_result(result, reader, output):
    """Persist a terminal TEST manifest, with input refs even on zero matches.

    Scan samples describe inspected inputs, never positive detection evidence.
    Only acknowledged rows are eligible; failed/revoked jobs expose no refs.
    """
    manifest = result.manifest()
    samples = []
    if result.status != "failed":
        for index, part in enumerate(reader.partitions):
            if index > result.checkpoint.partition_index:
                break
            after = (part.high_watermark if index < result.checkpoint.partition_index
                     else result.checkpoint.after)
            for record in reader._records[part.key][:after]:
                if len(samples) < 10:
                    samples.append({"partition_key": part.key, "ref": asdict(record.ref),
                                    "quality_reasons": record.quality_reasons})
    manifest["input_copy"] = {"version": COPY_VERSION, "sha256": reader.sha256,
                              "exported_at": reader.exported_at, "scan_samples": samples}
    output = Path(output)
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    temporary = output / "result.pending"
    with temporary.open("x", encoding="utf-8") as stream:
        json.dump(manifest, stream, sort_keys=True, ensure_ascii=True, indent=2)
        stream.write("\n")
    temporary.replace(output / "result.json")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--copy", required=True, type=Path)
    parser.add_argument("--copy-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    cancelled = False

    def cancel(signum, frame):
        nonlocal cancelled
        cancelled = True

    previous = signal.signal(signal.SIGINT, cancel)
    try:
        reader = LabCopyReader(args.copy, args.copy_sha256)
        result = evaluate_copy(reader, compile_profile(args.archive), cancelled=lambda: cancelled)
        write_copy_result(result, reader, args.output)
        # Do not print paths, source identifiers, payloads or exception details.
        print(json.dumps({"status": result.status, "reason": result.reason,
                          "rows_read": result.checkpoint.rows_read, "rules": len(result.request.rules),
                          "copy_sha256": reader.sha256}))
        return 0 if result.status == "completed" else 2
    except Exception:
        print("Sigma stage 08: FAILED (copy, profile or output invalid)")
        return 1
    finally:
        signal.signal(signal.SIGINT, previous)


if __name__ == "__main__":
    raise SystemExit(main())

"""Split out of ``server.sli.storage.warm_tier_incremental_copy_runtime`` (plan 7.2b).

Module-level names of ``warm_tier_incremental_copy_runtime`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import server.sli.storage.warm_tier_incremental_copy_runtime as _src


def _validated_archive_object_path(location: object) -> tuple[_src.Path, _src.os.stat_result]:
    """Validate a historical manifest locator without a configured archive root."""
    candidate = _src.Path(str(location))
    if not candidate.is_absolute() or ".." in candidate.parts:
        raise RuntimeError("archive_object_invalid_path")
    probes = [*reversed(candidate.parents), candidate]
    for probe in probes:
        try:
            metadata = probe.lstat()
        except OSError as exc:
            raise RuntimeError("archive_object_unavailable") from exc
        attributes = int(getattr(metadata, "st_file_attributes", 0))
        if _src.stat.S_ISLNK(metadata.st_mode) or attributes & 0x400:
            raise RuntimeError("archive_object_reparse_component")
    final_metadata = probes[-1].lstat()
    if not _src.stat.S_ISREG(final_metadata.st_mode):
        raise RuntimeError("archive_object_unavailable")
    return candidate, final_metadata


def _open_archive_object(location: object) -> _src._LockedArchiveObject:
    path, path_metadata = _src._validated_archive_object_path(location)
    if _src.os.name == "nt":
        import ctypes
        import msvcrt

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateFileW.restype = ctypes.c_void_p
        native = kernel32.CreateFileW(
            str(path), 0x80000000, 0x00000001, None, 3,
            0x00200000 | 0x08000000, None,
        )
        if native == ctypes.c_void_p(-1).value:
            raise RuntimeError("archive_object_locked_open_failed")
        try:
            descriptor = msvcrt.open_osfhandle(int(native), _src.os.O_RDONLY | _src.os.O_BINARY)
            handle = _src.os.fdopen(descriptor, "rb", buffering=0)
        except Exception:
            kernel32.CloseHandle(ctypes.c_void_p(native))
            raise
    else:
        flags = _src.os.O_RDONLY | getattr(_src.os, "O_CLOEXEC", 0) | getattr(_src.os, "O_NOFOLLOW", 0)
        try:
            descriptor = _src.os.open(path, flags)
        except OSError as exc:
            raise RuntimeError("archive_object_locked_open_failed") from exc
        handle = _src.os.fdopen(descriptor, "rb", buffering=0)
        try:
            import fcntl
            fcntl.flock(descriptor, fcntl.LOCK_SH)
        except (ImportError, OSError):
            handle.close()
            raise RuntimeError("archive_object_lock_failed")
    opened = _src.os.fstat(handle.fileno())
    attributes = int(getattr(opened, "st_file_attributes", 0))
    if (
        not _src.stat.S_ISREG(opened.st_mode)
        or attributes & 0x400
        or _src._file_identity(opened) != _src._file_identity(path_metadata)
    ):
        handle.close()
        raise RuntimeError("archive_object_changed_during_locked_open")
    return _src._LockedArchiveObject(path=path, handle=handle, identity=_src._file_identity(opened))


def _open_verified_archive_placements(
    rows: list[dict[str, _src.Any]],
    blocks: list[dict[str, _src.Any]],
) -> tuple[_src._ArchiveObjectLease, list[dict[str, _src.Any]], dict[str, _src.Any]]:
    """Open each object once, stream-verify it, and return retained handles."""
    expected = {
        int(row["id"]): (
            bytes(row["normalized_hash"]).hex()
            if not isinstance(row["normalized_hash"], str)
            else str(row["normalized_hash"]).lower()
        )
        for row in rows
    }
    expected_core = {}
    for row in rows:
        value = row.get("source_core_sha256")
        if isinstance(value, (bytes, bytearray, memoryview)):
            value = bytes(value).hex()
        expected_core[int(row["id"])] = (
            value.lower()
            if isinstance(value, str) and _src.re.fullmatch(r"[0-9a-fA-F]{64}", value)
            else None
        )
    found: dict[int, dict[str, _src.Any]] = {}
    duplicate_ids: set[int] = set()
    compressed_total = 0
    raw_total = 0
    block_digest = _src.hashlib.sha256()
    opened: list[_src._LockedArchiveObject] = []
    lease = _src._ArchiveObjectLease(opened)
    try:
        for block in blocks:
            item = _src._open_archive_object(block["object_location"])
            opened.append(item)
            path = item.path
            declared_compressed = int(block["compressed_bytes"])
            declared_raw = int(block["raw_bytes"])
            compressed_reader = _src._CompressedHashReader(
                item,
                declared_bytes=declared_compressed,
                hard_bytes=_src.MAX_ARCHIVE_COMPRESSED_BYTES - compressed_total,
            )
            expected_archive_sha = bytes(block["archive_sha256"])
            raw_digest = _src.hashlib.sha256()
            raw_bytes = 0
            block_rows = 0
            block_found: dict[int, dict[str, _src.Any]] = {}
            with _src.gzip.GzipFile(fileobj=compressed_reader, mode="rb") as archive:
                while True:
                    line = archive.readline(_src.MAX_ARCHIVE_JSONL_RECORD_BYTES + 1)
                    if not line:
                        break
                    if len(line) > _src.MAX_ARCHIVE_JSONL_RECORD_BYTES:
                        raise RuntimeError(f"archive_jsonl_record_too_large:{path.name}")
                    raw_bytes += len(line)
                    if raw_bytes > declared_raw or raw_total + raw_bytes > _src.MAX_ARCHIVE_RAW_BYTES:
                        raise RuntimeError("archive_raw_bytes_out_of_bounds")
                    raw_digest.update(line)
                    block_rows += 1
                    envelope = _src.json.loads(line)
                    if envelope.get("kind") != "event":
                        raise RuntimeError(f"archive_kind_mismatch:{path.name}")
                    event = dict(envelope.get("row") or {})
                    event_id = int(event.get("id") or 0)
                    if event_id not in expected:
                        continue
                    if event_id in block_found:
                        raise RuntimeError(f"archive_event_duplicate:{event_id}")
                    normalized = str(event.get("normalized_hash") or "").lower()
                    if normalized != expected[event_id]:
                        raise RuntimeError(f"archive_event_hash_mismatch:{event_id}")
                    block_found[event_id] = {
                        "placement": {
                            "id": event_id,
                            "normalized_hash": normalized,
                            "archive_file": str(path),
                            "archive_line": block_rows,
                        },
                        "row_sha256": _src.hashlib.sha256(_src.canonical_json_bytes(event)).digest(),
                        # Re-imports can retain a published archive with different
                        # capture provenance. No payload or other field may drift.
                        "content_sha256": _src.hashlib.sha256(_src.canonical_json_bytes({
                            key: value for key, value in event.items()
                            if key not in {"raw_log_file_id", "normalized_at"}
                        })).digest(),
                        "matches_source_core": (
                            _src.event_source_core_sha256(event).hex() == expected_core[event_id]
                        ),
                    }
            while compressed_reader.read(_src.ARCHIVE_STREAM_CHUNK_BYTES):
                pass
            if (
                compressed_reader.length != declared_compressed
                or compressed_reader.digest.digest() != expected_archive_sha
            ):
                raise RuntimeError(f"archive_compressed_mismatch:{path.name}")
            if raw_bytes != declared_raw or raw_digest.digest() != bytes(block["raw_sha256"]):
                raise RuntimeError(f"archive_raw_mismatch:{path.name}")
            if block_rows != int(block["row_count"]):
                raise RuntimeError(f"archive_row_count_mismatch:{path.name}")
            compressed_total += compressed_reader.length
            raw_total += raw_bytes
            block_digest.update(expected_archive_sha)
            for event_id, candidate in block_found.items():
                previous = found.get(event_id)
                if previous is None:
                    found[event_id] = candidate
                    continue
                duplicate_ids.add(event_id)
                if previous["content_sha256"] != candidate["content_sha256"]:
                    raise RuntimeError(f"archive_event_content_mismatch:{event_id}")
                if expected_core[event_id] is None:
                    raise RuntimeError(f"archive_event_source_core_missing:{event_id}")
                if candidate["matches_source_core"]:
                    if previous["matches_source_core"]:
                        if previous["row_sha256"] != candidate["row_sha256"]:
                            raise RuntimeError(f"archive_event_source_core_ambiguous:{event_id}")
                        old = previous["placement"]
                        new = candidate["placement"]
                        if (old["archive_file"], old["archive_line"]) <= (new["archive_file"], new["archive_line"]):
                            continue
                    found[event_id] = candidate
        lease.verify_identity()
        for event_id in sorted(duplicate_ids):
            if not found[event_id]["matches_source_core"]:
                raise RuntimeError(f"archive_event_source_core_mismatch:{event_id}")
        missing = sorted(set(expected) - set(found))
        if missing:
            raise RuntimeError(f"archive_events_missing:{len(missing)}")
        placements = [found[event_id]["placement"] for event_id in sorted(found)]
        if _src._identity(placements) != _src._identity(rows):
            raise RuntimeError("archive_batch_identity_mismatch")
    except Exception:
        lease.close()
        raise
    return lease, placements, {
        "blocks": len(blocks),
        "compressed_bytes_verified": compressed_total,
        "raw_bytes_verified": raw_total,
        "block_sha256_sequence": block_digest.hexdigest(),
    }

"""Split out of ``scripts.runtime.storage_lifecycle_worker`` (plan 7.2b).

Module-level names of ``storage_lifecycle_worker`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import scripts.runtime.storage_lifecycle_worker as _src


def _frozen_no_archive_cutoff(
    started: _src.datetime,
    *,
    retention_days: int,
) -> _src.datetime:
    fresh = started.astimezone(_src.timezone.utc) - _src.timedelta(days=retention_days)
    if not _src.NO_ARCHIVE_PROGRESS.is_file():
        return fresh
    try:
        progress = _src.json.loads(_src.NO_ARCHIVE_PROGRESS.read_text(encoding="utf-8"))
        if (
            not isinstance(progress, dict)
            or progress.get("contract") not in {
                "sli.storage-no-archive-progress.v1",
                "sli.storage-no-archive-progress.v2",
            }
            or progress.get("status") not in {"blocked", "partial", "complete"}
        ):
            raise ValueError("contract")
        if progress["status"] == "complete":
            return fresh
        expected_descriptors = [
            {key: descriptor[key] for key in ("source", "stream", "event_key")}
            for descriptor in _src.direct_no_archive_descriptors(
                _src.load_storage_policy(), event_keys=_src.NOISE_DELETE_EVENT_KEYS,
            )
        ]
        if progress.get("descriptor_identities") != expected_descriptors:
            raise ValueError("descriptor_predicate")
        cutoff = _src.datetime.fromisoformat(str(progress.get("cutoff_utc") or ""))
        if cutoff.tzinfo is None:
            raise ValueError("timezone")
        cutoff = cutoff.astimezone(_src.timezone.utc)
        if cutoff > started.astimezone(_src.timezone.utc):
            raise ValueError("future")
        return cutoff
    except (OSError, TypeError, ValueError, _src.json.JSONDecodeError) as exc:
        raise RuntimeError("no_archive_progress_invalid") from exc


def _declaration_progress_digest(progress: dict[str, object]) -> str:
    payload = {
        key: progress.get(key)
        for key in (
            "contract", "declaration_ids", "scope_identity",
            "declaration_sha256", "candidate_identity_sha256",
        )
    }
    return _src.hashlib.sha256(
        _src.json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _validated_declaration_progress(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise RuntimeError("declaration_progress_invalid")
    progress = dict(value)
    ids = progress.get("declaration_ids")
    hex_fields = ("declaration_sha256", "candidate_identity_sha256", "digest")
    if (
        progress.get("contract") != "sli.storage-lifecycle-declaration-progress.v1"
        or not isinstance(ids, list) or not ids
        or len(ids) > _src.MAX_DECLARATION_IDS
        or any(isinstance(item, bool) or not isinstance(item, int) or item <= 0 for item in ids)
        or ids != sorted(set(ids))
        or not str(progress.get("scope_identity") or "")
        or any(
            len(str(progress.get(field) or "")) != 64
            or any(character not in "0123456789abcdef" for character in str(progress.get(field) or ""))
            for field in hex_fields
        )
        or str(progress.get("digest")) != _src._declaration_progress_digest(progress)
    ):
        raise RuntimeError("declaration_progress_invalid")
    return progress


def _processed_declaration_ids() -> set[int]:
    if not _src.PROCESSED_PACKAGES.is_file():
        return set()
    result: set[int] = set()
    total_ids = 0
    for row in _src.iter_json_lines(
        _src.PROCESSED_PACKAGES, max_bytes=_src.MAX_PROCESSED_LEDGER_BYTES,
        max_line_bytes=_src.MAX_PROCESSED_LEDGER_LINE_BYTES,
        max_rows=_src.MAX_PROCESSED_LEDGER_ROWS,
        too_large="processed_package_ledger_too_large",
    ):
        try:
            progress = _src._validated_declaration_progress(row["declaration_progress"])
            if row.get("progress_digest") != progress["digest"]:
                raise RuntimeError("processed_package_ledger_digest_mismatch")
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeError("processed_package_ledger_invalid") from exc
        total_ids += len(progress["declaration_ids"])
        if total_ids > _src.MAX_PROCESSED_DECLARATION_IDS:
            raise RuntimeError("processed_package_declaration_id_count_out_of_bounds")
        result.update(int(item) for item in progress["declaration_ids"])
    return result


def _commit_processed_package(
    progress_value: object, *, promotion_output_identity: str,
) -> None:
    progress = _src._validated_declaration_progress(progress_value)
    output_identity = str(promotion_output_identity or "").lower()
    if len(output_identity) != 64 or any(value not in "0123456789abcdef" for value in output_identity):
        raise RuntimeError("promotion_output_identity_invalid")
    if set(int(item) for item in progress["declaration_ids"]).issubset(
        _src._processed_declaration_ids()
    ):
        return
    row = {
        "contract": "sli.storage-lifecycle-processed-package.v1",
        "progress_digest": progress["digest"],
        "promotion_output_identity": output_identity,
        "declaration_progress": progress,
        "committed_at_utc": _src.datetime.now(_src.timezone.utc).isoformat(),
    }
    _src.PROCESSED_PACKAGES.parent.mkdir(parents=True, exist_ok=True)
    with _src.PROCESSED_PACKAGES.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(_src.json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
        handle.flush()
        _src.os.fsync(handle.fileno())

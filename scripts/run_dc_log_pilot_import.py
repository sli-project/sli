"""Split out of ``scripts.run_dc_log_pilot`` (plan 6.3): raw batch manifest/cleanup and PostgreSQL import identity.

Module-level names of ``run_dc_log_pilot`` are looked up through ``_src`` at
call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import Callable

import scripts.run_dc_log_pilot as _src


def runtime_db_backend() -> str:
    try:
        return (_src.load_config().db_backend or "postgres").strip().lower()
    except Exception:
        return os.environ.get("ADLOG_DB_BACKEND", "postgres").strip().lower() or "postgres"


def postgres_import_timeout_seconds() -> int:
    try:
        return max(60, int(os.environ.get("ADLOG_POSTGRES_IMPORT_TIMEOUT_SECONDS", "1800")))
    except (TypeError, ValueError):
        return 1800


def raw_batch_manifest(*, output_dir: Path, raw_root: Path, server: str) -> dict[str, object]:
    """Return a deterministic identity and content manifest for one raw batch.

    Lifecycle marker files are deliberately excluded: the manifest describes
    the collector/importer input and therefore remains stable while PostgreSQL
    records later lifecycle transitions.
    """
    root = raw_root.resolve()
    candidate = output_dir.resolve()
    relative = candidate.relative_to(root)
    if not relative.parts:
        raise ValueError("raw batch cannot be the raw root")
    files: list[dict[str, object]] = []
    for path in sorted(candidate.rglob("*"), key=lambda item: item.as_posix()):
        if not path.is_file() or path.name in {
            "raw-batch-lifecycle.json", "postgres-import-profile.json",
        }:
            continue
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        files.append({
            "path": path.relative_to(candidate).as_posix(),
            "size_bytes": path.stat().st_size,
            "sha256": digest.hexdigest(),
        })
    manifest_payload = json.dumps(files, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    manifest_hash = hashlib.sha256(manifest_payload.encode("utf-8")).hexdigest()
    identity_payload = f"{server.casefold()}\0{relative.as_posix().casefold()}"
    return {
        "batch_identity": hashlib.sha256(identity_payload.encode("utf-8")).hexdigest(),
        "manifest_hash": manifest_hash,
        "raw_path": str(candidate),
        "files": files,
    }


def cleanup_confirmed_raw_output(
    *,
    output_dir: Path,
    raw_root: Path,
    server: str,
    archive: bool,
    batch_identity: str,
    manifest_hash: str,
    authorize_cleanup: Callable[..., bool],
    record_cleanup_outcome: Callable[..., object] | None = None,
) -> bool:
    """Remove one imported raw batch only when the operator explicitly enables it.

    The collector used to leave every successful JSONL export on disk.  In a
    high-volume Security channel this turns the transient import spool into a
    second, unbounded event store.  Deletion is opt-in and happens only after
    the importer and PostgreSQL cursor commit have both returned successfully.
    """
    if (
        not archive
        or os.environ.get("ADLOG_DELETE_IMPORTED_RAW", "1").strip().lower()
        not in {"1", "true", "yes", "on"}
    ):
        return False
    try:
        root = raw_root.resolve()
        candidate = output_dir.resolve()
        relative = candidate.relative_to(root)
        if not relative.parts:
            raise ValueError("refusing to remove raw root itself")
        current_manifest = _src.raw_batch_manifest(
            output_dir=candidate, raw_root=root, server=server,
        )
        if (
            current_manifest["batch_identity"] != batch_identity
            or current_manifest["manifest_hash"] != manifest_hash
        ):
            return False
        if not authorize_cleanup(
            batch_identity=batch_identity,
            manifest_hash=manifest_hash,
        ):
            return False
        shutil.rmtree(candidate)
        if record_cleanup_outcome is not None:
            record_cleanup_outcome(
                batch_identity=batch_identity,
                manifest_hash=manifest_hash,
                outcome="deleted",
            )
        _src.log_event(
            "runner",
            "confirmed_raw_output_deleted",
            "Deleted imported raw batch after successful PostgreSQL cursor commit.",
            server=server,
            path=str(candidate),
        )
        return True
    except Exception as exc:
        if record_cleanup_outcome is not None and output_dir.exists():
            try:
                record_cleanup_outcome(
                    batch_identity=batch_identity,
                    manifest_hash=manifest_hash,
                    outcome="delete_failed",
                    error=str(exc),
                )
            except Exception as journal_exc:
                _src.log_internal_error(
                    "runner", "confirmed_raw_cleanup_journal_failed",
                    "Raw batch was retained but cleanup failure journaling failed.",
                    exc=journal_exc, server=server, path=str(output_dir),
                )
        _src.log_internal_error(
            "runner",
            "confirmed_raw_output_cleanup_failed",
            "Imported raw batch was retained because post-import cleanup failed.",
            exc=exc,
            server=server,
            path=str(output_dir),
        )
        return False


def _normalize_source_fqdn(value: str, *, field_name: str) -> str:
    normalized = value.strip().rstrip(".").casefold()
    labels = normalized.split(".")
    if normalized in _src.POSTGRES_SOURCE_IDENTITY_PLACEHOLDERS:
        raise ValueError(f"{field_name}_placeholder_forbidden")
    if (
        len(normalized) > 253
        or len(labels) < 2
        or any(not _src.DNS_LABEL_RE.fullmatch(label) for label in labels)
    ):
        raise ValueError(f"{field_name}_must_be_fqdn")
    return normalized


def resolve_postgres_source_identity(
    *,
    connect_address: str,
    domain_override: str | None,
    forest_override: str | None,
) -> tuple[str, str]:
    if domain_override:
        domain_fqdn = _src._normalize_source_fqdn(domain_override, field_name="domain")
    else:
        validated_connect_address = _src._normalize_source_fqdn(
            connect_address,
            field_name="connect_address",
        )
        _, separator, derived_domain = validated_connect_address.partition(".")
        if not separator:
            raise ValueError("connect_address_must_include_domain_fqdn")
        domain_fqdn = _src._normalize_source_fqdn(derived_domain, field_name="domain")
    forest_name = _src._normalize_source_fqdn(
        forest_override or domain_fqdn,
        field_name="forest",
    )
    return domain_fqdn, forest_name

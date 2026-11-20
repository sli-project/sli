"""Versioned source identity for the managed semantic worker contract."""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path


_SOURCE_NAMES = (
    "server/sli/semantic/semantic_worker_contract.py",
    "server/sli/semantic/semantic_processing_repository.py",
    "server/sli/semantic/semantic_processing_repository_persist.py",
    "server/sli/semantic/semantic_processing.py",
    "server/sli/semantic/semantic_worker_runtime.py",
    "server/sli/semantic/semantic_production_runtime.py",
    "server/sli/semantic/default_detections.py",
    "server/sli/semantic/password_attacks.py",
    "server/sli/sigma/live_runtime.py",
    "scripts/runtime/semantic_production_worker.py",
)


def _normalized_source_bytes(raw: bytes) -> bytes:
    """Make Windows, Unix, and legacy-Mac checkouts fingerprint identically."""
    return raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def semantic_worker_release_fingerprint(*, root: Path | None = None) -> str:
    """Hash the managed release admitted at planning time, not a per-job execution proof."""
    source_root = root or Path(__file__).resolve().parents[3]
    material = sha256()
    for name in _SOURCE_NAMES:
        raw = _normalized_source_bytes((source_root / name).read_bytes())
        material.update(name.encode("ascii"))
        material.update(b"\0")
        material.update(sha256(raw).digest())
    return material.hexdigest()

#!/usr/bin/env python3
"""Verify the permanent corpus copy on a physically separate Windows disk."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOT = ROOT / "artifacts" / "stage7" / "tier-move-step1" / "backup"
DEFAULT_OUTPUT = (
    ROOT / "artifacts" / "stage7" / "evidence"
    / "independent-corpus-copy-verification.json"
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _disk_number(path: Path) -> int:
    drive = path.resolve().drive.rstrip(":\\")
    if not drive:
        raise RuntimeError(f"Windows drive letter is required: {path}")
    command = (
        f"(Get-Partition -DriveLetter '{drive}').DiskNumber"
    )
    completed = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            command,
        ],
        capture_output=True,
        timeout=15,
        check=False,
        text=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"cannot resolve physical disk for {path}: {completed.stderr.strip()}"
        )
    return int(completed.stdout.strip())


def verify_copy(
    source_root: Path,
    copy_root: Path,
    *,
    source_disk_number: int,
    copy_disk_number: int,
) -> dict[str, Any]:
    source_manifest_path = source_root / "manifest.json"
    copy_manifest_path = copy_root / "manifest.json"
    manifest = json.loads(source_manifest_path.read_text(encoding="utf-8"))
    expected_files = {
        str(item["name"]): {
            "bytes": int(item["bytes"]),
            "sha256": str(item["sha256"]).lower(),
        }
        for item in manifest.get("files") or []
    }
    actual_files = {
        path.name: path
        for path in (copy_root / "events").glob("*")
        if path.is_file()
    }

    missing = sorted(set(expected_files) - set(actual_files))
    unexpected = sorted(set(actual_files) - set(expected_files))
    size_mismatches: list[str] = []
    hash_mismatches: list[str] = []
    verified_bytes = 0
    for name, expected in expected_files.items():
        path = actual_files.get(name)
        if path is None:
            continue
        size = path.stat().st_size
        verified_bytes += size
        if size != expected["bytes"]:
            size_mismatches.append(name)
            continue
        if _sha256(path) != expected["sha256"]:
            hash_mismatches.append(name)

    source_manifest_sha256 = _sha256(source_manifest_path)
    copy_manifest_sha256 = (
        _sha256(copy_manifest_path) if copy_manifest_path.is_file() else None
    )
    blockers: list[str] = []
    if source_disk_number == copy_disk_number:
        blockers.append("copy_is_not_on_a_separate_physical_disk")
    if copy_manifest_sha256 != source_manifest_sha256:
        blockers.append("manifest_mismatch")
    if missing:
        blockers.append("files_missing")
    if unexpected:
        blockers.append("unexpected_files")
    if size_mismatches:
        blockers.append("file_size_mismatch")
    if hash_mismatches:
        blockers.append("file_sha256_mismatch")

    return {
        "package_type": "INDEPENDENT_CORPUS_COPY_VERIFICATION",
        "status": "ok" if not blockers else "blocked",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source": {
            "path": str(source_root.resolve()),
            "physical_disk_number": source_disk_number,
        },
        "copy": {
            "path": str(copy_root.resolve()),
            "physical_disk_number": copy_disk_number,
            "separate_physical_disk": source_disk_number != copy_disk_number,
        },
        "manifest": {
            "source_sha256": source_manifest_sha256,
            "copy_sha256": copy_manifest_sha256,
            "matches": copy_manifest_sha256 == source_manifest_sha256,
            "rows": int((manifest.get("backup") or {}).get("rows") or 0),
            "identity_sha256": (
                manifest.get("backup") or {}
            ).get("identity_sha256"),
            "full_payload_sequence_sha256": (
                manifest.get("backup") or {}
            ).get("full_payload_sequence_sha256"),
        },
        "files": {
            "expected": len(expected_files),
            "present": len(actual_files),
            "verified_bytes": verified_bytes,
            "missing": missing,
            "unexpected": unexpected,
            "size_mismatches": size_mismatches,
            "sha256_mismatches": hash_mismatches,
        },
        "blockers": blockers,
        "source_modified": False,
        "production_databases_contacted": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--copy-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    result = verify_copy(
        SOURCE_ROOT,
        args.copy_root,
        source_disk_number=_disk_number(SOURCE_ROOT),
        copy_disk_number=_disk_number(args.copy_root),
    )
    output = args.output.resolve()
    evidence_root = (ROOT / "artifacts" / "stage7" / "evidence").resolve()
    if output.parent != evidence_root:
        parser.error(f"output must be directly inside {evidence_root}")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())

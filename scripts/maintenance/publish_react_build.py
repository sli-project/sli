#!/usr/bin/env python3
"""Publish one verified React build with a non-empty hash-checked backup."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import uuid
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / "web" / "app" / "react"
ARTIFACTS = ROOT / "artifacts"
EVIDENCE_ROOT = ARTIFACTS / "runtime"
CONFIRMATION = "PUBLISH-REACT-BUILD"


def file_manifest(root: Path) -> dict[str, dict[str, Any]]:
    if not root.is_dir():
        raise RuntimeError(f"directory not found: {root}")
    manifest: dict[str, dict[str, Any]] = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise RuntimeError(f"symbolic links are not allowed: {path}")
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        manifest[relative] = {
            "size": path.stat().st_size,
            "sha256": digest.hexdigest(),
        }
    return manifest


def validate_build(manifest: dict[str, dict[str, Any]]) -> None:
    if not manifest:
        raise RuntimeError("React build is empty")
    if "index.html" not in manifest:
        raise RuntimeError("React build has no index.html")
    if not any(name.startswith("assets/") for name in manifest):
        raise RuntimeError("React build has no assets")


def publish_build(
    *,
    source: Path,
    target: Path,
    backup: Path,
    operation_id: str,
) -> dict[str, Any]:
    source = source.resolve()
    target = target.resolve()
    backup = backup.resolve()
    source_manifest = file_manifest(source)
    target_manifest = file_manifest(target)
    validate_build(source_manifest)
    validate_build(target_manifest)
    if backup.exists():
        raise RuntimeError(f"backup already exists: {backup}")

    publish_dir = target.parent / f".{target.name}.publish-{operation_id}"
    rollback_dir = target.parent / f".{target.name}.rollback-{operation_id}"
    for transient in (publish_dir, rollback_dir):
        if transient.exists():
            raise RuntimeError(f"transient path already exists: {transient}")

    shutil.copytree(target, backup)
    backup_manifest = file_manifest(backup)
    if backup_manifest != target_manifest:
        raise RuntimeError("backup hash readback does not match current target")

    shutil.copytree(source, publish_dir)
    if file_manifest(publish_dir) != source_manifest:
        raise RuntimeError("staged publish hash readback does not match source")

    target_replaced = False
    try:
        os.replace(target, rollback_dir)
        os.replace(publish_dir, target)
        target_replaced = True
        live_manifest = file_manifest(target)
        if live_manifest != source_manifest:
            raise RuntimeError("live hash readback does not match source")
    except Exception:
        if target_replaced and target.exists():
            failed_dir = target.parent / f".{target.name}.failed-{operation_id}"
            os.replace(target, failed_dir)
            os.replace(rollback_dir, target)
            shutil.rmtree(failed_dir)
        elif rollback_dir.exists() and not target.exists():
            os.replace(rollback_dir, target)
        if publish_dir.exists():
            shutil.rmtree(publish_dir)
        raise

    # Live verification is the commit point. Cleanup can partially destroy the old
    # tree, so its failure must never send that tree through the rollback path.
    cleanup_warning = None
    try:
        shutil.rmtree(rollback_dir)
    except OSError as exc:
        cleanup_warning = {
            "code": "rollback_cleanup_failed",
            "path": str(rollback_dir),
            "error_type": type(exc).__name__,
        }

    result = {
        "status": "ok",
        "operation_id": operation_id,
        "source": str(source),
        "target": str(target),
        "backup": str(backup),
        "source_file_count": len(source_manifest),
        "backup_file_count": len(backup_manifest),
        "live_file_count": len(file_manifest(target)),
        "source_manifest": source_manifest,
        "backup_manifest": backup_manifest,
    }
    if cleanup_warning is not None:
        result["warnings"] = [cleanup_warning]
    return result


def _project_path(value: str) -> Path:
    resolved = Path(value).resolve()
    try:
        resolved.relative_to(ROOT)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("source must be inside the project") from exc
    if resolved == TARGET.resolve():
        raise argparse.ArgumentTypeError("source must differ from the live target")
    return resolved


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=_project_path)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()

    source_manifest = file_manifest(args.source)
    target_manifest = file_manifest(TARGET)
    validate_build(source_manifest)
    validate_build(target_manifest)
    plan = {
        "package_type": "REACT_BUILD_PUBLISH",
        "status": "planned",
        "mode": "apply" if args.apply else "plan",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source": str(args.source),
        "target": str(TARGET),
        "source_file_count": len(source_manifest),
        "target_file_count": len(target_manifest),
        "restart_performed": False,
    }
    if not args.apply:
        print(json.dumps(plan, ensure_ascii=False))
        return 0
    if args.confirm != CONFIRMATION:
        parser.error(f"--apply requires --confirm {CONFIRMATION}")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    operation_id = f"{timestamp}-{uuid.uuid4().hex[:8]}"
    backup = ARTIFACTS / f"https-react-backup-{timestamp}"
    result = publish_build(
        source=args.source,
        target=TARGET,
        backup=backup,
        operation_id=operation_id,
    )
    result.update(
        {
            "package_type": "REACT_BUILD_PUBLISH",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "restart_performed": False,
        }
    )
    EVIDENCE_ROOT.mkdir(parents=True, exist_ok=True)
    evidence = EVIDENCE_ROOT / f"react-publish-{operation_id}.json"
    temporary = evidence.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, evidence)
    summary = {
        "status": "ok",
        "operation_id": operation_id,
        "backup": str(backup),
        "live_file_count": result["live_file_count"],
        "evidence": str(evidence),
    }
    if "warnings" in result:
        summary["warnings"] = result["warnings"]
    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Build the separately delivered administrative DC toolkit.

This archive is intentionally not accepted by ``apply_project_zip.py``.  It is
for an authorised Windows/DC administrator, not for the read-only web product.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
TOOLKIT_FILES = (
    "scripts/manual_dc_audit/Invoke-DcAuditLoggingSetup.ps1",
    "scripts/dc_client/Invoke-AdLogDcClient.ps1",
    "scripts/dc_client/Register-AdLogDcClientTask.ps1",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(files: list[Path]) -> dict[str, object]:
    return {
        "package_type": "ADMINISTRATIVE_DC_TOOLKIT",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "owner": "authorised Windows/DC administrator",
        "normal_product_update_allowed": False,
        "requires_explicit_operator_review": True,
        "files": [
            {"path": path.relative_to(ROOT).as_posix(), "sha256": _sha256(path)}
            for path in files
        ],
    }


def build_toolkit(output: Path, *, dry_run: bool = False) -> dict[str, object]:
    files = [ROOT / relative for relative in TOOLKIT_FILES]
    missing = [str(path.relative_to(ROOT)) for path in files if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"administrative toolkit source is missing: {', '.join(missing)}")
    manifest = build_manifest(files)
    if dry_run:
        return {"status": "dry_run", "files": [item["path"] for item in manifest["files"]], "manifest": manifest}
    output.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(output, "w", compression=ZIP_DEFLATED, compresslevel=9) as archive:
        for path in files:
            archive.write(path, path.relative_to(ROOT).as_posix())
        archive.writestr("ADMIN_TOOLKIT_MANIFEST.json", json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    return {"status": "ok", "output": str(output), "manifest": manifest}


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the separately delivered administrative DC toolkit.")
    parser.add_argument("--output", type=Path, default=ROOT / "dist" / "adlog_administrative_dc_toolkit.zip")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    print(json.dumps(build_toolkit(args.output, dry_run=args.dry_run), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""
Create a lightweight source ZIP for Security Log Intelligence.

Run from the project root:
    python scripts/package_project.py

Default output:
    dist/ad_log_reports_source_YYYYMMDD_HHMMSS.zip

The archive intentionally excludes runtime-heavy or sensitive files:
    .venv, __pycache__, data/raw, data/processed, data/reports,
    data/logs, SQLite DBs, logs, local env files, caches, etc.
"""

from __future__ import annotations

import argparse
import fnmatch
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

PROJECT_NAME = "ad_log_reports"

INCLUDE_DIRS = (
    # The React workspace is source, not runtime data.  node_modules remains
    # excluded below; web/app/react carries the already built fallback assets.
    "frontend",
    "server",
    "sli_collect",
    "sli_agent",
    "scripts",
    "web",
    "config",
    "docs",
    "tests",
    "tools",
)

INCLUDE_ROOT_FILES = (
    "LICENSE",
    ".gitignore",
    "AGENTS.md",
    "README.md",
    "CHANGELOG.md",
    "PROJECT_MAP.md",
    "PROJECT_RULES.md",
    "package.json",
    "package-lock.json",
    "security-log-intelligence-roadmap.html",
    "requirements.lock.txt",
    "requirements.txt",
    "requirements-dev.txt",
    "pyproject.toml",
    "setup.cfg",
    "pytest.ini",
    ".env.example",
)

EXCLUDE_DIR_NAMES = {
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".vscode",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "node_modules",
    "dist",
    "build",
    "bin",
    "obj",
}

# Runtime-heavy project paths. These should not go into source packages.
EXCLUDE_PATH_PREFIXES = (
    "data/raw/",
    "data/processed/",
    "data/reports/",
    "data/logs/",
    "data/tmp/",
    "data/cache/",
    "config/local/",
    "config/secrets/",
    "config/private/",
    # Administrative DC tooling is delivered only through the separate toolkit.
    # The normal product bundle must remain incapable of carrying DC-changing
    # audit-policy tools or DC task-registration scripts.
    "scripts/manual_dc_audit/",
    "scripts/dc_client/",
)

EXCLUDE_FILE_PATTERNS = (
    "identity-key.json",
    "*.packet",
    "*.pyc",
    "*.pyo",
    "*.pyd",
    "*.log",
    "*.sqlite",
    "*.sqlite3",
    "*.db",
    "*.evtx",
    "*.jsonl",
    "*.tmp",
    "*.bak",
    "*.old",
    "*.zip",
    "*.7z",
    "*.rar",
    ".env",
    ".env.*",
    "*.local",
    "*.local.*",
    "*.pem",
    "*.key",
    "*.pfx",
    "*.p12",
)

# Some generated browser-save folders use names like
# "Security Log Intelligence_files". They are not part of the source tree.
EXCLUDE_DIR_PATTERNS = (
    "*_files",
    "*.html_files",
)

SANITIZE_FILES = {
    "config/domain_controllers.json",
}

SANITIZED_DOMAIN_CONTROLLERS = """{
  "description": "Example only. Replace hostname/connect_address with local values after unpacking.",
  "domain_controllers": [
    {
      "hostname": "DC1",
      "connect_address": "192.0.2.10"
    },
    {
      "hostname": "DC2",
      "connect_address": "192.0.2.11"
    }
  ]
}
"""


def rel_posix(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def is_excluded_dir(path: Path, root: Path) -> bool:
    name = path.name
    if name in EXCLUDE_DIR_NAMES:
        return True
    if any(fnmatch.fnmatch(name.lower(), pattern.lower()) for pattern in EXCLUDE_DIR_PATTERNS):
        return True
    rel = rel_posix(path, root).rstrip("/") + "/"
    return any(rel.startswith(prefix) for prefix in EXCLUDE_PATH_PREFIXES)


def is_excluded_file(path: Path, root: Path) -> bool:
    name = path.name
    rel = rel_posix(path, root)
    if rel == ".env.example":
        return False
    if any(fnmatch.fnmatch(name.lower(), pattern.lower()) for pattern in EXCLUDE_FILE_PATTERNS):
        return True
    if any(rel.startswith(prefix) for prefix in EXCLUDE_PATH_PREFIXES):
        return True
    # Credential *implementations* are required runtime source. This exemption
    # is confined to Python source roots; secret values and local configs stay out.
    if (any(token in name.lower() for token in ("secret", "password", "credential"))
            and (path.suffix.lower() != ".py" or rel.split("/", 1)[0] not in {"server", "sli_collect", "sli_agent", "scripts", "tests"})):
        return True
    # Keep schema/catalog configs, but skip likely local secrets.
    return rel.startswith("config/") and any(token in name.lower() for token in ("local", "secret", "password", "credential"))


def iter_source_files(root: Path) -> list[Path]:
    files: list[Path] = []

    for filename in INCLUDE_ROOT_FILES:
        path = root / filename
        if path.is_file() and not is_excluded_file(path, root):
            files.append(path)

    for dirname in INCLUDE_DIRS:
        base = root / dirname
        if not base.exists():
            continue
        for current_root, dirnames, filenames in os.walk(base):
            current = Path(current_root)
            dirnames[:] = [
                d for d in dirnames
                if not is_excluded_dir(current / d, root)
            ]
            for filename in filenames:
                path = current / filename
                if not is_excluded_file(path, root):
                    files.append(path)

    # Stable order makes diffs/checks easier.
    return sorted(set(files), key=lambda p: rel_posix(p, root).lower())


def sanitized_text_for(rel: str) -> str | None:
    if rel == "config/domain_controllers.json":
        return SANITIZED_DOMAIN_CONTROLLERS
    return None


def make_zip(root: Path, output: Path, dry_run: bool = False, sanitize: bool = False) -> tuple[int, int]:
    source_files = iter_source_files(root)
    total_size = sum(p.stat().st_size for p in source_files)

    if dry_run:
        print("Files that would be archived:")
        for path in source_files:
            rel = rel_posix(path, root)
            marker = " [sanitized]" if sanitize and rel in SANITIZE_FILES else ""
            print(f"  {rel}{marker}")
        print(f"\nTotal files: {len(source_files)}")
        print(f"Total uncompressed size: {total_size:,} bytes")
        return len(source_files), total_size

    output.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(output, "w", compression=ZIP_DEFLATED, compresslevel=9) as zf:
        for path in source_files:
            rel = rel_posix(path, root)
            sanitized = sanitized_text_for(rel) if sanitize else None
            if sanitized is not None:
                zf.writestr(rel, sanitized)
            else:
                zf.write(path, rel)

    print(f"Created: {output}")
    print(f"Files: {len(source_files)}")
    print(f"Uncompressed source size: {total_size:,} bytes")
    print(f"ZIP size: {output.stat().st_size:,} bytes")
    return len(source_files), total_size


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create a lightweight source ZIP without runtime data."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="Project root. Default: current directory.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output ZIP path. Default: dist/ad_log_reports_source_<timestamp>.zip",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print files that would be archived without creating ZIP.",
    )
    parser.add_argument(
        "--sanitize",
        action="store_true",
        help="Replace local infrastructure values, such as DC IP addresses, with safe examples.",
    )
    parser.add_argument("--release-manifest", type=Path, help="Explicit signed release inventory/metadata; distinct from source ZIP.")
    parser.add_argument("--signing-key", type=Path, help="External operator-protected 32-byte Ed25519 key file.")
    parser.add_argument("--key-id", help="External trust-store key identifier.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.root.resolve()

    if not root.exists():
        raise SystemExit(f"Project root does not exist: {root}")

    if args.output is None:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        output = root / "dist" / f"{PROJECT_NAME}_source_{timestamp}.zip"
    else:
        output = args.output.resolve()

    if args.release_manifest is not None:
        if not args.signing_key or not args.key_id or args.output is None or args.dry_run or args.sanitize:
            raise SystemExit("Signed builds require --output, --signing-key and --key-id; dry-run/sanitize are source-only.")
        project_root = Path(__file__).resolve().parents[1]
        if str(project_root) not in sys.path:
            sys.path.insert(0, str(project_root))
        import json

        from scripts.maintenance.release_package import (
            PackageLimits,
            _bounded_read,
            build_package,
            read_json,
        )

        result = build_package(root, output, read_json(_bounded_read(args.release_manifest, PackageLimits().max_manifest_bytes)), signing_key=args.signing_key, key_id=args.key_id)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    if args.signing_key or args.key_id:
        raise SystemExit("Signing arguments require --release-manifest.")
    make_zip(root=root, output=output, dry_run=args.dry_run, sanitize=args.sanitize)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

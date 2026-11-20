#!/usr/bin/env python3
r"""
Apply a clean Security Log Intelligence project ZIP into the current project.

This is the opposite of package_project.py:
- takes a clean source ZIP produced by package_project.py or sent by ChatGPT;
- copies only project/source files into the current project;
- does NOT overwrite runtime data, logs, SQLite DB, raw events, reports, .env, or local configs;
- creates a timestamped backup of files that will be replaced.

Recommended location:
    scripts/apply_project_zip.py

Usage from project root:
    python scripts/apply_project_zip.py C:\Downloads\ad_log_reports_stage32.zip --dry-run

This command now supports source inspection only. The old environment-variable
mutation bypass is disabled. Signed release verification uses:
    python scripts/maintenance/apply_update.py --package release.zip --trust-store trust.json --verify-only
Installation and recovery are not yet implemented by the new package contract.
"""

from __future__ import annotations

import argparse
import fnmatch
import html
import io
import shutil
import subprocess
import sys
import tempfile
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.maintenance.release_package import (
    PackageError,
    read_archive_snapshot,
    safe_package_path,
)

# Top-level paths that may be updated from a clean source ZIP.
ALLOWED_TOP_LEVEL = {
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
}

# Root files that may be updated.
ALLOWED_ROOT_FILES = {
    "LICENSE",
    "AGENTS.md",
    "README.md",
    "CHANGELOG.md",
    "PROJECT_MAP.md",
    "PROJECT_RULES.md",
    "package.json",
    "package-lock.json",
    "requirements.lock.txt",
    "requirements.txt",
    "requirements-dev.txt",
    "pyproject.toml",
    "pytest.ini",
    "setup.cfg",
    "mypy.ini",
    ".gitignore",
    ".env.example",
    "security-log-intelligence-roadmap.html",
}

# Local environment configuration is preserved by default. Use
# --allow-local-config only for an intentional local restore.
LOCAL_CONFIG_FILES = {
    "config/domain_controllers.json",
}

# Paths and patterns that must never be copied into the working project.
DENY_PATTERNS = [
    ".env",
    ".env.*",
    "*.local",
    "*.local.*",
    "*.sqlite",
    "*.sqlite3",
    "*.db",
    "*.db-*",
    "*.log",
    "*.jsonl",
    "*.evtx",
    "*.zip",
    "*.7z",
    "*.rar",
    "*.tar",
    "*.gz",
    "__pycache__/*",
    "*/__pycache__/*",
    ".pytest_cache/*",
    "*/.pytest_cache/*",
    ".mypy_cache/*",
    "*/.mypy_cache/*",
    ".ruff_cache/*",
    "*/.ruff_cache/*",
    ".venv/*",
    "venv/*",
    "env/*",
    ".git/*",
    ".idea/*",
    ".vscode/*",
    "data/*",
    "dist/*",
    "build/*",
    "bin/*",
    "obj/*",
    "*/bin/*",
    "*/obj/*",
]

# Local config/runtime subtrees that should be preserved even under allowed top-level folders.
DENY_PATH_PREFIXES = [
    "data/",
    "dist/",
    "build/",
    "bin/",
    "obj/",
    ".git/",
    ".venv/",
    "venv/",
    "env/",
    "frontend/node_modules/",
    "config/local/",
    "config/secrets/",
    "config/private/",
    # These are deliberately distributed only by package_admin_toolkit.py and
    # must never arrive in a normal product update ZIP.
    "scripts/manual_dc_audit/",
    "scripts/dc_client/",
]


@dataclass(frozen=True)
class PlanItem:
    src: Path
    dst: Path
    rel: str
    action: str  # "create" or "replace"


def normalize_zip_name(name: str) -> str | None:
    """Return a safe normalized relative path from a zip entry."""
    try:
        return safe_package_path(name)
    except PackageError:
        return None


def is_denied(rel: str, *, allow_local_config: bool = False) -> bool:
    rel_posix = rel.replace("\\", "/").lstrip("/").casefold()

    if rel_posix == ".env.example":
        return False

    if not allow_local_config and rel_posix in LOCAL_CONFIG_FILES:
        return True

    for prefix in DENY_PATH_PREFIXES:
        if rel_posix == prefix.rstrip("/") or rel_posix.startswith(prefix):
            return True

    name = PurePosixPath(rel_posix).name
    for pattern in DENY_PATTERNS:
        if fnmatch.fnmatch(rel_posix, pattern) or fnmatch.fnmatch(name, pattern):
            return True

    return False


def is_allowed(rel: str, *, allow_local_config: bool = False) -> bool:
    rel_posix = rel.replace("\\", "/").lstrip("/")
    parts = PurePosixPath(rel_posix).parts
    if not parts:
        return False

    if is_denied(rel_posix, allow_local_config=allow_local_config):
        return False

    if len(parts) == 1:
        return parts[0] in ALLOWED_ROOT_FILES

    return parts[0] in ALLOWED_TOP_LEVEL


def detect_archive_root(extracted_dir: Path) -> Path:
    """
    If zip contains one top-level project directory, use it as source root.
    Otherwise use the extraction root directly.
    """
    entries = [p for p in extracted_dir.iterdir() if p.name not in {"__MACOSX"}]
    if len(entries) == 1 and entries[0].is_dir():
        candidate = entries[0]
        candidate_names = {p.name for p in candidate.iterdir()}
        if candidate_names & (ALLOWED_TOP_LEVEL | ALLOWED_ROOT_FILES):
            return candidate
    return extracted_dir


def iter_source_files(source_root: Path) -> Iterable[Path]:
    for path in source_root.rglob("*"):
        if path.is_file():
            yield path


def build_plan(source_root: Path, project_root: Path, *, allow_local_config: bool = False) -> list[PlanItem]:
    plan: list[PlanItem] = []
    for src in iter_source_files(source_root):
        rel = src.relative_to(source_root).as_posix()
        if not is_allowed(rel, allow_local_config=allow_local_config):
            continue
        dst = project_root / rel
        action = "replace" if dst.exists() else "create"
        plan.append(PlanItem(src=src, dst=dst, rel=rel, action=action))
    return sorted(plan, key=lambda item: item.rel.lower())


def backup_existing_files(plan: list[PlanItem], project_root: Path) -> Path | None:
    existing = [item for item in plan if item.dst.exists()]
    if not existing:
        return None

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_root = project_root / "backups" / f"before_zip_apply_{ts}"
    backup_root.mkdir(parents=True, exist_ok=True)

    for item in existing:
        rel_path = Path(item.rel)
        backup_path = backup_root / rel_path
        backup_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(item.dst, backup_path)

    return backup_root


def apply_plan(plan: list[PlanItem]) -> None:
    for item in plan:
        item.dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(item.src, item.dst)


def delete_removed_source_files(
    source_root: Path,
    project_root: Path,
    plan: list[PlanItem],
    *,
    allow_local_config: bool = False,
) -> list[str]:
    """
    Optional cleanup: remove allowed files from the project if they are absent in the source ZIP.
    This is OFF by default because it is safer not to delete files automatically.
    """
    source_rels = {item.rel for item in plan}
    removed: list[str] = []

    for top in sorted(ALLOWED_TOP_LEVEL):
        root = project_root / top
        if not root.exists():
            continue
        for dst in root.rglob("*"):
            if not dst.is_file():
                continue
            rel = dst.relative_to(project_root).as_posix()
            if is_allowed(rel, allow_local_config=allow_local_config) and rel not in source_rels:
                dst.unlink()
                removed.append(rel)

    for root_file in sorted(ALLOWED_ROOT_FILES):
        dst = project_root / root_file
        if dst.exists() and is_allowed(root_file, allow_local_config=allow_local_config) and root_file not in source_rels:
            dst.unlink()
            removed.append(root_file)

    return removed


def print_plan(plan: list[PlanItem], skipped_count: int) -> None:
    creates = sum(1 for item in plan if item.action == "create")
    replaces = sum(1 for item in plan if item.action == "replace")

    print(f"Plan: {len(plan)} files will be applied ({creates} create, {replaces} replace).")
    print(f"Skipped unsafe/non-project files: {skipped_count}")

    for item in plan:
        marker = "+" if item.action == "create" else "~"
        print(f"  {marker} {item.rel}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Safely apply a clean project ZIP into the current Security Log Intelligence project."
    )
    parser.add_argument("zip_path", help="Path to clean project ZIP.")
    parser.add_argument(
        "--project-root",
        default=".",
        help="Project root to update. Default: current directory.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Only show what would be changed; do not copy files.",
    )
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Do not create backup of replaced files.",
    )
    parser.add_argument(
        "--allow-delete",
        action="store_true",
        help="Delete allowed project/source files that are absent from the ZIP. Off by default.",
    )
    parser.add_argument(
        "--allow-local-config",
        action="store_true",
        help="Allow ZIP to replace local environment config such as config/domain_controllers.json. Off by default.",
    )
    parser.add_argument("--precheck", action="store_true", help="Run compile precheck before applying.")
    parser.add_argument("--postcheck", action="store_true", help="Run compile postcheck after applying.")
    parser.add_argument("--run-tests", action="store_true", help="Run pytest after applying.")
    parser.add_argument("--show-denied-files", action="store_true", help="Print skipped ZIP files.")
    return parser.parse_args()


def _run_update_check(command: list[str], project_root: Path) -> dict[str, object]:
    try:
        proc = subprocess.run(command, cwd=project_root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300, check=False)
        return {"command": " ".join(command), "exit_code": proc.returncode, "output": proc.stdout[-4000:]}
    except (OSError, subprocess.SubprocessError) as exc:
        return {"command": " ".join(command), "exit_code": 999, "output": str(exc)}


def write_update_report(project_root: Path, *, zip_path: Path, plan: list[PlanItem], backup_root: Path | None, skipped_count: int, checks: list[dict[str, object]], denied_preview: list[str] | None = None) -> Path:
    report_dir = project_root / "data" / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    path = report_dir / f"update-report-{ts}.html"
    rows = "".join(f"<tr><td>{html.escape(item.action)}</td><td>{html.escape(item.rel)}</td></tr>" for item in plan)
    check_rows = "".join("<tr><td>{}</td><td>{}</td><td><pre>{}</pre></td></tr>".format(html.escape(str(c.get("command"))), html.escape(str(c.get("exit_code"))), html.escape(str(c.get("output") or ""))) for c in checks) or '<tr><td colspan="3">Проверки не запускались</td></tr>'
    denied = "".join(f"<li>{html.escape(item)}</li>" for item in (denied_preview or [])) or "<li>Не выводились</li>"
    body = """<!doctype html><html lang=\"ru\"><head><meta charset=\"utf-8\"><title>Отчет обновления</title><style>body{{font-family:Segoe UI,Arial,sans-serif;background:#eef3f7;color:#1f2937;padding:24px}}main{{max-width:1100px;margin:auto;background:white;border:1px solid #d8e0e8;border-radius:18px;padding:22px}}table{{width:100%;border-collapse:collapse}}td,th{{border:1px solid #d8e0e8;padding:8px;vertical-align:top}}pre{{white-space:pre-wrap;max-height:240px;overflow:auto}}</style></head><body><main><h1>Отчет обновления Security Log Intelligence</h1><p><b>ZIP:</b> {zip}</p><p><b>Backup:</b> {backup}</p><p><b>Пропущено unsafe/non-project:</b> {skipped}</p><h2>Файлы</h2><table><thead><tr><th>Действие</th><th>Файл</th></tr></thead><tbody>{rows}</tbody></table><h2>Проверки</h2><table><thead><tr><th>Команда</th><th>Код</th><th>Вывод</th></tr></thead><tbody>{checks}</tbody></table><h2>Пропущенные файлы</h2><ul>{denied}</ul></main></body></html>""".format(zip=html.escape(str(zip_path)), backup=html.escape(str(backup_root or 'не создавался')), skipped=skipped_count, rows=rows, checks=check_rows, denied=denied)
    path.write_text(body, encoding="utf-8")
    return path


def main() -> int:
    args = parse_args()

    zip_path = Path(args.zip_path).expanduser().resolve()
    project_root = Path(args.project_root).expanduser().resolve()

    if not zip_path.exists():
        print(f"ERROR: ZIP not found: {zip_path}", file=sys.stderr)
        return 2

    if not project_root.exists():
        print(f"ERROR: project root not found: {project_root}", file=sys.stderr)
        return 2

    if not zipfile.is_zipfile(zip_path):
        print(f"ERROR: not a valid ZIP file: {zip_path}", file=sys.stderr)
        return 2

    if not args.dry_run:
        print(
            "ERROR: direct mutation is disabled; use "
            "scripts/maintenance/apply_update.py",
            file=sys.stderr,
        )
        return 3

    try:
        snapshot = read_archive_snapshot(zip_path)
    except PackageError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="adlog_apply_") as tmp:
        tmp_dir = Path(tmp)

        with zipfile.ZipFile(io.BytesIO(snapshot)) as zf:
            unsafe = []
            for info in zf.infolist():
                if info.is_dir():
                    continue
                normalized = normalize_zip_name(info.filename)
                if normalized is None:
                    unsafe.append(info.filename)
            if unsafe:
                print("ERROR: ZIP contains unsafe paths:", file=sys.stderr)
                for name in unsafe[:20]:
                    print(f"  {name}", file=sys.stderr)
                return 2

            zf.extractall(tmp_dir)

        source_root = detect_archive_root(tmp_dir)
        all_files = [p for p in iter_source_files(source_root)]
        plan = build_plan(source_root, project_root, allow_local_config=args.allow_local_config)
        planned_rels = {item.rel for item in plan}
        skipped_count = 0
        for src in all_files:
            rel = src.relative_to(source_root).as_posix()
            if rel not in planned_rels:
                skipped_count += 1

        print(f"ZIP: {zip_path}")
        print(f"Source root inside ZIP: {source_root}")
        print(f"Project root: {project_root}")
        print_plan(plan, skipped_count)
        denied_preview: list[str] = []
        if args.show_denied_files:
            for src in all_files:
                rel = src.relative_to(source_root).as_posix()
                if rel not in planned_rels:
                    denied_preview.append(rel)
            for rel in denied_preview[:100]:
                print(f"  ! skipped {rel}")
        checks: list[dict[str, object]] = []
        if args.precheck:
            checks.append(_run_update_check([sys.executable, "-m", "compileall", "-q", "server", "sli_collect", "sli_agent", "scripts", "tests"], project_root))

        if not plan:
            print("Nothing to apply.")
            return 0

        if args.dry_run:
            print("Dry run: no files changed.")
            report = write_update_report(project_root, zip_path=zip_path, plan=plan, backup_root=None, skipped_count=skipped_count, checks=checks, denied_preview=denied_preview)
            print(f"Update report: {report}")
            return 0

        backup_root = None
        if not args.no_backup:
            backup_root = backup_existing_files(plan, project_root)
            if backup_root:
                print(f"Backup created: {backup_root}")
            else:
                print("Backup not needed: no existing files will be replaced.")

        apply_plan(plan)
        print(f"Applied {len(plan)} files.")

        if args.allow_delete:
            removed = delete_removed_source_files(
                source_root,
                project_root,
                plan,
                allow_local_config=args.allow_local_config,
            )
            print(f"Deleted {len(removed)} obsolete allowed source files.")
            for rel in removed:
                print(f"  - {rel}")

        print("\nDone.")
        print("Recommended checks:")
        print("  python -m compileall -q server sli_collect sli_agent scripts tests")
        print("  python -m pytest -q")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())

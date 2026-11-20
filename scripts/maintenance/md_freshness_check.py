from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from server.sli.ops.version import get_release_metadata

REQUIRED_MD = [
    "README.md",
    "README.ru.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "docs/ADMIN_GUIDE.md",
    "docs/USER_GUIDE.md",
]

CONTRACT_MARKERS: dict[str, list[str]] = {}

INSTRUCTION_SURFACE_ROOTS = {
    ".github",
    "docs/agents",
    "frontend",
}
NEAREST_INSTRUCTION_ROOTS = {
    "config",
    "docs",
    "frontend",
    "scripts",
    "server",
    "sli_collect",
    "sli_agent",
    "tests",
    "tools",
    "web",
}
CURRENT_AUTHORITY_LABELS = {"canonical", "active", "local-index"}
DOCUMENTATION_LABELS = CURRENT_AUTHORITY_LABELS | {
    "reference",
    "historical",
    "duplicate",
    "unknown",
}
STALE_INSTRUCTION_SIGNATURES = (
    "AI operating model transition is in progress",
    "Git-действия выполняются только через Docker",
    "допустим только через Docker-контур",
    "два одинаковых сбоя",
)

FOLDER_INDEX_MARKER = "<!-- project-folder-index:v1 -->"
FOLDER_INDEX_BOUNDARIES = {
    "archive",
    "artifacts",
    "audit_20260727",
    "backups",
    "data",
}
FOLDER_INDEX_SKIPPED_SUBTREES = {
    "frontend/artifacts",
    "frontend/web",
    "web/app/react",
}
FOLDER_INDEX_SKIPPED_NAMES = {
    ".agents",
    ".claude",
    ".git",
    ".hermes",
    ".mypy_cache",
    ".pnpm-store",
    ".pytest_cache",
    ".pytest_tmp",
    ".ruff_cache",
    ".superpowers",
    ".venv",
    ".worktrees",
    "__pycache__",
    "graphify-out",
    "node_modules",
    "talk",
    "test-results",
}
FOLDER_INDEX_TOP_LEVEL_TRANSIENT_NAMES = {".planning", ".testtmp", ".tmp"}
FOLDER_INDEX_TOP_LEVEL_TRANSIENT_PREFIXES = (".pytest-", ".tmp-")


def _folder_index_name_is_skipped(name: str, *, top_level: bool = False) -> bool:
    if name in FOLDER_INDEX_SKIPPED_NAMES or name.startswith(
        (".pytest-tmp-", ".sli-v4-")
    ):
        return True
    return top_level and (
        name in FOLDER_INDEX_TOP_LEVEL_TRANSIENT_NAMES
        or name.startswith(FOLDER_INDEX_TOP_LEVEL_TRANSIENT_PREFIXES)
    )


def instruction_markdown_paths(root: Path) -> list[str]:
    result = {
        path.name
        for path in (root / "AGENTS.md", root / "CLAUDE.md")
        if path.is_file()
    }
    def markdown_under(source_root: Path):
        pending = [source_root]
        while pending:
            directory = pending.pop()
            for path in directory.iterdir():
                if path.is_symlink():
                    continue
                rel = path.relative_to(root).as_posix()
                if path.is_dir():
                    if (not _folder_index_name_is_skipped(path.name)
                            and rel not in FOLDER_INDEX_SKIPPED_SUBTREES
                            and rel not in FOLDER_INDEX_BOUNDARIES):
                        pending.append(path)
                elif path.suffix.lower() == ".md":
                    yield path

    for source_name in sorted(INSTRUCTION_SURFACE_ROOTS):
        source_root = root / source_name
        if not source_root.is_dir():
            continue
        result.update(
            path.relative_to(root).as_posix()
            for path in markdown_under(source_root)
            if path.is_file()
        )
    for source_name in sorted(NEAREST_INSTRUCTION_ROOTS):
        source_root = root / source_name
        if not source_root.is_dir():
            continue
        result.update(
            path.relative_to(root).as_posix()
            for path in markdown_under(source_root)
            if path.name in {"AGENTS.md", "CLAUDE.md"}
        )
    return sorted(result)


def _normalise_instruction_text(value: str) -> str:
    return " ".join(value.split()).casefold()


def instruction_surface_items(root: Path) -> tuple[list[dict[str, Any]], list[str]]:
    items: list[dict[str, Any]] = []
    warnings: list[str] = []
    for rel in instruction_markdown_paths(root):
        path = root / rel
        exists = path.is_file()
        text = path.read_text(encoding="utf-8-sig", errors="replace") if exists else ""
        normalised = _normalise_instruction_text(text)
        stale_signatures = [
            signature
            for signature in STALE_INSTRUCTION_SIGNATURES
            if _normalise_instruction_text(signature) in normalised
        ]
        if not exists:
            warnings.append(f"missing active instruction: {rel}")
        elif not text.strip():
            warnings.append(f"empty active instruction: {rel}")
        for signature in stale_signatures:
            warnings.append(f"stale instruction contamination: {rel}: {signature}")
        items.append({
            "path": rel,
            "exists": exists,
            "status": (
                "ok"
                if exists and bool(text.strip()) and not stale_signatures
                else "warn"
            ),
            "size_bytes": path.stat().st_size if exists else 0,
            "stale_contamination_signatures": stale_signatures,
        })
    return items, warnings


def _documentation_index_path(cell: str) -> str | None:
    cell = cell.strip().strip("`")
    link = re.fullmatch(r"\[[^]]+\]\(([^)]+)\)", cell)
    if link:
        return link.group(1).strip()
    return cell or None


def documentation_index_items(root: Path) -> tuple[list[dict[str, Any]], list[str]]:
    index_path = root / "docs" / "DOCUMENTATION_INDEX.md"
    if not index_path.is_file():
        return [], []
    items: list[dict[str, Any]] = []
    warnings: list[str] = []
    text = index_path.read_text(encoding="utf-8-sig", errors="replace")
    for raw_line in text.splitlines():
        if not raw_line.lstrip().startswith("|"):
            continue
        cells = [cell.strip() for cell in raw_line.strip().strip("|").split("|")]
        if len(cells) < 2:
            continue
        label = cells[1].strip("`").casefold()
        if label not in DOCUMENTATION_LABELS:
            continue
        target = _documentation_index_path(cells[0])
        if target is None or "://" in target or target.startswith("#"):
            continue
        resolved = (index_path.parent / target).resolve()
        try:
            rel = resolved.relative_to(root.resolve()).as_posix()
        except ValueError:
            rel = target
            exists = False
        else:
            exists = resolved.exists()
        current_authority = label in CURRENT_AUTHORITY_LABELS
        item = {
            "path": rel,
            "label": label,
            "exists": exists,
            "current_authority": current_authority,
        }
        items.append(item)
        if current_authority and not exists:
            warnings.append(f"broken current authority path: {rel}")
        elif not exists:
            warnings.append(f"broken {label} documentation path: {rel}")
    return items, warnings


def folder_index_directories(root: Path) -> list[str]:
    """Return stable directories in which existing navigation can be inventoried.

    Optional ignored runtime/generated roots are excluded from local README
    coverage. Their operational boundary is described by the nearest tracked
    parent or root navigation index, rather than a placeholder inside a
    forbidden runtime root.
    """
    result: list[str] = []
    pending = sorted(
        (
            child
            for child in root.iterdir()
            if not _folder_index_name_is_skipped(child.name, top_level=True)
            and child.is_dir()
        ),
        key=lambda item: item.name,
        reverse=True,
    )
    while pending:
        directory = pending.pop()
        if not directory.is_dir():
            continue
        rel = directory.relative_to(root).as_posix()
        if rel in FOLDER_INDEX_SKIPPED_SUBTREES:
            continue
        if rel in FOLDER_INDEX_BOUNDARIES:
            continue
        result.append(rel)
        children = sorted(
            (
                child
                for child in directory.iterdir()
                if not _folder_index_name_is_skipped(child.name)
                and child.is_dir()
            ),
            key=lambda item: item.name,
            reverse=True,
        )
        pending.extend(children)
    return sorted(set(result))


def folder_index_items(root: Path) -> tuple[list[dict[str, Any]], list[str]]:
    items: list[dict[str, Any]] = []
    warnings: list[str] = []
    for rel in [".", *folder_index_directories(root)]:
        readme = root / "README.md" if rel == "." else root / rel / "README.md"
        display_path = "README.md" if rel == "." else f"{rel}/README.md"
        exists = readme.is_file()
        if not exists:
            continue
        text = readme.read_text(encoding="utf-8-sig", errors="replace") if exists else ""
        marker_present = FOLDER_INDEX_MARKER in text
        items.append({
            "directory": rel,
            "path": display_path,
            "exists": exists,
            "marker_present": marker_present,
            "status": "ok",
        })
    return items, warnings


def check_markdown_freshness(root: Path = PROJECT_ROOT) -> dict[str, Any]:
    started = time.monotonic()
    items: list[dict[str, Any]] = []
    warnings: list[str] = []
    for rel in REQUIRED_MD:
        path = root / rel
        exists = path.is_file()
        text = path.read_text(encoding="utf-8-sig", errors="replace") if exists else ""
        missing_markers = [
            marker for marker in CONTRACT_MARKERS.get(rel, []) if marker not in text
        ]
        if not exists:
            warnings.append(f"missing mandatory markdown: {rel}")
        elif not text.strip():
            warnings.append(f"empty mandatory markdown: {rel}")
        elif missing_markers:
            warnings.append(
                f"mandatory markdown contract is incomplete: {rel}: "
                f"missing {', '.join(missing_markers)}"
            )
        items.append({
            "path": rel,
            "exists": exists,
            "status": "ok" if exists and bool(text.strip()) and not missing_markers else "warn",
            "size_bytes": path.stat().st_size if exists else 0,
            "missing_contract_markers": missing_markers,
        })
    authority_items, authority_warnings = documentation_index_items(root)
    warnings.extend(authority_warnings)
    folder_indexes, folder_warnings = folder_index_items(root)
    warnings.extend(folder_warnings)
    instruction_items, instruction_warnings = instruction_surface_items(root)
    warnings.extend(instruction_warnings)
    instruction_surfaces = [item["path"] for item in instruction_items]
    return {
        "package_type": "MD_FRESHNESS_CHECK",
        "status": "failed" if warnings else "ok",
        "duration_ms": int((time.monotonic() - started) * 1000),
        "release_metadata": get_release_metadata(root),
        "mandatory_contract_count": len(REQUIRED_MD),
        "instruction_surface_count": len(instruction_surfaces),
        "instruction_surfaces": instruction_surfaces,
        "instruction_checked_count": len(instruction_items),
        "checked_markdown_count": len(items) + len(instruction_items),
        "instruction_items": instruction_items,
        "items": items,
        "documentation_index_items": authority_items,
        "folder_index_count": len(folder_indexes),
        "folder_indexes": folder_indexes,
        "warnings": warnings,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Check the canonical project Markdown set.")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = check_markdown_freshness()
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"Markdown freshness: {result['status']} ({result['duration_ms']} ms)")
        for warning in result.get("warnings") or []:
            print(f"- {warning}")
    return 0 if result["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())

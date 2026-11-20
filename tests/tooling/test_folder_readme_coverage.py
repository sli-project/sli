from __future__ import annotations

from pathlib import Path

import pytest

from scripts.maintenance.md_freshness_check import (
    FOLDER_INDEX_MARKER,
    check_markdown_freshness,
    folder_index_directories,
    folder_index_items,
)

ROOT = Path(__file__).resolve().parents[2]


def test_existing_navigation_readmes_are_inventoried(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# Project\n", encoding="utf-8")
    items, warnings = folder_index_items(tmp_path)
    assert items
    assert not warnings
    assert all(item["status"] == "ok" for item in items)
    assert items[0]["directory"] == "."
    assert items[0]["path"] == "README.md"


def test_folder_index_does_not_require_runtime_root_placeholders() -> None:
    directories = set(folder_index_directories(ROOT))
    assert "data" not in directories
    assert "artifacts" not in directories
    assert "web/app" in directories
    assert "web/app/react" not in directories
    assert "frontend/src/app" in directories


def test_new_top_level_source_directory_is_discovered(tmp_path: Path) -> None:
    (tmp_path / "new_capability").mkdir()
    assert folder_index_directories(tmp_path) == ["new_capability"]


def test_ignored_worktree_root_is_not_traversed(tmp_path: Path) -> None:
    (tmp_path / ".worktrees" / "stale" / "data").mkdir(parents=True)
    (tmp_path / ".claude" / "worktrees").mkdir(parents=True)
    (tmp_path / ".hermes" / "plans").mkdir(parents=True)
    (tmp_path / "talk" / "research").mkdir(parents=True)
    (tmp_path / "stable").mkdir()

    assert folder_index_directories(tmp_path) == ["stable"]


def test_transient_top_level_test_and_tool_roots_are_not_traversed(tmp_path: Path) -> None:
    for name in (".pytest-full-root", ".tmp", ".testtmp", ".planning"):
        (tmp_path / name).mkdir()
    (tmp_path / "stable").mkdir()

    assert folder_index_directories(tmp_path) == ["stable"]


def test_transient_root_names_remain_visible_when_nested_in_stable_source(
    tmp_path: Path,
) -> None:
    for name in (".planning", ".tmp-gpo-tests"):
        (tmp_path / "stable" / name).mkdir(parents=True)

    assert folder_index_directories(tmp_path) == [
        "stable", "stable/.planning", "stable/.tmp-gpo-tests",
    ]


@pytest.mark.parametrize("name", [".pytest-tmp-denied", ".tmp-gpo-tests", ".tmp-gpo-tests-final"])
def test_transient_test_root_is_not_traversed(
    tmp_path: Path,
    monkeypatch,
    name: str,
) -> None:
    blocked = tmp_path / name
    blocked.mkdir()
    (tmp_path / "stable").mkdir()
    original_iterdir = Path.iterdir

    def guarded_iterdir(self: Path):
        if self == blocked:
            raise PermissionError("transient test root is inaccessible")
        return original_iterdir(self)

    monkeypatch.setattr(Path, "iterdir", guarded_iterdir)

    assert folder_index_directories(tmp_path) == ["stable"]
    assert folder_index_items(tmp_path) == ([], [])


def test_full_freshness_gate_never_walks_inaccessible_worktrees(
    tmp_path: Path,
    monkeypatch,
) -> None:
    (tmp_path / ".worktrees" / "blocked").mkdir(parents=True)
    (tmp_path / ".worktrees" / "blocked" / "secret.md").write_text(
        "ignored",
        encoding="utf-8",
    )
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "active.md").write_text("active", encoding="utf-8")
    blocked = tmp_path / ".worktrees" / "blocked"
    original_iterdir = Path.iterdir
    original_rglob = Path.rglob

    def is_blocked(path: Path) -> bool:
        return path == blocked or blocked in path.parents

    def guarded_iterdir(self: Path):
        if is_blocked(self):
            raise PermissionError("ignored worktree is inaccessible")
        return original_iterdir(self)

    def guarded_rglob(self: Path, pattern: str):
        if is_blocked(self):
            raise PermissionError("ignored worktree is inaccessible")
        return original_rglob(self, pattern)

    monkeypatch.setattr(Path, "iterdir", guarded_iterdir)
    monkeypatch.setattr(Path, "rglob", guarded_rglob)

    result = check_markdown_freshness(tmp_path)
    assert result["instruction_checked_count"] == 0
    assert result["checked_markdown_count"] == result["mandatory_contract_count"]
    assert not any(".worktrees" in warning for warning in result["warnings"])


def test_missing_readmes_do_not_require_navigation_placeholders(tmp_path: Path) -> None:
    items, warnings = folder_index_items(tmp_path)
    assert items == []
    assert warnings == []


def test_marker_is_stable_and_machine_readable() -> None:
    assert FOLDER_INDEX_MARKER == "<!-- project-folder-index:v1 -->"

from __future__ import annotations

from scripts.maintenance import documentation_consolidation as module


def test_cleanup_is_explicit_and_never_overlaps_canonical_set() -> None:
    assert module.CANONICAL_PATHS
    assert module.LEGACY_PATHS
    assert module.CANONICAL_PATHS.isdisjoint(module.LEGACY_PATHS)
    assert all(path.endswith(".md") for path in module.LEGACY_PATHS)
    assert "docs/CURRENT_BASELINE.md" in module.CANONICAL_PATHS
    assert "docs/forgtp.md" in module.CANONICAL_PATHS
    assert "docs/CURRENT_BASELINE.md" not in module.LEGACY_PATHS


def test_cleanup_does_not_define_broad_glob_deletion() -> None:
    assert "*.md" not in module.LEGACY_PATHS
    assert "docs" not in module.LEGACY_PATHS
    assert "CHANGELOG.md" not in module.LEGACY_PATHS
    assert "PROJECT_RULES.md" not in module.LEGACY_PATHS
    assert "server/README.md" not in module.LEGACY_PATHS
    assert "scripts/README.md" not in module.LEGACY_PATHS


def test_plan_mode_never_removes_files(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(module, "ROOT", tmp_path)
    for rel in module.CANONICAL_PATHS:
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# Canonical document\n" + "x" * 80, encoding="utf-8")
    legacy = tmp_path / next(iter(module.LEGACY_PATHS))
    legacy.parent.mkdir(parents=True, exist_ok=True)
    legacy.write_text("legacy", encoding="utf-8")
    result = module.execute(apply=False)
    assert result["status"] == "ready"
    assert legacy.exists()
    assert result["separate_documentation_archive_created"] is False


def test_active_markdown_count_excludes_technical_backups(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(module, "ROOT", tmp_path)
    active = tmp_path / "docs" / "CURRENT_BASELINE.md"
    active.parent.mkdir(parents=True, exist_ok=True)
    active.write_text("active", encoding="utf-8")
    backup = tmp_path / "backups" / "before_zip_apply" / "docs" / "OLD.md"
    backup.parent.mkdir(parents=True, exist_ok=True)
    backup.write_text("backup", encoding="utf-8")
    assert module.active_markdown_paths() == ["docs/CURRENT_BASELINE.md"]


def test_folder_navigation_indexes_are_not_legacy_noise(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(module, "ROOT", tmp_path)
    readme = tmp_path / "server" / "README.md"
    readme.parent.mkdir(parents=True)
    readme.write_text(
        module.FOLDER_INDEX_MARKER + "\n# Server\n",
        encoding="utf-8",
    )
    paths = module.active_markdown_paths()
    assert module.folder_index_paths(paths) == {"server/README.md"}

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("relative", [
    "scripts/package_project.py",
    "scripts/apply_project_zip.py",
    "scripts/maintenance/release_check.py",
    "scripts/maintenance/baseline_snapshot.py",
    "scripts/maintenance/collect_diagnostics.py",
    "scripts/maintenance/current_baseline_gate.py",
    "scripts/maintenance/documentation_consolidation.py",
    "scripts/maintenance/export_dev_handoff.py",
    "scripts/maintenance/md_freshness_check.py",
])
def test_python_source_root_lists_cover_collection_package(relative: str) -> None:
    tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
    root_lists = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            strings = {
                item.value for item in node.elts
                if isinstance(item, ast.Constant) and isinstance(item.value, str)
            }
            if "server" in strings and strings & {"scripts", "tests", "tools"}:
                root_lists.append(strings)

    assert root_lists, "Expected a source root list or compileall command"
    assert all("sli_collect" in roots for roots in root_lists)


def test_release_check_scans_collection_runtime_artifacts_and_size(tmp_path: Path) -> None:
    from scripts.maintenance.release_check import (
        _quick_runtime_size_checks,
        _runtime_source_warnings,
    )

    package = tmp_path / "sli_collect"
    package.mkdir()
    (package / "collector.py").write_bytes(b"pass\n")
    (package / "runtime.log").write_bytes(b"synthetic log\n")

    warnings = _runtime_source_warnings(tmp_path)
    assert len(warnings) == 1
    assert "sli_collect/runtime.log" in warnings[0]
    _, sizes = _quick_runtime_size_checks(tmp_path)
    assert sizes["source_roots"]["sli_collect"]["bytes"] == 19


def test_source_package_and_update_cover_collection_source_only(tmp_path: Path) -> None:
    from scripts.apply_project_zip import is_allowed
    from scripts.package_project import iter_source_files, rel_posix

    package = tmp_path / "sli_collect"
    package.mkdir()
    for name in ("collector.py", "credentials.py", "credentials.txt", "runtime.log"):
        (package / name).write_text("synthetic\n", encoding="utf-8")

    names = {rel_posix(path, tmp_path) for path in iter_source_files(tmp_path)}
    assert names == {"sli_collect/collector.py", "sli_collect/credentials.py"}
    assert all(is_allowed(name) for name in names)
    assert not is_allowed("sli_collect/runtime.log")
    assert not is_allowed("sli_collect/__pycache__/collector.pyc")


def test_source_fingerprint_changes_with_collection_source(tmp_path: Path) -> None:
    from scripts.maintenance.current_baseline_gate import source_fingerprint

    package = tmp_path / "sli_collect"
    package.mkdir()
    source = package / "collector.py"
    source.write_text("pass\n", encoding="utf-8")
    before = source_fingerprint(tmp_path)
    source.write_text("raise RuntimeError\n", encoding="utf-8")

    assert source_fingerprint(tmp_path) != before


def test_sanitary_check_scans_collection_package(tmp_path: Path) -> None:
    from scripts.maintenance.github_sanitary_check import scan

    package = tmp_path / "sli_collect"
    package.mkdir()
    (package / "collector.py").write_text("pass\n", encoding="utf-8")
    assert scan(tmp_path)["status"] == "ok"
    (package / "runtime.log").write_text("synthetic log\n", encoding="utf-8")

    result = scan(tmp_path)
    assert result["status"] == "failed"
    assert any(
        item["type"] == "forbidden_extension" and item["path"] == "sli_collect/runtime.log"
        for item in result["findings"]
    )

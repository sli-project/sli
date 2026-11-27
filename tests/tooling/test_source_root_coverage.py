from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]




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

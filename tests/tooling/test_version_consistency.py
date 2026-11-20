from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _version(path: str) -> str:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))["version"]


def test_package_versions_are_equal_semver() -> None:
    root_version = _version("package.json")
    assert root_version == _version("frontend/package.json")
    assert re.fullmatch(r"\d+\.\d+\.\d+", root_version)


def test_changelog_has_unreleased_section() -> None:
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "## [Unreleased]" in text
    assert "Keep a Changelog" in text

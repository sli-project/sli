"""Plan 7.3: tests live in domain folders (tests/<domain>/), never in the tests/ root."""

from __future__ import annotations

import subprocess
from pathlib import Path

TESTS = Path(__file__).resolve().parents[1]


def _git_ignored(paths: list[Path]) -> set[Path]:
    """Owner-local files kept out of git on purpose are not part of the layout."""
    if not paths:
        return set()
    result = subprocess.run(
        ["git", "check-ignore", "--", *(path.relative_to(TESTS.parent).as_posix() for path in paths)],
        cwd=TESTS.parent, capture_output=True, text=True, check=False,
    )
    return {(TESTS.parent / line.strip()).resolve() for line in result.stdout.splitlines() if line.strip()}


def test_no_test_module_sits_in_the_tests_root() -> None:
    candidates = sorted(TESTS.glob("test_*.py"))
    ignored = _git_ignored(candidates)
    assert [path.name for path in candidates if path.resolve() not in ignored] == []

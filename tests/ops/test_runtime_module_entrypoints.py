"""Every ``server.sli`` module that runtime scripts start with ``python -m`` must start.

Splitting a module (plan 7.2b) can break ``-m`` execution in ways import-only
tests miss: when run as ``__main__`` the split-out parts import the module by
its real name and a second copy loads half-initialised. ``--help`` exercises
module import and argument parsing without doing any work.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
_LAUNCH = re.compile(
    r"""["']-m["']\s*,\s*["'](server\.sli\.[\w.]+)["']"""
    r"""|_MODULE\s*=\s*["'](server\.sli\.[\w.]+)["']"""
    r"""|-m\s+(server\.sli\.[\w.]+)"""
)


def _launched_modules() -> list[str]:
    found: set[str] = set()
    for folder in ("scripts", "server", "tools"):
        for path in (ROOT / folder).rglob("*"):
            if path.suffix not in {".py", ".ps1"} or "__pycache__" in path.parts:
                continue
            for match in _LAUNCH.finditer(path.read_text(encoding="utf-8", errors="replace")):
                found.add(next(group for group in match.groups() if group))
    return sorted(found)


def test_runtime_launch_list_is_not_empty() -> None:
    assert "server.sli.storage.warm_tier_incremental_copy_runtime" in _launched_modules()


@pytest.mark.parametrize("module", _launched_modules())
def test_module_starts_with_help(module: str) -> None:
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    completed = subprocess.run(
        [sys.executable, "-m", module, "--help"],
        cwd=ROOT, capture_output=True, text=True, timeout=120, env=env, check=False,
    )
    assert completed.returncode == 0, completed.stderr[-2000:]
    assert "usage" in completed.stdout.lower()

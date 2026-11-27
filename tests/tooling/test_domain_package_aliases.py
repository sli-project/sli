"""ADR 0014 / plan 7.1: the backend lives in domain packages under ``server/sli``.

``server/app`` is an empty legacy namespace: no module may come back there,
and nothing may import or launch ``server.app.*``.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]




def _source_files() -> list[Path]:
    files: list[Path] = []
    for folder in ("scripts", "server", "tools", "tests"):
        for suffix in ("*.py", "*.ps1", "*.cmd", "*.bat"):
            files.extend((ROOT / folder).rglob(suffix))
    return [path for path in files if "__pycache__" not in path.parts and path != Path(__file__)]


def test_nothing_imports_or_launches_the_legacy_namespace() -> None:
    """An import of ``server.app.<m>``, a ``-m server.app.<m>`` launch, or a script launching ``server/app/<m>.py``."""
    python_use = re.compile(
        r"""^\s*(?:from|import)\s+server\.app\.\w+"""
        r"""|["']-m["']\s*,\s*["']server\.app\.\w+["']|-m\s+server\.app\.\w+"""
        r"""|_MODULE\s*=\s*["']server\.app\.\w+["']""",
        re.M,
    )
    script_launch = re.compile(r"server[\\/]+app[\\/]+\w+\.py")
    offenders = []
    for path in _source_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        pattern = python_use if path.suffix == ".py" else script_launch
        if pattern.search(text):
            offenders.append(str(path.relative_to(ROOT)))
    assert offenders == []

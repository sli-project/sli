from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]



def test_tool_does_not_expose_collection_start_actions() -> None:
    text = (ROOT / "tools/adlog-tool.ps1").read_text(encoding="utf-8")
    for marker in (
        '"pg-current-start"',
        '"pg-controlled-scheduler-start"',
        '"pg-canary-scheduler-start"',
        '"pg-archive-worker-all"',
        "ADLOG_ENABLE_POSTGRES_COLLECTION",
    ):
        assert marker not in text

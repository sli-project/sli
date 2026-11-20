from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_server_control_detaches_windows_runtime_and_redirects_output() -> None:
    text = (ROOT / "scripts/maintenance/server_control.py").read_text(encoding="utf-8")
    assert "DETACHED_PROCESS" in text
    assert "CREATE_NEW_PROCESS_GROUP" in text
    assert 'child_env.setdefault("PYTHONUNBUFFERED", "1")' in text
    assert '"stdin": subprocess.DEVNULL' in text
    assert '"stdout": log_handle' in text
    assert '"stderr": subprocess.STDOUT' in text
    assert '"detached": True' in text
    assert 'server-runtime.log' in text

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
    assert "Команды запуска сбора намеренно отсутствуют" in text

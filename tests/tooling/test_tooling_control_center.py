import re
from pathlib import Path, PureWindowsPath


ROOT = Path(__file__).resolve().parents[2]


def test_control_center_has_russian_menu_and_current_safe_actions() -> None:
    text = (ROOT / "tools" / "adlog-tool.ps1").read_text(encoding="utf-8-sig")
    for label in (
        "SLI — единый центр управления",
        "Состояние системы",
        "Диагностика",
        "Интерфейс и документация",
        "Хранилище и PostgreSQL",
        "Передача и обслуживание проекта",
        "Локальные процессы",
    ):
        assert label in text
    for action in (
        '"status"',
        '"http-status"',
        '"diagnostics"',
        '"export-analyst"',
        '"repository-audit"',
        '"storage-health"',
        '"supervisor-status"',
    ):
        assert action in text


def test_control_center_does_not_offer_collection_or_legacy_sqlite_actions() -> None:
    text = (ROOT / "tools" / "adlog-tool.ps1").read_text(encoding="utf-8-sig")
    forbidden = (
        "pg-canary-scheduler-start",
        "pg-controlled-scheduler-start",
        "pg-archive-canary-scheduler-start",
        "pg-archive-worker-all",
        "legacy-sqlite-cleanup",
        "ADLOG_CANARY_MAX_EVENTS",
        "ADLOG_ENABLE_POSTGRES_COLLECTION",
    )
    assert all(marker not in text for marker in forbidden)


def test_cmd_launcher_enables_utf8_and_opens_only_control_center() -> None:
    text = (ROOT / "tools" / "ADLog-Toolkit.cmd").read_text(encoding="utf-8")
    assert "chcp 65001" in text
    assert "tools\\adlog-tool.ps1" in text


def test_control_center_forces_utf8_for_python_tools() -> None:
    text = (ROOT / "tools" / "adlog-tool.ps1").read_text(encoding="utf-8-sig")
    assert '$env:PYTHONUTF8 = "1"' in text
    assert '$env:PYTHONIOENCODING = "utf-8"' in text
    assert "[Console]::OutputEncoding" in text


def test_every_project_script_referenced_by_control_center_exists() -> None:
    text = (ROOT / "tools" / "adlog-tool.ps1").read_text(encoding="utf-8-sig")
    referenced = set(re.findall(r'"((?:scripts|tools)\\[^"]+\.(?:py|ps1|mjs|cmd))"', text))
    assert referenced
    missing = [
        path for path in sorted(referenced)
        if not ROOT.joinpath(*PureWindowsPath(path).parts).is_file()
    ]
    assert missing == []

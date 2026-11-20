from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
POWER_SHELL_TOOL = PROJECT_ROOT / "tools" / "sli-control-center.ps1"
LIFECYCLE_CONTRACT = PROJECT_ROOT / "scripts" / "maintenance" / "control_center_lifecycle.py"


def test_control_center_ui_exposes_russian_guarded_controls() -> None:
    source = POWER_SHELL_TOOL.read_text(encoding="utf-8-sig")
    button_labels = re.findall(r'<Button[^>]*Content="([^"]+)"', source)

    assert button_labels == [
        "Запустить проект",
        "Перезапустить проект",
        "Остановить проект",
        "Перезапустить выбранный обработчик",
        "Остановить выбранный обработчик",
        "Обновить состояние",
        "Сохранить обезличенный отчёт",
        "Копировать обезличенную сводку",
        "Открыть локальную инструкцию",
    ]
    assert 'Title="Центр управления SLI"' in source
    assert 'Text="Проект"' in source
    assert 'Text="Выбранный обработчик"' in source
    assert 'Text="Состояние и результат"' in source
    assert "$StatusBox.Text = $Result | ConvertTo-Json" not in source
    for former_caption in (
        "Check status",
        "Save redacted result",
        "Copy redacted summary",
        "Open local instructions",
        "Read-only local status",
    ):
        assert former_caption not in source


def test_control_center_human_visible_supervisor_wording_is_russian() -> None:
    source = POWER_SHELL_TOOL.read_text(encoding="utf-8-sig")
    human_visible_text = re.findall(
        r'(?:return|\$StatusBox\.Text\s*=|\$WorkerStatusText\.Text\s*=|\[System\.Windows\.MessageBox\]::Show\(\s*)\s*"([^"]+)"',
        source,
    )
    human_visible_text += re.findall(r'<[^>]+\b(?:Title|Content|Text)="([^"]+)"', source)

    assert all("supervisor" not in text.casefold() for text in human_visible_text)
    assert any("супервизор" in text.casefold() for text in human_visible_text)


def test_control_center_mutations_use_only_confirmed_lifecycle_contract() -> None:
    source = POWER_SHELL_TOOL.read_text(encoding="utf-8-sig")

    assert "control_center_lifecycle.py" in source
    assert '"--json"' in source
    assert '"--confirm"' in source
    assert "CONTROL-CENTER:project:$Action" in source
    assert "CONTROL-CENTER:worker:${Action}:${Worker}" in source
    assert "[System.Windows.MessageBox]::Show" in source
    assert "[System.Windows.MessageBoxButton]::YesNo" in source
    assert "WaitForExit($LifecycleTimeoutMilliseconds)" in source
    for prohibited_direct_control in (
        "server_control.py",
        "worker_supervisor",
        "taskkill",
        "stop-process",
        "schtasks",
        "start-process",
        "invoke-webrequest",
        "curl",
    ):
        assert prohibited_direct_control not in source.casefold()


def test_worker_selector_is_read_only_and_contract_derived() -> None:
    source = POWER_SHELL_TOOL.read_text(encoding="utf-8-sig")
    lifecycle_source = LIFECYCLE_CONTRACT.read_text(encoding="utf-8")

    assert '"managed-workers"' in lifecycle_source
    assert "managed_worker_names()" in lifecycle_source
    assert '"managed-workers"' in source
    assert "$WorkerPicker.ItemsSource = @($workers.workers)" in source
    assert "$WorkerPicker.SelectedItem" in source
    for retired_or_manual_name in ("computers_v6_source", "manual-worker", "collection"):
        assert retired_or_manual_name not in source


@pytest.mark.windows_only
def test_control_center_validate_only_parses_in_windows_powershell() -> None:
    completed = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(POWER_SHELL_TOOL),
            "-ValidateOnly",
        ],
        capture_output=True,
        text=True,
        encoding="mbcs",
        errors="replace",
        check=False,
    )

    assert completed.returncode == 0, completed.stderr

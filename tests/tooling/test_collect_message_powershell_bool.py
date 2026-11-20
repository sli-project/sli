from pathlib import Path

import pytest

from scripts.run_dc_log_pilot import append_powershell_bool_param


pytestmark = pytest.mark.windows


def test_collect_message_bool_false_uses_powershell_colon_literal():
    command: list[str] = []
    append_powershell_bool_param(command, "CollectMessage", False)
    assert command == ["-CollectMessage:$false"]


def test_collect_message_bool_true_uses_powershell_colon_literal():
    command: list[str] = []
    append_powershell_bool_param(command, "CollectMessage", True)
    assert command == ["-CollectMessage:$true"]


def test_collect_message_script_normalizes_external_string_booleans():
    script = Path("scripts/collect/Collect-DcEventsLastHour.ps1").read_text(encoding="utf-8")
    assert "[object]$CollectMessage" in script
    assert "function ConvertTo-BooleanFlag" in script
    assert "$normalized = $text.TrimStart('$').ToLowerInvariant()" in script
    assert '"false" { return $false }' in script
    assert '"0" { return $false }' in script


def test_collector_script_normalizes_csv_channels_from_native_processes():
    script = Path("scripts/collect/Collect-DcEventsLastHour.ps1").read_text(encoding="utf-8")
    assert "function ConvertTo-ChannelList" in script
    assert '$item -split ","' in script
    assert "$Channels = ConvertTo-ChannelList -Value $Channels" in script

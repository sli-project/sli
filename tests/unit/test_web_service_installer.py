"""Static safety guards; native synthetic behavior harness requires PowerShell."""
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts/ops/Install-SLIWebServer-Service.ps1'
HELPER = ROOT / 'scripts/ops/WebServer-ServiceSafety.ps1'


def test_installer_never_terminates_port_owners_directly():
    source = SCRIPT.read_text(encoding='utf-8-sig')
    assert 'Stop-Process' not in source
    assert 'Stop-OwnedSLIWebService -ProjectRoot $ProjectRoot' in source
    assert source.index('Stop-OwnedSLIWebService -ProjectRoot') < source.index('Disable-ScheduledTask')


def test_elevation_uses_typed_encoded_arguments():
    source = SCRIPT.read_text(encoding='utf-8-sig')
    assert 'New-SLIServiceElevationCommand -ScriptPath $PSCommandPath -BoundParameters $PSBoundParameters' in source
    assert '-EncodedCommand $encodedCommand' in source


def test_registration_and_state_failures_are_not_reported_as_success():
    source = SCRIPT.read_text(encoding='utf-8-sig')
    assert 'if ($LASTEXITCODE -ne 0)' in source
    assert '$registration.StartMode -ne $expectedStartMode' in source
    assert "$service.Status -ne 'Stopped'" in source
    assert "$service.Status -ne 'Running'" in source


def test_helper_uses_controller_and_fails_closed():
    assert HELPER.exists()
    source = HELPER.read_text(encoding='utf-8-sig')
    assert 'Stop-Process' not in source
    assert 'Stop-Service -Name SLIWebServer -ErrorAction Stop' in source
    assert 'Get-NetTCPConnection -ErrorAction Stop' in source
    assert 'CreationDate' in source
    assert 'ExecutablePath' in source
    assert 'PythonClass' in source


@pytest.mark.parametrize(('shell_name', 'edition', 'version'), [
    pytest.param('pwsh', 'Core', None, id='pwsh-core'),
    pytest.param('powershell.exe', 'Desktop', '5.1', id='windows-powershell-5.1'),
])
def test_synthetic_powershell_contract(shell_name, edition, version):
    if edition == 'Desktop' and os.name != 'nt':
        pytest.skip('Native Windows PowerShell 5.1 unavailable on this OS; not executed')
    shell = shutil.which(shell_name)
    if not shell:
        pytest.skip(f'{shell_name} unavailable; {edition} synthetic behavior not executed')
    # Do not silently count a pwsh alias as coverage of the actual 5.1 entrypoint.
    probe = subprocess.run([
        shell, '-NoProfile', '-NonInteractive', '-Command',
        ("[pscustomobject]@{Edition=$PSVersionTable.PSEdition; "
        "Version=('{0}.{1}' -f $PSVersionTable.PSVersion.Major, "
        "$PSVersionTable.PSVersion.Minor)} | ConvertTo-Json -Compress"),
    ], check=True, capture_output=True, text=True, timeout=30)
    identity = json.loads(probe.stdout.strip())
    assert identity['Edition'] == edition, (shell, identity)
    if version is not None:
        assert identity['Version'] == version, (shell, identity)
    subprocess.run([shell, '-NoProfile', '-NonInteractive', '-File',
                    str(ROOT / 'tests/unit/web_service_installer_synthetic.ps1')],
                   check=True, timeout=60)

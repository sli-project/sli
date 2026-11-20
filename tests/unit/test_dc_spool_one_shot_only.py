"""Static safety contract; no task registration or event collection is run."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_registration_is_an_unconditional_explanatory_failure():
    source = (ROOT / 'scripts/dc_client/Register-AdLogDcClientTask.ps1').read_text()
    assert '\nthrow "dc_client_one_shot_only:' in source
    for command in ('New-ScheduledTaskAction', 'New-ScheduledTaskTrigger',
                    'New-ScheduledTaskSettingsSet', 'Register-ScheduledTask'):
        assert command not in source
    assert 'durable ingestion acknowledgment' in source
    assert 'Existing scheduled tasks are not changed' in source


def test_manual_export_keeps_oldest_first_and_explicit_cursors():
    source = (ROOT / 'scripts/dc_client/Invoke-AdLogDcClient.ps1').read_text()
    assert 'Oldest = $true' in source
    assert 'EventRecordID > $AfterRecordId' in source
    assert '"oldest_batch"' in source
    assert '"newest_batch"' not in source
    assert 'Copy-Item -Path $outDir -Destination $target -Recurse -Force' in source

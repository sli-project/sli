"""Static contracts only: these tests never execute Windows provisioning."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / 'tools/lab'


def test_child_exit_guards_precede_ready_and_task_removal():
    source = (LAB / 'lab-01-domain.ps1').read_text('utf-8-sig')
    start = source.index('            & "$PSScriptRoot\\lab-02-populate.ps1"')
    second = source.index('            & "$PSScriptRoot\\lab-03-simulate.ps1"')
    marker = source.index("            'ready' | Set-Content")
    removal = source.index('            Unregister-ScheduledTask')
    assert '$global:LASTEXITCODE = 0' in source[:start].split("if (-not $ready)")[-1]
    assert "if ($LASTEXITCODE -ne 0) { throw 'lab_population_failed' }" in source[start:second]
    assert '$global:LASTEXITCODE = 0' in source[start:second]
    assert "if ($LASTEXITCODE -ne 0) { throw 'lab_simulation_install_failed' }" in source[second:marker]
    assert marker < removal
    invalidation = source.index('Remove-Item -LiteralPath (Assert-LabPath "$script:LabRoot\\domain-ready") -Force')
    assert invalidation < source.index("            $ready = $false") < start
    assert source.index("throw 'lab_dc_required'") < invalidation
    assert source.index('$null = Assert-LabDomain') < invalidation


def test_file_schema_is_strict_and_dispatch_is_explicit():
    source = (LAB / 'lab-verify.ps1').read_text('utf-8-sig')
    for name in ('file_read', 'file_modify', 'file_delete', 'file_rename', 'file_permissions',
                 'file_mass_read', 'file_mass_delete', 'file_off_hours', 'file_denied', 'file_fixture_create'):
        assert "'" + name + "'" in source
    for field in ('file_path', 'share', 'operation', 'destination_path', 'outcome', 'audit_required', 'local_time'):
        assert "'" + field + "'" in source
    assert '$keys.Count -ne $required.Count' in source
    assert 'lab_expected_file_path_invalid' in source
    assert 'lab_expected_file_time_invalid' in source
    assert 'lab_expected_file_invalid' in source
    assert 'if (Test-LabFileExpected $row)' in source
    dispatch = source.index('if (Test-LabFileExpected $row)', source.index('$table = @('))
    assert dispatch < source.index('Find-LabEvent $row', dispatch)
    assert "File = 'UNAVAILABLE'" in source[dispatch:]
    assert "lab_file_verification_unavailable" in source
    assert "$_.File -notin @('FOUND', '-')" in source


def test_expected_schema_uses_case_sensitive_keys_and_absolute_end_anchors():
    source = (LAB / 'lab-verify.ps1').read_text('utf-8-sig')
    validation = source[source.index('function Assert-LabExpected'):source.index('function Write-LabAuthenticationFailure')]
    assert '$keys -cnotcontains $_' in validation
    assert "unknown_operation|io_error_\\d+)\\z'" in validation
    assert "Сводка-01\\.csv)\\z'" in validation
    assert "(Z|[+-]\\d{2}:\\d{2})\\z'" in validation
    assert "^lab\\.(u\\d{3}|svc\\d{2})\\z|^LAB-[A-Za-z]+\\z'" in validation
    assert "^S-1-5-21-\\d+-\\d+-\\d+-\\d+\\z'" in validation


def test_native_fixture_is_available_without_running_provisioning():
    fixture = ROOT / 'tests/unit/lab_readiness_contract.ps1'
    source = fixture.read_text('utf-8-sig')
    for mode in ("'ad'", "'mixed'", "'file'", "'failed-file'"):
        assert mode in source
    assert "@('ad-unavailable', 'populate', 'simulate', 'throw', 'none')" in source
    assert '$global:LASTEXITCODE = 99' in source
    assert 'failed_bootstrap_claimed_ready' in source
    assert 'file_sent_to_ad_matcher' in source
    assert 'ad_comparison_skipped' in source


def test_python_contract_accepts_mixed_stream_and_rejects_malformed_files():
    import importlib.util
    import json
    import tempfile

    spec = importlib.util.spec_from_file_location('readiness_lab_model', LAB / 'lab_model.py')
    model = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(model)
    ad = {'schema_version': 1, 'run_id': '00000000-0000-4000-8000-000000000001',
              'scenario': 'workday_logon', 'started_at_utc': '2026-10-09T10:00:00Z',
              'ended_at_utc': '2026-10-09T10:00:01Z', 'actor': 'lab-system', 'target': 'lab.u003',
              'source_address': None, 'event_ids': [4624], 'executed': True, 'object_id': None,
              'target_sid': None, 'related_object_id': None, 'event_object_id': None}
    file_row = dict(ad, scenario='file_read', actor='DEMO\\lab.u003', event_ids=[4663, 5145],
                    file_path='\\\\LAB-DC01.demo.example\\LAB-Finance\\fixture.txt', share='LAB-Finance',
                    operation='read', destination_path=None, outcome='success', audit_required=True,
                    local_time='2026-10-09T13:00:01+03:00')
    rows = [ad] + [dict(file_row, scenario=scenario) for scenario in sorted(model.FILE_SCENARIOS)]
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / 'synthetic.jsonl'
        path.write_text('\n'.join(json.dumps(row) for row in rows), encoding='utf-8-sig')
        assert model.read_expected(path) == rows
    for changes in ({'actor': 'DEMO\\Administrator'}, {'share': 'SYSVOL'}, {'share': []},
                    {'operation': 'auditpol'}, {'audit_required': False}, {'audit_required': 1},
                    {'file_path': 'C:\\private.txt'}, {'destination_path': 'C:\\private.txt'},
                    {'outcome': 'success\n'}, {'file_path': file_row['file_path'] + '\n'},
                    {'destination_path': file_row['file_path'] + '\n'},
                    {'target': 'lab.u003\n', 'actor': 'DEMO\\lab.u003\n'}, {'target_sid': 'S-1-5-21-1-2-3-4\n'},
                    {'local_time': '2026-10-09T13:00:01+03:00\n'},
                    {'outcome': 'anything'}, {'local_time': '2026-10-09T13:00:01'},
                    {'event_ids': [4624]}, {'scenario': 'file_unknown'}, {'private': 'synthetic'}):
        try:
            model.validate_expected(dict(file_row, **changes))
        except ValueError:
            continue
        raise AssertionError(f'malformed file contract accepted: {changes}')
    wrong_case = dict(file_row)
    wrong_case['SHARE'] = wrong_case.pop('share')
    try:
        model.validate_expected(wrong_case)
    except ValueError:
        pass
    else:
        raise AssertionError('case-mutated key accepted')


def test_native_readiness_fixture():
    import os
    import subprocess

    if os.name != 'nt':
        import unittest
        raise unittest.SkipTest('native Windows PowerShell fixture was not run')
    result = subprocess.run(
        ['powershell.exe', '-NoProfile', '-NonInteractive', '-File',
         str(ROOT / 'tests/unit/lab_readiness_contract.ps1')],
        capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'lab_readiness_contract_passed' in result.stdout
    assert 'lab_bootstrap_exit_contract_passed' in result.stdout


# Standard-library runner keeps this bounded suite independent of repository startup.
if __name__ == '__main__':
    import unittest

    suite = unittest.TestSuite(unittest.FunctionTestCase(test) for name, test in list(globals().items())
                               if name.startswith('test_'))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(not result.wasSuccessful())

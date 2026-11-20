"""Exercise retained CLI dispatch without source contact or subprocesses."""
import json
import sys

import pytest

from scripts.maintenance import stage9_radius_field_quality_audit as quality
from scripts.maintenance import stage9_radius_time_aligned_preflight as aligned


@pytest.fixture(params=[quality, aligned], ids=['quality', 'aligned'])
def cli(request, monkeypatch):
    module = request.param
    def forbidden(*args, **kwargs):
        pytest.fail('source contact or subprocess must not occur')
    monkeypatch.setattr(module.subprocess, 'Popen', forbidden)
    monkeypatch.setattr(module, 'run_internal', forbidden)
    monkeypatch.setattr(module, 'load_plan', lambda: {'plan_id': 'synthetic'})
    monkeypatch.setattr(module, 'validate_plan', lambda plan: {'limits': {}, 'status': 'validated_only'})
    return module


def test_validation_dispatch_has_no_source_contact(cli, monkeypatch, capsys):
    argv = ['probe'] + (['--validate-only'] if cli is aligned else [])
    monkeypatch.setattr(sys, 'argv', argv)
    assert cli.main() == 0
    assert json.loads(capsys.readouterr().out)['status'] == 'validated_only'


def test_internal_dispatch_does_not_load_external_plan(cli, monkeypatch, capsys):
    monkeypatch.setattr(sys, 'argv', ['probe', '--internal'])
    monkeypatch.setattr(cli, 'load_plan', lambda: pytest.fail('external dispatch'))
    monkeypatch.setattr(cli, 'run_internal', lambda: {'synthetic_internal': True})
    assert cli.main() == 0
    assert json.loads(capsys.readouterr().out) == {'synthetic_internal': True}


def test_internal_failure_keeps_sanitized_exit_contract(cli, monkeypatch, capsys):
    def failure():
        raise RuntimeError('private synthetic detail')
    monkeypatch.setattr(sys, 'argv', ['probe', '--internal'])
    monkeypatch.setattr(cli, 'run_internal', failure)
    assert cli.main() == (2 if cli is quality else 1)
    output = capsys.readouterr().out
    assert json.loads(output)['error_type'] == 'RuntimeError'
    assert 'private synthetic detail' not in output


def test_execute_without_confirmation_cannot_spawn(cli, monkeypatch, tmp_path):
    monkeypatch.setattr(cli, 'ROOT', tmp_path)
    monkeypatch.setattr(sys, 'argv', ['probe', '--execute', '--output', str(tmp_path / 'artifacts/result.json')])
    with pytest.raises(PermissionError, match='confirmation'):
        cli.main()


@pytest.mark.parametrize('args', [[], ['--validate-only', '--execute']])
def test_aligned_requires_exactly_one_public_mode(monkeypatch, args):
    monkeypatch.setattr(sys, 'argv', ['probe', *args])
    with pytest.raises(aligned.RadiusTimeAlignedPlanError, match='choose_exactly_one_mode'):
        aligned.main()

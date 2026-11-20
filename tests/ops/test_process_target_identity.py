"""Synthetic ownership fixtures; never inspect or terminate real processes."""
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.maintenance import ad_snapshot_runtime_control as control


@pytest.mark.parametrize('command', [
    'python /foreign/ad_context_snapshot_worker.py',
    "python '/owned/ad_context_snapshot_worker.py'",
    'python ad_context_snapshot_worker.py',
    'python -c "pass" /owned/ad_context_snapshot_worker.py',
    'echo /owned/ad_context_snapshot_worker.py',
    'python /foreign/runner.py /owned/ad_context_snapshot_worker.py',
    'python /owned/../owned/ad_context_snapshot_worker.py',
    'python " /owned/ad_context_snapshot_worker.py"',
    'python "/owned/ad_context_snapshot_worker.py',
])
def test_only_actual_absolute_script_operand_matches(command):
    assert not control._has_exact_script(command, Path('/owned/ad_context_snapshot_worker.py'))


@pytest.mark.parametrize('command', [
    'python /owned/ad_context_snapshot_worker.py',
    '"C:\\Python\\python.exe" -u "C:\\owned\\worker.py"',
])
def test_exact_absolute_python_operand_matches(command):
    path = Path('C:/owned/worker.py') if 'C:' in command else Path('/owned/ad_context_snapshot_worker.py')
    assert control._has_exact_script(command, path)


def test_snapshot_captures_creation_identity():
    result = control._snapshot([{'pid': 42, 'parent_pid': 0,
        'command_line': f'python {control.V5}', 'creation_time': '2026-10-01T00:00:00Z'}])
    assert result['legacy_target_identities'] == {42: {'creation_time': '2026-10-01T00:00:00Z', 'root_name': 'computers_v5_snapshot'}}


@pytest.mark.parametrize('creation,command', [
    ('2026-10-02T00:00:00Z', None),
    ('', None),
    ('2026-10-01T00:00:00Z', 'python /foreign/computers_report_v5_snapshot_worker.py'),
])
def test_revalidation_rejects_reused_or_foreign_target(monkeypatch, creation, command):
    monkeypatch.setattr(control, 'inventory_processes', lambda: {'complete': True, 'processes': [
        {'pid': 42, 'parent_pid': 0, 'command_line': command or f'python {control.V5}', 'creation_time': creation}]})
    with pytest.raises(RuntimeError, match='target_identity'):
        control._revalidate_target(42, {'creation_time': '2026-10-01T00:00:00Z', 'root_name': 'computers_v5_snapshot'})


def test_revalidation_accepts_same_target(monkeypatch):
    monkeypatch.setattr(control, 'inventory_processes', lambda: {'complete': True, 'processes': [
        {'pid': 42, 'parent_pid': 0, 'command_line': f'python {control.V5}', 'creation_time': 'stamp'}]})
    control._revalidate_target(42, {'creation_time': 'stamp', 'root_name': 'computers_v5_snapshot'})


def test_cim_inventory_retains_creation_date(monkeypatch):
    monkeypatch.setattr(control.os, 'name', 'nt')
    monkeypatch.setattr(control.subprocess, 'run', lambda command, **kwargs: SimpleNamespace(returncode=0,
        stdout='{"ProcessId":42,"ParentProcessId":1,"CommandLine":"python x","CreationDate":"stamp"}'))
    assert control.inventory_processes()['processes'][0]['creation_time'] == 'stamp'


@pytest.mark.parametrize('observed', [
    {'complete': False, 'processes': []},
    {'complete': True, 'processes': []},
])
def test_revalidation_refuses_incomplete_or_vanished_inventory(monkeypatch, observed):
    monkeypatch.setattr(control, 'inventory_processes', lambda: observed)
    with pytest.raises(RuntimeError, match='target_identity|process_inventory_incomplete'):
        control._revalidate_target(42, {'creation_time': 'stamp', 'root_name': 'computers_v5_snapshot'})


def test_foreign_same_basename_never_enters_legacy_target_tree():
    rows = [{'pid': 42, 'parent_pid': 0, 'creation_time': 'stamp',
             'command_line': f'python /foreign/{control.V5.name}'},
            {'pid': 43, 'parent_pid': 42, 'creation_time': 'child',
             'command_line': 'helper.exe'}]
    snapshot = control._snapshot(rows)
    assert snapshot['legacy_target_root_pids'] == []
    assert snapshot['legacy_target_tree_pids'] == []


@pytest.mark.parametrize('command,path', [
    ('python "C:/O\'Brien/worker.py"', "C:/O'Brien/worker.py"),
    ('python /owned/worker.py --name "O\'Brien"', '/owned/worker.py'),
])
def test_double_quoted_literal_apostrophes_are_not_quote_delimiters(command, path):
    assert control._has_exact_script(command, Path(path))

"""Synthetic lifecycle tests: no Docker, PostgreSQL, or PowerShell execution."""
import ast
import json
from pathlib import Path
import subprocess
import types

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def lifecycle(monkeypatch):
    path = ROOT / 'scripts/maintenance/storage_capacity_profile_disposable_acceptance.py'
    tree = ast.parse(path.read_text(encoding='utf-8'))
    # Exercise the actual lifecycle functions without loading database runtime dependencies.
    tree.body = [node for node in tree.body if not (
        isinstance(node, ast.ImportFrom) and (node.module or '').startswith('server.')
    ) and not isinstance(node, ast.If)]
    module = types.ModuleType('disposable_lifecycle')
    module.__file__ = str(path)
    exec(compile(tree, str(path), 'exec'), module.__dict__)
    monkeypatch.setattr(module, '_bootstrap', lambda dsn: None)
    monkeypatch.setattr(module, '_accept', lambda dsn: {'accepted': True})
    module.redact_dsn = lambda dsn: 'redacted'
    conninfo = types.ModuleType('psycopg.conninfo')
    conninfo.make_conninfo = lambda **kwargs: 'synthetic-dsn'
    monkeypatch.setitem(__import__('sys').modules, 'psycopg.conninfo', conninfo)
    class Connection:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def execute(self, *args): pass
    monkeypatch.setattr(module, '_connect', lambda dsn: Connection())
    return module


class Docker:
    def __init__(self, collision=None, fail=None):
        self.resources = {}
        self.calls = []
        self.collision = collision
        self.fail = fail

    def __call__(self, *args, check=True):
        self.calls.append(args)
        code, out = 0, ''
        if args[:2] in [('container', 'inspect'), ('volume', 'inspect')]:
            kind, _, name = args
            resource = self.resources.get((kind, name))
            if resource is None and self.collision == kind:
                resource = {'Id': 'foreign-id', 'Name': name, 'Labels': {}, 'Config': {'Labels': {}}}
            if resource is None:
                code = 1
            else:
                out = json.dumps([resource])
        elif args[:2] == ('volume', 'create') or args[0] == 'run':
            kind = 'volume' if args[0] == 'volume' else 'container'
            name = args[-1] if kind == 'volume' else args[args.index('--name') + 1]
            labels = dict(arg.split('=', 1) for i, arg in enumerate(args) if i and args[i-1] == '--label')
            if self.fail == 'volume-race' and kind == 'volume':
                labels = {}
            self.resources[kind, name] = {'Id': 'owned-id', 'Name': name, 'Labels': labels, 'Config': {'Labels': labels}}
            if self.fail == kind:
                code = 1
        elif args[0] == 'port':
            out = '127.0.0.1:54321'
        elif args[0] == 'rm' or args[:2] == ('volume', 'rm'):
            kind = 'container' if args[0] == 'rm' else 'volume'
            if self.fail == 'remove':
                code = 1
            else:
                for key, resource in list(self.resources.items()):
                    if key[0] == kind and args[-1] in (key[1], resource['Id']):
                        del self.resources[key]
        else:
            raise AssertionError(args)
        result = subprocess.CompletedProcess(args, code, out, 'synthetic failure' if code else '')
        if check and code:
            raise RuntimeError('synthetic docker failure')
        return result

    @property
    def removals(self):
        return [a for a in self.calls if a[0] == 'rm' or a[:2] == ('volume', 'rm')]


@pytest.mark.parametrize('kind', ['container', 'volume'])
def test_collision_preserves_existing_resource(lifecycle, monkeypatch, kind):
    docker = Docker(collision=kind)
    monkeypatch.setattr(lifecycle, '_docker', docker)
    with pytest.raises(RuntimeError):
        lifecycle.run()
    assert docker.removals == []


def test_idempotent_volume_create_does_not_adopt_racing_volume(lifecycle, monkeypatch):
    docker = Docker(fail='volume-race')
    monkeypatch.setattr(lifecycle, '_docker', docker)
    with pytest.raises(RuntimeError):
        lifecycle.run()
    assert docker.removals == []
    assert not any(a[0] == 'run' for a in docker.calls)


@pytest.mark.parametrize('kind', ['volume', 'container'])
def test_partial_creation_cleans_only_run_owned_resources(lifecycle, monkeypatch, kind):
    docker = Docker(fail=kind)
    monkeypatch.setattr(lifecycle, '_docker', docker)
    with pytest.raises(RuntimeError):
        lifecycle.run()
    assert docker.resources == {}
    assert len(docker.removals) == (1 if kind == 'volume' else 2)


def test_cleanup_failure_cannot_report_pass(lifecycle, monkeypatch):
    docker = Docker(fail='remove')
    monkeypatch.setattr(lifecycle, '_docker', docker)
    with pytest.raises(RuntimeError):
        lifecycle.run()
    assert docker.resources


def test_success_cleans_owned_cluster(lifecycle, monkeypatch):
    docker = Docker()
    monkeypatch.setattr(lifecycle, '_docker', docker)
    result = lifecycle.run()
    assert result['status'] == 'passed'
    assert result['disposable_cluster_removed'] is True
    assert docker.resources == {}


@pytest.mark.parametrize('kind', ['container', 'volume'])
def test_changed_owner_is_preserved_at_cleanup(lifecycle, monkeypatch, kind):
    docker = Docker()
    monkeypatch.setattr(lifecycle, '_docker', docker)
    def accept(dsn):
        for key, resource in docker.resources.items():
            if key[0] == kind:
                resource['Labels'].clear()
        return {}
    monkeypatch.setattr(lifecycle, '_accept', accept)
    with pytest.raises(RuntimeError, match='cleanup incomplete'):
        lifecycle.run()
    assert any(key[0] == kind for key in docker.resources)
    assert not any((a[0] == 'rm' if kind == 'container' else a[:2] == ('volume', 'rm')) for a in docker.removals)


def test_inspection_failure_preserves_uncertain_resources(lifecycle, monkeypatch):
    docker = Docker()
    monkeypatch.setattr(lifecycle, '_docker', docker)
    def accept(dsn):
        def unavailable(*args, **kwargs):
            if 'inspect' in args:
                raise RuntimeError('daemon unavailable')
            return docker(*args, **kwargs)
        monkeypatch.setattr(lifecycle, '_docker', unavailable)
        return {}
    monkeypatch.setattr(lifecycle, '_accept', accept)
    with pytest.raises(RuntimeError, match='cleanup incomplete'):
        lifecycle.run()
    assert len(docker.resources) == 2
    assert docker.removals == []


def test_container_removal_uses_verified_id(lifecycle, monkeypatch):
    docker = Docker()
    monkeypatch.setattr(lifecycle, '_docker', docker)
    lifecycle.run()
    assert ('rm', '--force', 'owned-id') in docker.removals


def test_bootstrap_failure_still_cleans_owned_resources(lifecycle, monkeypatch):
    docker = Docker()
    monkeypatch.setattr(lifecycle, '_docker', docker)
    def fail(dsn):
        raise RuntimeError('synthetic bootstrap failure')
    monkeypatch.setattr(lifecycle, '_bootstrap', fail)
    with pytest.raises(RuntimeError, match='bootstrap failure'):
        lifecycle.run()
    assert not docker.resources


@pytest.mark.parametrize('kind', ['container', 'volume'])
def test_timeout_after_creation_recovers_labeled_resources(lifecycle, monkeypatch, kind):
    docker = Docker()
    def timeout(*args, **kwargs):
        result = docker(*args, **kwargs)
        if (kind == 'container' and args[0] == 'run') or (kind == 'volume' and args[:2] == ('volume', 'create')):
            raise subprocess.TimeoutExpired('docker', 30)
        return result
    monkeypatch.setattr(lifecycle, '_docker', timeout)
    with pytest.raises(subprocess.TimeoutExpired):
        lifecycle.run()
    assert not docker.resources


def test_creation_failure_before_resource_exists_reports_uncertainty(lifecycle, monkeypatch):
    docker = Docker()
    def fail_create(*args, **kwargs):
        if args[:2] == ('volume', 'create'):
            raise RuntimeError('create rejected')
        return docker(*args, **kwargs)
    monkeypatch.setattr(lifecycle, '_docker', fail_create)
    with pytest.raises(RuntimeError, match='cleanup incomplete'):
        lifecycle.run()
    assert docker.removals == []

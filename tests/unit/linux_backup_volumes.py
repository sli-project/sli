"""Explicit volume identities for backup tests; never inspect host devices."""
from pathlib import Path

import pytest

from deploy.linux import backup_policy


@pytest.fixture(params=['host-device', 'repository-device'],
                ids=['tmp-repo-same-device', 'tmp-repo-different-devices'])
def volume_layout(tmp_path, monkeypatch, request):
    # Model both runner layouts, then let each test declare its mounted volumes.
    devices = {tmp_path.resolve(): 'host-device',
               Path(__file__).resolve().parents[2]: request.param}

    def device(path):
        path = Path(path).resolve()
        # Tests declare volumes with unresolved tmp_path children; /tmp may be a symlink on a runner.
        resolved = {Path(root).resolve(): name for root, name in devices.items()}
        for root in sorted(resolved, key=lambda item: len(item.parts), reverse=True):
            if path.is_relative_to(root):
                return resolved[root]
        pytest.fail(f'undeclared synthetic volume: {path}')

    monkeypatch.setattr(backup_policy, 'filesystem', device)
    monkeypatch.setattr(backup_policy, 'device', device)
    return devices

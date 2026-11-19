"""Bounded, allowlisted PostgreSQL diagnostics, never server text or values."""
# ruff: noqa: F811 -- imported pytest fixtures are intentionally named as parameters
from __future__ import annotations

import json
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from deploy.linux import backup
from deploy.linux import backup_restore_check as drill
from tests.unit.test_linux_backup import COUNTS, successful
from tests.unit.test_linux_backup_capacity import (
    private_postgres,  # noqa: F401 -- shared fixture
)

pytestmark = pytest.mark.posix_only

# Synthetic adversarial input is assembled only at runtime. It is never an
# actual connection or a credential-bearing URI embedded in repository source.
SYNTHETIC_CREDENTIAL_URI = "postgresql" + "://user:private-password@private-host/db"


CHECK_ERROR = ('pg_restore: error: COPY failed for table "semantic_qw_signals": ERROR: '
               'new row for relation "semantic_qw_signals" violates check constraint '
               '"semantic_qw_acl_identity_v265"\n'
               'DETAIL: Failing row contains (private-row-value, password=private-password).\n')


@pytest.mark.parametrize("stderr,expected", [
    (CHECK_ERROR, {"pg_reason": "check_constraint_violation", "pg_table": "semantic_qw_signals",
                   "pg_constraint": "semantic_qw_acl_identity_v265"}),
    (CHECK_ERROR.replace('semantic_qw_acl_identity_v265', 'password_v2_qw_identity'),
     {"pg_reason": "check_constraint_violation", "pg_table": "semantic_qw_signals",
      "pg_constraint": "password_v2_qw_identity"}),
    (CHECK_ERROR.replace('semantic_qw_signals', 'private_table_value'),
     {"pg_reason": "check_constraint_violation"}),
    (('ERROR: invalid input syntax for type integer: "private-row-value"\n'
     f'DETAIL: {SYNTHETIC_CREDENTIAL_URI}\n'), {"pg_reason": "unclassified"}),
    ('ERROR: password authentication failed for user "private-user"\n', {"pg_reason": "authentication_failed"}),
    ('ERROR: violates check constraint "password=private-password"\n', {"pg_reason": "unclassified"}),
    (('ERROR: private-row-value password=private-password\n'
     'DETAIL: new row for relation "semantic_qw_signals" violates check constraint '
     '"semantic_qw_acl_identity_v265"\n'), {"pg_reason": "unclassified"}),
    (('ERROR: new row for relation "semantic_qw_signals" violates check constraint '
     '"semantic_qw_acl_identity_v265" private-row-value\n'), {"pg_reason": "unclassified"}),
    ('ERROR: ' + 'private-row-value' * 10000, {"pg_reason": "unclassified"}),
    (f'ERROR: could not connect: {SYNTHETIC_CREDENTIAL_URI}', {"pg_reason": "unclassified"}),
    ('', {"pg_reason": "unclassified"}),
], ids=["acl", "password", "unknown-object", "row-value", "authentication", "secret-object",
        "detail-only", "trailing-value", "oversized", "dsn", "empty"])
def test_pg_failure_classification_never_copies_server_text(stderr, expected):
    diagnostic = backup.pg_failure_reason(stderr.encode())
    assert diagnostic == expected
    assert SYNTHETIC_CREDENTIAL_URI not in json.dumps(diagnostic)
    assert "private-password" not in json.dumps(diagnostic)


def test_pg_tool_captures_stderr_privately_and_exposes_only_safe_fields(tmp_path, monkeypatch, capsys):
    def run(arguments, **kwargs):
        assert kwargs['stdout'] == backup.subprocess.DEVNULL
        kwargs['stderr'].write(CHECK_ERROR.encode())
        return SimpleNamespace(returncode=1)

    monkeypatch.setattr(backup.subprocess, 'run', run)
    with pytest.raises(backup.BackupError) as caught:
        backup.pg_tool(['pg_restore', '--jobs=2'], tmp_path / 'unused')
    diagnostic = backup.failure_diagnostic(caught.value, 'restore')
    assert diagnostic == {"error_code": "linux_backup_pg_tool_failed", "step": "restore", "returncode": 1,
                          "pg_reason": "check_constraint_violation", "pg_table": "semantic_qw_signals",
                          "pg_constraint": "semantic_qw_acl_identity_v265"}
    backup.report_failure(caught.value, 'restore')
    assert 'private-' not in capsys.readouterr().err
    assert 'private-' not in repr(caught.value)


@pytest.mark.parametrize('light', [False, True])
def test_pg_failure_receipt_is_safe_and_remains_failed(tmp_path, monkeypatch, light, capsys, private_postgres):
    newest = successful(tmp_path, '20261002T010000.000000Z')
    monkeypatch.setattr(backup, 'pg_passfile', lambda: nullcontext(Path('unused')))
    from tests.unit.test_linux_backup_capacity import prepare_capacity

    admin = prepare_capacity(tmp_path, newest, monkeypatch)
    queries = admin.queries
    monkeypatch.setattr(backup, 'pg_connect', lambda *a, **kw: nullcontext(admin))
    monkeypatch.setattr(backup, 'row_counts', lambda *_: COUNTS)

    def fail(*args, **kwargs):
        error = backup.BackupError('linux_backup_pg_tool_failed', returncode=1)
        error.pg_diagnostic = backup.pg_failure_reason(CHECK_ERROR.encode())
        raise error

    monkeypatch.setattr(backup, 'pg_tool', fail)
    monkeypatch.setattr(drill, 'integrity_check', fail)
    operation = drill.light_check if light else drill.restore_check
    with pytest.raises(backup.BackupError) as caught:
        operation(tmp_path, selected=newest)
    receipt = json.loads((tmp_path / 'restore_check.json').read_text())
    assert receipt['status'] == 'failed'
    assert receipt['diagnostic']['pg_constraint'] == 'semantic_qw_acl_identity_v265'
    assert receipt['diagnostic']['pg_reason'] == 'check_constraint_violation'
    assert 'private-' not in json.dumps(receipt)
    assert 'completed_at_utc' in receipt
    if not light:
        assert private_postgres.commands[-1][-1] == 'stop'
        assert private_postgres.queries == ['CREATE DATABASE sli_check TEMPLATE template0']
    assert not any(query.startswith(('CREATE', 'DROP')) for query in queries)
    monkeypatch.setattr(drill, 'restore_check', lambda *_: (_ for _ in ()).throw(caught.value))
    monkeypatch.setattr(backup, 'backup_root', lambda: tmp_path)
    assert drill.main() == 1
    assert 'private-' not in capsys.readouterr().err
    with pytest.raises(RuntimeError, match='update_fresh_daily_backup_required'):
        drill.verified_daily_backup(tmp_path)


def test_restore_and_cleanup_failure_preserve_original_safe_diagnostic(tmp_path, monkeypatch, private_postgres):
    newest = successful(tmp_path, '20261002T010000.000000Z')
    monkeypatch.setattr(backup, 'pg_passfile', lambda: nullcontext(Path('unused')))
    from tests.unit.test_linux_backup_capacity import prepare_capacity

    admin = prepare_capacity(tmp_path, newest, monkeypatch)
    queries = admin.queries
    command = drill.restore_sandbox.command
    original = backup.BackupError('linux_backup_pg_tool_failed', returncode=1)
    original.pg_diagnostic = backup.pg_failure_reason(CHECK_ERROR.encode())

    def command_with_cleanup_failure(args, **kwargs):
        if args[-1] == 'stop':
            private_postgres.commands.append(args)
            raise RuntimeError('private-cleanup-value password=private-password')
        return command(args, **kwargs)

    monkeypatch.setattr(drill.restore_sandbox, 'command', command_with_cleanup_failure)
    monkeypatch.setattr(backup, 'pg_connect', lambda *a, **kw: nullcontext(admin))

    def fail(*args, **kwargs):
        raise original

    monkeypatch.setattr(backup, 'pg_tool', fail)
    with pytest.raises(backup.BackupError) as caught:
        drill.restore_check(tmp_path, selected=newest)
    assert caught.value is original
    receipt = json.loads((tmp_path / 'restore_check.json').read_text())
    assert receipt['status'] == 'failed'
    assert receipt['diagnostic']['pg_constraint'] == 'semantic_qw_acl_identity_v265'
    assert receipt['cleanup_diagnostic'] == {'error_code': 'linux_backup_restore_sandbox_failed',
                                             'step': 'restore_check_cleanup'}
    assert 'private-' not in json.dumps(receipt)
    stop = private_postgres.commands[-1]
    assert stop[-1] == 'stop'
    assert (Path(stop[stop.index('-D') + 1]) / 'postmaster.pid').is_file()
    assert not any(query.startswith(('CREATE', 'DROP')) for query in queries)



def test_synthetic_pg_diagnostic_source_passes_sanitary_scan(tmp_path):
    from scripts.maintenance.github_sanitary_check import scan

    source = Path(__file__)
    destination = tmp_path / "tests/unit" / source.name
    destination.parent.mkdir(parents=True)
    destination.write_bytes(source.read_bytes())
    assert scan(tmp_path)["status"] == "ok"

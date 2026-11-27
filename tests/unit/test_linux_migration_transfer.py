"""Server transfer contracts using synthetic files and fake PostgreSQL clients."""

from contextlib import nullcontext
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from deploy.linux import backup, native_install as install, native_runtime as runtime, native_upgrade as upgrade
from deploy.linux import restore_existing as subject
from deploy.linux.sli_core.auth import PASSWORD_HASHER


@pytest.mark.parametrize('missing', [False, True])
def test_roles_keep_existing_logins_and_quote_source_identifiers(tmp_path, monkeypatch, missing):
    source = tmp_path / 'roles.sql'
    source.write_text('CREATE ROLE postgres;\nCREATE ROLE "synthetic ""role";\n'
                      'ALTER ROLE postgres WITH SUPERUSER LOGIN;\n'
                      'GRANT "synthetic ""role" TO postgres;\n')
    rows = iter([[('postgres',)], [('postgres',)] if missing else [('postgres',), ('synthetic "role',)]])
    connection = SimpleNamespace(execute=lambda _: SimpleNamespace(fetchall=lambda: next(rows)))
    calls = []

    def run(paths, **options):
        body = paths[0].read_text()
        assert 'CREATE ROLE postgres;' not in body
        assert 'CREATE ROLE "synthetic ""role";' in body
        assert 'ALTER ROLE postgres' in body and 'GRANT' in body
        assert options['atomic'] is True
        calls.append(body)

    monkeypatch.setattr(subject.migrate, 'run_sql', run)
    if missing:
        with pytest.raises(RuntimeError, match='roles_readback_failed'):
            subject.restore_roles(source, connection, tmp_path / 'passfile', tmp_path)
    else:
        subject.restore_roles(source, connection, tmp_path / 'passfile', tmp_path)
    assert len(calls) == 1


@pytest.mark.parametrize('body', ["CREATE ROLE synthetic; ALTER ROLE synthetic PASSWORD 'synthetic';",
                                'CREATE ROLE synthetic; ALTER ROLE synthetic PASSWORD NULL;'])
def test_roles_with_password_clauses_are_rejected_before_sql(tmp_path, body):
    path = tmp_path / 'roles.sql'
    path.write_text(body)
    with pytest.raises(ValueError, match='role_passwords_forbidden'):
        subject.restore_roles(path, None, path, tmp_path)


def test_missing_roles_stop_import_before_database_access(tmp_path, monkeypatch):
    (tmp_path / 'toc.dat').write_bytes(b'synthetic')
    monkeypatch.setenv('SLI_PG_ADMIN_PASSWORD_FILE', str(tmp_path / 'secret'))
    monkeypatch.setattr(subject, 'secret_value', lambda _: 'synthetic-only')
    monkeypatch.setattr(subject.psycopg, 'connect', lambda **kw: pytest.fail('database must not be opened'))
    with pytest.raises(ValueError, match='roles_file_required'):
        subject.restore_existing(tmp_path)


@pytest.mark.parametrize('sync,valid,active', [(False, True, True), (False, False, True),
                                           (True, False, True), (True, False, False)])
def test_owner_reconciliation_requires_opt_in_and_revokes_sessions(monkeypatch, sync, valid, active):
    password = 'synthetic-owner-password'
    restored_hash = PASSWORD_HASHER.hash(password if valid else 'synthetic-previous-password')
    monkeypatch.setattr(subject, 'secret_value', lambda _: password)
    calls = []

    def execute(query, params):
        calls.append((query, params))
        return SimpleNamespace(fetchone=lambda: (42, restored_hash, active))

    connection = SimpleNamespace(execute=execute, transaction=nullcontext)
    if not active or (not sync and not valid):
        with pytest.raises(RuntimeError, match='owner_unavailable|owner_credentials_mismatch'):
            subject.reconcile_owner(connection, sync=sync)
        assert len(calls) == 1
    else:
        subject.reconcile_owner(connection, sync=sync)
        assert len(calls) == (1 if valid else 4)
        if not valid:
            query, (updated_hash, owner_id) = calls[1]
            assert 'UPDATE public.auth_users SET password_hash=' in query and owner_id == 42
            assert PASSWORD_HASHER.verify(updated_hash, password)
            assert 'auth_sessions' in calls[2][0] and calls[2][1] == (42,)
            assert 'auth_audit' in calls[3][0] and calls[3][1] == (42,)


@pytest.mark.parametrize('failed', [False, True])
def test_analyze_in_stages_is_required_and_failure_propagates(tmp_path, monkeypatch, failed, capsys):
    calls = []

    def tool(command, passfile, *, watch):
        assert watch.step == 'postgres_analyze' and watch.limit >= backup.TIMEOUT
        calls.append((command, passfile))
        if failed:
            raise backup.BackupError('linux_backup_pg_tool_failed', returncode=1)

    monkeypatch.setattr(backup, 'pg_tool', tool)
    connection = SimpleNamespace(execute=lambda _: SimpleNamespace(fetchone=lambda: (4096,)))
    monkeypatch.setattr(backup, 'pg_connect', lambda _: nullcontext(connection))
    monkeypatch.setattr(subject.operation_wait, 'history_path', lambda: tmp_path / '.status/summary.json')
    if failed:
        with pytest.raises(backup.BackupError):
            subject.analyze_postgres(tmp_path / 'pgpass', 3)
        assert not capsys.readouterr().out
    else:
        subject.analyze_postgres(tmp_path / 'pgpass', 3)
        assert 'analyze_verified' in capsys.readouterr().out
    command, passfile = calls[0]
    assert command[0] == 'vacuumdb' and '--analyze-in-stages' in command and '--jobs=3' in command
    assert passfile == tmp_path / 'pgpass'


@pytest.mark.parametrize('failed', [False, True])
def test_restore_cli_publishes_atomic_progress_and_terminal_result(tmp_path, monkeypatch, capsys, failed):
    result = tmp_path / 'result.json'

    def restore(*args, **options):
        assert options['sync_owner_password'] is True
        assert options['check_agent_trust'] is True
        options['progress']('analyze')
        assert json.loads(result.read_text())['stage'] == 'analyze'
        if failed:
            raise RuntimeError('synthetic-private-data')

    monkeypatch.setattr(subject, 'restore_existing', restore)
    code = subject.main([str(tmp_path), '--sync-owner-password', '--check-agent-trust',
                         '--result-file', str(result)])
    document = json.loads(result.read_text())
    assert code == int(failed)
    assert document['status'] == ('failed' if failed else 'success')
    assert document['stage'] == ('analyze' if failed else 'complete')
    assert 'synthetic-private-data' not in str(document) + capsys.readouterr().out
    assert not list(tmp_path.glob('.result.json.*'))


@pytest.mark.parametrize('missing_roles', [False, True])
def test_component_restore_imports_roles_before_replacing_database_and_analyzes_after_dump(
        tmp_path, monkeypatch, missing_roles):
    (tmp_path / 'postgres').mkdir()
    (tmp_path / 'postgres/toc.dat').write_bytes(b'synthetic')
    if not missing_roles:
        (tmp_path / 'roles.sql').write_text('CREATE ROLE synthetic;\n')
    manifest = {'migration_ledger_max_version': 3,
                'components': {'postgres': {'roles_file': 'roles.sql', 'row_counts': {'items': 2}}}}
    calls = []

    def execute(statement):
        calls.append(statement)
        return SimpleNamespace(fetchone=lambda: (3,))

    connection = SimpleNamespace(execute=execute)
    monkeypatch.setattr(backup, 'pg_passfile', lambda: nullcontext(tmp_path / 'pgpass'))
    monkeypatch.setattr(backup, 'pg_connect', lambda *a, **kw: nullcontext(connection))
    monkeypatch.setattr(subject, 'require_empty_database', lambda *a, **kw: calls.append('empty'))
    monkeypatch.setattr(subject, 'restore_roles', lambda *a: calls.append('roles'))
    monkeypatch.setattr(backup, 'pg_tool', lambda args, _, *, watch: calls.append(args[0]))
    monkeypatch.setattr(subject.operation_wait, 'history_path', lambda: tmp_path / '.status/summary.json')
    monkeypatch.setattr(backup, 'row_counts', lambda _: {'items': 2})
    if missing_roles:
        with pytest.raises(ValueError, match='roles_file_required'):
            subject.restore_postgres(tmp_path, manifest, replace_existing=False)
        assert calls == []
    else:
        subject.restore_postgres(tmp_path, manifest, replace_existing=False)
        assert calls[:2] == ['empty', 'roles']
        assert calls.index('pg_restore') < calls.index('vacuumdb')
        assert any(str(item).startswith('DROP DATABASE') for item in calls)


def test_failed_migrated_candidate_restores_database_acl_and_starts_previous_release(tmp_path, monkeypatch):
    (tmp_path / 'postgres').mkdir()
    (tmp_path / 'postgres/toc.dat').write_bytes(b'synthetic')
    (tmp_path / 'roles.sql').write_text('CREATE ROLE sli_semantic_login;\n')
    accepted = {'sli_semantic_login': {'CONNECT'}, 'sli_migration': {'CONNECT', 'TEMPORARY', 'CREATE'}}
    acl = {'candidate_only': {'CONNECT'}}
    calls = []
    selected = {'release': 'candidate'}
    accepted_unit = 'ExecStart=/opt/sli/dotnet/accepted/Sli.Server\n'
    saved = tmp_path / 'recovery/units'
    saved.mkdir(parents=True)
    (saved / 'sli-dotnet-api.service').write_text(accepted_unit)
    units = tmp_path / 'live-units'
    units.mkdir()
    (units / 'sli-dotnet-api.service').write_text('ExecStart=/opt/sli/dotnet/candidate/Sli.Server\n')

    def execute(sql):
        calls.append(sql)
        if sql.startswith('DROP DATABASE'):
            acl.clear()
        if 'GRANT CONNECT,TEMPORARY ON DATABASE sli TO sli_semantic_login;' in sql:
            assert '\\connect' not in sql and 'CREATE DATABASE' not in sql
            acl.update(accepted)
        return SimpleNamespace(fetchone=lambda: (390,))

    def pg_tool(argv, passfile, *, watch=None):
        if '--list' in argv:
            assert '--create' in argv
            Path(argv[argv.index('--file') + 1]).write_text(
                '1; 1262 123 DATABASE - sli sli_migration\n2; 0 0 ACL - DATABASE sli sli_migration\n')
            return
        if '--create' in argv:
            entries = Path(argv[argv.index('--use-list') + 1]).read_text()
            assert '1262 123 DATABASE -' not in entries
            assert 'ACL - DATABASE sli' in entries
            Path(argv[argv.index('--file') + 1]).write_text(
                'CREATE DATABASE sli;\n\\connect sli\n'
                '--\n-- Name: DATABASE sli; Type: ACL; Schema: -; Owner: sli_migration\n--\n\n'
                'GRANT CONNECT,TEMPORARY ON DATABASE sli TO sli_semantic_login;\n\n'
                '--\n-- PostgreSQL database dump complete\n--\n')
            return
        assert '--dbname=sli' in argv
        assert any('REVOKE ALL ON DATABASE sli FROM PUBLIC' in sql for sql in calls)

    monkeypatch.setattr(backup, 'pg_passfile', lambda: nullcontext(tmp_path / 'pgpass'))
    monkeypatch.setattr(backup, 'pg_connect', lambda *a, **kw: nullcontext(SimpleNamespace(execute=execute)))
    monkeypatch.setattr(backup, 'native_mode', lambda: True)
    monkeypatch.setattr(backup, 'helper_temporary_directory', lambda **kwargs: nullcontext(tmp_path))
    monkeypatch.setattr(backup, 'pg_tool', pg_tool)
    monkeypatch.setattr(backup, 'row_counts', lambda _: {'items': 2})
    monkeypatch.setattr(subject, 'require_empty_database', lambda *a, **kw: None)
    monkeypatch.setattr(subject, 'restore_roles', lambda *a: None)
    monkeypatch.setattr(subject, 'analyze_postgres', lambda *a: None)
    manifest = {'migration_ledger_max_version': 390,
                'components': {'postgres': {'roles_file': 'roles.sql', 'row_counts': {'items': 2}}}}
    journal = object.__new__(upgrade.Journal)
    journal.path = tmp_path / 'transaction'
    journal.value = {'status': 'candidate_testing', 'step': 'before', 'schema_changed': True,
                     'candidate': 'candidate', 'previous': 'accepted'}
    journal.write = lambda: None
    results = []

    def start_checked():
        assert acl == accepted
        assert selected['release'] == 'accepted'
        assert (units / 'sli-dotnet-api.service').read_text() == accepted_unit
        calls.append('accepted-services-started')

    monkeypatch.setattr(upgrade, 'UNITS', units)
    monkeypatch.setattr(upgrade, 'fence', lambda: None)
    monkeypatch.setattr(upgrade, 'verify_recovery', lambda release: (saved.parent, {}))
    monkeypatch.setattr(upgrade, 'restore_checkpoint', lambda _: subject.restore_postgres(tmp_path, manifest, replace_existing=True))
    monkeypatch.setattr(upgrade, 'switch', lambda root, *args: selected.update(release=root.name))
    monkeypatch.setattr(upgrade, 'restore_helpers', lambda *a: None)
    monkeypatch.setattr(upgrade, 'testing_units', lambda *a: None)
    monkeypatch.setattr(upgrade, 'start_checked', start_checked)
    monkeypatch.setattr(upgrade, 'cleanup_checkpoints', lambda: None)
    monkeypatch.setattr(install, 'STATE', tmp_path / 'state')
    monkeypatch.setattr(install, 'inventory', lambda release: (tmp_path / release, {}, 'digest'))
    monkeypatch.setattr(install, 'command', lambda argv: calls.append(argv))
    monkeypatch.setattr(install, 'backup_schedule', lambda: 'disabled')
    monkeypatch.setattr(install, 'atomic', lambda path, data: results.append(data))
    monkeypatch.setattr(runtime, 'configuration', lambda: pytest.fail('no agents reconfiguration intent'))
    upgrade.record_failure(journal, install.UnitCommandFailure('sli-health.service', 1, 'synthetic health failure'))
    upgrade.recover_compatible(journal)
    assert 'accepted-services-started' in calls
    assert results[-1]['services_restored'] and results[-1]['status'] == 'rolled_back'
    assert results[-1]['failure_detail']['unit'] == 'sli-health.service'

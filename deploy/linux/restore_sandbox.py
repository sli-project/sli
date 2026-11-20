"""A private PostgreSQL cluster: data, WAL, sockets and logs on the backup disk."""
from __future__ import annotations

import os
import shlex
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path

PG_BIN = Path('/usr/lib/postgresql/18/bin')


def command(args: list[str], *, timeout: int = 120, watch=None, probe=None) -> None:
    options = dict(stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, timeout=timeout, check=False,
                            env={'PATH': os.environ.get('PATH', ''), 'LC_ALL': 'C.UTF-8',
                                 'PGCONNECT_TIMEOUT': '5', 'PGCLIENTENCODING': 'UTF8'})
    if watch is None:
        result = subprocess.run(args, **options)
    else:
        from deploy.linux.operation_wait import wait_process
        options.pop('timeout')
        options.pop('check')
        result = subprocess.Popen(args, **options, start_new_session=os.name == 'posix')
        result.sli_process_group = os.name == 'posix'
        wait_process(result, watch, probe)
    if result.returncode:
        raise RuntimeError('linux_backup_restore_sandbox_failed')
    if watch is not None:
        watch.success()


@contextmanager
def postgres(root: Path):
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix='pg-', dir=root))
    data = work / 'data'
    error = None
    try:
        # Unix socket only; never accept TCP or inherit a working-install DSN.
        # Linux sockaddr_un.sun_path has 108 bytes including its trailing NUL.
        if len(os.fsencode(work / '.s.PGSQL.5432')) >= 108:
            raise ValueError('linux_backup_restore_socket_path_too_long')
        command([str(PG_BIN / 'initdb'), '-D', str(data), '-U', 'sli_check',
                 '--auth-local=trust', '--auth-host=reject', '--no-locale', '--encoding=UTF8'])
        command([str(PG_BIN / 'pg_ctl'), '-D', str(data), '-l', str(work / 'postgres.log'),
                 '-o', (f"-h '' -k {shlex.quote(str(work))} -c shared_buffers=64MB -c max_connections=12 "
                        "-c temp_tablespaces='' -c log_min_error_statement=panic -c log_error_verbosity=terse"),
                 '-w', '-t', '60', 'start'])
        yield {'host': str(work), 'port': 5432, 'user': 'sli_check', 'dbname': 'postgres',
               'password': '', 'connect_timeout': 5, 'options': ''}
    except BaseException as caught:
        error = caught
        raise
    finally:
        # Failed start may still have spawned a postmaster. Keep files unless
        # pg_ctl confirms shutdown; never erase a running cluster's directory.
        try:
            if (data / 'postmaster.pid').exists():
                command([str(PG_BIN / 'pg_ctl'), '-D', str(data), '-m', 'immediate', '-w', '-t', '60', 'stop'])
            from deploy.linux.operation_wait import remove_tree

            remove_tree(work)
        except Exception:
            if error is None:
                raise
            error.cleanup_diagnostic = {'error_code': 'linux_backup_restore_sandbox_failed',
                                        'step': 'restore_check_cleanup'}


def restore(root: Path, archive: Path, expected: dict, ledger: int, database_size: int = 0,
            backup_root: Path | None = None) -> dict:
    import psycopg

    from deploy.linux import backup
    from deploy.linux import operation_wait

    installed = None
    with postgres(root) as connection:
        with psycopg.connect(**connection, autocommit=True) as admin:
            roles = archive.parent / 'roles.sql'
            if roles.is_file():
                command(['psql', '--no-psqlrc', '--no-password', '--set=ON_ERROR_STOP=1',
                         '--single-transaction', '--port=5432', '--host=' + connection['host'], '--username=sli_check',
                         '--dbname=postgres', '--file=' + str(roles)])
            admin.execute('CREATE DATABASE sli_check TEMPLATE template0')
        def probe():
            try:
                with psycopg.connect(**connection, autocommit=True) as observer:
                    observer.execute('SET statement_timeout=5000')
                    return observer.execute("SELECT pg_database_size('sli_check'), "
                        "(SELECT sum(tuples_done) FROM pg_stat_progress_create_index), "
                        "(SELECT sum(bytes_processed) FROM pg_stat_progress_copy)").fetchone()
            except psycopg.Error:
                return None

        if backup_root is None:
            backup_root = Path(os.environ.get('SLI_BACKUP_ROOT', str(root.parent)))
        watch = operation_wait.Watch('postgres_restore', minimum=21600,
                                     size=max(database_size, operation_wait.file_bytes(archive) * 4),
                                     history=operation_wait.history_path(backup_root))
        command(['pg_restore', '--no-password', '--exit-on-error',
                 '--no-tablespaces', '--port=5432', '--host=' + connection['host'], '--username=sli_check',
                 '--dbname=sli_check', '--format=directory', '--jobs=2', str(archive)], watch=watch, probe=probe)
        with psycopg.connect(**(connection | {'dbname': 'sli_check'})) as restored:
            counts = backup.row_counts(restored)
            version = restored.execute('SELECT max(version) FROM public.schema_migrations').fetchone()[0]
            if restored.execute("SELECT to_regclass('public.installed_release_v1')").fetchone()[0]:
                installed = restored.execute(
                    "SELECT json_build_object('installation_key',installation_key,'inventory',inventory) "
                    'FROM public.installed_release_v1 WHERE singleton').fetchone()[0]
            if counts != expected or version != ledger:
                raise RuntimeError('linux_backup_restore_mismatch')
    return installed

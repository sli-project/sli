"""One-command beta setup, stdlib-only until the accepted runtime is invoked."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import ipaddress
import json
import os
import platform
import re
import socket
import ssl
import stat
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path


def helper(name):
    spec = importlib.util.spec_from_file_location('sli_' + name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


try:
    from deploy.linux import native_clickhouse_endpoint as ch
    from deploy.linux import native_diagnostics as diagnostics
    from deploy.linux import native_host as host
    from deploy.linux import native_install as install
except ModuleNotFoundError:  # /usr/bin/python3 -I /usr/lib/sli/native_setup.py
    host, install, ch, diagnostics = map(helper, ('native_host', 'native_install',
                                                 'native_clickhouse_endpoint', 'native_diagnostics'))


def require(condition, code):
    if not condition:
        raise RuntimeError(code)


def settings(*, server, port, mode=None, bind=None):
    ch.server_name(server)
    site = {'domain_fqdn': 'example.invalid', 'server_name': server, 'bind': '0.0.0.0' if bind is None else bind,
            'https_port': port, 'agents': True, 'owner_setup': True}
    return ch.parse_site(render_site(site))


def tls_names(site):
    name, bind = site.get('server_name', site['domain_fqdn']), site['bind']
    names = [name]
    if ipaddress.ip_address(bind).is_unspecified:
        try:
            names.append(str(ipaddress.ip_address(name)))
        except ValueError:
            try:
                addresses = socket.getaddrinfo(name, site['https_port'], type=socket.SOCK_STREAM)
                names.extend(sorted({row[4][0] for row in addresses}, key=lambda address: (':' in address, address)))
            except (OSError, ValueError):
                raise RuntimeError('native_setup_dns_failed') from None
        names.extend(['localhost', '127.0.0.1', '::1'])
    else:
        names.append(bind)
    return list(dict.fromkeys(names))


def render_site(site):
    # JSON quoted scalar strings are valid TOML and cannot inject new keys.
    return ''.join(key + ' = ' + json.dumps(value, ensure_ascii=True) + '\n' for key, value in sorted(site.items()))


def requested_site(existing, *, server, bind, port, mode):
    for key, value in (('server_name', server), ('bind', bind), ('https_port', port)):
        require(value is None or existing.get(key) == value, 'native_setup_configuration_conflict')
    return existing


def url(site):
    name = site.get('server_name', site['bind'])
    authority = '[' + name + ']' if ':' in name else name
    port = site.get('https_port', 8443)
    return 'https://' + authority + ('' if port == 443 else ':' + str(port))


def command(argv, *, code, cwd=None, env=None, timeout=120):
    if argv[:2] == ['/usr/sbin/sli-native-install', 'configure']:
        operation = install.operations()
        watch = install.setup_watch()
        # Setup plus an entire restore-drill allowance for child recovery.
        # This supervisor must outlive the child's silence watchdog/rollback.
        estimate = host.Host().backup_space_estimate(Path('/var/backups/sli/native'))
        recovery = operation.Watch('drill', minimum=0, size=estimate['drill_io_bytes'],
                                   native=True, work_path=Path(host.MOUNT))
        watch.limit += recovery.limit
        watch.stall = watch.limit
        return operation.setup_command(argv, cwd=cwd, env=env, watch=watch,
                                       failure_codes=diagnostics.COMMAND_FAILURES)
    result = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=timeout, cwd=cwd, env=env)
    require(result.returncode == 0, code)
    return result.stdout


def check_port(site):
    dual_stack = site['bind'] == '0.0.0.0' and socket.has_dualstack_ipv6()
    family = socket.AF_INET6 if dual_stack or ':' in site['bind'] else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            if dual_stack:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            sock.bind(('::' if dual_stack else site['bind'], site['https_port']))
    except OSError:
        raise RuntimeError('native_setup_port_busy') from None


@contextmanager
def setup_lock():
    import fcntl
    import stat
    fd = os.open('/run/sli-setup.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600,
                'native_setup_busy')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('native_setup_busy') from None
        yield
    finally:
        os.close(fd)


def owner_recovery(username):
    """Issue only to the root terminal using the verified installed runtime."""
    require(sys.stdout.isatty(), 'native_owner_recovery_terminal_required')
    current = install.CURRENT.resolve(strict=True)
    root, manifest, _ = install.inventory(current.name)
    require(root == current, 'native_setup_configuration_conflict')
    script = root / 'scripts/auth/manage_auth.py'
    install.trusted(script)
    # Pass only the runtime credential path, never an administrative password.
    env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C.UTF-8',
           'SLI_DEPLOYMENT_MODE': 'native', 'ADLOG_DB_BACKEND': 'postgres',
           'ADLOG_PG_DSN': 'host=127.0.0.1 port=5432 dbname=sli user=adlog_user',
           'ADLOG_PG_PASSWORD_FILE': str(install.SECRETS / 'runtime_password')}
    result = subprocess.run([manifest['python'], '-I', '-B', str(script),
                             'owner-recovery', '--username', username],
                            cwd=root, env=env, stderr=subprocess.PIPE, timeout=30, check=False)
    require(result.returncode == 0, 'native_owner_recovery_failed')


INITIAL_ADMIN_PASSWORD = 'admin'
INITIAL_HASH_PREFIX = 'initial-password:'


def initial_admin_password(mode):
    import psycopg
    from argon2 import PasswordHasher
    from argon2.exceptions import InvalidHashError, VerificationError

    postgres_password = install.trusted(install.SECRETS / 'postgres_password').decode().strip()
    hasher = PasswordHasher()
    with psycopg.connect(host='127.0.0.1', port=5432, dbname='sli', user='postgres',
                         password=postgres_password) as conn:
        row = conn.execute("""select u.id, u.username, u.password_hash, u.last_login_at
            from public.auth_users u
            join public.access_platform_owners o on o.user_id=u.id
            where o.owner_key='primary' and u.role='admin' and u.is_active and not u.is_service
            for update of u""").fetchone()
        require(row is not None, 'native_initial_admin_unavailable')
        user_id, username, stored_hash, last_login = row
        pending = stored_hash.startswith(INITIAL_HASH_PREFIX)
        legacy_pending = (username == 'platform-owner' and last_login is None
                          and install.site_configuration().get('owner_setup', False))
        if mode == 'reset' or (mode == 'prepare' and legacy_pending and not pending):
            # Keep the established login on recovery. Only initial setup names
            # the existing, unclaimed owner record admin.
            if legacy_pending and mode == 'prepare':
                username = 'admin'
            conn.execute("""update public.auth_users set username=%s,password_hash=%s,updated_at=now()
                where id=%s""", (username, INITIAL_HASH_PREFIX + hasher.hash(INITIAL_ADMIN_PASSWORD), user_id))
            conn.execute("""update public.auth_sessions set revoked_at=now()
                where user_id=%s and revoked_at is null""", (user_id,))
            conn.execute("delete from public.auth_owner_recovery where user_id=%s", (user_id,))
            return username
        if not pending:
            if mode == 'check':
                raise RuntimeError('native_install_interrupted_requires_recovery')
            if legacy_pending:
                raise RuntimeError('native_initial_admin_unavailable')
            return None
        try:
            hasher.verify(stored_hash[len(INITIAL_HASH_PREFIX):], INITIAL_ADMIN_PASSWORD)
        except (VerificationError, InvalidHashError):
            raise RuntimeError('native_initial_admin_unavailable') from None
        return username


def run_initial_admin(mode, release=None):
    current = install.CURRENT.resolve(strict=True)
    root, manifest, _ = install.inventory(release or current.name)
    require(root == current, 'native_setup_configuration_conflict')
    script = install.trusted_path(root / 'deploy/linux/native_setup.py')
    result = command([manifest['python'], '-I', '-B', str(script), '--initial-admin', mode, root.name],
                     code='native_initial_admin_unavailable', cwd=root, env=install.environment(), timeout=None).strip()
    if result:
        username = json.loads(result)
        print(f'Login {username}, password {INITIAL_ADMIN_PASSWORD} — change it at first sign-in.')
        print(f'Логин {username}, пароль {INITIAL_ADMIN_PASSWORD} — смените при первом входе.')


def wait_api(config=None):
    """Use the verified CA and bounded health polling before reporting success."""
    try:
        if config is None:
            if __package__ in {None, ''}:
                runtime = helper('native_runtime')
            else:
                from deploy.linux import native_runtime as runtime
            config = runtime.configuration()
        install.wait_api(config)
    except Exception as exc:  # noqa: BLE001 - only a bounded class name crosses this boundary
        if isinstance(exc, RuntimeError) and str(exc) == 'native_api_tls_untrusted':
            raise RuntimeError('native_api_tls_untrusted') from None
        reason = type(exc).__name__
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}', reason):
            reason = 'Exception'
        raise RuntimeError('native_setup_health_failed:' + reason) from None


def configure(args):
    operating_system = platform.freedesktop_os_release()
    require(operating_system.get('ID') == 'debian' and operating_system.get('VERSION_ID') == '13'
            and platform.machine() == 'x86_64', 'native_debian13_amd64_required')
    if getattr(args, 'reuse_existing', False):
        require(install.SITE.exists() and all((install.STATE / name).exists() for name in
                ('installed.json', 'host-prepared.json', 'package-install.json')),
                'native_reuse_installation_required')
    machine = host.Host()
    existing = ch.parse_site(install.trusted(install.SITE).decode()) if install.SITE.exists() or install.SITE.is_symlink() else None
    if existing is None:
        server = args.server
        if not server and not args.non_interactive:
            server = input('Server hostname or IP / Имя или IP сервера: ').strip().lower()
        require(bool(server), 'native_setup_server_required')
        port = args.port
        if port is None and not args.non_interactive:
            answer = input('HTTPS port / Порт HTTPS [443]: ').strip()
            try:
                port = int(answer) if answer else 443
            except ValueError:
                raise RuntimeError('native_site_port_invalid') from None
        site = settings(server=server, bind=args.bind, port=443 if port is None else port,
                        mode=None)
        if args.backup_root:
            site['backup_root'] = ch.backup_root_path(args.backup_root)
        if getattr(args, 'cold_tablespace_root', None):
            site['cold_tablespace_root'] = ch.cold_tablespace_root_path(args.cold_tablespace_root)
    else:
        site = requested_site(existing, server=args.server, bind=args.bind, port=args.port, mode=None)
        require(args.backup_root is None or args.backup_root == site.get('backup_root'),
                'native_setup_configuration_conflict')
        require(getattr(args, 'cold_tablespace_root', None) is None
                or args.cold_tablespace_root == site.get('cold_tablespace_root'),
                'native_setup_configuration_conflict')
    receipt_path = install.STATE / 'host-prepared.json'
    saved = json.loads(install.trusted(receipt_path)) if receipt_path.exists() else None
    if saved:
        require(args.uuid is None or args.uuid == saved.get('uuid'), 'native_setup_storage_conflict')
        require(args.directory is None or args.directory == saved.get('directory'), 'native_setup_storage_conflict')
    installed_path = install.STATE / 'installed.json'
    installed = json.loads(install.trusted(installed_path)) if installed_path.exists() else None
    if getattr(args, 'reuse_existing', False):
        require(installed and existing and saved, 'native_reuse_installation_required')
        pending = install.STATE / 'pending-release.json'
        require(pending.exists(), 'native_setup_not_staged')
        release = json.loads(install.trusted(pending))['release']
        root, manifest, _ = install.inventory(release)
        script = root / 'deploy/linux/native_upgrade.py'
        install.trusted(script)
        # Explicit handoff to the newly unpacked, verified release. Do not use
        # launch/dispatch: those intentionally select the previous coordinator.
        os.chdir(root)
        os.execve(manifest['python'], [manifest['python'], '-I', '-B', str(script),
                                      'reuse-existing', release], install.environment())
        return
    require(installed or not (install.STATE / 'package-install.json').exists(),
            'native_install_interrupted_requires_recovery')
    if installed:
        require(existing is not None, 'native_setup_configuration_conflict')
        release = Path(installed['release']).name
    else:
        pending = install.STATE / 'pending-release.json'
        require(pending.exists(), 'native_setup_not_staged')
        release = json.loads(install.trusted(pending))['release']
        check_port(site)
    root, manifest, _ = install.inventory(release)
    python = manifest['python']
    env = install.environment()
    if not installed:
        names = tls_names(site)
        # Validate space, foreign data and local bind before site publication.
        if not saved and not args.uuid:
            source = machine.validate_database_directory(args.directory or host.DIRECTORY)
            require(not source.exists() or not any(source.iterdir()), 'native_existing_database')
        if existing is None:
            machine.write('/etc/sli/site.toml', render_site(site))
        with host.administrative_lock():
            machine.prepare(saved.get('uuid') if saved else args.uuid,
                            directory=saved.get('directory', host.DIRECTORY) if saved else args.directory or host.DIRECTORY)
        print('Preparing certificates and services / Подготовка сертификатов и служб…', flush=True)
        command([python, '-B', '-m', 'deploy.linux.sli_secrets', 'ensure', '--directory', str(install.SECRETS),
                 '--agents', '--offline-root-dir', '/var/lib/sli-ca-offline',
                 *[arg for name in names for arg in ('--tls-name', name)]],
                code='native_setup_secrets_failed', cwd=root, env=env)
        command(['/usr/sbin/sli-native-install', 'configure', release],
                code='native_setup_install_failed', cwd=root, env=env)
    else:
        with host.administrative_lock():
            machine.receipt()
        receipt = json.loads(install.trusted(install.STATE / 'package-install.json'))
        require(receipt.get('site_sha256') == install.site_digest(site), 'native_setup_configuration_conflict')
        if receipt.get('status') == 'configured':
            command(['systemctl', 'start', 'sli.target'], code='native_setup_health_failed')
            command(['systemctl', 'start', 'sli-health.service'], code='native_setup_health_failed')
        else:
            require(receipt.get('status') in {'configuring', 'failed'},
                    'native_install_interrupted_requires_recovery')
            # Repeat acceptance only; the coordinator validates registry/owner.
            # Never prepare storage, secrets or schema on this path.
            command(['/usr/sbin/sli-native-install', 'configure', release],
                    code='native_setup_install_failed', cwd=root, env=env)
    ca = install.trusted(install.SECRETS / 'tls_ca').decode('ascii')
    machine.write('/var/lib/sli/tls-ca.crt', ca, 0o644)
    fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(ca)).hexdigest()
    print('Public TLS CA: /var/lib/sli/tls-ca.crt; SHA256 (DER): ' + fingerprint)
    wait_api()
    print('TLS uses a private CA. Verify/trust the public CA on clients; keep /var/lib/sli-ca-offline offline.')
    if 'backup_root' not in site:
        print('Backups are local to this disk. Copy recovery sets to another device for disk-failure protection.')
    print('SLI: ' + url(site) + '/app')
    if site.get('owner_setup'):
        run_initial_admin('status', release)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', help='Server hostname or IP, without scheme/port')
    parser.add_argument('--bind', help='Restrict HTTPS to a local IP (default: all server addresses)')
    parser.add_argument('--port', type=int, help='HTTPS port (default: 443)')
    storage = parser.add_mutually_exclusive_group()
    storage.add_argument('--uuid', help='Optional ext4 filesystem already mounted at /srv/sli-db')
    storage.add_argument('--directory', help='Database directory (default: /var/lib/sli-db)')
    parser.add_argument('--backup-root', help='Optional trusted directory on a separate backup disk')
    parser.add_argument('--cold-tablespace-root', help='Каталог ёмкого диска для холодных таблиц PostgreSQL')
    parser.add_argument('--non-interactive', action='store_true')
    parser.add_argument('--reuse-existing', action='store_true', help='Upgrade retained SLI data using the newly installed package release')
    owner = parser.add_mutually_exclusive_group()
    owner.add_argument('--reset-admin-password', action='store_true', help='Reset the primary owner password to admin and require a change')
    owner.add_argument('--owner-recovery', metavar='USERNAME', help='Root terminal: issue a single-use recovery code (10 minutes; password still required)')
    owner.add_argument('--initial-admin', nargs=2, metavar=('MODE', 'RELEASE'), help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        require(os.geteuid() == 0, 'native_root_required')
        os.umask(0o022)
        if args.owner_recovery:
            owner_recovery(args.owner_recovery)
        elif args.initial_admin:
            mode, release = args.initial_admin
            require(mode in {'prepare', 'check', 'status', 'reset'}, 'native_setup_configuration_conflict')
            root, manifest, _ = install.inventory(release)
            require(Path(sys.executable) == Path(manifest['python']), 'native_setup_configuration_conflict')
            install.trusted_path(root / 'deploy/linux/native_setup.py')
            sys.path.insert(0, str(root))
            result = initial_admin_password(mode)
            if mode in {'status', 'reset'} and result is not None:
                print(json.dumps(result))
        elif args.reset_admin_password:
            with setup_lock():
                run_initial_admin('reset')
        else:
            with setup_lock():
                configure(args)
    except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - never expose private subprocess diagnostics
        diagnostics.failure(error)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

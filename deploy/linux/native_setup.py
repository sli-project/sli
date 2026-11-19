"""One-command beta setup, stdlib-only until the accepted runtime is invoked."""
from __future__ import annotations

import argparse
import base64
import importlib.util
import ipaddress
import json
import os
import platform
import re
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
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


def resolved_addresses(name, port):
    try:
        return {str(ipaddress.ip_address(row[4][0]))
                for row in socket.getaddrinfo(name, port, type=socket.SOCK_STREAM)}
    except (OSError, ValueError):
        return set()


def server_address(server, bind, port):
    if server is not None:
        ch.server_name(server)
        try:
            return str(ipaddress.ip_address(server))
        except ValueError:
            if resolved_addresses(server, port):
                return server

    if not ipaddress.ip_address(bind).is_unspecified:
        addresses = [ch.server_name(bind)]
    else:
        local = sorted(map(ipaddress.ip_address, host.run(['hostname', '--all-ip-addresses']).split()),
                       key=lambda address: address.version)
        addresses = [str(address) for address in local if not (address.is_loopback or address.is_link_local
                                                               or address.is_unspecified or address.is_multicast)]
    require(bool(addresses), 'native_setup_server_required')

    name = server or socket.getfqdn().lower().rstrip('.')
    if server is None and '.' in name:
        try:
            ch.server_name(name)
        except ValueError:
            pass  # An invalid local hostname is not a public HTTPS address.
        else:
            resolved = resolved_addresses(name, port)
            if resolved and resolved.issubset(addresses):
                return name
    print(f'Server name is not usable for HTTPS; using {addresses[0]}.', flush=True)
    return addresses[0]


def tls_names(site):
    name, bind = site.get('server_name', site['domain_fqdn']), site['bind']
    names = [name]
    if ipaddress.ip_address(bind).is_unspecified:
        try:
            names.append(str(ipaddress.ip_address(name)))
        except ValueError:
            addresses = resolved_addresses(name, site['https_port'])
            require(bool(addresses), 'native_setup_dns_failed')
            names.extend(sorted(addresses, key=lambda address: (':' in address, address)))
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
            return sock.getsockname()[1]
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


def replace_text(path, body, *, mode=0o600):
    """Replace trusted root-owned text without following an existing symlink."""
    install.trusted(path)
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        if os.name == 'posix':
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


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


def owner_code(*, new=False, check_only=False):
    """Root-only helper; row locking serializes rotation with activation.

    updated_at is issuance time while unclaimed. The protected receipt suppresses
    repeat display; lost terminal output requires explicit rotation. The API
    never receives an administrative credential or the plaintext file.
    """
    import psycopg
    from argon2.exceptions import InvalidHashError, VerificationError

    from server.sli.access.auth import PASSWORD_HASHER, owner_code_current
    password = install.trusted(install.SECRETS / 'postgres_password').decode().strip()
    path = install.SECRETS / 'platform_owner_password'
    receipt = install.STATE / 'owner-code-issued.json'
    with psycopg.connect(host='127.0.0.1', port=5432, dbname='sli', user='postgres', password=password,
                         connect_timeout=5, options='-c statement_timeout=5000 -c lock_timeout=5000') as conn:
        row = conn.execute("""select u.password_hash, u.last_login_at,
            u.updated_at, clock_timestamp()
            from public.auth_users u
            join public.access_platform_owners o on o.user_id=u.id
            where u.username='platform-owner' and u.role='admin' and u.is_active=true
            and o.owner_key='primary' for update of u""").fetchone()
        require(row is not None, 'native_setup_owner_code_unavailable')
        if row[1] is not None:
            if check_only:
                return 'activated'
            if path.exists() or path.is_symlink():
                install.trusted(path)
                path.unlink()
            return 'activated'
        if new:
            # Explicit root rotation can recover an interrupted file/DB update.
            # An activated owner's password can never enter this branch.
            code = secrets.token_urlsafe(48)
            replace_text(path, code + '\n')
            conn.execute("""update public.auth_users set password_hash=%s, updated_at=clock_timestamp()
                where username='platform-owner' and last_login_at is null""", (PASSWORD_HASHER.hash(code),))
        else:
            code = install.trusted(path).decode().strip()
            try:
                PASSWORD_HASHER.verify(row[0], code)
            except (VerificationError, InvalidHashError):
                raise RuntimeError('native_setup_owner_code_unavailable') from None
            require(re.fullmatch(r'[A-Za-z0-9_-]{32,128}', code), 'native_setup_secrets_failed')
            if check_only:
                return 'unclaimed'
            if not owner_code_current(row[2], row[3]):
                return 'expired'
            if receipt.exists() or receipt.is_symlink():
                install.trusted(receipt)
                return 'pending'
        install.atomic(receipt, {'schema_version': 1, 'issued': True})
    return code


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


def disable_owner_setup():
    """Reconcile runtime without changing the installation's site digest."""
    if __package__ in {None, ''}:
        runtime = helper('native_runtime')
    else:
        from deploy.linux import native_runtime as runtime
    config = runtime.configuration()
    config_changed = config.get('owner_setup', False)
    config['owner_setup'] = False
    pending = install.STATE / 'owner-setup-restart.json'
    restart_pending = pending.exists() or pending.is_symlink()
    if restart_pending:
        install.trusted(pending)
    if config_changed or restart_pending:
        # Persist intent before either write: retry must finish a restart even
        # when an interruption left both files updated but the old API running.
        install.atomic(pending, {'schema_version': 1, 'pending': True})
        if config_changed:
            replace_text(runtime.CONFIG, json.dumps(config, sort_keys=True) + '\n', mode=0o644)
        command(['systemctl', 'daemon-reload'], code='native_setup_health_failed')
        command(['systemctl', 'restart', runtime.active_unit_name('api')], code='native_setup_health_failed')
        wait_api(config)
        pending.unlink()
    else:
        wait_api(config)



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
        port = 443 if args.port is None else args.port
        site = settings(server=args.server or 'localhost', bind=args.bind, port=port)
        site['server_name'] = server_address(args.server, site['bind'], port)
        if args.backup_root:
            site['backup_root'] = ch.backup_root_path(args.backup_root)
        if getattr(args, 'cold_tablespace_root', None):
            site['cold_tablespace_root'] = ch.cold_tablespace_root_path(args.cold_tablespace_root)
    else:
        server = args.server
        if server is not None and server != existing.get('server_name'):
            server = server_address(server, existing['bind'], existing['https_port'])
        site = requested_site(existing, server=server, bind=args.bind, port=args.port, mode=None)
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
        require(not args.new_owner_code, 'native_setup_configuration_conflict')
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
        try:
            check_port(site)
        except RuntimeError as error:
            if existing is not None or args.port is not None or str(error) != 'native_setup_port_busy':
                raise
            site['https_port'] = check_port({**site, 'https_port': 0})
            print(f'HTTPS port 443 is busy; using {site["https_port"]}.', flush=True)
    root, manifest, _ = install.inventory(release)
    python = manifest['python']
    env = install.environment()
    if not installed:
        names = tls_names(site)
        with host.administrative_lock():
            uuid = saved.get('uuid') if saved else args.uuid
            directory = saved.get('directory', host.DIRECTORY) if saved else args.directory
            if not uuid and directory is None:
                directory = machine.select_database_directory(backup_root=site.get('backup_root'))
            if not saved and not uuid:
                source = machine.validate_database_directory(directory)
                require(not source.exists() or not any(source.iterdir()), 'native_existing_database')
            if existing is None:
                machine.write('/etc/sli/site.toml', render_site(site))
            machine.prepare(uuid, directory=directory or host.DIRECTORY)
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
    browser_url = url(site) + '/app'
    print('SLI: ' + browser_url)
    api_checked = False
    if site.get('owner_setup'):
        code = command([python, '-I', '-B', str(root / 'deploy/linux/native_setup.py'), '--owner-code', release,
                        *(['--new-owner-code'] if args.new_owner_code else [])],
                       code='native_setup_health_failed', cwd=root, env=env).strip()
        if code == 'activated':
            disable_owner_setup()
            api_checked = True
            print('Owner already activated / Владелец уже создан. Login: platform-owner')
        elif code in {'pending', 'expired'}:
            print('Owner code: ' + code + '. Use --new-owner-code to issue a new code (valid for 24 hours).')
        else:
            require(re.fullmatch(r'[A-Za-z0-9_-]{32,128}', code), 'native_setup_secrets_failed')
            browser_url = url(site) + '/api/auth/bootstrap'
            print('Create owner / Создать владельца: ' + browser_url)
            print('One-time code / Одноразовый код: ' + code)
    if not api_checked:
        wait_api()
    der = base64.b64encode(ssl.PEM_cert_to_DER_cert(ca)).decode('ascii')
    print('Windows first connection / Первый вход с Windows (PowerShell):')
    print("& { $ErrorActionPreference = 'Stop'; $ca = [Security.Cryptography.X509Certificates.X509Certificate2]::new("
          f"[Convert]::FromBase64String('{der}')); "
          "$store = [Security.Cryptography.X509Certificates.X509Store]::new('Root','CurrentUser'); "
          "try { $store.Open('ReadWrite'); $store.Add($ca) } finally { $store.Dispose(); $ca.Dispose() }; "
          f"Start-Process '{browser_url}' }}")
    if 'backup_root' not in site:
        print('Backups are local to this disk. Copy recovery sets to another device for disk-failure protection.')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', help='Server hostname or IP, without scheme/port')
    parser.add_argument('--bind', help='Restrict HTTPS to a local IP (default: all server addresses)')
    parser.add_argument('--port', type=int, help='HTTPS port (default: 443)')
    storage = parser.add_mutually_exclusive_group()
    storage.add_argument('--uuid', help='Optional ext4 filesystem already mounted at /srv/sli-db')
    storage.add_argument('--directory', help='Database directory (default: /var/lib/sli-db or a mounted volume with free space)')
    parser.add_argument('--backup-root', help='Optional trusted directory on a separate backup disk')
    parser.add_argument('--cold-tablespace-root', help='Каталог ёмкого диска для холодных таблиц PostgreSQL')
    parser.add_argument('--non-interactive', action='store_true')
    parser.add_argument('--reuse-existing', action='store_true', help='Upgrade retained SLI data using the newly installed package release')
    parser.add_argument('--new-owner-code', action='store_true', help='Replace the unclaimed owner code (24 hours)')
    parser.add_argument('--owner-recovery', metavar='USERNAME', help='Root terminal: issue a single-use recovery code (10 minutes; password still required)')
    parser.add_argument('--owner-code', help=argparse.SUPPRESS)
    parser.add_argument('--check-unclaimed-owner', help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        require(os.geteuid() == 0, 'native_root_required')
        os.umask(0o022)
        if args.owner_recovery:
            owner_recovery(args.owner_recovery)
        elif args.owner_code or args.check_unclaimed_owner:
            root, manifest, _ = install.inventory(args.owner_code or args.check_unclaimed_owner)
            require(Path(sys.executable) == Path(manifest['python']), 'native_setup_configuration_conflict')
            install.trusted(root / 'deploy/linux/native_setup.py')
            sys.path.insert(0, str(root))
            if args.check_unclaimed_owner:
                require(owner_code(check_only=True) == 'unclaimed', 'native_install_interrupted_requires_recovery')
            else:
                print(owner_code(new=args.new_owner_code))
        else:
            with setup_lock():
                configure(args)
    except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - never expose private subprocess diagnostics
        diagnostics.failure(error)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

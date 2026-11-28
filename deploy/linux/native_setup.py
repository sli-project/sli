"""One-command beta setup, stdlib-only until the accepted runtime is invoked."""
from __future__ import annotations

import argparse
import base64
import errno
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


def tls_names(site, *, saved=False):
    name, bind = site.get('server_name', site['domain_fqdn']), site['bind']
    names = [name]
    try:
        addresses = [str(ipaddress.ip_address(name))]
    except ValueError:
        addresses = sorted(resolved_addresses(name, site['https_port']), key=lambda address: (':' in address, address))
        if not addresses:
            remedy = f'Correct DNS so getent ahosts {name} succeeds, then rerun sudo sli-setup'
            if not saved:
                remedy += ', or find a local address with ip -brief address and rerun sudo sli-setup --server <IP>'
            raise host.GuardError('native_setup_dns_failed', name, 'server name does not resolve', remedy)
    if ipaddress.ip_address(bind).is_unspecified:
        names.extend(addresses)
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


url = ch.public_url


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
                                       failure_codes=diagnostics.COMMAND_FAILURES,
                                       diagnose_failure=diagnose_install_failure)
    result = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=timeout, cwd=cwd, env=env)
    require(result.returncode == 0, code)
    return result.stdout


def diagnose_install_failure(lines):
    prefix = 'native_existing_configuration_conflict: '
    paths = [line[len(prefix):] for line in lines if line.startswith(prefix)
             and host.SYSTEMD_PATH.fullmatch(line[len(prefix):])]
    if paths:
        raise host.configuration_conflict(*dict.fromkeys(paths))


def check_port(site, *, saved=False):
    bind, port = site['bind'], site['https_port']
    dual_stack = bind == '0.0.0.0' and socket.has_dualstack_ipv6()
    family = socket.AF_INET6 if dual_stack or ':' in bind else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            if dual_stack:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            sock.bind(('::' if dual_stack else bind, port))
            return sock.getsockname()[1]
    except OSError as error:
        if error.errno == errno.EADDRNOTAVAIL:
            raise host.GuardError('native_setup_port_busy', f'{bind} (HTTPS port {port})', 'address is not assigned locally',
                                  'Run ip -brief address and rerun sudo sli-setup --bind <local-IP>') from None
        listeners = host.port_listeners(port)
        reason = 'cannot bind'
        if listeners:
            reason += '; listeners on this port: ' + ', '.join(listeners)
        remedy = f"Run sudo ss -ltnp 'sport = :{port}' to identify the service and free the port"
        if not saved:
            remedy += ', or rerun sudo sli-setup --port <free-port> with the other setup flags'
        raise host.GuardError('native_setup_port_busy', f'{bind} (HTTPS port {port})', reason, remedy) from None


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


COCKPIT_DIR = Path('/etc/cockpit')
COCKPIT_SOCKET = Path('/usr/lib/systemd/system/cockpit.socket')
COCKPIT_STATUS = Path('/run/sli-cockpit/terminal.json')
COCKPIT_DROP_IN = '''[Unit]
ConditionPathExists=/etc/cockpit/ws-certs.d/99-sli.cert
ConditionPathExists=/etc/cockpit/ws-certs.d/99-sli.key
ConditionPathExists=/etc/cockpit/sli-terminal.json

[Socket]
ListenStream=
ListenStream=9090
RuntimeDirectory=sli-cockpit
RuntimeDirectoryMode=0755
ExecStartPre=/usr/bin/grep -qxF root /etc/cockpit/disallowed-users
ExecStartPost=/usr/bin/install -m 0644 /etc/cockpit/sli-terminal.json /run/sli-cockpit/terminal.json
ExecStopPost=-/usr/bin/rm -f /run/sli-cockpit/terminal.json
'''


def enable_web_console(machine, site):
    code = 'native_web_console_setup_failed'
    # APT can start a new socket. Require configured TLS and the root deny entry first.
    machine.write('/etc/systemd/system/cockpit.socket.d/50-sli.conf', COCKPIT_DROP_IN, 0o644)
    command(['systemctl', 'daemon-reload'], code=code)
    command(['apt-get', 'install', '-y', '--no-install-recommends',
             'cockpit-ws', 'cockpit-system', 'cockpit-bridge'], code=code, timeout=None)
    command(['groupadd', '--force', '--system', 'cockpit-ws'], code=code)

    disallowed = COCKPIT_DIR / 'disallowed-users'
    policy = install.trusted(disallowed).decode() if disallowed.exists() or disallowed.is_symlink() else None
    root_added = policy is None or 'root' not in policy.splitlines()
    if policy is None:
        machine.write(str(disallowed), 'root\n', 0o644)
    elif root_added:
        replace_text(disallowed, policy + ('\n' if policy and not policy.endswith('\n') else '') + 'root\n', mode=0o644)

    terminal = COCKPIT_DIR / 'sli-terminal.json'
    body = json.dumps({'url': url({**site, 'https_port': 9090}) + '/system/terminal'}) + '\n'
    previous = install.trusted(terminal).decode() if terminal.exists() or terminal.is_symlink() else None
    if previous is None:
        machine.write(str(terminal), body, 0o644)
    elif previous != body:
        replace_text(terminal, body, mode=0o644)

    certificates = COCKPIT_DIR / 'ws-certs.d'
    host.ensure_directory(certificates)
    info = certificates.stat()
    require(info.st_uid == 0 and not info.st_mode & 0o022, code)
    tls_changed = False
    for source, name in (('tls_certificate', '99-sli.cert'), ('tls_key', '99-sli.key')):
        target = certificates / name
        if target.exists() or target.is_symlink():
            install.trusted_path(target)
        src = install.trusted_path(install.SECRETS / source)
        copied = command(['/usr/bin/install', '-Cv', '-o', 'root', '-g', 'cockpit-ws', '-m', '0640',
                          str(src), str(target)], code=code)
        tls_changed |= bool(copied)

    was_running = COCKPIT_STATUS.is_file()
    command(['systemctl', 'enable', '--now', 'cockpit.socket'], code=code)
    # An already running Cockpit socket may predate the SLI drop-in.
    if not COCKPIT_STATUS.is_file() or (was_running and previous != body):
        command(['systemctl', 'restart', 'cockpit.socket'], code=code)
    require(COCKPIT_STATUS.is_file(), code)
    if root_added or tls_changed:
        command(['systemctl', 'try-restart', 'cockpit.service'], code=code)


def disable_web_console():
    if COCKPIT_SOCKET.is_file():
        code = 'native_web_console_disable_failed'
        command(['systemctl', 'disable', '--now', 'cockpit.socket'], code=code)
        command(['systemctl', 'stop', 'cockpit.service'], code=code)


def owner_recovery(username):
    """Issue only to the root terminal using the verified installed runtime."""
    require(sys.stdout.isatty(), 'native_owner_recovery_terminal_required')
    current = install.CURRENT.resolve(strict=True)
    root, _, _ = install.inventory(current.name)
    require(root == current, 'native_setup_configuration_conflict')
    executable = Path('/opt/sli/dotnet') / root.name / 'Sli.Server'
    install.trusted_path(executable)
    # Pass only the runtime credential path, never an administrative password.
    env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C.UTF-8',
           'SLI_DEPLOYMENT_MODE': 'native', 'ADLOG_DB_BACKEND': 'postgres',
           'ADLOG_PG_DSN': 'host=127.0.0.1 port=5432 dbname=sli user=adlog_user',
           'ADLOG_PG_PASSWORD_FILE': str(install.SECRETS / 'runtime_password')}
    result = subprocess.run([str(executable), 'owner-recovery', '--username', username],
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
    """Poll with the verified CA; log readiness expiry as native_setup_health_failed:RuntimeError."""
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
    require(installed or saved or not (install.STATE / 'package-install.json').exists(),
            'native_install_interrupted_requires_recovery')
    if installed:
        require(existing is not None, 'native_setup_configuration_conflict')
        release = Path(installed['release']).name
    else:
        pending = install.STATE / 'pending-release.json'
        require(pending.exists(), 'native_setup_not_staged')
        release = json.loads(install.trusted(pending))['release']
        try:
            check_port(site, saved=existing is not None)
        except host.GuardError as error:
            cause = error.__context__
            if (existing is not None or args.port is not None or not isinstance(cause, OSError)
                    or cause.errno != errno.EADDRINUSE):
                raise
            site['https_port'] = check_port({**site, 'https_port': 0})
            print(f'HTTPS port 443 is busy; using {site["https_port"]}.', flush=True)
    root, manifest, _ = install.inventory(release)
    python = manifest['python']
    env = install.environment()
    if not installed:
        names = tls_names(site, saved=existing is not None)
        with host.administrative_lock():
            uuid = saved.get('uuid') if saved else args.uuid
            directory = saved.get('directory', host.DIRECTORY) if saved else args.directory
            if not uuid and directory is None:
                uuid = machine.mounted_database_uuid()
                if not uuid:
                    directory = machine.select_database_directory(backup_root=site.get('backup_root'))
            directory = directory or host.DIRECTORY
            machine.check_setup_units(directory, uuid=uuid, backup=bool(site.get('backup_root')))
            machine.prepare(uuid, directory=directory)
            if existing is None:
                machine.write('/etc/sli/site.toml', render_site(site))
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
    wait_api()
    if getattr(args, 'web_console', False):
        enable_web_console(machine, site)
    print('Public TLS CA: /var/lib/sli/tls-ca.crt')
    certificate = ssl.PEM_cert_to_DER_cert(ca)
    fingerprint = hashlib.sha256(certificate).hexdigest().upper()
    print('CA SHA-256 fingerprint: ' + ':'.join(re.findall(r'..', fingerprint)))
    der = base64.b64encode(certificate).decode('ascii')
    print('Windows first connection / Первый вход с Windows (PowerShell):')
    print("& { $ErrorActionPreference = 'Stop'; $ca = [Security.Cryptography.X509Certificates.X509Certificate2]::new("
          f"[Convert]::FromBase64String('{der}')); "
          "$store = [Security.Cryptography.X509Certificates.X509Store]::new('Root','CurrentUser'); "
          "try { $store.Open('ReadWrite'); $store.Add($ca) } finally { $store.Dispose(); $ca.Dispose() }; "
          f"Start-Process '{browser_url}' }}")
    print('TLS uses a private CA. Verify/trust the public CA on clients; keep /var/lib/sli-ca-offline offline.')
    if 'backup_root' not in site:
        print('Backups are local to this disk. Copy recovery sets to another device for disk-failure protection.')
    if site.get('owner_setup'):
        run_initial_admin('status', release)


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
    action = parser.add_mutually_exclusive_group()
    action.add_argument('--web-console', action='store_true', help='Install and enable the Cockpit web console on port 9090')
    action.add_argument('--no-web-console', action='store_true', help='Disable the Cockpit web console')
    action.add_argument('--reset-admin-password', action='store_true', help='Reset the primary owner password to admin and require a change')
    action.add_argument('--owner-recovery', metavar='USERNAME', help='Root terminal: issue a single-use recovery code (10 minutes; password still required)')
    action.add_argument('--initial-admin', nargs=2, metavar=('MODE', 'RELEASE'), help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.reuse_existing and (args.web_console or args.no_web_console):
        parser.error('--reuse-existing cannot be combined with a web console option')
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
        elif args.no_web_console:
            with setup_lock():
                disable_web_console()
        else:
            with setup_lock():
                configure(args)
    except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - never expose private subprocess diagnostics
        diagnostics.failure(error)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

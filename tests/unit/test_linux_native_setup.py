"""Fresh beta setup contracts; no daemon, network or host secret access."""
import json
import os
from pathlib import Path

import pytest

from deploy.linux import native_clickhouse_endpoint as ch
from deploy.linux import native_install as install
from deploy.linux import native_runtime as runtime


def test_owner_recovery_uses_installed_runtime_and_only_runtime_credential_path(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from deploy.linux import native_setup as setup

    root = tmp_path / 'release'
    root.mkdir()
    monkeypatch.setattr(install, 'CURRENT', root)
    monkeypatch.setattr(install, 'SECRETS', Path('/synthetic/secrets'))
    monkeypatch.setattr(install, 'inventory', lambda release: (root, {'python': '/verified/python'}, 'digest'))
    trusted = []
    monkeypatch.setattr(install, 'trusted', lambda path: trusted.append(path))
    monkeypatch.setattr(setup.sys.stdout, 'isatty', lambda: True)
    monkeypatch.setenv('ADLOG_PG_DSN', 'untrusted-inherited-dsn')
    monkeypatch.setenv('ADLOG_PG_PASSWORD', 'synthetic-inherited-secret')
    calls = []
    monkeypatch.setattr(setup.subprocess, 'run', lambda argv, **kwargs: calls.append((argv, kwargs)) or SimpleNamespace(returncode=0))
    setup.owner_recovery('platform-owner')
    argv, options = calls[0]
    assert argv == ['/verified/python', '-I', '-B', str(root / 'scripts/auth/manage_auth.py'),
                    'owner-recovery', '--username', 'platform-owner']
    assert trusted == [root / 'scripts/auth/manage_auth.py']
    assert options['cwd'] == root and options['timeout'] == 30
    assert options['stderr'] == setup.subprocess.PIPE
    assert 'stdout' not in options and 'shell' not in options
    assert options['env']['ADLOG_PG_DSN'] == 'host=127.0.0.1 port=5432 dbname=sli user=adlog_user'
    assert options['env']['ADLOG_PG_PASSWORD_FILE'] == str(Path('/synthetic/secrets/runtime_password'))
    assert 'ADLOG_PG_PASSWORD' not in options['env']
    assert 'SLI_PG_ADMIN_PASSWORD_FILE' not in options['env']
    assert 'synthetic-inherited-secret' not in str(calls)


def test_owner_recovery_refuses_redirected_output_before_release_or_database(monkeypatch):
    from deploy.linux import native_setup as setup

    monkeypatch.setattr(setup.sys.stdout, 'isatty', lambda: False)
    monkeypatch.setattr(install, 'inventory', lambda _: pytest.fail('must refuse before inventory'))
    with pytest.raises(RuntimeError, match='native_owner_recovery_terminal_required'):
        setup.owner_recovery('platform-owner')


@pytest.mark.parametrize('root', [False, True])
def test_owner_recovery_cli_requires_root_and_never_runs_setup(monkeypatch, root):
    from deploy.linux import native_setup as setup

    monkeypatch.setattr(setup.os, 'geteuid', lambda: 0 if root else 1000, raising=False)
    calls = []
    monkeypatch.setattr(setup, 'owner_recovery', calls.append)
    monkeypatch.setattr(setup, 'configure', lambda _: pytest.fail('recovery must not reconfigure'))
    monkeypatch.setattr(setup.diagnostics, 'failure', lambda _: None)
    assert setup.main(['--owner-recovery', 'platform-owner']) == (0 if root else 1)
    assert calls == (['platform-owner'] if root else [])


def test_site_port_supports_https443_and_legacy_default():
    site = ch.parse_site('domain_fqdn = "sli.example.invalid"\nbind = "192.0.2.10"\nhttps_port = 443')
    assert install.runtime_settings(site)['health_url'] == 'https://192.0.2.10:443/api/health/ready'
    assert install.runtime_settings(site)['https_port'] == 443
    assert install.runtime_settings(ch.parse_site(''))['health_url'] == 'https://127.0.0.1:8443/api/health/ready'


@pytest.mark.parametrize('port', ['0', '65536', 'true', '"443"'])
def test_site_rejects_invalid_https_port(port):
    with pytest.raises(ValueError, match='native_site_port_invalid'):
        ch.parse_site('https_port = ' + port)


def test_privileged_api_port_grants_only_bind_capability():
    config = {'profiles': ['light'], 'radius_pilot': False, 'bind': '192.0.2.10',
              'health_url': 'https://192.0.2.10:443/api/health/ready', 'https_port': 443}
    units = runtime.dotnet_units("test", config)
    assert 'User=sli-api\n' in units['sli-dotnet-api.service']
    assert 'CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n' in units['sli-dotnet-api.service']
    assert 'AmbientCapabilities=CAP_NET_BIND_SERVICE\n' in units['sli-dotnet-api.service']
    for name, body in units.items():
        if name != 'sli-dotnet-api.service':
            assert 'CAP_NET_BIND_SERVICE' not in body


def test_launch_uses_configured_https_port(monkeypatch):
    monkeypatch.setattr(runtime, 'release', lambda: (Path('/release'), {'python': '/python'}, 'digest'))
    monkeypatch.setattr(runtime, 'configuration', lambda: {
        'profiles': ['light'], 'radius_pilot': False, 'bind': '192.0.2.10',
        'health_url': 'https://192.0.2.10:443/api/health/ready', 'https_port': 443})
    monkeypatch.setenv('CREDENTIALS_DIRECTORY', '/synthetic')
    monkeypatch.setattr(runtime.os, 'chdir', lambda path: None)
    calls = []
    monkeypatch.setattr(runtime.os, 'execve', lambda *args: calls.append(args))
    runtime.launch('api')
    assert calls[0][1][-4:] == ['--host', '192.0.2.10', '--port', '443']


def test_runtime_configuration_accepts_443_and_rejects_mismatched_health_url(tmp_path, monkeypatch):
    path = tmp_path / 'runtime.json'
    monkeypatch.setattr(runtime, 'CONFIG', path)
    monkeypatch.setattr(runtime, 'trusted', lambda path: path.read_bytes())
    config = {'schema_version': 1, 'profiles': ['light'], 'radius_pilot': False,
              'bind': '192.0.2.10', 'https_port': 443, 'health_url': 'https://192.0.2.10:443/api/health/ready'}
    path.write_text(json.dumps(config))
    assert runtime.configuration()['https_port'] == 443
    path.write_text(json.dumps(dict(config, health_url='https://192.0.2.10:8443/api/health/ready')))
    with pytest.raises(runtime.RuntimeErrorCode, match='native_health_url_invalid'):
        runtime.configuration()


@pytest.mark.parametrize('bind,health', [('0.0.0.0', '127.0.0.1'), ('::', '[::1]'),
                                       ('192.0.2.10', '192.0.2.10'), ('::1', '[::1]')])
def test_wildcard_and_restricted_binds_have_reachable_health_urls(monkeypatch, bind, health):
    config = install.runtime_settings(ch.parse_site(f'bind = "{bind}"\nhttps_port = 443'))
    assert config['bind'] == bind
    assert config['health_url'] == f'https://{health}:443/api/health/ready'
    monkeypatch.setattr(runtime, 'document', lambda _: config)
    assert runtime.configuration() == config


@pytest.mark.parametrize('bind', ['0.0.0.0', '::'])
def test_runtime_cli_accepts_wildcard_without_using_it_as_health_destination(monkeypatch, bind):
    configs = []
    monkeypatch.setattr(runtime.os, 'geteuid', lambda: runtime.ROOT_UID, raising=False)
    monkeypatch.setattr(runtime.os, 'umask', lambda _: None)
    monkeypatch.setattr(runtime, 'configure', configs.append)
    assert runtime.main(['configure', '--bind', bind]) == 0
    assert configs[0]['health_url'] == ('https://127.0.0.1:8443/api/health/ready' if bind == '0.0.0.0'
                                      else 'https://[::1]:8443/api/health/ready')


def test_setup_wildcard_keeps_name_and_resolved_ip_in_tls_names(monkeypatch):
    from deploy.linux import native_setup as setup
    monkeypatch.setattr(setup.socket, 'getaddrinfo', lambda *args, **kwargs: [
        (2, 1, 6, '', ('192.0.2.10', 443))])
    site = setup.settings(server='sli.example.invalid', port=443, mode='docker')
    assert site['server_name'] == 'sli.example.invalid'
    assert site['bind'] == '0.0.0.0'
    assert setup.tls_names(site) == ['sli.example.invalid', '192.0.2.10', 'localhost', '127.0.0.1', '::1']
    assert ch.parse_site(setup.render_site(site)) == site


def test_setup_accepts_ip_only_and_noninteractive_flags():
    from deploy.linux import native_setup as setup
    site = setup.settings(server='192.0.2.10', port=443, mode='docker')
    assert site['bind'] == '0.0.0.0' and site['server_name'] == '192.0.2.10'
    assert setup.url(site) == 'https://192.0.2.10'
    site = setup.settings(server='2001:db8::10', port=9443, mode='native')
    assert setup.url(site) == 'https://[2001:db8::10]:9443'


def test_default_bind_preflight_checks_ipv6_port_too(monkeypatch):
    import socket
    from contextlib import nullcontext
    from types import SimpleNamespace

    from deploy.linux import native_setup as setup
    # Model Linux's occupied IPv6 port independently of Windows port-sharing
    # semantics. Real IPv4/IPv6 acceptance is covered by the listener tests.
    def port(family, kind):
        def bind(address):
            if family == socket.AF_INET6 and address == ('::', 443):
                raise OSError('synthetic IPv6 port occupied')
        return nullcontext(SimpleNamespace(bind=bind, setsockopt=lambda *args: None))
    monkeypatch.setattr(socket, 'has_dualstack_ipv6', lambda: True)
    monkeypatch.setattr(socket, 'socket', port)
    monkeypatch.setattr(setup.host, 'port_listeners', lambda port: [])
    with pytest.raises(RuntimeError, match='native_setup_port_busy'):
        setup.check_port({'bind': '0.0.0.0', 'https_port': 443})


def test_busy_https_port_names_listener_and_repair_command(monkeypatch, capsys):
    import errno
    from contextlib import nullcontext
    from types import SimpleNamespace

    from deploy.linux import native_setup as setup

    def busy(_):
        raise OSError(errno.EADDRINUSE, 'synthetic private socket error')

    def ss(argv):
        assert argv == ['ss', '-H', '-ltnp', 'sport = :443']
        return 'LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=1234,fd=6),("bad;name",pid=9,fd=8))'

    monkeypatch.setattr(setup.socket, 'socket', lambda *args: nullcontext(SimpleNamespace(bind=busy)))
    monkeypatch.setattr(setup.host, 'run', ss)
    with pytest.raises(RuntimeError, match='native_setup_port_busy') as caught:
        setup.check_port({'bind': '192.0.2.10', 'https_port': 443})
    setup.diagnostics.failure(caught.value)
    message = capsys.readouterr().err
    assert 'HTTPS port 443' in message and 'nginx (PID 1234)' in message
    assert "sudo ss -ltnp 'sport = :443'" in message and 'sudo sli-setup --port' in message
    assert 'private socket error' not in message and 'bad;name' not in message


@pytest.mark.parametrize('server', ['x;touch /tmp/x', 'https://sli.example.invalid', '-bad', 'name\nsecond', '0.0.0.0'])
def test_setup_refuses_invalid_names_before_commands(server):
    from deploy.linux import native_setup as setup
    with pytest.raises(ValueError):
        setup.settings(server=server, port=443, mode='docker')


def test_setup_repeat_preserves_configuration_and_rejects_requested_changes():
    from deploy.linux import native_setup as setup
    site = setup.settings(server='192.0.2.10', port=443, mode='docker')
    assert setup.requested_site(site, server=None, bind=None, port=None, mode=None) == site
    with pytest.raises(RuntimeError, match='native_setup_configuration_conflict'):
        setup.requested_site(site, server=None, bind=None, port=9443, mode=None)


def test_setup_errors_are_human_readable_and_do_not_echo_private_details(capsys, monkeypatch):
    from deploy.linux import native_diagnostics as diag
    logged = []
    monkeypatch.setattr(diag, 'log_code', logged.append)
    diag.failure(RuntimeError('native_database_space_insufficient'))
    assert logged == ['native_database_space_insufficient']
    assert '20 GiB' in capsys.readouterr().err
    diag.failure(RuntimeError('private password from a subprocess'))
    assert 'private password' not in capsys.readouterr().err
    assert logged[-1] == 'native_setup_failed'


@pytest.fixture
def setup_host(tmp_path, monkeypatch):
    from contextlib import nullcontext
    from types import SimpleNamespace

    from deploy.linux import native_setup as setup
    state = tmp_path / 'state'
    state.mkdir()
    site_path = tmp_path / 'site.toml'
    (state / 'pending-release.json').write_text(json.dumps({'release': 'beta'}))
    root = tmp_path / 'release'
    root.mkdir()
    calls = []
    monkeypatch.setattr(setup.platform, 'freedesktop_os_release', lambda: {'ID': 'debian', 'VERSION_ID': '13'})
    monkeypatch.setattr(setup.platform, 'machine', lambda: 'x86_64')
    monkeypatch.setattr(setup.install, 'STATE', state)
    monkeypatch.setattr(setup.install, 'SITE', site_path)
    def trusted(path):
        if path.name == 'clickhouse-package-mode':
            return b'docker'
        if path.name == 'tls_ca':
            return b'synthetic public CA'
        return path.read_bytes()
    monkeypatch.setattr(setup.install, 'trusted', trusted)
    monkeypatch.setattr(setup.ssl, 'PEM_cert_to_DER_cert', lambda text: b'synthetic DER certificate')
    monkeypatch.setattr(setup.install, 'inventory', lambda release: (root, {'python': '/accepted/python'}, 'digest'))
    monkeypatch.setattr(setup.install, 'environment', dict)
    monkeypatch.setattr(setup.install, 'CURRENT', root)
    monkeypatch.setattr(setup.install, 'trusted_path', lambda path: path)
    monkeypatch.setattr(setup.install, 'wait_api', lambda config: None)
    monkeypatch.setattr(runtime, 'configuration', lambda: {
        'health_url': 'https://127.0.0.1:443/api/health/ready'})
    monkeypatch.setattr(setup.host, 'administrative_lock', nullcontext)
    def write(path, body, *args):
        if path.endswith('/tls-ca.crt'):
            return
        calls.append('write-site')
        site_path.write_text(body)
    def prepare(uuid, *, directory):
        calls.append(('prepare', uuid, directory))
        (state / 'host-prepared.json').write_text(json.dumps({'uuid': uuid, 'directory': directory}))
    check_setup_units = setup.host.Host(tmp_path / 'host').check_setup_units
    machine = SimpleNamespace(write=write, prepare=prepare, receipt=lambda: calls.append('receipt'),
                              select_database_directory=lambda **kwargs: '/var/lib/sli-db',
                              check_setup_units=check_setup_units)
    monkeypatch.setattr(setup.host, 'Host', lambda: machine)
    monkeypatch.setattr(setup, 'check_port', lambda site, *, saved: calls.append('check-port'))
    monkeypatch.setattr('builtins.input', lambda prompt: pytest.fail('non-interactive mode must not prompt'))
    def command(argv, **kwargs):
        calls.append(argv)
        if argv[0] == '/usr/sbin/sli-native-install':
            (state / 'installed.json').write_text(json.dumps({'release': str(root)}))
            (state / 'package-install.json').write_text(json.dumps({'status': 'configured',
                'site_sha256': setup.install.site_digest(ch.parse_site(site_path.read_text()))}))
        return json.dumps('admin') if '--initial-admin' in argv else ''
    monkeypatch.setattr(setup, 'command', command)
    args = SimpleNamespace(server='192.0.2.10', bind=None, port=None, clickhouse_mode=None,
                           directory=None, uuid=None, backup_root=None, non_interactive=True)
    return setup, args, calls, state, site_path


@pytest.mark.parametrize('dns', ['local', 'loopback', 'unresolved'])
def test_setup_without_arguments_selects_address_and_never_prompts(setup_host, monkeypatch, capsys, dns):
    setup, args, calls, _, path = setup_host
    args.server, args.non_interactive = None, False
    monkeypatch.setattr(setup.socket, 'getfqdn', lambda: 'sli.example.test')
    monkeypatch.setattr(setup.host, 'run', lambda argv: '192.0.2.10\n')
    addresses = {'local': {'192.0.2.10'}, 'loopback': {'127.0.1.1'}, 'unresolved': set()}
    monkeypatch.setattr(setup, 'resolved_addresses', lambda *args: addresses[dns])

    setup.configure(args)

    site = ch.parse_site(path.read_text())
    address = 'sli.example.test' if dns == 'local' else '192.0.2.10'
    assert site['server_name'] == address and site['https_port'] == 443
    assert ('prepare', None, '/var/lib/sli-db') in calls
    output = capsys.readouterr().out
    assert f"Start-Process 'https://{address}/app'" in output
    assert ('using 192.0.2.10.' in output) == (dns != 'local')


def test_setup_uses_available_port_if_443_busy(setup_host, monkeypatch, capsys):
    setup, args, _, _, path = setup_host
    def check_port(site, *, saved=False):
        if site['https_port'] == 443:
            try:
                raise OSError(setup.errno.EADDRINUSE, 'synthetic occupied port')
            except OSError:
                raise setup.host.GuardError('native_setup_port_busy', 'HTTPS port 443', 'cannot bind', '') from None
        assert site['https_port'] == 0
        return 49152
    monkeypatch.setattr(setup, 'check_port', check_port)

    setup.configure(args)

    assert ch.parse_site(path.read_text())['https_port'] == 49152
    assert "Start-Process 'https://192.0.2.10:49152/app'" in capsys.readouterr().out


def test_unresolved_explicit_name_falls_back_and_can_be_retried(setup_host, monkeypatch):
    setup, args, calls, _, path = setup_host
    args.server = 'sli.example.test'
    monkeypatch.setattr(setup, 'resolved_addresses', lambda *args: set())
    monkeypatch.setattr(setup.host, 'run', lambda argv: '192.0.2.10\n')

    setup.configure(args)
    calls.clear()
    setup.configure(args)

    assert ch.parse_site(path.read_text())['server_name'] == '192.0.2.10'
    assert 'write-site' not in calls


@pytest.mark.parametrize('bind', [None, '192.0.2.10'])
def test_dns_failure_during_tls_preflight_refuses_writes_then_setup_accepts_ip(setup_host, monkeypatch, capsys, bind):
    setup, args, calls, state, site = setup_host
    args.server, args.bind = 'sli.example.test', bind

    resolved = iter([True, False])

    def unresolved(*args, **kwargs):
        if next(resolved):
            return [(2, 1, 6, '', ('192.0.2.10', 443))]
        raise setup.socket.gaierror('synthetic resolver output')

    monkeypatch.setattr(setup.socket, 'getaddrinfo', unresolved)
    with pytest.raises(RuntimeError, match='native_setup_dns_failed') as caught:
        setup.configure(args)
    setup.diagnostics.failure(caught.value)
    message = capsys.readouterr().err
    assert 'sli.example.test' in message and 'sudo sli-setup --server <IP>' in message
    assert 'synthetic resolver output' not in message
    assert not site.exists() and not (state / 'host-prepared.json').exists()
    assert calls == ['check-port']
    args.server = '192.0.2.10'
    setup.configure(args)
    assert ch.parse_site(site.read_text())['server_name'] == args.server


def test_foreign_systemd_units_are_named_and_left_intact_before_retry(setup_host, tmp_path, capsys):
    setup, args, calls, state, site = setup_host
    root = tmp_path / 'host'
    for relative in ['etc/systemd/system/sli-postgresql.service', 'usr/lib/systemd/system/sli-postgresql.service',
                     'etc/systemd/system/sli-dotnet-api.service.d/local.conf']:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('synthetic private configuration')
    with pytest.raises(RuntimeError, match='native_existing_configuration_conflict') as caught:
        setup.configure(args)
    setup.diagnostics.failure(caught.value)
    message = capsys.readouterr().err
    assert '/etc/systemd/system/sli-postgresql.service' in message
    assert '/usr/lib/systemd/system/sli-postgresql.service' in message
    assert '/etc/systemd/system/sli-dotnet-api.service.d' in message
    assert 'sudo sh -c' in message and 'systemctl daemon-reload' in message
    assert 'synthetic private configuration' not in message
    assert not site.exists() and not (state / 'host-prepared.json').exists()
    assert calls == ['check-port']

    for directory in ['etc/systemd/system', 'usr/lib/systemd/system']:
        original = root / directory
        saved = original.with_name('saved-units')
        original.rename(saved)
        assert all(path.read_text() == 'synthetic private configuration'
                   for path in saved.rglob('*') if path.is_file())
    setup.configure(args)
    assert site.exists() and (state / 'installed.json').exists()


@pytest.mark.parametrize('foreign_override', [False, True])
def test_setup_retries_over_its_units_after_partial_configure(setup_host, tmp_path, monkeypatch, foreign_override):
    setup, args, calls, state, site = setup_host
    real_command = setup.command
    machine_root = tmp_path / 'host'
    # Model Debian's metadata for actual rendered files on the Windows runner.
    machine = setup.host.Host().check_setup_units.__self__
    monkeypatch.setattr(machine, 'backup_trusted', lambda path: None)
    original_stat = Path.stat

    def stat(path, *args, **kwargs):
        info = original_stat(path, *args, **kwargs)
        if path.is_relative_to(machine_root) and path.suffix in {'.service', '.target', '.timer', '.mount', '.slice', '.conf'}:
            fields = list(info)
            fields[0], fields[5] = (info.st_mode & ~0o777) | 0o644, 0
            return os.stat_result(fields)
        return info

    monkeypatch.setattr(Path, 'stat', stat)
    args.backup_root = '/srv/sli-backup'

    def first_attempt(argv, **kwargs):
        if argv[0] != '/usr/sbin/sli-native-install':
            return real_command(argv, **kwargs)
        for base, files in [('etc/systemd/system', setup.host.units()), ('usr/lib/systemd/system', runtime.units({}))]:
            folder = machine_root / base
            folder.mkdir(parents=True)
            for name, body in files.items():
                (folder / name).write_bytes(body.encode())
        drop_in = machine_root / 'etc/systemd/system/sli-postgresql.service.d'
        drop_in.mkdir()
        (drop_in / setup.host.BACKUP_DROP_IN).write_bytes(setup.host.BACKUP_DROP_IN_BODY.encode())
        if foreign_override:
            (drop_in / 'local.conf').write_text('[Service]\n')
        (state / 'package-install.json').write_text(json.dumps({
            'schema_version': 1, 'release': 'beta', 'status': 'failed', 'first_start_pending': True,
            'site_sha256': setup.install.site_digest(ch.parse_site(site.read_text()))}))
        raise RuntimeError('synthetic_configure_failure')

    monkeypatch.setattr(setup, 'command', first_attempt)
    with pytest.raises(RuntimeError, match='synthetic_configure_failure'):
        setup.configure(args)
    monkeypatch.setattr(setup, 'command', real_command)
    if foreign_override:
        with pytest.raises(RuntimeError, match='native_existing_configuration_conflict') as caught:
            setup.configure(args)
        assert caught.value.conflict_paths == ('/etc/systemd/system/sli-postgresql.service.d',)
    else:
        setup.configure(args)
        assert (state / 'installed.json').exists()
    assert len([call for call in calls if call == 'write-site']) == 1


@pytest.mark.parametrize('mounted', [True, False])
def test_low_database_space_reports_free_space_and_volume_options(tmp_path, monkeypatch, capsys, mounted):
    from deploy.linux import native_setup as setup

    gib = 1024**3
    machine = setup.host.Host(tmp_path)
    (tmp_path / 'var/lib').mkdir(parents=True)
    monkeypatch.setattr(machine, 'backup_trusted', lambda path: None)
    monkeypatch.setattr(machine, 'backup_free', lambda path: 12 * gib)
    ext4 = '11111111-2222-3333-4444-555555555555'
    unmounted = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'

    def run(argv):
        if argv[0] == 'findmnt':
            return json.dumps({'filesystems': [{'fstype': 'ext4', 'options': 'rw'}]})
        assert argv[0] == 'lsblk'
        devices = [
            {'name': '/dev/sdb1', 'ro': False, 'fstype': 'ext4', 'uuid': ext4,
             'mountpoints': ['/mnt/big'], 'fsavail': 280 * gib},
            {'name': '/dev/sdc1', 'ro': False, 'fstype': 'ext4', 'uuid': unmounted,
             'mountpoints': [None], 'size': 256 * gib},
            {'name': '/dev/sdd1', 'ro': False, 'fstype': 'xfs', 'mountpoints': ['/mnt/extra'], 'fsavail': 240 * gib},
            {'name': '/dev/sde1', 'ro': True, 'fstype': 'xfs', 'mountpoints': ['/mnt/readonly'], 'fsavail': 1024 * gib},
        ] if mounted else [{'name': '/dev/sdb', 'ro': False, 'type': 'disk', 'size': 280 * gib}]
        return json.dumps({'blockdevices': devices})

    monkeypatch.setattr(setup.host, 'run', run)
    with pytest.raises(RuntimeError, match='native_database_space_insufficient') as caught:
        machine.validate_database_directory('/var/lib/sli-db')
    setup.diagnostics.failure(caught.value)
    message = capsys.readouterr().err
    assert '/var/lib/sli-db: 12.0 GiB free (20 GiB required)' in message
    if mounted:
        assert '/mnt/big (280.0 GiB free)' in message and f'--uuid {ext4}' in message
        assert '/dev/sdc1 (256.0 GiB capacity, unmounted)' in message and f'--uuid {unmounted}' in message
        assert '--directory /mnt/extra' in message
    else:
        assert '/dev/sdb (280.0 GiB capacity, no detected filesystem)' in message
        assert 'verify it is unused' in message
    assert '/mnt/readonly' not in message and not (tmp_path / 'var/lib/sli-db').exists()


def test_setup_fresh_then_repeat_preserves_site_and_never_reprovisions(setup_host, capsys):
    setup, args, calls, _, path = setup_host
    setup.configure(args)
    original = path.read_bytes()
    site = ch.parse_site(path.read_text())
    assert site['https_port'] == 443 and site['agents'] is True and site['owner_setup'] is True
    provision = next(call for call in calls if isinstance(call, list) and 'deploy.linux.sli_secrets' in call)
    assert provision.count('--tls-name') == 4  # Server IP plus health loopbacks.
    assert '--agents' in provision and '--offline-root-dir' in provision
    output = capsys.readouterr().out
    assert 'https://192.0.2.10/app' in output
    assert 'Логин admin, пароль admin — смените при первом входе.' in output
    calls.clear()
    setup.configure(args)
    assert path.read_bytes() == original
    assert 'Login admin, password admin — change it at first sign-in.' in capsys.readouterr().out
    assert 'write-site' not in calls and not any(isinstance(call, tuple) for call in calls)
    assert not any('ensure' in call for call in calls if isinstance(call, list))


def test_repeat_setup_waits_for_health_before_returning(setup_host, monkeypatch):
    setup, args, calls, _, _ = setup_host
    setup.configure(args)
    calls.clear()
    def wait_api(config):
        assert config['health_url'] == 'https://127.0.0.1:443/api/health/ready'
        raise RuntimeError('native_install_api_unready')
    monkeypatch.setattr(setup.install, 'wait_api', wait_api)
    with pytest.raises(RuntimeError, match='native_setup_health_failed'):
        setup.configure(args)
    assert ['systemctl', 'start', 'sli.target'] in calls


def test_setup_health_polls_refusal_and_http503_until_ready(tmp_path, monkeypatch):
    from contextlib import nullcontext
    from types import SimpleNamespace
    from urllib.error import HTTPError, URLError

    from deploy.linux import native_setup as setup
    address = 'https://127.0.0.1:8443/api/health/ready'
    results = iter([URLError(ConnectionRefusedError()), HTTPError(address, 503, 'private', None, None),
                    SimpleNamespace(status=200)])
    context = object()
    def create_context(*, cafile):
        assert cafile == str(tmp_path / 'tls_ca')
        return context
    def urlopen(url, **kwargs):
        assert url == address and kwargs == {'context': context, 'timeout': 3}
        result = next(results)
        if isinstance(result, Exception):
            raise result
        return nullcontext(result)
    monkeypatch.setattr(install, 'SECRETS', tmp_path)
    monkeypatch.setattr(setup.ssl, 'create_default_context', create_context)
    monkeypatch.setattr('urllib.request.urlopen', urlopen)
    monkeypatch.setattr(install.time, 'monotonic', lambda: 0)
    sleeps = []
    monkeypatch.setattr(install.time, 'sleep', sleeps.append)
    setup.wait_api({'health_url': address})
    assert list(results) == []
    assert sleeps == [30, 30]


def test_setup_health_deadline_has_fixed_error(monkeypatch):
    from urllib.error import URLError

    from deploy.linux import native_setup as setup
    ticks = iter([0, 1800])
    monkeypatch.setattr(setup.ssl, 'create_default_context', lambda **kwargs: object())
    monkeypatch.setattr(install.time, 'monotonic', lambda: next(ticks))
    def urlopen(*args, **kwargs):
        raise URLError(ConnectionRefusedError('private'))
    monkeypatch.setattr('urllib.request.urlopen', urlopen)
    monkeypatch.setattr(install.time, 'sleep', lambda _: pytest.fail('deadline already expired'))
    with pytest.raises(RuntimeError, match='^native_setup_health_failed:RuntimeError$'):
        setup.wait_api({'health_url': 'https://127.0.0.1:8443/api/health/ready'})


@pytest.mark.parametrize('error,reason', [
    (OSError('private password'), 'OSError'),
    (runtime.RuntimeErrorCode('private password'), 'RuntimeErrorCode'),
    (type('private\npassword', (Exception,), {})('private token'), 'Exception'),
])
def test_setup_health_reports_only_safe_reason_class(monkeypatch, capsys, error, reason):
    from deploy.linux import native_diagnostics as diag
    from deploy.linux import native_setup as setup

    def wait_api(config):
        raise error
    monkeypatch.setattr(install, 'wait_api', wait_api)
    logged = []
    monkeypatch.setattr(diag, 'log_code', logged.append)
    with pytest.raises(RuntimeError) as caught:
        setup.wait_api({'health_url': 'https://127.0.0.1:443/api/health/ready'})
    expected = 'native_setup_health_failed:' + reason
    assert str(caught.value) == expected
    assert caught.value.__suppress_context__
    diag.failure(caught.value)
    assert logged == [expected]
    assert capsys.readouterr().err.strip() == diag.MESSAGES['native_setup_health_failed']


def test_setup_health_passes_untrusted_tls_code_to_user(monkeypatch, capsys):
    from deploy.linux import native_diagnostics as diag
    from deploy.linux import native_setup as setup

    def wait_api(config):
        raise RuntimeError('native_api_tls_untrusted')
    monkeypatch.setattr(install, 'wait_api', wait_api)
    monkeypatch.setattr(diag, 'log_code', lambda code: None)
    with pytest.raises(RuntimeError, match='^native_api_tls_untrusted$') as caught:
        setup.wait_api({'health_url': 'https://127.0.0.1:443/api/health/ready'})
    diag.failure(caught.value)
    assert capsys.readouterr().err.strip() == diag.MESSAGES['native_api_tls_untrusted']


@pytest.mark.parametrize('option,value', [('port', 9443), ('bind', '192.0.2.11')])
def test_setup_changed_address_or_port_fails_before_any_mutation(setup_host, option, value):
    setup, args, calls, _, path = setup_host
    setup.configure(args)
    before = path.read_bytes()
    calls.clear()
    setattr(args, option, value)
    with pytest.raises(RuntimeError, match='native_setup_configuration_conflict'):
        setup.configure(args)
    assert not calls and path.read_bytes() == before


def test_setup_dns_generates_tls_for_server_name_and_local_ip(setup_host, monkeypatch):
    setup, args, calls, _, _ = setup_host
    args.server, args.bind = 'sli.example.test', '192.0.2.10'
    monkeypatch.setattr(setup, 'resolved_addresses', lambda *args: {'192.0.2.10'})
    setup.configure(args)
    provision = next(call for call in calls if isinstance(call, list) and 'deploy.linux.sli_secrets' in call)
    names = [provision[i + 1] for i, arg in enumerate(provision) if arg == '--tls-name']
    assert names == ['sli.example.test', '192.0.2.10']


def test_setup_does_not_select_clickhouse_for_new_install(setup_host):
    setup, args, calls, _, path = setup_host
    setup.configure(args)
    assert 'clickhouse_mode' not in path.read_text()


def test_setup_uuid_option_reaches_host_without_directory_preparation(setup_host):
    setup, args, calls, _, _ = setup_host
    args.uuid = '11111111-2222-3333-4444-555555555555'
    setup.configure(args)
    assert ('prepare', '11111111-2222-3333-4444-555555555555', '/var/lib/sli-db') in calls


def test_setup_refuses_interrupted_install_before_provisioning(setup_host):
    setup, args, calls, state, _ = setup_host
    (state / 'package-install.json').write_text(json.dumps({'status': 'failed'}))
    with pytest.raises(RuntimeError, match='native_install_interrupted_requires_recovery'):
        setup.configure(args)
    assert not calls


@pytest.mark.parametrize('status', ['failed', 'configuring'])
def test_setup_resumes_first_start_without_reprovisioning(setup_host, status):
    setup, args, calls, state, site_path = setup_host
    setup.configure(args)
    original = site_path.read_bytes()
    receipt_path = state / 'package-install.json'
    receipt = json.loads(receipt_path.read_text())
    receipt['status'] = status
    receipt_path.write_text(json.dumps(receipt))
    calls.clear()
    setup.configure(args)
    assert json.loads(receipt_path.read_text())['status'] == 'configured'
    assert site_path.read_bytes() == original
    assert not any(isinstance(call, tuple) or call == 'write-site' for call in calls)
    assert not any('ensure' in call for call in calls if isinstance(call, list))


@pytest.fixture
def first_start_install(tmp_path, monkeypatch):
    """Run the real coordinator; emulate only host/daemon and atomic I/O boundaries."""
    from contextlib import nullcontext
    from types import SimpleNamespace

    from deploy.linux import native_backup, native_host
    state, root = tmp_path / 'state', tmp_path / 'release'
    state.mkdir()
    root.mkdir()
    monkeypatch.setattr(install, 'STATE', state)
    monkeypatch.setattr(install, 'CURRENT', SimpleNamespace(
        exists=lambda: False, is_symlink=lambda: False, resolve=lambda **kwargs: root))
    monkeypatch.setattr(install, 'select', lambda path: None)
    monkeypatch.setattr(install, 'atomic', lambda path, value: path.write_text(json.dumps(value)))
    monkeypatch.setattr(install, 'trusted', lambda path: path.read_bytes())
    manifest = {'python': '/accepted/python', 'clickhouse_version': ch.endpoint('history', 'native').version}
    monkeypatch.setattr(install, 'inventory', lambda release: (root, manifest, 'digest'))
    monkeypatch.setattr(install.platform, 'freedesktop_os_release', lambda: {'ID': 'debian', 'VERSION_ID': '13'})
    monkeypatch.setattr(install.platform, 'machine', lambda: 'x86_64')
    monkeypatch.setattr(install, 'site_configuration', lambda: {'owner_setup': True, 'domain_fqdn': 'sli.invalid',
                                                               'bind': '192.0.2.10'})
    monkeypatch.setattr(ch, 'configured_mode', lambda: 'native')
    monkeypatch.setattr(native_host, 'MOUNT', str(tmp_path / 'db'))
    monkeypatch.setattr(native_host, 'administrative_lock', nullcontext)
    monkeypatch.setattr(native_host, 'validate_identity', lambda: None)
    calls = []
    monkeypatch.setattr(native_host, 'Host', lambda: SimpleNamespace(
        receipt=lambda: None, configure=lambda: calls.append('host-configure')))
    monkeypatch.setattr(runtime, 'no_transaction', lambda: None)
    monkeypatch.setattr(runtime, 'wait_databases', lambda: None)
    monkeypatch.setattr(runtime, 'configure', lambda config: calls.append('runtime-configure'))
    monkeypatch.setattr(runtime, 'stop_writers', lambda: calls.append('stop-writers'))
    monkeypatch.setattr(runtime, 'configuration', dict)
    monkeypatch.setattr(runtime, 'selected', lambda config: [])
    monkeypatch.setattr(install, 'wait_api', lambda config: calls.append('api-ready'))
    monkeypatch.setattr(install, 'wait_health', lambda: calls.append('healthy'))
    monkeypatch.setattr(install, 'preserve_recovery', lambda *args: calls.append('recovery-saved'))
    monkeypatch.setattr(native_backup, 'configure', lambda: calls.append('backup-configured'))
    control = {'fail': True, 'owner': 'unclaimed'}
    def command(argv, **kwargs):
        calls.append(argv)
        if argv == ['systemctl', 'start', 'sli-ready.service'] and control['fail']:
            raise RuntimeError('synthetic_first_start_failure')
        if '--initial-admin' in argv and 'check' in argv and control['owner'] != 'unclaimed':
            raise RuntimeError('native_install_command_failed')
    monkeypatch.setattr(install, 'command', command)
    return state, calls, control


@pytest.mark.parametrize('database_exists', [False, True])
def test_retry_after_early_configure_failure_preserves_existing_postgres(first_start_install, monkeypatch, database_exists):
    from deploy.linux import native_host

    state, _, control = first_start_install
    machine = native_host.Host()
    configure = machine.configure
    monkeypatch.setattr(native_host, 'Host', lambda: machine)

    def fail():
        raise RuntimeError('synthetic_host_configure_failure')

    machine.configure = fail
    with pytest.raises(RuntimeError, match='synthetic_host_configure_failure'):
        install.configure('beta')
    machine.configure = configure
    control['fail'] = False
    if database_exists:
        data = Path(native_host.MOUNT) / 'pgdata/PG_VERSION'
        data.parent.mkdir(parents=True)
        data.write_bytes(b'18\n')
        with pytest.raises(RuntimeError, match='native_install_interrupted_requires_recovery'):
            install.configure('beta')
        assert data.read_bytes() == b'18\n'
    else:
        install.configure('beta')
        assert json.loads((state / 'package-install.json').read_text())['status'] == 'configured'


@pytest.mark.parametrize('legacy', [False, True])
def test_install_resumes_failed_first_start_without_reset(first_start_install, legacy):
    state, calls, control = first_start_install
    with pytest.raises(RuntimeError, match='synthetic_first_start_failure'):
        install.configure('beta')
    registry = (state / 'installed.json').read_bytes()
    path = state / 'package-install.json'
    receipt = json.loads(path.read_text())
    assert receipt['status'] == 'failed'
    if legacy:
        receipt.pop('first_start_pending', None)
        path.write_text(json.dumps(receipt))
    control['fail'] = False
    calls.clear()
    install.configure('beta')
    assert json.loads(path.read_text())['status'] == 'configured'
    assert (state / 'installed.json').read_bytes() == registry
    assert not {'host-configure', 'runtime-configure', 'warm-schema'} & {c for c in calls if isinstance(c, str)}
    assert not any('migrate' in c or 'ensure' in c for c in calls if isinstance(c, list))
    assert calls.index('healthy') < calls.index('recovery-saved') < calls.index(['systemctl', 'enable', 'sli.target'])


def test_install_refuses_resume_after_owner_activation(first_start_install):
    state, calls, control = first_start_install
    with pytest.raises(RuntimeError, match='synthetic_first_start_failure'):
        install.configure('beta')
    before = (state / 'package-install.json').read_bytes()
    control.update(fail=False, owner='activated')
    calls.clear()
    with pytest.raises(RuntimeError, match='native_install_interrupted_requires_recovery'):
        install.configure('beta')
    assert (state / 'package-install.json').read_bytes() == before
    assert ['systemctl', 'start', 'sli-ready.service'] not in calls


@pytest.mark.parametrize('key,value', [('first_start_pending', False), ('site_sha256', 'different'),
                                       ('release', 'other'), ('status', 'unknown')])
def test_install_refuses_resume_with_changed_or_accepted_receipt(first_start_install, key, value):
    state, calls, control = first_start_install
    with pytest.raises(RuntimeError, match='synthetic_first_start_failure'):
        install.configure('beta')
    path = state / 'package-install.json'
    receipt = json.loads(path.read_text())
    receipt[key] = value
    path.write_text(json.dumps(receipt))
    before = path.read_bytes()
    calls.clear()
    control['fail'] = False
    with pytest.raises(RuntimeError, match='native_'):
        install.configure('beta')
    assert path.read_bytes() == before and not calls


def test_uninstall_stops_database_units_after_writers_without_deleting_data(monkeypatch):
    calls = []
    monkeypatch.setattr(install, 'command', lambda argv, **kwargs: calls.append(argv))
    monkeypatch.setattr(runtime, 'stop_writers', lambda: calls.append('writers-stopped'))
    install.remove()
    databases = ['systemctl', 'stop', *runtime.DATABASES]
    assert databases in calls and calls.index('writers-stopped') < calls.index(databases)


def test_package_cli_requires_no_clickhouse_image(tmp_path, monkeypatch):
    from deploy.linux import native_package as package
    captured = []
    monkeypatch.setattr(package, 'build', lambda *args, **kwargs: captured.append(kwargs))
    assert package.main(['--source', str(tmp_path), '--output', str(tmp_path), '--release', 'beta',
                         '--version', '1.0-1~deb13', '--runtime-version', '1.0-1~deb13']) == 0
    assert 'clickhouse_mode' not in captured[0] and 'image_archive' not in captured[0]


@pytest.mark.parametrize('root', [True, False])
def test_reset_admin_password_requires_root_and_does_not_configure(setup_host, monkeypatch, capsys, root):
    from contextlib import nullcontext

    setup, _, calls, _, _ = setup_host
    monkeypatch.setattr(setup.os, 'geteuid', lambda: 0 if root else 1000, raising=False)
    monkeypatch.setattr(setup, 'setup_lock', nullcontext)
    status = setup.main(['--reset-admin-password'])
    output = capsys.readouterr()
    if root:
        assert status == 0
        (command,) = calls
        assert command[-3:-1] == ['--initial-admin', 'reset']
        assert 'Login admin, password admin — change it at first sign-in.' in output.out
    else:
        assert status == 1
        assert not calls
        assert not output.out


def test_staged_package_needs_one_setup_command_and_preserves_owner_password(setup_host, monkeypatch, capsys):
    from contextlib import nullcontext

    setup, _, calls, state, site = setup_host
    monkeypatch.setattr(setup.os, 'geteuid', lambda: 0, raising=False)
    monkeypatch.setattr(setup, 'setup_lock', nullcontext)
    monkeypatch.setattr(install, 'atomic', lambda path, value: path.write_text(json.dumps(value)))
    monkeypatch.setattr(setup.socket, 'getfqdn', lambda: 'debian')
    monkeypatch.setattr(setup.host, 'run', lambda argv: '192.0.2.10\n')
    (state / 'pending-release.json').unlink()

    assert install.main(['stage', 'beta']) == 0
    assert not site.exists()
    assert not calls

    assert setup.main([]) == 0
    output = capsys.readouterr().out
    assert "Start-Process 'https://192.0.2.10/app'" in output
    assert 'Login admin, password admin' in output
    original = site.read_bytes()
    calls.clear()

    command = setup.command

    def established_owner(argv, **kwargs):
        result = command(argv, **kwargs)
        if '--initial-admin' in argv:
            assert argv[-2] == 'status'
            return ''
        return result

    monkeypatch.setattr(setup, 'command', established_owner)
    assert setup.main([]) == 0
    assert 'Login admin, password admin' not in capsys.readouterr().out
    assert site.read_bytes() == original
    assert 'write-site' not in calls
    assert not any(isinstance(call, list) and call[0] == '/usr/sbin/sli-native-install' for call in calls)

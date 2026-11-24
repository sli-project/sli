import hashlib
import json
import os
import shutil
import subprocess
import tarfile

import pytest

from deploy.linux import build_beta_kit as kit, native_plugins


@pytest.mark.parametrize('tampered', [False, True])
def test_copy_agent_checks_packaged_bytes(tmp_path, tampered):
    source = tmp_path / 'agent'
    source.mkdir()
    payloads = {'SliAgent.msi': b'synthetic MSI', 'SliAgent-publish-win-x64.zip': b'synthetic ZIP'}
    for name, body in payloads.items():
        (source / name).write_bytes(body)
    sums = ''.join(f'{hashlib.sha256(body).hexdigest()}  {name}\n' for name, body in payloads.items())
    (source / 'SHA256SUMS').write_text(sums, encoding='utf-8-sig')
    destination = tmp_path / 'installers'
    if tampered:
        (source / 'SliAgent.msi').write_bytes(b'changed MSI')
        with pytest.raises(ValueError, match='Agent SHA-256 verification failed'):
            kit.include_agent(source, destination)
    else:
        kit.include_agent(source, destination)
        assert {path.name: path.read_bytes() for path in destination.iterdir()} == {
            **payloads, 'SHA256SUMS': sums.encode('ascii'),
        }


def test_archive_contains_the_installer_and_verified_kit_bytes(tmp_path):
    files = {'install-beta-kit': b'synthetic script', 'sli-fixture.deb': b'synthetic package',
             'manifest.json': b'{}', 'SHA256SUMS': b'synthetic checksums'}
    for name, body in files.items():
        (tmp_path / name).write_bytes(body)

    kit.archive_kit(tmp_path)

    with tarfile.open(tmp_path / 'sli-debian-beta-kit.tar.gz') as archive:
        assert {member.name: archive.extractfile(member).read() for member in archive} == {
            'sli-debian-beta-kit/' + name: body for name, body in files.items()
        }


@pytest.mark.parametrize('change', [None, 'package', 'commit', 'unlisted'])
def test_verify_offline_kit_checks_the_archived_files_and_source(tmp_path, change):
    commit = 'a' * 40
    files = {'install-beta-kit': b'installer', 'remove-beta-kit': b'remover', 'sli-fixture.deb': b'package'}
    for name, body in files.items():
        (tmp_path / name).write_bytes(body)
    entries = {name: {'filename': name, 'sha256': kit.sha256(tmp_path / name)} for name in files}
    kit.write_json(tmp_path / 'manifest.json', {
        'git_commit': 'b' * 40 if change == 'commit' else commit,
        'target': 'debian-13-amd64', 'packages': [entries['sli-fixture.deb']],
        'installer': entries['install-beta-kit'], 'remover': entries['remove-beta-kit'],
    })
    sums = {name: row['sha256'] for name, row in entries.items()}
    sums['manifest.json'] = kit.sha256(tmp_path / 'manifest.json')
    (tmp_path / 'SHA256SUMS').write_text(''.join(f'{digest}  {name}\n' for name, digest in sums.items()))
    if change == 'package':
        (tmp_path / 'sli-fixture.deb').write_bytes(b'changed')
    elif change == 'unlisted':
        (tmp_path / 'unlisted.deb').write_bytes(b'unlisted')
    kit.archive_kit(tmp_path)
    archive = tmp_path / 'sli-debian-beta-kit.tar.gz'
    if change:
        reason = 'selected commit and target' if change == 'commit' else 'do not match SHA256SUMS'
        with pytest.raises(ValueError, match=reason):
            kit.verify_offline_kit(archive, commit)
    else:
        kit.verify_offline_kit(archive, commit)


@pytest.mark.parametrize('claim_present', [False, True])
def test_verify_offline_kit_rejects_original_runtime_under_compatibility_claim(tmp_path, claim_present):
    commit = 'a' * 40
    original = 'sli-runtime-cp3146-n03-20261026_3.14.6-1~deb13_amd64.deb'
    files = {original: b'original runtime fixture', 'install-beta-kit': b'installer',
             'remove-beta-kit': b'remover'}
    for name, body in files.items():
        (tmp_path / name).write_bytes(body)
    entries = {name: {'filename': name, 'sha256': kit.sha256(tmp_path / name)} for name in files}
    manifest = {
        'git_commit': commit,
        'target': 'debian-13-amd64',
        'packages': [{**entries[original], 'package': 'sli-runtime-cp3146-n03-20261026',
                      'version': '3.14.6-1~deb13', 'architecture': 'amd64'}],
        'installer': entries['install-beta-kit'],
        'remover': entries['remove-beta-kit'],
    }
    if claim_present:
        manifest['runtime_delivery'] = kit.N03_RUNTIME_DELIVERY
    kit.write_json(tmp_path / 'manifest.json', manifest)
    sums = {name: row['sha256'] for name, row in entries.items()}
    sums['manifest.json'] = kit.sha256(tmp_path / 'manifest.json')
    (tmp_path / 'SHA256SUMS').write_text(''.join(f'{digest}  {name}\n' for name, digest in sums.items()))
    kit.archive_kit(tmp_path)
    reason = 'the package inventory' if claim_present else 'the selected commit'
    with pytest.raises(ValueError, match=f'[Rr]untime compatibility declaration does not match {reason}'):
        kit.verify_offline_kit(tmp_path / 'sli-debian-beta-kit.tar.gz', commit,
                              expected_runtime_delivery=kit.N03_RUNTIME_DELIVERY)


def test_copies_only_pinned_debs_and_leaves_cache_intact(tmp_path):
    cache = tmp_path / 'cache'
    cache.mkdir()
    output = tmp_path / 'kit'
    output.mkdir()
    pinned = cache / 'libpq5_1%3a18.6-1_amd64.deb'
    pinned.write_bytes(b'pinned package bytes')
    (cache / 'libpq5_older_amd64.deb').write_bytes(b'unrelated .deb')

    kit.copy_inputs(cache, output, {'libpq5_18.6-1_amd64.deb': hashlib.sha256(pinned.read_bytes()).hexdigest()})

    assert {path.name: path.read_bytes() for path in output.iterdir()} == {
        'libpq5_18.6-1_amd64.deb': b'pinned package bytes',
    }
    assert pinned.read_bytes() == b'pinned package bytes'


def test_modified_cache_package_aborts_before_copy(tmp_path):
    cache = tmp_path / 'cache'
    cache.mkdir()
    output = tmp_path / 'kit'
    output.mkdir()
    trusted = cache / 'libpq5_trusted_amd64.deb'
    trusted.write_bytes(b'pinned')
    (cache / 'postgresql-18_bad_amd64.deb').write_bytes(b'modified')

    with pytest.raises(ValueError, match='postgresql-18_bad_amd64.deb'):
        kit.copy_inputs(cache, output, {
            trusted.name: hashlib.sha256(trusted.read_bytes()).hexdigest(),
            'postgresql-18_bad_amd64.deb': hashlib.sha256(b'original').hexdigest(),
        })

    assert not list(output.iterdir())


@pytest.mark.parametrize(('filename', 'asset_name'), [
    ('sli-runtime-fixture_1~deb13_amd64.deb', 'sli-runtime-fixture_1.deb13_amd64.deb'),
    ('sli-runtime-fixture_1-deb13_amd64.deb', 'sli-runtime-fixture_1-deb13_amd64.deb'),
    ('.sli-runtime fixture.deb.', 'sli-runtime.fixture.deb'),
])
def test_github_release_asset_name(filename, asset_name):
    assert kit.github_release_asset_name(filename) == asset_name


@pytest.mark.parametrize('tampered', [False, True])
def test_fetch_inputs_verifies_packages_before_they_enter_cache(tmp_path, monkeypatch, tampered):
    runtime = b'pinned runtime'
    package = b'pinned Debian package'
    row = {'name': 'libfixture', 'filename': 'pool/main/libf/libfixture/libfixture_1_amd64.deb',
           'sha256': hashlib.sha256(package).hexdigest(), 'version': '1',
           'url': 'http://deb.debian.org/debian/pool/main/libf/libfixture/libfixture_1_amd64.deb'}
    runtime_version = '1~deb13'
    pins = {'roots': [], 'packages': [row], 'dependency_edges': [], 'captured_utc': '2020-01-02T03:04:05Z',
            'runtime_build': {'id': 'fixture', 'version': runtime_version, 'debian_artifacts': [], 'debian_runtime': [row]},
            'runtime_artifact': {'runtime_id': 'fixture', 'version': runtime_version,
                                 'sha256': hashlib.sha256(runtime).hexdigest()}}
    urls = []

    def download(argv):
        destination, url = argv[-2:]
        urls.append(url)
        if '/beta-input-' in url:
            destination.write_bytes(runtime)
        elif url.startswith('https://deb.debian.org/'):
            raise subprocess.CalledProcessError(22, argv)
        else:
            destination.write_bytes(b'tampered package' if tampered else package)

    monkeypatch.setattr(kit, 'command', download)
    name = 'libfixture_1_amd64.deb'
    if tampered:
        with pytest.raises(ValueError, match=f'Package SHA-256 mismatch: {name}'):
            kit.fetch_inputs(tmp_path, pins)
        assert not (tmp_path / name).exists()
    else:
        kit.fetch_inputs(tmp_path, pins)
        assert (tmp_path / name).read_bytes() == package
    assert (tmp_path / 'sli-runtime-fixture_1~deb13_amd64.deb').read_bytes() == runtime
    assert urls == ['https://github.com/sli-project/sli/releases/download/'
                    'beta-input-fixture/sli-runtime-fixture_1.deb13_amd64.deb',
                    row['url'].replace('http:', 'https:'),
                    f"https://snapshot.debian.org/archive/debian/20200102T030405Z/{row['filename']}"]
    assert list(tmp_path.glob('.beta-download-*')) == []


def test_builder_probes_postgresql_with_its_loader_path_and_no_database_environment(tmp_path, monkeypatch):
    calls = []

    def probe(argv, *, env, **kwargs):
        calls.append(argv)
        assert env['LD_LIBRARY_PATH'] == str(tmp_path / 'lib')
        assert 'PGHOST' not in env
        return subprocess.CompletedProcess(argv, 0, stdout=f'{argv[0].name} (PostgreSQL) 18.6\n', stderr='')

    monkeypatch.setenv('PGHOST', 'example.test')
    monkeypatch.setenv('LD_LIBRARY_PATH', str(tmp_path / 'lib'))
    monkeypatch.setattr(kit.subprocess, 'run', probe)
    env = kit.postgres_environment(tmp_path)
    assert env['LC_ALL'] == 'C.UTF-8'
    assert calls == [[tmp_path / name, '--version'] for name in ('initdb', 'postgres', 'pg_isready')]


@pytest.mark.parametrize('failure', ['missing', 'loader', 'wrong_major'])
def test_builder_reports_unusable_postgresql_before_export(tmp_path, monkeypatch, failure):
    def probe(argv, **kwargs):
        if failure == 'missing':
            raise FileNotFoundError(2, 'No such file or directory')
        if failure == 'loader':
            return subprocess.CompletedProcess(argv, 127, stdout='', stderr='libicuuc.so.76: cannot open shared object file')
        return subprocess.CompletedProcess(argv, 0, stdout='initdb (PostgreSQL) 17.1\n', stderr='')

    monkeypatch.setattr(kit.platform, 'system', lambda: 'Linux')
    monkeypatch.setattr(kit.platform, 'machine', lambda: 'x86_64')
    monkeypatch.setattr(kit.os, 'geteuid', lambda: 123, raising=False)
    monkeypatch.setattr(kit.subprocess, 'run', probe)
    expected = {'missing': 'No such file or directory', 'loader': r'libicuuc\.so\.76', 'wrong_major': '17.1'}[failure]

    with pytest.raises(ValueError, match=f'initdb.*{expected}'):
        kit.build(tmp_path, 'HEAD', tmp_path, tmp_path / 'kit', tmp_path / 'pg')
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize('explicit', [False, True])
def test_agent_msi_uses_trusted_manifest_for_cache_and_explicit_path(tmp_path, explicit):
    commit = 'a' * 40
    cache = tmp_path / 'cache'
    cache.mkdir()
    source = tmp_path / 'agent.msi' if explicit else cache / f'SliAgent-{commit}.msi'
    source.write_bytes(b'agent MSI bytes')
    kit.write_json(cache / f'SliAgent-{commit}.msi.json', {
        'source_commit': commit, 'sha256': kit.sha256(source), 'product_version': '26.0.1000',
    })
    work = tmp_path / 'work'
    work.mkdir()

    staged = kit.stage_agent_msi(cache, commit, work, source if explicit else None)
    source.write_bytes(b'changed after verification')

    assert staged.read_bytes() == b'agent MSI bytes'
    assert json.loads(staged.with_suffix('.msi.json').read_text(encoding='utf-8')) == {
        'product_version': '26.0.1000', 'sha256': kit.sha256(staged),
    }


@pytest.mark.parametrize('sdk', ['10.0.113', '10.0.112', None])
def test_hosted_agent_msi_manifest_matches_the_locked_sdk(tmp_path, sdk):
    commit = 'a' * 40
    source = tmp_path / f'SliAgent-{commit}.msi'
    source.write_bytes(b'agent MSI bytes')
    metadata = {'source_commit': commit, 'sha256': kit.sha256(source), 'product_version': '26.0.1000'}
    if sdk is not None:
        metadata['dotnet_sdk'] = sdk
    kit.write_json(tmp_path / f'{source.name}.json', metadata)
    if sdk == '10.0.113':
        assert kit.stage_agent_msi(tmp_path, commit, tmp_path, expected_sdk='10.0.113').read_bytes() == source.read_bytes()
    else:
        with pytest.raises(ValueError, match=r'does not identify \.NET SDK 10\.0\.113'):
            kit.stage_agent_msi(tmp_path, commit, tmp_path, expected_sdk='10.0.113')
        assert not (tmp_path / 'SliAgent.msi').exists()


@pytest.mark.parametrize(('problem', 'message'), [
    ('missing', 'Missing trusted agent MSI manifest'),
    ('hash', 'Agent MSI SHA-256 mismatch'),
    ('commit', 'Agent MSI manifest does not identify source commit'),
    ('version', 'Invalid agent MSI product version'),
])
def test_beta_kit_rejects_unverified_agent_msi(tmp_path, monkeypatch, problem, message):
    commit = 'a' * 40
    cache = tmp_path / 'cache'
    cache.mkdir()
    source = cache / f'SliAgent-{commit}.msi'
    source.write_bytes(b'agent MSI bytes')
    if problem != 'missing':
        kit.write_json(cache / f'{source.name}.json', {
            'source_commit': 'b' * 40 if problem == 'commit' else commit,
            'sha256': '0' * 64 if problem == 'hash' else kit.sha256(source),
            'product_version': '26.0.100000' if problem == 'version' else '26.0.1000',
        })
    monkeypatch.setattr(kit.platform, 'system', lambda: 'Linux')
    monkeypatch.setattr(kit.platform, 'machine', lambda: 'x86_64')
    monkeypatch.setattr(kit.os, 'geteuid', lambda: 1000, raising=False)
    monkeypatch.setattr(kit.os, 'umask', lambda mask: None)
    monkeypatch.setattr(kit, 'postgres_environment', lambda pg_bin: {})
    monkeypatch.setattr(kit, 'git', lambda root, operation, *args: commit if operation == 'rev-parse' else '123')

    def export_commit(root, ref, checkout, archive):
        installer = checkout / 'server-dotnet/src/Sli.Server/Agents/Control/InstallAgent.ps1'
        installer.parent.mkdir(parents=True)
        installer.touch()

    monkeypatch.setattr(kit, 'export_commit', export_commit)
    output = tmp_path / 'kit'
    with pytest.raises(ValueError, match=message):
        kit.build(kit.ROOT, commit, cache, output, tmp_path)

    assert not output.exists()


def test_generated_linux_restore_must_use_hashes_from_the_committed_lock():
    package = {'type': 'Transitive', 'resolved': '1.0', 'contentHash': 'fixture-sha512'}
    original = {'version': 2, 'dependencies': {'net10.0': {'Package': package}}}
    restored = {'version': 2, 'dependencies': {**original['dependencies'], 'net10.0/linux-x64': {'Package': package}}}
    kit.verify_generated_runtime_lock(original, restored)

    restored['dependencies']['net10.0/linux-x64']['Package'] = {**package, 'contentHash': 'other-sha512'}
    with pytest.raises(ValueError, match='not pinned'):
        kit.verify_generated_runtime_lock(original, restored)


def test_generated_restore_refreshes_only_versions_of_existing_local_project_references():
    package = {'type': 'Direct', 'resolved': '1.0', 'contentHash': 'fixture-sha512'}
    entries = {
        'External.Package': package,
        'local.protocol': {'type': 'Project'},
        'local.agent': {'type': 'Project', 'dependencies': {'Local.Protocol': '[1.0, )', 'External.Package': '[1.0, )'}},
    }
    original = {'version': 2, 'dependencies': {'net10.0': entries}}
    current = {**entries, 'local.agent': {'type': 'Project', 'dependencies': {
        'Local.Protocol': '[2.0, )', 'External.Package': '[1.0, )',
    }}}
    restored = {'version': 2, 'dependencies': {'net10.0': current}}
    kit.verify_generated_runtime_lock(original, restored)

    current['local.agent']['dependencies']['External.Package'] = '[2.0, )'
    with pytest.raises(ValueError, match='changed the committed NuGet lock'):
        kit.verify_generated_runtime_lock(original, restored)


@pytest.mark.skipif(not shutil.which('dpkg-deb') or not shutil.which('dotnet'), reason='Linux .NET packaging tools required')
def test_small_commit_builds_valid_debs_and_a_runnable_self_contained_server(tmp_path):
    repo = tmp_path / 'source'
    repo.mkdir()
    subprocess.run(['git', 'init', '-q', repo], check=True)
    (repo / 'Program.cs').write_text('System.Console.WriteLine("beta kit smoke");')
    (repo / 'Sli.Server.csproj').write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'
                                            '<TargetFramework>net10.0</TargetFramework>'
                                            '<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>'
                                            '<OutputType>Exe</OutputType></PropertyGroup></Project>')
    subprocess.run(['dotnet', 'restore', 'Sli.Server.csproj', '--use-lock-file'], cwd=repo, check=True)
    subprocess.run(['git', '-C', repo, 'add', 'Program.cs', 'Sli.Server.csproj', 'packages.lock.json'], check=True)
    subprocess.run(['git', '-C', repo, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.test',
                    'commit', '-qm', 'Initial fixture'], check=True)
    commit = kit.git(repo, 'rev-parse', 'HEAD')
    checkout = tmp_path / 'checkout'
    checkout.mkdir()
    kit.export_commit(repo, commit, checkout, tmp_path / 'source.tar')
    published = tmp_path / 'published'
    kit.publish_dotnet(checkout / 'Sli.Server.csproj', published, commit, os.environ.copy())

    release = tmp_path / 'release'
    release.mkdir()
    plugin = release / native_plugins.REMOTE_FILE
    plugin.parent.mkdir(parents=True)
    shutil.copyfile(kit.ROOT / native_plugins.REMOTE_FILE, plugin)
    kit.write_json(release / 'native-runtime.json', {
        'schema_version': 1, 'python': '/opt/sli/runtimes/fixture/bin/python3.14',
        'python_sha256': hashlib.sha256(b'fixture Python payload').hexdigest(),
        'migration_ledger': [{'version': 1}], 'roles': [['sli_test', False]],
        'plugins': {name: {'version': version} for name, version in native_plugins.VERSIONS.items()},
    })
    output = tmp_path / 'kit'
    kit.native_package.build(release, output, 'fixture', '1.0-1~deb13', '1.0-1~deb13', dotnet_published=published)
    manifest = kit.finish(output, commit, 'fixture', '1.0-1~deb13', toolchain={})

    assert manifest['git_commit'] == commit
    assert {row['package'] for row in manifest['packages']} == {
        'sli', 'sli-host', 'sli-release-fixture', 'sli-rollback-hold', 'sli-server-dotnet',
    }
    assert json.loads((output / 'manifest.json').read_text()) == manifest
    assert kit.sha256(output / 'remove-beta-kit') == manifest['remover']['sha256']
    kit.archive_kit(output)
    with tarfile.open(output / 'sli-debian-beta-kit.tar.gz') as archive:
        assert archive.getmember('sli-debian-beta-kit/remove-beta-kit').mode & 0o111 == 0o111
    remover = subprocess.run([output / 'remove-beta-kit', '--help'], capture_output=True, text=True, check=True)
    assert '--purge-data' in remover.stdout
    subprocess.run(['sha256sum', '--check', 'SHA256SUMS'], cwd=output, check=True)
    extracts = tmp_path / 'package'
    server_package = next(output.glob('sli-release-fixture_*.deb'))
    subprocess.run(['dpkg-deb', '-x', server_package, extracts], check=True)
    server = extracts / 'opt/sli/dotnet/fixture/Sli.Server'
    result = subprocess.run([server], capture_output=True, text=True, check=True, env={'PATH': '/usr/bin:/bin'})
    assert result.stdout.strip() == 'beta kit smoke'

def test_kit_installer_matches_the_packaged_source(tmp_path):
    checkout = tmp_path / 'source'
    installer = checkout / 'deploy/linux/install-beta-kit'
    installer.parent.mkdir(parents=True)
    installer.write_bytes(b'#!/usr/bin/env bash\n# Selected source fixture\n')
    output = tmp_path / 'kit'
    output.mkdir()
    manifest = kit.finish(output, 'a' * 40, 'fixture', '1.0-1~deb13', toolchain={}, installer_root=checkout)
    assert (output / 'install-beta-kit').read_bytes() == installer.read_bytes()
    assert manifest['installer']['sha256'] == kit.sha256(installer)
    assert f'{kit.sha256(installer)}  install-beta-kit' in (output / 'SHA256SUMS').read_text(encoding='utf-8')


@pytest.mark.skipif(os.name != 'posix' or not shutil.which('bash'), reason='Linux shell tools required')
@pytest.mark.parametrize('scenario', ['valid', 'newer_vendor', 'apt_failure', 'unlisted', 'tampered', 'invalid_name', 'duplicate',
                                      'fresh_native', 'upgrade_space_ok', 'upgrade_space_shortfall'])
def test_install_helper_uses_the_verified_package_set(tmp_path, scenario):
    source = kit.ROOT / 'deploy/linux/install-beta-kit'
    assert source.is_file(), 'The Debian beta kit needs a standalone install helper'
    extracted = tmp_path / 'kit'
    extracted.mkdir()
    script = extracted / source.name
    script.write_text(source.read_text(encoding='utf-8'), encoding='utf-8', newline='\n')
    native = scenario in {'fresh_native', 'upgrade_space_ok', 'upgrade_space_shortfall'}
    deb = extracted / ('sli_1.0-1~deb13_amd64.deb' if native else 'sli-example_1.0~deb13_amd64.deb')
    deb.write_bytes(b'synthetic package')
    manifest = extracted / 'manifest.json'
    manifest.write_text('{}\n', encoding='utf-8')
    lines = [f'{kit.sha256(path)}  {path.name}\n' for path in (script, deb, manifest)]
    if native:
        host = extracted / 'sli-host_1.0-1~deb13_all.deb'
        host.write_bytes(b'synthetic host package')
        lines.append(f'{kit.sha256(host)}  {host.name}\n')
    if scenario == 'newer_vendor':
        vendor = extracted / 'tzdata_2026c_all.deb'
        vendor.write_bytes(b'verified vendor package')
        lines.append(f'{kit.sha256(vendor)}  {vendor.name}\n')
    elif scenario == 'unlisted':
        (extracted / 'unlisted.deb').write_bytes(b'not authorized')
    elif scenario == 'tampered':
        deb.write_bytes(b'changed package')
    elif scenario == 'invalid_name':
        lines.append(f'{kit.sha256(deb)}  ../{deb.name}\n')
    elif scenario == 'duplicate':
        lines.append(lines[1])
    (extracted / 'SHA256SUMS').write_text(''.join(lines), encoding='utf-8', newline='\n')

    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    apt_calls = tmp_path / 'apt-calls'
    running = tmp_path / 'old-service-running'
    if scenario.startswith('upgrade_space_'):
        running.touch()
    sudo = bin_dir / 'sudo'
    sudo.write_text("""#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$APT_CALLS"
if [[ " $* " == *' check-package-space '* ]]; then
    test -f "$RUNNING" || exit 2
    if [[ $SCENARIO == upgrade_space_shortfall ]]; then
        echo 'native_upgrade_insufficient_space required=3000 bytes free=2000 bytes' >&2
        exit 1
    fi
elif [[ " $* " == *' install '* ]]; then
    rm -f -- "$RUNNING"
    if [[ $SCENARIO == apt_failure ]]; then exit 1; fi
fi
""", encoding='utf-8', newline='\n')
    systemctl = bin_dir / 'systemctl'
    systemctl.write_text('#!/usr/bin/env bash\nprintf "systemctl %s\\n" "$*" >> "$APT_CALLS"\n',
                         encoding='utf-8', newline='\n')
    systemctl.chmod(0o755)
    sudo.chmod(0o755)
    dpkg_deb = bin_dir / 'dpkg-deb'
    dpkg_deb.write_text('''#!/usr/bin/env bash
if [[ $1 == --extract ]]; then mkdir -p -- "$3/usr/lib/sli"; exit; fi
case "$2:$3" in
    ./tzdata*:Package) echo tzdata;; ./tzdata*:Version) echo 2026c;; ./tzdata*:Architecture) echo all;;
    ./sli-host*:Package) echo sli-host;; ./sli_*.deb:Package) echo sli;;
    ./sli-host*:Version|./sli_*.deb:Version) echo '1.0-1~deb13';;
    *:Package) echo sli-example;; *:Version) echo 1.0;; *:Architecture) echo amd64;; *) exit 1;;
esac
''', encoding='utf-8', newline='\n')
    query = bin_dir / 'dpkg-query'
    query.write_text("""#!/usr/bin/env bash
if [[ $3 == sli-host && $SCENARIO == upgrade_space_* ]]; then echo installed
elif [[ $3 == tzdata ]]; then echo 'installed 2026e'
else exit 1
fi
""", encoding='utf-8', newline='\n')
    dpkg = bin_dir / 'dpkg'
    dpkg.write_text('#!/usr/bin/env bash\ntest "$*" = "--compare-versions 2026e gt 2026c"\n', encoding='utf-8', newline='\n')
    for stub in (dpkg_deb, query, dpkg):
        stub.chmod(0o755)
    env = dict(os.environ, PATH=f'{bin_dir}{os.pathsep}{os.environ["PATH"]}', APT_CALLS=str(apt_calls),
               SCENARIO=scenario, RUNNING=str(running))
    run = subprocess.run(['bash', './install-beta-kit', '--port', '9443'],
                         cwd=extracted, env=env, capture_output=True, text=True)
    if scenario == 'upgrade_space_shortfall':
        assert run.returncode != 0
        assert 'native_upgrade_insufficient_space' in run.stderr
        assert 'required=3000 bytes free=2000 bytes' in run.stderr
        assert running.is_file(), 'the accepted service must stay up'
        calls = apt_calls.read_text(encoding='utf-8').splitlines()
        assert len(calls) == 1
        assert calls[0].endswith(' check-package-space 1.0-1~deb13')
    elif scenario in {'valid', 'newer_vendor', 'fresh_native', 'upgrade_space_ok'}:
        assert run.returncode == 0, run.stderr
        if scenario == 'newer_vendor':
            assert 'Keeping tzdata 2026e' in run.stdout
        calls = apt_calls.read_text(encoding='utf-8').splitlines()
        if scenario == 'upgrade_space_ok':
            assert calls.pop(0).endswith(' check-package-space 1.0-1~deb13')
        expected_packages = './' + deb.name + (' ./' + host.name if native else '')
        assert calls == [
            'apt-get update', 'env DEBIAN_FRONTEND=noninteractive apt-get --assume-yes '
            '-o APT::Get::allow-Downgrades=false -o Dpkg::Options::=--force-confdef '
            f'-o Dpkg::Options::=--force-confold install --no-remove --fix-broken {expected_packages}',
            '/usr/sbin/sli-setup --port 9443',
        ]
    elif scenario == 'apt_failure':
        assert run.returncode != 0
        assert '/usr/sbin/sli-setup' not in apt_calls.read_text(encoding='utf-8')
    else:
        assert run.returncode != 0
        assert 'SLI beta kit:' in run.stderr
        assert not apt_calls.exists()


@pytest.mark.skipif(not all(shutil.which(name) for name in ('apt-get', 'dpkg-deb', 'bash')),
                    reason='Debian package planning tools required')
def test_install_plan_keeps_newer_system_packages_and_installs_pinned_dependencies(tmp_path):
    extracted = tmp_path / 'kit'
    extracted.mkdir()
    script = extracted / 'install-beta-kit'
    shutil.copyfile(kit.ROOT / 'deploy/linux/install-beta-kit', script)
    manifest = extracted / 'manifest.json'
    manifest.write_text('{}\n', encoding='utf-8')
    files = [script, manifest]
    control = 'Package: {0}\nVersion: {1}\nArchitecture: {2}\nMaintainer: Fixture <fixture@example.test>\nDescription: Fixture\n'
    for name, version, arch, depends in (
        ('tzdata', '2026c-1', 'all', ''),
        ('libfixture1', '2:1.0-1', 'amd64', ''),
        ('libfixture2', '1.0-1', 'amd64', ''),
        ('sli-fixture', '1.0-1', 'amd64', 'Depends: tzdata (>= 2026c-1), libfixture1, libfixture2\n'),
    ):
        staging = tmp_path / name / 'DEBIAN'
        staging.mkdir(parents=True)
        (staging / 'control').write_text(control.format(name, version, arch) + depends, encoding='utf-8')
        deb = extracted / f'{name}_fixture.deb'
        subprocess.run(['dpkg-deb', '--root-owner-group', '--build', staging.parent, deb], check=True)
        files.append(deb)
    (extracted / 'SHA256SUMS').write_text(''.join(f'{kit.sha256(file)}  {file.name}\n' for file in files), encoding='utf-8')

    admin = tmp_path / 'dpkg'
    admin.mkdir()
    (admin / 'status').write_text(''.join(
        control.format(name, version, arch) + 'Status: install ok installed\n\n'
        for name, version, arch in (('tzdata', '2026e-1', 'all'), ('libfixture1', '3:0.9-1', 'amd64'))
    ), encoding='utf-8')
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    query = bin_dir / 'dpkg-query'
    query.write_text('#!/usr/bin/env bash\nexec "$REAL_QUERY" --admindir="$FIXTURE_ADMIN" "$@"\n', encoding='utf-8')
    query.chmod(0o755)
    sudo = bin_dir / 'sudo'
    sudo.write_text('''#!/usr/bin/env bash
set -eu
if [[ $1 == apt-get && $2 == update ]]; then exit 0; fi
if [[ $# == 1 && $1 == /usr/sbin/sli-setup ]]; then exit 0; fi
test "$1 $2 $3" = 'env DEBIAN_FRONTEND=noninteractive apt-get'
shift 3
exec "$REAL_APT" -s -o Dir::State::status="$FIXTURE_ADMIN/status" -o Dir::State="$FIXTURE_ADMIN" \\
    -o Dir::Etc::sourcelist=/dev/null -o Dir::Etc::sourceparts=- -o Dir::Etc::preferences=/dev/null \\
    -o Dir::Etc::preferencesparts=- -o Dir::Cache="$FIXTURE_ADMIN" "$@"
''', encoding='utf-8')
    sudo.chmod(0o755)
    env = dict(os.environ, PATH=f'{bin_dir}{os.pathsep}{os.environ["PATH"]}', FIXTURE_ADMIN=str(admin),
               REAL_QUERY=shutil.which('dpkg-query'), REAL_APT=shutil.which('apt-get'))

    result = subprocess.run(['bash', script], env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr + result.stdout
    assert 'Keeping tzdata 2026e-1' in result.stdout
    assert 'Keeping libfixture1:amd64 3:0.9-1' in result.stdout
    assert 'Inst sli-fixture' in result.stdout and 'Inst libfixture2' in result.stdout
    assert 'Inst tzdata' not in result.stdout and 'Inst libfixture1' not in result.stdout

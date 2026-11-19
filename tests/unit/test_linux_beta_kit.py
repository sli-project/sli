import hashlib
import json
import os
import shutil
import subprocess

import pytest

from deploy.linux import build_beta_kit as kit, native_plugins


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
    subprocess.run(['sha256sum', '--check', 'SHA256SUMS'], cwd=output, check=True)
    extracts = tmp_path / 'package'
    server_package = next(output.glob('sli-server-dotnet_*.deb'))
    subprocess.run(['dpkg-deb', '-x', server_package, extracts], check=True)
    server = extracts / 'opt/sli/dotnet/fixture/Sli.Server'
    result = subprocess.run([server], capture_output=True, text=True, check=True, env={'PATH': '/usr/bin:/bin'})
    assert result.stdout.strip() == 'beta kit smoke'

@pytest.mark.skipif(not shutil.which('bash'), reason='Bash required')
@pytest.mark.parametrize('scenario', ['valid', 'newer_vendor', 'unlisted', 'tampered', 'invalid_name', 'duplicate'])
def test_install_helper_uses_the_verified_package_set(tmp_path, scenario):
    source = kit.ROOT / 'deploy/linux/install-beta-kit'
    assert source.is_file(), 'The Debian beta kit needs a standalone install helper'
    extracted = tmp_path / 'kit'
    extracted.mkdir()
    script = extracted / source.name
    script.write_text(source.read_text(encoding='utf-8'), encoding='utf-8', newline='\n')
    deb = extracted / 'sli-example_1.0~deb13_amd64.deb'
    deb.write_bytes(b'synthetic package')
    manifest = extracted / 'manifest.json'
    manifest.write_text('{}\n', encoding='utf-8')
    lines = [f'{kit.sha256(path)}  {path.name}\n' for path in (script, deb, manifest)]
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
    sudo = bin_dir / 'sudo'
    sudo.write_text('#!/usr/bin/env bash\nprintf "%s\\n" "$*" >> "$APT_CALLS"\n', encoding='utf-8', newline='\n')
    sudo.chmod(0o755)
    dpkg_deb = bin_dir / 'dpkg-deb'
    dpkg_deb.write_text('''#!/usr/bin/env bash
case "$2:$3" in
    ./tzdata*:Package) echo tzdata;; ./tzdata*:Version) echo 2026c;; ./tzdata*:Architecture) echo all;;
    *:Package) echo sli-example;; *:Version) echo 1.0;; *:Architecture) echo amd64;; *) exit 1;;
esac
''', encoding='utf-8', newline='\n')
    query = bin_dir / 'dpkg-query'
    query.write_text('#!/usr/bin/env bash\ntest "$3" = tzdata && echo "installed 2026e"\n', encoding='utf-8', newline='\n')
    dpkg = bin_dir / 'dpkg'
    dpkg.write_text('#!/usr/bin/env bash\ntest "$*" = "--compare-versions 2026e gt 2026c"\n', encoding='utf-8', newline='\n')
    for stub in (dpkg_deb, query, dpkg):
        stub.chmod(0o755)
    env = dict(os.environ, PATH=f'{bin_dir}{os.pathsep}{os.environ["PATH"]}', APT_CALLS=apt_calls.as_posix())
    run = subprocess.run([shutil.which('bash'), './install-beta-kit'], cwd=extracted, env=env, capture_output=True, text=True)
    if scenario in {'valid', 'newer_vendor'}:
        assert run.returncode == 0, run.stderr
        if scenario == 'newer_vendor':
            assert 'Keeping tzdata 2026e' in run.stdout
        assert apt_calls.read_text(encoding='utf-8').splitlines() == [
            'apt-get update', 'env DEBIAN_FRONTEND=noninteractive apt-get --assume-yes '
            '-o APT::Get::allow-Downgrades=false -o Dpkg::Options::=--force-confdef '
            f'-o Dpkg::Options::=--force-confold install --fix-broken ./{deb.name}',
        ]
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

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


@pytest.mark.parametrize('explicit', [False, True])
def test_agent_msi_uses_trusted_manifest_for_cache_and_explicit_path(tmp_path, explicit):
    commit = 'a' * 40
    cache = tmp_path / 'cache'
    cache.mkdir()
    source = tmp_path / 'agent.msi' if explicit else cache / f'SliAgent-{commit}.msi'
    source.write_bytes(b'agent MSI bytes')
    kit.write_json(cache / f'SliAgent-{commit}.msi.json', {
        'source_commit': commit, 'sha256': kit.sha256(source),
    })
    work = tmp_path / 'work'
    work.mkdir()

    staged = kit.stage_agent_msi(cache, commit, work, source if explicit else None)
    source.write_bytes(b'changed after verification')

    assert staged.read_bytes() == b'agent MSI bytes'


@pytest.mark.parametrize(('problem', 'message'), [
    ('missing', 'Missing trusted agent MSI manifest'),
    ('hash', 'Agent MSI SHA-256 mismatch'),
    ('commit', 'Agent MSI manifest does not identify source commit'),
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
        })
    monkeypatch.setattr(kit.platform, 'system', lambda: 'Linux')
    monkeypatch.setattr(kit.platform, 'machine', lambda: 'x86_64')
    monkeypatch.setattr(kit.os, 'geteuid', lambda: 1000, raising=False)
    monkeypatch.setattr(kit.os, 'umask', lambda mask: None)
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
    subprocess.run(['sha256sum', '--check', 'SHA256SUMS'], cwd=output, check=True)
    extracts = tmp_path / 'package'
    server_package = next(output.glob('sli-server-dotnet_*.deb'))
    subprocess.run(['dpkg-deb', '-x', server_package, extracts], check=True)
    server = extracts / 'opt/sli/dotnet/fixture/Sli.Server'
    result = subprocess.run([server], capture_output=True, text=True, check=True, env={'PATH': '/usr/bin:/bin'})
    assert result.stdout.strip() == 'beta kit smoke'

@pytest.mark.skipif(os.name != 'posix' or not shutil.which('bash'), reason='Linux shell tools required')
@pytest.mark.parametrize('scenario', ['valid', 'unlisted', 'tampered', 'invalid_name', 'duplicate'])
def test_install_helper_uses_the_verified_package_set(tmp_path, scenario):
    source = kit.ROOT / 'deploy/linux/install-beta-kit'
    assert source.is_file(), 'The Debian beta kit needs a standalone install helper'
    extracted = tmp_path / 'kit'
    extracted.mkdir()
    script = extracted / source.name
    shutil.copyfile(source, script)
    deb = extracted / 'sli-example_1.0~deb13_amd64.deb'
    deb.write_bytes(b'synthetic package')
    manifest = extracted / 'manifest.json'
    manifest.write_text('{}\n', encoding='utf-8')
    lines = [f'{kit.sha256(path)}  {path.name}\n' for path in (script, deb, manifest)]
    if scenario == 'unlisted':
        (extracted / 'unlisted.deb').write_bytes(b'not authorized')
    elif scenario == 'tampered':
        deb.write_bytes(b'changed package')
    elif scenario == 'invalid_name':
        lines.append(f'{kit.sha256(deb)}  ../{deb.name}\n')
    elif scenario == 'duplicate':
        lines.append(lines[1])
    (extracted / 'SHA256SUMS').write_text(''.join(lines), encoding='utf-8')

    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    apt_calls = tmp_path / 'apt-calls'
    sudo = bin_dir / 'sudo'
    sudo.write_text('#!/usr/bin/env bash\nprintf "%s\\n" "$*" >> "$APT_CALLS"\n', encoding='utf-8')
    sudo.chmod(0o755)
    env = dict(os.environ, PATH=f'{bin_dir}{os.pathsep}{os.environ["PATH"]}', APT_CALLS=str(apt_calls),
               TMPDIR=str(tmp_path))
    run = subprocess.run(['bash', script], cwd=extracted, env=env, capture_output=True, text=True)
    if scenario == 'valid':
        assert run.returncode == 0, run.stderr
        assert apt_calls.read_text(encoding='utf-8').splitlines() == [
            'apt-get update', f'apt-get install --fix-broken ./{deb.name}',
        ]
    else:
        assert run.returncode != 0
        assert not apt_calls.exists()

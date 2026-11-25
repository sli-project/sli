import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
import yaml

from deploy.linux import build_apt_repo as apt_repo
from deploy.linux import build_beta_kit, n03_runtime_control, native_restore


WORKFLOWS = Path(__file__).resolve().parents[2] / '.github/workflows'
MAIN_ONLY = "github.ref == 'refs/heads/main'"


@pytest.fixture
def signing_key():
    if not all(shutil.which(tool) for tool in ('gpg', 'gpgconf')):
        pytest.skip('GnuPG signing tools required')
    with tempfile.TemporaryDirectory(prefix='sli-apt-test-') as home:
        gpg = ['gpg', '--no-options', '--homedir', '.', '--batch', '--no-tty']
        key = Path(home) / 'fixture-secret.asc'
        try:
            subprocess.run([*gpg, '--pinentry-mode', 'loopback', '--passphrase', '', '--quick-generate-key',
                            'APT fixture <apt@example.test>', 'ed25519', 'sign', '1d'], cwd=home, check=True)
            with key.open('wb') as output:
                subprocess.run([*gpg, '--armor', '--export-secret-keys'], cwd=home, stdout=output, check=True)
        finally:
            subprocess.run(['gpgconf', '--homedir', '.', '--kill', 'gpg-agent'], cwd=home, check=True)
        yield key


def verify_signatures(release, keyring):
    with tempfile.TemporaryDirectory(prefix='sli-apt-verify-') as home:
        gpg = ['gpg', '--no-options', '--homedir', '.', '--batch']
        try:
            for name in ('InRelease', 'Release.gpg', 'Release'):
                shutil.copyfile(release.with_name(name), Path(home) / name)
            with keyring.open('rb') as stream:
                subprocess.run([*gpg, '--import'], cwd=home, stdin=stream, check=True)
            subprocess.run([*gpg, '--verify', 'InRelease'], cwd=home, check=True)
            subprocess.run([*gpg, '--verify', 'Release.gpg', 'Release'], cwd=home, check=True)
            assert subprocess.check_output([*gpg, '--list-secret-keys'], cwd=home) == b''
            assert subprocess.check_output([*gpg, '--decrypt', 'InRelease'], cwd=home) == release.read_bytes()
        finally:
            subprocess.run(['gpgconf', '--homedir', '.', '--kill', 'gpg-agent'], cwd=home, check=True)


def test_release_signatures_use_the_exported_public_key(tmp_path, signing_key):
    release = tmp_path / 'Release'
    release.write_bytes(b'Origin: SLI\n')
    keyring = tmp_path / apt_repo.KEYRING

    with apt_repo.signing_context(signing_key) as (gpg, home, signer):
        apt_repo.sign_release(release, keyring, gpg, home, signer)

    verify_signatures(release, keyring)


@pytest.fixture
def debian_tools(monkeypatch):
    if shutil.which('dpkg-deb') and shutil.which('dpkg'):
        return True
    monkeypatch.setattr(apt_repo, 'package_control', lambda path: path.read_text(encoding='ascii').rstrip('\n'))
    run = subprocess.run

    def compare_versions(args, **kwargs):
        if args[:2] == ['dpkg', '--compare-versions']:
            return subprocess.CompletedProcess(args, int(not args[2] < args[4]))
        return run(args, **kwargs)

    monkeypatch.setattr(subprocess, 'run', compare_versions)
    return False


def make_kit(debs, version, debian_tools, *, runtime=('sli-runtime-fixture', '1.0-1')):
    debs.mkdir()
    runtime_package, runtime_version = runtime
    revision = version.split('-')[1][0]
    packages = {
        'sli': ('amd64', version, f'sli-host (= {version}), sli-rollback-hold (= {version}), '
                'postgresql-18, postgresql-client-18'),
        'sli-host': ('amd64', version, 'postgresql-common'),
        'sli-rollback-hold': ('amd64', version, f'sli-server-dotnet (= {version}), sli-release-beta-{revision}'),
        'sli-server-dotnet': ('amd64', version, ''),
        f'sli-release-beta-{revision}': ('amd64', version, f'{runtime_package} (= {runtime_version})'),
        runtime_package: ('amd64', runtime_version, 'libfixture (= 1.0-1)'),
        'postgresql-18': ('amd64', '18.1-1', 'postgresql-common'),
        'postgresql-client-18': ('amd64', '18.1-1', 'postgresql-common'),
        'postgresql-common': ('all', '1.0-1', ''),
        'libfixture': ('amd64', '1.0-1', ''),
    }
    pinned = {}
    for package, (architecture, package_version, depends) in packages.items():
        destination = debs / f'{package}_{package_version}_{architecture}.deb'
        data = (f'Package: {package}\nVersion: {package_version}\nArchitecture: {architecture}\n'
                'Maintainer: Fixture <apt@example.test>\n')
        if depends:
            data += f'Depends: {depends}\n'
        data += 'Description: Test package\n More details.\n'
        if debian_tools:
            control = debs.parent / f'{debs.name}-{package}/DEBIAN/control'
            control.parent.mkdir(parents=True)
            control.write_bytes(data.encode('ascii'))
            subprocess.run(['dpkg-deb', '--root-owner-group', '--build', control.parent.parent, destination],
                           env={**os.environ, 'SOURCE_DATE_EPOCH': '1'}, check=True)
        else:
            destination.write_bytes(data.encode('ascii'))
        if package_version != version:
            pinned[destination.name] = apt_repo.sha256(destination)
    return pinned


def read_index(output):
    index = output / 'dists/trixie' / apt_repo.INDEX_PATH
    return [dict(line.split(': ', 1) for line in stanza.splitlines() if not line.startswith(' '))
            for stanza in index.read_text().strip().split('\n\n')]


def assert_apt_install_resolves(tmp_path, output, version):
    root = tmp_path / 'apt'
    for component in ('etc', 'state', 'cache'):
        (root / component).mkdir(parents=True)
    (root / 'state/status').touch()
    sources = root / 'etc/sources.list'
    sources.write_text(f'deb [signed-by={output / apt_repo.KEYRING}] {output.as_uri()} trixie main\n')
    config = root / 'apt.conf'
    config.write_text(f'Dir::Etc "{root}/etc";\nDir::State "{root}/state";\n'
                      f'Dir::State::status "{root}/state/status";\nDir::Cache "{root}/cache";\n'
                      'APT::Architecture "amd64";\nAcquire::Languages "none";\n')
    env = {**os.environ, 'APT_CONFIG': str(config), 'LC_ALL': 'C'}
    subprocess.run(['apt-get', 'update'], env=env, check=True)
    simulation = subprocess.check_output(['apt-get', '-s', 'install', 'sli'], env=env, text=True)
    assert f'Inst sli ({version} ' in simulation
    installed = {line.split()[1] for line in simulation.splitlines() if line.startswith('Inst ')}
    assert {'postgresql-18', 'postgresql-client-18', 'libfixture'} <= installed


def test_signed_pool_retains_the_previous_rollback_version(tmp_path, signing_key, debian_tools, monkeypatch):
    published = tmp_path / 'published'
    url = 'https://apt.example.test'

    def download(url_path, destination, limit):
        source = published / url_path.removeprefix(url + '/')
        if not source.is_file():
            return False
        assert source.stat().st_size <= limit
        shutil.copyfile(source, destination)
        return True

    monkeypatch.setattr(apt_repo, 'download', download)
    old, new, latest = [f'1.0-{revision}~deb13' for revision in range(1, 4)]
    debs = tmp_path / 'debs-old'
    pins = make_kit(debs, old, debian_tools)
    with pytest.raises(ValueError, match='No previous APT publication'):
        apt_repo.build(debs, published, signing_key, pins, previous_url=url)
    apt_repo.build(debs, published, signing_key, pins, previous_url=url, initialize=True)

    debs = tmp_path / 'debs-new'
    pins = make_kit(debs, new, debian_tools)
    output = tmp_path / 'repo'
    apt_repo.build(debs, output, signing_key, pins, previous_url=url)

    release = output / 'dists/trixie/Release'
    verify_signatures(release, output / apt_repo.KEYRING)
    index = release.parent / apt_repo.INDEX_PATH
    assert gzip.decompress(index.with_suffix('.gz').read_bytes()) == index.read_bytes()
    entries = read_index(output)
    for fields in entries:
        file = output / fields['Filename']
        original = debs / file.name
        if not original.exists():
            original = published / fields['Filename']
        assert file.read_bytes() == original.read_bytes()
        assert fields['Size'] == str(file.stat().st_size)
        assert fields['SHA256'] == hashlib.sha256(file.read_bytes()).hexdigest()
    assert '\n More details.\n' in index.read_text()
    indexed = {f'{fields["Package"]}={fields["Version"]}' for fields in entries}
    assert {'postgresql-18=18.1-1', 'postgresql-client-18=18.1-1',
            'postgresql-common=1.0-1', 'libfixture=1.0-1'} <= indexed
    assert {entry['Version'] for entry in entries if entry['Package'] == 'sli'} == {old, new}
    for checksum in release.read_text().split('SHA256:\n')[1].splitlines():
        digest, size, filename = checksum.split()
        file = release.parent / filename
        assert int(size) == file.stat().st_size
        assert digest == hashlib.sha256(file.read_bytes()).hexdigest()
    if debian_tools and shutil.which('apt-get'):
        assert_apt_install_resolves(tmp_path, output, new)

    requested = []

    def apt_install(command, **kwargs):
        assert command[:2] == ['apt-get', '-y']
        requested.append(command[command.index('install') + 1:])
        assert set(requested[-1]) <= indexed

    monkeypatch.setattr(native_restore.install, 'command', apt_install)
    monkeypatch.setattr(native_restore.native, 'command', lambda _: f'install ok installed\t{old}'.encode())
    previous = native_restore.rollback_packages(old, None)
    native_restore.apt_rollback(old, previous, download_only=True)
    native_restore.apt_rollback(old, previous)
    expected = [f'{package}={old}' for package in ('sli', 'sli-host', 'sli-rollback-hold', 'sli-server-dotnet')]
    assert requested == [expected, expected]

    published = output
    retry = tmp_path / 'retry'
    apt_repo.build(debs, retry, signing_key, pins, previous_url=url)
    assert read_index(retry) == entries

    debs = tmp_path / 'debs-latest'
    pins = make_kit(debs, latest, debian_tools)
    next_release = tmp_path / 'next'
    original_release = release.read_bytes()
    release.write_bytes(original_release.replace(b'Origin: SLI', b'Origin: Fixture'))
    with pytest.raises(subprocess.CalledProcessError):
        apt_repo.build(debs, next_release, signing_key, pins, previous_url=url)
    assert not next_release.exists()
    release.write_bytes(original_release)
    previous_deb = published / 'pool' / f'sli_{new}_amd64.deb'
    original = previous_deb.read_bytes()
    previous_deb.write_bytes(b'X' * len(original))
    with pytest.raises(ValueError, match='Previous package SHA-256'):
        apt_repo.build(debs, next_release, signing_key, pins, previous_url=url)
    assert not next_release.exists()
    previous_deb.write_bytes(original)
    apt_repo.build(debs, next_release, signing_key, pins, previous_url=url)
    assert {entry['Version'] for entry in read_index(next_release) if entry['Package'] == 'sli'} == {new, latest}

    dependency = debs / 'postgresql-18_18.1-1_amd64.deb'
    original = dependency.read_bytes()
    dependency.write_bytes(b'invalid')
    with pytest.raises(ValueError, match='Pinned package SHA-256 mismatch'):
        apt_repo.build(debs, tmp_path / 'bad-pin', signing_key, pins)
    dependency.write_bytes(original)
    monkeypatch.setattr(apt_repo, 'MAX_FILE_SIZE', 1)
    rejected = tmp_path / 'rejected'
    with pytest.raises(ValueError, match='Pages file limit'):
        apt_repo.build(debs, rejected, signing_key, pins)
    assert not rejected.exists()



def test_repository_file_limit_accepts_100_mib_and_rejects_one_more_byte(tmp_path, monkeypatch):
    limit = 104_857_600
    assert apt_repo.MAX_SITE_SIZE == 1_000_000_000
    package = tmp_path / 'sli_1.0-1_amd64.deb'
    monkeypatch.setattr(apt_repo, 'package_control', lambda _: 'Package: sli\nVersion: 1.0-1\nArchitecture: amd64')
    with package.open('wb') as stream:
        stream.truncate(limit)

    accepted = tmp_path / 'accepted'
    accepted.mkdir()
    packages = {package.name: package}
    apt_repo.write_packages(packages, {}, accepted)
    assert (accepted / 'pool' / package.name).stat().st_size == limit

    with package.open('r+b') as stream:
        stream.truncate(limit + 1)
    rejected = tmp_path / 'rejected'
    rejected.mkdir()
    with pytest.raises(ValueError, match='exceeds the Pages file limit of 104857600 bytes'):
        apt_repo.write_packages(packages, {}, rejected)
    assert not (rejected / 'pool' / package.name).exists()


def test_repository_pins_select_only_the_qualified_delivery_runtime():
    pin_path = WORKFLOWS.parents[1] / 'deploy/linux/native_pins.json'
    pins = json.loads(pin_path.read_text(encoding='utf-8'))
    _, original_runtime, original_pins = build_beta_kit.input_pins(pins)
    delivery = build_beta_kit.N03_RUNTIME_DELIVERY
    delivered_runtime = f"{n03_runtime_control.PACKAGE}_{delivery['version']}_amd64.deb"

    assert apt_repo.repository_pins(pins) == {
        **{name: digest for name, digest in original_pins.items() if name != original_runtime},
        delivered_runtime: delivery['sha256'],
    }
    pins['runtime_delivery'] = {**delivery, 'version': delivery['version'] + '+wrong'}
    with pytest.raises(ValueError, match='Unexpected runtime compatibility input or pin'):
        apt_repo.repository_pins(pins)
    del pins['runtime_delivery']
    assert apt_repo.repository_pins(pins) == original_pins


def test_cli_signs_only_the_exact_pinned_delivery_runtime(tmp_path, signing_key, debian_tools, monkeypatch):
    debs = tmp_path / 'debs'
    package = n03_runtime_control.PACKAGE
    runtime_id = package.removeprefix('sli-runtime-')
    delivery = dict(build_beta_kit.N03_RUNTIME_DELIVERY)
    filename = f"{package}_{delivery['version']}_amd64.deb"
    external = make_kit(debs, '1.0-1~deb13', debian_tools, runtime=(package, delivery['version']))
    delivery['sha256'] = external.pop(filename)
    monkeypatch.setattr(apt_repo, 'N03_RUNTIME_DELIVERY', delivery)
    original_version = n03_runtime_control.ORIGINAL_VERSION
    dependencies = [
        {'name': name.split('_', 1)[0], 'filename': name, 'sha256': digest}
        for name, digest in sorted(external.items())
    ]
    pins = {
        'runtime_build': {'id': runtime_id, 'version': original_version, 'debian_artifacts': [], 'debian_runtime': []},
        'runtime_artifact': {'runtime_id': runtime_id, 'version': original_version,
                             'sha256': n03_runtime_control.ORIGINAL_SHA256},
        'runtime_delivery': delivery,
        'packages': dependencies,
        'roots': [dep['name'] for dep in dependencies],
        'dependency_edges': [],
    }
    pin_path = tmp_path / 'pins.json'
    pin_path.write_text(json.dumps(pins), encoding='utf-8')
    output = tmp_path / 'repo'
    monkeypatch.setattr(sys, 'argv', ['build_apt_repo', '--debs', str(debs), '--output', str(output),
                                    '--signing-key', str(signing_key), '--pins', str(pin_path)])
    apt_repo.main()

    runtime = next(row for row in read_index(output) if row['Package'] == package)
    assert (runtime['Version'], runtime['SHA256'], Path(runtime['Filename']).name) == (
        delivery['version'], delivery['sha256'], filename
    )
    verify_signatures(output / 'dists/trixie/Release', output / apt_repo.KEYRING)

    expected_pins = apt_repo.repository_pins(pins)
    runtime_deb = debs / filename
    alias = runtime_deb.with_name(runtime_deb.stem + '-other.deb')
    runtime_deb.rename(alias)
    with pytest.raises(ValueError, match='Unexpected package in the beta kit'):
        apt_repo.build(debs, tmp_path / 'wrong-name', signing_key, expected_pins)
    alias.rename(runtime_deb)
    original = runtime_deb.read_bytes()
    runtime_deb.write_bytes(original + b'changed')
    with pytest.raises(ValueError, match='Pinned package SHA-256 mismatch'):
        apt_repo.build(debs, tmp_path / 'wrong-runtime-sha', signing_key, expected_pins)
    runtime_deb.write_bytes(original)
    (debs / 'libfixture_1.0-1_amd64.deb').write_bytes(b'changed')
    with pytest.raises(ValueError, match='Pinned package SHA-256 mismatch'):
        apt_repo.build(debs, tmp_path / 'wrong-dependency-sha', signing_key, expected_pins)


@pytest.mark.parametrize('key_argument', [False, True])
def test_cli_rejects_missing_signing_key(tmp_path, key_argument):
    output = tmp_path / 'repo'
    command = [sys.executable, '-m', 'deploy.linux.build_apt_repo', '--debs', tmp_path, '--output', output,
               '--pins', Path(__file__).resolve().parents[2] / 'deploy/linux/native_pins.json']
    if key_argument:
        command.extend(['--signing-key', tmp_path / 'missing.asc'])
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    assert result.returncode
    assert 'signing' in result.stderr
    assert not output.exists()


def test_workflow_limits_apt_publication_to_main_and_scopes_the_signing_secret():
    source = (WORKFLOWS / 'apt-repo.yml').read_text(encoding='utf-8')
    workflow = yaml.load(source, Loader=yaml.BaseLoader)
    trigger = workflow['on']
    assert set(trigger) == {'workflow_dispatch'}
    assert trigger['workflow_dispatch']['inputs']['commit']['required'] == 'false'
    assert workflow['permissions'] == {'contents': 'read'}
    jobs = workflow['jobs']
    assert all(job['if'] == MAIN_ONLY for job in jobs.values())
    assert jobs['build']['with']['commit'] == '${{ inputs.commit || github.sha }}'
    archive = yaml.load((WORKFLOWS / 'beta-kit.yml').read_text(encoding='utf-8'), Loader=yaml.BaseLoader)
    assert jobs['build']['uses'] == archive['jobs']['build']['uses']
    assert jobs['publish']['environment'] == 'apt-publish'
    assert jobs['publish']['needs'] == 'build' and jobs['deploy']['needs'] == 'publish'
    assert jobs['deploy']['permissions'] == {'pages': 'write', 'id-token': 'write'}
    assert all('permissions' not in job for name, job in jobs.items() if name != 'deploy')
    assert all('secrets' not in job for job in jobs.values())
    secret = '${{ secrets.SLI_APT_SIGNING_KEY }}'
    assert source.count(secret) == 1
    assert any(step.get('env', {}).get('SLI_APT_SIGNING_KEY') == secret for step in jobs['publish']['steps'])
    assert any(step.get('uses', '').startswith('actions/upload-pages-artifact@') for step in jobs['publish']['steps'])
    assert any(step.get('uses', '').startswith('actions/deploy-pages@') for step in jobs['deploy']['steps'])

    shared = (WORKFLOWS / Path(jobs['build']['uses']).name).read_text(encoding='utf-8')
    for content in [source, shared]:
        for job in yaml.load(content, Loader=yaml.BaseLoader)['jobs'].values():
            for step in job.get('steps', []):
                if 'uses' in step:
                    action = step['uses']
                    assert re.fullmatch(r'actions/[a-z-]+@[0-9a-f]{40}', action)
                    assert re.search(rf'^\s*(?:- )?uses: {re.escape(action)} # v[\d.]+$', content, flags=re.M)

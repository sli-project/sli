import gzip
import hashlib
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
import yaml

from deploy.linux import build_apt_repo as apt_repo


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

    apt_repo.sign_release(release, signing_key, keyring)

    verify_signatures(release, keyring)


@pytest.mark.skipif(not shutil.which('dpkg-deb'), reason='Debian packaging tools required')
def test_build_indexes_and_signs_sli_packages(tmp_path, signing_key, monkeypatch):
    debs = tmp_path / 'debs'
    debs.mkdir()
    for package, architecture in [('sli', 'amd64'), ('sli-fixture', 'all'), ('libfixture', 'amd64')]:
        control = tmp_path / package / 'DEBIAN/control'
        control.parent.mkdir(parents=True)
        control.write_bytes((f'Package: {package}\nVersion: 1.0-1\nArchitecture: {architecture}\n'
                             'Maintainer: Fixture <apt@example.test>\nDepends: libfixture\n'
                             'Description: Test package\n More details.\n').encode('ascii'))
        subprocess.run(['dpkg-deb', '--root-owner-group', '--build', control.parent.parent,
                        debs / f'{package}_1.0-1_{architecture}.deb'], check=True)
    output = tmp_path / 'repo'
    apt_repo.build(debs, output, signing_key)

    assert {path.name for path in (output / 'pool').iterdir()} == {
        'sli_1.0-1_amd64.deb', 'sli-fixture_1.0-1_all.deb',
    }
    release = output / 'dists/trixie/Release'
    verify_signatures(release, output / apt_repo.KEYRING)
    index = release.parent / 'main/binary-amd64/Packages'
    assert gzip.decompress(index.with_suffix('.gz').read_bytes()) == index.read_bytes()
    for metadata in index.read_text().strip().split('\n\n'):
        fields = dict(line.split(': ', 1) for line in metadata.splitlines() if not line.startswith(' '))
        file = output / fields['Filename']
        assert file.read_bytes() == (debs / file.name).read_bytes()
        assert fields['Size'] == str(file.stat().st_size)
        assert fields['SHA256'] == hashlib.sha256(file.read_bytes()).hexdigest()
        assert fields['Depends'] == 'libfixture'
        assert '\n More details.\n' in metadata
    for checksum in release.read_text().split('SHA256:\n')[1].splitlines():
        digest, size, filename = checksum.split()
        file = release.parent / filename
        assert int(size) == file.stat().st_size
        assert digest == hashlib.sha256(file.read_bytes()).hexdigest()

    monkeypatch.setattr(apt_repo, 'MAX_FILE_SIZE', 1)
    rejected = tmp_path / 'rejected'
    with pytest.raises(ValueError, match='Pages file limit'):
        apt_repo.build(debs, rejected, signing_key)
    assert not rejected.exists()


@pytest.mark.parametrize('key_argument', [False, True])
def test_cli_rejects_missing_signing_key(tmp_path, key_argument):
    output = tmp_path / 'repo'
    command = [sys.executable, '-m', 'deploy.linux.build_apt_repo', '--debs', tmp_path, '--output', output]
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

"""Build a signed Debian 13 APT repository from a verified SLI kit."""

from __future__ import annotations

import argparse
import gzip
import json
import re
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from datetime import UTC, datetime
from email.utils import format_datetime
from pathlib import Path

from deploy.linux import n03_runtime_control
from deploy.linux.build_beta_kit import N03_RUNTIME_DELIVERY, input_pins, sha256


MAX_FILE_SIZE = 100 * 1024**2
MAX_SITE_SIZE = 1_000_000_000
KEYRING = 'sli-archive-keyring.gpg'
INDEX_PATH = 'main/binary-amd64/Packages'
INDEX_FIELDS = {'filename', 'size', 'md5sum', 'sha1', 'sha256', 'sha512', 'x-sli-current'}
DEB_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9.+_~-]*\.deb')
SLI_PACKAGES = {'sli', 'sli-host', 'sli-rollback-hold', 'sli-server-dotnet'}


def fields(control):
    return {key.lower(): value.strip() for key, value in re.findall(r'^([\w-]+):([^\n]*)', control, re.M)}


def package_control(source):
    return subprocess.check_output(['dpkg-deb', '--field', str(source.absolute())], encoding='utf-8').rstrip('\n')


def current_packages(debs, pinned):
    packages = {}
    release_packages = {}
    for source in sorted(debs.glob('*.deb')):
        if source.is_symlink() or not source.is_file() or not DEB_NAME.fullmatch(source.name):
            raise ValueError(f'Invalid Debian package input: {source.name}')
        if source.name in pinned:
            if sha256(source) != pinned[source.name]:
                raise ValueError(f'Pinned package SHA-256 mismatch: {source.name}')
        else:
            metadata = fields(package_control(source))
            name, version = metadata.get('package', ''), metadata.get('version')
            if name not in SLI_PACKAGES and not name.startswith('sli-release-'):
                raise ValueError(f'Unexpected package in the beta kit: {source.name}')
            if name in release_packages or not version:
                raise ValueError(f'Invalid SLI release package: {source.name}')
            release_packages[name] = version
        packages[source.name] = source
    version = release_packages.get('sli')
    if (not SLI_PACKAGES <= release_packages.keys() or not pinned.keys() <= packages.keys()
            or len(set(release_packages.values())) != 1
            or not any(name.startswith('sli-release-') for name in release_packages)):
        raise ValueError('The beta kit must include a complete SLI release and its pinned dependencies')
    return packages, version


def download(url, destination, limit):
    result = subprocess.run(['curl', '--fail', '--silent', '--show-error', '--location', '--retry', '3',
                             '--proto', '=https', '--proto-redir', '=https', '--max-filesize', str(limit),
                             '--header', 'Cache-Control: no-cache',
                             '--output', destination, '--write-out', '%{http_code}', url],
                            capture_output=True, text=True, check=False)
    if result.returncode == 22 and result.stdout == '404':
        return False
    if result.returncode or result.stdout != '200' or destination.stat().st_size > limit:
        raise ValueError(f'Could not download {url} (curl {result.returncode}, HTTP {result.stdout})')
    return True


def previous_packages(url, staging, current, version, gpg, home, *, initialize):
    release_path = staging / 'Release'
    if not download(f'{url}/dists/trixie/Release', release_path, MAX_FILE_SIZE):
        if initialize:
            return {}
        raise ValueError('No previous APT publication found. Use initialize only for the first publication.')
    signature = staging / 'Release.gpg'
    if not download(f'{url}/dists/trixie/Release.gpg', signature, MAX_FILE_SIZE):
        raise ValueError('Previous Release signature is missing')
    # Trust the publication key imported from the workflow secret, never a key from Pages.
    subprocess.run([*gpg, '--verify', str(signature.absolute()), str(release_path.absolute())], cwd=home, check=True)
    release = release_path.read_text(encoding='utf-8')
    metadata = fields(release)
    if metadata.get('origin') != 'SLI' or metadata.get('codename') != 'trixie':
        raise ValueError('Previous Release does not identify the SLI Debian 13 repository')
    checksum = re.search(rf'^SHA256:\s*\n(?: [^\n]+\n)*? ([a-f0-9]{{64}}) (\d+) {re.escape(INDEX_PATH)}$',
                         release, re.M)
    if not checksum:
        raise ValueError('Previous Release is missing the Packages checksum')
    digest, size = checksum[1], int(checksum[2])
    index = staging / 'Packages'
    if (not 0 < size <= MAX_FILE_SIZE or not download(f'{url}/dists/trixie/{INDEX_PATH}', index, size)
            or index.stat().st_size != size or sha256(index) != digest):
        raise ValueError('Previous Packages index does not match the signed Release')

    entries = [fields(stanza) for stanza in index.read_text(encoding='utf-8').strip().split('\n\n')]
    published = metadata.get('x-sli-current-version')
    if published is None:  # The original publisher only published a single SLI release.
        versions = [entry['version'] for entry in entries if entry.get('package') == 'sli']
        if len(versions) != 1:
            raise ValueError('Could not identify the previous SLI version')
        published = versions[0]
    elif version != published:
        entries = [entry for entry in entries if entry.get('x-sli-current') == 'yes']
    if not SLI_PACKAGES <= {entry.get('package') for entry in entries if entry.get('version') == published}:
        raise ValueError('Previous publication is missing rollback packages')
    if subprocess.run(['dpkg', '--compare-versions', version, 'lt', published], check=False).returncode != 1:
        raise ValueError(f'Cannot replace published version {published} with {version}')

    previous = {}
    for entry in entries:
        filename = entry.get('filename', '').removeprefix('pool/')
        size, digest = int(entry.get('size', '0')), entry.get('sha256', '')
        if (entry.get('filename') != f'pool/{filename}' or not DEB_NAME.fullmatch(filename)
                or filename in previous or not 0 < size <= MAX_FILE_SIZE or not re.fullmatch('[0-9a-f]{64}', digest)):
            raise ValueError('Invalid package entry in the previous publication')
        source = current.get(filename)
        if source is None:
            source = staging / filename
            if not download(f'{url}/pool/{filename}', source, size):
                raise ValueError(f'Previous package is missing: {filename}')
        if source.stat().st_size != size or sha256(source) != digest:
            raise ValueError(f'Previous package SHA-256 or size mismatch: {filename}')
        previous[filename] = source
    return previous


def write_packages(current, previous, site):
    pool = site / 'pool'
    pool.mkdir()
    entries, identities = [], set()
    total_size = 0
    for name, source in sorted((previous | current).items()):
        control = package_control(source)
        metadata = fields(control)
        package, version, architecture = (metadata.get(field) for field in ('package', 'version', 'architecture'))
        if not package or not version or architecture not in {'amd64', 'all'} or metadata.keys() & INDEX_FIELDS:
            raise ValueError(f'Invalid APT metadata in {source.name}')
        identity = (package, version, architecture)
        if identity in identities:
            raise ValueError(f'Duplicate package: {source.name}')
        identities.add(identity)

        size = source.stat().st_size
        total_size += size
        if size > MAX_FILE_SIZE:
            raise ValueError(f'{source.name} is {size} bytes and exceeds the Pages file limit of {MAX_FILE_SIZE} bytes')
        if total_size > MAX_SITE_SIZE:
            raise ValueError(f'Packages exceed the Pages site limit of {MAX_SITE_SIZE} bytes')
        destination = pool / name
        shutil.copyfile(source, destination)
        marker = 'X-SLI-Current: yes\n' if name in current else ''
        entries.append(f'{control}\n{marker}Filename: pool/{name}\nSize: {size}\nSHA256: {sha256(destination)}\n\n')

    index = site / 'dists/trixie' / INDEX_PATH
    index.parent.mkdir(parents=True)
    data = ''.join(entries).encode('utf-8')
    index.write_bytes(data)
    compressed = index.with_suffix('.gz')
    compressed.write_bytes(gzip.compress(data, mtime=0))
    return index, compressed


@contextmanager
def signing_context(key):
    with tempfile.TemporaryDirectory(prefix='sli-apt-gpg-') as temporary:
        gpg = ['gpg', '--no-options', '--homedir', '.', '--batch', '--no-tty']
        try:
            with key.open('rb') as stream:
                subprocess.run([*gpg, '--import'], cwd=temporary, stdin=stream, check=True, capture_output=True)
            listing = subprocess.check_output([*gpg, '--with-colons', '--list-secret-keys'], cwd=temporary, text=True)
            primary = re.findall(r'^sec:.*\n^fpr:(?:[^:\n]*:){8}([0-9A-F]+):', listing, re.M)
            if len(primary) != 1:
                raise ValueError('The GPG signing key file must contain exactly one secret primary key')
            yield gpg, temporary, primary[0]
        finally:
            subprocess.run(['gpgconf', '--homedir', '.', '--kill', 'gpg-agent'], cwd=temporary, check=False)


def sign_release(release, keyring, gpg, home, signer):
    signing = [*gpg, '--local-user', signer, '--pinentry-mode', 'loopback', '--passphrase', '',
               '--digest-algo', 'SHA256']
    for name, mode in [('InRelease', '--clearsign'), ('Release.gpg', '--detach-sign')]:
        with release.open('rb') as source, release.with_name(name).open('wb') as output:
            subprocess.run([*signing, '--armor', '--output', '-', mode], cwd=home,
                           stdin=source, stdout=output, check=True)
    with keyring.open('wb') as output:
        subprocess.run([*gpg, '--export', signer], cwd=home, stdout=output, check=True)
    if not keyring.stat().st_size:
        raise ValueError('Could not export the public signing key')


def build(debs, output, key, pinned, *, previous_url=None, initialize=False):
    if key is None or not key.is_file() or not key.stat().st_size:
        raise ValueError('A nonempty GPG signing key file is required')
    if not debs.is_dir() or output.exists() or output.is_symlink():
        raise ValueError('Provide a package directory and a new output directory')

    current, version = current_packages(debs, pinned)
    output.parent.mkdir(parents=True, exist_ok=True)
    with (tempfile.TemporaryDirectory(prefix='.sli-apt-', dir=output.parent) as temporary,
          signing_context(key) as (gpg, home, signer)):
        site = Path(temporary) / 'site'
        site.mkdir()
        previous = previous_packages(previous_url, Path(temporary), current, version, gpg, home,
                                     initialize=initialize) if previous_url else {}
        indexes = write_packages(current, previous, site)
        release_dir = site / 'dists/trixie'
        release = release_dir / 'Release'
        checksums = ''.join(f' {sha256(path)} {path.stat().st_size} {path.relative_to(release_dir).as_posix()}\n'
                            for path in indexes)
        date = format_datetime(datetime.now(UTC), usegmt=True)
        release.write_text('Origin: SLI\nLabel: SLI\nSuite: trixie\nCodename: trixie\n'
                           f'Date: {date}\nArchitectures: amd64\nComponents: main\n'
                           f'X-SLI-Current-Version: {version}\nSHA256:\n{checksums}',
                           encoding='ascii', newline='\n')
        sign_release(release, site / KEYRING, gpg, home, signer)
        sizes = [path.stat().st_size for path in site.rglob('*') if path.is_file()]
        if max(sizes) > MAX_FILE_SIZE or sum(sizes) > MAX_SITE_SIZE:
            raise ValueError('Signed repository exceeds GitHub Pages size limits')
        site.rename(output)


def repository_pins(pins):
    _, input_runtime, pinned = input_pins(pins)
    if 'runtime_delivery' not in pins:
        return pinned

    delivery = pins['runtime_delivery']
    package = n03_runtime_control.PACKAGE
    original = f'{package}_{n03_runtime_control.ORIGINAL_VERSION}_amd64.deb'
    if (delivery != N03_RUNTIME_DELIVERY or input_runtime != original
            or pinned[original] != n03_runtime_control.ORIGINAL_SHA256):
        raise ValueError('Unexpected runtime compatibility input or pin')

    # The kit replaces the original runtime input with the qualified delivery.
    delivered = f"{package}_{delivery['version']}_amd64.deb"
    del pinned[original]
    pinned[delivered] = delivery['sha256']
    return pinned


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--debs', type=Path, required=True, help='directory of input .deb packages')
    parser.add_argument('--output', type=Path, required=True, help='new directory for the signed repository')
    parser.add_argument('--signing-key', type=Path, required=True, help='file containing the GPG secret key export')
    parser.add_argument('--pins', type=Path, required=True, help='native_pins.json for the selected commit')
    parser.add_argument('--previous-url', help='published APT repository to retain for rollback')
    parser.add_argument('--initialize', action='store_true', help='allow the first publication when no Release exists')
    args = parser.parse_args()
    try:
        pinned = repository_pins(json.loads(args.pins.read_text(encoding='utf-8')))
        build(args.debs, args.output, args.signing_key, pinned, previous_url=args.previous_url,
              initialize=args.initialize)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'APT repository build failed: {error}\n')
    total = 0
    for package in sorted((args.output / 'pool').glob('*.deb')):
        size = package.stat().st_size
        total += size
        print(f'{package.name}: {size} bytes')
    print(f'Total APT packages: {total} bytes')


if __name__ == '__main__':
    main()

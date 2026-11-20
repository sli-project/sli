"""Build a signed Debian 13 APT repository from SLI .deb packages."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import re
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime
from email.utils import format_datetime
from pathlib import Path


MAX_FILE_SIZE = 100_000_000
MAX_SITE_SIZE = 1_000_000_000
KEYRING = 'sli-archive-keyring.gpg'
INDEX_FIELDS = {'filename', 'size', 'md5sum', 'sha1', 'sha256', 'sha512'}


def sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write_packages(debs, site):
    pool = site / 'pool'
    pool.mkdir()
    entries, identities = [], set()
    total_size = 0
    for source in sorted(debs.glob('*.deb')):
        if source.is_symlink() or not source.is_file():
            raise ValueError(f'Invalid Debian package input: {source.name}')
        control = subprocess.check_output(['dpkg-deb', '--field', str(source.absolute())], encoding='utf-8').rstrip('\n')
        fields = {key.lower(): value.strip() for key, value in re.findall(r'^([\w-]+):([^\n]*)', control, re.M)}
        package = fields.get('package', '')
        if package != 'sli' and not package.startswith('sli-'):
            continue

        version, architecture = fields.get('version'), fields.get('architecture')
        if not version or architecture not in {'amd64', 'all'} or fields.keys() & INDEX_FIELDS:
            raise ValueError(f'Invalid APT metadata in {source.name}')
        identity = (package, version, architecture)
        if identity in identities or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.+_~-]*\.deb', source.name):
            raise ValueError(f'Duplicate package or invalid filename: {source.name}')
        identities.add(identity)

        size = source.stat().st_size
        total_size += size
        if size > MAX_FILE_SIZE:
            raise ValueError(f'{source.name} is {size} bytes and exceeds the Pages file limit of {MAX_FILE_SIZE} bytes')
        if total_size > MAX_SITE_SIZE:
            raise ValueError(f'Packages exceed the Pages site limit of {MAX_SITE_SIZE} bytes')
        destination = pool / source.name
        shutil.copyfile(source, destination)
        entries.append(f'{control}\nFilename: pool/{source.name}\nSize: {size}\nSHA256: {sha256(destination)}\n\n')

    if not entries:
        raise ValueError('No SLI Debian packages found')
    index = site / 'dists/trixie/main/binary-amd64/Packages'
    index.parent.mkdir(parents=True)
    data = ''.join(entries).encode('utf-8')
    index.write_bytes(data)
    compressed = index.with_suffix('.gz')
    compressed.write_bytes(gzip.compress(data, mtime=0))
    return index, compressed


def sign_release(release, key, keyring):
    with tempfile.TemporaryDirectory(prefix='sli-apt-gpg-') as temporary:
        gpg = ['gpg', '--no-options', '--homedir', '.', '--batch', '--no-tty']
        try:
            with key.open('rb') as stream:
                subprocess.run([*gpg, '--import'], cwd=temporary, stdin=stream, check=True, capture_output=True)
            listing = subprocess.check_output([*gpg, '--with-colons', '--list-secret-keys'], cwd=temporary, text=True)
            primary = re.findall(r'^sec:.*\n^fpr:(?:[^:\n]*:){8}([0-9A-F]+):', listing, re.M)
            if len(primary) != 1:
                raise ValueError('The GPG signing key file must contain exactly one secret primary key')
            signer = primary[0]
            signing = [*gpg, '--local-user', signer, '--pinentry-mode', 'loopback', '--passphrase', '',
                       '--digest-algo', 'SHA256']
            for name, mode in [('InRelease', '--clearsign'), ('Release.gpg', '--detach-sign')]:
                with release.open('rb') as source, release.with_name(name).open('wb') as output:
                    subprocess.run([*signing, '--armor', '--output', '-', mode], cwd=temporary,
                                   stdin=source, stdout=output, check=True)
            with keyring.open('wb') as output:
                subprocess.run([*gpg, '--export', signer], cwd=temporary, stdout=output, check=True)
            if not keyring.stat().st_size:
                raise ValueError('Could not export the public signing key')
        finally:
            subprocess.run(['gpgconf', '--homedir', '.', '--kill', 'gpg-agent'], cwd=temporary, check=False)


def build(debs, output, key):
    if key is None or not key.is_file() or not key.stat().st_size:
        raise ValueError('A nonempty GPG signing key file is required')
    if not debs.is_dir() or output.exists() or output.is_symlink():
        raise ValueError('Provide a package directory and a new output directory')

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.sli-apt-', dir=output.parent) as temporary:
        site = Path(temporary) / 'site'
        site.mkdir()
        indexes = write_packages(debs, site)
        release_dir = site / 'dists/trixie'
        release = release_dir / 'Release'
        checksums = ''.join(f' {sha256(path)} {path.stat().st_size} {path.relative_to(release_dir).as_posix()}\n'
                            for path in indexes)
        date = format_datetime(datetime.now(UTC), usegmt=True)
        release.write_text('Origin: SLI\nLabel: SLI\nSuite: trixie\nCodename: trixie\n'
                           f'Date: {date}\nArchitectures: amd64\nComponents: main\nSHA256:\n{checksums}',
                           encoding='ascii', newline='\n')
        sign_release(release, key, site / KEYRING)
        sizes = [path.stat().st_size for path in site.rglob('*') if path.is_file()]
        if max(sizes) > MAX_FILE_SIZE or sum(sizes) > MAX_SITE_SIZE:
            raise ValueError('Signed repository exceeds GitHub Pages size limits')
        site.rename(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--debs', type=Path, required=True, help='directory of input .deb packages')
    parser.add_argument('--output', type=Path, required=True, help='new directory for the signed repository')
    parser.add_argument('--signing-key', type=Path, required=True, help='file containing the GPG secret key export')
    args = parser.parse_args()
    try:
        build(args.debs, args.output, args.signing_key)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'APT repository build failed: {error}\n')
    total = 0
    for package in sorted((args.output / 'pool').glob('*.deb')):
        size = package.stat().st_size
        total += size
        print(f'{package.name}: {size} bytes')
    print(f'Total SLI packages: {total} bytes')


if __name__ == '__main__':
    main()

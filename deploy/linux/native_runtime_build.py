"""Build a pinned, private CPython runtime on Debian 13 without wheel downloads."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile

try:
    from deploy.linux import native_package
except ModuleNotFoundError:  # Direct execution alongside native_package.py on the builder.
    import native_package


def require(condition, code):
    if not condition:
        raise ValueError('native_runtime_' + code)


def sha256(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest() if hasattr(hashlib, 'file_digest') else hashlib.sha256(stream.read()).hexdigest()


def normalized(name):
    return re.sub(r'[-_.]+', '-', name).lower()


def verify_inputs(spec, source, wheelhouse):
    require(native_package.ID.fullmatch(spec['id']) and native_package.VERSION.fullmatch(spec['version'])
            and spec['python_version'] == '3.14.6', 'identity_invalid')
    expected = {w['filename'] for w in spec['wheels']}
    require(expected and len(expected) == len(spec['wheels'])
            and all(Path(n).name == n and n.endswith('.whl') for n in expected), 'wheel_set_invalid')
    require({p.name for p in wheelhouse.iterdir()} == expected, 'wheel_set_unlocked')
    for path, digest in [(source, spec['source']['sha256']),
                         *((wheelhouse / w['filename'], w['sha256']) for w in spec['wheels'])]:
        require(path.is_file() and not path.is_symlink() and re.fullmatch('[0-9a-f]{64}', digest)
                and sha256(path) == digest, 'artifact_sha256_mismatch')


def wheel_lock(spec):
    lines = []
    names = set()
    for wheel in sorted(spec['wheels'], key=lambda w: normalized(w['name'])):
        name = normalized(wheel['name'])
        require(re.fullmatch('[a-z0-9][a-z0-9-]*', name) and name not in names
                and re.fullmatch('[0-9][a-zA-Z0-9.+!]*', wheel['version'])
                and re.fullmatch('[0-9a-f]{64}', wheel['sha256']), 'wheel_lock_invalid')
        names.add(name)
        lines.append(f"{name}=={wheel['version']} --hash=sha256:{wheel['sha256']}")
    return '\n'.join(lines) + '\n'


class Commands:
    """Keep bounded command output and UTC/exit receipts outside the repository."""
    def __init__(self, output):
        self.output = output
        (output / 'logs').mkdir(parents=True, exist_ok=True)
        self.sequence = len(list((output / 'logs').glob('*.json')))

    def __call__(self, argv, *, cwd=None, env=None, timeout=1800):
        self.sequence += 1
        label = f'{self.sequence:03d}-{Path(str(argv[0])).name}'
        started = datetime.now(timezone.utc).isoformat()
        result = subprocess.run(list(map(str, argv)), cwd=cwd, env=env, capture_output=True, timeout=timeout)
        for suffix, content in (('stdout', result.stdout), ('stderr', result.stderr)):
            (self.output / 'logs' / f'{label}.{suffix}').write_bytes(content)
        receipt = {'argv': list(map(str, argv)), 'cwd': str(cwd) if cwd else None, 'started_utc': started,
                   'finished_utc': datetime.now(timezone.utc).isoformat(), 'exit_code': result.returncode}
        (self.output / 'logs' / f'{label}.json').write_text(json.dumps(receipt, indent=2) + '\n')
        print(label, result.returncode, flush=True)
        result.stdout = result.stdout.decode('utf-8', errors='replace')
        require(result.returncode == 0, 'command_failed_' + label)
        return result


def install_wheels(prefix, wheelhouse, spec, lock, run):
    lock.write_text(wheel_lock(spec), encoding='utf-8')
    python = str(prefix / 'bin/python3.14')
    run([python, '-I', '-m', 'pip', '--isolated', 'install', '--no-index', '--find-links', str(wheelhouse),
         '--require-hashes', '--only-binary=:all:', '--no-compile', '--disable-pip-version-check', '-r', str(lock)])
    run([python, '-I', '-m', 'pip', 'check'])


def validate_tree(prefix):
    require(prefix.is_dir() and not prefix.is_symlink(), 'prefix_invalid')
    resolved = prefix.resolve()
    for path in prefix.rglob('*'):
        if path.is_symlink():
            require(path.resolve().is_relative_to(resolved), 'symlink_escapes_prefix')
        else:
            require(path.is_file() or path.is_dir(), 'special_file')


def scan_shared_libraries(prefix, pins, run):
    files, external = [], set()
    for path in sorted(prefix.rglob('*')):
        if path.is_symlink() or not path.is_file():
            continue
        with path.open('rb') as stream:
            header = stream.read(18)
            if header[:4] != b'\x7fELF':
                continue
        require(len(header) == 18 and header[5] in (1, 2), 'elf_header_invalid')
        kind = int.from_bytes(header[16:18], 'little' if header[5] == 1 else 'big')
        if kind == 1:  # ET_REL: CPython installs python.o for extension embedders.
            continue
        require(kind in (2, 3), 'elf_type_invalid')
        # auditwheel's private transitive DSOs rely on the importing extension's
        # RPATH, which ldd on a DSO alone does not inherit. Supply only that DSO's
        # private directory for this audit; the actual smoke has no such override.
        bundle = next((p for p in path.parents if p.name.endswith('.libs')
                       and p.is_relative_to(prefix)), None)
        audit_path = [str(bundle), str(prefix / 'lib')] if bundle else []
        kwargs = {'env': dict(os.environ, LD_LIBRARY_PATH=os.pathsep.join(audit_path))} if bundle else {}
        text = run(['ldd', str(path)], **kwargs).stdout
        require('not found' not in text, 'shared_library_unresolved')
        resolved = []
        for line in text.splitlines():
            match = re.search(r'(?:=>\s+|^\s*)(/\S+)\s+\(', line)
            if match:
                library = Path(match[1]).resolve()
                resolved.append(str(library))
                if not library.is_relative_to(prefix.resolve()):
                    external.add(str(library))
        # Many CPython extension DSOs use only symbols exported by libpython;
        # ldd calls these "statically linked" when they have no DT_NEEDED entries.
        require(resolved or (kind == 3 and text.strip() == 'statically linked'), 'elf_without_dependencies')
        files.append({'path': str(path.relative_to(prefix)), 'sha256': sha256(path),
                      'ldd': re.sub(r'\s+\(0x[0-9a-fA-F]+\)', '', text),
                      'resolved': resolved, 'audit_library_path': audit_path})
    require(files, 'no_elf_files')
    packages, providers = {}, []
    accepted = {p['name']: p['version'] for p in pins['packages']}
    for library in sorted(external):
        owner = run(['dpkg-query', '-S', library]).stdout.split(': ', 1)[0].strip()
        require(re.fullmatch(r'[a-z0-9][a-z0-9+.-]*(?::amd64)?', owner), 'library_owner_invalid')
        fields = run(['dpkg-query', '-W', '-f=${Package}\t${Version}\t${Architecture}\n', owner]).stdout.strip().split('\t')
        require(len(fields) == 3, 'library_package_invalid')
        name, version, arch = fields
        require(name not in accepted or accepted[name] == version, 'n02_version_drift_' + name)
        packages[name] = {'name': name, 'version': version, 'architecture': arch}
        providers.append({'path': library, 'package': name, 'version': version})
    return {'schema_version': 1, 'elf_files': files, 'providers': providers,
            'debian_packages': [packages[n] for n in sorted(packages)]}


def make_sbom(prefix, spec, source, debian):
    share = prefix / 'share/sli-runtime'
    licenses = share / 'licenses'
    licenses.mkdir(parents=True, exist_ok=True)
    require((source / 'LICENSE').is_file(), 'python_license_missing')
    packages = []
    for path in sorted(source.rglob('*')):
        if path.is_file() and path.name.upper().startswith(('LICENSE', 'COPYING', 'NOTICE')):
            dest = licenses / 'cpython' / path.relative_to(source)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, dest)
    packages.append({'SPDXID': 'SPDXRef-CPython', 'name': 'CPython', 'versionInfo': spec['python_version'],
                     'downloadLocation': spec['source'].get('url', 'NOASSERTION'), 'filesAnalyzed': False,
                     'licenseDeclared': 'Python-2.0', 'checksums': [{'algorithm': 'SHA256', 'checksumValue': spec['source']['sha256']}]})
    wheels = {normalized(w['name']): w for w in spec['wheels']}
    installed = set()
    site = prefix / 'lib/python3.14/site-packages'
    for dist in sorted(metadata.distributions(path=[str(site)]), key=lambda d: normalized(d.metadata['Name'])):
        name, version = normalized(dist.metadata['Name']), dist.version
        if name == 'pip':
            bundled = list((source / 'Lib/ensurepip/_bundled').glob(f'pip-{version}-*.whl'))
            require(len(bundled) == 1, 'pip_source_missing')
            artifact = {'sha256': sha256(bundled[0]), 'url': spec['source'].get('url', 'NOASSERTION')}
        else:
            require(name in wheels and version == wheels[name]['version'], 'installed_distribution_unlocked')
            installed.add(name)
            artifact = wheels[name]
        copied = []
        for item in dist.files or []:
            if '__pycache__' in item.parts or item.suffix in {'.pyc', '.pyo'}:
                continue
            if 'licenses' in item.parts or item.name.upper().startswith(('LICENSE', 'COPYING', 'NOTICE')):
                path = Path(dist.locate_file(item))
                require(path.resolve().is_relative_to(prefix.resolve()), 'license_path_invalid')
                if path.is_file():
                    dest = licenses / 'python' / name / str(item).replace('../', '_/')
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(path, dest)
                    copied.append({'path': str(dest.relative_to(prefix)), 'sha256': sha256(dest)})
        require(copied, 'distribution_license_missing_' + name)
        packages.append({'SPDXID': 'SPDXRef-pypi-' + name, 'name': name, 'versionInfo': version,
                         'downloadLocation': artifact.get('url', 'NOASSERTION'), 'filesAnalyzed': False,
                         'licenseDeclared': dist.metadata.get('License-Expression')
                         or (dist.metadata.get('License') if dist.metadata.get('License')
                             in {'MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'PSF-2.0'} else 'NOASSERTION'),
                         'licenseComments': 'License texts and their SHA256: share/sli-runtime/licenses.json; '
                         + 'legacy metadata: ' + str(dist.metadata.get('License') or '')
                         + '; classifiers: ' + str(dist.metadata.get_all('Classifier', []) if hasattr(dist.metadata, 'get_all') else []),
                         'checksums': [{'algorithm': 'SHA256', 'checksumValue': artifact['sha256']}],
                         'externalRefs': [{'referenceCategory': 'PACKAGE-MANAGER', 'referenceType': 'purl',
                                           'referenceLocator': f'pkg:pypi/{name}@{version}'}]})
    require(installed == set(wheels), 'installed_wheel_set_mismatch')
    for package in debian:
        name = package['name']
        copyright_file = Path('/usr/share/doc') / name / 'copyright'
        require(copyright_file.is_file(), 'debian_license_missing_' + name)
        dest = licenses / 'debian' / (name + '.copyright')
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(copyright_file, dest)
        artifact = next((p for p in spec.get('debian_artifacts', []) if p['name'] == name
                         and p['version'] == package['version']), None)
        require(artifact is not None, 'debian_artifact_hash_missing_' + name)
        packages.append({'SPDXID': 'SPDXRef-deb-' + name, 'name': name, 'versionInfo': package['version'],
                         'downloadLocation': 'NOASSERTION', 'filesAnalyzed': False, 'licenseDeclared': 'NOASSERTION',
                         'licenseComments': 'See share/sli-runtime/licenses/debian/' + name + '.copyright',
                         'checksums': [{'algorithm': 'SHA256', 'checksumValue': artifact['sha256']}]})
    license_inventory = [{'path': str(p.relative_to(prefix)), 'sha256': sha256(p)}
                         for p in sorted(licenses.rglob('*')) if p.is_file()
                         and '__pycache__' not in p.parts and p.suffix not in {'.pyc', '.pyo'}]
    (share / 'licenses.json').write_text(json.dumps(license_inventory, indent=2) + '\n')
    root = 'SPDXRef-runtime'
    packages.insert(0, {'SPDXID': root, 'name': 'sli-runtime-' + spec['id'], 'versionInfo': spec['version'],
                        'downloadLocation': 'NOASSERTION', 'filesAnalyzed': False, 'licenseDeclared': 'NOASSERTION'})
    return {'spdxVersion': 'SPDX-2.3', 'dataLicense': 'CC0-1.0', 'SPDXID': 'SPDXRef-DOCUMENT',
            'name': 'sli-runtime-' + spec['id'],
            'documentNamespace': 'https://sli.invalid/sbom/' + spec['id'] + '-' + spec['source']['sha256'],
            'creationInfo': {'creators': ['Tool: sli-native-runtime-build'],
                             'created': datetime.fromtimestamp(spec['source_date_epoch'], timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')},
            'documentDescribes': [root], 'packages': packages,
            'relationships': [{'spdxElementId': root, 'relationshipType': 'CONTAINS', 'relatedSpdxElement': p['SPDXID']}
                              for p in packages[1:]]}


def package_runtime(prefix, spec, output, run):
    require(native_package.ID.fullmatch(spec['id']) and native_package.VERSION.fullmatch(spec['version'])
            and prefix.name == spec['id'], 'identity_invalid')
    validate_tree(prefix)
    share = prefix / 'share/sli-runtime'
    require(all((share / name).is_file() for name in ('sbom.json', 'shared-libraries.json'))
            and (share / 'licenses').is_dir() and any((share / 'licenses').rglob('*')), 'inventory_required')
    dependencies = spec.get('debian_runtime', [])
    require(dependencies and all(re.fullmatch('[a-z0-9][a-z0-9+.-]*', p['name'])
            and re.fullmatch('[a-zA-Z0-9:.+~_-]+', p['version']) for p in dependencies), 'dependencies_invalid')
    output.mkdir(parents=True, exist_ok=True)
    destination = output / f"sli-runtime-{spec['id']}_{spec['version']}_amd64.deb"
    with tempfile.TemporaryDirectory(prefix='runtime-package-', dir=output) as temp:
        root = Path(temp)
        payload = root / 'opt/sli/runtimes' / spec['id']
        shutil.copytree(prefix, payload, symlinks=True, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        native_package.control(root, 'sli-runtime-' + spec['id'], spec['version'],
                               ', '.join(f"{p['name']} (= {p['version']})" for p in dependencies),
                               'SLI private CPython 3.14.6 and verified Linux wheels')
        size = sum((p.lstat().st_size + 1023) // 1024 for p in payload.rglob('*'))
        with (root / 'DEBIAN/control').open('a') as stream:
            stream.write(f'Installed-Size: {size}\n')
        for path in sorted(root.rglob('*')):
            if not path.is_symlink():
                path.chmod(0o755 if path.is_dir() or path.stat().st_mode & 0o111 else 0o644)
            os.utime(path, (spec.get('source_date_epoch', 0),) * 2, follow_symlinks=False)
        root.chmod(0o755)
        os.utime(root, (spec.get('source_date_epoch', 0),) * 2)
        run(['dpkg-deb', '--root-owner-group', '-Zgzip', '--build', str(root), str(destination)],
            env=dict(os.environ, SOURCE_DATE_EPOCH=str(spec.get('source_date_epoch', 0)), TZ='UTC'))
    return destination


def smoke_code(spec):
    modules = sorted(set(spec.get('import_modules', [])) | {'psycopg', 'psycopg.pq', 'cryptography',
        'cryptography.hazmat.primitives.ciphers.aead', 'ssl', 'sqlite3', 'ctypes', 'zoneinfo',
        'zlib', 'bz2', 'lzma', 'readline', 'compression.zstd', 'dbm.gnu', 'dbm.ndbm'})
    expected = {normalized(w['name']): w['version'] for w in spec['wheels']}
    return f'''import errno, hashlib, importlib, importlib.metadata, json, os, socket, sys
from pathlib import Path
assert sys.version.split()[0] == {spec['python_version']!r}, sys.version
assert sys.prefix == '/opt/sli/runtimes/{spec['id']}', sys.prefix
s = socket.socket()
assert s.connect_ex(('198.51.100.1', 9)) in (errno.ENETUNREACH, errno.EHOSTUNREACH), 'network namespace is not isolated'
s.close()
modules = {modules!r}
for module in modules: importlib.import_module(module)
for name, version in {expected!r}.items(): assert importlib.metadata.version(name) == version, name
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
key = AESGCM(bytes(32)); nonce = bytes(12)
assert key.decrypt(nonce, key.encrypt(nonce, b'sli-n03', None), None) == b'sli-n03'
from argon2 import PasswordHasher
h = PasswordHasher(); assert h.verify(h.hash('synthetic-n03'), 'synthetic-n03')
from pydantic import BaseModel
class Check(BaseModel): value: int
assert Check(value='3').value == 3
from zoneinfo import ZoneInfo
assert str(ZoneInfo('Europe/Moscow')) == 'Europe/Moscow'
from psycopg import pq
assert pq.__impl__ == 'binary', pq.__impl__
import ssl, sqlite3, ctypes, zlib, bz2, lzma
assert ssl.create_default_context().cert_store_stats()['x509_ca'] > 0
assert sqlite3.connect(':memory:').execute('select 3').fetchone() == (3,)
assert ctypes.CDLL(None).getpid() == os.getpid()
for m in (zlib, bz2, lzma): assert m.decompress(m.compress(b'n03')) == b'n03'
print(json.dumps(dict(status='verified', python=sys.version, prefix=sys.prefix, imported=modules,
    distributions={expected!r}, network='unshare --net; external connect fails ENETUNREACH/EHOSTUNREACH',
    libpq=pq.version(), openssl=ssl.OPENSSL_VERSION, python_sha256=hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()), sort_keys=True))
'''


def compile_runtime(spec, source, wheelhouse, work, run, jobs):
    prefix = Path('/opt/sli/runtimes') / spec['id']
    require(not prefix.exists() and not work.exists(), 'build_path_already_exists')
    verify_inputs(spec, source, wheelhouse)
    work.mkdir(parents=True)
    with tarfile.open(source) as archive:
        archive.extractall(work, filter='data')
    tree = work / ('Python-' + spec['python_version'])
    require((tree / 'configure').is_file(), 'source_layout_invalid')
    env = dict(os.environ, LC_ALL='C.UTF-8', TZ='UTC', SOURCE_DATE_EPOCH=str(spec['source_date_epoch']),
               CFLAGS=f'-O2 -g0 -ffile-prefix-map={work}=/usr/src/sli-runtime',
               LDFLAGS=f'-Wl,-rpath,{prefix}/lib')
    run(['./configure', '--prefix=' + str(prefix), '--enable-shared', '--with-ensurepip=install',
         '--disable-test-modules'], cwd=tree, env=env)
    run(['make', '-j' + str(jobs)], cwd=tree, env=env, timeout=3600)
    run(['make', 'install'], cwd=tree, env=env, timeout=1800)
    install_wheels(prefix, wheelhouse, spec, work / 'requirements-linux.lock.txt', run)
    return prefix, tree


def finalize(spec, pins, prefix, tree, output, run):
    shlibs = scan_shared_libraries(prefix, pins, run)
    # TLS trust data is a runtime dependency, even though it is not an ELF library.
    ca = run(['dpkg-query', '-W', '-f=${Package}\t${Version}\t${Architecture}\n', 'ca-certificates']).stdout.strip().split('\t')
    observed = sorted(shlibs['debian_packages'] + [dict(zip(('name', 'version', 'architecture'), ca))], key=lambda p: p['name'])
    if spec.get('debian_runtime'):
        require(observed == spec['debian_runtime'], 'runtime_dependency_drift')
    spec['debian_runtime'] = observed
    share = prefix / 'share/sli-runtime'
    share.mkdir(parents=True, exist_ok=True)
    (share / 'shared-libraries.json').write_text(json.dumps(shlibs, indent=2) + '\n')
    (share / 'sbom.json').write_text(json.dumps(make_sbom(prefix, spec, tree, observed), indent=2) + '\n')
    (share / 'build-spec.json').write_text(json.dumps(spec, indent=2) + '\n')
    (share / 'requirements-linux.lock.txt').write_text(wheel_lock(spec))
    (share / 'smoke.py').write_text(smoke_code(spec))
    run(['unshare', '--net', '--', str(prefix / 'bin/python3.14'), '-I', str(share / 'smoke.py')])
    destination = package_runtime(prefix, spec, output, run)
    for name in ('shared-libraries.json', 'sbom.json', 'licenses.json', 'build-spec.json'):
        shutil.copy2(share / name, output / name)
    (output / 'artifact.json').write_text(json.dumps({'filename': destination.name, 'sha256': sha256(destination),
        'size': destination.stat().st_size, 'python_sha256': sha256(prefix / 'bin/python3.14')}, indent=2) + '\n')
    return destination


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('pins', 'source', 'wheelhouse', 'work', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--jobs', type=int, default=2, choices=range(1, 17))
    parser.add_argument('--phase', choices=('all', 'finalize'), default='all')
    args = parser.parse_args(argv)
    pins = json.loads(args.pins.read_text())
    spec = pins['runtime_build']
    require(platform.freedesktop_os_release().get('ID') == 'debian'
            and platform.freedesktop_os_release().get('VERSION_ID') == '13'
            and platform.machine() == 'x86_64' and os.geteuid() == 0, 'debian13_amd64_root_required')
    run = Commands(args.output)
    verify_inputs(spec, args.source, args.wheelhouse)
    for package in spec.get('debian_build', []):
        observed = run(['dpkg-query', '-W', '-f=${Version}', package['name']]).stdout
        require(observed == package['version'], 'build_dependency_drift_' + package['name'])
    if args.phase == 'all':
        prefix, tree = compile_runtime(spec, args.source, args.wheelhouse, args.work, run, args.jobs)
    else:
        prefix = Path('/opt/sli/runtimes') / spec['id']
        tree = args.work / ('Python-' + spec['python_version'])
    finalize(spec, pins, prefix, tree, args.output, run)
    print('native_runtime_built')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

"""N03 artifact contracts with local fixtures and fake Debian commands."""
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from deploy.linux import native_runtime_build as build

ELF_SHARED = b'\x7fELF\x02\x01' + bytes(10) + b'\x03\x00'
ELF_OBJECT = b'\x7fELF\x02\x01' + bytes(10) + b'\x01\x00'


@pytest.fixture
def inputs(tmp_path):
    source = tmp_path / 'Python.tar.xz'
    source.write_bytes(b'accepted source')
    wheels = tmp_path / 'wheels'
    wheels.mkdir()
    wheel = wheels / 'demo-1.0-py3-none-any.whl'
    wheel.write_bytes(b'accepted wheel')
    spec = {'id': 'cp3146-test', 'version': '3.14.6-1~deb13', 'python_version': '3.14.6',
            'source': {'filename': source.name, 'sha256': hashlib.sha256(source.read_bytes()).hexdigest()},
            'wheels': [{'name': 'demo', 'version': '1.0', 'filename': wheel.name,
                        'sha256': hashlib.sha256(wheel.read_bytes()).hexdigest()}]}
    return source, wheels, spec


def test_verified_inputs_produce_complete_hash_lock(inputs):
    source, wheels, spec = inputs
    build.verify_inputs(spec, source, wheels)
    assert build.wheel_lock(spec) == 'demo==1.0 --hash=sha256:' + spec['wheels'][0]['sha256'] + '\n'


@pytest.mark.parametrize('which', ['source', 'wheel'])
def test_tampered_input_fails_before_build(inputs, which):
    source, wheels, spec = inputs
    target = source if which == 'source' else next(wheels.iterdir())
    target.write_bytes(b'tampered')
    with pytest.raises(ValueError, match='sha256'):
        build.verify_inputs(spec, source, wheels)


def test_unlocked_wheel_is_rejected(inputs):
    source, wheels, spec = inputs
    (wheels / 'unlocked.whl').write_bytes(b'not locked')
    with pytest.raises(ValueError, match='wheel_set'):
        build.verify_inputs(spec, source, wheels)


@pytest.mark.parametrize('field,value', [('id', '../outside'), ('version', '1\nDepends: evil'),
                                      ('python_version', '3.13.0')])
def test_invalid_identity_rejected(inputs, field, value):
    source, wheels, spec = inputs
    spec[field] = value
    with pytest.raises(ValueError, match='identity'):
        build.verify_inputs(spec, source, wheels)


def test_install_is_hash_enforced_binary_only_and_offline(inputs, tmp_path):
    _, wheels, spec = inputs
    calls = []
    build.install_wheels(tmp_path / 'prefix', wheels, spec, tmp_path / 'locked.txt',
                         lambda argv, **kw: calls.append(argv))
    install = calls[0]
    assert {'--no-index', '--require-hashes', '--only-binary=:all:', '--no-compile'} <= set(install)
    assert calls[-1][-2:] == ['pip', 'check']
    assert 'demo==1.0 --hash=sha256:' in (tmp_path / 'locked.txt').read_text()


def test_missing_shared_library_fails_closed(tmp_path):
    elf = tmp_path / 'module.so'
    elf.write_bytes(ELF_SHARED)
    def missing(argv, **kw):
        return SimpleNamespace(stdout='libbad.so => not found\n', returncode=0)
    with pytest.raises(ValueError, match='unresolved'):
        build.scan_shared_libraries(tmp_path, {'packages': []}, missing)


def test_python_extension_without_dt_needed_is_in_inventory(tmp_path):
    (tmp_path / '_asyncio.so').write_bytes(ELF_SHARED)
    def static(argv, **kw):
        return SimpleNamespace(stdout='\tstatically linked\n')
    result = build.scan_shared_libraries(tmp_path, {'packages': []}, static)
    assert result['elf_files'][0]['path'] == '_asyncio.so'
    assert result['elf_files'][0]['resolved'] == []
    assert result['debian_packages'] == []


def test_vendored_dso_is_audited_with_its_private_loader_context(tmp_path):
    bundle = tmp_path / 'site/demo.libs'
    bundle.mkdir(parents=True)
    (bundle / 'libfoo.so').write_bytes(ELF_SHARED)
    def audit(argv, **kw):
        assert str(bundle) in kw['env']['LD_LIBRARY_PATH']
        return SimpleNamespace(stdout='statically linked\n')
    result = build.scan_shared_libraries(tmp_path, {'packages': []}, audit)
    assert result['elf_files'][0]['audit_library_path']


def test_shlibs_resolve_exact_debian_packages_and_reject_n02_drift(tmp_path):
    elf = tmp_path / 'module.so'
    elf.write_bytes(ELF_SHARED)
    (tmp_path / 'python.o').write_bytes(ELF_OBJECT)
    def fake(argv, **kw):
        if argv[0] == 'ldd':
            assert not argv[-1].endswith('python.o'), 'relocatable objects cannot be inspected with ldd'
            return SimpleNamespace(stdout='libc.so.6 => /usr/lib/x86_64-linux-gnu/libc.so.6 (0x123)\n')
        if argv[:2] == ['dpkg-query', '-S']:
            return SimpleNamespace(stdout='libc6:amd64: /usr/lib/x86_64-linux-gnu/libc.so.6\n')
        return SimpleNamespace(stdout='libc6\t2.41-12\tamd64\n')
    pins = {'packages': [{'name': 'libc6', 'version': '2.41-12'}]}
    result = build.scan_shared_libraries(tmp_path, pins, fake)
    assert result['debian_packages'] == [{'name': 'libc6', 'version': '2.41-12', 'architecture': 'amd64'}]
    assert '0x123' not in result['elf_files'][0]['ldd']
    pins['packages'][0]['version'] = 'different'
    with pytest.raises(ValueError, match='n02_version'):
        build.scan_shared_libraries(tmp_path, pins, fake)


def test_runtime_symlinks_cannot_escape_prefix(tmp_path):
    prefix = tmp_path / 'runtime'
    prefix.mkdir()
    (prefix / 'python').write_bytes(b'python')
    (prefix / 'link').symlink_to('python')
    build.validate_tree(prefix)
    (prefix / 'link').unlink()
    (prefix / 'link').symlink_to('../outside')
    with pytest.raises(ValueError, match='symlink'):
        build.validate_tree(prefix)


def test_package_preserves_private_prefix_and_requires_inventory(tmp_path, inputs):
    _, _, spec = inputs
    prefix = tmp_path / spec['id']
    (prefix / 'bin').mkdir(parents=True)
    (prefix / 'bin/python3.14').write_bytes(b'python')
    (prefix / 'bin/python3').symlink_to('python3.14')
    cache = prefix / 'lib/python3.14/__pycache__'
    cache.mkdir(parents=True)
    (cache / 'generated.pyc').write_bytes(b'build-time bytecode')
    out = tmp_path / 'out'
    with pytest.raises(ValueError, match='inventory'):
        build.package_runtime(prefix, spec, out, lambda argv, **kw: None)
    share = prefix / 'share/sli-runtime'
    share.mkdir(parents=True)
    for name in ('sbom.json', 'shared-libraries.json'):
        (share / name).write_text('{}')
    (share / 'licenses').mkdir()
    (share / 'licenses/Python.txt').write_text('PSF license')
    captured = {}
    def fake(argv, **kw):
        assert kw['env']['SOURCE_DATE_EPOCH'] == '0'
        root = Path(argv[-2])
        assert root.stat().st_mode & 0o777 == 0o755
        captured['control'] = (root / 'DEBIAN/control').read_text()
        assert (root / 'opt/sli/runtimes' / spec['id'] / 'bin/python3').is_symlink()
        assert not list(root.rglob('*.pyc'))
        assert not (root / 'DEBIAN/postinst').exists()
    spec['debian_runtime'] = [{'name': 'libc6', 'version': '2.41-12', 'architecture': 'amd64'}]
    build.package_runtime(prefix, spec, out, fake)
    assert 'Depends: libc6 (= 2.41-12)' in captured['control']
    assert 'Package: sli-runtime-cp3146-test' in captured['control']


def test_smoke_covers_all_locked_distributions_and_critical_modules(inputs):
    _, _, spec = inputs
    spec['import_modules'] = ['demo']
    code = build.smoke_code(spec)
    for name in ('demo', 'psycopg', 'cryptography', 'ssl', 'sqlite3', 'ctypes', 'zoneinfo'):
        assert name in code
    assert '3.14.6' in code
    assert 'sys.prefix' in code


def test_sbom_rejects_missing_license(inputs, tmp_path):
    source, _, spec = inputs
    with pytest.raises(ValueError, match='license'):
        build.make_sbom(tmp_path, spec, source, [])


def test_sbom_carries_artifact_hash_and_legacy_license(inputs, tmp_path, monkeypatch):
    _, _, spec = inputs
    spec['source_date_epoch'] = 0
    tree = tmp_path / 'source'
    tree.mkdir()
    (tree / 'LICENSE').write_text('PSF license')
    prefix = tmp_path / 'runtime'
    item = Path('demo.dist-info/licenses/LICENSE')
    path = prefix / 'lib/python3.14/site-packages' / item
    path.parent.mkdir(parents=True)
    path.write_text('MIT license')
    cache = Path('demo.dist-info/licenses/__pycache__/generated.pyc')
    cache_path = prefix / 'lib/python3.14/site-packages' / cache
    cache_path.parent.mkdir()
    cache_path.write_bytes(b'generated cache, not license text')
    dist = SimpleNamespace(metadata={'Name': 'demo', 'License': 'MIT'}, version='1.0', files=[item, cache],
                           locate_file=lambda relative: prefix / 'lib/python3.14/site-packages' / relative)
    monkeypatch.setattr(build.metadata, 'distributions', lambda **kw: [dist])
    sbom = build.make_sbom(prefix, spec, tree, [])
    package = next(p for p in sbom['packages'] if p['name'] == 'demo')
    assert package['licenseDeclared'] == 'MIT'
    assert package['checksums'][0]['checksumValue'] == spec['wheels'][0]['sha256']
    inventory = json.loads((prefix / 'share/sli-runtime/licenses.json').read_text())
    assert inventory
    assert not any(p['path'].endswith('.pyc') or '__pycache__' in p['path'] for p in inventory)

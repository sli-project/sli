"""Synthetic staged updater protocol. No host CLI, services or release keys."""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from server.sli import release_package as package
from deploy.linux import updater_launcher as launcher
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def materialize(root, version):
    names = package.UPDATER_CLOSURE_FILES if version == '1.1.0' else package.UPDATER_FILES
    for name in names:
        destination = root / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        body = (ROOT / name).read_bytes()
        if name == 'server/sli/release_package.py':
            marker = b'UPDATER_RELEASE_VERSION = "1.1.0"'
            assert body.count(marker) == 1
            body = body.replace(marker, ('UPDATER_RELEASE_VERSION = "' + version + '"').encode())
        destination.write_bytes(body)
    return names


def signed_fixture(root, output, source, target, key, *, alter=None):
    names = package.UPDATER_CLOSURE_FILES if target == '1.1.0' else package.UPDATER_FILES
    payload = {name: (root / name).read_bytes() for name in names}
    manifest = dict(schema_version=2, package_type='plugin-update', package_id='sli.updater',
        component='updater', version=target, from_version=source, to_version=target,
        platform='linux-amd64', source_commit='a' * 40, build_id='synthetic-only', minimum_updater=1,
        compatibility=dict(core_api=1, ui_api=1, from_version=source, min_version=source,
                           max_version=source, os='linux', architecture='amd64'),
        required_free_disk=1024, migrations={}, deletions=[], restart_profile='none',
        image=None, compose_delta=None, config_delta=None,
        files=[dict(path=name, size=len(body), sha256=hashlib.sha256(body).hexdigest())
               for name, body in sorted(payload.items())])
    if alter:
        alter(manifest)
    raw = package.canonical_json(manifest)
    signature = dict(algorithm='ed25519', key_id='synthetic-only', signature=base64.b64encode(
        key.sign(package.SIGNING_CONTEXT + raw)).decode())
    with zipfile.ZipFile(output, 'w') as archive:
        archive.writestr(package.MANIFEST_NAME, raw)
        archive.writestr(package.SIGNATURE_NAME, package.canonical_json(signature))
        for name, body in payload.items():
            archive.writestr('payload/' + name, body)
    return manifest


ISOLATED = r"""
import importlib.abc, importlib.machinery, sys
from pathlib import Path
source = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(source))
class PackagedOnly(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] not in {'deploy', 'scripts', 'server'}:
            return None
        spec = importlib.machinery.PathFinder.find_spec(fullname, path)
        assert spec is not None, 'missing packaged module: ' + fullname
        locations = [spec.origin] if spec.origin else list(spec.submodule_search_locations)
        assert locations and all(Path(p).resolve().is_relative_to(source) for p in locations), fullname
        return spec
sys.meta_path.insert(0, PackagedOnly())
"""


def run_isolated(source, code, arguments, cwd):
    return subprocess.run([sys.executable, '-I', '-B', '-c', ISOLATED + code, str(source),
                           *map(str, arguments)], cwd=cwd, text=True, capture_output=True,
                          timeout=60, check=False)


@unittest.skipUnless(sys.platform == "linux", "Linux updater contracts")
class TransitionTests(unittest.TestCase):
    def test_exact_profile_source_builder_and_default_identity(self):
        from tools.build_update_package import validate_updater_source
        from deploy.linux.updater_component import UpdaterComponent, APPROVED_LAUNCHER_SHA256
        self.assertEqual(package.UPDATER_RELEASE_VERSION, '1.1.0')
        self.assertEqual(package.updater_files(package.UPDATER_RELEASE_VERSION), package.UPDATER_CLOSURE_FILES)
        self.assertEqual(hashlib.sha256((ROOT/'deploy/linux/updater_launcher.py').read_bytes()).hexdigest(),
                         APPROVED_LAUNCHER_SHA256)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for version, profile, previous in [('1.0.1','bridge-17','1.0.0'),('1.1.0','closure-22','1.0.1')]:
                source = root / version
                names = materialize(source, version)
                metadata = dict(version=version, to_version=version, from_version=previous,
                                files=[dict(path=p) for p in names])
                validate_updater_source(metadata, source, profile)
                for wrong in (None, 'unknown', 'closure-22' if profile=='bridge-17' else 'bridge-17'):
                    with self.assertRaises(package.PackageError):
                        validate_updater_source(metadata, source, wrong)
                bad = dict(metadata, from_version='0.0.0')
                with self.assertRaises(package.PackageError):
                    validate_updater_source(bad, source, profile)
            # The actual new source baseline is closure22, never legacy17.
            manager = UpdaterComponent(root/'runtime', source_root=ROOT)
            baseline = manager.baseline()
            self.assertEqual(baseline['version'], '1.1.0')
            self.assertEqual(set(baseline['files']), set(package.UPDATER_CLOSURE_FILES))
            self.assertFalse(manager.state.exists())

    def test_authenticated_closure_rejects_every_added_file_tamper_and_bad_contract(self):
        with tempfile.TemporaryDirectory() as temp:
            _, complete, artifact, trust, _ = self.lifecycle_fixture(temp)
            with zipfile.ZipFile(artifact) as archive:
                original = {n:archive.read(n) for n in archive.namelist()}
            for path in package.UPDATER_CLOSURE_FILES - package.UPDATER_FILES:
                for mode in ('modified','missing'):
                    changed = dict(original)
                    if mode == 'modified':
                        changed['payload/'+path] += b'changed'
                    else:
                        del changed['payload/'+path]
                    bad = Path(temp)/'bad.zip'
                    with zipfile.ZipFile(bad,'w') as archive:
                        for name, body in changed.items():
                            archive.writestr(name,body)
                    with self.subTest(path=path, mode=mode), self.assertRaises(package.PackageError):
                        package.verify_package(bad, trust)
            manifest = package.read_json(original[package.MANIFEST_NAME])
            for change in ({'minimum_updater':2},{'minimum_updater':True},{'to_version':'1.2.0','version':'1.2.0'},
                           {'from_version':'1.0.0'}, {'files':manifest['files'][:-1]}):
                invalid = {**manifest,**change}
                with self.subTest(change=change), self.assertRaises(package.PackageError):
                    package.validate_manifest(invalid, package.PackageLimits())
            installed = dict(component='updater', version='1.0.0', os='linux', architecture='amd64')
            with self.assertRaises(package.PackageError):
                package.verify_package(artifact, trust, installed=installed, component='updater', free_bytes=10**9)

    def lifecycle_fixture(self, temp):
        root = Path(temp)
        bridge, complete = root / 'bridge', root / 'complete'
        materialize(bridge, '1.0.1')
        materialize(complete, '1.1.0')
        key = Ed25519PrivateKey.generate()
        artifact = root / 'complete.zip'
        signed_fixture(complete, artifact, '1.0.1', '1.1.0', key)
        trust = root / 'trust.json'
        trust.write_bytes(package.canonical_json(dict(schema_version=1, keys=[dict(
            key_id='synthetic-only', public_key=base64.b64encode(key.public_key().public_bytes(
                Encoding.Raw, PublicFormat.Raw)).decode(), package_ids=['sli.updater'], revoked=False)])))
        neutral = root / 'neutral'
        neutral.mkdir()
        return bridge, complete, artifact, trust, neutral

    def test_frozen_old_to_bridge_then_closure_uses_real_packaged_sources(self):
        with tempfile.TemporaryDirectory() as temp:
            bridge, _, artifact, trust, neutral = self.lifecycle_fixture(temp)
            root = Path(temp)
            old = root / 'old'
            materialize(old, '1.0.0')
            frozen = ROOT / 'tests/fixtures/updater_pre_closure'
            for target, fixture, digest in (
                ('server/sli/release_package.py', 'release_package.py', '5e6c006d9df1e80c382d3e5bff38aa525da4cb625f2e90142968a27aee8ef4ec'),
                ('scripts/maintenance/release_package.py', 'release_package_exports.py', 'ae123608b229790e50dff8afb49cd6029c7bb0b585447deabe6548960a4b1325'),
                ('deploy/linux/updater_component.py', 'updater_component.py', '0e46d20ff763aacc6787d4dadc43792db61aa0c33359d1ddea5ee1fd2c04bb63'),
                ('deploy/linux/sli_update.py', 'sli_update.py', 'f99e8c8dd1a98a98a2acb22a8f1f1f6cb62ec593ad78f6c6134a644fcd2612a7'),
                ('deploy/linux/installation.py', 'installation.py', 'd13771bbfa19a77b3ac4844d4205bb5c3ba718d415fe53770432e045b738ac22'),
            ):
                body = (frozen / fixture).read_bytes()
                self.assertEqual(hashlib.sha256(body).hexdigest(), digest)
                (old / target).write_bytes(body)
            key = Ed25519PrivateKey.generate()
            trust.write_bytes(package.canonical_json(dict(schema_version=1, keys=[dict(
                key_id='synthetic-only', public_key=base64.b64encode(key.public_key().public_bytes(
                    Encoding.Raw, PublicFormat.Raw)).decode(), package_ids=['sli.updater'], revoked=False)])))
            b = root / 'bridge.zip'
            signed_fixture(bridge, b, '1.0.0', '1.0.1', key)
            signed_fixture(root / 'complete', artifact, '1.0.1', '1.1.0', key)
            runtime = root / 'runtime'
            code = r"""
from deploy.linux import updater_component as component
from server.sli.release_package import verify_package, PackageError
import subprocess
runtime, artifact, trust, closure = map(Path, sys.argv[2:6])
try:
    verify_package(closure, trust)
except PackageError:
    pass
else:
    raise AssertionError('old verifier admitted closure')
def selftest(root, version):
    command = sys.argv[6] + '\nfrom deploy.linux.updater_component import selftest; assert selftest(sys.argv[2]) == "selftest_passed"'
    result = subprocess.run([sys.executable, '-I', '-B', '-c', command, str(root), version],
                            cwd=Path.cwd(), text=True, capture_output=True, timeout=20, check=False)
    assert result.returncode == 0, result.stderr
manager = component.UpdaterComponent(runtime, trust, source_root=source, selftest=selftest)
assert manager.apply(artifact) == 'committed'
assert manager.read_pointer()['current']['version'] == '1.0.1'
assert manager.read_pointer()['previous']['version'] == '1.0.0'
"""
            result = run_isolated(old, code, [runtime, b, trust, artifact, ISOLATED], neutral)
            self.assertEqual(result.returncode, 0, result.stderr)
            operator = runtime / 'tools/updater_launcher.py'
            operator.parent.mkdir()
            operator.write_bytes((frozen / 'updater_launcher.py').read_bytes())
            pointer = json.loads((runtime / 'state/updater.json').read_bytes())
            selected_bridge = runtime / 'updater/versions' / pointer['current']['directory']
            code = r"""
from deploy.linux import updater_component as component
from server.sli.release_package import PackageError
import os, subprocess
runtime, artifact, trust = map(Path, sys.argv[2:5])
real = component.check_launcher
component.check_launcher = lambda p, h: real(p, h, owner_uid=os.getuid())
def selftest(root, version):
    command = sys.argv[5] + '\nfrom deploy.linux.updater_component import selftest; assert selftest(sys.argv[2]) == "selftest_passed"'
    result = subprocess.run([sys.executable, '-I', '-B', '-c', command, str(root), version],
                            cwd=Path.cwd(), text=True, capture_output=True, timeout=20, check=False)
    assert result.returncode == 0, result.stderr
manager = component.UpdaterComponent(runtime, trust, source_root=source, selftest=selftest)
if sys.argv[6] == 'old':
    before = {str(p.relative_to(runtime)): (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode)
              for p in runtime.rglob('*') if p.is_file()}
    try:
        manager.apply(artifact)
    except PackageError as exc:
        assert str(exc) == 'update_launcher_upgrade_required', str(exc)
    else:
        raise AssertionError('old launcher admitted')
    after = {str(p.relative_to(runtime)): (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode)
             for p in runtime.rglob('*') if p.is_file()}
    assert before == after
else:
    assert manager.apply(artifact) == 'committed'
    assert manager.read_pointer()['current']['version'] == '1.1.0'
    assert manager.rollback() == 'rolled_back'
    assert manager.read_pointer()['current']['version'] == '1.0.1'
    assert manager.read_pointer()['previous'] is None
"""
            result = run_isolated(selected_bridge, code, [runtime, artifact, trust, ISOLATED, 'old'], neutral)
            self.assertEqual(result.returncode, 0, result.stderr)
            operator.write_bytes((ROOT / 'deploy/linux/updater_launcher.py').read_bytes())
            result = run_isolated(selected_bridge, code, [runtime, artifact, trust, ISOLATED, 'new'], neutral)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_bridge_refuses_missing_or_old_launcher_before_mutation(self):
        code = r"""
from deploy.linux import updater_component as component, sli_update
from deploy.linux import installation
from server.sli.release_package import PackageError
import os
runtime, artifact, trust = map(Path, sys.argv[2:5])
real = component.check_launcher
# Only the synthetic operator UID differs; the real digest/path checks run.
component.check_launcher = lambda p, h: real(p, h, owner_uid=os.getuid())
manager = component.UpdaterComponent(runtime, trust, source_root=source,
    selftest=lambda *_: (_ for _ in ()).throw(AssertionError('must not execute')))
def snapshot():
    return {str(p.relative_to(runtime)): p.read_bytes() for p in runtime.rglob('*') if p.is_file()}
before = snapshot()
for dry in (False, True):
    try:
        manager.apply(artifact, dry_run=dry)
    except PackageError as exc:
        assert str(exc) == 'update_launcher_upgrade_required', str(exc)
    else:
        raise AssertionError('old launcher admitted')
    assert snapshot() == before
    assert not (runtime / 'state').exists()
for operation in (lambda: sli_update.Updater(runtime, trust, None),
                  lambda: installation.adopt(runtime, None),
                  lambda: installation.install(None, None, runtime, None, None),
                  lambda: sli_update.apply_update(None), lambda: sli_update.rollback_update()):
    try:
        operation()
    except PackageError as exc:
        assert str(exc) == 'update_updater_transition_required', str(exc)
    else:
        raise AssertionError('bridge ordinary operation admitted')
assert snapshot() == before
"""
        for old in (False, True):
            with self.subTest(old=old), tempfile.TemporaryDirectory() as temp:
                bridge, _, artifact, trust, neutral = self.lifecycle_fixture(temp)
                runtime = Path(temp) / 'runtime'
                if old:
                    launcher_path = runtime / 'tools/updater_launcher.py'
                    launcher_path.parent.mkdir(parents=True)
                    launcher_path.write_bytes((ROOT / 'tests/fixtures/updater_pre_closure/updater_launcher.py').read_bytes())
                result = run_isolated(bridge, code, [runtime, artifact, trust], neutral)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_launcher_is_rechecked_under_lock_before_staging(self):
        code = r"""
from deploy.linux import updater_component as component
from server.sli.release_package import PackageError
import os
runtime, artifact, trust = map(Path,sys.argv[2:5])
real = component.check_launcher
checks = []
def checked(path,digest):
    checks.append(path)
    if len(checks) == 2:
        assert (runtime/'state/update.lock').exists()
        path.write_bytes(b'# changed after lock')
    return real(path,digest,owner_uid=os.getuid())
component.check_launcher = checked
manager = component.UpdaterComponent(runtime,trust,source_root=source)
try:
    manager.apply(artifact)
except PackageError as exc:
    assert str(exc) == 'update_launcher_upgrade_required',str(exc)
else:
    raise AssertionError('launcher was not rechecked')
assert len(checks)==2
assert not manager.journal.exists() and not manager.pointer.exists() and not manager.versions.exists()
"""
        with tempfile.TemporaryDirectory() as temp:
            bridge, _, artifact, trust, neutral = self.lifecycle_fixture(temp)
            runtime = Path(temp)/'runtime'
            operator = runtime/'tools/updater_launcher.py'
            operator.parent.mkdir(parents=True)
            operator.write_bytes((ROOT/'deploy/linux/updater_launcher.py').read_bytes())
            result = run_isolated(bridge,code,[runtime,artifact,trust],neutral)
            self.assertEqual(result.returncode,0,result.stderr)

    def test_bridge_to_closure_rollback_interruption_and_damaged_current(self):
        code = r"""
from deploy.linux import updater_component as component
from server.sli.release_package import PackageError, read_json
import os, subprocess, json, importlib.util
runtime, artifact, trust = map(Path, sys.argv[2:5])
mode = sys.argv[5]
real = component.check_launcher
component.check_launcher = lambda p, h: real(p, h, owner_uid=os.getuid())
selftests = []
def selftest(root, version):
    command = sys.argv[6] + '\nfrom deploy.linux.updater_component import selftest; assert selftest(sys.argv[2]) == "selftest_passed"'
    result = subprocess.run([sys.executable, '-I', '-B', '-c', command, str(root), version],
                            cwd=Path.cwd(), text=True, capture_output=True, timeout=20, check=False)
    assert result.returncode == 0, result.stderr
    selftests.append(version)
manager = component.UpdaterComponent(runtime, trust, source_root=source, selftest=selftest)
assert manager.apply(artifact, dry_run=True) == 'verified'
assert not manager.state.exists()
class PowerLoss(BaseException):
    pass
save = manager.save
normal_selftest = selftest
if mode == 'selftest_interrupt':
    def interrupted(*args):
        raise PowerLoss()
    manager.selftest = interrupted
elif mode in {'switch_interrupt', 'switch_fsync'}:
    def interrupted(path, value):
        save(path, value)
        if path == manager.pointer and value.get('previous'):
            if mode == 'switch_fsync':
                raise OSError('synthetic fsync failure after replace')
            raise PowerLoss()
    manager.save = interrupted
elif mode in {'launcher_change', 'pointer_change'}:
    def changed(root, version):
        normal_selftest(root, version)
        if mode == 'launcher_change':
            (runtime / 'tools/updater_launcher.py').write_bytes(b'# changed')
        else:
            value = manager.read_pointer()
            value['previous'] = value['current']
            manager.save(manager.pointer, value)
    manager.selftest = changed
try:
    status = manager.apply(artifact)
except PowerLoss:
    assert mode in {'selftest_interrupt', 'switch_interrupt'}
except PackageError as exc:
    assert str(exc) == {'launcher_change':'update_launcher_upgrade_required',
                        'pointer_change':'update_current_updater_changed',
                        'switch_fsync':'update_updater_activation_failed'}[mode], str(exc)
else:
    assert mode in {'happy', 'damaged', 'rollback_interrupt'} and status == 'committed'
manager.save = save
manager.selftest = normal_selftest
pointer = read_json(manager.pointer.read_bytes())
if mode in {'selftest_interrupt', 'launcher_change', 'pointer_change'}:
    assert pointer['current']['version'] == '1.0.1'
else:
    assert pointer['current']['version'] == '1.1.0'
    assert pointer['previous']['version'] == '1.0.1'
if mode == 'damaged':
    (manager.versions / pointer['current']['directory'] / 'server/sli/plugin_validation.py').write_bytes(b'damaged')
    spec = importlib.util.spec_from_file_location('operator_launcher', runtime / 'tools/updater_launcher.py')
    launcher = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(launcher)
    try:
        launcher.selected_script(runtime)
    except ValueError:
        pass
    else:
        raise AssertionError('damaged current selected')
    assert '1.0.1-' in str(launcher.selected_script(runtime, previous=True))
    selected = launcher.selected_script(runtime, previous=True).parents[2]
    recovery = sys.argv[6] + r'''
from deploy.linux import updater_component as component
import subprocess
def test(root, version):
    code = sys.argv[3] + "\nfrom deploy.linux.updater_component import selftest; assert selftest(sys.argv[2]) == \"selftest_passed\""
    result = subprocess.run([sys.executable, "-I", "-B", "-c", code, str(root), version], cwd=Path.cwd(), capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
manager = component.UpdaterComponent(Path(sys.argv[2]), selftest=test)
assert manager.rollback() == "rolled_back"
assert manager.read_pointer()["current"]["version"] == "1.0.1"
'''
    result = subprocess.run([sys.executable, '-I', '-B', '-c', recovery, str(selected), str(runtime), sys.argv[6]],
                            cwd=Path.cwd(), text=True, capture_output=True, timeout=30, check=False)
    assert result.returncode == 0, result.stderr
if mode == 'rollback_interrupt':
    def interrupted_rollback(path, value):
        save(path, value)
        if path == manager.pointer:
            raise PowerLoss()
    manager.save = interrupted_rollback
    try:
        manager.rollback()
    except PowerLoss:
        pass
    else:
        raise AssertionError('rollback interruption missing')
    manager.save = save
assert manager.rollback() == 'rolled_back'
assert manager.read_pointer()['current']['version'] == '1.0.1'
assert manager.rollback() == 'rolled_back'
if mode not in {'selftest_interrupt', 'launcher_change', 'pointer_change'}:
    assert manager.read_pointer()['previous'] is None  # no multihop rollback
assert not (runtime / 'state/installed.json').exists()
"""
        for mode in ('happy', 'damaged', 'selftest_interrupt', 'switch_interrupt', 'switch_fsync',
                     'launcher_change', 'pointer_change', 'rollback_interrupt'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp:
                bridge, _, artifact, trust, neutral = self.lifecycle_fixture(temp)
                runtime = Path(temp) / 'runtime'
                launcher_path = runtime / 'tools/updater_launcher.py'
                launcher_path.parent.mkdir(parents=True)
                launcher_path.write_bytes((ROOT / 'deploy/linux/updater_launcher.py').read_bytes())
                result = run_isolated(bridge, code, [runtime, artifact, trust, mode, ISOLATED], neutral)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_closure_profile_admission_and_launcher_selection(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            snapshot = root / 'updater/versions' / ('1.1.0-' + 'a' * 64)
            names = materialize(snapshot, '1.1.0')
            key = Ed25519PrivateKey.generate()
            manifest = signed_fixture(snapshot, root / 'n.zip', '1.0.1', '1.1.0', key)
            package.validate_manifest(manifest, package.PackageLimits())
            descriptor = dict(component='updater', version='1.1.0', os='linux', architecture='amd64',
                directory=snapshot.name, files={p: hashlib.sha256((snapshot / p).read_bytes()).hexdigest() for p in names})
            (root / 'state').mkdir()
            (root / 'state/updater.json').write_text(json.dumps(dict(format_version=1, current=descriptor, previous=None)))
            self.assertEqual(launcher.selected_script(root), snapshot / 'deploy/linux/sli_update.py')
            self.assertTrue(launcher.inspect_compatibility(root)['closure_activation_supported'])


if __name__ == '__main__':
    unittest.main()

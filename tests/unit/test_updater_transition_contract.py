"""Read-only candidate transition contracts; no updater CLI or real installation."""
from contextlib import ExitStack
import hashlib
import base64
import zipfile
import importlib.util
from itertools import product
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from deploy.linux import updater_component as component
from deploy.linux import updater_launcher as launcher
from server.sli import release_package as package


@unittest.skipUnless(sys.platform == "linux", "Linux updater contracts")
class TransitionContractTests(unittest.TestCase):
    def test_existing_17_file_snapshot_imports_without_source_fallback(self):
        code = r"""
import importlib.abc, importlib.machinery, sys
from pathlib import Path
root = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(root))
class PackagedOnly(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] not in {'deploy', 'scripts', 'server'}:
            return None
        spec = importlib.machinery.PathFinder.find_spec(fullname, path)
        assert spec is not None, 'missing packaged module: ' + fullname
        locations = [spec.origin] if spec.origin else list(spec.submodule_search_locations)
        assert locations and all(Path(p).resolve().is_relative_to(root) for p in locations), fullname
        return spec
sys.meta_path.insert(0, PackagedOnly())
from deploy.linux import updater_component, sli_update, installation
from scripts.maintenance import release_package
assert len(release_package.UPDATER_FILES) == 17
assert len(release_package.UPDATER_CLOSURE_FILES) == 22
assert release_package.updater_inventory_profile(release_package.UPDATER_FILES) == 'legacy-17'
for name, module in sys.modules.copy().items():
    if name.split('.')[0] in {'deploy', 'scripts', 'server'} and getattr(module, '__file__', None):
        assert Path(module.__file__).resolve().is_relative_to(root), name
"""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'snapshot'
            neutral = Path(temp) / 'neutral'
            neutral.mkdir()
            for name in package.UPDATER_FILES:
                destination = root / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes((ROOT / name).read_bytes())
            result = subprocess.run([sys.executable, '-I', '-B', '-c', code, str(root)],
                                    cwd=neutral, capture_output=True, text=True, timeout=20, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_fixed_profiles_remain_exact(self):
        self.assertTrue(hasattr(package, 'UPDATER_CLOSURE_FILES'), 'closure contract missing')
        self.assertEqual(len(package.UPDATER_FILES), 17)
        self.assertEqual(len(package.UPDATER_CLOSURE_FILES), 22)
        self.assertEqual(package.updater_inventory_profile(package.UPDATER_FILES), 'legacy-17')
        self.assertEqual(package.updater_inventory_profile(package.UPDATER_CLOSURE_FILES), 'closure-22')
        for names in (package.UPDATER_FILES | {'extra.py'}, package.UPDATER_CLOSURE_FILES - {'config/plugin_architecture_v3.json'},
                      [*package.UPDATER_FILES, next(iter(package.UPDATER_FILES))]):
            with self.assertRaisesRegex(package.PackageError, '^update_unsupported_updater_inventory$'):
                package.updater_inventory_profile(names)
        self.assertNotIn('deploy/linux/updater_launcher.py', package.UPDATER_CLOSURE_FILES)

    def manifest(self, source='1.0.1', target='1.1.0', files=None):
        return dict(from_version=source, to_version=target, minimum_updater=1,
                    files=[{'path': p} for p in (package.UPDATER_CLOSURE_FILES if files is None else files)])

    def test_advisory_version_contract_preserves_equality_and_exact_source(self):
        self.assertTrue(hasattr(package, 'updater_transition_diagnostic'), 'transition diagnostic missing')
        self.assertEqual(package.updater_transition_diagnostic(self.manifest(), '1.0.1'), 'update_launcher_check_required')
        self.assertEqual(package.updater_transition_diagnostic(self.manifest(), '1.0.0'), 'update_bridge_required')
        self.assertEqual(package.updater_transition_diagnostic(self.manifest(source='1.0.0'), '1.0.1'), 'update_source_version_mismatch')
        self.assertEqual(package.updater_transition_diagnostic(self.manifest(target='1.2.0'), '1.0.1'), 'update_unsupported_updater_release')
        self.assertEqual(package.updater_transition_diagnostic(self.manifest(files=package.UPDATER_FILES), '1.0.1'), 'update_unsupported_updater_inventory')
        for minimum in (0, 2, True, '1'):
            value = self.manifest()
            value['minimum_updater'] = minimum
            self.assertEqual(package.updater_transition_diagnostic(value, '1.0.1'), 'update_incompatible_updater')
        bridge = self.manifest(source='1.0.0', target='1.0.1', files=package.UPDATER_FILES)
        self.assertEqual(package.updater_transition_diagnostic(bridge, '1.0.0'), 'update_bridge_contract_matches')
        self.assertEqual(package.updater_transition_diagnostic(bridge, '1.0.2'), 'update_source_version_mismatch')

    def snapshot(self, runtime, names, version='1.0.0'):
        name = version + '-' + 'a' * 64
        root = runtime / 'updater/versions' / name
        files = {}
        for relative in names:
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'# synthetic fixture; never executed\n')
            files[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
        descriptor = dict(component='updater', version=version, os='linux', architecture='amd64', directory=name, files=files)
        pointer = runtime / 'state/updater.json'
        pointer.parent.mkdir(parents=True, exist_ok=True)
        pointer.write_text(json.dumps(dict(format_version=1, current=descriptor, previous=descriptor)))
        return root, descriptor

    def test_read_only_inspection_retains_frozen_historical_selection(self):
        self.assertTrue(hasattr(launcher, 'inspect_compatibility'), 'read-only inspection missing')
        frozen = ROOT / 'tests/fixtures/updater_pre_closure/updater_launcher.py'
        self.assertEqual(hashlib.sha256(frozen.read_bytes()).hexdigest(), 'aa0a366c560cf9a5830613a1b6d010bc0f3604a1a3289c326f1912911744effd')
        spec = importlib.util.spec_from_file_location('frozen_old_launcher', frozen)
        old = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(old)
        for names, version in product(launcher.SUPPORTED_INVENTORIES, ('1.0.0','1.0.1','1.1.0')):
            for previous in (False, True):
                with self.subTest(count=len(names), previous=previous), tempfile.TemporaryDirectory() as temp:
                    runtime = Path(temp)
                    root, descriptor = self.snapshot(runtime, names, version=version)
                    before = {str(p.relative_to(runtime)): p.read_bytes() for p in runtime.rglob('*') if p.is_file()}
                    with patch.object(os, 'execv', side_effect=AssertionError('must not execute')):
                        report = launcher.inspect_compatibility(runtime, previous=previous)
                    self.assertEqual(report['version'], descriptor['version'])
                    self.assertEqual(report['files'], sorted(names))
                    self.assertTrue(report['closure_activation_supported'])
                    self.assertEqual(old.selected_script(runtime, previous=previous), root / 'deploy/linux/sli_update.py')
                    self.assertEqual(launcher.selected_script(runtime, previous=previous), root / 'deploy/linux/sli_update.py')
                    self.assertEqual(before, {str(p.relative_to(runtime)): p.read_bytes() for p in runtime.rglob('*') if p.is_file()})

    def test_inspection_refuses_unknown_tampered_and_symlink_snapshots(self):
        spec = importlib.util.spec_from_file_location(
            'frozen_old_launcher', ROOT / 'tests/fixtures/updater_pre_closure/updater_launcher.py')
        old = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(old)
        self.assertTrue(hasattr(launcher, 'inspect_compatibility'), 'read-only inspection missing')
        for kind in ('closure', 'extra', 'tamper', 'symlink'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temp:
                runtime = Path(temp)
                names = package.UPDATER_CLOSURE_FILES if kind == 'closure' else package.UPDATER_FILES
                if kind == 'extra':
                    names = names | {'extra.py'}
                root, _ = self.snapshot(runtime, names)
                target = root / 'deploy/linux/update_checkpoint.py'
                if kind == 'tamper':
                    target.write_bytes(b'tampered')
                if kind == 'symlink':
                    target.unlink()
                    target.symlink_to(root / 'deploy/linux/sli_update.py')
                with self.assertRaises(ValueError):
                    launcher.inspect_compatibility(runtime)
                with self.assertRaises(ValueError):
                    old.selected_script(runtime)

    def test_actual_old_verifier_and_component_accept_bridge_reject_closure(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        fixtures = ROOT / 'tests/fixtures/updater_pre_closure'
        modules = {}
        for name, expected_hash in (
            ('release_package', '5e6c006d9df1e80c382d3e5bff38aa525da4cb625f2e90142968a27aee8ef4ec'),
            ('updater_component', '0e46d20ff763aacc6787d4dadc43792db61aa0c33359d1ddea5ee1fd2c04bb63'),
        ):
            path = fixtures / (name + '.py')
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), expected_hash)
            spec = importlib.util.spec_from_file_location('frozen_' + name, path)
            module = importlib.util.module_from_spec(spec)
            # The old component must bind to the actual frozen old verifier,
            # not new code with patched inventory constants.
            with patch.dict(sys.modules, {'frozen_' + name: module,
                            **({'scripts.maintenance.release_package': modules['release_package']}
                               if name == 'updater_component' else {})}):
                spec.loader.exec_module(module)
            modules[name] = module
        old = modules['release_package']
        key = Ed25519PrivateKey.generate()  # ephemeral synthetic test material only
        with tempfile.TemporaryDirectory() as temp:
            runtime = Path(temp) / 'runtime'
            trust = Path(temp) / 'trust.json'
            trust.write_bytes(package.canonical_json({'schema_version': 1, 'keys': [{
                'key_id': 'synthetic-only', 'public_key': base64.b64encode(
                    key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode(),
                'package_ids': ['sli.updater'], 'revoked': False}]}))
            for names, target in ((package.UPDATER_FILES, '1.0.1'), (package.UPDATER_CLOSURE_FILES, '1.1.0'),
                                  (package.UPDATER_FILES, '1.1.0')):
                root, descriptor = self.snapshot(runtime, names, version=target)
                source = '1.0.0' if target == '1.0.1' else '1.0.1'
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
                raw = package.canonical_json(manifest)
                signature = dict(algorithm='ed25519', key_id='synthetic-only', signature=base64.b64encode(
                    key.sign(package.SIGNING_CONTEXT + raw)).decode())
                contents = {package.MANIFEST_NAME: raw, package.SIGNATURE_NAME: package.canonical_json(signature),
                            **{'payload/' + name: body for name, body in payload.items()}}
                artifact = Path(temp) / (target + '.zip')
                with zipfile.ZipFile(artifact, 'w') as archive:
                    for name, body in contents.items():
                        archive.writestr(name, body)
                installed = dict(component='updater', version=source, os='linux', architecture='amd64')
                for verifier in (old, package):
                    if (len(names) == 17 and verifier is old) or (verifier is package and
                            (target == '1.0.1' or len(names) == 22)):
                        result = verifier.verify_package(artifact, trust, installed=installed,
                                                         free_bytes=1024 * 1024, component='updater')
                        self.assertEqual(result.manifest['to_version'], target)
                    else:
                        with self.assertRaisesRegex(verifier.PackageError, 'update_invalid_updater_payload'):
                            verifier.verify_package(artifact, trust, installed=installed,
                                                    free_bytes=1024 * 1024, component='updater')
                for cls in (modules['updater_component'].UpdaterComponent, component.UpdaterComponent):
                    manager = cls(runtime)
                    if len(names) == 17 or cls is component.UpdaterComponent:
                        self.assertEqual(manager.validate(descriptor), root)
                    else:
                        with self.assertRaisesRegex(ValueError, 'update_updater_files_changed'):
                            manager.validate(descriptor)
                if len(names) == 17:
                    for failure in ('signature', 'payload', 'revoked', 'owner'):
                        changed = dict(contents)
                        policy = package.read_json(trust.read_bytes())
                        if failure == 'signature':
                            changed[package.SIGNATURE_NAME] = package.canonical_json(
                                dict(signature, signature=base64.b64encode(b'x' * 64).decode()))
                        elif failure == 'payload':
                            changed['payload/deploy/linux/sli_update.py'] += b'changed'
                        else:
                            policy['keys'][0].update({'revoked': True} if failure == 'revoked'
                                                     else {'package_ids': ['sli.other']})
                        badtrust = Path(temp) / 'badtrust.json'
                        badtrust.write_bytes(package.canonical_json(policy))
                        bad = Path(temp) / 'bad.zip'
                        with zipfile.ZipFile(bad, 'w') as archive:
                            for name, body in changed.items():
                                archive.writestr(name, body)
                        for verifier in (old, package):
                            with self.subTest(failure=failure), self.assertRaises(verifier.PackageError):
                                verifier.verify_package(bad, badtrust)

    def test_launcher_pin_rejects_replaceable_parent_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp) / 'unsafe'
            parent.mkdir(mode=0o777)
            parent.chmod(0o777)
            path = parent / 'launcher.py'
            path.write_bytes(b'# synthetic')
            path.chmod(0o600)
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            with self.assertRaisesRegex(package.PackageError, '^update_launcher_upgrade_required$'):
                component.check_launcher(path, digest, owner_uid=os.getuid())

    def test_launcher_pin_is_bounded_read_only_and_never_executes(self):
        self.assertTrue(hasattr(component, 'check_launcher'), 'launcher pin check missing')
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'operator-launcher.py'
            body = b'raise AssertionError("unrecognized code must never run")\n'
            path.write_bytes(body)
            path.chmod(0o600)
            digest = hashlib.sha256(body).hexdigest()
            with ExitStack() as stack:
                stack.enter_context(patch('subprocess.run', side_effect=AssertionError('must not execute')))
                stack.enter_context(patch.object(os, 'execv', side_effect=AssertionError('must not execute')))
                self.assertEqual(component.check_launcher(path, digest, owner_uid=os.getuid()), digest)
                for invalid in (None, '', 'f' * 64):
                    with self.assertRaisesRegex(package.PackageError, '^update_launcher_upgrade_required$'):
                        component.check_launcher(path, invalid, owner_uid=os.getuid())
                for kind in ('missing', 'symlink', 'hardlink', 'writable', 'oversize', 'owner'):
                    with self.subTest(kind=kind):
                        candidate = path
                        if kind == 'missing':
                            candidate = Path(temp) / 'missing'
                        elif kind in ('symlink', 'hardlink'):
                            candidate = Path(temp) / kind
                            if kind == 'symlink':
                                candidate.symlink_to(path)
                            else:
                                os.link(path, candidate)
                        elif kind == 'writable':
                            path.chmod(0o666)
                        elif kind == 'oversize':
                            path.write_bytes(b'x' * (1024 * 1024 + 1))
                        owner = os.getuid() + 1 if kind == 'owner' else os.getuid()
                        with self.assertRaisesRegex(package.PackageError, '^update_launcher_upgrade_required$'):
                            component.check_launcher(candidate, digest, owner_uid=owner)
                        if kind in ('symlink', 'hardlink'):
                            candidate.unlink()
                        path.write_bytes(body)
                        path.chmod(0o600)
            self.assertEqual(sorted(p.name for p in Path(temp).iterdir()), ['operator-launcher.py'])
            self.assertEqual(path.read_bytes(), body)


if __name__ == '__main__':
    unittest.main()

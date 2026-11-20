"""Authenticated 22-file lazy paths with fake host, real validators and synthetic images."""
import base64
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
# Test utilities are used only in the parent, never imported by the isolated child.
sys.path.insert(0, str(Path(__file__).parent))
from test_updater_transition import materialize, signed_fixture, run_isolated
from server.sli import release_package as package
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

LAZY_PATHS = r'''
import base64, hashlib, io, json, tarfile, zipfile, copy
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from server.sli import release_package as package
from deploy.linux import sli_update as update, installed_state, plugin_update, backup_activity
runtime = Path(sys.argv[2])
update.require_snapshot_imports(source)
foreign = runtime.parent / 'foreign-site-packages'
(foreign/'server').mkdir(parents=True)
(foreign/'server/__init__.py').write_text('raise AssertionError("must never execute foreign SLI")')
sys.path.insert(0,str(foreign))
try:
    update.require_snapshot_imports(source)
except RuntimeError as exc:
    assert str(exc) == 'update_updater_import_mismatch'
else:
    raise AssertionError('foreign regular package admitted over snapshot namespace')
finally:
    sys.path.remove(str(foreign))
jobs = json.loads(Path(sys.argv[3]).read_bytes())
key = Ed25519PrivateKey.generate()
trust = runtime.parent / 'synthetic-trust.json'
trust.write_bytes(package.canonical_json(dict(schema_version=1, keys=[dict(key_id='test-only',
    public_key=base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode(),
    package_ids=['sli.remote-access', 'sli.core'], revoked=False)])))
def sign(name, manifest, payload):
    manifest['files'] = [dict(path=p, size=len(body), sha256=hashlib.sha256(body).hexdigest())
                         for p, body in sorted(payload.items())]
    raw = package.canonical_json(manifest)
    signature = dict(algorithm='ed25519', key_id='test-only',
                     signature=base64.b64encode(key.sign(package.SIGNING_CONTEXT + raw)).decode())
    path = runtime.parent / name
    with zipfile.ZipFile(path, 'w') as archive:
        archive.writestr(package.MANIFEST_NAME, raw)
        archive.writestr(package.SIGNATURE_NAME, package.canonical_json(signature))
        for p, body in payload.items():
            archive.writestr('payload/' + p, body)
    return path

def metadata(component, package_id, restart):
    return dict(schema_version=2, package_type='plugin-update' if component=='plugin' else 'core-update',
        package_id=package_id, component=component, version='1.1.0', from_version='1.0.0', to_version='1.1.0',
        platform='linux-amd64', source_commit='a'*40, build_id='synthetic-only', minimum_updater=1,
        compatibility=dict(core_api=1, ui_api=1, from_version='1.0.0', min_version='1.0.0', max_version='1.0.0',
                           os='linux', architecture='amd64'), required_free_disk=1024, migrations={}, deletions=[],
        restart_profile=restart, image=None, compose_delta=None, config_delta=None)

jobs['plugin_version'] = '1.1.0'
asset = b'export const synthetic = true;'
descriptor = dict(plugin_id='sli.remote-access', version='1.1.0', ui_api='sli.plugin-ui.v1',
    routes=['/extensions/sli.remote-access/accounts'], required_capabilities=[],
    entry=dict(path='entry.js', sha256=hashlib.sha256(asset).hexdigest()))
plugin_manifest = metadata('plugin', 'sli.remote-access', 'plugin-only')
plugin_manifest.update(plugin_id='sli.remote-access', plugin_version='1.1.0',
    core_api=jobs['core_api'], ui_api=dict(minimum='1.0.0', maximum_exclusive='2.0.0'),
    handlers=[h['handler_id'] for h in jobs['handlers']])
plugin_archive = sign('plugin.zip', plugin_manifest, {
    'backend/jobs-v3.json': package.canonical_json(jobs), 'backend/registration.py': b'# never executed',
    'ui/descriptor.json': package.canonical_json(descriptor), 'ui/entry.js': asset})
sql1 = b"insert into schema_migrations(version,name) values(1,'example');\n"
sql2 = b"insert into schema_migrations(version,name) values(2,'later');\n"
h1, h2 = (hashlib.sha256(b).hexdigest() for b in (sql1,sql2))
ledger1 = [dict(version=1, name='example', sha256=h1)]
ledger2 = [*ledger1, dict(version=2, name='later', sha256=h2)]
core = dict(component='server', version='1.0.0', os='linux', architecture='amd64',
    image_tag='synthetic:previous', image_digest='sha256:'+'a'*64, compose_project='sli', volumes={},
    migrations={'config/postgres_migrations/001_example.sql':h1}, migration_ledger=ledger1,
    plugins={'sli.remote-access':dict(version='1.0.0', migrations={})})
(runtime / 'state').mkdir(parents=True)
class Host:
    def __init__(self):
        self.ledger = ledger1
        self.calls = []
    def preflight(self, installed, manifest):
        self.calls.append('preflight')
        return dict(migration_ledger=self.ledger, migration_ledger_max=max(r['version'] for r in self.ledger),
            installed_release_available=True, installed_release=dict(installation_key=installed_state.installation_key(core),
                inventory=installed_state.inventory(core)),
            services={'api':{k:core[k] for k in ('version','image_tag','image_digest')}},
            plugins=[dict(plugin_id='sli.remote-access', version='1.1.0', installed=True, enabled=True)])
host = Host()
updater = update.Updater(runtime, trust, host)
verified = updater.verified(plugin_archive, core)  # actual lazy plugin verifier and external key scope
assert verified.manifest['component'] == 'plugin'
generation = verified.archive_sha256
release = runtime / 'plugins/sli.remote-access/versions' / generation
package.extract_payload(verified, release)
plugin_update.validate_payload(release, verified.manifest)  # valid schema/handlers/UI, no early rejection
(release / 'release.json').write_bytes(package.canonical_json(verified.manifest))
(release.parents[1] / 'active.json').write_bytes(package.canonical_json(dict(generation=generation)))
core['plugins']['sli.remote-access'].update(version='1.1.0', generation=generation)
installed_state.pointers_match(runtime, core)  # reaches valid payload again

def tar_bytes(files):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w') as archive:
        for path, body in files.items():
            entry = tarfile.TarInfo(path)
            entry.size = len(body)
            archive.addfile(entry, io.BytesIO(body))
    return output.getvalue()
layer = tar_bytes({'opt/sli/config/postgres_migrations/001_example.sql':sql1,
                   'opt/sli/config/postgres_migrations/002_later.sql':sql2})
config = package.canonical_json(dict(os='linux', architecture='amd64',
    config=dict(Labels={'org.opencontainers.image.version':'1.1.0'}),
    rootfs=dict(diff_ids=['sha256:'+hashlib.sha256(layer).hexdigest()])))
config_name = hashlib.sha256(config).hexdigest()+'.json'
image = tar_bytes({config_name:config, 'layer.tar':layer, 'manifest.json':package.canonical_json([
    dict(Config=config_name, Layers=['layer.tar'], RepoTags=['synthetic:unused'])])})
manifest = metadata('server', 'sli.core', 'docker-compose')
manifest.update(image=dict(path='image.tar', digest='sha256:'+hashlib.sha256(config).hexdigest()),
    migrations={'config/postgres_migrations/001_example.sql':h1,'config/postgres_migrations/002_later.sql':h2})
manifest['compatibility'].update(migration_ledger_max=1, plugins={
    'sli.remote-access':dict(min_version='1.1.0', max_version='1.1.0', enabled=True)})
archive = sign('core.zip', manifest, {'image.tar':image})
verified_core = updater.verified(archive, core)
updater.preflight(core, verified_core.manifest)  # actual installed_state.validate and plugin generation
updater.installed_path.write_bytes(package.canonical_json(core))
before = updater.installed_path.read_bytes()
manifest['compatibility']['migration_ledger_max'] = 2
archive = sign('reconcile.zip', manifest, {'image.tar':image})
host.ledger = ledger2
assert updater.reconcile(archive, dry_run=True) == 'verified'  # real signed image parser, no SQL execution
assert updater.installed_path.read_bytes() == before
assert not updater.reconciliation_path.exists()
assert host.calls == ['preflight','preflight']
assert not (source / 'config/postgres_migrations').exists()
assert not installed_state.migration_checksums_match('config/postgres_migrations/001_example.sql',h1,'b'*64)
# The real DockerHost method only reads the packaged probe; the compose boundary is fake.
probe = object.__new__(update.DockerHost)
seen = []
def compose(args, **kwargs):
    assert args[:5] == ['exec','-T','backup','python','-c'] and kwargs == {'timeout':10}
    assert args[-1] == (source/'deploy/linux/backup_activity.py').read_text()
    seen.append(args[-1])
    return '{"busy":false,"next_backup_at_utc":null}'
probe.compose = compose
assert probe.backup_activity() == dict(busy=False,next_backup_at_utc=None) and len(seen)==1
backup = runtime / 'synthetic-backup'
backup.mkdir()
(backup/'heartbeat.json').write_text('{"status":"waiting","next_backup_at_utc":null}')
assert backup_activity.activity(backup)['busy'] is False
# Confirm the child never imported app scheduling/discovery or an external SLI checkout.
for name, module in sys.modules.copy().items():
    if name.split('.')[0] in {'deploy','scripts','server'} and getattr(module,'__file__',None):
        assert Path(module.__file__).resolve().is_relative_to(source), name
assert 'scripts.maintenance.existing_postgres_bootstrap' not in sys.modules
assert 'server.sli.core.job_registry' not in sys.modules
'''


@unittest.skipUnless(sys.platform == "linux", "Linux updater contracts")
class IsolatedClosureTests(unittest.TestCase):
    def run_snapshot(self, *, missing_marker=False):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            payload = root / 'payload'
            materialize(payload, '1.1.0')
            if missing_marker:
                # Restore the actual old lazy edge as a negative control. This
                # signed synthetic snapshot must fail only once SQL is parsed.
                target = payload / 'deploy/linux/sli_update.py'
                body = target.read_text()
                old = '                        markers = MIGRATION_MARKER.findall(body.decode("utf-8"))'
                replacement = ('                        from scripts.maintenance.existing_postgres_bootstrap import _MARKER\n'
                               '                        markers = _MARKER.findall(body.decode("utf-8"))')
                assert old in body
                target.write_text(body.replace(old, replacement))
            key = Ed25519PrivateKey.generate()
            trust = root / 'trust.json'
            trust.write_bytes(package.canonical_json(dict(schema_version=1, keys=[dict(key_id='synthetic-only',
                public_key=base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode(),
                package_ids=['sli.updater'], revoked=False)])))
            archive = root / 'closure.zip'
            signed_fixture(payload, archive, '1.0.1', '1.1.0', key)
            verified = package.verify_package(archive, trust)
            snapshot = root / 'authenticated'
            package.extract_payload(verified, snapshot)
            self.assertEqual({p.relative_to(snapshot).as_posix() for p in snapshot.rglob('*') if p.is_file()},
                             set(package.UPDATER_CLOSURE_FILES))
            jobs = root / 'synthetic-jobs.json'
            jobs.write_bytes((ROOT / 'config/plugin_packages/sli.remote-access.jobs-v3.json').read_bytes())
            neutral = root / 'neutral'
            neutral.mkdir()
            result = run_isolated(snapshot, LAZY_PATHS, [root / 'runtime', jobs], neutral)
            return result

    def test_authenticated_snapshot_executes_valid_lazy_paths_without_source_fallback(self):
        result = self.run_snapshot()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_negative_control_old_lazy_marker_edge_fails_on_real_sql(self):
        result = self.run_snapshot(missing_marker=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('missing packaged module: scripts.maintenance.existing_postgres_bootstrap', result.stderr)

    def test_migration_marker_exact_pattern_flags_and_compatibility(self):
        import re
        from scripts.maintenance.existing_postgres_bootstrap import _MARKER
        original = re.compile(
            r"insert\s+into\s+(?:public\.)?schema_migrations\s*"
            r"\(\s*version\s*,\s*name\s*\)\s*values\s*"
            r"\(\s*(\d+)\s*,\s*'([^']+)'",
            re.IGNORECASE | re.DOTALL,
        )
        self.assertIs(_MARKER, package.MIGRATION_MARKER)
        self.assertEqual((_MARKER.pattern, _MARKER.flags), (original.pattern, original.flags))
        for text, matches in [
            ("insert into schema_migrations(version,name) values(1,'example');", [('1','example')]),
            ("INSERT INTO public.schema_migrations\n(version, name) VALUES (22, 'unicode-имя');", [('22','unicode-имя')]),
            ("insert into other(version,name) values(1,'wrong');", []),
            ("insert into schema_migrations(name,version) values('wrong',1);", []),
        ]:
            self.assertEqual(_MARKER.findall(text), matches)
            self.assertEqual(_MARKER.findall(text), original.findall(text))


if __name__ == '__main__':
    unittest.main()

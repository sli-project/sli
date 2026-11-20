"""Read-only validation contracts; runnable with unittest without runtime services."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))


def manifest():
    return json.loads((ROOT / 'config/plugin_packages/sli.remote-access.jobs-v3.json').read_text('utf-8'))


def descriptor():
    return {
        'plugin_id': 'sli.remote-access', 'ui_api': 'sli.plugin-ui.v1',
        'version': '1.0.0', 'routes': ['/extensions/sli.remote-access/accounts'],
        'entry': {'path': 'assets/entry.js', 'sha256': 'a' * 64},
        'required_capabilities': ['reports.catalog'],
    }


class ValidationTests(unittest.TestCase):
    def setUp(self):
        from server.sli import plugin_validation
        self.validation = plugin_validation

    def test_pure_import_and_schema_resolution_from_neutral_cwd(self):
        code = '''
import importlib.abc, sys, json
sys.path.insert(0, sys.argv[1])
class BlockRuntime(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.startswith('server.') and fullname not in {'server.sli', 'server.sli.plugin_validation'}:
            raise AssertionError('runtime import: ' + fullname)
sys.meta_path.insert(0, BlockRuntime())
from server.sli.plugin_validation import HandlerRegistry, ROOT
assert str(ROOT) == sys.argv[1]
registry = HandlerRegistry()
registry.register(json.loads(sys.argv[2]))
assert len(registry.handlers) == 2
'''
        with tempfile.TemporaryDirectory() as cwd:
            result = subprocess.run([sys.executable, '-I', '-B', '-c', code, str(ROOT),
                                     json.dumps(manifest())], cwd=cwd, capture_output=True,
                                    text=True, timeout=20, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_canonical_digest_encoding(self):
        value = {'z': [True, None, 1.25], 'a': '\u00e9'}
        expected = r'{"a":"\u00e9","z":[true,null,1.25]}'
        self.assertEqual(self.validation.canonical(value), expected)
        self.assertEqual(self.validation.digest(value), hashlib.sha256(expected.encode('utf-8')).hexdigest())

    def test_valid_descriptor_preserves_identity(self):
        value = descriptor()
        self.assertIs(self.validation.validate_descriptor(value, value['plugin_id']), value)

    def test_invalid_descriptors(self):
        changes = [
            {'ui_api': 'unsupported'}, {'version': 'future'}, {'extra': True},
            {'routes': []}, {'routes': ['/settings']},
            {'routes': ['/extensions/sli.remote-access/accounts'] * 2},
            {'required_capabilities': ['reports.catalog'] * 2},
            {'required_capabilities': [42]}, {'entry': {'path': '../entry.js', 'sha256': 'a'*64}},
            {'entry': {'path': 'entry.js', 'sha256': 'A'*64}},
        ]
        for change in changes:
            with self.subTest(change=change):
                value = {**descriptor(), **change}
                code = ('plugin_ui_unsupported_api' if 'ui_api' in change
                        else 'plugin_ui_invalid_descriptor')
                with self.assertRaisesRegex(self.validation.PluginUiError, '^' + code + '$'):
                    self.validation.validate_descriptor(value, 'sli.remote-access')

    def test_all_allowlisted_profiles_and_budget_caps(self):
        for (plugin_id, handler_id, version), (profile, rights) in self.validation.ALLOWLIST.items():
            with self.subTest(handler=handler_id):
                value = manifest()
                value['plugin_id'] = plugin_id
                handler = value['handlers'][0]
                handler.update(handler_id=handler_id, handler_version=version,
                               resource_profile=profile, rights_profile=rights)
                handler['budget'] = {key: 10**12 for key in handler['budget']}
                value['handlers'] = [handler]
                value['schedules'] = []
                registry = self.validation.HandlerRegistry()
                registry.register(value)
                actual = next(iter(registry.handlers.values()))['budget']
                wall, memory, records = self.validation.PROFILES[profile]
                self.assertEqual(actual, dict(wall_seconds=wall, cpu_seconds=wall,
                    memory_bytes=memory, max_records=records, max_result_bytes=65536,
                    max_db_connections=1, statement_timeout_ms=10000, lock_timeout_ms=1000))
                self.assertEqual(len(registry.identities(profile)), 1)

    def test_lower_budgets_and_optional_dependencies_are_preserved(self):
        value = manifest()
        value['dependencies'] = [{
            'contract_id': 'synthetic.contract', 'versions': value['core_api'],
            'required': False, 'exchange': 'immutable_typed_result',
        }]
        for handler in value['handlers']:
            handler['budget'] = {name: 1 for name in handler['budget']}
        before = deepcopy(value)
        registry = self.validation.HandlerRegistry()
        registry.register(value)
        self.assertEqual(value, before)
        self.assertTrue(all(all(limit == 1 for limit in h['budget'].values())
                            for h in registry.handlers.values()))

    def test_schema_vocabulary_rejects_invalid_shapes(self):
        schema = {'$defs': {'integer': {'type': 'integer'}}}
        invalid = [
            (True, {'$ref': '#/$defs/integer'}),
            (0, {'const': False}), ('x', {'enum': ['y']}),
            ([], {'type': 'array', 'minItems': 1, 'items': {}}),
            ([1, 1], {'type': 'array', 'uniqueItems': True, 'items': {'type': 'integer'}}),
            ('x', {'type': 'string', 'minLength': 2}),
            ('abc', {'type': 'string', 'maxLength': 2}),
            ('x', {'type': 'string', 'pattern': '^y$'}),
            (2, {'type': 'integer', 'maximum': 1}),
            ({'x': 1}, {'type': 'object', 'required': ['y']}),
            ({'x': 1}, {'type': 'object', 'additionalProperties': False}),
            (None, {'oneOf': [{'type': 'null'}, {'type': 'null'}]}),
        ]
        for value, node in invalid:
            with self.subTest(value=value, node=node):
                with self.assertRaisesRegex(ValueError, '^manifest_shape_invalid$'):
                    self.validation.validate_shape(value, node, schema)
        self.validation.validate_shape(None, {'oneOf': [{'type': 'null'}, {'type': 'integer'}]}, schema)
        self.validation.validate_shape(1, {'$ref': '#/$defs/integer'}, schema)

    def test_registration_failures_are_atomic(self):
        cases = []
        def case(code, edit):
            value = manifest()
            edit(value)
            cases.append((code, value))
        case('manifest_shape_invalid', lambda m: m.update(extra=True))
        case('manifest_shape_invalid', lambda m: m.update(own_permanent_workers=0))
        case('manifest_shape_invalid', lambda m: m.update(capabilities=['same', 'same']))
        case('handler_core_api_incompatible', lambda m: m['core_api'].update(minimum='2.0.0'))
        case('handler_dependency_unavailable', lambda m: m.update(dependencies=[{
            'contract_id': 'synthetic.contract', 'versions': m['core_api'],
            'required': True, 'exchange': 'immutable_typed_result'}]))
        case('handler_not_allowlisted', lambda m: m['handlers'][0].update(handler_version='9.0.0'))
        case('handler_not_allowlisted', lambda m: m['handlers'][0].update(rights_profile='ad-read'))
        case('handler_not_allowlisted', lambda m: m['handlers'].append(deepcopy(m['handlers'][0])))
        case('schedule_reference_invalid', lambda m: m['schedules'][0].update(handler_id='missing'))
        case('schedule_reference_invalid', lambda m: m['schedules'].append(deepcopy(m['schedules'][0])))
        case('schedule_trigger_invalid', lambda m: m['schedules'][0].update(interval_seconds=None))
        case('schedule_trigger_invalid', lambda m: m['schedules'][0].update(trigger='calendar'))
        case('schedule_trigger_invalid', lambda m: m['schedules'][0].update(trigger='input_available'))
        for code, value in cases:
            with self.subTest(code=code, value=value):
                registry = self.validation.HandlerRegistry()
                with self.assertRaisesRegex(ValueError, '^' + code + '$'):
                    registry.register(value)
                self.assertEqual(registry.handlers, {})
                self.assertEqual(registry.manifests, [])

    def test_schedules_timezone_and_duplicate_registration(self):
        for trigger, interval, calendar in [('interval', 30, None),
                ('calendar', None, {'local_times': ['01:30']}), ('input_available', None, None)]:
            value = manifest()
            value['schedules'][0].update(trigger=trigger, interval_seconds=interval, calendar=calendar)
            registry = self.validation.HandlerRegistry()
            registry.register(value)
            before = deepcopy(registry.handlers)
            with self.assertRaisesRegex(ValueError, '^handler_registration_duplicate$'):
                registry.register(value)
            self.assertEqual(registry.handlers, before)
            self.assertEqual(len(registry.manifests), 1)
        value = manifest()
        value['schedules'][0]['timezone'] = 'Synthetic/Unavailable_Zone'
        registry = self.validation.HandlerRegistry()
        from zoneinfo import ZoneInfoNotFoundError
        with self.assertRaises(ZoneInfoNotFoundError):
            registry.register(value)
        self.assertEqual(registry.handlers, {})

    def test_resolve_pins_contract_and_input(self):
        registry = self.validation.HandlerRegistry()
        registry.register(manifest())
        handler = next(iter(registry.handlers.values()))
        value = dict(handler, plugin_id='sli.remote-access', job_type=handler['kind'],
                     pinned_input={'synthetic': 1})
        value['input_sha256'] = self.validation.digest(value['pinned_input'])
        self.assertIs(registry.resolve(value), handler)
        for change in [{'handler_version': '9.0.0'}, {'rights_profile': 'other'},
                       {'job_type': 'other'}, {'budget': {}}, {'input_sha256': 'b'*64}]:
            with self.subTest(change=change):
                code = 'job_input_hash_conflict' if 'input_sha256' in change else 'handler_version_unavailable'
                with self.assertRaisesRegex(ValueError, '^' + code + '$'):
                    registry.resolve({**value, **change})

    def test_legacy_imports_reexport_same_objects(self):
        # Only runtime collaborators are synthetic: import real compatibility modules.
        code = '''
import sys, types
sys.path.insert(0, sys.argv[1])
from pathlib import Path
for name, attributes in {
    'server.sli.core.paths': {'WEB_DIR': Path('/synthetic-web')},
    'server.sli.plugins.update_runtime': dict(generation=None, fenced=None, job_manifests=None),
    'server.sli.plugins.registry': dict(plugin_hook=None, plugin_installed=None),
}.items():
    module = types.ModuleType(name)
    module.__dict__.update(attributes)
    sys.modules[name] = module
from server.sli import plugin_validation as pure
from server.sli.core import job_registry, job_queue
from server.sli.plugins import ui_assets
for module, names in [(job_registry, ['HandlerRegistry', 'validate_shape', 'PROFILES', 'ALLOWLIST']),
                      (job_queue, ['canonical', 'digest']),
                      (ui_assets, ['validate_descriptor', 'PluginUiError', 'UI_API', 'PLUGIN_ID',
                                   'ASSET_PATH', 'SHA256', 'MAX_ASSET_BYTES'])]:
    for name in names:
        assert getattr(module, name) is getattr(pure, name), name
assert job_registry.ROOT == pure.ROOT
'''
        result = subprocess.run([sys.executable, '-I', '-B', '-c', code, str(ROOT)],
                                capture_output=True, text=True, timeout=20, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()

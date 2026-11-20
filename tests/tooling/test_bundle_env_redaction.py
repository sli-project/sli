"""Synthetic-only regression tests; no runtime probes or operator configuration."""
import importlib.util
import sys
import tempfile
import types
import unittest
import zipfile
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from scripts.maintenance import bundle_common as common
from scripts.maintenance import export_dev_handoff as handoff


CASES = (
    ('ADLOG_PG_DSN', 'postgresql://example_operator:synth-uri-password@db.invalid/app', 'synth-uri-password'),
    ('DATABASE_URL', 'postgres://example_operator:synth%40encoded@db.invalid/app', 'synth@encoded'),
    ('CUSTOM_CONNECTION', "host=db.invalid user=operator password='synth quoted pass' dbname=app", 'synth quoted pass'),
    ('REPORT_ENDPOINT', 'https://db.invalid/?password=synth-query-pass', 'synth-query-pass'),
    ('OTHER', 'postgresql://db.invalid/app?sslpassword=synth-ssl-pass', 'synth-ssl-pass'),
    ('OTHER', r"host=db.invalid password='synth\'escaped'", "synth'escaped"),
    ('DATABASE_URL', 'postgresql://example_operator:abc@db.invalid/app', 'abc'),
    ('OTHER', 'postgresql://example_operator:synth-long-pass@db.invalid/' + 'x' * 200, 'synth-long-pass'),
    ('OTHER', 'https://db.invalid/?%70assword=synth%2Bquery', 'synth+query'),
    ('OTHER', "'host=db.invalid password=synthetic\\ escaped'", 'synthetic escaped'),
    ('ADLOG_PG_DSN', '\"host=db.invalid password=\\\"synth double quoted\\\"\"', 'synth double quoted'),
    ('CUSTOM_CONNECTION', 'Server=db.invalid;PWD=synth-odbc-pass;Database=app', 'synth-odbc-pass'),
    ('DATABASE_URL', '\"postgresql://example_user:synth-quoted-uri@db.invalid/app\"', 'synth-quoted-uri'),
    ('REPORT_ENDPOINT', '\"https://example_operator:synth\'apostrophe@db.invalid/app\"', "synth'apostrophe"),

)


class BundleEnvRedactionTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.stack.enter_context(patch.object(handoff, 'PROJECT_ROOT', self.root))
        self.stack.enter_context(patch.object(handoff, 'audit_action'))
        self.stack.enter_context(patch.object(handoff, 'basic_project_snapshot', return_value={'generated_at_utc': 'synthetic'}))

    def write_env(self, key, value):
        (self.root / '.env').write_text(f'{key}={value}\nADLOG_SERVER_PORT=8080\n', encoding='utf-8')

    def test_sensitive_values(self):
        for key, value, _ in CASES:
            with self.subTest(key=key):
                self.assertEqual(common.redact_env_value(key, value), '<REDACTED>')
        self.assertEqual(common.redact_env_value('ADLOG_SERVER_PORT', '8080'), '8080')
        self.assertEqual(common.redact_env_value('PUBLIC_URL', 'https://example.invalid/status'), 'https://example.invalid/status')

    def test_scanner_detects_password_only_and_encoded_forms(self):
        staging = self.root / 'staging'
        staging.mkdir()
        for key, value, secret in CASES:
            self.write_env(key, value)
            for representation in (secret, value):
                with self.subTest(key=key, representation='synthetic'):
                    (staging / 'evidence.txt').write_text(representation, encoding='utf-8')
                    self.assertEqual(handoff._find_configured_secret_matches(staging), ['evidence.txt'])

    def test_scanner_preserves_raw_query_values_with_encoded_keys(self):
        self.write_env('REPORT_ENDPOINT', 'https://db.invalid/?%70assword=synth%2Bquery')
        staging = self.root / 'staging'
        staging.mkdir()
        for representation in ('synth%2Bquery', 'synth+query'):
            with self.subTest(representation=representation):
                (staging / 'evidence.txt').write_text(representation, encoding='utf-8')
                self.assertEqual(handoff._find_configured_secret_matches(staging), ['evidence.txt'])

    def test_short_password_scan_uses_token_boundaries(self):
        staging = self.root / 'staging'
        staging.mkdir()
        evidence = staging / 'evidence.txt'
        for secret in ('a', 'ab', 'abc'):
            with self.subTest(length=len(secret)):
                self.write_env('DATABASE_URL', f'postgresql://example_user:{secret}@db.invalid/db')
                evidence.write_text('database alphabet abcdef', encoding='utf-8')
                self.assertEqual(handoff._find_configured_secret_matches(staging), [])
                evidence.write_text(f'password={secret}', encoding='utf-8')
                self.assertEqual(handoff._find_configured_secret_matches(staging), ['evidence.txt'])

    def test_handoff_zip_redacts_env(self):
        self.stack.enter_context(patch.object(handoff, 'REQUIRED_ANALYST_PATHS', ()))
        self.stack.enter_context(patch.object(handoff, 'CURRENT_EVIDENCE_FILES', ()))
        self.stack.enter_context(patch.object(handoff, 'INCLUDE_ROOTS', ()))
        for key, value, secret in CASES:
            with self.subTest(key=key):
                self.write_env(key, value)
                result = handoff.build_dev_handoff(out_dir=self.root / 'out', evidence_root=self.root)
                with zipfile.ZipFile(result['zip_path']) as archive:
                    content = archive.read('_handoff_meta/ENV_REDACTED.txt').decode()
                    self.assertNotIn(secret, content)
                    self.assertIn(f'{key}=<REDACTED>', content)
                    self.assertIn('ADLOG_SERVER_PORT=8080', content)

    def test_handoff_rejects_secret_in_final_generated_manifest(self):
        self.write_env('ADLOG_PG_DSN', 'postgresql://example_user:synth-final-secret@db.invalid/db')
        self.stack.enter_context(patch.object(handoff, 'REQUIRED_ANALYST_PATHS', ()))
        self.stack.enter_context(patch.object(handoff, 'CURRENT_EVIDENCE_FILES', ()))
        self.stack.enter_context(patch.object(handoff, 'INCLUDE_ROOTS', ()))
        self.stack.enter_context(patch.object(handoff, 'basic_project_snapshot', return_value={
            'generated_at_utc': 'synthetic', 'synthetic_leak': 'synth-final-secret',
        }))
        with self.assertRaises(RuntimeError) as raised:
            handoff.build_dev_handoff(out_dir=self.root / 'out', evidence_root=self.root)
        self.assertNotIn('synth-final-secret', str(raised.exception))
        self.assertEqual(list((self.root / 'out').glob('*.zip')), [])

    def test_multiline_quoted_escaped_and_malformed_env(self):
        (self.root / '.env').write_text(
            'export DATABASE_URL="postgresql://example_user:synth-multi\nline@db.invalid/db"\n'
            'ADLOG_SERVER_PORT=8080\n'
            'ADLOG_PG_DSN=host=db.invalid password=synth-continued\\\n'
            'tail\n'
            '# password=synth-comment\n'
            'not-an-assignment synth-invalid\n', encoding='utf-8')
        content = common.redact_env_file(self.root / '.env')
        for secret in ('synth-multi', 'line@db', 'synth-continued', 'tail', 'synth-comment', 'synth-invalid'):
            self.assertNotIn(secret, content)
        self.assertIn('ADLOG_SERVER_PORT=8080', content)

    def test_diagnostics_zip_redacts_env(self):
        # Isolate database import before loading the real packaging caller. No
        # database/config module is imported and no runtime probe can execute.
        database = types.ModuleType('server.sli.core.database')
        database.active_backend = lambda: 'postgres'
        database.is_postgres_runtime_db = lambda: True
        version = types.ModuleType('server.sli.ops.version')
        version.get_release_metadata = lambda root: {}
        with patch.dict(sys.modules, {'server.sli.core.database': database, 'server.sli.ops.version': version}):
            spec = importlib.util.spec_from_file_location('synthetic_diagnostics', Path(common.__file__).with_name('collect_diagnostics.py'))
            diagnostics = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(diagnostics)
        with ExitStack() as stack:
            stack.enter_context(patch.object(diagnostics, 'PROJECT_ROOT', self.root))
            stack.enter_context(patch.object(diagnostics, 'LOG_DIR', self.root / 'logs'))
            for name in ('_health_snapshots', '_db_snapshot', '_storage_snapshot', 'run_command'):
                stack.enter_context(patch.object(diagnostics, name, return_value={}))
            stack.enter_context(patch.object(diagnostics, 'basic_project_snapshot', return_value={'generated_at_utc': 'synthetic'}))
            stack.enter_context(patch.object(diagnostics, 'audit_action'))
            stack.enter_context(patch.object(diagnostics, '_diag_progress'))
            for key, value, secret in CASES:
                with self.subTest(key=key):
                    self.write_env(key, value)
                    result = diagnostics.build_diagnostics(out_dir=self.root / 'out', include_release_check=False)
                    with zipfile.ZipFile(result['zip_path']) as archive:
                        content = archive.read('snapshots/ENV_REDACTED.txt').decode()
                        self.assertNotIn(secret, content)
                        self.assertIn(f'{key}=<REDACTED>', content)
                        self.assertIn('ADLOG_SERVER_PORT=8080', content)


if __name__ == '__main__':
    unittest.main()

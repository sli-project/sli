"""Inactive Compose declaration and synthetic password-file contracts.

No Compose/Docker/service/network action, credential provisioning or DB call.
The Compose overlay uses JSON, which is valid Compose/YAML and permits strict
stdlib parsing without installing a YAML dependency for these source checks.
"""
import json
from contextlib import nullcontext
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import pytest

from deploy.linux import native_runtime
from server.sli.core import report_schedule_producer as producer

ROOT = Path(__file__).resolve().parents[2]
OVERLAY = ROOT / 'deploy/linux/docker-compose.report-producer.json'


class DeploymentTests(unittest.TestCase):
    def configuration(self):
        self.assertTrue(OVERLAY.exists(), 'optional isolated producer service declaration is missing')
        return json.loads(OVERLAY.read_text('utf-8'))

    @pytest.mark.legacy
    def test_service_invokes_producer_with_only_its_own_secret_and_environment(self):
        config = self.configuration()
        self.assertEqual(set(config['services']), {'postgres', 'report-producer'})
        service = config['services']['report-producer']
        self.assertEqual(service['entrypoint'], ['python', '-m', 'server.sli.core.report_schedule_producer'])
        self.assertEqual(service['command'], [])
        self.assertEqual(service['profiles'], ['report-producer'])
        self.assertEqual(service['environment'], {
            'SLI_REPORT_PRODUCER_PG_DSN': 'host=postgres port=5432 dbname=sli user=sli_report_producer_login',
            'SLI_REPORT_PRODUCER_PG_PASSWORD_FILE': '/run/secrets/report_producer_password'})
        self.assertEqual(service['secrets'], ['report_producer_password'])
        self.assertNotIn('volumes', service)
        self.assertNotIn('ports', service)
        self.assertNotIn('env_file', service)
        self.assertNotIn('<<', service)
        self.assertEqual(set(config['secrets']), {'report_producer_password'})
        self.assertIn('SLI_REPORT_PRODUCER_PASSWORD_SOURCE', config['secrets']['report_producer_password']['file'])

    @pytest.mark.legacy
    def test_private_network_keeps_postgres_on_existing_default_network(self):
        config = self.configuration()
        self.assertEqual(config['networks'], {'default': {}, 'report-db': {'internal': True}})
        self.assertEqual(config['services']['postgres'], {'networks': ['default', 'report-db']})
        service = config['services']['report-producer']
        self.assertEqual(service['networks'], ['report-db'])
        self.assertEqual(service['user'], '10001:10001')
        self.assertIs(service['read_only'], True)
        self.assertEqual(service['cap_drop'], ['ALL'])
        self.assertEqual(service['security_opt'], ['no-new-privileges:true'])
        self.assertNotIn('network_mode', service)
        self.assertNotIn('cap_add', service)
        self.assertNotIn('privileged', service)
        self.assertEqual(service['tmpfs'], ['/tmp:mode=1777'])
        self.assertEqual(service['healthcheck']['test'],
            ['CMD', 'python', '-m', 'server.sli.core.report_schedule_producer', '--health'])
        self.assertLessEqual(service['pids_limit'], 64)
        # The real entry module is included by the existing image build rules.
        rules = (ROOT / 'deploy/linux/Dockerfile.dockerignore').read_text('utf-8')
        self.assertIn('!server/**', rules)

    @pytest.mark.legacy
    def test_base_compose_stays_inactive(self):
        base = (ROOT / 'deploy/linux/docker-compose.yml').read_text('utf-8')
        self.assertNotIn('report-producer', base)
        self.assertNotIn('report_producer_password', base)

    def test_native_secret_is_not_delivered_to_services(self):
        manifest = json.loads((ROOT / 'deploy/linux/secrets-manifest.json').read_text('utf-8'))
        self.assertEqual(manifest['secrets']['report_producer_password'],
                         {'kind': 'password', 'group': 'core'})
        for radius_pilot in (False, True):
            config = {'profiles': ['light', 'heavy', 'long'], 'radius_pilot': radius_pilot,
                      'bind': '192.0.2.1', 'health_url': 'https://192.0.2.1:8443/api/health/ready',
                      'agents': True, 'ad_credentials': True, 'owner_setup': True}
            with patch.object(native_runtime.clickhouse, 'configured_mode', return_value='native'):
                native = native_runtime.dotnet_units('synthetic', config)
                units = native_runtime.units(config) | native
            consumers = {name for name, body in units.items() if 'report_producer_password' in body}
            self.assertEqual(consumers, set())
            self.assertNotIn('sli-dotnet-report-producer.service', units)
            self.assertNotIn('sli-report-producer.service', units)
            self.assertNotIn('report-producer', native['sli-dotnet.target'])

    def options(self, env):
        self.assertTrue(callable(getattr(producer, 'connection_options', None)),
                        'producer must load only its explicitly mounted password file')
        return producer.connection_options(env)

    @pytest.mark.legacy
    def test_only_explicit_producer_password_file_is_used(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'synthetic-password'
            path.write_bytes(b'synthetic-producer-only\n')
            options = self.options({'SLI_REPORT_PRODUCER_PG_DSN': 'host=synthetic.invalid user=producer',
                'SLI_REPORT_PRODUCER_PG_PASSWORD_FILE': str(path), 'ADLOG_PG_DSN': 'private-api-value',
                'PGPASSWORD': 'private-environment-value', 'ADLOG_PG_PASSWORD_FILE': 'private-api-path'})
            self.assertEqual(options, {'conninfo': 'host=synthetic.invalid user=producer',
                                      'password': 'synthetic-producer-only'})

    @pytest.mark.legacy
    def test_missing_and_invalid_secret_fail_with_value_free_error(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'synthetic-password'
            for data in (b'', b'x' * 4097, b'one\ntwo', b'one\x00two', b'\xff'):
                path.write_bytes(data)
                with self.assertRaisesRegex(ValueError, '^invalid_report_producer_connection$'):
                    self.options({'SLI_REPORT_PRODUCER_PG_DSN': 'synthetic-dsn',
                                  'SLI_REPORT_PRODUCER_PG_PASSWORD_FILE': str(path)})
            for env in ({'ADLOG_PG_DSN': 'private-api-dsn', 'PGPASSWORD': 'private-api-password'},
                        {'SLI_REPORT_PRODUCER_PG_DSN': 'synthetic-dsn'},
                        {'SLI_REPORT_PRODUCER_PG_DSN': 'synthetic-dsn',
                         'SLI_REPORT_PRODUCER_PG_PASSWORD_FILE': 'relative-private-path'}):
                with self.assertRaisesRegex(ValueError, '^invalid_report_producer_connection$'):
                    self.options(env)

    @pytest.mark.legacy
    def test_health_never_reads_a_secret_or_connects(self):
        with TemporaryDirectory() as directory:
            status = Path(directory) / 'status.json'
            status.write_text(json.dumps({'pid': 1, 'at': time.time(), 'state': 'ok'}))
            with patch.object(sys, 'argv', ['producer', '--health']), patch.object(producer, 'STATUS', status), \
                 patch.object(producer, 'connection_options', side_effect=AssertionError('health read a secret')):
                self.assertEqual(producer.main(), 0)

    @pytest.mark.legacy
    def test_entrypoint_passes_only_explicit_mounted_password_to_driver(self):
        with TemporaryDirectory() as directory:
            password = Path(directory) / 'synthetic-password'
            password.write_bytes(b'synthetic-file-value\n')
            calls = []
            def connect(**kwargs):
                calls.append(kwargs)
                return nullcontext(object())
            driver, rows = SimpleNamespace(connect=connect), SimpleNamespace(dict_row=object())
            with patch.dict(sys.modules, {'psycopg': driver, 'psycopg.rows': rows}), \
                 patch.dict('os.environ', {'SLI_REPORT_PRODUCER_PG_DSN': 'synthetic-dsn',
                    'SLI_REPORT_PRODUCER_PG_PASSWORD_FILE': str(password), 'PGPASSWORD': 'wrong-fallback'}), \
                 patch.object(sys, 'argv', ['producer']), patch.object(producer.signal, 'signal'), \
                 patch.object(producer, 'run_cycle', return_value={'status': 'failed', 'leader': None}):
                self.assertEqual(producer.main(), 1)
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0]['conninfo'], 'synthetic-dsn')
            self.assertEqual(calls[0]['password'], 'synthetic-file-value')


if __name__ == '__main__':
    unittest.main()

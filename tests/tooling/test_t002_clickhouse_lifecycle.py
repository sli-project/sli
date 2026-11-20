"""No Docker required: lifecycle command/ownership regression tests."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts.ci import t002_clickhouse as ci


class FakeDocker:
    def __init__(self):
        self.calls = []
        self.objects = {}
        self.fail = None
        self.digest = 'clickhouse/clickhouse-server@sha256:' + 'a' * 64

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if self.fail and args[0] == self.fail:
            raise ci.LifecycleError('synthetic_failure')
        if args[0] == 'info':
            return 'linux'
        if args[0] == 'pull':
            return ''
        if args[:2] == ('image', 'inspect'):
            return json.dumps([{'RepoDigests': [self.digest], 'Os': 'linux', 'Architecture': 'amd64'}])
        if args[0] in {'volume', 'container'} and args[1] == 'ls':
            name = args[args.index('--filter') + 1][6:-1]
            return name if (args[0], name) in self.objects else ''
        if args[0] in {'volume', 'container'} and args[1] == 'inspect':
            label = self.objects[(args[0], args[2])]
            return json.dumps([{'Labels': {ci.LABEL: label}}] if args[0] == 'volume' else [{'Config': {'Labels': {ci.LABEL: label}}}])
        if args[:2] == ('volume', 'create'):
            self.objects[('volume', args[-1])] = args[args.index('--label') + 1].split('=', 1)[1]
            return args[-1]
        if args[0] == 'create':
            self.objects[('container', args[args.index('--name') + 1])] = args[args.index('--label') + 1].split('=', 1)[1]
            return 'container-id'
        if args[0] == 'start':
            return ''
        if args[0] == 'port':
            return '127.0.0.1:49152'
        if args[0] in {'volume', 'container'} and args[1] == 'rm':
            del self.objects[(args[0], args[-1])]
            return ''
        raise AssertionError(args)


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.state = Path(self.directory.name) / 'sli-t002-check.json'
        self.env = patch.dict(os.environ, {'RUNNER_TEMP': self.directory.name}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        socket = patch.object(ci, 'local_socket_state', return_value='socket')
        socket.start()
        self.addCleanup(socket.stop)
        self.docker = FakeDocker()

    def test_image_pin_reads_validated_repository_reference(self):
        pin = Path(self.directory.name) / 'pins.json'
        pin.write_text(json.dumps({'schema_version': 1, 'clickhouse_modes': {'docker': {
            'version': '999.1.2.3', 'image': {'reference': 'clickhouse/clickhouse-server:999.1.2.3'},
        }}}))
        self.assertEqual(ci.read_clickhouse_pin(pin), ('999.1.2.3', 'clickhouse/clickhouse-server:999.1.2.3'))

    def test_image_pin_refuses_missing_malformed_or_mismatched_reference(self):
        pin = Path(self.directory.name) / 'pins.json'
        with self.assertRaisesRegex(ci.LifecycleError, '^t002_clickhouse_pin_invalid$'):
            ci.read_clickhouse_pin(pin)
        for contents in ('not json', '{}', json.dumps({'schema_version': 2}),
                         json.dumps({'schema_version': 1, 'clickhouse_modes': {'docker': {
                             'version': '999.1.2.3', 'image': {'reference': 'untrusted/example:999.1.2.3'},
                         }}}),
                         json.dumps({'schema_version': 1, 'clickhouse_modes': {'docker': {
                             'version': 'latest', 'image': {'reference': 'clickhouse/clickhouse-server:latest'},
                         }}})):
            pin.write_text(contents)
            with self.assertRaisesRegex(ci.LifecycleError, '^t002_clickhouse_pin_invalid$'):
                ci.read_clickhouse_pin(pin)

    def invoke(self, returncode=0):
        def complete(args, **kwargs):
            report = Path(next(arg.split('=', 1)[1] for arg in args if arg.startswith('--junitxml=')))
            report.write_text('<testsuites><testsuite><testcase name="test_actual_report_native_context_history_and_volume" /></testsuite></testsuites>')
            return subprocess.CompletedProcess([], returncode)
        with patch.object(ci, 'docker', self.docker), patch.object(ci, 'query_version', return_value=ci.VERSION), patch.object(ci.subprocess, 'run', side_effect=complete) as child:
            ci.run(self.state)
        return child

    def test_resources_are_bounded_loopback_and_removed_after_success(self):
        child = self.invoke()
        self.assertFalse(self.state.exists())
        self.assertEqual(self.docker.objects, {})
        create = next(args for args, _ in self.docker.calls if args[0] == 'create')
        self.assertEqual(create[create.index('--cpus') + 1], '2')
        self.assertEqual(create[create.index('--memory') + 1], '2g')
        self.assertEqual(create[create.index('--publish') + 1], '127.0.0.1::8123')
        self.assertEqual(create[-1], self.docker.digest)
        self.assertNotIn('--privileged', create)
        self.assertNotIn('--network', create)
        self.assertEqual(child.call_args.kwargs['env']['ADLOG_HISTORY_CLICKHOUSE_PORT'], '49152')
        self.assertLessEqual(child.call_args.kwargs['timeout'], 480)
        password = child.call_args.kwargs['env']['ADLOG_HISTORY_CLICKHOUSE_PASSWORD']
        self.assertNotIn(password, str(create))

    def test_docker_failure_reports_only_allowlisted_stage_and_category(self):
        for stderr, reason in (("permission denied SECRET", "permission_denied"),
                               ("Cannot connect to daemon SECRET", "daemon_unreachable"),
                               ("unexpected SECRET", "command_failed")):
            completed = subprocess.CompletedProcess([], 1, stdout="", stderr=stderr)
            with patch.object(ci.subprocess, 'run', return_value=completed):
                with self.assertRaisesRegex(ci.LifecycleError, '^t002_docker_info_' + reason + '$'):
                    ci.docker('info', '--format', '{{.OSType}}')

    def test_absent_or_denied_socket_stops_before_docker(self):
        for state in ('absent', 'access_denied', 'not_socket'):
            with patch.object(ci, 'local_socket_state', return_value=state), patch.object(ci, 'docker', self.docker):
                with self.assertRaisesRegex(ci.LifecycleError, '^t002_local_docker_socket_' + state + '$'):
                    ci.run(self.state)
            self.assertEqual(self.docker.calls, [])
            self.assertFalse(self.state.exists())

    def test_failed_native_test_cleans_both_resources(self):
        with self.assertRaisesRegex(ci.LifecycleError, 'native_measurement_failed'):
            self.invoke(1)
        self.assertEqual(self.docker.objects, {})
        self.assertFalse(self.state.exists())

    def test_partial_startup_cleans_created_volume(self):
        self.docker.fail = 'create'
        with self.assertRaisesRegex(ci.LifecycleError, 'synthetic_failure'):
            self.invoke()
        self.assertEqual(self.docker.objects, {})
        self.assertFalse(self.state.exists())

    def test_foreign_daemon_is_refused_before_any_docker_command(self):
        os.environ['DOCKER_HOST'] = 'tcp://example.invalid:2375'
        with patch.object(ci, 'docker', self.docker), self.assertRaisesRegex(ci.LifecycleError, 'remote_docker_refused'):
            ci.run(self.state)
        self.assertEqual(self.docker.calls, [])
        self.assertFalse(self.state.exists())

    def test_foreign_ownership_is_never_deleted(self):
        owner = 'a' * 32
        self.state.write_text(json.dumps({'owner': owner}))
        name = f'sli-t002-{owner}'
        self.docker.objects[('container', name)] = 'foreign'
        with patch.object(ci, 'docker', self.docker), self.assertRaisesRegex(ci.LifecycleError, 'resource_not_owned'):
            ci.cleanup(self.state)
        self.assertEqual(self.docker.objects[('container', name)], 'foreign')
        self.assertTrue(self.state.exists())
        self.assertFalse(any(args[1:2] == ('rm',) for args, _ in self.docker.calls))

    def test_existing_state_is_not_overwritten(self):
        self.state.write_text('existing')
        with patch.object(ci, 'docker', self.docker), self.assertRaises(FileExistsError):
            ci.run(self.state)
        self.assertEqual(self.state.read_text(), 'existing')
        self.assertFalse(any(args[0] == 'pull' for args, _ in self.docker.calls))

    def test_name_collision_is_not_adopted_or_deleted(self):
        owner = 'b' * 32
        name = f'sli-t002-{owner}'
        self.docker.objects[('container', name)] = owner
        with patch.object(ci.uuid, 'uuid4') as nonce, patch.object(ci, 'docker', self.docker):
            nonce.return_value.hex = owner
            with self.assertRaisesRegex(ci.LifecycleError, 'resource_collision'):
                ci.run(self.state)
        self.assertFalse(self.state.exists())
        self.assertEqual(self.docker.objects[('container', name)], owner)
        self.assertFalse(any(args[1:2] == ('rm',) for args, _ in self.docker.calls))

    def test_interrupt_cleans_resources(self):
        with patch.object(ci, 'docker', self.docker), patch.object(ci, 'query_version', return_value=ci.VERSION), patch.object(ci.subprocess, 'run', side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            ci.run(self.state)
        self.assertEqual(self.docker.objects, {})

    def test_symlink_state_is_rejected(self):
        target = Path(self.directory.name) / 'untouched'
        target.write_text('existing')
        self.state.symlink_to(target)
        with self.assertRaisesRegex(ci.LifecycleError, 'state_symlink'):
            ci.cleanup(self.state)
        self.assertEqual(target.read_text(), 'existing')

    def test_image_without_official_digest_is_refused(self):
        self.docker.digest = 'untrusted/example@sha256:' + 'a' * 64
        with self.assertRaisesRegex(ci.LifecycleError, 'image_identity_unverified'):
            self.invoke()
        self.assertEqual(self.docker.objects, {})

    def test_version_mismatch_cleans_resources(self):
        with patch.object(ci, 'docker', self.docker), patch.object(ci, 'query_version', return_value='unexpected'), self.assertRaisesRegex(ci.LifecycleError, 'version_mismatch'):
            ci.run(self.state)
        self.assertEqual(self.docker.objects, {})

    def test_timeout_also_cleans_resources(self):
        with patch.object(ci, 'docker', self.docker), patch.object(ci, 'query_version', return_value=ci.VERSION), patch.object(ci.subprocess, 'run', side_effect=subprocess.TimeoutExpired('synthetic', 1)), self.assertRaisesRegex(ci.LifecycleError, 'native_measurement_timeout'):
            ci.run(self.state)
        self.assertEqual(self.docker.objects, {})

    def test_skipped_native_case_is_not_success(self):
        report = Path(self.directory.name) / 'result.xml'
        report.write_text('<testsuites><testsuite><testcase name="test_actual_report_native_context_history_and_volume"><skipped /></testcase></testsuite></testsuites>')
        with self.assertRaisesRegex(ci.LifecycleError, 'expected_case_not_passed'):
            ci.verify_native_result(report)

    def test_empty_or_missing_native_result_is_not_success(self):
        report = Path(self.directory.name) / 'result.xml'
        with self.assertRaisesRegex(ci.LifecycleError, 'result_missing_or_invalid'):
            ci.verify_native_result(report)
        report.write_text('<testsuites />')
        with self.assertRaisesRegex(ci.LifecycleError, 'expected_case_not_run'):
            ci.verify_native_result(report)


if __name__ == '__main__':
    unittest.main()

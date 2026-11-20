"""Characterize the actual file report's conditional detail dependency.

No database or raw detail reader is invoked. SQL proposal execution is a
separate PostgreSQL gate; these tests preserve the Python oracle conditions.
"""
import ast
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest

from tests.unit.test_report_schedule_projection import actual_report_access, access, Rule


def oracle():
    source = Path(__file__).resolve().parents[2] / 'server/sli/plugins/file_audit/reports.py'
    tree = ast.parse(source.read_text('utf-8'))
    tree.body = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'ransom_details']
    resolver = actual_report_access().__init__.__globals__['resolve_access_scope']
    namespace = dict(json=json, PLUGIN_ID='sli.file-audit', resolve_access_scope=resolver, AccessRule=Rule)
    exec(compile(tree, str(source), 'exec'), namespace)
    return namespace['ransom_details']


class FileDependencyTests(unittest.TestCase):
    def run_oracle(self, *, granted=True, items=True, state='admitted', fail=False):
        policy = access()
        if not granted:
            policy['reports'] = []
        # Allowed root is deliberately outside the page's item root.
        root = dict(agent_id='a', source_instance_id='s', collection_scope_id='allowed')
        page = [dict(id='synthetic-id', rule_code='file-audit.mass-read',
                     agent_id='a', source_instance_id='s', collection_scope_id='outside')] if items else []
        before = deepcopy(page)
        calls = []
        def execute(sql, params):
            calls.append((sql, params))
            if fail:
                raise RuntimeError('synthetic_detail_fault')
        cursor = SimpleNamespace(execute=execute, fetchone=lambda: {'decisions': {'synthetic-id': {'state': state}}})
        context = SimpleNamespace(access=policy, action='view')
        oracle()(cursor, context, [root], page)
        return calls, before, page

    def test_mass_read_and_allowed_root_outside_page_still_execute(self):
        calls, _, page = self.run_oracle()
        self.assertEqual(len(calls), 1)
        self.assertEqual(json.loads(calls[0][1][0])[0]['collection_scope_id'], 'allowed')
        self.assertEqual(json.loads(calls[0][1][1]), ['synthetic-id'])
        self.assertEqual(page[0]['ransom'], {'state': 'not_applicable'})

    def test_no_queue_grant_or_empty_page_skips_detail_reader(self):
        self.assertEqual(self.run_oracle(granted=False, fail=True)[0], [])
        self.assertEqual(self.run_oracle(items=False, fail=True)[0], [])

    def test_detail_states_do_not_change_population_or_count(self):
        for state in ('excluded', 'admitted', 'diagnostic', 'details_unavailable', 'not_evaluated'):
            _, before, page = self.run_oracle(state=state)
            self.assertEqual([{k: v for k, v in row.items() if k != 'ransom'} for row in page], before)

    def test_fault_only_propagates_when_dependency_executes(self):
        with self.assertRaisesRegex(RuntimeError, '^synthetic_detail_fault$'):
            self.run_oracle(fail=True)
        self.run_oracle(granted=False, fail=True)
        self.run_oracle(items=False, fail=True)


if __name__ == '__main__':
    unittest.main()

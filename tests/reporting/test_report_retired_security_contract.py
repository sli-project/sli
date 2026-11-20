"""Bounded stdlib/AST regressions; no application imports, database or network.

These exercise production function bodies with a synthetic cursor, not PostgreSQL
SQL execution, rollback, locking, or concurrency. Pytest also collects this suite.
"""
from __future__ import annotations

import ast
import copy
import json
from pathlib import Path
import re
from types import SimpleNamespace
import unittest
from collections.abc import Mapping

ROOT = Path(__file__).resolve().parents[2]
REPORTING = ROOT / 'server/sli/reporting'
KEY = 'my.report'
ACCESS = {'capabilities': ['reports.design', 'reports.publish']}
BASE = {
    'columns': ['name'], 'filters': [{'field': 'domain', 'op': 'eq', 'value': 1}],
    'sort': [], 'actions': ['view'], 'required_capabilities': ['field.identity_basic'],
    'field_categories': ['identity_basic'], 'target_path': '/reports/my.report',
    'export_policy': 'disabled', 'dashboard_metrics': [],
}


def functions(filename, namespace):
    tree = ast.parse((REPORTING / filename).read_text())
    tree.body = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    exec(compile(tree, filename, 'exec', flags=__import__('__future__').annotations.compiler_flag), namespace)


class Db:
    def __init__(self):
        self.history = []
        self.direct = False
        self.package = False
        self.executed = []
        self.rows = []
        self.clock = 0

    def execute(self, sql, params=()):
        sql = ' '.join(sql.split())
        self.executed.append((sql, params))
        self.rows = []
        if 'pg_advisory_xact_lock' in sql:
            return
        if 'has_grants' in sql:
            assert 'access_report_assignments' in sql and 'access_package_reports' in sql
            self.rows = [{'has_grants': self.direct or self.package}]
        elif 'select id from report_datasets_v4' in sql:
            self.rows = [{'id': 1}]
        elif 'max(version)' in sql:
            self.rows = [{'version': max((r['version'] for r in self.history), default=0) + 1}]
        elif 'from report_registry_v4 r join' in sql:
            if 'r.version=%s' in sql:
                self.rows = [r for r in self.history if r['version'] == params[1]]
            elif "r.status='retired'" in sql:
                assert params == (KEY,)
                assert 'r.published_at is not null' in sql.lower()
                assert 'order by r.published_at desc,r.version desc,r.id desc' in sql.lower()
                self.rows = sorted((r for r in self.history if r['status'] == 'retired' and r['published_at'] is not None), key=lambda r: (r['published_at'], r['version'], r['id']), reverse=True)[:1]
            elif "r.status='published'" in sql:
                self.rows = [r for r in self.history if r['status'] == 'published']
            else:
                raise AssertionError(sql)
        elif sql.startswith('insert into report_registry_v4'):
            self.clock += 1
            row = self.row(params[1], json.loads(params[6]), params[8], self.clock if params[8] == 'published' else None)
            row.update(discoverable=params[-3], requestable=params[-2], request_profile_json=json.loads(params[-1]))
            self.history.append(row)
            self.rows = [row]
        elif sql.startswith("update report_registry_v4 set status='retired'"):
            for r in self.history:
                if r['status'] == 'published':
                    r['status'] = 'retired'
                    self.rows.append(r)
        elif sql.startswith("update report_registry_v4 set status='published'"):
            self.clock += 1
            for r in self.history:
                if r['version'] == params[1]:
                    r.update(status='published', published_at=self.clock)
                    self.rows.append(r)
        else:
            raise AssertionError(sql)

    @staticmethod
    def row(version, definition=None, status='retired', published_at=1):
        return dict(id=version, version=version, report_key=KEY, status=status,
                    definition_json=copy.deepcopy(BASE if definition is None else definition),
                    dataset_key='entities.v2', dataset_version=1, published_at=published_at,
                    discoverable=True, requestable=True, request_profile_json={'max_duration_days': 7})

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows

    def cursor(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class RetiredSecurityContractTests(unittest.TestCase):
    def setUp(self):
        self.db = Db()
        self.audits = []
        self.definition = copy.deepcopy(BASE)
        self.dataset = 'entities.v2'
        ns = {'Mapping': Mapping, 'json': json}
        functions('reporting_v4_definitions.py', ns)
        self.src = SimpleNamespace(
            re=re, json=json, Mapping=Mapping, _connect=lambda: self.db,
            _json_mapping=lambda v: v or {}, _security_expands=ns['_security_expands'],
            code_defined_report_keys=lambda: frozenset(), builder_preview=self.preview,
            record_access_audit_with_cursor=lambda **kw: self.audits.append(kw),
        )
        self.ns = {'_src': self.src}
        helper = REPORTING / 'reporting_v4_security.py'
        if helper.exists():
            functions(helper.name, self.ns)
        functions('reporting_v4_publish.py', self.ns)
        functions('reporting_v4_lifecycle.py', self.ns)

    def preview(self, *args, **kwargs):
        d = self.definition
        return dict(dataset={'key': self.dataset, 'version': 1}, fields=[{'key': c} for c in d['columns']], filters=d['filters'], sort=d['sort'], actions=d['actions'], required_capabilities=d['required_capabilities'], required_field_categories=d['field_categories'], dashboard_metrics=d['dashboard_metrics'])

    def publish(self, status='published'):
        return self.ns['publish_report'](dict(report_key=KEY, name='Name', purpose='Test', owner='Owner', status=status), None, access=ACCESS)

    def promote(self):
        version = max((r['version'] for r in self.db.history), default=0) + 1
        row = self.db.row(version, self.definition, 'draft', None)
        row['dataset_key'] = self.dataset
        self.db.history.append(row)
        return self.ns['promote_report_version'](KEY, version, None, access=ACCESS)

    def rejected(self, operation):
        before = copy.deepcopy(self.db.history)
        audits = len(self.audits)
        self.db.executed.clear()
        with self.assertRaisesRegex(ValueError, '^report_security_reapproval_required$'):
            operation()
        # promote adds its synthetic draft before invoking production code.
        self.assertEqual(self.db.history[:len(before)], before)
        self.assertEqual(len(self.audits), audits)
        self.assertFalse(any(sql.startswith(('insert ', 'update ', 'delete ')) for sql, _ in self.db.executed))
        self.assertIn('pg_advisory_xact_lock', self.db.executed[0][0])

    def test_retire_then_expansion_rejected_for_both_grant_sources_and_paths(self):
        for grant in ('direct', 'package'):
            for path in ('publish', 'promote'):
                for change in ('dataset', 'filters', 'field_categories', 'actions', 'columns', 'required_capabilities'):
                    with self.subTest(grant=grant, path=path, change=change):
                        self.setUp()
                        self.publish()
                        setattr(self.db, grant, True)
                        self.ns['retire_report'](KEY, None, access=ACCESS)
                        if change == 'dataset':
                            self.dataset = 'events.v2'
                        elif change == 'filters':
                            self.definition['filters'] = []
                        else:
                            self.definition[change].append('extra')
                        self.rejected(getattr(self, path))
                        self.assertTrue(getattr(self.db, grant))

    def test_grants_without_published_history_fail_closed(self):
        for path in ('publish', 'promote'):
            with self.subTest(path=path):
                self.setUp()
                self.db.direct = True
                self.db.history = [self.db.row(3, status='draft', published_at=None), self.db.row(4, status='retired', published_at=None)]
                self.rejected(getattr(self, path))

    def test_latest_publication_not_highest_version_or_draft(self):
        for path in ('publish', 'promote'):
            with self.subTest(path=path):
                self.setUp()
                self.db.package = True
                expanded = copy.deepcopy(BASE)
                expanded['filters'] = []
                self.db.history = [self.db.row(2, BASE, published_at=20), self.db.row(8, expanded, published_at=10), self.db.row(9, expanded, 'draft', None)]
                self.definition = expanded
                self.rejected(getattr(self, path))

    def test_same_contract_and_no_grants_are_accepted(self):
        for path in ('publish', 'promote'):
            for grants in (True, False):
                with self.subTest(path=path, grants=grants):
                    self.setUp()
                    self.db.direct = grants
                    self.db.history = [self.db.row(1)]
                    if not grants:
                        self.definition['filters'] = []
                    result = getattr(self, path)()
                    self.assertEqual(result['status'], 'published')
                    if path == 'publish':
                        self.assertFalse(result['discoverable'])
                        self.assertFalse(result['requestable'])
                        self.assertEqual(result['request_profile_json']['max_duration_days'], 90)
                    else:
                        self.assertIsNone(self.audits[-1]['details']['retired_version'])

    def test_draft_creation_allowed_until_promotion(self):
        self.db.direct = True
        self.db.history = [self.db.row(1)]
        self.definition['filters'] = []
        result = self.publish('draft')
        self.assertEqual(result['status'], 'draft')
        self.rejected(lambda: self.ns['promote_report_version'](KEY, result['version'], None, access=ACCESS))

    def test_current_publication_wins_and_visibility_is_inherited(self):
        self.db.direct = True
        expanded = copy.deepcopy(BASE)
        expanded['filters'] = []
        self.db.history = [self.db.row(1, expanded, published_at=100), self.db.row(2, BASE, 'published', 10)]
        result = self.publish()
        self.assertTrue(result['discoverable'])
        self.assertTrue(result['requestable'])
        self.assertEqual(result['request_profile_json']['max_duration_days'], 7)
        self.assertFalse(any("r.status='retired'" in sql for sql, _ in self.db.executed))


def test_imported_publication_paths_retain_retired_security_contract(monkeypatch):
    """Normal pytest regression through actual imports; requires app dependencies."""
    from server.sli.reporting import reporting_v4

    for grant in ('direct', 'package'):
        for path in ('publish', 'promote'):
            case = RetiredSecurityContractTests()
            case.setUp()
            for name in ('_connect', 'builder_preview', 'record_access_audit_with_cursor', 'code_defined_report_keys'):
                monkeypatch.setattr(reporting_v4, name, getattr(case.src, name))
            case.ns = {
                'publish_report': reporting_v4.publish_report,
                'promote_report_version': reporting_v4.promote_report_version,
                'retire_report': reporting_v4.retire_report,
            }
            case.publish()
            setattr(case.db, grant, True)
            case.ns['retire_report'](KEY, None, access=ACCESS)
            case.definition['filters'] = []
            case.rejected(getattr(case, path))


if __name__ == '__main__':
    unittest.main()

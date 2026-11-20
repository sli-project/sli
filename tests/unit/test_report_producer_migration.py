"""Unapplied migration source contracts; real PostgreSQL checks live separately."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / 'config/postgres_migrations/285_report_producer.sql'


class ProducerMigrationTests(unittest.TestCase):
    def test_fixture_reset_deletes_only_own_marker_and_retains_upstream(self):
        import ast
        source = (ROOT / 'tests/migrations/test_report_producer_migration285.py').read_text('utf-8')
        tree = ast.parse(source)
        reset = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'predecessor')
        sql = [node.args[0].value for node in ast.walk(reset) if isinstance(node, ast.Call)
               and isinstance(node.func, ast.Attribute) and node.func.attr == 'execute' and node.args
               and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)]
        self.assertEqual([query for query in sql if query.startswith('delete from public.schema_migrations')],
                         ["delete from public.schema_migrations where version=285 and name='report_producer'"])
        self.assertEqual(sum('select * from public.schema_migrations where version=284' in query for query in sql), 2)

    def test_single_numbered_atomic_migration_contains_full_chain(self):
        self.assertTrue(MIGRATION.exists(), 'full chain must be in normal migration discovery')
        text = MIGRATION.read_text('utf-8')
        self.assertEqual(text.count('\nbegin;'), 1)
        self.assertEqual(text.count('\ncommit;'), 1)
        self.assertIn("version=284 and name='event_source_identity'", text)
        self.assertIn('where version>=285', text)
        self.assertIn("values(285,'report_producer')", text)
        for name in ('report_schedule_claim', 'report_schedule_acl_facts', 'report_schedule_candidates',
                     'report_schedule_publish', 'report_schedule_delivery'):
            self.assertIn('create function public.' + name + '(', text)
        self.assertIn('grant update(id) on public.notification_outbox to adlog_report_producer_owner;', text)
        self.assertNotRegex(text.lower(), r'grant\s+update\s+on\s+public\.notification_outbox')


if __name__ == '__main__':
    unittest.main()

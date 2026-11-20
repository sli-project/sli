"""Generated fixed aggregate SQL must share the existing population/cohorts."""
import unittest
from pathlib import Path
from server.sli.semantic import report_aggregate_sql as sql


class AggregateSqlTests(unittest.TestCase):
    def test_checked_in_generator_and_post_count_timestamp(self):
        definition = sql.security_aggregate_sql()
        self.assertIn('v_generated:=clock_timestamp();', definition)
        self.assertLess(definition.index('into v_result;'), definition.index('v_generated:=clock_timestamp();'))
        self.assertLess(definition.index('v_generated:=clock_timestamp();'), definition.index('into v_heartbeat'))
        proposal = (Path(__file__).resolve().parents[2] / 'config/postgres_migrations/285_report_producer.sql').read_text('utf-8')
        self.assertIn(definition.strip(), proposal)

    def test_fixed_search_path_and_qualified_source_population(self):
        definition = sql.security_aggregate_sql()
        for token in ("set search_path=pg_catalog,pg_temp", "public.findings_active", "public.finding_evidence",
                      "public.events_v2_core", "public.is_semantic_finding_published_v1", "representative_rank=1"):
            self.assertIn(token, definition)
        self.assertNotIn("?::", definition)
        self.assertNotRegex(definition.lower(), r"(?m)^\s*execute\s")

    def test_both_has_more_values_follow_default_limit(self):
        definition = sql.security_aggregate_sql()
        self.assertIn("'individual'", definition)
        self.assertIn("'cohorts'", definition)
        self.assertEqual(definition.count("'has_more',total>50"), 2)
        self.assertIn("findings.last_seen_utc::timestamptz >= p_start", definition)
        self.assertIn("findings.last_seen_utc::timestamptz < p_end", definition)


if __name__ == "__main__":
    unittest.main()

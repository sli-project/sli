"""Pure shared SQL population predicates; actual SQL parity needs PostgreSQL."""
import unittest

from server.sli.semantic import problem_population as population


class PopulationTests(unittest.TestCase):
    def test_publication_suppression_and_expired_risk_are_preserved(self):
        effective, accepted, clauses, params = population.problem_population_filters()
        self.assertIn("risk.expires_at <= statement_timestamp()", effective)
        self.assertIn("risk.expires_at > statement_timestamp()", accepted)
        self.assertIn("is_semantic_finding_published_v1(findings.id)", clauses)
        self.assertTrue(any("semantic_finding_in_domains_v265(findings.id,null)" in clause for clause in clauses))
        self.assertTrue(any("not semantic_finding_suppressed_v160" in clause for clause in clauses))
        self.assertEqual(params, [])

    def test_status_severity_and_half_open_last_seen_bounds(self):
        _, _, clauses, params = population.problem_population_filters(status="active",severity="high",
            time_from="2026-10-24T00:00:00Z",time_to="2026-10-25T00:00:00Z")
        self.assertIn("findings.last_seen_utc::timestamptz >= ?::timestamptz", clauses)
        self.assertIn("findings.last_seen_utc::timestamptz < ?::timestamptz", clauses)
        self.assertEqual(params, ["active", "high", "2026-10-24T00:00:00Z", "2026-10-25T00:00:00Z"])

    def test_accepted_population_does_not_apply_suppression_exclusion(self):
        _, _, clauses, _ = population.problem_population_filters(risk="accepted")
        self.assertFalse(any("semantic_finding_suppressed" in clause for clause in clauses))


if __name__ == "__main__":
    unittest.main()

"""The report displays an outcome, not the quality of its source evidence."""

import unittest
from copy import deepcopy

from server.sli.reporting.v2.reports import security_events
from server.sli.reports.security_event_reporting import _outcome


class SecurityEventOutcomePresentationTests(unittest.TestCase):
    def assert_display(self, item, expected):
        original = deepcopy(item)
        row = security_events._with_derived(item)
        self.assertEqual(row["outcome_code"], expected)
        self.assertEqual(item, original)
        if "outcome" in item:
            self.assertIs(row["outcome"], item["outcome"])
            self.assertEqual(row["outcome"], original["outcome"])

    def test_actual_engine_outcomes_keep_source_evidence(self):
        cases = [
            ({}, 4624, "success"),
            ({}, 4625, "failure"),
            ({"audit_keywords": "AuditSuccess", "result_code": "0xC000006D"}, 4724, "success"),
            ({"audit_keywords": "AuditFailure", "result_code": "0x0"}, 4724, "failure"),
            ({"result_code": "0x0"}, 4724, "unknown"),
            ({}, 4740, "unknown"),
        ]
        for event, event_id, expected in cases:
            with self.subTest(event_id=event_id, event=event):
                self.assert_display({"event_db_id": 7, "outcome": _outcome(event, event_id)}, expected)

    def test_missing_or_unproven_outcomes_never_promote_a_value(self):
        for outcome in [
            None, {}, "success", [],
            {"state": "unknown"},
            {"state": "unknown", "value": "success", "reason": "not_proven"},
            {"state": "unexpected", "value": "failure"},
            {"value": "success"},
            {"state": "observed"},
            {"state": "observed", "value": "unexpected"},
            {"state": "observed", "value": ["success"]},
        ]:
            with self.subTest(outcome=outcome):
                self.assert_display({"outcome": outcome}, "unknown")
        self.assert_display({}, "unknown")

    def test_column_reads_the_derived_outcome_with_existing_labels(self):
        column = next(column for column in security_events.REPORT.columns if column.key == "outcome")
        self.assertEqual(column.path, "outcome_code")
        self.assertEqual(column.labels, dict(security_events.OUTCOMES))

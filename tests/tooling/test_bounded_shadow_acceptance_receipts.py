"""Synthetic-only controller tests: no production imports or state-file access."""
from __future__ import annotations

import ast
import json
import unittest
from contextlib import nullcontext
from datetime import UTC, datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

ROOT = Path(__file__).resolve().parents[2]


class ShadowAcceptanceTests(unittest.TestCase):

    def receipt(self, policy_index):
        policy_id, definition = self.ns["POLICIES"][policy_index]
        return {"policy_id": policy_id, "policy_version": 2,
                    "action_kind": definition["source_selector"]["action_kind"],
                    "scenario_kind": definition["scenario_kind"],
                    "job_id": f"job-{policy_index}", "source_event_id": 101 + policy_index,
                    "canonical_action_id": f"action-{policy_index}", "scenario_id": f"scenario-{policy_index}"}

    def test_historical_scenarios_with_zero_inputs_never_complete(self):
        result = self.ns["poll"](limit=16)
        self.assertEqual(result["status"], "waiting_for_new_events")

    def test_all_three_kinds_but_only_three_policies_are_incomplete(self):
        self.targets = [101, 102, 103, 104]
        self.receipts = [self.receipt(i) for i in (0, 2, 3)]
        result = self.ns["poll"](limit=16)
        self.assertEqual(result["status"], "waiting_for_new_events")

    def test_each_exact_policy_receipt_completes_and_retains_inputs(self):
        self.targets = [101, 102, 103, 104]
        self.receipts = [self.receipt(i) for i in range(4)]
        result = self.ns["poll"](limit=16)
        self.assertEqual(result["status"], "shadow_evidence_complete")
        self.assertEqual(self.state["input_event_ids"], self.targets)
        self.assertEqual(len(result["shadow_evidence"]["receipts"]), 4)
        self.targets = []
        self.assertEqual(self.ns["poll"](limit=16)["status"], "shadow_evidence_complete")

    def test_old_state_is_not_upgraded_from_aggregates_or_new_inputs(self):
        del self.state["evidence_contract_version"]
        self.targets = [101, 102, 103, 104]
        self.receipts = [self.receipt(i) for i in range(4)]
        self.assertEqual(self.ns["poll"](limit=16)["status"], "shadow_evidence_unknown")
        self.assertNotIn("evidence_contract_version", self.state)

    def test_wrong_version_or_policy_action_receipts_do_not_complete(self):
        self.targets = [101, 102, 103, 104]
        for field, value in (("policy_version", 1), ("action_kind", "audit.policy.changed")):
            with self.subTest(field=field):
                self.receipts = [self.receipt(i) for i in range(4)]
                self.receipts[0][field] = value
                self.assertEqual(self.ns["poll"](limit=16)["status"], "waiting_for_new_events")

    def test_wrong_modes_source_ids_old_jobs_and_unfinished_jobs_are_incomplete(self):
        self.targets = [101, 102, 103, 104]
        for field, value in (("evaluation_mode", "test"), ("result_mode", "enabled"),
                             ("source_kind", "correlation_candidate"),
                             ("source_event_id", 99), ("source_event_id", 999),
                             ("evaluation_status", "queued"),
                             ("created_at", "2026-10-21T00:00:00+00:00")):
            with self.subTest(field=field, value=value):
                self.receipts = [self.receipt(i) for i in range(4)]
                self.receipts[0][field] = value
                self.assertEqual(self.ns["poll"](limit=16)["status"], "waiting_for_new_events")

    def test_apply_freezes_each_policy_version_with_empty_new_run_scope(self):
        saved = []
        self.ns.update(STATE_PATH=SimpleNamespace(exists=lambda: False),
                       _ensure_semantic_role=lambda cur: False,
                       _apply_migrations=lambda cur: [],
                       _register_policies=lambda conn: self.state["policy_ids"],
                       _write_state=lambda state: saved.append(state))
        self.ns["apply"]()
        self.assertEqual(saved[0]["policy_versions"], self.state["policy_versions"])
        self.assertEqual(saved[0]["input_event_ids"], [])
        self.assertEqual(saved[0]["evidence_contract_version"], 1)
        self.assertEqual(saved[0]["start_event_id"], 104)

    def test_unsupported_policy_scope_or_unscoped_inputs_are_unknown(self):
        for field, value in (("policy_versions", {"old-policy": 1}),
                             ("input_event_ids", [99]),
                             ("input_event_ids", [105]),
                             ("started_at_utc", "2026-10-22T00:00:00")):
            with self.subTest(field=field):
                state = dict(self.state, **{field: value})
                evidence = self.ns["_shadow_evidence"](None, state)
                self.assertEqual(evidence["status"], "unknown")

    def test_receipt_query_binds_scope_modes_versions_and_completed_result(self):
        self.targets = [101, 102, 103, 104]
        self.ns["poll"](limit=16)
        sql, params = next((q, p) for q, p in self.queries
                           if "from semantic_risk_evaluation_jobs job" in q)
        for guard in ("job.policy_version=%s", "job.source_kind='canonical_action'",
                      "job.evaluation_mode='shadow'", "result.evaluation_mode='shadow'",
                      "job.evaluation_status='completed'", "job.created_at>=%s",
                      "result.created_at>=%s", "normalized.source_event_id=any(%s)",
                      "evidence.evidence_role='primary'", "join semantic_risk_evaluation_results",
                      "join semantic_security_scenarios", "join canonical_action_evidence",
                      "join normalized_events"):
            self.assertIn(guard, sql)
        self.assertIn([101, 102, 103, 104], params)
        self.assertIn(2, params)
        self.assertIn(self.state["started_at_utc"], params)
        target_sql, target_params = next((q, p) for q, p in self.queries
                                        if "from events_v2_core core" in q)
        self.assertIn("core.id<=%s", target_sql)
        self.assertEqual(target_params, (100, 104, 5000))




if __name__ == "__main__":
    unittest.main()

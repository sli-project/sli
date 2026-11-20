"""Portable validation of the producer's pre-projection aggregate boundary.

These tests establish payload bounds only, not SQL ACL or report parity.
Run directly with unittest; no database, service or transport is used.
"""
import copy
import unittest

from server.sli.core import report_schedule_candidates as candidates


def security():
    return {
        "report_key": "security.problems", "quality": "partial",
        "counts": {"individual": {"total": 51, "has_more": True}, "cohorts": {"total": 1, "has_more": False}},
        "roots": [],
    }


def files():
    return {
        "report_key": "file-audit.mass-operations", "quality": "partial", "root_limit": False,
        "counts": {}, "roots": [{"agent_id": "a", "source_instance_id": "s",
            "collection_scope_id": "r", "source_kind": "server"}],
    }


class CandidateBoundaryTests(unittest.TestCase):
    def reject(self, payload):
        with self.assertRaisesRegex(ValueError, "^invalid_report_candidate$"):
            candidates.validate(payload)

    def test_bounded_preprojection_shapes(self):
        for payload in (security(), files()):
            self.assertEqual(candidates.validate(payload), payload)

    def test_source_rows_evidence_and_identity_fields_rejected(self):
        for key in ("items", "evidence", "username", "actor", "source_rows", "owner_user_id"):
            with self.subTest(key=key):
                self.reject({**security(), key: "private-fixture"})

    def test_no_authority_flags_or_client_root_selection(self):
        for key in ("allowed", "group_queue", "recipient_user_id", "admitted_roots", "sql"):
            self.reject({**files(), key: True})

    def test_counts_are_nonnegative_bounded_integers(self):
        for bad in (True, -1, 2**63, 1.5, "1", None):
            payload = security()
            payload["counts"]["individual"]["total"] = bad
            self.reject(payload)

    def test_has_more_matches_each_variants_actual_default_limit(self):
        payload = security()
        payload["counts"]["individual"]["has_more"] = False
        self.reject(payload)
        payload = security()
        payload["counts"]["cohorts"]["has_more"] = True
        self.reject(payload)

    def test_variants_are_exact_and_do_not_select_authority(self):
        payload = security()
        del payload["counts"]["cohorts"]
        self.reject(payload)
        payload = security()
        payload["counts"]["cohorts"]["identity"] = "private-fixture"
        self.reject(payload)

    def test_file_tuples_cannot_carry_names_paths_or_evidence(self):
        for key in ("path", "share_name", "evidence", "subject_sid", "allowed", "total"):
            payload = files()
            payload["roots"][0][key] = "private-fixture"
            self.reject(payload)

    def test_root_limit_is_rejection_not_silent_truncation(self):
        payload = files()
        payload["roots"] = [{**payload["roots"][0], "collection_scope_id": str(i)} for i in range(1001)]
        self.reject(payload)

    def test_initial_root_limit_is_distinct_from_no_admitted_roots(self):
        payload = files()
        payload.update(root_limit=True, roots=[])
        self.assertEqual(candidates.validate(payload), payload)
        payload["roots"] = files()["roots"]
        self.reject(payload)

    def test_duplicate_or_missing_tuple_dimensions_rejected(self):
        payload = files()
        payload["roots"] *= 2
        self.reject(payload)
        for value in ("", " a", "x" * 257, None, 1):
            payload = files()
            payload["roots"][0]["agent_id"] = value
            self.reject(payload)

    def test_quality_and_count_visibility_remain_distinct(self):
        for quality in ("denied", "error", "not_collected", "processing"):
            payload = security()
            payload.update(quality=quality, counts={})
            self.assertEqual(candidates.validate(payload), payload)
            payload["counts"] = security()["counts"]
            self.reject(payload)
        self.reject({**security(), "quality": "healthy"})

    def test_wrong_report_shape_or_top_level_truncation_rejected(self):
        self.reject({**security(), "roots": files()["roots"]})
        self.reject({**files(), "counts": security()["counts"]})
        self.reject({**security(), "truncated": 1})
        self.reject({**security(), "report_key": "arbitrary"})

    def test_validation_does_not_retain_mutable_input(self):
        payload = security()
        before = copy.deepcopy(payload)
        validated = candidates.validate(payload)
        payload["counts"]["individual"]["total"] = 99
        self.assertEqual(validated, before)


if __name__ == "__main__":
    unittest.main()

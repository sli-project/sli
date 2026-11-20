from hashlib import sha256

import pytest

from server.sli.ops import runtime_workers
from server.sli.semantic.semantic_processing_repository import PROCESSOR_ID, PROCESSOR_VERSION


def proof():
    detail = 'duplicate key violates "canonical_actions_pkey"'
    return {
        "source_event_id": 17, "source_hash": "a" * 64,
        "original_job_count": 1, "original_job_id": "original-job",
        "original_status": "quarantined", "original_attempt_count": 5,
        "original_max_attempts": 5, "original_error_code": "UniqueViolation",
        "original_error_detail": detail,
        "original_source_hash": "a" * 64,
        "repair_job_count": 1, "repair_status": "completed",
        "repair_processor_id": PROCESSOR_ID, "repair_processor_version": PROCESSOR_VERSION,
        "repair_semantic_contract_version": 1,
        "repair_source_hash": "a" * 64, "repair_payload_source_hash": "a" * 64,
        "repair_original_job_id": "original-job",
        "repair_history_plan_digest": "b" * 64, "repair_plan_digest": "c" * 64,
        "repair_original_attempt_count": 5, "repair_original_max_attempts": 5,
        "repair_original_error_code": "UniqueViolation",
        "repair_original_error_detail_sha256": sha256(detail.encode()).hexdigest(),
        "normalized_current_count": 1, "normalized_proof_count": 1,
        "normalized_proof_hash": "a" * 64, "normalized_action_count": 1,
    }


def overview(proof_rows):
    class Cursor:
        def __init__(self):
            self.results = iter([
                [{"queue_name": "processing", "queue_status": "quarantined",
                  "depth": 2, "retries": 8},
                 {"queue_name": "processing", "queue_status": "completed", "depth": 1}],
                [{"source_event_id": 17, "source_hash": "a" * 64}],
                proof_rows,
            ])

        def execute(self, sql, params=()):
            assert not any(word in sql.lower().split() for word in ("update", "delete", "insert"))

        def fetchall(self):
            return next(self.results)

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    class Connection(Cursor):
        def cursor(self):
            return self

    return runtime_workers.get_semantic_queue_overview(connection_factory=Connection)


def test_completed_exact_repair_is_separate_history_without_hiding_other_quarantine():
    result = overview([proof()])
    rows = {row["queue_status"]: row for row in result["items"]}
    assert result["status"] == "ok"
    assert rows["quarantined"]["depth"] == 1
    assert rows["quarantined"]["retries"] == 4
    assert rows["repaired"]["depth"] == 1
    assert rows["repaired"]["retries"] == 4
    assert rows["completed"]["depth"] == 1
    assert "canonical_actions_pkey" not in str(result)
    assert "original-job" not in str(result)


@pytest.mark.parametrize(("field", "value"), [
    ("repair_status", "queued"), ("repair_status", "failed"),
    ("repair_job_count", 2), ("repair_original_job_id", "another-job"),
    ("repair_source_hash", "d" * 64), ("repair_payload_source_hash", "d" * 64),
    ("repair_original_error_detail_sha256", "d" * 64),
    ("repair_original_attempt_count", 4), ("repair_processor_version", "old"),
    ("repair_history_plan_digest", "invalid"), ("repair_plan_digest", "invalid"),
    ("original_error_code", "InsufficientPrivilege"),
    ("original_job_count", 2), ("source_hash", "d" * 64),
    ("normalized_current_count", 2), ("normalized_proof_count", 0),
    ("normalized_proof_hash", "d" * 64), ("normalized_action_count", 0),
    ("repair_original_attempt_count", "invalid"),
])
def test_unproven_repairs_remain_in_quarantine(field, value):
    row = proof()
    row[field] = value
    result = overview([row])
    assert result["status"] == "ok"
    rows = {row["queue_status"]: row for row in result["items"]}
    assert rows["quarantined"]["depth"] == 2
    assert rows["quarantined"]["retries"] == 8
    assert "repaired" not in rows


def test_duplicate_proof_rows_do_not_cover_two_originals():
    result = overview([proof(), proof()])
    assert result["status"] == "ok"
    assert not any(row["queue_status"] == "repaired" for row in result["items"])

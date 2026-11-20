from __future__ import annotations

from hashlib import sha256
from uuid import UUID

import pytest

from server.sli.semantic.semantic_processing import NORMALIZER_ID, NORMALIZER_VERSION
from server.sli.semantic.semantic_processing_repository import (
    PROCESSOR_ID,
    PROCESSOR_VERSION,
    SEMANTIC_V2_QUARANTINE_REPAIR_JOB_KIND,
    _identity,
)
from server.sli.semantic.semantic_worker_runtime import _validate_semantic_v2_quarantine_repair_job


SOURCE_HASH = "a" * 64
ORIGINAL_ID = "12345678-1234-5678-1234-567812345678"
ERROR_DETAIL = 'duplicate key value violates unique constraint "canonical_actions_pkey"'


def repair_job() -> dict[str, object]:
    return {
        "job_kind": SEMANTIC_V2_QUARANTINE_REPAIR_JOB_KIND,
        "source_event_id": 260,
        "semantic_contract_version": 1,
        "processor_id": PROCESSOR_ID,
        "processor_version": PROCESSOR_VERSION,
        "source_identity_json": {
            "id": 260, "server_id": 1, "domain_id": 1, "log_source_id": 1,
            "event_id": 4624, "time_created_utc": "2026-09-20T00:00:00+00:00",
            "normalized_hash": SOURCE_HASH, "migrated_at": "2026-09-20T00:00:00+00:00",
            "channel": "Security",
        },
    }


def repair_payload() -> dict[str, object]:
    return {
        "repair_plan_digest": "b" * 64,
        "history_plan_digest": "c" * 64,
        "original_source_hash": SOURCE_HASH,
        "original_job_id": ORIGINAL_ID,
        "original_attempt_count": 5,
        "original_max_attempts": 5,
        "original_error_code": "UniqueViolation",
        "original_error_detail_sha256": sha256(ERROR_DETAIL.encode()).hexdigest(),
    }


class Cursor:
    def __init__(self, *, original: dict[str, object] | None = None, normalized: bool = False) -> None:
        self.original = original or {
            "source_event_id": 260, "job_kind": "normalize_event", "status": "quarantined",
            "semantic_contract_version": 1, "processor_id": PROCESSOR_ID,
            "processor_version": PROCESSOR_VERSION, "source_hash": SOURCE_HASH,
            "attempt_count": 5, "max_attempts": 5, "last_error_code": "UniqueViolation",
            "last_error_detail": ERROR_DETAIL,
        }
        self.normalized = normalized
        self.calls: list[tuple[str, tuple[object, ...]]] = []

    def execute(self, sql: str, params: tuple[object, ...] = ()) -> None:
        self.calls.append((" ".join(sql.split()).lower(), params))

    def fetchone(self):
        return self.original if len(self.calls) == 1 else {"exists": self.normalized}


def test_v2_quarantine_repair_accepts_only_exact_terminal_original_before_source_load() -> None:
    cur = Cursor()
    _validate_semantic_v2_quarantine_repair_job(cur, repair_job(), repair_payload())
    assert len(cur.calls) == 2
    assert "last_error_detail" in cur.calls[0][0]
    assert "normalizer_id=%s" in cur.calls[1][0]
    assert cur.calls[1][1] == (260, 1, NORMALIZER_ID, NORMALIZER_VERSION)


def test_v2_quarantine_repair_remains_executable_after_admitted_worker_release_changes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A queued repair keeps its immutable lineage; compatible F2 need not be F1's binary."""
    from server.sli.semantic import semantic_worker_contract as contract

    monkeypatch.setattr(contract, "semantic_worker_release_fingerprint", lambda: "f" * 64)
    payload = repair_payload()

    assert "worker_release_fingerprint" not in payload
    _validate_semantic_v2_quarantine_repair_job(Cursor(), repair_job(), payload)
    changed_version = repair_job()
    changed_version["processor_version"] = "incompatible-processor-version"
    with pytest.raises(RuntimeError, match="terminal evidence"):
        _validate_semantic_v2_quarantine_repair_job(Cursor(), changed_version, payload)


@pytest.mark.parametrize("field,value", [
    ("job_kind", "semantic_repair"), ("status", "completed"),
    ("attempt_count", 4), ("last_error_code", "IntegrityError"),
    ("source_hash", "d" * 64),
])
def test_v2_quarantine_repair_rejects_original_contract_mismatches(field: str, value: object) -> None:
    original = Cursor().original.copy()
    original[field] = value
    with pytest.raises(RuntimeError):
        _validate_semantic_v2_quarantine_repair_job(Cursor(original=original), repair_job(), repair_payload())


@pytest.mark.parametrize("field,value", [
    ("repair_plan_digest", "B" * 64), ("original_job_id", "ABCDEFAB-CDEF-ABCD-EFAB-CDEFABCDEFAB"),
    ("original_attempt_count", 0), ("original_max_attempts", 4),
    ("original_attempt_count", "5"),
    ("original_error_code", "uniqueviolation"), ("original_error_detail_sha256", "0" * 64),
])
def test_v2_quarantine_repair_rejects_invalid_payload(field: str, value: object) -> None:
    payload = repair_payload()
    payload[field] = value
    with pytest.raises(RuntimeError):
        _validate_semantic_v2_quarantine_repair_job(Cursor(), repair_job(), payload)


def test_v2_quarantine_repair_rejects_current_normalization_and_noncanonical_error_detail() -> None:
    with pytest.raises(RuntimeError):
        _validate_semantic_v2_quarantine_repair_job(Cursor(normalized=True), repair_job(), repair_payload())
    original = Cursor().original.copy()
    original["last_error_detail"] = "canonical_actions_pkey"
    payload = repair_payload()
    payload["original_error_detail_sha256"] = sha256(str(original["last_error_detail"]).encode()).hexdigest()
    with pytest.raises(RuntimeError):
        _validate_semantic_v2_quarantine_repair_job(Cursor(original=original), repair_job(), payload)


def test_v2_quarantine_repair_accepts_localized_exact_constraint_name() -> None:
    detail = 'ОШИБКА: повторяющееся значение ключа нарушает ограничение уникальности "canonical_actions_pkey"'
    original = Cursor().original.copy()
    original["last_error_detail"] = detail
    payload = repair_payload()
    payload["original_error_detail_sha256"] = sha256(detail.encode()).hexdigest()
    _validate_semantic_v2_quarantine_repair_job(Cursor(original=original), repair_job(), payload)


def test_v2_quarantine_repair_rejects_a_different_quoted_constraint_name() -> None:
    detail = 'ОШИБКА: повторяющееся значение ключа нарушает ограничение уникальности "other_pkey"'
    original = Cursor().original.copy()
    original["last_error_detail"] = detail
    payload = repair_payload()
    payload["original_error_detail_sha256"] = sha256(detail.encode()).hexdigest()
    with pytest.raises(RuntimeError):
        _validate_semantic_v2_quarantine_repair_job(Cursor(original=original), repair_job(), payload)


def test_v2_repair_identity_is_distinct_and_deterministic() -> None:
    v1 = _identity(source_event_id=260, job_kind="semantic_repair", processor_id=PROCESSOR_ID, processor_version=PROCESSOR_VERSION)
    v2 = _identity(source_event_id=260, job_kind=SEMANTIC_V2_QUARANTINE_REPAIR_JOB_KIND, processor_id=PROCESSOR_ID, processor_version=PROCESSOR_VERSION)
    assert v1 != v2
    assert v2 == _identity(source_event_id=260, job_kind=SEMANTIC_V2_QUARANTINE_REPAIR_JOB_KIND, processor_id=PROCESSOR_ID, processor_version=PROCESSOR_VERSION)

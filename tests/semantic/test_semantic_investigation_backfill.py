from __future__ import annotations

from pathlib import Path
from contextlib import contextmanager
import json
from hashlib import sha256

import pytest

from server.sli.semantic.semantic_processing_repository import PROCESSOR_ID, PROCESSOR_VERSION
from server.sli.semantic.semantic_processing import SEMANTIC_CONTRACT_VERSION


def test_security_history_vocabulary_freezes_exact_provider_bound_compact_cohorts() -> None:
    """Wrong provider, an interior hash change, or raw ID lists must invalidate the pass."""
    from server.sli.semantic.semantic_investigation_backfill import (
        SECURITY_HISTORY_EVENT_IDS,
        new_security_history_manifest,
        security_history_cohort_digest,
        select_security_history_targets,
    )

    assert SECURITY_HISTORY_EVENT_IDS == (
        4740, 4767, 4723, 4724, 4720, 4722, 4725, 4726, 4738, 4781,
        4728, 4729, 4732, 4733, 4756, 4757,
        4727, 4730, 4737, 4731, 4734, 4735, 4754, 4755, 4758, 4764,
        4624, 4625, 4771, 4776, 4719, 1102,
    )
    first = security_history_cohort_digest([(7, "a" * 64), (9, "b" * 64), (11, "c" * 64)])
    changed = security_history_cohort_digest([(7, "a" * 64), (9, "d" * 64), (11, "c" * 64)])
    assert first != changed

    class Cursor:
        sql = ""
        params = ()

        def execute(self, sql, params=()):
            self.sql = " ".join(sql.lower().split())
            self.params = params

        def fetchall(self):
            return [{"id": 7}]

    cur = Cursor()
    assert select_security_history_targets(
        cur, event_id=1102, after_id=0, high_watermark=9, limit=999,
    ) == (7,)
    assert "provider.value=%s" in cur.sql
    assert "Microsoft-Windows-Eventlog" in cur.params
    assert cur.params[-1] == 999

    manifest = new_security_history_manifest(
        database_identity={"host": "local", "database": "sli", "role": "owner"},
        plan_digest=sha256(b"plan").hexdigest(),
        cohorts={
            4740: {"high_watermark": 11, "count": 3, "cohort_digest": first, "min_id": 7, "max_id": 11},
            1102: {"high_watermark": 0, "count": 0, "cohort_digest": security_history_cohort_digest(()), "min_id": None, "max_id": None},
        },
    )
    assert manifest["manifest_type"] == "retained_security_events_vocabulary_v1"
    assert manifest["events"]["1102"]["state"] == "no_retained_events"
    rendered = json.dumps(manifest, sort_keys=True)
    assert '"source_event_ids"' not in rendered
    assert '"normalized_hashes"' not in rendered


def test_security_history_cohorts_stream_rows_without_materializing_retained_ids() -> None:
    """A retained cohort digest must consume bounded cursor pages, never fetchall()."""
    from server.sli.semantic.semantic_investigation_backfill import security_history_cohorts

    class Cursor:
        query = -1
        page = 0

        def execute(self, _sql, _params=()):
            self.query += 1
            self.page = 0

        def fetchmany(self, size):
            assert size == 256
            if self.query != 0 or self.page:
                return []
            self.page += 1
            return [
                {"id": 7, "normalized_hash": "a" * 64},
                {"id": 9, "normalized_hash": "b" * 64},
            ]

        def fetchall(self):
            raise AssertionError("retained cohort selector must stream with fetchmany")

    cohorts = security_history_cohorts(Cursor())

    assert cohorts[4740] == {
        "high_watermark": 9,
        "count": 2,
        "cohort_digest": "3f79137b4ce393198ac9c652dd4e5291966c6ff74db26bf4782e5a117e01dd4f",
        "min_id": 7,
        "max_id": 9,
    }
    assert cohorts[1102]["count"] == 0


def test_security_history_manifest_keeps_its_frozen_batch_limit_across_versions() -> None:
    """New plans use the producer bound while a 100-row legacy plan stays resumable."""
    from server.sli.semantic.semantic_investigation_backfill import (
        new_security_history_manifest,
        security_history_cohort_digest,
        validate_security_history_manifest,
    )

    identity = {"host": "local", "database": "sli", "role": "owner"}
    cohorts = {
        4740: {
            "high_watermark": 7, "count": 1,
            "cohort_digest": security_history_cohort_digest([(7, "a" * 64)]),
            "min_id": 7, "max_id": 7,
        },
    }
    plan_digest = sha256(b"batch-limit").hexdigest()

    current = new_security_history_manifest(
        database_identity=identity, plan_digest=plan_digest, cohorts=cohorts,
    )
    legacy = new_security_history_manifest(
        database_identity=identity, plan_digest=plan_digest, cohorts=cohorts,
        batch_limit=100,
    )

    assert current["batch_limit"] == 5000
    assert legacy["batch_limit"] == 100
    validate_security_history_manifest(
        legacy, database_identity=identity, cohorts=None, plan_digest=plan_digest,
    )


def test_security_history_v2_supersede_keeps_raw_4624_coverage_but_scopes_semantics_to_exact_context() -> None:
    """A versioned replacement must not turn routine logons into semantic work."""
    from server.sli.semantic.semantic_investigation_backfill import (
        SECURITY_HISTORY_MANIFEST_TYPE_V2,
        SECURITY_HISTORY_MANIFEST_TYPE_V1,
        SECURITY_HISTORY_SUPERSEDE_REASON,
        new_security_history_manifest_v1,
        new_security_history_manifest_v2,
        security_history_cohort_digest,
        validate_security_history_manifest,
    )

    identity = {"host": "local", "database": "sli", "role": "owner"}
    cohorts = {
        4624: {
            "high_watermark": 9, "count": 3,
            "cohort_digest": security_history_cohort_digest([
                (7, "a" * 64), (8, "b" * 64), (9, "c" * 64),
            ]),
            "min_id": 7, "max_id": 9,
        },
        4724: {
            "high_watermark": 6, "count": 1,
            "cohort_digest": security_history_cohort_digest([(6, "d" * 64)]),
            "min_id": 6, "max_id": 6,
        },
    }
    legacy = new_security_history_manifest_v1(
        database_identity=identity, plan_digest=sha256(b"legacy").hexdigest(),
        cohorts=cohorts, batch_limit=100,
    )
    replacement = new_security_history_manifest_v2(
        database_identity=identity, plan_digest=sha256(b"replacement").hexdigest(),
        cohorts=cohorts,
        semantic_context_cohort={
            "count": 1,
            "cohort_digest": security_history_cohort_digest([(8, "b" * 64)]),
            "reset_high_watermark": 6,
        },
        supersedes={
            "manifest_type": SECURITY_HISTORY_MANIFEST_TYPE_V1,
            "plan_digest": legacy["plan_digest"],
            "reason": SECURITY_HISTORY_SUPERSEDE_REASON,
        },
    )

    assert legacy["manifest_type"] == SECURITY_HISTORY_MANIFEST_TYPE_V1
    assert replacement["manifest_type"] == SECURITY_HISTORY_MANIFEST_TYPE_V2
    assert replacement["batch_limit"] == 5000
    assert replacement["supersedes"]["plan_digest"] == legacy["plan_digest"]
    logons = replacement["events"]["4624"]
    assert logons["raw_retained_count"] == 3
    assert logons["semantic_scope"] == "password_reset_context_only"
    assert logons["semantic_expected_count"] == 1
    assert logons["count"] == 1
    validate_security_history_manifest(
        replacement, database_identity=identity, cohorts=None,
        plan_digest=sha256(b"replacement").hexdigest(),
    )
    with pytest.raises(RuntimeError, match="supersedes"):
        replacement["supersedes"]["reason"] = "silent"
        validate_security_history_manifest(
            replacement, database_identity=identity, cohorts=None,
            plan_digest=sha256(b"replacement").hexdigest(),
        )
    replacement["supersedes"]["reason"] = SECURITY_HISTORY_SUPERSEDE_REASON
    replacement["events"]["4624"]["semantic_context_reset_high_watermark"] = 5
    with pytest.raises(RuntimeError, match="logon context coverage"):
        validate_security_history_manifest(
            replacement, database_identity=identity, cohorts=None,
            plan_digest=sha256(b"replacement").hexdigest(),
        )


def test_security_history_context_selector_binds_frozen_reset_boundary_before_limit() -> None:
    """A later reset cannot change a frozen 4624 context cohort or page it in."""
    from server.sli.semantic.semantic_investigation_backfill import select_security_history_context_targets

    class Cursor:
        sql = ""
        params: tuple[object, ...] = ()
        page = 0

        def execute(self, sql: str, params: tuple[object, ...]) -> None:
            self.sql = sql
            self.params = params

        def fetchmany(self, _size: int):
            self.page += 1
            return ([{
                "source_event_id": 8, "normalized_hash": "a" * 64,
                "login_target_user_sid": "S-1-5-21-100-200-300-400",
                "reset_target_user_sid": "S-1-5-21-100-200-300-400",
                "reset_keywords": "0x0020000000000000",
            }] if self.page == 1 else [])

    cur = Cursor()
    assert select_security_history_context_targets(
        cur, after_id=7, high_watermark=99, reset_high_watermark=55, limit=5000,
    ) == (8,)
    assert "reset_event.id<=%s" in cur.sql
    assert cur.params[:8] == (
        "Security", "Microsoft-Windows-Security-Auditing", [4724], 55,
        "Security", "Microsoft-Windows-Security-Auditing", 7, 99,
    )
    assert len(cur.params) == 11
    assert "limit %s" not in cur.sql


def test_security_history_context_reconciliation_finishes_stream_before_chunked_aggregate() -> None:
    """A >5000 eligible cohort cannot lose later rows when the cursor is reused."""
    from server.sli.semantic.semantic_investigation_backfill import reconcile_security_history_context_event

    class Cursor:
        def __init__(self) -> None:
            self.rows = [
                {"source_event_id": source_id, "normalized_hash": "a" * 64,
                 "login_target_user_sid": "S-1-5-21-100-200-300-400",
                 "reset_target_user_sid": "S-1-5-21-100-200-300-400",
                 "reset_keywords": "0x0020000000000000"}
                for source_id in range(1, 5002)
            ]
            self.offset = 0
            self.aggregate_ids: list[list[int]] = []
            self.aggregate = False

        def execute(self, sql: str, params: tuple[object, ...]) -> None:
            self.aggregate = "where core.id=any(%s)" in sql
            if self.aggregate:
                self.aggregate_ids.append(list(params[-1]))

        def fetchmany(self, size: int):
            if self.aggregate:
                raise AssertionError("aggregate must start only after source stream finishes")
            page = self.rows[self.offset:self.offset + size]
            self.offset += len(page)
            return page

        def fetchone(self):
            count = len(self.aggregate_ids[-1])
            return {
                "retained_count": count, "normalized_count": count,
                "normalization_failed": 0, "normalization_quarantined": 0,
                "outbox_queued": 0, "outbox_leased": 0, "outbox_completed": count,
                "outbox_failed": 0, "outbox_quarantined": 0,
                "action_evidence_count": count,
            }

    cur = Cursor()
    result = reconcile_security_history_context_event(
        cur, high_watermark=6000, reset_high_watermark=6000,
    )

    assert cur.offset == 5001
    assert [len(ids) for ids in cur.aggregate_ids] == [5000, 1]
    assert result["retained_count"] == 5001
    assert result["normalized_count"] == 5001


@pytest.mark.parametrize("repair_status,has_normalized,expected", [
    (None, False, "absent"),
    ("queued", False, "queued"),
    ("leased", False, "leased"),
    ("completed", True, "completed"),
    ("failed", False, "failed"),
    ("quarantined", False, "quarantined"),
    ("completed", False, "conflict"),
    ("queued", True, "conflict"),
])
def test_security_history_v2_repair_row_requires_bound_terminal_repair_and_current_proof(
    repair_status: str | None, has_normalized: bool, expected: str,
) -> None:
    """Only a completed, proof-bound v2 job can reconcile a quarantined original."""
    from server.sli.semantic.semantic_investigation_backfill import classify_security_history_v2_repair_row

    row = {
        "source_event_id": 260,
        "source_hash": "a" * 64,
        "original_job_count": 1,
        "original_job_id": "12345678-1234-5678-1234-567812345678",
        "original_status": "quarantined",
        "original_attempt_count": 5,
        "original_max_attempts": 5,
        "original_error_code": "UniqueViolation",
        "original_error_detail": 'duplicate key value violates unique constraint "canonical_actions_pkey"',
        "original_error_detail_sha256": "b" * 64,
        "original_source_hash": "a" * 64,
        "repair_job_count": 0 if repair_status is None else 1,
        "repair_status": repair_status,
        "repair_processor_id": PROCESSOR_ID,
        "repair_processor_version": PROCESSOR_VERSION,
        "repair_source_hash": "a" * 64,
        "repair_payload_source_hash": "a" * 64,
        "repair_semantic_contract_version": SEMANTIC_CONTRACT_VERSION,
        "repair_original_job_id": "12345678-1234-5678-1234-567812345678",
        "repair_history_plan_digest": "c" * 64,
        "repair_plan_digest": "d" * 64,
        "repair_original_attempt_count": 5,
        "repair_original_max_attempts": 5,
        "repair_original_error_code": "UniqueViolation",
        "repair_original_error_detail_sha256": "b" * 64,
        "normalized_current_count": 1 if has_normalized else 0,
        "normalized_proof_count": 1 if has_normalized else 0,
        "normalized_proof_hash": "a" * 64 if has_normalized else None,
        "normalized_action_count": 1 if has_normalized else 0,
    }

    assert classify_security_history_v2_repair_row(
        row, source_hash="a" * 64, history_plan_digest="c" * 64,
    ) == expected


def test_security_history_v2_repair_row_rejects_duplicate_or_mismatched_binding() -> None:
    from server.sli.semantic.semantic_investigation_backfill import classify_security_history_v2_repair_row

    row = {
        "source_event_id": 260,
        "source_hash": "a" * 64,
        "original_job_count": 1,
        "original_job_id": "12345678-1234-5678-1234-567812345678",
        "original_status": "quarantined",
        "original_attempt_count": 5,
        "original_max_attempts": 5,
        "original_error_code": "UniqueViolation",
        "original_error_detail": 'duplicate key value violates unique constraint "canonical_actions_pkey"',
        "original_error_detail_sha256": "b" * 64,
        "original_source_hash": "a" * 64,
        "repair_job_count": 2,
        "repair_status": "completed",
        "repair_processor_id": PROCESSOR_ID,
        "repair_processor_version": PROCESSOR_VERSION,
        "repair_source_hash": "a" * 64,
        "repair_payload_source_hash": "a" * 64,
        "repair_semantic_contract_version": SEMANTIC_CONTRACT_VERSION,
        "repair_original_job_id": "12345678-1234-5678-1234-567812345678",
        "repair_history_plan_digest": "c" * 64,
        "repair_plan_digest": "d" * 64,
        "repair_original_attempt_count": 5,
        "repair_original_max_attempts": 5,
        "repair_original_error_code": "UniqueViolation",
        "repair_original_error_detail_sha256": "b" * 64,
        "normalized_current_count": 1,
        "normalized_proof_count": 1,
        "normalized_proof_hash": "a" * 64,
        "normalized_action_count": 1,
    }

    assert classify_security_history_v2_repair_row(
        row, source_hash="a" * 64, history_plan_digest="c" * 64,
    ) == "conflict"
    row["repair_job_count"] = 1
    row["repair_original_job_id"] = "not-the-original"
    assert classify_security_history_v2_repair_row(
        row, source_hash="a" * 64, history_plan_digest="c" * 64,
    ) == "conflict"
    row["repair_original_job_id"] = "12345678-1234-5678-1234-567812345678"
    row["repair_payload_source_hash"] = "b" * 64
    assert classify_security_history_v2_repair_row(
        row, source_hash="a" * 64, history_plan_digest="c" * 64,
    ) == "conflict"
    row["repair_payload_source_hash"] = "a" * 64
    row["repair_semantic_contract_version"] = SEMANTIC_CONTRACT_VERSION + 1
    assert classify_security_history_v2_repair_row(
        row, source_hash="a" * 64, history_plan_digest="c" * 64,
    ) == "conflict"


def test_security_history_v2_context_reconciliation_queries_exact_selected_repair_lineage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from server.sli.semantic import semantic_investigation_backfill as backfill

    current = {
        "retained_count": 1, "normalized_count": 1,
        "normalization_failed": 0, "normalization_quarantined": 0,
        "outbox_queued": 0, "outbox_leased": 0, "outbox_completed": 1,
        "outbox_failed": 0, "outbox_quarantined": 1, "action_evidence_count": 1,
    }
    detail = 'duplicate key value violates unique constraint "canonical_actions_pkey"'
    monkeypatch.setattr(backfill, "_iter_security_history_context_pairs", lambda *_args, **_kwargs: iter(((260, "a" * 64),)))
    monkeypatch.setattr(backfill, "reconcile_security_history_context_event", lambda *_args, **_kwargs: current)

    class Cursor:
        sql = ""
        params: tuple[object, ...] = ()

        def execute(self, sql: str, params: tuple[object, ...]) -> None:
            self.sql = sql
            self.params = params

        def fetchall(self) -> list[dict[str, object]]:
            return [{
                "source_event_id": 260, "source_hash": "a" * 64,
                "original_job_count": 1, "original_job_id": "12345678-1234-5678-1234-567812345678",
                "original_status": "quarantined", "original_attempt_count": 5,
                "original_max_attempts": 5, "original_error_code": "UniqueViolation",
                "original_error_detail": detail, "original_source_hash": "a" * 64,
                "repair_job_count": 1, "repair_status": "completed",
                "repair_processor_id": PROCESSOR_ID, "repair_processor_version": PROCESSOR_VERSION,
                "repair_source_hash": "a" * 64,
                "repair_payload_source_hash": "a" * 64,
                "repair_semantic_contract_version": SEMANTIC_CONTRACT_VERSION,
                "repair_original_job_id": "12345678-1234-5678-1234-567812345678",
                "repair_history_plan_digest": "c" * 64, "repair_plan_digest": "d" * 64,
                "repair_original_attempt_count": "5", "repair_original_max_attempts": "5",
                "repair_original_error_code": "UniqueViolation",
                "repair_original_error_detail_sha256": sha256(detail.encode()).hexdigest(),
                "normalized_current_count": 1, "normalized_proof_count": 1,
                "normalized_proof_hash": "a" * 64,
                "normalized_action_count": 1,
            }]

    cur = Cursor()
    result = backfill.reconcile_security_history_v2_context_event(
        cur, high_watermark=300, reset_high_watermark=100, history_plan_digest="c" * 64,
    )

    assert result.current == current
    assert result.repair_states == {
        "absent": 0, "queued": 0, "leased": 0, "completed": 1,
        "failed": 0, "quarantined": 0, "conflict": 0,
    }
    assert "job_kind='semantic_v2_quarantine_repair'" in cur.sql
    assert cur.params[:2] == ([260], ["a" * 64])


def test_security_history_context_poll_selector_excludes_current_normalization_but_full_cohort_does_not() -> None:
    """The residual selector must not make the frozen eligible cohort shrink."""
    from server.sli.semantic.semantic_investigation_backfill import (
        security_history_context_cohort,
        select_security_history_context_targets,
    )

    class Cursor:
        def __init__(self) -> None:
            self.normalized_filter = False
            self.done = False

        def execute(self, sql: str, _params: tuple[object, ...]) -> None:
            self.normalized_filter = "from normalized_events normalized" in sql
            self.done = False

        def fetchmany(self, _size: int):
            if self.done:
                return []
            self.done = True
            return ([] if self.normalized_filter else [{
                "source_event_id": 8, "normalized_hash": "a" * 64,
                "login_target_user_sid": "S-1-5-21-100-200-300-400",
                "reset_target_user_sid": "S-1-5-21-100-200-300-400",
                "reset_keywords": "Audit Success",
            }])

    cur = Cursor()
    frozen = security_history_context_cohort(
        cur, high_watermark=9, reset_high_watermark=6,
    )
    residual = select_security_history_context_targets(
        cur, after_id=0, high_watermark=9, reset_high_watermark=6,
    )

    assert frozen["count"] == 1
    assert frozen["cohort_digest"] == "dcddd2043ede59dbf319e63e70277579ccbd5ae9ea2ef074e98181984e1687be"
    assert residual == ()


def test_security_history_context_iterator_rejects_noncanonical_sid_candidates() -> None:
    """The frozen cohort only digests rows that pass the shared exact-SID check."""
    from server.sli.semantic import semantic_investigation_backfill as backfill

    class Cursor:
        def execute(self, *_args, **_kwargs) -> None:
            return None

        def fetchmany(self, _size: int):
            if getattr(self, "done", False):
                return []
            self.done = True
            return [
                {
                    "source_event_id": 8, "normalized_hash": "a" * 64,
                    "login_target_user_sid": "S-1-5-21-100-200-300-400",
                    "reset_target_user_sid": "S-1-5-21-100-200-300-400",
                    "reset_keywords": "Audit Success",
                },
                {
                    "source_event_id": 9, "normalized_hash": "b" * 64,
                    "login_target_user_sid": "S-1-5-21-100-200-300-400 ",
                    "reset_target_user_sid": "S-1-5-21-100-200-300-400 ",
                    "reset_keywords": "Audit Success",
                },
                {
                    "source_event_id": 10, "normalized_hash": "c" * 64,
                    "login_target_user_sid": "S-1-5-21-100-200-300-400",
                    "reset_target_user_sid": "s-1-5-21-100-200-300-400",
                    "reset_keywords": "Audit Success",
                },
            ]

    assert tuple(backfill._iter_security_history_context_pairs(
        Cursor(), after_id=0, high_watermark=10, reset_high_watermark=7,
    )) == ((8, "a" * 64),)


def test_security_history_manifest_rejects_illegal_progress_state_and_mutated_plan_digest() -> None:
    """A local checkpoint cannot skip retained work through an invented state or plan."""
    from server.sli.semantic.semantic_investigation_backfill import (
        new_security_history_manifest,
        security_history_cohort_digest,
        validate_security_history_manifest,
    )

    identity = {"host": "local", "database": "sli", "role": "owner"}
    cohorts = {
        4740: {
            "high_watermark": 9,
            "count": 2,
            "cohort_digest": security_history_cohort_digest([(7, "a" * 64), (9, "b" * 64)]),
            "min_id": 7,
            "max_id": 9,
        },
    }
    expected_plan_digest = sha256(b"frozen-plan").hexdigest()
    manifest = new_security_history_manifest(
        database_identity=identity, plan_digest=expected_plan_digest, cohorts=cohorts,
    )

    manifest["events"]["4740"]["state"] = "not-a-real-progress-state"
    with pytest.raises(RuntimeError, match="state"):
        validate_security_history_manifest(
            manifest, database_identity=identity, cohorts={**cohorts},
            plan_digest=expected_plan_digest,
        )

    manifest["events"]["4740"]["state"] = "planned"
    manifest["plan_digest"] = "b" * 64
    with pytest.raises(RuntimeError, match="immutable contract"):
        validate_security_history_manifest(
            manifest, database_identity=identity, cohorts={**cohorts},
            plan_digest=expected_plan_digest,
        )


@pytest.mark.parametrize(
    ("event_id", "count", "state", "reason", "invalid_reason"),
    (
        (4740, 2, "planned", None, "must-not-be-terminal"),
        (4740, 2, "publishing", None, "must-not-be-terminal"),
        (4740, 2, "queued", None, "must-not-be-terminal"),
        (4740, 2, "processing", None, "must-not-be-terminal"),
        (4740, 2, "complete", "current_version_normalized_hash_reconciled", None),
        (1102, 0, "no_retained_events", "no_retained_events", "wrong-reason"),
        (4740, 2, "incomplete_original", "frozen_original_integrity_mismatch", None),
        (4740, 2, "incomplete_normalization", "current_version_non_unknown_normalization_missing", None),
        (4740, 2, "blocked", "operator_blocked_after_evidence", "wrong-blocked-reason"),
        (4740, 2, "failed", "failed_current_version_work", None),
        (4740, 2, "quarantined", "quarantined_current_version_work", None),
    ),
)
def test_security_history_manifest_accepts_only_evidence_bound_state_reasons(
    event_id: int, count: int, state: str, reason: str | None, invalid_reason: str | None,
) -> None:
    """Progress has no conclusion; exceptional/terminal state needs its evidence reason."""
    from server.sli.semantic.semantic_investigation_backfill import (
        new_security_history_manifest,
        security_history_cohort_digest,
        validate_security_history_manifest,
    )

    identity = {"host": "local", "database": "sli", "role": "owner"}
    cohorts = {
        4740: {
            "high_watermark": 9, "count": 2,
            "cohort_digest": security_history_cohort_digest([(7, "a" * 64), (9, "b" * 64)]),
            "min_id": 7, "max_id": 9,
        },
        1102: {
            "high_watermark": 0, "count": 0,
            "cohort_digest": security_history_cohort_digest(()),
            "min_id": None, "max_id": None,
        },
    }
    manifest = new_security_history_manifest(
        database_identity=identity, plan_digest=sha256(b"state-contract").hexdigest(), cohorts=cohorts,
    )
    entry = manifest["events"][str(event_id)]
    assert int(entry["count"]) == count
    entry["state"] = state
    entry["terminal_reason"] = reason

    validate_security_history_manifest(
        manifest, database_identity=identity, cohorts=cohorts,
        plan_digest=sha256(b"state-contract").hexdigest(),
    )

    entry["terminal_reason"] = invalid_reason
    with pytest.raises(RuntimeError, match="reason"):
        validate_security_history_manifest(
            manifest, database_identity=identity, cohorts=cohorts,
            plan_digest=sha256(b"state-contract").hexdigest(),
        )

def test_investigation_backfill_uses_only_accepted_exact_relation_rules() -> None:
    from server.sli.semantic.semantic_investigation_backfill import (
        INVESTIGATION_RULE_IDS,
        INVESTIGATION_CONTEXT_WINDOWS_EVENT_IDS,
        INVESTIGATION_SOURCE_WINDOWS_EVENT_IDS,
        selected_investigation_rules,
    )

    rules = selected_investigation_rules(Path("config/semantic_chain_pack_v1.json"))

    assert tuple(rule.rule_id for rule in rules) == INVESTIGATION_RULE_IDS
    assert all(rule.rule_id.startswith("investigation.") for rule in rules)
    assert "auth.session.lifecycle" not in INVESTIGATION_RULE_IDS
    assert INVESTIGATION_SOURCE_WINDOWS_EVENT_IDS == (
        4625, 4720, 4724, 4728, 4729, 4732, 4733, 4740, 4756, 4757, 4767,
    )
    assert "investigation.password.reset-then-logon" in INVESTIGATION_RULE_IDS
    assert INVESTIGATION_CONTEXT_WINDOWS_EVENT_IDS == (4624,)


def test_investigation_control_accepts_explicit_dpapi_environment_without_printing_secrets() -> None:
    source = Path("scripts/maintenance/semantic_investigation_control.py").read_text(encoding="utf-8")
    assert '"--environment-file"' in source
    assert "load_supervisor_environment(" in source
    assert "override_existing=True" in source
    assert "ADLOG_PG_ADMIN_PASSWORD" not in source
    assert '"--max-polls"' in source
    assert '"--plan-digest"' in source
    assert '"quarantine-plan"' in source
    assert '"quarantine-recover"' in source
    assert 'if payload.get("status") in {"complete", "blocked_batch"}' in source


def test_dispatch_quarantine_recovery_is_exact_bounded_and_auditable() -> None:
    from server.sli.semantic.semantic_investigation_backfill import (
        investigation_quarantine_recovery_candidates,
        investigation_quarantine_recovery_digest,
        investigation_rule_identities,
        recover_investigation_quarantined_dispatch_jobs,
    )

    frozen = "2026-09-14T09:00:00+00:00"
    identity = investigation_rule_identities()[
        "investigation.account.unlock.after-lock"
    ]
    rows = [{
        "job_id": "00000000-0000-0000-0000-000000000001",
        "normalized_event_id": "10000000-0000-0000-0000-000000000001",
        "source_event_id": 123,
        "normalized_at": frozen,
        "rule_id": "investigation.account.unlock.after-lock",
        "rule_version": identity["rule_version"],
        "definition_sha256": identity["definition_sha256"],
        "dispatch_status": "quarantined",
        "attempt_count": 5,
        "max_attempts": 5,
        "last_error_code": "InsufficientPrivilege",
        "last_error_detail": "permission denied for table semantic_correlation_rules",
    }]

    class Cursor:
        def __init__(self) -> None:
            self.sql = ""
            self.params = ()
            self.returning = False

        def execute(self, sql, params=()):
            self.sql = " ".join(sql.lower().split())
            self.params = params
            self.returning = self.sql.startswith(
                "update semantic_correlation_dispatch_jobs"
            )

        def fetchall(self):
            if self.returning:
                return [{"job_id": rows[0]["job_id"]}]
            return rows

    cur = Cursor()
    candidates = investigation_quarantine_recovery_candidates(
        cur,
        frozen_normalized_at=frozen,
        high_watermark_source_event_id=123,
        for_update=True,
    )
    assert candidates == tuple(rows)
    assert "dispatch_status='quarantined'" in cur.sql
    assert "last_error_code=%s" in cur.sql
    assert "for update of job" in cur.sql
    assert "%semantic_correlation_rules%" in cur.params
    digest = investigation_quarantine_recovery_digest(
        candidates,
        database_identity={"host": "local", "database": "sli", "role": "owner"},
        frozen_normalized_at=frozen,
        high_watermark_source_event_id=123,
    )
    assert len(digest) == 64

    recovered = recover_investigation_quarantined_dispatch_jobs(
        cur,
        expected_digest=digest,
        database_identity={"host": "local", "database": "sli", "role": "owner"},
        frozen_normalized_at=frozen,
        high_watermark_source_event_id=123,
    )
    assert recovered == (rows[0]["job_id"],)
    assert "dispatch_status='failed'" in cur.sql
    assert "attempt_count=max_attempts-1" in cur.sql
    assert "last_error_code=null" not in cur.sql
    assert "last_error_detail=null" not in cur.sql


def test_dispatch_quarantine_recovery_rejects_changed_candidate_set() -> None:
    from server.sli.semantic.semantic_investigation_backfill import (
        recover_investigation_quarantined_dispatch_jobs,
    )

    class Cursor:
        sql = ""

        def execute(self, sql, params=()):
            self.sql = " ".join(sql.lower().split())

        def fetchall(self):
            return []

    with pytest.raises(RuntimeError, match="candidate set changed"):
        recover_investigation_quarantined_dispatch_jobs(
            Cursor(),
            expected_digest="0" * 64,
            database_identity={"host": "local", "database": "sli", "role": "owner"},
            frozen_normalized_at="2026-09-14T09:00:00+00:00",
            high_watermark_source_event_id=123,
        )


def test_quarantine_recovery_refuses_enabled_semantic_before_database_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scripts.maintenance import semantic_investigation_control as control

    digest = "1" * 64
    monkeypatch.setattr(control, "_load_environment", lambda: None)
    monkeypatch.setattr(
        control,
        "_connect_admin",
        lambda: (_ for _ in ()).throw(AssertionError("database must not be opened")),
    )
    monkeypatch.setenv("ADLOG_SEMANTIC_PRODUCTION_ENABLED", "1")
    monkeypatch.setenv("ADLOG_SEMANTIC_RUNTIME_MODE", "investigation-v1")

    with pytest.raises(RuntimeError, match="must be disabled"):
        control.quarantine_recover(
            plan_digest=digest,
            confirmation=control._recovery_confirmation(digest),
        )


def test_quarantine_recovery_confirmation_is_bound_to_plan_digest() -> None:
    from scripts.maintenance import semantic_investigation_control as control

    first = control._recovery_confirmation("1" * 64)
    second = control._recovery_confirmation("2" * 64)

    assert first != second
    assert first == "RECOVER-INVESTIGATION-DISPATCH-1111111111111111"


def test_activate_checks_migration_before_worker_role_and_activates_rules(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The admin-only migration ledger check precedes the worker-role switch."""
    from scripts.maintenance import semantic_investigation_control as control

    class Cursor:
        def __init__(self) -> None:
            self.worker_role = False
            self.queries: list[str] = []

        def execute(self, query: str, params: object = None) -> None:
            del params
            normalized = " ".join(query.lower().split())
            self.queries.append(normalized)
            if normalized.startswith("set local role adlog_storage_worker"):
                self.worker_role = True
            if "from schema_migrations" in normalized and self.worker_role:
                raise AssertionError("migration ledger queried after worker role switch")

        def fetchone(self) -> dict[str, bool]:
            return {"ready": True}

    class Connection:
        def __init__(self, cursor: Cursor) -> None:
            self.cursor_value = cursor

        def __enter__(self) -> "Connection":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        @contextmanager
        def transaction(self):
            yield

        @contextmanager
        def cursor(self):
            yield self.cursor_value

    cursor = Cursor()
    conn = Connection(cursor)
    activated: list[bool] = []
    monkeypatch.setattr(control, "_load_environment", lambda: None)
    monkeypatch.setattr(control, "_settings", lambda: object())
    monkeypatch.setattr(control, "_connect_admin", lambda: conn)
    monkeypatch.setattr(
        control,
        "activate_investigation_rules",
        lambda cur: activated.append(not cur.worker_role) or [{"status": "shadow"}],
    )

    result = control.activate()

    assert result["status"] == "investigation_rules_shadow"
    assert activated == [False]
    migration_query = next(query for query in cursor.queries if "schema_migrations" in query)
    assert "version=138" in migration_query
    assert "name='normalized_event_versioned_identity'" in migration_query
    assert cursor.queries.index(migration_query) < cursor.queries.index(
        "set local role adlog_storage_worker"
    )


def test_investigation_checkpoint_freezes_range_rules_and_progress() -> None:
    from server.sli.semantic.semantic_investigation_backfill import (
        new_investigation_checkpoint,
        validate_investigation_checkpoint,
    )

    checkpoint = new_investigation_checkpoint(high_watermark=1900000, fingerprint="a" * 64)
    validate_investigation_checkpoint(checkpoint, fingerprint="a" * 64)
    assert checkpoint["frozen_high_watermark_source_event_id"] == 1900000
    assert checkpoint["last_committed_source_event_id"] == 0
    assert checkpoint["source"] == "normalized_events"
    assert checkpoint["facts_contract"]["normalizer_id"]
    assert checkpoint["frozen_normalized_at"]
    assert checkpoint["moves_collection_cursors"] is False

    with pytest.raises(RuntimeError, match="fingerprint"):
        validate_investigation_checkpoint(checkpoint, fingerprint="b" * 64)


def test_backfill_targets_are_bounded_ordered_and_require_retained_source_proof() -> None:
    from server.sli.semantic.semantic_investigation_backfill import select_investigation_targets

    class Cursor:
        sql = ""
        params = ()

        def execute(self, sql, params=()):
            self.sql = " ".join(sql.lower().split())
            self.params = params

        def fetchall(self):
            return [{"normalized_event_id": "n-1", "source_event_id": 11}]

    cur = Cursor()
    assert select_investigation_targets(cur, after_id=10, high_watermark=99, limit=999) == [
        {"normalized_event_id": "n-1", "source_event_id": 11},
    ]
    assert "from normalized_events" in cur.sql
    assert "join events_v2_core source_event" in cur.sql
    assert "source_event.event_id=source_contract.event_id" in cur.sql
    assert "join events_v2_core reset_source_event" in cur.sql
    assert "reset_source_event.event_id=%s" in cur.sql
    assert 4724 in cur.params
    assert "order by normalized_events.source_event_id" in cur.sql
    assert cur.params[-1] == 100
    assert "normalizer_id=%s" in cur.sql
    assert "normalized_at<=%s" in cur.sql
    assert "normalized_events.semantic_type<>'authentication.session.created'" in cur.sql
    assert "reset.semantic_type='account.password.reset.succeeded'" in cur.sql
    assert "normalized_events.facts_json->>'relation_account_sid'" in cur.sql


def test_backfill_targets_qualify_all_outer_normalized_event_predicates() -> None:
    from server.sli.semantic.semantic_investigation_backfill import select_investigation_targets

    class PostgreSQLBoundaryCursor:
        def execute(self, sql, params=()):
            normalized_sql = " ".join(sql.lower().split())
            ambiguous_outer_predicates = (
                " and semantic_contract_version=%s ",
                " and normalizer_id=%s ",
                " and normalizer_version=%s ",
                " and source_event_id>%s ",
                " and source_event_id<=%s ",
                " and semantic_type=any(%s) ",
            )
            if any(predicate in normalized_sql for predicate in ambiguous_outer_predicates):
                raise RuntimeError("AmbiguousColumn: column semantic_type is ambiguous")

        def fetchall(self):
            return []

    assert select_investigation_targets(
        PostgreSQLBoundaryCursor(),
        after_id=0,
        high_watermark=1,
        frozen_normalized_at="2026-09-11T00:00:00+00:00",
    ) == []


def test_investigation_fact_targets_use_only_frozen_retained_event_ids() -> None:
    from server.sli.semantic.semantic_investigation_backfill import (
        INVESTIGATION_SOURCE_WINDOWS_EVENT_IDS,
        select_investigation_fact_targets,
    )

    class Cursor:
        sql = ""
        params = ()

        def execute(self, sql, params=()):
            self.sql = " ".join(sql.lower().split())
            self.params = params

        def fetchall(self):
            return [{"id": 17}, {"id": 19}]

    cur = Cursor()
    assert select_investigation_fact_targets(
        cur, after_id=10, high_watermark=99, limit=999,
    ) == (17, 19)
    assert "from events_v2_core" in cur.sql
    assert "event_id=any" in cur.sql
    assert "order by id" in cur.sql
    assert cur.params == (
        10, 99, list(INVESTIGATION_SOURCE_WINDOWS_EVENT_IDS), 100,
    )


def test_investigation_context_targets_select_only_exact_logons_after_proven_reset() -> None:
    from server.sli.semantic.semantic_investigation_backfill import select_investigation_fact_targets

    class Cursor:
        sql = ""
        params = ()

        def execute(self, sql, params=()):
            self.sql = " ".join(sql.lower().split())
            self.params = params

        def fetchall(self):
            return [{"id": 31}]

    cur = Cursor()
    assert select_investigation_fact_targets(
        cur, after_id=10, high_watermark=99, limit=999, phase="context",
    ) == (31,)
    assert "reset.semantic_type='account.password.reset.succeeded'" in cur.sql
    assert "reset_event.event_id=%s" in cur.sql
    assert 4724 in cur.params
    assert "login.event_id=any" in cur.sql
    assert "login.target_user_sid" in cur.sql
    assert "reset_event.target_user_sid" in cur.sql
    assert "relation_account_identity" in cur.sql
    assert "interval '1 hour'" in cur.sql
    assert "order by login.id" in cur.sql
    assert cur.params[-1] == 100


def test_investigation_facts_checkpoint_is_frozen_and_source_isolated() -> None:
    from server.sli.semantic.semantic_investigation_backfill import (
        new_investigation_facts_checkpoint,
        validate_investigation_facts_checkpoint,
    )

    checkpoint = new_investigation_facts_checkpoint(
        high_watermark=99, fingerprint="a" * 64,
    )
    validate_investigation_facts_checkpoint(checkpoint, fingerprint="a" * 64)
    assert checkpoint["frozen_high_watermark_event_id"] == 99
    assert checkpoint["last_committed_event_id"] == 0
    assert checkpoint["contacts_sources"] is False
    assert checkpoint["moves_collection_cursors"] is False
    assert checkpoint["phase"] == "anchors"
    assert checkpoint["context_windows_event_ids"] == [4624]
    assert checkpoint["source_event_ids_by_semantic_type"]["authentication.session.created"] == [4624]


def test_facts_checkpoint_runs_anchors_then_context_before_completion() -> None:
    from scripts.maintenance import semantic_investigation_control as control
    from server.sli.semantic.semantic_investigation_backfill import new_investigation_facts_checkpoint

    checkpoint = new_investigation_facts_checkpoint(
        high_watermark=99, fingerprint="a" * 64,
    )
    control._advance_facts_checkpoint(
        checkpoint, phase="anchors", targets=(), high_watermark=99,
    )
    assert checkpoint["phase"] == "context"
    assert checkpoint["last_committed_event_id"] == 0
    assert checkpoint["status"] == "active"

    control._advance_facts_checkpoint(
        checkpoint, phase="context", targets=(), high_watermark=99,
    )
    assert checkpoint["phase"] == "context"
    assert checkpoint["last_committed_event_id"] == 99
    assert checkpoint["status"] == "complete"


def test_completed_facts_checkpoint_rolls_forward_without_reprocessing_old_range() -> None:
    from scripts.maintenance import semantic_investigation_control as control
    from server.sli.semantic.semantic_investigation_backfill import new_investigation_facts_checkpoint

    checkpoint = new_investigation_facts_checkpoint(
        high_watermark=99, fingerprint="a" * 64,
    )
    checkpoint.update({
        "status": "complete",
        "phase": "context",
        "last_committed_event_id": 99,
        "database_identity": {
            "host": "127.0.0.1",
            "database": "sli_local",
            "role": "postgres",
        },
    })

    resumed = control._resume_facts_checkpoint_for_snapshot(
        checkpoint,
        snapshot={
            "database_identity": checkpoint["database_identity"],
            "retained_fact_high_watermark_event_id": 123,
        },
        fingerprint="a" * 64,
    )

    assert resumed is not checkpoint
    assert resumed["status"] == "active"
    assert resumed["phase"] == "anchors"
    assert resumed["range_start_event_id"] == 100
    assert resumed["last_committed_event_id"] == 99
    assert resumed["frozen_high_watermark_event_id"] == 123
    assert resumed["completed_ranges"] == [{"start": 1, "end": 99}]

    control._advance_facts_checkpoint(
        resumed, phase="anchors", targets=(), high_watermark=123,
    )
    assert resumed["phase"] == "context"
    assert resumed["last_committed_event_id"] == 99


def test_completed_relation_checkpoint_rolls_forward_to_new_frozen_snapshot() -> None:
    from scripts.maintenance import semantic_investigation_control as control
    from server.sli.semantic.semantic_investigation_backfill import new_investigation_checkpoint

    checkpoint = new_investigation_checkpoint(
        high_watermark=88,
        fingerprint="b" * 64,
        frozen_normalized_at="2026-09-12T20:00:00+00:00",
    )
    checkpoint.update({
        "status": "complete",
        "last_committed_source_event_id": 88,
        "database_identity": {
            "host": "127.0.0.1",
            "database": "sli_local",
            "role": "postgres",
        },
    })

    resumed = control._resume_relation_checkpoint_for_snapshot(
        checkpoint,
        snapshot={
            "database_identity": checkpoint["database_identity"],
            "high_watermark_source_event_id": 120,
            "frozen_normalized_at": "2026-09-13T00:00:00+00:00",
        },
        fingerprint="b" * 64,
    )

    assert resumed is not checkpoint
    assert resumed["status"] == "active"
    assert resumed["range_start_source_event_id"] == 89
    assert resumed["last_committed_source_event_id"] == 88
    assert resumed["frozen_high_watermark_source_event_id"] == 120
    assert resumed["frozen_normalized_at"] == "2026-09-13T00:00:00+00:00"
    assert resumed["completed_ranges"] == [{"start": 1, "end": 88}]


def test_rule_activation_stops_at_shadow_and_never_enables_findings(monkeypatch) -> None:
    from server.sli.semantic import semantic_investigation_backfill as backfill

    states = {rule_id: "draft" for rule_id in backfill.INVESTIGATION_RULE_IDS}
    transitions: list[tuple[str, str]] = []
    monkeypatch.setattr(backfill, "register_correlation_rule", lambda _cur, *, rule: None)
    monkeypatch.setattr(backfill, "replace_rule_subscriptions", lambda _cur, *, rule: None)
    monkeypatch.setattr(backfill, "retire_superseded_investigation_rule_versions", lambda *_args: None)
    monkeypatch.setattr(backfill, "_rule_status", lambda _cur, rule_id, _version: states[rule_id])

    def transition(_cur, *, rule_id, rule_version, target_status):
        expected_versions = backfill.investigation_rule_identities()
        assert rule_version == expected_versions[rule_id]["rule_version"]
        transitions.append((rule_id, target_status))
        states[rule_id] = target_status
        return target_status

    monkeypatch.setattr(backfill, "transition_correlation_rule", transition)
    monkeypatch.setattr(backfill, "_verify_rule_subscriptions", lambda *_args, **_kwargs: None)

    result = backfill.activate_investigation_rules(object(), Path("config/semantic_chain_pack_v1.json"))

    assert set(result.values()) == {"shadow"}
    assert all(status != "enabled" for _, status in transitions)
    assert [status for rule_id, status in transitions if rule_id == backfill.INVESTIGATION_RULE_IDS[0]] == ["validated", "test", "shadow"]


def test_retire_superseded_sequence_rule_keeps_old_definition_and_candidates() -> None:
    from server.sli.semantic import semantic_investigation_backfill as backfill
    from server.sli.semantic.semantic_correlation_repository import CorrelationRuleDefinition

    class Cursor:
        def execute(self, *_args, **_kwargs):
            return None

        def fetchall(self):
            return [{"rule_version": 1, "lifecycle_status": "shadow"}]

    transitions: list[tuple[int, str]] = []
    original = backfill.transition_correlation_rule
    try:
        backfill.transition_correlation_rule = lambda _cur, *, rule_id, rule_version, target_status: transitions.append((rule_version, target_status)) or target_status
        backfill.retire_superseded_investigation_rule_versions(
            Cursor(),
            CorrelationRuleDefinition(
                rule_id="investigation.password.reset-then-logon", rule_version=2,
                rule_kind="sequence", definition={
                    "type": "sequence",
                    "inputs": ["account.password.reset.succeeded", "authentication.session.created"],
                    "partition_kind": "domain_account_sid", "window_seconds": 3600,
                    "minimum_count": 2, "strict_time_order": True,
                    "continuation_policy": "anchor_all_admissible",
                    "output_relation_kind": "authentication.password_reset_followed_by_logon_observed",
                    "confidence": "medium", "explanation": "observed alternatives, not a causal claim",
                },
            ),
        )
    finally:
        backfill.transition_correlation_rule = original

    assert transitions == [(1, "deprecated")]


def test_readiness_rejects_an_extra_executable_version_of_an_accepted_rule() -> None:
    from scripts.maintenance import semantic_investigation_control as control

    identities = control.investigation_rule_identities()
    rows = [
        {
            "rule_id": rule_id,
            "rule_version": identity["rule_version"],
            "definition_sha256": identity["definition_sha256"],
            "lifecycle_status": "shadow",
        }
        for rule_id, identity in identities.items()
    ]
    assert control._rules_ready({"rules": rows})

    rows.append({
        "rule_id": next(iter(identities)),
        "rule_version": 999,
        "definition_sha256": "ff" * 32,
        "lifecycle_status": "test",
    })
    assert not control._rules_ready({"rules": rows})


@pytest.mark.parametrize("outbox_status", ["leased", "quarantined"])
def test_facts_completion_requires_current_terminal_fact_for_every_source(
    outbox_status: str,
) -> None:
    from scripts.maintenance import semantic_investigation_control as control

    class Cursor:
        sql = ""
        params = ()

        def execute(self, sql, params=()):
            self.sql = " ".join(sql.lower().split())
            self.params = params

        def fetchall(self):
            return [
                {
                    "source_event_id": 7,
                    "processing_status": "normalized",
                    "outbox_status": "completed",
                },
                {
                    "source_event_id": 8,
                    "processing_status": None,
                    "outbox_status": outbox_status,
                },
            ]

    cur = Cursor()
    state = control._facts_completion_state(cur, (7, 8))

    assert state["state"] == "pending"
    assert state["completed"] == 1
    assert state[outbox_status] == 1
    assert state["unresolved_event_ids"] == [8]
    assert "from unnest" in cur.sql
    assert "normalizer_id=%s" in cur.sql
    assert "processor_version=%s" in cur.sql


@pytest.mark.parametrize("outbox_status", ["leased", "quarantined"])
def test_facts_backfill_does_not_advance_checkpoint_for_unresolved_exact_job(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    outbox_status: str,
) -> None:
    from scripts.maintenance import semantic_investigation_control as control
    from server.sli.semantic.semantic_investigation_backfill import new_investigation_facts_checkpoint

    checkpoint_path = tmp_path / "facts-checkpoint.json"
    checkpoint = new_investigation_facts_checkpoint(
        high_watermark=10,
        fingerprint="a" * 64,
    )
    checkpoint["database_identity"] = {
        "host": "127.0.0.1",
        "database": "sli_local",
        "role": "candidate_owner",
    }
    checkpoint_path.write_text(json.dumps(checkpoint), encoding="utf-8")

    class Cursor:
        def execute(self, *_args, **_kwargs):
            return None

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        @contextmanager
        def cursor(self):
            yield Cursor()

    @contextmanager
    def held_lock(*_args, **_kwargs):
        yield True

    snapshot = {
        "database_identity": checkpoint["database_identity"],
        "retained_fact_high_watermark_event_id": 10,
    }
    monkeypatch.setattr(control, "FACTS_CHECKPOINT_PATH", checkpoint_path)
    monkeypatch.setattr(control, "_load_environment", lambda: None)
    monkeypatch.setattr(control, "investigation_rules_fingerprint", lambda: "a" * 64)
    monkeypatch.setattr(control, "session_advisory_lock", held_lock)
    monkeypatch.setattr(control, "_connect_admin", lambda: Connection())
    monkeypatch.setattr(control, "_snapshot", lambda _cur: snapshot)
    monkeypatch.setattr(
        control,
        "select_investigation_fact_targets",
        lambda *_args, **_kwargs: (7, 8),
    )
    monkeypatch.setattr(
        control,
        "_process_exact_facts",
        lambda _ids: {
            "status": "pending",
            "verification": {
                "state": "pending",
                "completed": 1,
                outbox_status: 1,
                "unresolved_event_ids": [8],
            },
        },
    )

    result = control.facts_backfill_poll()

    persisted = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    assert result["status"] == "blocked_batch"
    assert persisted["last_committed_event_id"] == 0

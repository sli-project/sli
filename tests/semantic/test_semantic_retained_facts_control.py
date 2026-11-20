from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import sys
from typing import Any, Iterator

import pytest

from scripts.maintenance import semantic_production_control as control


class _Cursor:
    def __init__(self, ids: list[int]) -> None:
        self.ids = ids
        self.calls: list[tuple[str, object]] = []

    def execute(self, query: str, params: object = None) -> None:
        self.calls.append((query, params))

    def fetchall(self) -> list[dict[str, int]]:
        return [{"id": value} for value in self.ids]

    def fetchone(self) -> dict[str, str]:
        if self.calls and "runtime_worker_heartbeats" in self.calls[-1][0]:
            from server.sli.semantic.semantic_processing import (
                ASSEMBLER_ID, ASSEMBLER_VERSION, NORMALIZER_ID, NORMALIZER_VERSION,
                SEMANTIC_CONTRACT_VERSION,
            )
            from server.sli.semantic.semantic_processing_repository import PROCESSOR_ID, PROCESSOR_VERSION
            return {
                "status": "idle", "phase": "production_sleep",
                "details_json": {
                    "runtime_mode": "investigation-v1", "manual_runtime": False,
                    "processing_contract": {
                        "claim_protocol_version": 1,
                        "semantic_contract_version": SEMANTIC_CONTRACT_VERSION,
                        "processor_id": PROCESSOR_ID, "processor_version": PROCESSOR_VERSION,
                        "normalizer": {"id": NORMALIZER_ID, "version": NORMALIZER_VERSION},
                        "assembler": {"id": ASSEMBLER_ID, "version": ASSEMBLER_VERSION},
                    },
                },
            }
        return {"host": "127.0.0.1", "database": "sli", "role": "owner",
                "system_identifier": "12345", "port": "5432", "database_oid": "16384"}


class _Connection:
    def __init__(self, cursor: _Cursor) -> None:
        self._cursor = cursor
        self.committed = 0

    @contextmanager
    def cursor(self) -> Iterator[_Cursor]:
        yield self._cursor

    @contextmanager
    def transaction(self) -> Iterator[None]:
        try:
            yield
        except Exception:
            raise
        else:
            self.committed += 1

    def __enter__(self) -> _Connection:
        return self

    def __exit__(self, *_args: object) -> None:
        return None


@contextmanager
def _held_lock(*_args: object, **_kwargs: object) -> Iterator[bool]:
    yield True


def _checkpoint(*, watermark: int = 10, last_committed: int = 5, fingerprint: str = "rules-v1") -> dict[str, object]:
    return {
        "checkpoint_type": "retained_v2_semantic_facts",
        "database_identity": {"host": "127.0.0.1", "database": "sli", "role": "owner",
                              "system_identifier": "12345", "port": "5432", "database_oid": "16384"},
        "status": "active",
        "range_start_event_id": 1,
        "frozen_high_watermark_event_id": watermark,
        "last_committed_event_id": last_committed,
        "rules_fingerprint": fingerprint,
        "batch_limit": 5000,
        "include_context": True,
    }


def _configure_poll(monkeypatch: pytest.MonkeyPatch, checkpoint_path: Path, cursor: _Cursor) -> _Connection:
    conn = _Connection(cursor)
    monkeypatch.setattr(control, "FACTS_CHECKPOINT_PATH", checkpoint_path, raising=False)
    monkeypatch.setattr(control, "_load_environment", lambda: None)
    monkeypatch.setattr(control, "_validate_facts_admission", lambda: None, raising=False)
    monkeypatch.setattr(control, "_facts_rules_fingerprint", lambda: "rules-v1", raising=False)
    monkeypatch.setattr(control, "session_advisory_lock", _held_lock, raising=False)
    monkeypatch.setattr(control, "_connect_admin", lambda: conn)
    return conn


def test_security_history_rejects_heartbeat_without_version_claim_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An old worker must not be admitted merely because it is fresh and idle."""
    cursor = _Cursor([])
    conn = _Connection(cursor)
    monkeypatch.setattr(control, "_connect_admin", lambda: conn)

    def old_heartbeat() -> dict[str, object]:
        return {"status": "idle", "details_json": {"runtime_mode": "investigation-v1", "manual_runtime": False}}

    monkeypatch.setattr(cursor, "fetchone", old_heartbeat)
    with pytest.raises(RuntimeError, match="fresh compatible managed investigation worker"):
        control._require_compatible_investigation_worker()


def test_facts_poll_does_not_advance_checkpoint_when_publication_transaction_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A failed producer transaction must leave the durable resume point intact."""
    path = tmp_path / "retained-facts.json"
    path.write_text(json.dumps(_checkpoint()), encoding="utf-8")
    _configure_poll(monkeypatch, path, _Cursor([6, 7]))

    def fail_publish(*_args: object, **_kwargs: object) -> dict[str, int]:
        raise RuntimeError("producer transaction failed")

    monkeypatch.setattr(control, "publish_semantic_candidates", fail_publish)

    with pytest.raises(RuntimeError, match="producer transaction failed"):
        control.facts_poll()

    assert json.loads(path.read_text(encoding="utf-8"))["last_committed_event_id"] == 5


def test_facts_poll_resumes_only_inside_frozen_range_and_never_starts_consumer(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A resumed batch stops at the persisted high-watermark and leaves consumption managed."""
    path = tmp_path / "retained-facts.json"
    path.write_text(json.dumps(_checkpoint(watermark=10, last_committed=5)), encoding="utf-8")
    cursor = _Cursor([6, 8])
    conn = _configure_poll(monkeypatch, path, cursor)
    published: list[tuple[list[int], bool]] = []

    def publish(_cur: object, ids: list[int], *, include_context: bool) -> dict[str, int]:
        published.append((ids, include_context))
        return {"scanned": len(ids), "queued": len(ids)}

    monkeypatch.setattr(control, "publish_semantic_candidates", publish)
    monkeypatch.setattr(
        control,
        "_run_ephemeral",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("consumer must stay managed")),
    )

    result = control.facts_poll()

    assert published == [([6, 8], True)]
    assert conn.committed == 1
    assert any(params == (5, 10, 5000) for _query, params in cursor.calls)
    checkpoint = json.loads(path.read_text(encoding="utf-8"))
    assert checkpoint["last_committed_event_id"] == 8
    assert result["consumer"] == "existing_managed_facts_worker"


def test_facts_poll_refuses_changed_rules_before_reading_or_publishing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A changed selector/catalogue/normalizer contract cannot silently resume old work."""
    path = tmp_path / "retained-facts.json"
    path.write_text(json.dumps(_checkpoint(fingerprint="rules-v1")), encoding="utf-8")
    cursor = _Cursor([6])
    _configure_poll(monkeypatch, path, cursor)
    monkeypatch.setattr(control, "_facts_rules_fingerprint", lambda: "rules-v2", raising=False)
    monkeypatch.setattr(
        control,
        "publish_semantic_candidates",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must not publish")),
    )

    with pytest.raises(RuntimeError, match="rules fingerprint mismatch"):
        control.facts_poll()

    assert cursor.calls == []


def test_facts_poll_initializes_a_frozen_checkpoint_before_one_bounded_batch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """New retained work fixes its upper bound once; later event IDs cannot enter this plan."""
    path = tmp_path / "retained-facts.json"
    cursor = _Cursor([1, 2])
    _configure_poll(monkeypatch, path, cursor)
    monkeypatch.setattr(control, "_facts_target_snapshot", lambda: (_checkpoint()["database_identity"], 9))
    monkeypatch.setattr(
        control,
        "publish_semantic_candidates",
        lambda _cur, ids, *, include_context: {"scanned": len(ids), "queued": len(ids)},
    )

    control.facts_poll()

    checkpoint = json.loads(path.read_text(encoding="utf-8"))
    assert checkpoint["range_start_event_id"] == 1
    assert checkpoint["frozen_high_watermark_event_id"] == 9
    assert checkpoint["last_committed_event_id"] == 2


def test_facts_poll_checks_explicit_admission_before_creating_checkpoint(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A legacy/disabled runtime cannot leave even an initial retained checkpoint."""
    path = tmp_path / "retained-facts.json"
    _configure_poll(monkeypatch, path, _Cursor([1]))

    def deny_admission() -> None:
        raise RuntimeError("retained facts requires explicit facts-v1 admission")

    monkeypatch.setattr(control, "_validate_facts_admission", deny_admission)

    with pytest.raises(RuntimeError, match="explicit facts-v1 admission"):
        control.facts_poll()

    assert not path.exists()


def test_facts_poll_repeats_only_committed_batch_after_atomic_checkpoint_write_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A crash after commit keeps the durable cursor, so retry republishes that batch only."""
    path = tmp_path / "retained-facts.json"
    path.write_text(json.dumps(_checkpoint(watermark=10, last_committed=5)), encoding="utf-8")
    first_cursor = _Cursor([6, 8])
    first_conn = _configure_poll(monkeypatch, path, first_cursor)
    published: list[list[int]] = []
    monkeypatch.setattr(
        control,
        "publish_semantic_candidates",
        lambda _cur, ids, *, include_context: published.append(ids) or {"scanned": len(ids), "queued": len(ids)},
    )
    write_checkpoint = control._write_facts_checkpoint
    monkeypatch.setattr(
        control,
        "_write_facts_checkpoint",
        lambda _checkpoint: (_ for _ in ()).throw(OSError("checkpoint disk unavailable")),
    )

    with pytest.raises(OSError, match="checkpoint disk unavailable"):
        control.facts_poll()

    assert first_conn.committed == 1
    assert json.loads(path.read_text(encoding="utf-8"))["last_committed_event_id"] == 5

    second_cursor = _Cursor([6, 8])
    second_conn = _Connection(second_cursor)
    monkeypatch.setattr(control, "_connect_admin", lambda: second_conn)
    monkeypatch.setattr(control, "_write_facts_checkpoint", write_checkpoint)

    control.facts_poll()

    assert published == [[6, 8], [6, 8]]
    assert second_conn.committed == 1
    assert json.loads(path.read_text(encoding="utf-8"))["last_committed_event_id"] == 8


def test_facts_poll_cli_requires_its_own_explicit_confirmation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The default CLI path cannot turn a retained preview into publication."""
    called: list[bool] = []
    monkeypatch.setattr(control, "facts_poll", lambda: called.append(True) or {})
    monkeypatch.setattr(
        sys,
        "argv",
        ["semantic_production_control.py", "facts-poll"],
    )

    assert control.main() == 1
    assert called == []


def _v2_history_manifest(
    history: Any, *, identity: dict[str, str], cohorts: dict[int, dict[str, object]],
) -> dict[str, object]:
    """Small test fixture for v2-only controller behaviours unrelated to 4624."""
    return history.new_security_history_manifest_v2(
        database_identity=identity, cohorts=cohorts, plan_digest="d" * 64,
        semantic_context_cohort={
            "count": 0, "cohort_digest": history.security_history_cohort_digest(()),
            "reset_high_watermark": 0,
        },
        supersedes={
            "manifest_type": history.SECURITY_HISTORY_MANIFEST_TYPE_V1,
            "plan_digest": "e" * 64,
            "reason": history.SECURITY_HISTORY_SUPERSEDE_REASON,
        },
    )


def test_security_history_plan_is_read_only_and_poll_publishes_one_frozen_cohort_chunk(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """The vocabulary facade freezes compact cohorts and leaves consumption to the managed worker."""
    from scripts.maintenance import semantic_production_control as history

    path = tmp_path / "security-history.json"
    digest = "a" * 64
    cohorts = {
        4727: {
            "high_watermark": 9, "count": 2, "cohort_digest": digest,
            "min_id": 7, "max_id": 9,
        },
    }
    snapshot = {
        "database_identity": {"host": "127.0.0.1", "database": "sli", "role": "owner"},
        "cohorts": cohorts,
        "semantic_context_cohort": {
            "count": 0, "cohort_digest": history.security_history_cohort_digest(()),
            "reset_high_watermark": 0,
        },
    }
    published: list[tuple[list[int], bool, tuple[int, ...]]] = []

    monkeypatch.setattr(history, "SECURITY_HISTORY_MANIFEST_PATH", path, raising=False)
    monkeypatch.setattr(history, "_load_environment", lambda: None)
    monkeypatch.setattr(history, "_validate_security_history_admission", lambda: None, raising=False)
    monkeypatch.setattr(history, "_security_history_v2_snapshot", lambda **_kwargs: snapshot, raising=False)
    monkeypatch.setattr(history, "session_advisory_lock", _held_lock, raising=False)
    monkeypatch.setattr(history, "_connect_admin", lambda: _Connection(_Cursor([7, 9])))
    monkeypatch.setattr(
        history,
        "select_security_history_targets",
        lambda *_args, **_kwargs: (7, 9),
        raising=False,
    )
    monkeypatch.setattr(
        history,
        "publish_semantic_candidates",
        lambda _cur, ids, *, include_context, context_event_ids: published.append(
            (list(ids), include_context, tuple(context_event_ids))
        ) or {
            "scanned": len(ids), "queued": len(ids), "signal_queued": len(ids),
            "unknown_queued": 0, "unknown_suppressed": 0,
            "context_skipped": 0, "noise_skipped": 0,
        },
    )

    plan = history.security_history_plan()
    assert plan["production_changed"] is False
    assert not path.exists()

    result = history.security_history_poll(confirmation=plan["confirmation"])

    assert result["consumer"] == "existing_managed_investigation_worker"
    assert published == [([7, 9], True, (7, 9))]
    manifest = json.loads(path.read_text(encoding="utf-8"))
    assert manifest["events"]["4727"]["cursor"] == 9
    assert manifest["events"]["4727"]["state"] == "queued"
    assert manifest["events"]["1102"]["state"] == "no_retained_events"


def test_security_history_v2_poll_routes_routine_logon_cohort_through_exact_investigation_context(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """A raw 4624 cohort cannot be bulk-admitted by the generic publisher."""
    from scripts.maintenance import semantic_production_control as history
    from server.sli.semantic.semantic_investigation_backfill import (
        SECURITY_HISTORY_MANIFEST_TYPE_V1,
        SECURITY_HISTORY_SUPERSEDE_REASON,
        new_security_history_manifest_v2,
        security_history_cohort_digest,
    )

    path = tmp_path / "security-history.json"
    identity = {"host": "127.0.0.1", "database": "sli", "role": "owner"}
    cohorts = {
        4624: {
            "high_watermark": 9, "count": 3,
            "cohort_digest": security_history_cohort_digest([
                (7, "a" * 64), (8, "b" * 64), (9, "c" * 64),
            ]),
            "min_id": 7, "max_id": 9,
        },
    }
    manifest = new_security_history_manifest_v2(
        database_identity=identity, plan_digest="b" * 64, cohorts=cohorts,
        semantic_context_cohort={
            "count": 1,
            "cohort_digest": security_history_cohort_digest([(8, "b" * 64)]),
            "reset_high_watermark": 0,
        },
        supersedes={
            "manifest_type": SECURITY_HISTORY_MANIFEST_TYPE_V1,
            "plan_digest": "a" * 64,
            "reason": SECURITY_HISTORY_SUPERSEDE_REASON,
        },
    )
    path.write_text(json.dumps(manifest), encoding="utf-8")
    published: list[tuple[int, ...]] = []
    monkeypatch.setattr(history, "SECURITY_HISTORY_MANIFEST_PATH", path, raising=False)
    monkeypatch.setattr(history, "_load_environment", lambda: None)
    monkeypatch.setattr(history, "_validate_security_history_admission", lambda: None, raising=False)
    monkeypatch.setattr(history, "_require_compatible_investigation_worker", lambda: None, raising=False)
    monkeypatch.setattr(history, "_security_history_current_database_identity", lambda: identity, raising=False)
    monkeypatch.setattr(history, "session_advisory_lock", _held_lock, raising=False)
    monkeypatch.setattr(history, "_connect_admin", lambda: _Connection(_Cursor([])))
    monkeypatch.setattr(
        history, "select_security_history_context_targets", lambda *_args, **_kwargs: (8,),
        raising=False,
    )
    monkeypatch.setattr(
        history, "select_security_history_targets",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("routine 4624 must not be selected")),
        raising=False,
    )
    monkeypatch.setattr(
        history, "publish_investigation_candidates",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("historical poll must not create expansion")),
        raising=False,
    )
    monkeypatch.setattr(
        history, "publish_semantic_candidates",
        lambda _cur, ids, *, include_context, context_event_ids: published.append(tuple(ids)) or {
            "scanned": len(ids), "queued": len(ids), "signal_queued": 0,
            "unknown_queued": 0, "unknown_suppressed": 0,
            "context_skipped": 0, "noise_skipped": 0,
        },
        raising=False,
    )

    result = history.security_history_poll(
        confirmation=history.SECURITY_HISTORY_POLL_CONFIRM_PREFIX + manifest["plan_digest"],
    )

    assert result["event_id"] == 4624
    assert published == [(8,)]
    resumed = json.loads(path.read_text(encoding="utf-8"))["events"]["4624"]
    assert resumed["raw_retained_count"] == 3
    assert resumed["semantic_expected_count"] == 1


def test_security_history_fresh_plan_and_poll_create_v2_without_late_context_expansion(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """A clean checkout cannot create legacy v1 or widen frozen 4624 context."""
    from scripts.maintenance import semantic_production_control as history

    path = tmp_path / "security-history.json"
    identity = {"host": "127.0.0.1", "database": "sli", "role": "owner"}
    snapshot = {
        "database_identity": identity,
        "cohorts": {4624: {
            "high_watermark": 9, "count": 2, "cohort_digest": "a" * 64,
            "min_id": 7, "max_id": 9,
        }},
        "semantic_context_cohort": {
            "count": 1, "cohort_digest": history.security_history_cohort_digest([(8, "b" * 64)]),
            "reset_high_watermark": 0,
        },
    }
    published: list[tuple[tuple[int, ...], bool, tuple[int, ...]]] = []
    monkeypatch.setattr(history, "SECURITY_HISTORY_MANIFEST_PATH", path, raising=False)
    monkeypatch.setattr(history, "_load_environment", lambda: None)
    monkeypatch.setattr(history, "_validate_security_history_admission", lambda: None, raising=False)
    monkeypatch.setattr(history, "_require_compatible_investigation_worker", lambda: None, raising=False)
    monkeypatch.setattr(history, "_security_history_v2_snapshot", lambda **_kwargs: snapshot, raising=False)
    monkeypatch.setattr(
        history, "_security_history_snapshot",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("fresh v2 must not create v1")),
        raising=False,
    )
    monkeypatch.setattr(history, "_security_history_current_database_identity", lambda: identity, raising=False)
    monkeypatch.setattr(history, "session_advisory_lock", _held_lock, raising=False)
    monkeypatch.setattr(history, "_connect_admin", lambda: _Connection(_Cursor([])))
    monkeypatch.setattr(history, "select_security_history_context_targets", lambda _cur, **_kwargs: (8,), raising=False)
    monkeypatch.setattr(
        history, "publish_semantic_candidates",
        lambda _cur, ids, *, include_context, context_event_ids: published.append(
            (tuple(ids), include_context, tuple(context_event_ids))
        ) or {
            "scanned": len(ids), "queued": len(ids), "signal_queued": 0,
            "unknown_queued": 0, "unknown_suppressed": 0,
            "context_skipped": 0, "noise_skipped": 0,
        },
        raising=False,
    )
    monkeypatch.setattr(
        history, "publish_investigation_candidates",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("historical poll must not create expansion")),
        raising=False,
    )

    plan = history.security_history_plan()
    result = history.security_history_poll(confirmation=plan["confirmation"])

    assert result["event_id"] == 4624
    assert published == [((8,), True, (8,))]
    manifest = json.loads(path.read_text(encoding="utf-8"))
    assert manifest["manifest_type"] == history.SECURITY_HISTORY_MANIFEST_TYPE_V2
    assert manifest["supersedes"] is None


def test_security_history_v2_exact_batch_accepts_catalogue_context_4776() -> None:
    """A selected vocabulary member may be context without becoming incomplete."""
    from scripts.maintenance import semantic_production_control as history

    assert history._security_history_v2_publication_is_exact(
        event_id=4776,
        target_ids=(77,),
        published={
            "scanned": 1, "queued": 1, "signal_queued": 0,
            "unknown_queued": 0, "unknown_suppressed": 0,
            "context_skipped": 0, "noise_skipped": 0,
        },
    ) is True


def test_security_history_v1_checkpoint_cannot_resume_without_explicit_supersede(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """The legacy 100-row plan remains repairable but cannot mutate by polling."""
    from scripts.maintenance import semantic_production_control as history

    path = tmp_path / "security-history.json"
    identity = {"host": "127.0.0.1", "database": "sli", "role": "owner"}
    snapshot = {
        "database_identity": identity,
        "cohorts": {4724: {
            "high_watermark": 9, "count": 1, "cohort_digest": "a" * 64,
            "min_id": 9, "max_id": 9,
        }},
    }
    manifest = history.new_security_history_manifest(
        database_identity=identity, cohorts=snapshot["cohorts"],
        plan_digest=history._security_history_plan_digest(snapshot), batch_limit=100,
    )
    path.write_text(json.dumps(manifest), encoding="utf-8")
    before = path.read_text(encoding="utf-8")
    monkeypatch.setattr(history, "SECURITY_HISTORY_MANIFEST_PATH", path, raising=False)
    monkeypatch.setattr(history, "_load_environment", lambda: None)
    monkeypatch.setattr(history, "_validate_security_history_admission", lambda: None, raising=False)
    monkeypatch.setattr(history, "_security_history_current_database_identity", lambda: identity, raising=False)
    monkeypatch.setattr(
        history, "select_security_history_targets",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("v1 must not select")),
        raising=False,
    )

    with pytest.raises(RuntimeError, match="explicit supersede"):
        history.security_history_poll(
            confirmation=history.SECURITY_HISTORY_POLL_CONFIRM_PREFIX + manifest["plan_digest"],
        )

    assert path.read_text(encoding="utf-8") == before


def test_security_history_supersede_plan_reuses_legacy_frozen_high_watermarks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """The replacement changes semantic scope, not the historical source range."""
    from scripts.maintenance import semantic_production_control as history

    path = tmp_path / "security-history.json"
    identity = {"host": "127.0.0.1", "database": "sli", "role": "owner"}
    raw_cohorts = {
        4624: {"high_watermark": 90, "count": 2, "cohort_digest": "a" * 64, "min_id": 7, "max_id": 90},
        4724: {"high_watermark": 80, "count": 1, "cohort_digest": "b" * 64, "min_id": 80, "max_id": 80},
    }
    legacy = history.new_security_history_manifest(
        database_identity=identity, cohorts=raw_cohorts,
        plan_digest=history._security_history_plan_digest({"database_identity": identity, "cohorts": raw_cohorts}),
        batch_limit=100,
    )
    path.write_text(json.dumps(legacy), encoding="utf-8")
    seen: list[dict[int, int]] = []
    replacement_snapshot = {
        "database_identity": identity, "cohorts": raw_cohorts,
        "semantic_context_cohort": {"count": 1, "cohort_digest": "c" * 64, "reset_high_watermark": 80},
    }
    monkeypatch.setattr(history, "SECURITY_HISTORY_MANIFEST_PATH", path, raising=False)
    monkeypatch.setattr(history, "_load_environment", lambda: None)
    monkeypatch.setattr(history, "_validate_security_history_admission", lambda: None, raising=False)
    monkeypatch.setattr(history, "_security_history_current_database_identity", lambda: identity, raising=False)
    monkeypatch.setattr(history, "_connect_admin", lambda: _Connection(_Cursor([])))
    monkeypatch.setattr(history, "_security_history_require_repair_resolved", lambda *_args: None, raising=False)
    monkeypatch.setattr(
        history, "_security_history_v2_snapshot",
        lambda *, high_watermarks: seen.append(high_watermarks) or replacement_snapshot,
        raising=False,
    )

    plan = history.security_history_supersede_plan()

    assert plan["batch_limit"] == 5000
    assert seen == [{event_id: int(legacy["events"][str(event_id)]["high_watermark"])
                     for event_id in history.SECURITY_HISTORY_EVENT_IDS}]


def test_security_history_supersede_archives_v1_once_then_installs_resumable_v2(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """Apply never rewrites the old checkpoint and a retry cannot supersede v2 again."""
    from scripts.maintenance import semantic_production_control as history

    path = tmp_path / "security-history.json"
    identity = {"host": "127.0.0.1", "database": "sli", "role": "owner"}
    cohorts = {4624: {"high_watermark": 9, "count": 1, "cohort_digest": "a" * 64, "min_id": 9, "max_id": 9}}
    legacy = history.new_security_history_manifest(
        database_identity=identity, cohorts=cohorts,
        plan_digest=history._security_history_plan_digest({"database_identity": identity, "cohorts": cohorts}),
        batch_limit=100,
    )
    path.write_text(json.dumps(legacy), encoding="utf-8")
    snapshot = {
        "database_identity": identity, "cohorts": cohorts,
        "semantic_context_cohort": {"count": 0, "cohort_digest": history.security_history_cohort_digest(()), "reset_high_watermark": 0},
    }
    monkeypatch.setattr(history, "SECURITY_HISTORY_MANIFEST_PATH", path, raising=False)
    monkeypatch.setattr(history, "_load_environment", lambda: None)
    monkeypatch.setattr(history, "_validate_security_history_admission", lambda: None, raising=False)
    monkeypatch.setattr(history, "_security_history_current_database_identity", lambda: identity, raising=False)
    monkeypatch.setattr(history, "_connect_admin", lambda: _Connection(_Cursor([])))
    monkeypatch.setattr(history, "session_advisory_lock", _held_lock, raising=False)
    monkeypatch.setattr(history, "_security_history_require_repair_resolved", lambda *_args: None, raising=False)
    monkeypatch.setattr(history, "_security_history_v2_snapshot", lambda **_kwargs: snapshot, raising=False)

    plan = history.security_history_supersede_plan()
    applied = history.security_history_supersede(
        plan_digest=plan["replacement_plan_digest"], confirmation=plan["confirmation"],
    )

    archive = Path(applied["v1_archive_path"])
    assert json.loads(archive.read_text(encoding="utf-8")) == legacy
    replacement = json.loads(path.read_text(encoding="utf-8"))
    assert replacement["manifest_type"] == history.SECURITY_HISTORY_MANIFEST_TYPE_V2
    assert replacement["supersedes"]["plan_digest"] == legacy["plan_digest"]
    with pytest.raises(RuntimeError, match="requires a v1 manifest"):
        history.security_history_supersede_plan()


def test_security_history_supersede_fails_closed_when_frozen_v1_raw_cohort_drifts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """A changed retained hash is not silently carried into the replacement contract."""
    from scripts.maintenance import semantic_production_control as history

    path = tmp_path / "security-history.json"
    identity = {"host": "127.0.0.1", "database": "sli", "role": "owner"}
    cohorts = {4624: {"high_watermark": 9, "count": 1, "cohort_digest": "a" * 64, "min_id": 9, "max_id": 9}}
    legacy = history.new_security_history_manifest(
        database_identity=identity, cohorts=cohorts,
        plan_digest=history._security_history_plan_digest({"database_identity": identity, "cohorts": cohorts}),
        batch_limit=100,
    )
    path.write_text(json.dumps(legacy), encoding="utf-8")
    drifted = {
        "database_identity": identity,
        "cohorts": {**cohorts, 4624: {**cohorts[4624], "cohort_digest": "b" * 64}},
        "semantic_context_cohort": {"count": 0, "cohort_digest": history.security_history_cohort_digest(()), "reset_high_watermark": 0},
    }
    monkeypatch.setattr(history, "SECURITY_HISTORY_MANIFEST_PATH", path, raising=False)
    monkeypatch.setattr(history, "_load_environment", lambda: None)
    monkeypatch.setattr(history, "_validate_security_history_admission", lambda: None, raising=False)
    monkeypatch.setattr(history, "_security_history_current_database_identity", lambda: identity, raising=False)
    monkeypatch.setattr(history, "_connect_admin", lambda: _Connection(_Cursor([])))
    monkeypatch.setattr(history, "_security_history_require_repair_resolved", lambda *_args: None, raising=False)
    monkeypatch.setattr(history, "_security_history_v2_snapshot", lambda **_kwargs: drifted, raising=False)

    with pytest.raises(RuntimeError, match="frozen v1 cohort changed"):
        history.security_history_supersede_plan()

    assert path.read_text(encoding="utf-8") == json.dumps(legacy)


def test_security_history_resume_plan_uses_manifest_without_rescanning_frozen_cohorts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """A resumable plan must not reread every frozen source/hash pair."""
    from scripts.maintenance import semantic_production_control as history

    path = tmp_path / "security-history.json"
    snapshot = {
        "database_identity": {"host": "127.0.0.1", "database": "sli", "role": "owner"},
        "cohorts": {4727: {"high_watermark": 1, "count": 1, "cohort_digest": "a" * 64, "min_id": 1, "max_id": 1}},
    }
    manifest = _v2_history_manifest(
        history, identity=snapshot["database_identity"], cohorts=snapshot["cohorts"],
    )
    path.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(history, "SECURITY_HISTORY_MANIFEST_PATH", path, raising=False)
    monkeypatch.setattr(history, "_load_environment", lambda: None)
    monkeypatch.setattr(history, "_validate_security_history_admission", lambda: None, raising=False)
    monkeypatch.setattr(
        history,
        "_security_history_current_database_identity",
        lambda: snapshot["database_identity"],
        raising=False,
    )
    monkeypatch.setattr(
        history,
        "_security_history_snapshot",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("resume must not rescan frozen cohorts")),
        raising=False,
    )

    plan = history.security_history_plan()

    assert plan["status"] == "security_history_resume_ready"
    assert plan["plan_digest"] == manifest["plan_digest"]


def test_security_history_full_published_chunk_waits_for_managed_worker(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """A full chunk cannot open another chunk until worker readback settles it."""
    from scripts.maintenance import semantic_production_control as history

    path = tmp_path / "security-history.json"
    snapshot = {
        "database_identity": {"host": "127.0.0.1", "database": "sli", "role": "owner"},
        "cohorts": {4727: {"high_watermark": 100, "count": 100, "cohort_digest": "a" * 64, "min_id": 1, "max_id": 100}},
        "semantic_context_cohort": {
            "count": 0, "cohort_digest": history.security_history_cohort_digest(()),
            "reset_high_watermark": 0,
        },
    }
    monkeypatch.setattr(history, "SECURITY_HISTORY_MANIFEST_PATH", path, raising=False)
    monkeypatch.setattr(history, "_load_environment", lambda: None)
    monkeypatch.setattr(history, "_validate_security_history_admission", lambda: None, raising=False)
    monkeypatch.setattr(history, "_security_history_v2_snapshot", lambda **_kwargs: snapshot, raising=False)
    monkeypatch.setattr(history, "session_advisory_lock", _held_lock, raising=False)
    monkeypatch.setattr(history, "_connect_admin", lambda: _Connection(_Cursor([])))
    selected_limits: list[int] = []
    monkeypatch.setattr(
        history,
        "select_security_history_targets",
        lambda *_args, **kwargs: selected_limits.append(int(kwargs["limit"])) or tuple(range(1, 101)),
        raising=False,
    )
    monkeypatch.setattr(
        history,
        "publish_semantic_candidates",
        lambda _cur, ids, **_kwargs: {
            "scanned": len(ids), "queued": len(ids), "signal_queued": len(ids),
            "unknown_queued": 0, "unknown_suppressed": 0,
            "context_skipped": 0, "noise_skipped": 0,
        },
    )

    plan = history.security_history_plan()
    history.security_history_poll(confirmation=plan["confirmation"])

    entry = json.loads(path.read_text(encoding="utf-8"))["events"]["4727"]
    assert entry["cursor"] == 100
    assert entry["state"] == "queued"
    assert selected_limits == [5000]


def test_security_history_empty_current_selection_recovers_cursor_to_frozen_high_watermark(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """Already-current rows must not leave a resumable cursor retrying an empty page."""
    from scripts.maintenance import semantic_production_control as history

    path = tmp_path / "security-history.json"
    snapshot = {
        "database_identity": {"host": "127.0.0.1", "database": "sli", "role": "owner"},
        "cohorts": {4727: {"high_watermark": 9, "count": 1, "cohort_digest": "a" * 64, "min_id": 9, "max_id": 9}},
        "semantic_context_cohort": {
            "count": 0, "cohort_digest": history.security_history_cohort_digest(()),
            "reset_high_watermark": 0,
        },
    }
    monkeypatch.setattr(history, "SECURITY_HISTORY_MANIFEST_PATH", path, raising=False)
    monkeypatch.setattr(history, "_load_environment", lambda: None)
    monkeypatch.setattr(history, "_validate_security_history_admission", lambda: None, raising=False)
    monkeypatch.setattr(history, "_security_history_v2_snapshot", lambda **_kwargs: snapshot, raising=False)
    monkeypatch.setattr(history, "session_advisory_lock", _held_lock, raising=False)
    monkeypatch.setattr(history, "_connect_admin", lambda: _Connection(_Cursor([])))
    monkeypatch.setattr(history, "select_security_history_targets", lambda *_args, **_kwargs: (), raising=False)
    monkeypatch.setattr(
        history, "publish_semantic_candidates",
        lambda _cur, ids, **_kwargs: {"queued": len(ids)},
    )

    plan = history.security_history_plan()
    result = history.security_history_poll(confirmation=plan["confirmation"])

    entry = json.loads(path.read_text(encoding="utf-8"))["events"]["4727"]
    assert result["production_changed"] is False
    assert entry["cursor"] == 9
    assert entry["state"] == "queued"


@pytest.mark.parametrize("blocked_state", ["queued", "processing"])
def test_security_history_poll_waits_when_another_cohort_is_unfinished(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, blocked_state: str,
) -> None:
    """One unfinished managed batch blocks publication from every other cohort."""
    from scripts.maintenance import semantic_production_control as history

    path = tmp_path / "security-history.json"
    snapshot = {
        "database_identity": {"host": "127.0.0.1", "database": "sli", "role": "owner"},
        "cohorts": {
            4727: {"high_watermark": 1, "count": 1, "cohort_digest": "a" * 64, "min_id": 1, "max_id": 1},
            4730: {"high_watermark": 2, "count": 1, "cohort_digest": "b" * 64, "min_id": 2, "max_id": 2},
        },
    }
    manifest = _v2_history_manifest(
        history, identity=snapshot["database_identity"], cohorts=snapshot["cohorts"],
    )
    manifest["events"]["4727"].update({"cursor": 1, "state": blocked_state})
    manifest["events"]["4730"].update({"cursor": 0, "state": "publishing"})
    path.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(history, "SECURITY_HISTORY_MANIFEST_PATH", path, raising=False)
    monkeypatch.setattr(history, "_load_environment", lambda: None)
    monkeypatch.setattr(history, "_validate_security_history_admission", lambda: None, raising=False)
    monkeypatch.setattr(
        history,
        "_security_history_current_database_identity",
        lambda: snapshot["database_identity"],
        raising=False,
    )
    monkeypatch.setattr(history, "session_advisory_lock", _held_lock, raising=False)
    monkeypatch.setattr(history, "_connect_admin", lambda: _Connection(_Cursor([])))
    monkeypatch.setattr(
        history,
        "select_security_history_targets",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("queued cohort must block selection")),
    )
    monkeypatch.setattr(
        history,
        "publish_semantic_candidates",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("queued cohort must block publication")),
    )

    result = history.security_history_poll(
        confirmation=history.SECURITY_HISTORY_POLL_CONFIRM_PREFIX + manifest["plan_digest"],
    )

    assert result["status"] == "security_history_poll_waiting_for_managed_worker"
    assert result["production_changed"] is False


def test_security_history_terminal_hash_drift_is_persisted_as_incomplete_original(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """Final source-hash drift must fail the exact frozen Event ID, not success."""
    from scripts.maintenance import semantic_production_control as history

    path = tmp_path / "security-history.json"
    frozen = {
        "database_identity": {"host": "127.0.0.1", "database": "sli", "role": "owner"},
        "cohorts": {4727: {"high_watermark": 1, "count": 1, "cohort_digest": "a" * 64, "min_id": 1, "max_id": 1}},
    }
    manifest = history.new_security_history_manifest(
        database_identity=frozen["database_identity"],
        cohorts=frozen["cohorts"], plan_digest=history._security_history_plan_digest(frozen),
    )
    manifest["events"]["4727"].update({"cursor": 1, "state": "queued"})
    path.write_text(json.dumps(manifest), encoding="utf-8")
    drifted = {
        "database_identity": frozen["database_identity"],
        "cohorts": {4727: {"high_watermark": 1, "count": 1, "cohort_digest": "b" * 64, "min_id": 1, "max_id": 1}},
    }
    snapshots: list[dict[str, object]] = []
    monkeypatch.setattr(history, "SECURITY_HISTORY_MANIFEST_PATH", path, raising=False)
    monkeypatch.setattr(history, "_load_environment", lambda: None)
    monkeypatch.setattr(
        history,
        "_security_history_current_database_identity",
        lambda: frozen["database_identity"],
        raising=False,
    )
    monkeypatch.setattr(
        history,
        "_security_history_snapshot",
        lambda **_kwargs: snapshots.append(drifted) or drifted,
        raising=False,
    )
    monkeypatch.setattr(history, "session_advisory_lock", _held_lock, raising=False)
    monkeypatch.setattr(history, "_connect_admin", lambda: _Connection(_Cursor([])))

    def reconciliation(_cur: object, *, event_id: int, high_watermark: int) -> dict[str, int]:
        if event_id == 4727:
            return {
                "retained_count": 1, "normalized_count": 1,
                "normalization_failed": 0, "normalization_quarantined": 0,
                "outbox_queued": 0, "outbox_leased": 0, "outbox_completed": 1,
                "outbox_failed": 0, "outbox_quarantined": 0, "action_evidence_count": 0,
            }
        return {name: 0 for name in (
            "retained_count", "normalized_count", "normalization_failed", "normalization_quarantined",
            "outbox_queued", "outbox_leased", "outbox_completed", "outbox_failed",
            "outbox_quarantined", "action_evidence_count",
        )}

    monkeypatch.setattr(history, "reconcile_security_history_event", reconciliation)

    plan = history.security_history_check_plan()
    assert snapshots == []
    result = history.security_history_check(
        plan_digest=plan["plan_digest"], confirmation=plan["confirmation"],
    )

    assert result["terminal_success"] is False
    assert snapshots == [drifted]
    entry = json.loads(path.read_text(encoding="utf-8"))["events"]["4727"]
    assert entry["state"] == "incomplete_original"
    assert entry["terminal_reason"] == "frozen_original_integrity_mismatch"


def test_security_history_v2_check_accepts_only_completed_proof_bound_repair(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """The 4624 original quarantine is not terminal once its exact v2 repair proves current normalization."""
    from scripts.maintenance import semantic_production_control as history
    from server.sli.semantic.semantic_investigation_backfill import SecurityHistoryV2ContextReconciliation

    path = tmp_path / "security-history-v2.json"
    identity = {"host": "127.0.0.1", "database": "sli", "role": "owner"}
    cohorts = {
        4624: {"high_watermark": 20, "count": 1, "cohort_digest": "a" * 64, "min_id": 20, "max_id": 20},
        4724: {"high_watermark": 10, "count": 1, "cohort_digest": "b" * 64, "min_id": 10, "max_id": 10},
    }
    manifest = history.new_security_history_manifest_v2(
        database_identity=identity, plan_digest="d" * 64, cohorts=cohorts,
        semantic_context_cohort={"count": 1, "cohort_digest": "c" * 64, "reset_high_watermark": 10},
        supersedes={"manifest_type": history.SECURITY_HISTORY_MANIFEST_TYPE_V1, "plan_digest": "e" * 64, "reason": history.SECURITY_HISTORY_SUPERSEDE_REASON},
    )
    manifest["events"]["4624"].update({"cursor": 20, "state": "queued"})
    path.write_text(json.dumps(manifest), encoding="utf-8")
    frozen_raw_cohorts = {
        int(event_id): {
            "high_watermark": entry["high_watermark"], "count": entry["raw_retained_count"],
            "cohort_digest": entry["raw_cohort_digest"], "min_id": entry["min_id"], "max_id": entry["max_id"],
        }
        for event_id, entry in manifest["events"].items()
    }
    snapshot = {"database_identity": identity, "cohorts": frozen_raw_cohorts, "semantic_context_cohort": {
        "count": 1, "cohort_digest": "c" * 64, "reset_high_watermark": 10,
    }}
    zero = {name: 0 for name in (
        "retained_count", "normalized_count", "normalization_failed", "normalization_quarantined",
        "outbox_queued", "outbox_leased", "outbox_completed", "outbox_failed",
        "outbox_quarantined", "action_evidence_count",
    )}
    current = {**zero, "retained_count": 1, "normalized_count": 1, "outbox_completed": 1,
               "outbox_quarantined": 1, "action_evidence_count": 1}
    states = {state: 0 for state in (
        "absent", "queued", "leased", "completed", "failed", "quarantined", "conflict",
    )}
    states["completed"] = 1

    monkeypatch.setattr(history, "SECURITY_HISTORY_MANIFEST_PATH", path, raising=False)
    monkeypatch.setattr(history, "_load_environment", lambda: None)
    monkeypatch.setattr(history, "_security_history_current_database_identity", lambda: identity)
    monkeypatch.setattr(history, "session_advisory_lock", _held_lock)
    monkeypatch.setattr(history, "_connect_admin", lambda: _Connection(_Cursor([])))
    monkeypatch.setattr(
        history, "reconcile_security_history_event",
        lambda *_args, **kwargs: ({**zero, "retained_count": 1, "normalized_count": 1}
                                   if kwargs.get("event_id") == 4724 else dict(zero)),
    )
    monkeypatch.setattr(history, "reconcile_security_history_context_event", lambda *_args, **_kwargs: dict(current))
    monkeypatch.setattr(history, "reconcile_security_history_v2_context_event", lambda *_args, **_kwargs: SecurityHistoryV2ContextReconciliation(current=current, repair_states=states))
    monkeypatch.setattr(history, "_security_history_v2_snapshot", lambda **_kwargs: snapshot)

    plan = history.security_history_check_plan()
    result = history.security_history_check(plan_digest=plan["plan_digest"], confirmation=plan["confirmation"])

    assert result["terminal_success"] is True, result
    entry = json.loads(path.read_text(encoding="utf-8"))["events"]["4624"]
    assert entry["state"] == "complete"
    assert entry["v2_repair_states"] == states


def test_security_history_check_reads_one_repeatable_read_snapshot() -> None:
    from scripts.maintenance import semantic_production_control as history

    sql = "\n".join(
        value for value in history.security_history_check.__code__.co_consts
        if isinstance(value, str)
    ).casefold()

    assert "set transaction isolation level repeatable read, read only" in sql


def test_security_history_cli_keeps_plan_read_only_and_binds_mutations_to_distinct_confirmations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scripts.maintenance import semantic_production_control as history

    calls: list[tuple[str, object]] = []
    monkeypatch.setattr(history, "security_history_plan", lambda: calls.append(("plan", None)) or {"status": "ok"}, raising=False)
    monkeypatch.setattr(history, "security_history_poll", lambda *, confirmation: calls.append(("poll", confirmation)) or {"status": "ok"}, raising=False)
    monkeypatch.setattr(history, "security_history_check_plan", lambda: calls.append(("check-plan", None)) or {"status": "ok"}, raising=False)
    monkeypatch.setattr(history, "security_history_check", lambda *, plan_digest, confirmation: calls.append(("check", (plan_digest, confirmation))) or {"status": "ok"}, raising=False)

    monkeypatch.setattr(sys, "argv", ["semantic_production_control.py", "security-history-plan"])
    assert history.main() == 0
    monkeypatch.setattr(sys, "argv", ["semantic_production_control.py", "security-history-poll", "--confirm", "POLL-SECURITY-HISTORY:digest"])
    assert history.main() == 0
    monkeypatch.setattr(sys, "argv", ["semantic_production_control.py", "security-history-check-plan"])
    assert history.main() == 0
    monkeypatch.setattr(sys, "argv", ["semantic_production_control.py", "security-history-check", "--plan-digest", "digest", "--confirm", "CHECK-SECURITY-HISTORY:digest"])
    assert history.main() == 0

    assert calls == [
        ("plan", None),
        ("poll", "POLL-SECURITY-HISTORY:digest"),
        ("check-plan", None),
        ("check", ("digest", "CHECK-SECURITY-HISTORY:digest")),
    ]


def test_security_history_cli_can_load_an_explicit_existing_dpapi_profile(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    from scripts.maintenance import semantic_production_control as history

    profile = tmp_path / "worker-supervisor.env.dpapi"
    loaded: list[tuple[Path, bool]] = []
    monkeypatch.setattr(
        history,
        "load_supervisor_environment",
        lambda *, path, override_existing: loaded.append((path, override_existing)) or {"status": "ok"},
        raising=False,
    )
    monkeypatch.setattr(history, "security_history_plan", lambda: {"status": "ok"})
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "semantic_production_control.py",
            "security-history-plan",
            "--environment-file",
            str(profile),
        ],
    )

    assert history.main() == 0
    assert loaded == [(profile.resolve(), True)]


def test_security_history_check_preserves_residual_after_queued_work_then_poll_reaches_next_chunk(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """A readback during managed work cannot strand the next frozen source page."""
    from scripts.maintenance import semantic_production_control as history

    path = tmp_path / "security-history.json"
    cohort_digest = "a" * 64
    snapshot = {
        "database_identity": {"host": "127.0.0.1", "database": "sli", "role": "owner"},
        "cohorts": {
            4727: {"high_watermark": 200, "count": 200, "cohort_digest": cohort_digest, "min_id": 1, "max_id": 200},
        },
    }
    selected = iter((tuple(range(1, 101)), tuple(range(101, 201))))
    published: list[tuple[int, ...]] = []
    manifest = _v2_history_manifest(
        history, identity=snapshot["database_identity"], cohorts=snapshot["cohorts"],
    )
    path.write_text(json.dumps(manifest), encoding="utf-8")

    monkeypatch.setattr(history, "SECURITY_HISTORY_MANIFEST_PATH", path, raising=False)
    monkeypatch.setattr(history, "_load_environment", lambda: None)
    monkeypatch.setattr(history, "_validate_security_history_admission", lambda: None, raising=False)
    snapshot_calls: list[dict[str, int]] = []
    monkeypatch.setattr(
        history,
        "_security_history_snapshot",
        lambda **kwargs: snapshot_calls.append(dict(kwargs.get("high_watermarks") or {})) or snapshot,
        raising=False,
    )
    monkeypatch.setattr(history, "session_advisory_lock", _held_lock, raising=False)
    monkeypatch.setattr(history, "_connect_admin", lambda: _Connection(_Cursor([])))
    monkeypatch.setattr(history, "select_security_history_targets", lambda *_args, **_kwargs: next(selected), raising=False)
    monkeypatch.setattr(
        history,
        "publish_semantic_candidates",
        lambda _cur, ids, **_kwargs: published.append(tuple(ids)) or {
            "scanned": len(ids), "queued": len(ids), "signal_queued": len(ids),
            "unknown_queued": 0, "unknown_suppressed": 0,
            "context_skipped": 0, "noise_skipped": 0,
        },
    )

    first_plan = history.security_history_plan()
    history.security_history_poll(confirmation=first_plan["confirmation"])
    snapshot_calls.clear()

    def queued_reconciliation(*_args: object, **_kwargs: object) -> dict[str, int]:
        return {
            "retained_count": 200, "normalized_count": 100,
            "normalization_failed": 0, "normalization_quarantined": 0,
            "outbox_queued": 100, "outbox_leased": 0, "outbox_completed": 0,
            "outbox_failed": 0, "outbox_quarantined": 0, "action_evidence_count": 0,
        }

    monkeypatch.setattr(history, "reconcile_security_history_event", queued_reconciliation)
    monkeypatch.setattr(
        history, "reconcile_security_history_context_event",
        lambda *_args, **_kwargs: {
            "retained_count": 0, "normalized_count": 0,
            "normalization_failed": 0, "normalization_quarantined": 0,
            "outbox_queued": 0, "outbox_leased": 0, "outbox_completed": 0,
            "outbox_failed": 0, "outbox_quarantined": 0, "action_evidence_count": 0,
        },
    )
    from server.sli.semantic.semantic_investigation_backfill import SecurityHistoryV2ContextReconciliation
    monkeypatch.setattr(
        history, "reconcile_security_history_v2_context_event",
        lambda *_args, **_kwargs: SecurityHistoryV2ContextReconciliation(
            current={
                "retained_count": 0, "normalized_count": 0,
                "normalization_failed": 0, "normalization_quarantined": 0,
                "outbox_queued": 0, "outbox_leased": 0, "outbox_completed": 0,
                "outbox_failed": 0, "outbox_quarantined": 0, "action_evidence_count": 0,
            },
            repair_states={state: 0 for state in (
                "absent", "queued", "leased", "completed", "failed", "quarantined", "conflict",
            )},
        ),
    )
    queued_plan = history.security_history_check_plan()
    result = history.security_history_check(
        plan_digest=queued_plan["plan_digest"], confirmation=queued_plan["confirmation"],
    )
    assert result["terminal_success"] is False
    assert json.loads(path.read_text(encoding="utf-8"))["events"]["4727"]["state"] == "queued"
    assert snapshot_calls == []

    def completed_first_page(*_args: object, **_kwargs: object) -> dict[str, int]:
        return {
            "retained_count": 200, "normalized_count": 100,
            "normalization_failed": 0, "normalization_quarantined": 0,
            "outbox_queued": 0, "outbox_leased": 0, "outbox_completed": 100,
            "outbox_failed": 0, "outbox_quarantined": 0, "action_evidence_count": 0,
        }

    monkeypatch.setattr(history, "reconcile_security_history_event", completed_first_page)
    completed_plan = history.security_history_check_plan()
    history.security_history_check(
        plan_digest=completed_plan["plan_digest"], confirmation=completed_plan["confirmation"],
    )
    assert json.loads(path.read_text(encoding="utf-8"))["events"]["4727"]["state"] == "publishing"
    history.security_history_poll(confirmation=history.security_history_plan()["confirmation"])

    assert published == [tuple(range(1, 101)), tuple(range(101, 201))]


@pytest.mark.parametrize("outbox_state", ("queued", "leased"))
def test_security_history_check_does_not_complete_current_rows_while_outbox_is_nonterminal(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, outbox_state: str,
) -> None:
    """Current normalized rows remain nonterminal until their exact outbox work settles."""
    from scripts.maintenance import semantic_production_control as history

    path = tmp_path / f"security-history-{outbox_state}.json"
    snapshot = {
        "database_identity": {"host": "127.0.0.1", "database": "sli", "role": "owner"},
        "cohorts": {4727: {"high_watermark": 1, "count": 1, "cohort_digest": "a" * 64, "min_id": 1, "max_id": 1}},
    }
    manifest = history.new_security_history_manifest(
        database_identity=snapshot["database_identity"],
        cohorts=snapshot["cohorts"], plan_digest=history._security_history_plan_digest(snapshot),
    )
    manifest["events"]["4727"].update({"cursor": 1, "state": "queued"})
    path.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(history, "SECURITY_HISTORY_MANIFEST_PATH", path, raising=False)
    monkeypatch.setattr(history, "_load_environment", lambda: None)
    monkeypatch.setattr(history, "_security_history_snapshot", lambda **_kwargs: snapshot, raising=False)
    monkeypatch.setattr(history, "session_advisory_lock", _held_lock, raising=False)
    monkeypatch.setattr(history, "_connect_admin", lambda: _Connection(_Cursor([])))

    def reconciliation(_cur: object, *, event_id: int, high_watermark: int) -> dict[str, int]:
        if event_id != 4727:
            return {name: 0 for name in (
                "retained_count", "normalized_count", "normalization_failed", "normalization_quarantined",
                "outbox_queued", "outbox_leased", "outbox_completed", "outbox_failed",
                "outbox_quarantined", "action_evidence_count",
            )}
        return {
            "retained_count": 1, "normalized_count": 1,
            "normalization_failed": 0, "normalization_quarantined": 0,
            "outbox_queued": 1 if outbox_state == "queued" else 0,
            "outbox_leased": 1 if outbox_state == "leased" else 0,
            "outbox_completed": 0, "outbox_failed": 0,
            "outbox_quarantined": 0, "action_evidence_count": 1,
        }

    monkeypatch.setattr(history, "reconcile_security_history_event", reconciliation)
    plan = history.security_history_check_plan()
    result = history.security_history_check(plan_digest=plan["plan_digest"], confirmation=plan["confirmation"])

    assert result["terminal_success"] is False
    assert json.loads(path.read_text(encoding="utf-8"))["events"]["4727"]["state"] == {
        "queued": "queued", "leased": "processing",
    }[outbox_state]


def test_security_history_check_rejects_confirmation_stale_inside_controller_lock(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """A plan observed before a concurrent poll cannot write a readback for its newer manifest."""
    from scripts.maintenance import semantic_production_control as history

    path = tmp_path / "security-history.json"
    snapshot = {
        "database_identity": {"host": "127.0.0.1", "database": "sli", "role": "owner"},
        "cohorts": {4727: {"high_watermark": 1, "count": 1, "cohort_digest": "a" * 64, "min_id": 1, "max_id": 1}},
    }
    manifest = history.new_security_history_manifest(
        database_identity=snapshot["database_identity"],
        cohorts=snapshot["cohorts"], plan_digest=history._security_history_plan_digest(snapshot),
    )
    path.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(history, "SECURITY_HISTORY_MANIFEST_PATH", path, raising=False)
    monkeypatch.setattr(history, "_load_environment", lambda: None)
    monkeypatch.setattr(history, "_security_history_snapshot", lambda **_kwargs: snapshot, raising=False)
    monkeypatch.setattr(history, "_connect_admin", lambda: _Connection(_Cursor([])))
    plan = history.security_history_check_plan()

    @contextmanager
    def mutate_manifest_inside_lock(*_args: object, **_kwargs: object) -> Iterator[bool]:
        changed = json.loads(path.read_text(encoding="utf-8"))
        changed["events"]["4727"]["state"] = "publishing"
        path.write_text(json.dumps(changed), encoding="utf-8")
        yield True

    monkeypatch.setattr(history, "session_advisory_lock", mutate_manifest_inside_lock, raising=False)
    monkeypatch.setattr(
        history, "reconcile_security_history_event",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("stale check must stop before reconciliation")),
    )

    with pytest.raises(RuntimeError, match="check plan changed"):
        history.security_history_check(plan_digest=plan["plan_digest"], confirmation=plan["confirmation"])


class _FactsCheckCursor:
    def __init__(self, ids: list[int]) -> None:
        self.ids = ids
        self.calls: list[tuple[str, object]] = []

    def __enter__(self) -> "_FactsCheckCursor":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, query: str, params: object = None) -> None:
        self.calls.append((query, params))

    def fetchone(self) -> dict[str, str]:
        return {"host": "127.0.0.1", "database": "sli_local", "role": "candidate_owner"}

    def fetchall(self) -> list[dict[str, int]]:
        return [{"id": value} for value in self.ids]


class _FactsCheckConnection:
    def __init__(self, cursor: _FactsCheckCursor) -> None:
        self.cursor_value = cursor

    def cursor(self) -> _FactsCheckCursor:
        return self.cursor_value

    @contextmanager
    def transaction(self):
        yield

    def __enter__(self) -> "_FactsCheckConnection":
        return self

    def __exit__(self, *_args: object) -> None:
        return None


def _configure_facts_check_plan(
    monkeypatch: pytest.MonkeyPatch, ids: list[int]
) -> _FactsCheckCursor:
    cursor = _FactsCheckCursor(ids)
    monkeypatch.setattr(control, "_load_environment", lambda: None)
    monkeypatch.setattr(control, "_facts_rules_fingerprint", lambda: "rules-v1")
    monkeypatch.setattr(control, "_connect_admin", lambda: _FactsCheckConnection(cursor))
    return cursor


def test_facts_check_plan_rejects_invalid_or_duplicate_ids_before_environment_or_db(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        control,
        "_load_environment",
        lambda: (_ for _ in ()).throw(AssertionError("invalid IDs must fail before DPAPI/environment")),
    )

    for invalid in ([0], [-7], [7, 7], list(range(1, 18))):
        with pytest.raises(RuntimeError, match="facts check IDs"):
            control.facts_check_plan(invalid)


def test_facts_check_plan_is_read_only_and_binds_exact_ids_rules_and_caller_database(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cursor = _configure_facts_check_plan(monkeypatch, [517547, 517548, 517549])
    manifest_path = tmp_path / "facts-check.json"
    monkeypatch.setattr(control, "FACTS_CHECK_MANIFEST_PATH", manifest_path, raising=False)

    plan = control.facts_check_plan([517547, 517548, 517549])

    assert plan["event_ids"] == [517547, 517548, 517549]
    assert plan["rules_fingerprint"] == "rules-v1"
    assert plan["database_identity"] == {
        "host": "127.0.0.1", "database": "sli_local", "role": "candidate_owner"
    }
    assert plan["confirmation"] == "CHECK-STAGE8-EXACT-FACTS:" + plan["plan_digest"]
    assert not manifest_path.exists()
    assert any(params == ([517547, 517548, 517549],) for _query, params in cursor.calls)


def test_facts_check_rejects_wrong_confirmation_before_durable_intent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _configure_facts_check_plan(monkeypatch, [7])
    manifest_path = tmp_path / "facts-check.json"
    monkeypatch.setattr(control, "FACTS_CHECK_MANIFEST_PATH", manifest_path, raising=False)
    plan = control.facts_check_plan([7])
    monkeypatch.setattr(
        control,
        "_load_environment",
        lambda: (_ for _ in ()).throw(AssertionError("bad confirmation must not load credentials")),
    )

    with pytest.raises(RuntimeError, match="exact facts check confirmation required"):
        control.facts_check([7], plan_digest=plan["plan_digest"], confirmation="wrong")

    assert not manifest_path.exists()


def test_facts_check_publishes_and_consumes_only_planned_ids_under_production_lock(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _configure_facts_check_plan(monkeypatch, [7, 8])
    manifest_path = tmp_path / "facts-check.json"
    monkeypatch.setattr(control, "FACTS_CHECK_MANIFEST_PATH", manifest_path, raising=False)
    plan = control.facts_check_plan([7, 8])
    published: list[tuple[list[int], bool]] = []
    runtime_calls: list[dict[str, object]] = []
    lock_names: list[str] = []
    sequence: list[str] = []

    @contextmanager
    def credentials():
        yield "adlog_semantic_runtime_test"

    @contextmanager
    def lock(_factory: object, name: str, **_kwargs: object):
        lock_names.append(name)
        sequence.append("lock-enter")
        try:
            yield True
        finally:
            sequence.append("lock-exit")

    monkeypatch.setenv("ADLOG_SEMANTIC_PRODUCTION_ENABLED", "0")
    monkeypatch.setattr(control, "ephemeral_worker_environment", credentials, raising=False)
    monkeypatch.setattr(control, "session_advisory_lock", lock)
    monkeypatch.setattr(control, "_archive_reader", lambda: object())
    monkeypatch.setattr(
        control,
        "publish_semantic_candidates",
        lambda _cur, ids, *, include_context: sequence.append("publish")
        or published.append((list(ids), include_context)) or {"scanned": 2, "queued": 2},
    )
    monkeypatch.setattr(
        control,
        "run_production_once",
        lambda **kwargs: sequence.append("consume") or runtime_calls.append(kwargs) or {
            "status": "ok", "runtime_mode": "facts-v1", "processing": {"completed": 2, "failed": 0},
            "dispatch": {"completed": 0, "failed": 0, "relations": 0},
            "risk_queued": 0, "findings_created": 0,
        },
        raising=False,
    )
    monkeypatch.setattr(
        control,
        "_facts_check_queue_status",
        lambda _ids: {"completed": 2, "queued": 0, "failed": 0, "leased": 0, "not_enqueued": 0},
        raising=False,
    )

    result = control.facts_check(
        [7, 8], plan_digest=plan["plan_digest"], confirmation=plan["confirmation"]
    )

    assert published == [([7, 8], True)]
    assert runtime_calls[0]["source_event_ids"] == (7, 8)
    assert runtime_calls[0]["limit"] == 2
    assert lock_names == [control.PRODUCTION_WORKER_LOCK_NAME]
    assert sequence == ["lock-enter", "publish", "consume", "lock-exit"]
    assert result["state"] == "processed"
    assert result["result"]["runtime"]["findings_created"] == 0
    assert os.environ["ADLOG_SEMANTIC_PRODUCTION_ENABLED"] == "0"


def test_facts_check_reports_no_admitted_events_instead_of_processed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _configure_facts_check_plan(monkeypatch, [7])
    manifest_path = tmp_path / "facts-check.json"
    monkeypatch.setattr(control, "FACTS_CHECK_MANIFEST_PATH", manifest_path, raising=False)
    plan = control.facts_check_plan([7])

    @contextmanager
    def credentials():
        yield "adlog_semantic_runtime_test"

    @contextmanager
    def lock(*_args: object, **_kwargs: object):
        yield True

    monkeypatch.setattr(control, "ephemeral_worker_environment", credentials, raising=False)
    monkeypatch.setattr(control, "session_advisory_lock", lock)
    monkeypatch.setattr(control, "_archive_reader", lambda: object())
    monkeypatch.setattr(control, "publish_semantic_candidates", lambda *_args, **_kwargs: {"scanned": 1, "signal_queued": 0, "unknown_queued": 0})
    monkeypatch.setattr(control, "run_production_once", lambda **_kwargs: {"status": "ok", "runtime_mode": "facts-v1", "processing": {"completed": 0, "failed": 0}, "findings_created": 0}, raising=False)
    monkeypatch.setattr(control, "_facts_check_queue_status", lambda _ids: {"completed": 0, "queued": 0, "failed": 0, "leased": 0, "not_enqueued": 1}, raising=False)

    result = control.facts_check([7], plan_digest=plan["plan_digest"], confirmation=plan["confirmation"])

    assert result["state"] == "no_admitted_events"


def test_facts_check_never_marks_quarantined_exact_job_as_processed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _configure_facts_check_plan(monkeypatch, [7])
    manifest_path = tmp_path / "facts-check.json"
    monkeypatch.setattr(control, "FACTS_CHECK_MANIFEST_PATH", manifest_path, raising=False)
    plan = control.facts_check_plan([7])

    @contextmanager
    def credentials():
        yield "adlog_semantic_runtime_test"

    @contextmanager
    def lock(*_args: object, **_kwargs: object):
        yield True

    monkeypatch.setattr(control, "ephemeral_worker_environment", credentials, raising=False)
    monkeypatch.setattr(control, "session_advisory_lock", lock)
    monkeypatch.setattr(control, "_archive_reader", lambda: object())
    monkeypatch.setattr(control, "publish_semantic_candidates", lambda *_args, **_kwargs: {"scanned": 1, "queued": 0})
    monkeypatch.setattr(control, "run_production_once", lambda **_kwargs: {"status": "ok", "runtime_mode": "facts-v1", "processing": {"completed": 0, "failed": 0}, "findings_created": 0}, raising=False)
    monkeypatch.setattr(control, "_facts_check_queue_status", lambda _ids: {"completed": 0, "queued": 0, "failed": 0, "leased": 0, "quarantined": 1, "not_enqueued": 0}, raising=False)

    result = control.facts_check([7], plan_digest=plan["plan_digest"], confirmation=plan["confirmation"])

    assert result["state"] == "partial"
    assert json.loads(manifest_path.read_text(encoding="utf-8"))["state"] == "partial"


def test_facts_check_cli_requires_exact_ids_digest_and_confirmation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[list[int], str, str | None]] = []
    monkeypatch.setattr(
        control,
        "facts_check",
        lambda ids, *, plan_digest, confirmation: calls.append(
            (list(ids), plan_digest, confirmation)
        ) or {"status": "ok"},
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "semantic_production_control.py", "facts-check",
            "--event-id", "7", "--event-id", "8",
            "--plan-digest", "digest", "--confirm", "CHECK-STAGE8-EXACT-FACTS:digest",
        ],
    )

    assert control.main() == 0
    assert calls == [([7, 8], "digest", "CHECK-STAGE8-EXACT-FACTS:digest")]


def test_facts_check_keeps_same_intent_after_partial_result_and_never_uses_global_poll(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _configure_facts_check_plan(monkeypatch, [7])
    manifest_path = tmp_path / "facts-check.json"
    monkeypatch.setattr(control, "FACTS_CHECK_MANIFEST_PATH", manifest_path, raising=False)
    plan = control.facts_check_plan([7])

    @contextmanager
    def credentials():
        yield "adlog_semantic_runtime_test"

    @contextmanager
    def lock(*_args: object, **_kwargs: object):
        yield True

    monkeypatch.setattr(control, "ephemeral_worker_environment", credentials, raising=False)
    monkeypatch.setattr(control, "session_advisory_lock", lock)
    monkeypatch.setattr(control, "_archive_reader", lambda: object())
    monkeypatch.setattr(control, "publish_semantic_candidates", lambda *_args, **_kwargs: {"scanned": 1, "queued": 1})
    monkeypatch.setattr(
        control,
        "run_production_once",
        lambda **_kwargs: {"status": "partial", "runtime_mode": "facts-v1", "processing": {"completed": 0, "failed": 1}, "findings_created": 0},
        raising=False,
    )
    monkeypatch.setattr(control, "_facts_check_queue_status", lambda _ids: {"completed": 0, "queued": 0, "failed": 1, "leased": 0, "not_enqueued": 0}, raising=False)
    monkeypatch.setattr(control, "facts_poll", lambda: (_ for _ in ()).throw(AssertionError("exact check must not call global facts poll")))

    result = control.facts_check(
        [7], plan_digest=plan["plan_digest"], confirmation=plan["confirmation"]
    )

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert result["state"] == "partial"
    assert manifest["event_ids"] == [7]
    assert manifest["state"] == "partial"

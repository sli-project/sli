from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import sys

import pytest


def _manifest() -> dict[str, object]:
    return {
        "manifest_type": "security_history_v2",
        "plan_digest": "a" * 64,
        "database_identity": {"host": "127.0.0.1", "database": "sli", "role": "runtime"},
        "events": {"4624": {"count": 260, "high_watermark": 300, "cohort_digest": "0" * 64}},
    }


def _row() -> dict[str, object]:
    return {
        "original_job_id": "12345678-1234-5678-1234-567812345678",
        "source_event_id": 260,
        "original_source_hash": "b" * 64,
        "original_attempt_count": 5,
        "original_max_attempts": 5,
        "original_error_code": "UniqueViolation",
        "original_error_detail_sha256": "c" * 64,
    }


def _context() -> dict[str, object]:
    return {"count": 260, "cohort_digest": "d" * 64, "reset_high_watermark": 99}


def test_semantic_worker_release_fingerprint_is_stable_and_hex() -> None:
    from server.sli.semantic.semantic_worker_contract import semantic_worker_release_fingerprint, _normalized_source_bytes

    fingerprint = semantic_worker_release_fingerprint()

    assert fingerprint == semantic_worker_release_fingerprint()
    assert len(fingerprint) == 64
    assert set(fingerprint) <= set("0123456789abcdef")
    assert _normalized_source_bytes(b"one\r\ntwo\rthree\nfour") == b"one\ntwo\nthree\nfour"


def test_semantic_worker_release_fingerprint_binds_scope_critical_sources(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    from server.sli.semantic import semantic_worker_contract as contract

    source_root = Path(contract.__file__).resolve().parents[3]
    for source_name in contract._SOURCE_NAMES:
        target = tmp_path / source_name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((source_root / source_name).read_bytes())

    fingerprint = contract.semantic_worker_release_fingerprint(root=tmp_path)
    worker = tmp_path / "scripts/runtime/semantic_production_worker.py"
    worker.write_bytes(worker.read_bytes() + b"\n# release-fingerprint mutation\n")

    assert contract.semantic_worker_release_fingerprint(root=tmp_path) != fingerprint
    fingerprint = contract.semantic_worker_release_fingerprint(root=tmp_path)
    contract_source = tmp_path / "server/sli/semantic/semantic_worker_contract.py"
    contract_source.write_bytes(contract_source.read_bytes() + b"\n# contract mutation\n")

    assert contract.semantic_worker_release_fingerprint(root=tmp_path) != fingerprint


def test_v2_controller_and_worker_use_the_same_source_transaction_lock() -> None:
    from scripts.maintenance import semantic_production_control as control
    from server.sli.semantic import semantic_worker_runtime as worker

    assert "lock_semantic_sources" in control.__dict__
    assert "lock_semantic_source" in worker.__dict__


def test_security_history_database_identity_uses_session_principal_across_set_role() -> None:
    from scripts.maintenance import semantic_production_control as control

    queries: list[str] = []

    class Cursor:
        def execute(self, query: str) -> None:
            queries.append(query)

        def fetchone(self):
            return {"host": "127.0.0.1", "database": "sli", "role": "admin_login"}

    assert control._security_history_database_identity(Cursor()) == {
        "host": "127.0.0.1", "database": "sli", "role": "admin_login",
    }
    assert "session_user as role" in queries[0]
    assert "current_user as role" not in queries[0]


def test_source_transaction_lock_is_deterministic_and_uses_postgres_xact_lock() -> None:
    from server.sli.semantic.semantic_processing_repository import lock_semantic_source
    from scripts.maintenance import semantic_production_control as control

    calls: list[tuple[str, tuple[object, ...]]] = []

    class Cursor:
        def execute(self, sql: str, params: tuple[object, ...]) -> None:
            calls.append((sql, params))

    cursor = Cursor()
    control.lock_semantic_sources(cursor, [3, 1, 3, 2])

    assert [params[0] for _, params in calls] == ["semantic_source:1", "semantic_source:2", "semantic_source:3"]
    assert all("pg_advisory_xact_lock" in sql for sql, _ in calls)
    lock_semantic_source(cursor, source_event_id=4)


def test_v2_worker_gate_locks_the_fresh_heartbeat_row(monkeypatch: pytest.MonkeyPatch) -> None:
    from scripts.maintenance import semantic_production_control as control

    monkeypatch.setattr(control, "semantic_worker_release_fingerprint", lambda: "f" * 64)
    queries: list[str] = []

    class Cursor:
        def execute(self, sql: str) -> None:
            queries.append(sql)

        def fetchone(self):
            return {"details_json": {
                "runtime_mode": control.INVESTIGATION_MODE,
                "manual_runtime": False,
                "repair_scope": {
                    "job_kind": "semantic_v2_quarantine_repair",
                    "repair_plan_digest": "a" * 64,
                },
                "processing_contract": {
                    "release_fingerprint": "f" * 64,
                    "claim_protocol_version": 1,
                    "semantic_contract_version": control.SEMANTIC_CONTRACT_VERSION,
                    "processor_id": control.PROCESSOR_ID,
                    "processor_version": control.PROCESSOR_VERSION,
                    "normalizer": {"id": control.NORMALIZER_ID, "version": control.NORMALIZER_VERSION},
                    "assembler": {"id": control.ASSEMBLER_ID, "version": control.ASSEMBLER_VERSION},
                },
            }}

    control._require_v2_repair_worker(Cursor(), repair_plan_digest="a" * 64)

    assert "for share" in queries[0].lower()


def test_managed_worker_heartbeat_advertises_release_fingerprint() -> None:
    from scripts.runtime import semantic_production_worker as worker
    from server.sli.semantic.semantic_worker_contract import semantic_worker_release_fingerprint

    details = worker._details(limit=1, runtime_mode="investigation-v1")

    assert details["processing_contract"]["release_fingerprint"] == semantic_worker_release_fingerprint()


def test_v2_repair_digest_is_stable_and_binds_terminal_error_hash() -> None:
    from scripts.maintenance import semantic_production_control as control

    first = control._security_history_v2_quarantine_repair_digest(_manifest(), [_row()], _context())
    changed = _row()
    changed["original_error_detail_sha256"] = "e" * 64

    assert first == control._security_history_v2_quarantine_repair_digest(_manifest(), [_row()], _context())
    assert first != control._security_history_v2_quarantine_repair_digest(_manifest(), [changed], _context())


def test_v2_controller_keeps_all_current_normalization_and_raw_cohorts_in_the_gate() -> None:
    from scripts.maintenance import semantic_production_control as control

    source = control._security_history_v2_quarantine_rows.__code__.co_consts
    rendered = "\n".join(value for value in source if isinstance(value, str))

    assert "processing_status='normalized'" not in rendered
    assert "originals are missing, extra, or duplicate" in rendered


def test_v2_repair_digest_binds_all_frozen_raw_cohorts() -> None:
    from scripts.maintenance import semantic_production_control as control

    manifest = _manifest()
    manifest["events"] = {"4624": {"count": 260, "high_watermark": 300, "cohort_digest": "0" * 64}}
    first = control._security_history_v2_quarantine_repair_digest(manifest, [_row()], _context())
    manifest["events"]["4624"]["count"] = 261

    assert first != control._security_history_v2_quarantine_repair_digest(manifest, [_row()], _context())


@pytest.mark.parametrize("originals,normalized,error", [
    ([
        {"source_event_id": 1, "original_job_id": "a"},
        {"source_event_id": 1, "original_job_id": "b"},
    ], [], "missing, extra, or duplicate"),
    ([
        {"source_event_id": 1, "original_job_id": "a"},
        {"source_event_id": 2, "original_job_id": "b"},
    ], [{"source_event_id": 1, "normalized_count": 1}], "already normalized"),
])
def test_v2_selection_fails_closed_for_duplicate_originals_or_any_current_normalization(
    monkeypatch: pytest.MonkeyPatch, originals, normalized, error: str,
) -> None:
    from scripts.maintenance import semantic_production_control as control

    monkeypatch.setattr(control, "_security_history_v2_quarantine_snapshot", lambda *_args: ([(1, "a" * 64), (2, "b" * 64)], _context()))

    class Cursor:
        calls = 0

        def execute(self, *_args, **_kwargs):
            self.calls += 1

        def fetchall(self):
            return originals if self.calls == 1 else normalized

    with pytest.raises(RuntimeError, match=error):
        control._security_history_v2_quarantine_rows(Cursor(), _manifest())


def test_v2_apply_rejects_bad_confirmation_before_lock_or_write(monkeypatch: pytest.MonkeyPatch) -> None:
    from scripts.maintenance import semantic_production_control as control

    monkeypatch.setattr(control, "security_history_v2_quarantine_repair_plan", lambda: {
        "repair_plan_digest": "f" * 64,
        "confirmation": "REPAIR-SECURITY-HISTORY-V2-QUARANTINE:" + "f" * 64,
    })
    monkeypatch.setattr(control, "session_advisory_lock", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("lock must not be opened")))

    with pytest.raises(RuntimeError, match="confirmation"):
        control.security_history_v2_quarantine_repair(plan_digest="f" * 64, confirmation="wrong")


def test_v2_apply_rejects_busy_lock_without_writes(monkeypatch: pytest.MonkeyPatch) -> None:
    from scripts.maintenance import semantic_production_control as control

    digest = "f" * 64
    monkeypatch.setattr(control, "security_history_v2_quarantine_repair_plan", lambda: {
        "repair_plan_digest": digest,
        "confirmation": control.SECURITY_HISTORY_V2_QUARANTINE_REPAIR_CONFIRM_PREFIX + digest,
    })

    @contextmanager
    def busy_lock(*_args, **_kwargs):
        yield False

    monkeypatch.setattr(control, "session_advisory_lock", busy_lock)
    monkeypatch.setattr(control, "_connect_admin", lambda: (_ for _ in ()).throw(AssertionError("database must not be opened")))

    with pytest.raises(RuntimeError, match="lock is busy"):
        control.security_history_v2_quarantine_repair(
            plan_digest=digest,
            confirmation=control.SECURITY_HISTORY_V2_QUARANTINE_REPAIR_CONFIRM_PREFIX + digest,
        )


def test_v2_cli_uses_explicit_main_frozen_manifest_only_for_v2_plan(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    from scripts.maintenance import semantic_production_control as control

    # Main is resolved by the code (checkout layout dependent); pin it to a fake Main root
    # holding the manifest so the test does not depend on where the worktree lives.
    monkeypatch.setattr(control, "_main_checkout_root", lambda: tmp_path)
    main_manifest = tmp_path / "artifacts" / "stage8" / "evidence" / "retained-security-history-vocabulary.json"
    main_manifest.parent.mkdir(parents=True)
    main_manifest.write_text("{}", encoding="utf-8")
    original_manifest = control.SECURITY_HISTORY_MANIFEST_PATH
    seen: list[Path] = []
    monkeypatch.setattr(
        control,
        "security_history_v2_quarantine_repair_plan",
        lambda: seen.append(control.SECURITY_HISTORY_MANIFEST_PATH) or {"status": "ok"},
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "semantic_production_control.py",
            "security-history-v2-quarantine-repair-plan",
            "--frozen-security-history-manifest",
            str(main_manifest),
        ],
    )

    assert control.main() == 0
    assert seen == [main_manifest.resolve()]
    assert control.SECURITY_HISTORY_MANIFEST_PATH == original_manifest


def test_frozen_manifest_flag_is_rejected_before_any_non_v2_action(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    from scripts.maintenance import semantic_production_control as control

    main_manifest = control.ROOT.parents[1] / "artifacts" / "stage8" / "evidence" / "retained-security-history-vocabulary.json"
    monkeypatch.setattr(
        control,
        "security_history_plan",
        lambda: (_ for _ in ()).throw(AssertionError("non-v2 plan must not run")),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "semantic_production_control.py",
            "security-history-plan",
            "--frozen-security-history-manifest",
            str(main_manifest),
        ],
    )

    assert control.main() == 1
    assert "frozen_security_history_manifest_requires_v2_quarantine_repair" in capsys.readouterr().out


def test_v2_cli_rejects_non_main_frozen_manifest_before_controller_action(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    from scripts.maintenance import semantic_production_control as control

    foreign_manifest = tmp_path / "retained-security-history-vocabulary.json"
    foreign_manifest.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        control,
        "security_history_v2_quarantine_repair_plan",
        lambda: (_ for _ in ()).throw(AssertionError("controller action must not run")),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "semantic_production_control.py",
            "security-history-v2-quarantine-repair-plan",
            "--frozen-security-history-manifest",
            str(foreign_manifest),
        ],
    )

    assert control.main() == 1


def test_v2_apply_exact_replay_is_idempotent_and_conflicts_fail_before_enqueue(monkeypatch: pytest.MonkeyPatch) -> None:
    from scripts.maintenance import semantic_production_control as control

    manifest = _manifest()
    manifest["manifest_type"] = control.SECURITY_HISTORY_MANIFEST_TYPE_V2
    rows, context = [_row()], _context()
    digest = control._security_history_v2_quarantine_repair_digest(manifest, rows, context)
    jobs: list[dict[str, object]] = []
    enqueued: list[dict[str, object]] = []
    queries: list[str] = []

    class Cursor:
        def execute(self, _sql: str, _params: object = ()) -> None:
            queries.append(_sql)

        def fetchall(self):
            return [{"payload_json": item["payload"]} for item in jobs]

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def cursor(self):
            return cursor_context(Cursor())

        def transaction(self):
            return cursor_context(self)

    @contextmanager
    def cursor_context(value):
        yield value

    @contextmanager
    def lock(*_args, **_kwargs):
        yield True

    def enqueue(_cur, **kwargs):
        enqueued.append(kwargs)
        jobs.append({"payload": kwargs["payload"]})
        return "new-job"

    monkeypatch.setattr(control, "security_history_v2_quarantine_repair_plan", lambda: {
        "repair_plan_digest": digest,
        "confirmation": control.SECURITY_HISTORY_V2_QUARANTINE_REPAIR_CONFIRM_PREFIX + digest,
    })
    monkeypatch.setattr(control, "session_advisory_lock", lock)
    monkeypatch.setattr(control, "_validate_security_history_admission", lambda: None)
    monkeypatch.setattr(
        control,
        "_require_v2_repair_worker",
        lambda _cur=None, **_kwargs: None,
    )
    monkeypatch.setattr(control, "_read_security_history_manifest", lambda: manifest)
    monkeypatch.setattr(control, "_connect_admin", Connection)
    monkeypatch.setattr(control, "_security_history_current_database_identity", lambda: manifest["database_identity"])
    monkeypatch.setattr(control, "validate_security_history_manifest", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(control, "_require_migration143", lambda _cur: None)
    monkeypatch.setattr(control, "_security_history_v2_quarantine_snapshot", lambda *_args: ([(260, "b" * 64)], context))
    monkeypatch.setattr(control, "_security_history_v2_quarantine_rows", lambda _cur, _manifest: (rows, context))
    monkeypatch.setattr(control, "enqueue_semantic_job", enqueue)

    first = control.security_history_v2_quarantine_repair(plan_digest=digest, confirmation=control.SECURITY_HISTORY_V2_QUARANTINE_REPAIR_CONFIRM_PREFIX + digest)
    second = control.security_history_v2_quarantine_repair(plan_digest=digest, confirmation=control.SECURITY_HISTORY_V2_QUARANTINE_REPAIR_CONFIRM_PREFIX + digest)

    assert first["newly_queued"] == 1
    assert second["newly_queued"] == 0
    assert len(enqueued) == 2
    assert any("set local role adlog_storage_worker" in query for query in queries)
    jobs[0]["payload"] = {"unexpected": "conflict"}
    before = len(enqueued)
    with pytest.raises(RuntimeError, match="conflicts"):
        control.security_history_v2_quarantine_repair(plan_digest=digest, confirmation=control.SECURITY_HISTORY_V2_QUARANTINE_REPAIR_CONFIRM_PREFIX + digest)
    assert len(enqueued) == before

"""Disposable PostgreSQL proof for the V2 quarantine-repair transaction boundary.

These checks intentionally use real PostgreSQL transactions and advisory locks.
They are limited to a schema-only ``sli_test_*`` database and synthetic event
rows; no retained event, worker, source or production database is contacted.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from urllib.parse import unquote, urlsplit

import pytest

from server.sli.semantic.semantic_processing import (
    NormalizedEvent,
    assemble_canonical_actions,
)
from server.sli.semantic.semantic_processing_repository import (
    SEMANTIC_V2_QUARANTINE_REPAIR_JOB_KIND,
    claim_semantic_jobs,
    enqueue_semantic_job,
    persist_canonical_actions,
    persist_normalized_event,
)
from server.sli.semantic.semantic_worker_contract import (
    semantic_worker_release_fingerprint,
)
from server.sli.semantic.semantic_worker_runtime import (
    lock_semantic_source as worker_lock_semantic_source,
)
from tests.migrations.historical_postgres import historical_connection
from tests.postgres_integration_guard import assert_disposable_database

ROOT = Path(__file__).resolve().parents[2]
MIGRATION_143 = ROOT / "config/postgres_migrations/143_semantic_v2_quarantine_repair.sql"


def _test_dsn() -> str:
    dsn = (os.environ.get("ADLOG_TEST_PG_DSN") or "").strip()
    if not dsn:
        pytest.skip("ADLOG_TEST_PG_DSN is not configured for disposable PostgreSQL tests")
    parsed = urlsplit(dsn)
    database = unquote(parsed.path).lstrip("/") if parsed.scheme else ""
    if not database:
        matched = re.search(r"(?:^|\s)dbname=(?:'([^']+)'|\"([^\"]+)\"|(\S+))", dsn)
        database = next((item for item in (matched.groups() if matched else ()) if item), "")
    if not database.startswith("sli_test_"):
        pytest.skip("ADLOG_TEST_PG_DSN must name a disposable sli_test_* database")
    return dsn


@pytest.fixture
def current_connect():
    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row

    dsn = _test_dsn()

    def _connect():
        return psycopg.connect(dsn, row_factory=dict_row)

    with _connect() as conn:
        assert_disposable_database(conn)
    return _connect



@pytest.fixture
def historical_connect(tmp_path, monkeypatch):
    import psycopg
    from psycopg.rows import dict_row

    # Migration 372 retires the event table used by the legacy repair control.
    # Worker, controller and observer connections must share this owned database.
    with historical_connection(tmp_path, monkeypatch, (371, "password_domain_auto")) as conn:
        with conn.transaction():
            conn.execute("set local role adlog_storage_owner")
            conn.execute(
                "insert into event_catalog_revisions(version) values ('pending-backfill') "
                "on conflict(version) do nothing"
            )
        parameters = conn.info.get_parameters()

        def connect():
            return psycopg.connect(**parameters, row_factory=dict_row)

        yield connect


def _insert_source(
    cur, *, source_event_id: int, windows_event_id: int = 4624,
    provider_value: str = "v2-repair-pg-provider",
    channel_value: str = "v2-repair-pg-channel",
    target_user_sid: str | None = None,
    keywords_value: str | None = None,
    occurred: datetime | None = None,
) -> None:
    occurred = occurred or datetime(2026, 9, 20, tzinfo=timezone.utc)
    identifiers: dict[str, int] = {}
    for table, value in {
        "storage_v2_provider": provider_value,
        "storage_v2_channel": channel_value,
        "storage_v2_computer": "v2-repair-pg-computer",
    }.items():
        cur.execute(
            f"insert into {table}(value) values (%s) on conflict(value) do update "
            f"set value=excluded.value returning id",
            (value,),
        )
        identifiers[table] = cur.fetchone()["id"]
    keywords_id = None
    if keywords_value is not None:
        cur.execute(
            """insert into storage_v2_keywords(value) values (%s)
               on conflict(value) do update set value=excluded.value returning id""",
            (keywords_value,),
        )
        keywords_id = cur.fetchone()["id"]
    cur.execute(
        """
        insert into events_v2_core(
            id,server_id,domain_id,log_source_id,event_record_id,event_id,
            keywords_id,provider_id,channel_id,computer_id,time_created_utc,target_user_sid,correlation_id,
            normalized_at,normalized_hash,source_core_sha256
        ) values (%s,1,1,1,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """,
        (
            source_event_id,
            source_event_id,
            windows_event_id,
            keywords_id,
            identifiers["storage_v2_provider"],
            identifiers["storage_v2_channel"],
            identifiers["storage_v2_computer"],
            occurred,
            target_user_sid,
            f"v2-repair-pg-{source_event_id}",
            occurred,
            b"a" * 32,
            b"b" * 32,
        ),
    )


def _apply_migration143(connect) -> None:
    """Apply only the submitted migration to the disposable schema clone."""
    with connect() as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(MIGRATION_143.read_text(encoding="utf-8"), prepare=False)

def _repair_payload(*, source_event_id: int, original_job_id: str) -> dict[str, object]:
    return {
        "repair_plan_digest": "c" * 64,
        "history_plan_digest": "d" * 64,
        "original_source_hash": ("61" * 32),
        "original_job_id": original_job_id,
        "original_attempt_count": 5,
        "original_max_attempts": 5,
        "original_error_code": "UniqueViolation",
        "original_error_detail_sha256": sha256(
            b'duplicate key value violates unique constraint "canonical_actions_pkey"'
        ).hexdigest(),
    }


def _insert_terminal_original(cur, *, source_event_id: int) -> str:
    cur.execute("set local role adlog_storage_worker")
    original_id = enqueue_semantic_job(cur, source_event_id=source_event_id)
    cur.execute(
        """update semantic_processing_outbox set status='quarantined',attempt_count=5,
               max_attempts=5,last_error_code='UniqueViolation',
               last_error_detail=%s where job_id=%s""",
        ('duplicate key value violates unique constraint "canonical_actions_pkey"', original_id),
    )
    return original_id


def _terminal_original_snapshot(cur, *, source_event_ids: tuple[int, ...]) -> list[dict[str, object]]:
    """Read the immutable original rows without relying on controller output."""
    cur.execute(
        """select to_jsonb(outbox) as row
           from semantic_processing_outbox
           as outbox
           where source_event_id=any(%s) and job_kind='normalize_event'
           order by source_event_id,job_id""",
        (list(source_event_ids),),
    )
    return [dict(row)["row"] for row in cur.fetchall()]


@pytest.mark.postgres_integration
def test_public_v2_quarantine_repair_controls_queue_exact_260_without_mutating_originals(
    historical_connect, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """Exercise public plan/repair controls against only a synthetic 260-row cohort."""
    from scripts.maintenance import semantic_production_control as control
    from server.sli.semantic.semantic_investigation_backfill import (
        new_security_history_manifest_v2,
        security_history_cohorts,
        security_history_context_cohort,
    )

    cohort_ids = tuple(range(9_720_000, 9_720_260))
    out_of_scope_id = 9_720_260
    reset_event_id = cohort_ids[0] - 1
    source_hash = "61" * 32
    account_sid = "S-1-5-21-100-200-300-400"
    reset_at = datetime(2026, 9, 20, 12, 0, tzinfo=timezone.utc)
    login_at = reset_at + timedelta(minutes=1)
    expected_context_digest = sha256(
        "".join(f"{source_event_id}:{source_hash}\n" for source_event_id in cohort_ids).encode()
    ).hexdigest()
    with historical_connect() as conn, conn.transaction(), conn.cursor() as cur:
        cur.execute("set local role adlog_storage_owner")
        _insert_source(
            cur, source_event_id=reset_event_id, windows_event_id=4724,
            provider_value="Microsoft-Windows-Security-Auditing", channel_value="Security",
            target_user_sid=account_sid, keywords_value="Audit Success", occurred=reset_at,
        )
        for source_event_id in cohort_ids:
            _insert_source(
                cur, source_event_id=source_event_id,
                provider_value="Microsoft-Windows-Security-Auditing", channel_value="Security",
                target_user_sid=account_sid, occurred=login_at,
            )
            _insert_terminal_original(cur, source_event_id=source_event_id)
        _insert_source(
            cur, source_event_id=out_of_scope_id, windows_event_id=4625,
            provider_value="Microsoft-Windows-Security-Auditing", channel_value="Security",
            target_user_sid=account_sid, occurred=login_at,
        )
        _insert_terminal_original(cur, source_event_id=out_of_scope_id)
        originals_before = _terminal_original_snapshot(
            cur, source_event_ids=(*cohort_ids, out_of_scope_id),
        )
        cohorts = security_history_cohorts(cur)
        context = security_history_context_cohort(
            cur, high_watermark=cohort_ids[-1], reset_high_watermark=reset_event_id,
        )

    assert context == {
        "count": 260,
        "cohort_digest": expected_context_digest,
        "reset_high_watermark": reset_event_id,
    }
    assert cohorts[4624] == {
        "high_watermark": cohort_ids[-1], "count": 260,
        "cohort_digest": expected_context_digest,
        "min_id": cohort_ids[0], "max_id": cohort_ids[-1],
    }
    assert cohorts[4724]["high_watermark"] == reset_event_id
    assert cohorts[4724]["count"] == 1

    with historical_connect() as conn, conn.cursor() as cur:
        cur.execute(
            """select coalesce(inet_server_addr()::text,'') as host,
                      current_database() as database,current_user as role"""
        )
        database_identity = dict(cur.fetchone())
    manifest = new_security_history_manifest_v2(
        database_identity=database_identity,
        plan_digest="e" * 64,
        cohorts=cohorts,
        semantic_context_cohort=context,
        supersedes=None,
    )
    manifest_path = tmp_path / "synthetic-security-history-v2.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(control, "SECURITY_HISTORY_MANIFEST_PATH", manifest_path)
    monkeypatch.setattr(control, "_load_environment", lambda: None)
    monkeypatch.setattr(control, "_connect_admin", historical_connect)
    for name, value in {
        "ADLOG_SEMANTIC_PRODUCTION_ENABLED": "1",
        "ADLOG_SEMANTIC_RUNTIME_MODE": control.INVESTIGATION_MODE,
        "ADLOG_SEMANTIC_NORMALIZATION_ENABLED": "1",
        "ADLOG_SEMANTIC_ASSEMBLY_ENABLED": "1",
        "ADLOG_SEMANTIC_DIRECTORY_STATE_ENABLED": "0",
        "ADLOG_SEMANTIC_CORRELATION_ENABLED": "1",
        "ADLOG_SEMANTIC_RISK_ENGINE_ENABLED": "0",
        "ADLOG_SEMANTIC_FINDING_CREATION_ENABLED": "0",
    }.items():
        monkeypatch.setenv(name, value)

    plan = control.security_history_v2_quarantine_repair_plan()
    assert plan["status"] == "security_history_v2_quarantine_repair_plan_ready"
    assert plan["target_events"] == 260
    assert plan["production_changed"] is False

    with pytest.raises(RuntimeError, match="confirmation"):
        control.security_history_v2_quarantine_repair(
            plan_digest=str(plan["repair_plan_digest"]), confirmation="controlled-wrong-confirmation",
        )
    with historical_connect() as conn, conn.cursor() as cur:
        cur.execute(
            "select count(*) as value from semantic_processing_outbox where job_kind=%s",
            (SEMANTIC_V2_QUARANTINE_REPAIR_JOB_KIND,),
        )
        assert cur.fetchone()["value"] == 0

    # Controlled negative probe: a changed terminal original must stop public
    # repair before it can append even one repair job.  Restore the exact
    # synthetic original before the successful control-path call below.
    with historical_connect() as conn, conn.transaction(), conn.cursor() as cur:
        cur.execute("set local role adlog_storage_worker")
        cur.execute(
            """update semantic_processing_outbox set last_error_detail=%s
               where source_event_id=%s and job_kind='normalize_event'""",
            ("controlled-invalid-terminal-detail", cohort_ids[0]),
        )
    with pytest.raises(RuntimeError, match="original terminal contract changed"):
        control.security_history_v2_quarantine_repair(
            plan_digest=str(plan["repair_plan_digest"]), confirmation=str(plan["confirmation"]),
        )
    with historical_connect() as conn, conn.cursor() as cur:
        cur.execute(
            "select count(*) as value from semantic_processing_outbox where job_kind=%s",
            (SEMANTIC_V2_QUARANTINE_REPAIR_JOB_KIND,),
        )
        assert cur.fetchone()["value"] == 0
    with historical_connect() as conn, conn.transaction(), conn.cursor() as cur:
        cur.execute("set local role adlog_storage_worker")
        cur.execute(
            """update semantic_processing_outbox set last_error_detail=%s
               where source_event_id=%s and job_kind='normalize_event'""",
            ('duplicate key value violates unique constraint "canonical_actions_pkey"', cohort_ids[0]),
        )

    details = {
        "runtime_mode": control.INVESTIGATION_MODE,
        "manual_runtime": False,
        "repair_scope": {
            "job_kind": SEMANTIC_V2_QUARANTINE_REPAIR_JOB_KIND,
            "repair_plan_digest": plan["repair_plan_digest"],
        },
        "processing_contract": {
            "release_fingerprint": semantic_worker_release_fingerprint(),
            "claim_protocol_version": 1,
            "semantic_contract_version": control.SEMANTIC_CONTRACT_VERSION,
            "processor_id": control.PROCESSOR_ID,
            "processor_version": control.PROCESSOR_VERSION,
            "normalizer": {"id": control.NORMALIZER_ID, "version": control.NORMALIZER_VERSION},
            "assembler": {"id": control.ASSEMBLER_ID, "version": control.ASSEMBLER_VERSION},
        },
    }
    with historical_connect() as conn, conn.transaction(), conn.cursor() as cur:
        cur.execute(
            """insert into runtime_worker_heartbeats(
                worker_name,worker_id,process_pid,status,phase,expected_interval_seconds,
                details_json,started_at,heartbeat_at,updated_at
            ) values ('semantic','synthetic-v2-control',1,'idle','test',60,%s::jsonb,now(),now(),now())""",
            (json.dumps(details),),
        )

    result = control.security_history_v2_quarantine_repair(
        plan_digest=str(plan["repair_plan_digest"]), confirmation=str(plan["confirmation"]),
    )
    assert result == {
        "status": "security_history_v2_quarantine_repair_queued",
        "history_plan_digest": manifest["plan_digest"],
        "repair_plan_digest": plan["repair_plan_digest"],
        "target_events": 260,
        "newly_queued": 260,
        "production_changed": True,
        "collection_changed": False,
    }
    second = control.security_history_v2_quarantine_repair(
        plan_digest=str(plan["repair_plan_digest"]), confirmation=str(plan["confirmation"]),
    )
    assert second == {
        **result,
        "newly_queued": 0,
        "production_changed": False,
    }

    with historical_connect() as conn, conn.cursor() as cur:
        cur.execute(
            """select source_event_id,payload_json from semantic_processing_outbox
               where job_kind=%s order by source_event_id""",
            (SEMANTIC_V2_QUARANTINE_REPAIR_JOB_KIND,),
        )
        repair_rows = [dict(row) for row in cur.fetchall()]
        originals_after = _terminal_original_snapshot(
            cur, source_event_ids=(*cohort_ids, out_of_scope_id),
        )
        cur.execute(
            """select
                (select count(*) from normalized_events normalized
                 where normalized.source_event_id=any(%s)) as normalized_events,
                (select count(*) from canonical_actions action
                 join canonical_action_evidence evidence
                   on evidence.canonical_action_id=action.canonical_action_id
                 join normalized_events normalized
                   on normalized.normalized_event_id=evidence.normalized_event_id
                 where normalized.source_event_id=any(%s)) as canonical_actions,
                (select count(*) from semantic_correlation_dispatch_jobs dispatch
                 join normalized_events normalized
                   on normalized.normalized_event_id=dispatch.normalized_event_id
                 where normalized.source_event_id=any(%s)) as dispatch_jobs""",
            (list(cohort_ids), list(cohort_ids), list(cohort_ids)),
        )
        downstream = dict(cur.fetchone())
    assert [row["source_event_id"] for row in repair_rows] == list(cohort_ids)
    assert len(repair_rows) == 260
    original_id_by_source = {
        int(row["source_event_id"]): str(row["job_id"])
        for row in originals_before
    }
    expected_error_detail_sha256 = sha256(
        b'duplicate key value violates unique constraint "canonical_actions_pkey"'
    ).hexdigest()
    for row in repair_rows:
        source_event_id = int(row["source_event_id"])
        assert row["payload_json"] == {
            "repair_plan_digest": plan["repair_plan_digest"],
            "history_plan_digest": manifest["plan_digest"],
            "original_job_id": original_id_by_source[source_event_id],
            "source_event_id": source_event_id,
            "original_source_hash": source_hash,
            "original_attempt_count": 5,
            "original_max_attempts": 5,
            "original_error_code": "UniqueViolation",
            "original_error_detail_sha256": expected_error_detail_sha256,
        }
    assert originals_after == originals_before
    assert downstream == {
        "normalized_events": 0,
        "canonical_actions": 0,
        "dispatch_jobs": 0,
    }


@pytest.mark.postgres_integration
def test_v2_repair_claim_is_exactly_digest_scoped_and_ordinary_claims_skip_it(historical_connect) -> None:
    normal_source_id = 971240
    repair_source_id = 971241
    digest = "c" * 64
    with historical_connect() as conn, conn.transaction(), conn.cursor() as cur:
        _insert_source(cur, source_event_id=normal_source_id)
        _insert_source(cur, source_event_id=repair_source_id)
        cur.execute("set local role adlog_storage_worker")
        enqueue_semantic_job(cur, source_event_id=normal_source_id)
        original_id = _insert_terminal_original(cur, source_event_id=repair_source_id)
        enqueue_semantic_job(
            cur,
            source_event_id=repair_source_id,
            job_kind=SEMANTIC_V2_QUARANTINE_REPAIR_JOB_KIND,
            payload=_repair_payload(
                source_event_id=repair_source_id, original_job_id=original_id,
            ),
        )

        ordinary = claim_semantic_jobs(cur, limit=2)
        wrong_scope = claim_semantic_jobs(cur, limit=2, repair_plan_digest="d" * 64)
        scoped = claim_semantic_jobs(cur, limit=2, repair_plan_digest=digest)

    assert [row["job_kind"] for row in ordinary] == ["normalize_event"]
    assert wrong_scope == []
    assert [row["job_kind"] for row in scoped] == [SEMANTIC_V2_QUARANTINE_REPAIR_JOB_KIND]
    assert scoped[0]["payload_json"]["repair_plan_digest"] == digest


def _enqueue_completed_v2_repair(cur, *, source_event_id: int, original_job_id: str, payload: dict[str, object]) -> str:
    cur.execute("set local role adlog_storage_worker")
    repair_id = enqueue_semantic_job(
        cur,
        source_event_id=source_event_id,
        job_kind=SEMANTIC_V2_QUARANTINE_REPAIR_JOB_KIND,
        payload=payload,
    )
    cur.execute(
        """update semantic_processing_outbox set status='completed',completed_at=now(),
               updated_at=now() where job_id=%s""",
        (repair_id,),
    )
    return repair_id


def _reconcile_one_v2_context(monkeypatch, cur, *, source_event_id: int, history_plan_digest: str):
    """Keep selection synthetic; execute reconciliation lineage SQL on PostgreSQL."""
    from server.sli.semantic import semantic_investigation_backfill as backfill

    monkeypatch.setattr(
        backfill,
        "_iter_security_history_context_pairs",
        lambda *_args, **_kwargs: iter(((source_event_id, "61" * 32),)),
    )
    return backfill.reconcile_security_history_v2_context_event(
        cur,
        high_watermark=source_event_id,
        reset_high_watermark=source_event_id,
        history_plan_digest=history_plan_digest,
    )


@pytest.mark.postgres_integration
def test_v2_repair_payload_is_exact_and_real_database_replay_is_idempotent(historical_connect) -> None:
    """A payload change cannot add a second identity-only V2 repair job."""
    source_event_id = 971260
    original_id = str(uuid.uuid4())
    payload = _repair_payload(source_event_id=source_event_id, original_job_id=original_id)
    with historical_connect() as conn, conn.transaction(), conn.cursor() as cur:
        _insert_source(cur, source_event_id=source_event_id)
        cur.execute("set local role adlog_storage_worker")
        first = enqueue_semantic_job(
            cur, source_event_id=source_event_id,
            job_kind=SEMANTIC_V2_QUARANTINE_REPAIR_JOB_KIND, payload=payload,
        )
        assert enqueue_semantic_job(
            cur, source_event_id=source_event_id,
            job_kind=SEMANTIC_V2_QUARANTINE_REPAIR_JOB_KIND, payload=payload,
        ) == first
        changed = {**payload, "repair_plan_digest": "e" * 64}
        with pytest.raises(RuntimeError, match="payload conflict"), conn.transaction():
            enqueue_semantic_job(
                cur, source_event_id=source_event_id,
                job_kind=SEMANTIC_V2_QUARANTINE_REPAIR_JOB_KIND, payload=changed,
            )
        cur.execute(
            """select payload_json from semantic_processing_outbox
               where source_event_id=%s and job_kind=%s""",
            (source_event_id, SEMANTIC_V2_QUARANTINE_REPAIR_JOB_KIND),
        )
        assert cur.fetchone()["payload_json"] == payload


@pytest.mark.postgres_integration
def test_worker_source_lock_interleaving_forces_controller_recheck_and_zero_repair_rows(historical_connect, monkeypatch) -> None:
    """The controller cannot pass a stale selection after the worker normalizes it."""
    from scripts.maintenance import semantic_production_control as control

    source_event_id = 971261
    original_id: str
    with historical_connect() as conn, conn.transaction(), conn.cursor() as cur:
        _insert_source(cur, source_event_id=source_event_id)
        original_id = _insert_terminal_original(cur, source_event_id=source_event_id)

    context = {"count": 1, "cohort_digest": "f" * 64, "reset_high_watermark": 1}
    monkeypatch.setattr(
        control, "_security_history_v2_quarantine_snapshot",
        lambda _cur, _manifest: ([(source_event_id, "61" * 32)], context),
    )
    worker_has_lock = threading.Event()
    release_worker = threading.Event()
    worker_finished = threading.Event()
    worker_error: list[BaseException] = []

    def worker_transaction() -> None:
        try:
            with historical_connect() as conn, conn.transaction(), conn.cursor() as cur:
                cur.execute("set local role adlog_storage_worker")
                worker_lock_semantic_source(cur, source_event_id=source_event_id)
                worker_has_lock.set()
                assert release_worker.wait(timeout=5)
                persist_normalized_event(
                    cur,
                    event=NormalizedEvent(
                        source_event_id=source_event_id,
                        semantic_type="authentication.succeeded",
                        occurred_at_utc=datetime(2026, 9, 20, tzinfo=timezone.utc),
                        roles={"source_host": "1"},
                        facts={"synthetic": True},
                        quality={},
                        semantic_sha256="c" * 64,
                    ),
                )
        except BaseException as exc:  # noqa: BLE001 - propagate thread failure into pytest
            worker_error.append(exc)
        finally:
            worker_finished.set()

    thread = threading.Thread(target=worker_transaction, daemon=True)
    thread.start()
    assert worker_has_lock.wait(timeout=5)
    timer = threading.Timer(0.15, release_worker.set)
    timer.start()
    started = time.monotonic()
    try:
        with historical_connect() as conn, conn.transaction(), conn.cursor() as cur:
            cur.execute("set local role adlog_storage_worker")
            control.lock_semantic_sources(cur, [source_event_id])
            assert time.monotonic() - started >= 0.10
            assert worker_finished.wait(timeout=5)
            assert not worker_error
            with pytest.raises(RuntimeError, match="already normalized"):
                control._security_history_v2_quarantine_rows(cur, {"events": {"4624": {}}})
            cur.execute(
                """select count(*) as value from semantic_processing_outbox
                   where source_event_id=%s and job_kind=%s""",
                (source_event_id, SEMANTIC_V2_QUARANTINE_REPAIR_JOB_KIND),
            )
            assert cur.fetchone()["value"] == 0
    finally:
        release_worker.set()
        timer.cancel()
        thread.join(timeout=5)
    assert not thread.is_alive()
    assert not worker_error
    assert original_id


@pytest.mark.postgres_integration
def test_real_postgres_migration_and_heartbeat_gates_fail_closed(current_connect) -> None:
    """Missing/misnamed marker and stale/wrong worker proof never admit repair."""
    from scripts.maintenance import semantic_production_control as control

    fingerprint = semantic_worker_release_fingerprint()
    repair_plan_digest = "c" * 64
    _apply_migration143(current_connect)
    details = {
        "runtime_mode": control.INVESTIGATION_MODE,
        "manual_runtime": False,
        "repair_scope": {
            "job_kind": SEMANTIC_V2_QUARANTINE_REPAIR_JOB_KIND,
            "repair_plan_digest": repair_plan_digest,
        },
        "processing_contract": {
            "release_fingerprint": fingerprint,
            "claim_protocol_version": 1,
            "semantic_contract_version": control.SEMANTIC_CONTRACT_VERSION,
            "processor_id": control.PROCESSOR_ID,
            "processor_version": control.PROCESSOR_VERSION,
            "normalizer": {"id": control.NORMALIZER_ID, "version": control.NORMALIZER_VERSION},
            "assembler": {"id": control.ASSEMBLER_ID, "version": control.ASSEMBLER_VERSION},
        },
    }
    with current_connect() as conn, conn.transaction(), conn.cursor() as cur:
        cur.execute("delete from schema_migrations where version=143")
        with pytest.raises(RuntimeError, match="exact migration143"):
            control._require_migration143(cur)
        cur.execute("insert into schema_migrations(version,name) values (143,%s)", ("semantic_v2_quarantine_repair",))
        control._require_migration143(cur)
        cur.execute(
            """insert into runtime_worker_heartbeats(
                worker_name,worker_id,process_pid,status,phase,expected_interval_seconds,
                details_json,started_at,heartbeat_at,updated_at
            ) values ('semantic','synthetic-v2',1,'idle','test',60,%s::jsonb,now(),now()-interval '181 seconds',now())""",
            (json.dumps(details),),
        )
        with pytest.raises(RuntimeError, match="fresh managed worker release fingerprint"):
            control._require_v2_repair_worker(
                cur, repair_plan_digest=repair_plan_digest,
            )
        details["processing_contract"]["release_fingerprint"] = "0" * 64
        cur.execute(
            "update runtime_worker_heartbeats set heartbeat_at=now(),details_json=%s::jsonb where worker_name='semantic'",
            (json.dumps(details),),
        )
        with pytest.raises(RuntimeError, match="fresh managed worker release fingerprint"):
            control._require_v2_repair_worker(
                cur, repair_plan_digest=repair_plan_digest,
            )


@pytest.mark.postgres_integration
def test_v2_context_reconciliation_keeps_quarantined_original_without_repair_nonterminal(historical_connect, monkeypatch) -> None:
    """A real original quarantine remains explicitly absent, never implicitly complete."""
    source_event_id = 971262
    history_plan_digest = "d" * 64
    with historical_connect() as conn, conn.transaction(), conn.cursor() as cur:
        _insert_source(cur, source_event_id=source_event_id)
        _insert_terminal_original(cur, source_event_id=source_event_id)
        result = _reconcile_one_v2_context(
            monkeypatch, cur, source_event_id=source_event_id, history_plan_digest=history_plan_digest,
        )
    assert result.repair_states == {
        "absent": 1, "queued": 0, "leased": 0, "completed": 0,
        "failed": 0, "quarantined": 0, "conflict": 0,
    }
    assert result.current["normalized_count"] == 0
    assert result.current["outbox_quarantined"] == 1


@pytest.mark.postgres_integration
def test_v2_context_reconciliation_accepts_only_completed_repair_with_current_normalized_proof(historical_connect, monkeypatch) -> None:
    """Terminal success binds the exact completed V2 row to current normalized evidence."""
    source_event_id = 971263
    history_plan_digest = "d" * 64
    with historical_connect() as conn, conn.transaction(), conn.cursor() as cur:
        _insert_source(cur, source_event_id=source_event_id)
        original_id = _insert_terminal_original(cur, source_event_id=source_event_id)
        _enqueue_completed_v2_repair(
            cur,
            source_event_id=source_event_id,
            original_job_id=original_id,
            payload=_repair_payload(source_event_id=source_event_id, original_job_id=original_id),
        )
        normalized = NormalizedEvent(
            source_event_id=source_event_id,
            semantic_type="authentication.session.created",
            occurred_at_utc=datetime(2026, 9, 20, tzinfo=timezone.utc),
            roles={"source_host": "1"}, facts={"synthetic": True}, quality={},
            semantic_sha256="c" * 64,
        )
        persist_normalized_event(cur, event=normalized)
        persist_canonical_actions(cur, actions=assemble_canonical_actions((normalized,)))
        result = _reconcile_one_v2_context(
            monkeypatch, cur, source_event_id=source_event_id, history_plan_digest=history_plan_digest,
        )
    assert result.repair_states == {
        "absent": 0, "queued": 0, "leased": 0, "completed": 1,
        "failed": 0, "quarantined": 0, "conflict": 0,
    }
    assert result.current["normalized_count"] == 1


@pytest.mark.postgres_integration
def test_v2_context_reconciliation_fails_closed_for_completed_repair_without_normalized_proof(historical_connect, monkeypatch) -> None:
    """A completed repair is conflict, not success, until the exact current proof exists."""
    source_event_id = 971264
    history_plan_digest = "d" * 64
    with historical_connect() as conn, conn.transaction(), conn.cursor() as cur:
        _insert_source(cur, source_event_id=source_event_id)
        original_id = _insert_terminal_original(cur, source_event_id=source_event_id)
        _enqueue_completed_v2_repair(
            cur,
            source_event_id=source_event_id,
            original_job_id=original_id,
            payload=_repair_payload(source_event_id=source_event_id, original_job_id=original_id),
        )
        result = _reconcile_one_v2_context(
            monkeypatch, cur, source_event_id=source_event_id, history_plan_digest=history_plan_digest,
        )
    assert result.repair_states == {
        "absent": 0, "queued": 0, "leased": 0, "completed": 0,
        "failed": 0, "quarantined": 0, "conflict": 1,
    }


@pytest.mark.postgres_integration
def test_v2_context_reconciliation_fails_closed_for_conflicting_repair_payload(historical_connect, monkeypatch) -> None:
    """Current proof cannot rescue a repair whose immutable lineage digest differs."""
    source_event_id = 971265
    history_plan_digest = "d" * 64
    with historical_connect() as conn, conn.transaction(), conn.cursor() as cur:
        _insert_source(cur, source_event_id=source_event_id)
        original_id = _insert_terminal_original(cur, source_event_id=source_event_id)
        payload = _repair_payload(source_event_id=source_event_id, original_job_id=original_id)
        payload["history_plan_digest"] = "e" * 64
        _enqueue_completed_v2_repair(
            cur, source_event_id=source_event_id, original_job_id=original_id, payload=payload,
        )
        normalized = NormalizedEvent(
            source_event_id=source_event_id,
            semantic_type="authentication.session.created",
            occurred_at_utc=datetime(2026, 9, 20, tzinfo=timezone.utc),
            roles={"source_host": "1"}, facts={"synthetic": True}, quality={},
            semantic_sha256="c" * 64,
        )
        persist_normalized_event(cur, event=normalized)
        persist_canonical_actions(cur, actions=assemble_canonical_actions((normalized,)))
        result = _reconcile_one_v2_context(
            monkeypatch, cur, source_event_id=source_event_id, history_plan_digest=history_plan_digest,
        )
    assert result.repair_states == {
        "absent": 0, "queued": 0, "leased": 0, "completed": 0,
        "failed": 0, "quarantined": 0, "conflict": 1,
    }


@pytest.mark.postgres_integration
def test_security_history_check_snapshot_uses_repeatable_read_read_only_transaction(current_connect) -> None:
    """The intended check snapshot mode is accepted and observable on PostgreSQL."""
    with current_connect() as conn, conn.transaction(), conn.cursor() as cur:
        cur.execute("set transaction isolation level repeatable read, read only")
        cur.execute(
            """select current_setting('transaction_isolation') as isolation,
                      current_setting('transaction_read_only') as read_only"""
        )
        settings = cur.fetchone()
    assert settings == {"isolation": "repeatable read", "read_only": "on"}


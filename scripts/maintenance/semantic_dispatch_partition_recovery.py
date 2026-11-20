#!/usr/bin/env python3
"""Exact plan/apply recovery for the three quarantined cross-DC dispatch jobs.

This controller is deliberately source-free: it reads PostgreSQL only and calls
``process_semantic_dispatch`` with an archive trap, so an accidental hydration
path is an immediate failure rather than a source/archive read.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
from typing import Any, Mapping, Sequence
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.ops.postgres_session_lock import session_advisory_lock  # noqa: E402
from server.sli.semantic.semantic_dispatch_partition_recovery import (  # noqa: E402
    COMPLETION_ERROR_CODE, COMPLETION_ERROR_CONSTRAINT, CONFIRM_PREFIX,
    ERROR_CODE, ERROR_CONSTRAINT, EXPECTED_JOBS, EXPECTED_RELATIONS, RULE_ID, RULE_SHA256, RULE_VERSION,
    RecoveryController, build_sealed_plan, validate_recovery_rows,
)
LOCK_NAME = "semantic_dispatch_partition_recovery_controller_v1"
PRODUCTION_WORKER_LOCK_NAME = "ad_log_reports_runtime_semantic_production_worker"
DEFAULT_PLAN = ROOT / "artifacts/stage8/evidence/semantic-dispatch-partition-recovery-plan.json"
DEFAULT_AUDIT = ROOT / "artifacts/stage8/evidence/semantic-dispatch-partition-recovery-audit.json"


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def _digest(value: object) -> str:
    return sha256(_canonical(value).encode("utf-8")).hexdigest()


def _candidate_key_hex(contribution_key: str) -> str:
    return sha256(_canonical({"rule_id": RULE_ID, "rule_version": RULE_VERSION,
                              "contribution_key": contribution_key}).encode("utf-8")).hexdigest()


def _load_main_environment() -> None:
    from scripts.maintenance.semantic_l1_shadow_control import _load_environment
    _load_environment()


def _connect_admin(*, autocommit: bool = False):
    from scripts.maintenance.semantic_l1_shadow_control import _connect_admin as connect
    return connect(autocommit=autocommit)


def _redact(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(k): ("[redacted]" if any(token in str(k).casefold() for token in ("password", "secret", "dsn", "credential", "token")) else _redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def _atomic_json(path: Path, payload: Mapping[str, object]) -> dict[str, object]:
    safe = _redact(dict(payload))
    if not isinstance(safe, dict):
        raise RuntimeError("recovery audit is invalid")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(safe, sort_keys=True, indent=2, ensure_ascii=True), encoding="utf-8")
    os.replace(temporary, path)
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if _canonical(loaded) != _canonical(safe):
        raise RuntimeError("recovery audit readback mismatch")
    return loaded


def write_atomic_audit(path: Path, payload: Mapping[str, object]) -> dict[str, object]:
    return _atomic_json(path, payload)


def load_apply_plan(path: Path, *, plan_digest: str, confirmation: str) -> dict[str, object]:
    try:
        plan = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("semantic dispatch recovery plan file is invalid") from exc
    if not isinstance(plan, dict) or _digest({k: v for k, v in plan.items() if k not in {"plan_digest", "confirmation"}}) != str(plan.get("plan_digest") or ""):
        raise RuntimeError("semantic dispatch recovery plan digest is invalid")
    if plan_digest != plan.get("plan_digest") or confirmation != plan.get("confirmation") or confirmation != CONFIRM_PREFIX + str(plan_digest):
        raise RuntimeError("exact semantic dispatch recovery confirmation required")
    return plan


class TrapArchive:
    """Proof that this recovery path cannot read archive/source evidence."""
    def __getattr__(self, _name: str) -> object:
        raise RuntimeError("semantic dispatch partition recovery forbids archive access")


def claim_recovery_dispatch_jobs(
    cur: Any,
    *,
    limit: int,
    allowed_rule_ids: Sequence[str] | None = None,
    allowed_rule_identities: Sequence[tuple[str, int, bytes | str]] | None = None,
    allowed_job_ids: Sequence[str] | None = None,
) -> list[dict[str, object]]:
    job_ids = list(allowed_job_ids or ())
    identities = list(allowed_rule_identities or ())
    if (
        limit != 1
        or allowed_rule_ids is not None
        or not job_ids
        or not set(job_ids).issubset(EXPECTED_JOBS)
        or identities != [(RULE_ID, RULE_VERSION, RULE_SHA256)]
    ):
        raise RuntimeError("semantic dispatch recovery claim scope changed")
    lease_token = str(uuid4())
    cur.execute(
        """
        with candidate as (
          select job.job_id
          from semantic_correlation_dispatch_jobs job
          join semantic_correlation_rules rule
            on rule.rule_id=job.rule_id and rule.rule_version=job.rule_version
          where job.job_id=any(%s::uuid[])
            and job.dispatch_status='queued'
            and job.attempt_count=5 and job.max_attempts=5
            and job.lease_token is null and job.lease_until is null and job.heartbeat_at is null
            and job.available_at<=now()
            and ((job.last_error_code=%s and position(%s in coalesce(job.last_error_detail,''))>0)
              or (job.last_error_code=%s and position(%s in coalesce(job.last_error_detail,''))>0))
            and rule.rule_id=%s and rule.rule_version=%s
            and encode(rule.definition_sha256,'hex')=%s
          order by job.available_at,job.created_at,job.job_id
          for update of job skip locked limit 1
        )
        update semantic_correlation_dispatch_jobs job
        set dispatch_status='leased',lease_token=%s,
            lease_until=now()+(300 * interval '1 second'),heartbeat_at=now(),updated_at=now()
        from candidate where job.job_id=candidate.job_id
        returning job.*
        """,
        (
            job_ids, ERROR_CODE, f'"{ERROR_CONSTRAINT}"',
            COMPLETION_ERROR_CODE, f'"{COMPLETION_ERROR_CONSTRAINT}"',
            RULE_ID, RULE_VERSION, RULE_SHA256, lease_token,
        ),
    )
    return [dict(row) for row in (cur.fetchall() or [])]


def complete_recovery_dispatch_job(cur: Any, *, job_id: str, lease_token: str) -> None:
    cur.execute(
        """
        update semantic_correlation_dispatch_jobs
        set dispatch_status='completed',completed_at=now(),lease_token=null,
            lease_until=null,heartbeat_at=now(),last_error_code=null,
            last_error_detail=null,updated_at=now()
        where job_id=%s and dispatch_status='leased' and lease_token=%s
        returning job_id
        """,
        (job_id, lease_token),
    )
    if cur.fetchone() is None:
        raise RuntimeError("semantic dispatch recovery lease was lost")


class PostgresRecoveryAdapter:
    def baseline(self) -> dict[str, object]:
        with _connect_admin() as conn, conn.cursor() as cur:
            cur.execute("set transaction read only")
            cur.execute(
                """
                select
                  (select count(*)::bigint from semantic_security_scenarios
                    where evidence_count<>0) as scenario_evidence_nonzero_count,
                  (select md5(coalesce(string_agg(scenario_id::text || ':' || evidence_count::text, ',' order by scenario_id),''))
                     from semantic_security_scenarios) as scenario_evidence_digest,
                  (select count(*)::bigint from semantic_correlation_dispatch_jobs
                    where job_id<>all(%s::uuid[])) as unrelated_dispatch_count,
                  (select md5(coalesce(string_agg(job_id::text || ':' || dispatch_status, ',' order by job_id),''))
                     from semantic_correlation_dispatch_jobs where job_id<>all(%s::uuid[])) as unrelated_dispatch_digest
                """,
                (sorted(EXPECTED_JOBS), sorted(EXPECTED_JOBS)),
            )
            return dict(cur.fetchone() or {})

    def snapshot(self) -> list[dict[str, object]]:
        with _connect_admin() as conn, conn.cursor() as cur:
            cur.execute("set transaction read only")
            cur.execute(
                """
                select job.job_id::text as job_id,job.dispatch_status,trigger.source_event_id,
                       job.partition_key,job.last_error_code,job.last_error_detail,
                       job.attempt_count,job.max_attempts,
                       job.lease_token,job.lease_until,job.heartbeat_at,
                       case when job.lease_until is not null then job.lease_until<=now() else false end as lease_expired,
                       rule.rule_id,rule.rule_version,encode(rule.definition_sha256,'hex') as definition_sha256,
                       encode(trigger.semantic_sha256,'hex') as source_hash,
                       trigger.semantic_contract_version,trigger.normalizer_id,trigger.normalizer_version,
                       trigger.normalized_at,
                       regexp_replace(job.partition_key, '^.*(?:-|:)', '') as trigger_identity
                from semantic_correlation_dispatch_jobs job
                join normalized_events trigger on trigger.normalized_event_id=job.normalized_event_id
                join semantic_correlation_rules rule on rule.rule_id=job.rule_id and rule.rule_version=job.rule_version
                where job.job_id=any(%s::uuid[])
                order by job.job_id
                """,
                (sorted(EXPECTED_JOBS),),
            )
            rows = [dict(row) for row in (cur.fetchall() or [])]
            for row in rows:
                cur.execute(
                        """
                        select %s::bigint as trigger_source_event_id,
                               array_agg(distinct normalized.source_event_id order by normalized.source_event_id) as source_event_ids,
                               encode(candidate.candidate_key,'hex') as candidate_key_hex,
                               count(distinct normalized.source_event_id) filter (where
                                 normalized.processing_status='normalized'
                                 and normalized.semantic_contract_version=%s
                                 and normalized.normalizer_id=%s
                                 and normalized.normalizer_version=%s
                               ) = count(distinct normalized.source_event_id) as contract_exact,
                               bool_and(
                                 normalized.processing_status='normalized'
                                 and normalized.semantic_contract_version=1
                                 and normalized.normalizer_id='windows.named-eventdata'
                                 and normalized.normalizer_version='1.3+identity-1.0'
                               ) as repairable_contract_exact
                        from semantic_correlation_candidates candidate
                        join semantic_correlation_candidate_evidence evidence on evidence.candidate_id=candidate.candidate_id
                        join normalized_events normalized on normalized.normalized_event_id=evidence.normalized_event_id
                        where candidate.rule_id=%s and candidate.rule_version=%s
                        group by candidate.candidate_key
                        having bool_or(normalized.source_event_id=%s)
                        order by candidate_key_hex
                        """,
                        (
                            row["source_event_id"],
                            row["semantic_contract_version"], row["normalizer_id"], row["normalizer_version"],
                            RULE_ID, RULE_VERSION,
                            row["source_event_id"],
                        ),
                )
                accepted: list[dict[str, object]] = []
                repairable: list[dict[str, object]] = []
                blocking: list[dict[str, object]] = []
                for relation in (dict(item) for item in (cur.fetchall() or [])):
                    source_ids = [int(item) for item in relation["source_event_ids"]]
                    matched_key = ""
                    for expected_trigger, expected_ids, expected_key in EXPECTED_RELATIONS:
                        if expected_trigger == int(row["source_event_id"]) and source_ids == list(expected_ids) and str(relation["candidate_key_hex"]) == _candidate_key_hex(expected_key):
                            matched_key = expected_key
                            break
                    observed = {
                        "trigger_source_event_id": int(row["source_event_id"]),
                        "source_event_ids": source_ids,
                        "contribution_key": matched_key or f"unexpected-candidate-key:{relation['candidate_key_hex']}",
                    }
                    if matched_key and relation.get("contract_exact") is True:
                        accepted.append(observed)
                    elif matched_key and relation.get("repairable_contract_exact") is True:
                        repairable.append(observed)
                    else:
                        blocking.append(observed)
                row["accepted_relations"] = accepted
                row["repairable_relations"] = repairable
                row["blocking_relations"] = blocking
            return rows

    @staticmethod
    def requeue_with_cursor(cur: Any, job_ids: Sequence[str]) -> None:
        cur.execute(
            """
            update semantic_correlation_dispatch_jobs
            set dispatch_status='queued',available_at=now(),lease_token=null,
                lease_until=null,heartbeat_at=null,updated_at=now()
            where job_id=any(%s::uuid[])
              and (
                (
                  dispatch_status='quarantined'
                  and lease_token is null and lease_until is null
                  and attempt_count=max_attempts and attempt_count=5
                  and ((heartbeat_at is null and last_error_code=%s)
                    or (heartbeat_at is not null and last_error_code=%s))
                )
                or (
                  dispatch_status='queued'
                  and lease_token is null and lease_until is null and heartbeat_at is null
                  and attempt_count=5 and max_attempts=5
                )
                or (
                  dispatch_status='leased'
                  and lease_token is not null and lease_until<=now() and heartbeat_at is not null
                  and attempt_count=5 and max_attempts=5
                )
              )
              and ((last_error_code=%s and position(%s in coalesce(last_error_detail,''))>0)
                or (last_error_code=%s and position(%s in coalesce(last_error_detail,''))>0))
            returning job_id
            """,
            (
                list(job_ids), ERROR_CODE, COMPLETION_ERROR_CODE,
                ERROR_CODE, f'"{ERROR_CONSTRAINT}"',
                COMPLETION_ERROR_CODE, f'"{COMPLETION_ERROR_CONSTRAINT}"',
            ),
        )
        returned = {str(row["job_id"]) for row in (cur.fetchall() or [])}
        if returned != set(job_ids) or len(returned) != len(job_ids):
            raise RuntimeError("semantic dispatch recovery requeue set changed")

    def requeue(self, plan: Mapping[str, object]) -> None:
        jobs = list(plan.get("jobs") or [])
        job_ids = [str(row["job_id"]) for row in jobs if isinstance(row, Mapping)]
        with _connect_admin() as conn:
            with conn.transaction(), conn.cursor() as cur:
                cur.execute("set local role adlog_storage_worker")
                self.requeue_with_cursor(cur, job_ids)

    def worker_is_live(self) -> bool:
        try:
            from scripts.maintenance import worker_guard
            guard = dict(worker_guard.evaluate_cycle(["semantic"]).get("semantic") or {})
        except Exception as exc:
            raise RuntimeError("semantic dispatch recovery supervisor guard is unavailable") from exc
        # Worker guard combines trusted OS process inventory with durable
        # heartbeat state. Only its explicit safe-to-launch result proves the
        # dispatcher is stopped; all other outcomes fail closed.
        return int(guard.get("code", 1)) != 0

    def preflight(self, plan: Mapping[str, object]) -> bool:
        expected = dict(plan.get("baseline") or {})
        current = self.baseline()
        return current == expected

    def dispatch(self, scope: Mapping[str, object]) -> Mapping[str, object]:
        from server.sli.semantic.semantic_production_runtime import INVESTIGATION_MODE, prepare_production_connection
        from server.sli.semantic.semantic_worker_connection import connect_semantic_worker
        from server.sli.semantic.semantic_worker_runtime import process_semantic_dispatch
        from scripts.maintenance.semantic_l1_shadow_control import (
            _create_ephemeral_login, _drop_ephemeral_login, _worker_dsn,
        )
        boundary = datetime.fromisoformat(str(scope["normalized_before"]).replace("Z", "+00:00"))
        recovery_environment = {
            "ADLOG_SEMANTIC_RUNTIME_MODE": INVESTIGATION_MODE,
            "ADLOG_SEMANTIC_RISK_ENGINE_ENABLED": "0",
            "ADLOG_SEMANTIC_FINDING_CREATION_ENABLED": "0",
        }
        previous_environment = {
            key: os.environ.get(key)
            for key in ("ADLOG_SEMANTIC_WORKER_DSN", *recovery_environment)
        }
        role = ""
        try:
            with _connect_admin(autocommit=True) as admin_conn, admin_conn.cursor() as cur:
                role, password = _create_ephemeral_login(cur)
            os.environ["ADLOG_SEMANTIC_WORKER_DSN"] = _worker_dsn(role=role, password=password)
            os.environ.update(recovery_environment)
            with connect_semantic_worker() as conn:
                settings = prepare_production_connection(conn, runtime_mode=INVESTIGATION_MODE)
                return process_semantic_dispatch(
                    conn, archive=TrapArchive(), settings=settings, limit=len(scope["allowed_job_ids"]),
                    allowed_job_ids=scope["allowed_job_ids"],
                    allowed_rule_identities=[(RULE_ID, RULE_VERSION, RULE_SHA256)],
                    normalized_before=boundary,
                    claim_jobs=claim_recovery_dispatch_jobs,
                    complete_job=complete_recovery_dispatch_job,
                )
        finally:
            for key, previous in previous_environment.items():
                if previous is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = previous
            if role:
                with _connect_admin(autocommit=True) as admin_conn, admin_conn.cursor() as cur:
                    _drop_ephemeral_login(cur, role)

    def verify(self, plan: Mapping[str, object]) -> Mapping[str, object]:
        rows = self.snapshot()
        all_completed = len(rows) == 3 and all(row.get("dispatch_status") == "completed" for row in rows)
        try:
            relations_exact = all_completed and not validate_recovery_rows(rows)
        except RuntimeError:
            relations_exact = False
        expected_baseline = dict(plan.get("baseline") or {})
        current_baseline = self.baseline()
        scenario_unchanged = (
            current_baseline.get("scenario_evidence_digest") == expected_baseline.get("scenario_evidence_digest")
            and current_baseline.get("scenario_evidence_nonzero_count")
            == expected_baseline.get("scenario_evidence_nonzero_count")
        )
        unrelated_unchanged = (current_baseline.get("unrelated_dispatch_count") == expected_baseline.get("unrelated_dispatch_count") and current_baseline.get("unrelated_dispatch_digest") == expected_baseline.get("unrelated_dispatch_digest"))
        return {"completed": all_completed, "relations_exact": relations_exact,
                "scenario_evidence_added": 0 if scenario_unchanged else 1,
                "unrelated_status_unchanged": unrelated_unchanged}


def plan_payload(adapter: PostgresRecoveryAdapter) -> dict[str, object]:
    rows = adapter.snapshot()
    if len(rows) != 3:
        raise RuntimeError("semantic dispatch recovery exact job rows are missing")
    normalized_before = max(str(row["normalized_at"]) for row in rows)
    base = build_sealed_plan(rows, normalized_before=normalized_before)
    baseline = adapter.baseline()
    material = {**{k: v for k, v in base.items() if k not in {"plan_digest", "confirmation"}}, "baseline": baseline,
                "generated_at_utc": datetime.now(timezone.utc).isoformat(), "source_contacted": False}
    digest = _digest(material)
    return {**material, "plan_digest": digest, "confirmation": CONFIRM_PREFIX + digest}


def run_plan(path: Path) -> dict[str, object]:
    _load_main_environment()
    plan = plan_payload(PostgresRecoveryAdapter())
    return _atomic_json(path, plan)


def run_apply(path: Path, *, plan_digest: str, confirmation: str, audit_path: Path) -> dict[str, object]:
    plan = load_apply_plan(path, plan_digest=plan_digest, confirmation=confirmation)
    _load_main_environment()
    adapter = PostgresRecoveryAdapter()
    try:
        with session_advisory_lock(_connect_admin, LOCK_NAME) as controller_lock:
            if not controller_lock:
                raise RuntimeError("semantic dispatch recovery controller advisory lock is busy")
            with session_advisory_lock(_connect_admin, PRODUCTION_WORKER_LOCK_NAME) as worker_lock:
                if not worker_lock:
                    raise RuntimeError("semantic dispatch recovery production worker lock is busy")
                controller = RecoveryController(snapshot=adapter.snapshot, worker_is_live=adapter.worker_is_live,
                    acquire_locks=lambda: True, requeue=adapter.requeue, dispatch=adapter.dispatch,
                    verify=adapter.verify, preflight=adapter.preflight,
                    audit=lambda result: _atomic_json(audit_path, {**result, "at_utc": datetime.now(timezone.utc).isoformat()}))
                return controller.apply(plan_digest=plan_digest, confirmation=confirmation, plan=plan)
    except Exception as exc:
        _atomic_json(audit_path, {"status": "failed_closed", "plan_digest": plan_digest,
                                  "error_type": type(exc).__name__, "at_utc": datetime.now(timezone.utc).isoformat()})
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "apply"))
    parser.add_argument("--plan-file", type=Path, default=DEFAULT_PLAN)
    parser.add_argument("--audit-file", type=Path, default=DEFAULT_AUDIT)
    parser.add_argument("--plan-digest", default="")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()
    try:
        result = run_plan(args.plan_file) if args.action == "plan" else run_apply(args.plan_file, plan_digest=args.plan_digest, confirmation=args.confirm, audit_path=args.audit_file)
    except Exception as exc:
        print(
            json.dumps({"status": "failed_closed", "error_type": type(exc).__name__}, sort_keys=True),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(_redact(result), sort_keys=True, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

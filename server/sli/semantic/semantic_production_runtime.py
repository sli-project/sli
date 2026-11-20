"""Fail-closed runtime contract for continuous production semantics."""
from __future__ import annotations

from server.sli.semantic.runtime_state import FACTS_MODE, INVESTIGATION_MODE, FINDINGS_MODE

import os
from functools import partial
from typing import Any, Mapping, Sequence

from server.sli.ops import shutdown
from server.sli.semantic.semantic_processing import SemanticFeatureSettings
from server.sli.semantic.default_detections import run_default_detections
from server.sli.semantic.password_attack_producer import ProducerConnectionFatal, require_password_connection_idle
from server.sli.sigma.live_runtime import run_sigma_detections
from server.sli.semantic.semantic_investigation_backfill import investigation_rule_identity_tuples
from server.sli.semantic.semantic_risk_runtime_repository import (
    MAX_RISK_CLAIM,
    claim_risk_evaluation_jobs,
    enqueue_risk_backlog,
    execute_risk_evaluation,
    fail_risk_evaluation_job,
    load_risk_evaluation_work_item,
)
from server.sli.semantic.semantic_worker_runtime import (
    MAX_SEMANTIC_BATCH,
    MAX_SEMANTIC_RECOVERY_BATCH,
    process_semantic_dispatch,
    process_semantic_outbox,
)
from server.sli.semantic.semantic_processing_repository import (
    SEMANTIC_V2_QUARANTINE_REPAIR_JOB_KIND,
)


ENABLED_POLICY_ID = "l1-audit-policy-changed"
POLICY_VERSION = 2
# Exact-source maintenance plans retain their existing admission bound.
MAX_LIMIT = MAX_SEMANTIC_RECOVERY_BATCH
MAX_BATCH_LIMIT = MAX_SEMANTIC_BATCH
_RUNTIME_MODES = frozenset({FACTS_MODE, INVESTIGATION_MODE, FINDINGS_MODE})
# The managed worker and an exact maintenance check must never claim together.
PRODUCTION_WORKER_LOCK_NAME = "ad_log_reports_runtime_semantic_production_worker"
SEMANTIC_V2_QUARANTINE_REPAIR_PLAN_DIGEST_ENV = (
    "ADLOG_SEMANTIC_V2_QUARANTINE_REPAIR_PLAN_DIGEST"
)


def semantic_v2_quarantine_repair_plan_digest_from_env(
    environ: Mapping[str, str] | None = None,
) -> str | None:
    """Return the explicitly armed recovery digest, or fail closed before claim."""
    values = environ if environ is not None else os.environ
    digest = str(values.get(SEMANTIC_V2_QUARANTINE_REPAIR_PLAN_DIGEST_ENV, "")).strip()
    if not digest:
        return None
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise RuntimeError("semantic v2 quarantine repair digest is invalid")
    return digest


def semantic_runtime_mode_from_env(
    environ: Mapping[str, str] | None = None,
) -> str:
    """Resolve the admitted runtime mode without turning an OFF chain on."""
    values = environ if environ is not None else os.environ
    admitted = str(
        values.get("ADLOG_SEMANTIC_PRODUCTION_ENABLED", "")
    ).strip().casefold() in {"1", "true", "yes", "on"}
    if not admitted:
        raise RuntimeError("semantic production admission is required")
    declared = str(values.get("ADLOG_SEMANTIC_RUNTIME_MODE", "")).strip()
    if not declared:
        # Existing admitted production payloads predate the mode selector.
        return FINDINGS_MODE
    if declared not in _RUNTIME_MODES:
        raise RuntimeError("semantic runtime mode is unsupported")
    return declared


def _validate_facts_settings(settings: SemanticFeatureSettings) -> None:
    if not (settings.normalization_enabled and settings.assembly_enabled):
        raise RuntimeError("facts mode requires normalization and assembly")
    if settings.directory_state_enabled:
        raise RuntimeError("directory-state persistence is not accepted")
    if settings.correlation_enabled:
        raise RuntimeError("facts mode forbids correlation")
    if settings.risk_engine_enabled:
        raise RuntimeError("facts mode forbids risk evaluation")
    if settings.finding_creation_enabled:
        raise RuntimeError("facts mode forbids finding creation")


def _validate_findings_settings(settings: SemanticFeatureSettings) -> None:
    if not (
        settings.normalization_enabled
        and settings.assembly_enabled
        and settings.correlation_enabled
        and settings.risk_engine_enabled
        and settings.finding_creation_enabled
    ):
        raise RuntimeError("complete semantic production feature chain is required")
    if settings.directory_state_enabled:
        raise RuntimeError("directory-state persistence is not accepted")


def _validate_investigation_settings(settings: SemanticFeatureSettings) -> None:
    if not (
        settings.normalization_enabled
        and settings.assembly_enabled
        and settings.correlation_enabled
    ):
        raise RuntimeError(
            "investigation mode requires normalization, assembly and correlation"
        )
    if settings.directory_state_enabled:
        raise RuntimeError("investigation mode forbids directory-state persistence")
    if settings.risk_engine_enabled:
        raise RuntimeError("investigation mode forbids risk evaluation")
    if settings.finding_creation_enabled:
        raise RuntimeError("investigation mode forbids finding creation")


def validate_semantic_runtime_settings(
    mode: str, settings: SemanticFeatureSettings, *, environ: Mapping[str, str] | None = None,
) -> None:
    """Shared execution/presentation contract; does not connect or enable work."""
    if mode == FACTS_MODE:
        _validate_facts_settings(settings)
        values = os.environ if environ is None else environ
        for stage in ("DIRECTORY_STATE", "CORRELATION", "RISK_ENGINE", "FINDING_CREATION"):
            if str(values.get(f"ADLOG_SEMANTIC_{stage}_ENABLED", "")).strip().casefold() in {"1", "true", "yes", "on"}:
                raise RuntimeError(f"facts mode forbids raw {stage.lower()} flag")
    elif mode == FINDINGS_MODE:
        _validate_findings_settings(settings)
    elif mode == INVESTIGATION_MODE:
        _validate_investigation_settings(settings)
    else:
        raise RuntimeError("semantic runtime mode is unsupported")


def semantic_publisher_for_runtime(
    *,
    settings: SemanticFeatureSettings | None = None,
    environ: Mapping[str, str] | None = None,
):
    """Return the one producer configuration used by every V2 write route.

    Storage V2 may be populated either by the compatibility outbox or by the
    authorized direct importer.  Both routes must make the same atomic
    semantic-publication decision; otherwise a storage cutover can silently
    stop new facts while collection itself remains healthy.
    """
    values = os.environ if environ is None else environ
    declared_mode = str(values.get("ADLOG_SEMANTIC_RUNTIME_MODE", "")).strip()
    admitted = str(values.get("ADLOG_SEMANTIC_PRODUCTION_ENABLED", "")).strip().casefold() in {
        "1", "true", "yes", "on",
    }
    if not admitted:
        if declared_mode:
            semantic_runtime_mode_from_env(values)
        return None

    feature_settings = settings or SemanticFeatureSettings.from_env(values)
    mode = semantic_runtime_mode_from_env(values)
    validate_semantic_runtime_settings(mode, feature_settings, environ=values)

    from server.sli.semantic.semantic_producer import (
        publish_investigation_candidates,
        publish_semantic_candidates,
    )

    if mode == FACTS_MODE:
        return partial(publish_semantic_candidates, include_context=True)
    if mode == INVESTIGATION_MODE:
        return publish_investigation_candidates
    return publish_semantic_candidates


def prepare_production_connection(
    conn: Any,
    *,
    runtime_mode: str | None = None,
) -> SemanticFeatureSettings:
    """Validate the admitted mode's schema and bounded worker capabilities."""
    mode = runtime_mode or semantic_runtime_mode_from_env()
    settings = SemanticFeatureSettings.from_env()
    validate_semantic_runtime_settings(mode, settings)
    rule_lock_guard: dict[str, Any] = {}
    if mode in {FACTS_MODE, INVESTIGATION_MODE, FINDINGS_MODE}:
        with conn.cursor() as cur:
            cur.execute(
                """
                select exists(
                         select 1 from schema_migrations
                         where version=54 and name='semantic_worker_runtime_schema_guard'
                       ) as facts_schema_ready,
                       exists(
                         select 1 from schema_migrations
                         where version=142 and name='semantic_processor_version_gate_and_repair'
                       ) as processor_version_gate_schema_ready,
                       has_table_privilege(
                         current_user, 'semantic_processing_outbox', 'SELECT,INSERT,UPDATE'
                       ) and has_table_privilege(
                         current_user, 'normalized_events', 'SELECT,INSERT,UPDATE'
                       ) and has_table_privilege(
                         current_user, 'canonical_actions', 'SELECT,INSERT,UPDATE'
                       ) as facts_capability_ready,
                       exists(
                         select 1 from schema_migrations
                         where version=27 and name='semantic_dispatch_foundation'
                       ) as investigation_schema_ready,
                       exists(
                         select 1 from schema_migrations
                         where version=141 and name='semantic_dispatch_rule_lock_acl'
                       ) as investigation_rule_lock_schema_ready,
                       exists(
                         select 1 from schema_migrations
                         where version=140 and name='semantic_investigation_context_acl'
                       ) and exists(
                         select 1 from pg_constraint
                         where conrelid='semantic_processing_outbox'::regclass
                           and conname='semantic_processing_outbox_job_kind_check'
                           and pg_get_constraintdef(oid) like '%investigation_context%'
                       ) as investigation_context_schema_ready,
                       has_table_privilege(
                         current_user, 'semantic_correlation_candidates', 'SELECT,INSERT,UPDATE'
                       ) and has_table_privilege(
                         current_user, 'semantic_correlation_candidate_evidence', 'SELECT,INSERT,UPDATE'
                       ) and has_table_privilege(
                         current_user, 'semantic_correlation_dispatch_jobs', 'SELECT,INSERT,UPDATE'
                       ) as investigation_capability_ready,
                       has_table_privilege(
                         current_user, 'semantic_correlation_rules', 'SELECT'
                       ) and has_column_privilege(
                         current_user, 'semantic_correlation_rules', 'updated_at', 'UPDATE'
                       ) and not has_table_privilege(
                         current_user, 'semantic_correlation_rules', 'UPDATE'
                       ) and not has_column_privilege(
                         current_user, 'semantic_correlation_rules', 'updated_at',
                         'UPDATE WITH GRANT OPTION'
                       ) and not exists(
                         select 1
                         from pg_attribute rule_column
                         where rule_column.attrelid='semantic_correlation_rules'::regclass
                           and rule_column.attnum > 0
                           and not rule_column.attisdropped
                           and rule_column.attname <> 'updated_at'
                           and has_column_privilege(
                             current_user,
                             rule_column.attrelid,
                             rule_column.attname,
                             'UPDATE'
                           )
                       ) as investigation_rule_lock_capability_ready,
                       has_table_privilege(
                         current_user, 'storage_v2_keywords', 'SELECT'
                       ) as investigation_context_capability_ready
                """
            )
            guard = dict(cur.fetchone() or {})
        rule_lock_guard = guard
        if mode == FACTS_MODE:
            if not bool(guard.get("facts_schema_ready")) or not bool(
                guard.get("processor_version_gate_schema_ready")
            ):
                raise RuntimeError("semantic facts schema markers 54 and 142 are required")
            if not bool(guard.get("facts_capability_ready")):
                raise RuntimeError("semantic facts least-privilege capability is required")
        elif mode == INVESTIGATION_MODE:
            if not bool(guard.get("facts_schema_ready")) or not bool(
                guard.get("processor_version_gate_schema_ready")
            ) or not bool(
                guard.get("investigation_schema_ready")
            ) or not bool(guard.get("investigation_rule_lock_schema_ready")) or not bool(
                guard.get("investigation_context_schema_ready")
            ):
                raise RuntimeError(
                    "semantic investigation schema markers 27, 54, 140 and 141 are required"
                )
            if not bool(guard.get("facts_capability_ready")) or not bool(
                guard.get("investigation_capability_ready")
            ) or not bool(guard.get("investigation_rule_lock_capability_ready")) or not bool(
                guard.get("investigation_context_capability_ready")
            ):
                raise RuntimeError("semantic investigation least-privilege capability is required")
        if mode in {FACTS_MODE, INVESTIGATION_MODE}:
            conn.commit()
            return settings

    with conn.cursor() as cur:
        cur.execute(
            """
            select exists(
                     select 1 from schema_migrations
                     where version=55 and name='semantic_finding_publication'
                   ) as schema_ready,
                   array(
                     select policy_id || ':' || policy_version::text
                     from semantic_risk_policies
                     where semantic_policy_mode_v160(policy_id,policy_version,lifecycle_status)='enabled'
                     order by policy_id,policy_version
                   ) as enabled_policies,
                   array(
                     select p.policy_id || ':' || p.policy_version::text
                     from semantic_risk_policies p
                     where p.lifecycle_status='enabled' and not exists(
                         select 1 from semantic_policy_admission a
                         where a.policy_id=p.policy_id and a.policy_version=p.policy_version)
                     order by p.policy_id,p.policy_version
                   ) as unmanaged_enabled_policies,
                   exists(select 1 from semantic_policy_admission) as admission_configured,
                   exists(
                     select 1 from semantic_risk_policies
                     where semantic_policy_mode_v160(policy_id,policy_version,lifecycle_status)='test'
                   ) as test_policy_exists
            """
        )
        guard = dict(cur.fetchone() or {})
    if not bool(guard.get("schema_ready")) or not bool(
        rule_lock_guard.get("investigation_rule_lock_schema_ready")
    ):
        raise RuntimeError("semantic production schema markers 55 and 141 are required")
    if not bool(rule_lock_guard.get("investigation_rule_lock_capability_ready")):
        raise RuntimeError("semantic production rule-lock capability is required")
    expected = [f"{ENABLED_POLICY_ID}:{POLICY_VERSION}"]
    unmanaged = guard.get("unmanaged_enabled_policies", guard.get("enabled_policies")) or []
    if any(identity not in expected for identity in unmanaged) or (
        not guard.get("admission_configured") and list(unmanaged) != expected
    ):
        raise RuntimeError("semantic production enabled policy set differs")
    if bool(guard.get("test_policy_exists")):
        raise RuntimeError("semantic production refuses TEST policy")
    conn.commit()
    return settings


def run_once(
    *,
    limit: int,
    connect_factory: Any,
    archive: Any,
    source_event_ids: Sequence[int] | None = None,
    repair_plan_digest: str | None = None,
) -> dict[str, object]:
    """Run one bounded production cycle through durable publication."""
    bounded_limit = max(1, min(int(limit), MAX_BATCH_LIMIT))
    completed = failed = queued = findings_created = 0
    modes = {"shadow": 0, "enabled": 0}
    runtime_mode = semantic_runtime_mode_from_env()
    enabled_policies: list[str] = []
    detections: dict[str, int | dict[str, int]] = {"sources": 0, "jobs": 0, "failed": 0,
        "coverage_counts": {}, "password_work_counts": {}}
    sigma: dict[str, int] = {"policies": 0, "jobs": 0, "failed": 0}
    recovery_digest = (
        semantic_v2_quarantine_repair_plan_digest_from_env(
            {SEMANTIC_V2_QUARANTINE_REPAIR_PLAN_DIGEST_ENV: repair_plan_digest}
        )
        if repair_plan_digest is not None
        else None
    )
    if recovery_digest is not None and runtime_mode != INVESTIGATION_MODE:
        raise RuntimeError("semantic v2 quarantine recovery requires investigation mode")
    if recovery_digest is not None:
        bounded_limit = min(bounded_limit, MAX_SEMANTIC_RECOVERY_BATCH)
    validate_semantic_runtime_settings(runtime_mode, SemanticFeatureSettings.from_env())
    exact_source_ids: tuple[int, ...] | None = None
    if source_event_ids is not None:
        try:
            exact_source_ids = tuple(int(value) for value in source_event_ids)
        except (TypeError, ValueError) as exc:
            raise RuntimeError("exact semantic source IDs are invalid") from exc
        if (
            runtime_mode != FACTS_MODE
            or not exact_source_ids
            or len(exact_source_ids) > MAX_LIMIT
            or any(value <= 0 for value in exact_source_ids)
            or len(set(exact_source_ids)) != len(exact_source_ids)
        ):
            raise RuntimeError("exact semantic source IDs require facts mode")
    if recovery_digest is not None and source_event_ids is not None:
        raise RuntimeError("semantic v2 quarantine recovery forbids source ID selection")
    conn = connect_factory()
    processing: dict[str, int] = {"completed": 0, "failed": 0, "normalized": 0, "actions": 0}
    dispatch: dict[str, int] = {"completed": 0, "failed": 0, "relations": 0}
    try:
        settings = prepare_production_connection(conn, runtime_mode=runtime_mode)
        if runtime_mode == FINDINGS_MODE:
            with conn.transaction(), conn.cursor() as cur:
                cur.execute("select expire_semantic_suppressions_v160()")
                cur.execute("""select array(select policy_id || ':' || policy_version::text
                    from semantic_risk_policies
                    where semantic_policy_mode_v160(policy_id,policy_version,lifecycle_status)='enabled'
                    order by policy_id,policy_version) as enabled_policies""")
                enabled_policies = list((cur.fetchone() or {}).get("enabled_policies") or [])
        investigation_rule_identities = (
            investigation_rule_identity_tuples()
            if runtime_mode == INVESTIGATION_MODE
            else None
        )
        processing_kwargs: dict[str, Any] = {
            "archive": archive,
            "settings": settings,
            "limit": bounded_limit,
            "source_event_ids": exact_source_ids,
        }
        if recovery_digest is not None:
            processing_kwargs["repair_plan_digest"] = recovery_digest
        if investigation_rule_identities is not None:
            processing_kwargs["allowed_rule_identities"] = investigation_rule_identities
        processing = process_semantic_outbox(conn, **processing_kwargs)
        completed += int(processing["completed"])
        failed += int(processing["failed"])
        if recovery_digest is not None:
            return {
                "status": "ok" if not failed else "partial",
                "runtime_mode": runtime_mode,
                "repair_scope": {
                    "job_kind": SEMANTIC_V2_QUARANTINE_REPAIR_JOB_KIND,
                    "repair_plan_digest": recovery_digest,
                },
                "processing": processing,
                "dispatch": dispatch,
                "risk_queued": 0,
                "completed": completed,
                "failed": failed,
                "modes": modes,
                "findings_created": 0,
            }
        if runtime_mode == FACTS_MODE or shutdown.requested():
            return {
                "status": "ok" if not failed else "partial",
                "runtime_mode": runtime_mode,
                "processing": processing,
                "dispatch": dispatch,
                "risk_queued": 0,
                "completed": completed,
                "failed": failed,
                "modes": modes,
                "findings_created": 0,
            }
        dispatch = process_semantic_dispatch(
            conn,
            archive=archive,
            settings=settings,
            limit=bounded_limit,
            allowed_rule_identities=investigation_rule_identities,
        )
        completed += int(dispatch["completed"])
        failed += int(dispatch["failed"])
        if runtime_mode == INVESTIGATION_MODE or shutdown.requested():
            return {
                "status": "ok" if not failed else "partial",
                "runtime_mode": runtime_mode,
                "processing": processing,
                "dispatch": dispatch,
                "risk_queued": 0,
                "completed": completed,
                "failed": failed,
                "modes": modes,
                "findings_created": 0,
            }
        # Keep risk discovery/evaluation from monopolizing a normalization cycle.
        # Each evaluation still claims one lease immediately before processing.
        try:
            detections = run_default_detections(conn)
        except ProducerConnectionFatal:
            raise
        except Exception:
            detections["failed"] += 1
        require_password_connection_idle(conn)
        failed += detections["failed"]
        if not shutdown.requested():
            try:
                sigma = run_sigma_detections(conn)
            except Exception:
                sigma["failed"] += 1
        require_password_connection_idle(conn)
        failed += sigma["failed"]
        risk_limit = min(bounded_limit, MAX_RISK_CLAIM)
        if not shutdown.requested():
            with conn.transaction(), conn.cursor() as cur:
                queued = len(enqueue_risk_backlog(cur, limit=risk_limit))
        for _ in range(risk_limit):
            if shutdown.requested():
                break
            with conn.transaction(), conn.cursor() as cur:
                claimed = claim_risk_evaluation_jobs(cur, limit=1)
            if not claimed:
                break
            job = claimed[0]
            try:
                with conn.transaction(), conn.cursor() as cur:
                    work = load_risk_evaluation_work_item(
                        cur,
                        job_id=str(job["job_id"]),
                        lease_token=str(job["lease_token"]),
                    )
                    result = execute_risk_evaluation(
                        cur,
                        work=work,
                        evaluation_ms=0,
                        create_finding=(
                            work.evaluation_mode == "enabled"
                            and settings.finding_creation_enabled
                        ),
                    )
                    if result.evaluation_mode not in modes:
                        raise RuntimeError("unexpected semantic production mode")
                    modes[result.evaluation_mode] += 1
                    findings_created += int(result.finding_created)
                    completed += 1
            except Exception as exc:
                with conn.transaction(), conn.cursor() as cur:
                    fail_risk_evaluation_job(
                        cur,
                        job_id=str(job["job_id"]),
                        lease_token=str(job["lease_token"]),
                        attempt_count=int(job["attempt_count"]),
                        max_attempts=int(job["max_attempts"]),
                        error_code=type(exc).__name__,
                        error_detail=str(exc),
                    )
                failed += 1
    finally:
        conn.close()
    return {
        "status": "ok" if not failed else "partial",
        "runtime_mode": runtime_mode,
        "processing": processing,
        "dispatch": dispatch,
        "risk_queued": queued,
        "enabled_policies": enabled_policies,
        "detections": detections,
        "sigma": sigma,
        "completed": completed,
        "failed": failed,
        "modes": modes,
        "findings_created": findings_created,
    }

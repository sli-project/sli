#!/usr/bin/env python3
"""Apply and manually poll the bounded Stage-8 L1 semantic SHADOW."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.core.app_config import redact_dsn  # noqa: E402
from server.sli.semantic.semantic_producer import publish_semantic_candidates  # noqa: E402
from server.sli.semantic.semantic_risk import ScenarioSourceKind  # noqa: E402
from server.sli.semantic.semantic_risk_policy import RiskPolicyDefinition  # noqa: E402
from server.sli.semantic.semantic_risk_runtime_repository import (  # noqa: E402
    register_risk_policy,
    transition_risk_policy,
)
from server.sli.semantic.semantic_production_credentials import (  # noqa: E402
    grant_ephemeral_login_connect,
    revoke_ephemeral_login_connect,
)
from server.sli.storage.storage_v2_archive import ArchiveReader  # noqa: E402
from server.sli.storage.storage_v2_repository import (  # noqa: E402
    PostgresArchiveManifestStore,
)
from server.sli.storage.storage_v2_runtime_authorization import (  # noqa: E402
    load_runtime_authorization_if_available,
)
from server.sli.ops.worker_supervisor_secrets import (  # noqa: E402
    load_supervisor_environment,
)


APPLY_CONFIRM = "START-STAGE8-L1-BOUNDED-SHADOW"
POLL_CONFIRM = "POLL-STAGE8-L1-BOUNDED-SHADOW"
STATE_PATH = (
    ROOT / "artifacts/stage8/evidence/semantic-l1-shadow-state.json"
)
MIGRATIONS = {
    version: ROOT / "config/postgres_migrations" / filename
    for version, filename in (
        (50, "050_semantic_worker_least_privilege.sql"),
        (51, "051_event_catalog_revision_reference.sql"),
        (52, "052_semantic_conclusion_completeness.sql"),
        (53, "053_semantic_canonical_action_risk.sql"),
        (54, "054_semantic_worker_runtime_schema_guard.sql"),
    )
}
TARGET_KINDS = {
    "eventlog.cleared": "security.audit_controls_changed",
    "audit.policy.changed": "security.audit_controls_changed",
    "group.member.added": "security.privileged_group_member_added",
    "scheduled_task.created": "security.scheduled_task_created",
}
POLICY_VERSION = 2


def _policy_definition(
    *,
    action_kind: str,
    scenario_kind: str,
    strict_roles: list[str],
    title: str,
    explanation: str,
    display_points: int,
) -> dict[str, object]:
    return {
        "type": "scenario_policy",
        "source_selector": {"action_kind": action_kind},
        "scenario_kind": scenario_kind,
        "result_class": "security_incident",
        "strict_roles": strict_roles,
        "merge_window_seconds": 300,
        "title": title,
        "explanation": explanation,
        "expected_evidence_count": 1,
        "required_controls": [],
        "allowed_lateness_seconds": 60,
        "risk": {
            "class": "high" if display_points >= 70 else "medium",
            "raw_score": str(display_points),
            "display_points": display_points,
            "hard_critical": False,
            "rationale": "Bounded Stage-8 L1 SHADOW policy match",
        },
    }


POLICIES = (
    (
        "l1-eventlog-cleared",
        _policy_definition(
            action_kind="eventlog.cleared",
            scenario_kind=TARGET_KINDS["eventlog.cleared"],
            strict_roles=["source_host"],
            title="Security event log was cleared",
            explanation="Exact provider-aware Event 1102 action was observed",
            display_points=85,
        ),
    ),
    (
        "l1-audit-policy-changed",
        _policy_definition(
            action_kind="audit.policy.changed",
            scenario_kind=TARGET_KINDS["audit.policy.changed"],
            strict_roles=["source_host", "actor"],
            title="Audit policy was changed",
            explanation="Exact named EventData from Event 4719 was observed",
            display_points=75,
        ),
    ),
    (
        "l1-privileged-group-member-added",
        _policy_definition(
            action_kind="group.member.added",
            scenario_kind=TARGET_KINDS["group.member.added"],
            strict_roles=["source_host", "container_entity", "target_entity"],
            title="Member was added to a privileged group",
            explanation="Exact group and member identities were observed",
            display_points=85,
        ),
    ),
    (
        "l1-scheduled-task-created",
        _policy_definition(
            action_kind="scheduled_task.created",
            scenario_kind=TARGET_KINDS["scheduled_task.created"],
            strict_roles=["source_host", "target_entity"],
            title="Scheduled task was registered",
            explanation="Exact Task Scheduler Event 106 action was observed",
            display_points=65,
        ),
    ),
)


def _load_environment() -> None:
    if not (
        os.getenv("ADLOG_PG_ADMIN_USER", "").strip()
        and os.getenv("ADLOG_PG_ADMIN_PASSWORD", "")
        and os.getenv("ADLOG_PG_DSN", "").strip()
    ):
        load_supervisor_environment()


def _admin_dsn() -> str:
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    source = os.getenv("ADLOG_PG_DSN", "").strip()
    user = os.getenv("ADLOG_PG_ADMIN_USER", "").strip()
    password = os.getenv("ADLOG_PG_ADMIN_PASSWORD", "")
    if not source or not user or not password:
        raise RuntimeError("protected PostgreSQL migration credentials are required")
    parts = conninfo_to_dict(source)
    parts.update(user=user, password=password)
    return make_conninfo(**parts)


def _connect_admin(*, autocommit: bool = False):
    import psycopg
    from psycopg.rows import dict_row

    return psycopg.connect(
        _admin_dsn(),
        autocommit=autocommit,
        row_factory=dict_row,
        connect_timeout=5,
        application_name="sli_stage8_l1_shadow_control",
        options="-c statement_timeout=1800000 -c lock_timeout=5000",
    )


def _snapshot(cur: Any) -> dict[str, Any]:
    cur.execute(
        """
        select
          coalesce((select max(version) from schema_migrations),0) as marker,
          (select count(*) from findings) as findings,
          (select count(*) from semantic_processing_outbox) as processing_jobs,
          (select count(*) from normalized_events) as normalized_events,
          (select count(*) from canonical_actions) as canonical_actions,
          (select count(*) from semantic_security_scenarios) as scenarios,
          (select count(*) from semantic_risk_evaluation_jobs) as risk_jobs,
          (select coalesce(max(id),0) from events_v2_core) as max_event_id,
          exists(
            select 1 from runtime_worker_heartbeats
            where worker_name='semantic'
              and status not in ('stopped','disabled')
              and heartbeat_at >= now() - (
                greatest(180,expected_interval_seconds*3)
                * interval '1 second'
              )
          ) as semantic_worker_live
        """
    )
    result = dict(cur.fetchone())
    cur.execute(
        """
        select policy_id,policy_version,source_kind,lifecycle_status
        from semantic_risk_policies
        where policy_id=any(%s)
        order by policy_id,policy_version
        """,
        ([item[0] for item in POLICIES],),
    )
    result["l1_policies"] = [dict(row) for row in (cur.fetchall() or [])]
    cur.execute(
        """
        select scenario_kind,count(*)::bigint as count
        from semantic_security_scenarios
        where scenario_kind=any(%s)
        group by scenario_kind order by scenario_kind
        """,
        (sorted(set(TARGET_KINDS.values())),),
    )
    result["l1_scenarios"] = [dict(row) for row in (cur.fetchall() or [])]
    return result


def _shadow_scope(state: dict[str, Any]) -> list[int] | None:
    """Only new-format state can attest which inputs this exercise selected.

    Old poll aggregates and a watermark cannot reconstruct that evidence.
    Event occurrence time is deliberately not used as collection/run time.
    """
    required = {policy_id: POLICY_VERSION for policy_id, _ in POLICIES}
    policy_ids = state.get("policy_ids")
    if (
        state.get("evidence_contract_version") != 1
        or state.get("policy_versions") != required
        or not isinstance(policy_ids, list)
        or any(not isinstance(item, str) for item in policy_ids)
        or set(policy_ids) != set(required)
    ):
        return None
    inputs = state.get("input_event_ids")
    start = state.get("start_event_id")
    watermark = state.get("watermark_event_id")
    if (
        not isinstance(inputs, list)
        or type(start) is not int
        or type(watermark) is not int
        or start < 0
        or watermark < start
        or any(type(item) is not int or not start < item <= watermark for item in inputs)
    ):
        return None
    try:
        started = datetime.fromisoformat(state["started_at_utc"])
        if started.utcoffset() is None:
            return None
    except (KeyError, TypeError, ValueError):
        return None
    return sorted(set(inputs))


def _shadow_evidence(cur: Any, state: dict[str, Any]) -> dict[str, Any]:
    inputs = _shadow_scope(state)
    if inputs is None:
        return {
            "status": "unknown",
            "reason": "state lacks supported current-run input and policy scope",
            "receipts": [],
        }
    required = {
        policy_id: (
            POLICY_VERSION,
            definition["source_selector"]["action_kind"],
            definition["scenario_kind"],
        )
        for policy_id, definition in POLICIES
    }
    rows = []
    if inputs:
        cur.execute(
            """
            select distinct job.job_id::text,job.policy_id,job.policy_version,
                   job.canonical_action_id::text,action.action_kind,
                   result.scenario_id::text,scenario.scenario_kind,
                   normalized.source_event_id
            from semantic_risk_evaluation_jobs job
            join semantic_risk_evaluation_results result on result.job_id=job.job_id
            join canonical_actions action
              on action.canonical_action_id=job.canonical_action_id
            join semantic_security_scenarios scenario
              on scenario.scenario_id=result.scenario_id
            join canonical_action_evidence evidence
              on evidence.canonical_action_id=job.canonical_action_id
            join normalized_events normalized
              on normalized.normalized_event_id=evidence.normalized_event_id
            where job.policy_id=any(%s) and job.policy_version=%s
              and job.source_kind='canonical_action'
              and job.evaluation_mode='shadow'
              and result.evaluation_mode='shadow'
              and job.evaluation_status='completed'
              and job.created_at>=%s and result.created_at>=%s
              and normalized.source_event_id=any(%s)
              and evidence.evidence_role='primary'
            order by job.policy_id,job.job_id::text,normalized.source_event_id
            """,
            (list(required), POLICY_VERSION, state["started_at_utc"],
             state["started_at_utc"], inputs),
        )
        rows = [dict(row) for row in (cur.fetchall() or [])]
    receipts = [
        row for row in rows
        if required.get(row.get("policy_id")) == (
            row.get("policy_version"), row.get("action_kind"), row.get("scenario_kind")
        ) and row.get("source_event_id") in inputs
    ]
    observed = {row["policy_id"] for row in receipts}
    return {
        "status": "complete" if observed == set(required) else "incomplete",
        "source_kind": "canonical_action",
        "evaluation_mode": "shadow",
        "started_at_utc": state["started_at_utc"],
        "policy_versions": dict(state["policy_versions"]),
        "missing_policy_ids": sorted(set(required) - observed),
        "receipts": receipts,
    }


def _role_state(cur: Any) -> dict[str, Any]:
    cur.execute(
        """
        select rolname,rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,
               rolinherit,rolbypassrls,rolreplication
        from pg_roles where rolname='adlog_semantic_worker'
        """
    )
    return dict(cur.fetchone() or {})


def _assert_semantic_role(row: dict[str, Any]) -> None:
    expected = {
        "rolname": "adlog_semantic_worker",
        "rolcanlogin": False,
        "rolsuper": False,
        "rolcreatedb": False,
        "rolcreaterole": False,
        "rolinherit": False,
        "rolbypassrls": False,
        "rolreplication": False,
    }
    if row != expected:
        raise RuntimeError(f"semantic worker role differs from contract: {row}")


def _ensure_semantic_role(cur: Any) -> bool:
    row = _role_state(cur)
    if row:
        _assert_semantic_role(row)
        return False
    cur.execute(
        "create role adlog_semantic_worker noinherit nologin "
        "nosuperuser nocreatedb nocreaterole nobypassrls noreplication"
    )
    _assert_semantic_role(_role_state(cur))
    return True


def _apply_migrations(cur: Any) -> list[int]:
    cur.execute("select version,name from schema_migrations order by version")
    markers = {int(row["version"]): str(row["name"]) for row in cur.fetchall()}
    if max(markers, default=0) < 49:
        raise RuntimeError("Stage-8 L1 requires production schema 49")
    applied: list[int] = []
    for version, path in MIGRATIONS.items():
        existing = markers.get(version)
        expected = {
            50: "semantic_worker_least_privilege",
            51: "event_catalog_revision_reference",
            52: "semantic_conclusion_completeness",
            53: "semantic_canonical_action_risk",
            54: "semantic_worker_runtime_schema_guard",
        }[version]
        if existing is not None:
            if existing != expected:
                raise RuntimeError(
                    f"schema marker {version} differs from contract: {existing}"
                )
            if version == 54:
                cur.execute(
                    "select has_table_privilege("
                    "'adlog_semantic_worker','schema_migrations','SELECT'"
                    ") as ready"
                )
                if not bool(cur.fetchone()["ready"]):
                    cur.execute(path.read_text(encoding="utf-8"))
                    applied.append(version)
            continue
        cur.execute(path.read_text(encoding="utf-8"))
        applied.append(version)
        markers[version] = expected
    return applied


def _register_policies(conn: Any) -> list[str]:
    registered: list[str] = []
    with conn.transaction(), conn.cursor() as cur:
        cur.execute("set local role adlog_storage_worker")
        for policy_id, definition in POLICIES:
            policy = RiskPolicyDefinition(
                policy_id=policy_id,
                policy_version=POLICY_VERSION,
                source_kind=ScenarioSourceKind.CANONICAL_ACTION,
                definition=definition,
            )
            register_risk_policy(cur, policy=policy)
            cur.execute(
                """
                select lifecycle_status from semantic_risk_policies
                where policy_id=%s and policy_version=%s
                """,
                (policy_id, POLICY_VERSION),
            )
            status = str(cur.fetchone()["lifecycle_status"])
            transitions = {
                "draft": "validated",
                "validated": "test",
                "test": "shadow",
            }
            while status != "shadow":
                target = transitions.get(status)
                if target is None:
                    raise RuntimeError(
                        f"L1 policy {policy_id} has incompatible state {status}"
                    )
                status = transition_risk_policy(
                    cur,
                    policy_id=policy_id,
                    policy_version=POLICY_VERSION,
                    target_status=target,
                )
            cur.execute(
                """
                select policy_version,lifecycle_status
                from semantic_risk_policies
                where policy_id=%s and policy_version<>%s
                  and lifecycle_status in ('test','shadow','enabled')
                order by policy_version
                for update
                """,
                (policy_id, POLICY_VERSION),
            )
            for older in (dict(row) for row in (cur.fetchall() or [])):
                transition_risk_policy(
                    cur,
                    policy_id=policy_id,
                    policy_version=int(older["policy_version"]),
                    target_status="disabled",
                )
            registered.append(policy_id)
    return registered


def _read_state() -> dict[str, Any]:
    payload = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError("L1 state must contain an object")
    return payload


def _write_state(payload: dict[str, Any]) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = STATE_PATH.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )
    os.replace(temporary, STATE_PATH)


def _create_ephemeral_login(cur: Any) -> tuple[str, str]:
    from psycopg import sql

    suffix = f"{os.getpid()}_{int(datetime.now(timezone.utc).timestamp())}"
    role = f"adlog_semantic_l1_{suffix}"
    password = secrets.token_urlsafe(36)
    cur.execute(
        sql.SQL(
            "create role {} login noinherit nosuperuser nocreatedb "
            "nocreaterole nobypassrls noreplication password {}"
        ).format(sql.Identifier(role), sql.Literal(password))
    )
    cur.execute(
        sql.SQL("grant adlog_semantic_worker to {}").format(
            sql.Identifier(role)
        )
    )
    grant_ephemeral_login_connect(cur, role)
    return role, password


def _drop_ephemeral_login(cur: Any, role: str) -> None:
    from psycopg import sql

    if not role.startswith("adlog_semantic_l1_"):
        raise RuntimeError("refusing unexpected ephemeral role name")
    revoke_ephemeral_login_connect(cur, role)
    cur.execute(sql.SQL("drop role if exists {}").format(sql.Identifier(role)))


def _worker_dsn(*, role: str, password: str) -> str:
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    parts = conninfo_to_dict(os.environ["ADLOG_PG_DSN"])
    parts.update(user=role, password=password)
    return make_conninfo(**parts)


def _authorized_archive_reader(connect_factory) -> ArchiveReader:
    authorization = load_runtime_authorization_if_available(_connect_admin)
    if authorization is None:
        raise RuntimeError("active persisted Storage V2 authorization is required")
    return ArchiveReader(
        PostgresArchiveManifestStore(connect_factory),
        archive_root=Path(authorization.archive_root),
    )


def _run_worker_once(*, limit: int) -> dict[str, object]:
    previous = {
        name: os.environ.get(name)
        for name in (
            "ADLOG_SEMANTIC_WORKER_DSN",
            "ADLOG_SEMANTIC_NORMALIZATION_ENABLED",
            "ADLOG_SEMANTIC_ASSEMBLY_ENABLED",
            "ADLOG_SEMANTIC_DIRECTORY_STATE_ENABLED",
            "ADLOG_SEMANTIC_CORRELATION_ENABLED",
            "ADLOG_SEMANTIC_RISK_ENGINE_ENABLED",
            "ADLOG_SEMANTIC_FINDING_CREATION_ENABLED",
        )
    }
    role = ""
    try:
        with _connect_admin(autocommit=True) as conn, conn.cursor() as cur:
            role, password = _create_ephemeral_login(cur)
        os.environ.update(
            {
                "ADLOG_SEMANTIC_WORKER_DSN": _worker_dsn(
                    role=role, password=password
                ),
                "ADLOG_SEMANTIC_NORMALIZATION_ENABLED": "1",
                "ADLOG_SEMANTIC_ASSEMBLY_ENABLED": "1",
                "ADLOG_SEMANTIC_DIRECTORY_STATE_ENABLED": "0",
                "ADLOG_SEMANTIC_CORRELATION_ENABLED": "1",
                "ADLOG_SEMANTIC_RISK_ENGINE_ENABLED": "1",
                "ADLOG_SEMANTIC_FINDING_CREATION_ENABLED": "0",
            }
        )
        from scripts.runtime.semantic_worker import run_once
        from server.sli.ops.runtime_workers import record_worker_heartbeat
        from server.sli.semantic.semantic_worker_connection import connect_semantic_worker

        archive = _authorized_archive_reader(connect_semantic_worker)
        result = run_once(limit=limit, archive=archive)
        record_worker_heartbeat(
            worker_name="semantic",
            worker_id=f"semantic-l1-manual-{os.getpid()}",
            status="stopped",
            phase="manual_poll_complete",
            expected_interval_seconds=180,
            started_at=datetime.now(timezone.utc),
            details={
                "last_result": result,
                "allowed_modes": ["test", "shadow"],
                "manual_runtime": True,
            },
            connection_factory=connect_semantic_worker,
        )
        return result
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        if role:
            with _connect_admin(autocommit=True) as conn, conn.cursor() as cur:
                _drop_ephemeral_login(cur, role)


def plan() -> dict[str, Any]:
    _load_environment()
    with _connect_admin() as conn, conn.cursor() as cur:
        cur.execute("set transaction read only")
        snapshot = _snapshot(cur)
        role = _role_state(cur)
    return {
        "status": "planned_read_only",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "database": redact_dsn(_admin_dsn()),
        "snapshot": snapshot,
        "semantic_role": role or None,
        "production_changed": False,
        "surveyed_servers_contacted": False,
    }


def apply() -> dict[str, Any]:
    _load_environment()
    previous_state = _read_state() if STATE_PATH.exists() else None
    with _connect_admin(autocommit=True) as conn, conn.cursor() as cur:
        before = _snapshot(cur)
        if bool(before["semantic_worker_live"]):
            raise RuntimeError("continuous semantic worker is already live")
        role_created = _ensure_semantic_role(cur)
        applied = _apply_migrations(cur)
    with _connect_admin() as conn:
        registered = _register_policies(conn)
    with _connect_admin() as conn, conn.cursor() as cur:
        after = _snapshot(cur)
    if int(after["findings"]) != int(before["findings"]):
        raise RuntimeError("L1 setup changed legacy findings")
    if previous_state is not None:
        if set(previous_state.get("policy_ids") or ()) != set(registered):
            raise RuntimeError("existing L1 state policy set differs from runtime")
        if int(previous_state["production_findings_baseline"]) != int(
            after["findings"]
        ):
            raise RuntimeError("existing L1 findings baseline differs from runtime")
        state = dict(previous_state)
        state["schema_migrations_applied"] = sorted(
            {
                *(
                    int(item)
                    for item in previous_state.get(
                        "schema_migrations_applied", []
                    )
                ),
                *applied,
            }
        )
        state["semantic_role_created"] = bool(
            previous_state.get("semantic_role_created") or role_created
        )
        state["last_maintenance_at_utc"] = datetime.now(
            timezone.utc
        ).isoformat()
        state["last_snapshot"] = after
    else:
        state = {
            "package_type": "STAGE8_L1_BOUNDED_SHADOW",
            "status": "waiting_for_new_events",
            "started_at_utc": datetime.now(timezone.utc).isoformat(),
            "start_event_id": int(after["max_event_id"]),
            "watermark_event_id": int(after["max_event_id"]),
            "polls": [],
            "policy_ids": registered,
            "evidence_contract_version": 1,
            "policy_versions": {policy_id: POLICY_VERSION for policy_id in registered},
            "input_event_ids": [],
            "target_scenario_kinds": sorted(set(TARGET_KINDS.values())),
            "manual_runtime": True,
            "finding_creation_enabled": False,
            "production_findings_baseline": int(after["findings"]),
            "schema_migrations_applied": applied,
            "semantic_role_created": role_created,
            "last_snapshot": after,
        }
    _write_state(state)
    return {
        "status": (
            "updated_existing_shadow"
            if previous_state is not None
            else "started_waiting_for_new_events"
        ),
        "state_path": str(STATE_PATH),
        "schema_migrations_applied": applied,
        "semantic_role_created": role_created,
        "policies": registered,
        "start_event_id": state["start_event_id"],
        "findings_unchanged": True,
        "continuous_worker_started": False,
        "manual_poll_required": True,
        "surveyed_servers_contacted": False,
    }


def poll(*, limit: int) -> dict[str, Any]:
    _load_environment()
    state = _read_state()
    watermark = int(state["watermark_event_id"])
    with _connect_admin() as conn, conn.cursor() as cur:
        before = _snapshot(cur)
        if bool(before["semantic_worker_live"]):
            raise RuntimeError("another semantic worker is live")
        cur.execute(
            """
            select core.id
            from events_v2_core core
            join storage_v2_channel channel on channel.id=core.channel_id
            left join storage_v2_provider provider on provider.id=core.provider_id
            where core.id>%s and core.id<=%s and (
              (
                channel.value='Security'
                and provider.value='Microsoft-Windows-Eventlog'
                and core.event_id=1102
              )
              or (
                channel.value='Security'
                and provider.value='Microsoft-Windows-Security-Auditing'
                and core.event_id in (4719,4728,4732)
              )
              or (
                channel.value='Microsoft-Windows-TaskScheduler/Operational'
                and provider.value='Microsoft-Windows-TaskScheduler'
                and core.event_id=106
              )
            )
            order by core.id limit %s
            """,
            (watermark, int(before["max_event_id"]), 5000),
        )
        target_ids = [int(row["id"]) for row in (cur.fetchall() or [])]
        upper_bound = int(before["max_event_id"])
    if target_ids and len(target_ids) == 5000:
        next_watermark = target_ids[-1]
    else:
        next_watermark = upper_bound
    # Do not infer scoped evidence for legacy state from its old poll totals.
    scoped_ids = _shadow_scope(state)
    evidence_state = dict(state)
    if scoped_ids is not None:
        evidence_state["input_event_ids"] = sorted(set(scoped_ids) | set(target_ids))
    evidence_state["watermark_event_id"] = next_watermark
    with _connect_admin() as conn:
        with conn.transaction(), conn.cursor() as cur:
            cur.execute("set local role adlog_storage_worker")
            published = publish_semantic_candidates(cur, target_ids)
    worker = _run_worker_once(limit=max(1, min(int(limit), 16)))
    with _connect_admin() as conn, conn.cursor() as cur:
        after = _snapshot(cur)
        shadow_evidence = _shadow_evidence(cur, evidence_state)
    baseline = int(state["production_findings_baseline"])
    if int(after["findings"]) != baseline:
        raise RuntimeError("L1 SHADOW changed legacy findings")
    poll_result = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "from_event_id_exclusive": watermark,
        "to_event_id_inclusive": next_watermark,
        "target_new_events": len(target_ids),
        "shadow_evidence": shadow_evidence,
        "producer": published,
        "worker": worker,
        "findings_unchanged": True,
        "snapshot": after,
    }
    state["watermark_event_id"] = next_watermark
    state["polls"] = [*(state.get("polls") or []), poll_result][-100:]
    if scoped_ids is not None:
        state["input_event_ids"] = evidence_state["input_event_ids"]
    state["status"] = {
        "complete": "shadow_evidence_complete",
        "incomplete": "waiting_for_new_events",
        "unknown": "shadow_evidence_unknown",
    }[shadow_evidence["status"]]
    state["last_snapshot"] = after
    _write_state(state)
    return {
        "status": state["status"],
        "state_path": str(STATE_PATH),
        **poll_result,
        "continuous_worker_started": False,
        "surveyed_servers_contacted": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "apply", "poll"))
    parser.add_argument("--confirm")
    parser.add_argument("--limit", type=int, default=16)
    args = parser.parse_args()
    try:
        if args.action == "plan":
            payload = plan()
        elif args.action == "apply":
            if args.confirm != APPLY_CONFIRM:
                payload = {"status": "blocked", "connections": 0}
            else:
                payload = apply()
        else:
            if args.confirm != POLL_CONFIRM:
                payload = {"status": "blocked", "connections": 0}
            else:
                payload = poll(limit=args.limit)
    except Exception as exc:  # noqa: BLE001
        payload = {
            "status": "failed",
            "error_type": type(exc).__name__,
            "error": str(exc),
        }
    print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
    return 0 if payload["status"] not in {"failed"} else 1


if __name__ == "__main__":
    raise SystemExit(main())

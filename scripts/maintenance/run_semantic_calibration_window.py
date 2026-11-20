"""Run one bounded semantic TEST -> SHADOW calibration scenario.

The command is deliberately fail-closed:

* ``plan`` is read-only and selects exact, archive-verified Security evidence;
* ``test`` writes one TEST evaluation and must not create a scenario;
* ``shadow`` requires the accepted TEST artifact, writes at most one SHADOW
  scenario, enforces the total authorised evaluation ceiling, and disables the
  calibration rule and policy before returning.

No raw payload, SID, account, host name, LogonId or credential is written to
the result artifacts.  The script never creates legacy findings and never
registers a continuous worker.
"""
from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
from time import perf_counter
import sys
import tempfile
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.semantic.semantic_correlation import (  # noqa: E402
    SemanticRelation,
    aggregate_bruteforce_attempts,
    correlate_session_privilege_observation,
)
from server.sli.semantic.semantic_correlation_repository import (  # noqa: E402
    CorrelationRuleDefinition,
    persist_correlation_candidate,
    register_correlation_rule,
    transition_correlation_rule,
)
from server.sli.semantic.semantic_processing import (  # noqa: E402
    NormalizedEvent,
    SemanticFeatureSettings,
    StoredEvent,
    normalize_windows_event,
)
from server.sli.semantic.semantic_processing_repository import persist_normalized_event  # noqa: E402
from server.sli.semantic.semantic_calibration_contract import (  # noqa: E402
    MAX_AUTHORISED_SHADOW_EVALUATIONS,
)
from server.sli.semantic.semantic_risk import ScenarioSourceKind  # noqa: E402
from server.sli.semantic.semantic_risk_policy import RiskPolicyDefinition  # noqa: E402
from server.sli.semantic.semantic_risk_runtime_repository import (  # noqa: E402
    claim_risk_evaluation_jobs,
    enqueue_candidate_risk_jobs,
    execute_risk_evaluation,
    fail_risk_evaluation_job,
    load_risk_evaluation_work_item,
    register_risk_policy,
    transition_risk_policy,
)
from server.sli.storage.storage_v2_archive import ArchiveReader  # noqa: E402
from server.sli.storage.storage_v2_config import load_storage_v2_settings  # noqa: E402
from server.sli.storage.storage_v2_models import parse_utc_timestamp  # noqa: E402
from server.sli.storage.storage_v2_repository import PostgresArchiveManifestStore  # noqa: E402


VERSION = 1
MAX_EVALUATIONS = 1
MAX_ARCHIVE_BLOCKS = 4
ARTIFACTS = (ROOT / "artifacts").resolve()


@dataclass(frozen=True, kw_only=True)
class CalibrationProfile:
    key: str
    calibration_id: str
    event_ids: tuple[int, ...]
    evidence_count: int
    rule_kind: str
    input_types: tuple[str, ...]
    join_roles: tuple[str, ...]
    window_seconds: int
    relation_kind: str
    scenario_kind: str
    result_class: str
    strict_roles: tuple[str, ...]
    merge_window_seconds: int
    title: str
    explanation: str
    risk_class: str
    raw_score: str
    display_points: int
    rationale: str

    @property
    def rule_id(self) -> str:
        return f"{self.calibration_id}-rule"

    @property
    def policy_id(self) -> str:
        return f"{self.calibration_id}-policy"


SESSION_PRIVILEGES = CalibrationProfile(
    key="session-privileges",
    calibration_id="semantic-calibration-session-privileges-20260719",
    event_ids=(4624, 4672),
    evidence_count=2,
    rule_kind="all_of",
    input_types=(
        "authentication.session.created",
        "authentication.privileged_session.created",
    ),
    join_roles=("source_host", "session_principal"),
    window_seconds=900,
    relation_kind="authentication.session.has_special_privileges",
    scenario_kind="authentication.session.special_privileges_observed",
    result_class="security_exposure",
    strict_roles=("session_principal",),
    merge_window_seconds=1800,
    title="Сессия со специальными привилегиями",
    explanation=(
        "Точно совпали source_host и LogonId для 4624/4672; "
        "это наблюдение сессии, а не доказательство повышения прав."
    ),
    risk_class="info",
    raw_score="5",
    display_points=5,
    rationale=(
        "4672 подтверждает наличие специальных привилегий в сессии, "
        "но сам по себе не является инцидентом."
    ),
)

AUTH_FAILURE_BURST = CalibrationProfile(
    key="authentication-failure-burst",
    calibration_id="semantic-calibration-auth-failure-burst-20260719",
    event_ids=(4625,),
    evidence_count=5,
    rule_kind="count",
    input_types=("authentication.session.failed",),
    join_roles=("source_host", "affected_entity", "source_ip"),
    window_seconds=600,
    relation_kind="authentication.bruteforce.suspected",
    scenario_kind="authentication.bruteforce.suspected",
    result_class="security_exposure",
    strict_roles=("affected_entity", "source_ip"),
    merge_window_seconds=600,
    title="Серия неуспешных входов",
    explanation=(
        "Не менее пяти 4625 относятся к одной учётной записи и одному "
        "источнику IP на одном DC в пределах десяти минут."
    ),
    risk_class="low",
    raw_score="25",
    display_points=25,
    rationale=(
        "Точный bounded-кластер неуспешных входов требует проверки, но без "
        "успешного входа или подтверждённого воздействия не является инцидентом."
    ),
)

PROFILES = {
    SESSION_PRIVILEGES.key: SESSION_PRIVILEGES,
    AUTH_FAILURE_BURST.key: AUTH_FAILURE_BURST,
}

SNAPSHOT_COUNT_FIELDS = (
    "findings",
    "normalized_events",
    "candidates",
    "risk_jobs",
    "risk_results",
    "scenarios",
    "canonical_actions",
    "shadow_results",
    "risk_open_jobs",
    "risk_errors",
    "semantic_worker_heartbeats",
)


@dataclass(frozen=True, kw_only=True)
class SelectedEvidence:
    events: tuple[NormalizedEvent, ...]
    relation: SemanticRelation
    fingerprint_sha256: str
    partition_sha256: str

    @property
    def source_event_ids(self) -> tuple[int, ...]:
        return tuple(sorted(item.source_event_id for item in self.events))


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def _safe_artifact_path(value: Path) -> Path:
    path = value.resolve()
    try:
        path.relative_to(ARTIFACTS)
    except ValueError as exc:
        raise ValueError("calibration artifacts must stay under ProjectRoot/artifacts") from exc
    if path.suffix.casefold() != ".json":
        raise ValueError("calibration artifact must use a .json suffix")
    return path


def _write_json_atomic(path: Path, payload: Mapping[str, object]) -> None:
    target = _safe_artifact_path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True, default=str)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=target.parent,
        prefix=f".{target.name}.",
        suffix=".tmp",
        text=True,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(encoded)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(target)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _read_json(path: Path) -> dict[str, Any]:
    source = _safe_artifact_path(path)
    payload = json.loads(source.read_text(encoding="utf-8-sig"))
    if not isinstance(payload, Mapping):
        raise ValueError("calibration artifact must contain a JSON object")
    return dict(payload)


def _connect(*, role: str, read_only: bool = False):
    import psycopg
    from psycopg.conninfo import conninfo_to_dict
    from psycopg.rows import dict_row

    if role not in {"adlog_user", "adlog_storage_worker"}:
        raise ValueError("unsupported calibration database role")
    base_dsn = os.getenv("ADLOG_PG_DSN", "").strip()
    if not base_dsn:
        raise RuntimeError("ADLOG_PG_DSN is required")
    parts = conninfo_to_dict(base_dsn)
    admin_user = os.getenv("ADLOG_PG_ADMIN_USER", "").strip()
    admin_password = os.getenv("ADLOG_PG_ADMIN_PASSWORD", "")
    if not admin_user or not admin_password:
        raise RuntimeError("protected local PostgreSQL admin credentials are required")
    parts.update(
        user=admin_user,
        password=admin_password,
        connect_timeout=5,
        application_name=f"adlog_semantic_calibration_{role}",
        options="-c statement_timeout=30000 -c lock_timeout=5000",
    )
    conn = psycopg.connect(**parts, row_factory=dict_row)
    with conn.cursor() as cur:
        if role == "adlog_user":
            cur.execute("set role adlog_user")
        else:
            cur.execute("set role adlog_storage_worker")
        cur.execute("select current_user as role")
        actual = str(dict(cur.fetchone() or {}).get("role") or "")
        if actual != role:
            raise RuntimeError("least-privilege PostgreSQL role activation failed")
    conn.commit()
    if read_only:
        conn.read_only = True
    return conn


def _archive_reader() -> ArchiveReader:
    load_storage_v2_settings(strict=True)
    return ArchiveReader(
        PostgresArchiveManifestStore(
            lambda: _connect(role="adlog_storage_worker", read_only=True)
        ),
    )


def _event_data(value: object) -> Mapping[str, object]:
    if isinstance(value, Mapping):
        return dict(value)
    parsed = json.loads(str(value or "{}"))
    if not isinstance(parsed, Mapping):
        raise ValueError("event_data_json must contain a named object")
    return dict(parsed)


def _stored_event(row: Mapping[str, Any]) -> StoredEvent:
    return StoredEvent(
        event_id=int(row["id"]),
        windows_event_id=int(row["event_id"]),
        channel=str(row["channel"]),
        server=str(row.get("computer") or row["server_id"]),
        occurred_at_utc=parse_utc_timestamp(row["time_created_utc"]),
        event_data=_event_data(row.get("event_data_json")),
        provider=str(row.get("provider_name") or "") or None,
        correlation_id=str(row.get("correlation_id") or "") or None,
        source_host_id=row["server_id"],
    )


def _hydrate_exact_rows(
    metadata: Sequence[Mapping[str, Any]],
) -> dict[int, Mapping[str, Any]]:
    if not metadata:
        return {}
    ids = {int(item["id"]) for item in metadata}
    archive = _archive_reader()
    blocks = archive.manifest.find_published_range(
        "event", min(ids), max(ids), MAX_ARCHIVE_BLOCKS + 1
    )
    if len(blocks) > MAX_ARCHIVE_BLOCKS:
        raise RuntimeError("calibration evidence spans more than four archive blocks")
    rows: dict[int, Mapping[str, Any]] = {}
    for block in blocks:
        for row in archive.read_block_rows(block):
            event_id = int(row["id"])
            if event_id in ids:
                rows[event_id] = row
    missing = sorted(ids - rows.keys())
    if missing:
        raise RuntimeError(f"verified archive is missing selected event IDs: {missing[:4]}")
    by_id = {int(item["id"]): item for item in metadata}
    for event_id, row in rows.items():
        expected = by_id[event_id]
        if (
            int(row["event_id"]) != int(expected["event_id"])
            or int(row["server_id"]) != int(expected["server_id"])
            or parse_utc_timestamp(row["time_created_utc"])
            != parse_utc_timestamp(expected["time_created_utc"])
            or str(row["channel"]).casefold() != "security"
        ):
            raise RuntimeError("archive/core identity mismatch for calibration evidence")
    return rows


def _fingerprint(events: Sequence[NormalizedEvent], relation: SemanticRelation) -> str:
    payload = {
        "source_event_ids": sorted(item.source_event_id for item in events),
        "semantic_sha256": {
            str(item.source_event_id): item.semantic_sha256 for item in events
        },
        "relation_kind": relation.relation_kind,
        "relation_contribution_sha256": sha256(
            relation.contribution_key.encode("utf-8")
        ).hexdigest(),
    }
    return sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _profile_from_plan(plan: Mapping[str, Any]) -> CalibrationProfile:
    key = str(plan.get("scenario_profile") or SESSION_PRIVILEGES.key)
    try:
        profile = PROFILES[key]
    except KeyError as exc:
        raise ValueError(f"unsupported calibration scenario profile: {key}") from exc
    if str(plan.get("calibration_id") or "") != profile.calibration_id:
        raise ValueError("calibration plan profile identity does not match calibration_id")
    return profile


def _selected(
    profile: CalibrationProfile,
    events: Sequence[NormalizedEvent],
) -> SelectedEvidence:
    if len(events) != profile.evidence_count:
        raise ValueError(
            f"{profile.key} calibration requires exactly {profile.evidence_count} events"
        )
    ordered = tuple(sorted(events, key=lambda item: item.source_event_id))
    if profile is SESSION_PRIVILEGES:
        relations = correlate_session_privilege_observation(
            ordered,
            window=timedelta(seconds=profile.window_seconds),
        )
    else:
        relations = aggregate_bruteforce_attempts(
            ordered,
            minimum_failures=profile.evidence_count,
            window=timedelta(seconds=profile.window_seconds),
        )
    if len(relations) != 1:
        raise RuntimeError(f"selected evidence is not one exact {profile.relation_kind} relation")
    relation = relations[0]
    if relation.relation_kind != profile.relation_kind:
        raise RuntimeError("selected evidence relation kind does not match the profile")
    partitions = {str(item.roles.get("source_host") or "") for item in ordered}
    if len(partitions) != 1 or "" in partitions:
        raise RuntimeError("selected evidence does not have one exact source_host")
    for role in profile.strict_roles:
        values = {str(item.roles.get(role) or "") for item in ordered}
        if len(values) != 1 or "" in values:
            raise RuntimeError(f"selected evidence does not have one exact {role}")
    return SelectedEvidence(
        events=ordered,
        relation=relation,
        fingerprint_sha256=_fingerprint(ordered, relation),
        partition_sha256=sha256(next(iter(partitions)).encode("utf-8")).hexdigest(),
    )


def _find_recent_evidence(
    profile: CalibrationProfile,
    *,
    hours: int,
    candidate_limit: int,
) -> SelectedEvidence:
    with _connect(role="adlog_storage_worker", read_only=True) as conn:
        with conn.cursor() as cur:
            if profile is SESSION_PRIVILEGES:
                cur.execute(
                    """
                    with recent_privilege as (
                        select core.id,core.event_id,core.server_id,core.logon_id,
                               core.time_created_utc
                        from events_v2_core core
                        join storage_v2_channel channel on channel.id=core.channel_id
                        where channel.value=%s and core.event_id=%s
                          and core.logon_id is not null
                          and core.time_created_utc >= now()-(%s * interval '1 hour')
                        order by core.id desc limit %s
                    )
                    select privilege.id as privilege_id,
                           privilege.event_id as privilege_event_id,
                           privilege.server_id as privilege_server_id,
                           privilege.time_created_utc as privilege_time_created_utc,
                           session.id as session_id,
                           session.event_id as session_event_id,
                           session.server_id as session_server_id,
                           session.time_created_utc as session_time_created_utc
                    from recent_privilege privilege
                    join events_v2_core session
                      on session.server_id=privilege.server_id
                     and session.logon_id=privilege.logon_id
                     and session.event_id=%s
                     and session.time_created_utc between
                         privilege.time_created_utc-interval '15 minutes'
                         and privilege.time_created_utc+interval '15 minutes'
                    order by privilege.time_created_utc desc,
                             abs(extract(epoch from
                                 (privilege.time_created_utc-session.time_created_utc))),
                             session.id desc
                    limit 1
                    """,
                    ("Security", 4672, int(hours), int(candidate_limit), 4624),
                )
                pair = dict(cur.fetchone() or {})
                metadata = (
                    [
                        {
                            "id": pair["session_id"],
                            "event_id": pair["session_event_id"],
                            "server_id": pair["session_server_id"],
                            "time_created_utc": pair["session_time_created_utc"],
                        },
                        {
                            "id": pair["privilege_id"],
                            "event_id": pair["privilege_event_id"],
                            "server_id": pair["privilege_server_id"],
                            "time_created_utc": pair["privilege_time_created_utc"],
                        },
                    ]
                    if pair
                    else []
                )
            else:
                cur.execute(
                    """
                    with recent as materialized (
                        select core.id,core.event_id,core.server_id,
                               coalesce(nullif(core.target_user_sid,''),
                                        nullif(lower(core.target_user_name),'')) as target_key,
                               nullif(core.ip_address,'') as source_ip,
                               core.time_created_utc
                        from events_v2_core core
                        join storage_v2_channel channel on channel.id=core.channel_id
                        where channel.value=%s and core.event_id=%s
                          and core.time_created_utc >= now()-(%s * interval '1 hour')
                          and coalesce(nullif(core.target_user_sid,''),
                                       nullif(lower(core.target_user_name),'')) is not null
                          and nullif(core.ip_address,'') is not null
                          and core.ip_address not in ('-','::1','127.0.0.1')
                        order by core.id desc limit %s
                    ), candidate as (
                        select anchor.id as anchor_id,anchor.time_created_utc,
                               array_agg(member.id order by member.time_created_utc,member.id)
                                   as event_ids
                        from recent anchor
                        join recent member
                          on member.server_id=anchor.server_id
                         and member.target_key=anchor.target_key
                         and member.source_ip=anchor.source_ip
                         and member.time_created_utc between anchor.time_created_utc
                             and anchor.time_created_utc+interval '10 minutes'
                        group by anchor.id,anchor.time_created_utc
                        having count(*) >= %s
                        order by anchor.time_created_utc desc,anchor.id desc
                        limit 1
                    )
                    select core.id,core.event_id,core.server_id,core.time_created_utc
                    from events_v2_core core
                    join candidate on core.id=any(candidate.event_ids[1:%s])
                    order by core.time_created_utc,core.id
                    """,
                    (
                        "Security",
                        4625,
                        int(hours),
                        int(candidate_limit),
                        profile.evidence_count,
                        profile.evidence_count,
                    ),
                )
                metadata = [dict(item) for item in (cur.fetchall() or [])]
    if len(metadata) != profile.evidence_count:
        raise RuntimeError(f"no recent exact {profile.key} evidence is available")
    rows = _hydrate_exact_rows(metadata)
    normalized = tuple(
        normalize_windows_event(_stored_event(rows[int(item["id"])]))
        for item in metadata
    )
    return _selected(profile, normalized)


def _load_selected_from_plan(plan: Mapping[str, Any]) -> SelectedEvidence:
    if plan.get("package_type") != "SEMANTIC_CALIBRATION_PLAN":
        raise ValueError("unexpected calibration plan package type")
    profile = _profile_from_plan(plan)
    event_rows = plan.get("evidence")
    if not isinstance(event_rows, Sequence) or isinstance(event_rows, (str, bytes)):
        raise ValueError("calibration plan evidence must be a list")
    ids = sorted(int(dict(item)["event_db_id"]) for item in event_rows)
    if len(ids) != profile.evidence_count or len(set(ids)) != profile.evidence_count:
        raise ValueError("calibration plan does not contain the exact evidence count")
    with _connect(role="adlog_storage_worker", read_only=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select core.id,core.event_id,core.server_id,core.time_created_utc
                from events_v2_core core
                join storage_v2_channel channel on channel.id=core.channel_id
                where channel.value=%s and core.id=any(%s)
                order by core.id
                """,
                ("Security", ids),
            )
            metadata = [dict(item) for item in (cur.fetchall() or [])]
    if len(metadata) != profile.evidence_count:
        raise RuntimeError("planned evidence is no longer available in events_v2_core")
    rows = _hydrate_exact_rows(metadata)
    selected = _selected(
        profile,
        tuple(normalize_windows_event(_stored_event(rows[int(item["id"])])) for item in metadata)
    )
    if selected.fingerprint_sha256 != str(plan.get("evidence_fingerprint_sha256") or ""):
        raise RuntimeError("calibration evidence fingerprint changed")
    return selected


def _snapshot() -> dict[str, Any]:
    with _connect(role="adlog_user", read_only=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select
                  current_database() as database_name,
                  (select max(version) from schema_migrations) as runtime_marker,
                  (select count(*) from findings) as findings,
                  (select count(*) from normalized_events) as normalized_events,
                  (select count(*) from semantic_correlation_candidates) as candidates,
                  (select count(*) from semantic_risk_evaluation_jobs) as risk_jobs,
                  (select count(*) from semantic_risk_evaluation_results) as risk_results,
                  (select count(*) from semantic_security_scenarios) as scenarios,
                  (select count(*) from canonical_actions) as canonical_actions,
                  (select count(*) from semantic_risk_evaluation_results
                   where evaluation_mode='shadow') as shadow_results,
                  (select count(*) from semantic_risk_evaluation_jobs
                   where evaluation_status in ('queued','leased')) as risk_open_jobs,
                  (select count(*) from semantic_risk_evaluation_jobs
                   where evaluation_status in ('failed','quarantined')) as risk_errors,
                  (select count(*) from runtime_worker_heartbeats
                   where worker_name='semantic') as semantic_worker_heartbeats,
                  exists(
                    select 1 from runtime_worker_heartbeats
                    where worker_name='semantic'
                      and status not in ('stopped','disabled')
                      and heartbeat_at >= now()-(
                        greatest(180,expected_interval_seconds*3)
                        * interval '1 second'
                      )
                  ) as semantic_worker_live
                """
            )
            return dict(cur.fetchone() or {})


def _ensure_execution_flags() -> None:
    settings = SemanticFeatureSettings.from_env()
    if not (
        settings.normalization_enabled
        and settings.assembly_enabled
        and settings.correlation_enabled
        and settings.risk_engine_enabled
    ):
        raise RuntimeError("the process-local semantic dependency chain is not enabled")
    if settings.finding_creation_enabled:
        raise RuntimeError("ADLOG_SEMANTIC_FINDING_CREATION_ENABLED must remain false")


def _rule_definition(profile: CalibrationProfile) -> CorrelationRuleDefinition:
    definition: dict[str, object] = {
        "type": profile.rule_kind,
        "inputs": list(profile.input_types),
        "window_seconds": profile.window_seconds,
        "join_roles": list(profile.join_roles),
        "output_relation_kind": profile.relation_kind,
        "confidence": "high" if profile is SESSION_PRIVILEGES else "medium",
        "explanation": profile.explanation,
    }
    if profile.rule_kind == "count":
        definition["minimum_count"] = profile.evidence_count
    return CorrelationRuleDefinition(
        rule_id=profile.rule_id,
        rule_version=VERSION,
        rule_kind=profile.rule_kind,
        definition=definition,
    )


def _policy_definition(profile: CalibrationProfile) -> RiskPolicyDefinition:
    return RiskPolicyDefinition(
        policy_id=profile.policy_id,
        policy_version=VERSION,
        source_kind=ScenarioSourceKind.CORRELATION_CANDIDATE,
        definition={
            "type": "scenario_policy",
            "source_selector": {"relation_kind": profile.relation_kind},
            "scenario_kind": profile.scenario_kind,
            "result_class": profile.result_class,
            "strict_roles": list(profile.strict_roles),
            "merge_window_seconds": profile.merge_window_seconds,
            "title": profile.title,
            "explanation": profile.explanation,
            "expected_evidence_count": profile.evidence_count,
            "required_controls": ["security-audit-logon"],
            "risk": {
                "class": profile.risk_class,
                "raw_score": profile.raw_score,
                "display_points": profile.display_points,
                "hard_critical": False,
                "rationale": profile.rationale,
            },
        },
    )


def _assert_runtime_safe(snapshot: Mapping[str, Any]) -> None:
    if int(snapshot.get("runtime_marker") or 0) < 32:
        raise RuntimeError("production runtime marker 32 is required")
    if int(snapshot.get("risk_errors") or 0) != 0:
        raise RuntimeError("calibration is blocked by semantic risk errors")
    if int(snapshot.get("risk_open_jobs") or 0) != 0:
        raise RuntimeError("calibration is blocked by another open semantic risk job")
    if bool(snapshot.get("semantic_worker_live")):
        raise RuntimeError("continuous semantic worker must not be live")
    if int(snapshot.get("shadow_results") or 0) >= MAX_AUTHORISED_SHADOW_EVALUATIONS:
        raise RuntimeError("the authorised SHADOW evaluation ceiling is exhausted")


def _assert_snapshot_matches(
    current: Mapping[str, Any],
    expected: Mapping[str, Any],
    *,
    fields: Sequence[str],
) -> None:
    for field in fields:
        if int(current.get(field) or 0) != int(expected.get(field) or 0):
            raise RuntimeError(f"calibration baseline changed after approval: {field}")


def _assert_profile_unused(profile: CalibrationProfile) -> None:
    with _connect(role="adlog_user", read_only=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "select count(*) as count from semantic_correlation_rules "
                "where rule_id=%s and rule_version=%s",
                (profile.rule_id, VERSION),
            )
            rule_count = int(dict(cur.fetchone() or {}).get("count") or 0)
            cur.execute(
                "select count(*) as count from semantic_risk_policies "
                "where policy_id=%s and policy_version=%s",
                (profile.policy_id, VERSION),
            )
            policy_count = int(dict(cur.fetchone() or {}).get("count") or 0)
    if rule_count or policy_count:
        raise RuntimeError("calibration profile version is already registered")


def _assert_evidence_unseen(selected: SelectedEvidence) -> None:
    with _connect(role="adlog_user", read_only=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "select count(*) as count from normalized_events "
                "where source_event_id=any(%s)",
                (list(selected.source_event_ids),),
            )
            count = int(dict(cur.fetchone() or {}).get("count") or 0)
    if count:
        raise RuntimeError("calibration evidence is already present in normalized_events")


def _execute_expected_job(conn: Any, *, expected_job_id: str):
    with conn.transaction(), conn.cursor() as cur:
        claimed = claim_risk_evaluation_jobs(cur, limit=MAX_EVALUATIONS)
    if len(claimed) != 1 or str(claimed[0]["job_id"]) != expected_job_id:
        raise RuntimeError("risk claim did not return the exact calibration job")
    job = claimed[0]
    started = perf_counter()
    try:
        with conn.transaction(), conn.cursor() as cur:
            work = load_risk_evaluation_work_item(
                cur,
                job_id=str(job["job_id"]),
                lease_token=str(job["lease_token"]),
            )
            return execute_risk_evaluation(
                cur,
                work=work,
                evaluation_ms=max(0, int((perf_counter() - started) * 1000)),
            )
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
        raise


def _plan(
    profile: CalibrationProfile,
    *,
    hours: int,
    candidate_limit: int,
) -> dict[str, Any]:
    before = _snapshot()
    _assert_runtime_safe(before)
    _assert_profile_unused(profile)
    selected = _find_recent_evidence(
        profile,
        hours=hours,
        candidate_limit=candidate_limit,
    )
    _assert_evidence_unseen(selected)
    return {
        "package_type": "SEMANTIC_CALIBRATION_PLAN",
        "status": "planned_read_only",
        "generated_at_utc": _utc_now().isoformat(),
        "calibration_id": profile.calibration_id,
        "scenario_profile": profile.key,
        "relation_kind": profile.relation_kind,
        "scenario_kind": profile.scenario_kind,
        "database_name": before["database_name"],
        "runtime_marker": before["runtime_marker"],
        "window_hours": hours,
        "candidate_limit": candidate_limit,
        "max_evaluations": MAX_EVALUATIONS,
        "maximum_authorised_shadow_evaluations": MAX_AUTHORISED_SHADOW_EVALUATIONS,
        "remaining_shadow_evaluations_before": (
            MAX_AUTHORISED_SHADOW_EVALUATIONS - int(before["shadow_results"])
        ),
        "evidence_fingerprint_sha256": selected.fingerprint_sha256,
        "partition_sha256": selected.partition_sha256,
        "evidence": [
            {
                "event_db_id": item.source_event_id,
                "windows_event_id": int(item.facts["windows_event_id"]),
                "semantic_type": item.semantic_type,
                "occurred_at_utc": item.occurred_at_utc.isoformat(),
                "semantic_sha256": item.semantic_sha256,
            }
            for item in selected.events
        ],
        "before": before,
        "payload_persisted": False,
        "sensitive_identity_persisted": False,
        "connections_read_only": True,
    }


def _validate_artifact_age(payload: Mapping[str, Any], *, maximum_minutes: int) -> None:
    created = parse_utc_timestamp(payload["generated_at_utc"])
    age = _utc_now() - created
    if age < timedelta(minutes=-1) or age > timedelta(minutes=maximum_minutes):
        raise RuntimeError("calibration artifact is outside the approved execution window")


def _test(*, plan: Mapping[str, Any], max_age_minutes: int) -> dict[str, Any]:
    _ensure_execution_flags()
    _validate_artifact_age(plan, maximum_minutes=max_age_minutes)
    profile = _profile_from_plan(plan)
    selected = _load_selected_from_plan(plan)
    before = _snapshot()
    _assert_runtime_safe(before)
    _assert_profile_unused(profile)
    _assert_evidence_unseen(selected)
    _assert_snapshot_matches(
        before,
        dict(plan["before"]),
        fields=SNAPSHOT_COUNT_FIELDS,
    )
    with _connect(role="adlog_storage_worker") as conn:
        with conn.transaction(), conn.cursor() as cur:
            for event in selected.events:
                persist_normalized_event(cur, event=event)
            register_correlation_rule(cur, rule=_rule_definition(profile))
            transition_correlation_rule(
                cur,
                rule_id=profile.rule_id,
                rule_version=VERSION,
                target_status="validated",
            )
            transition_correlation_rule(
                cur,
                rule_id=profile.rule_id,
                rule_version=VERSION,
                target_status="test",
            )
            candidate_id = persist_correlation_candidate(
                cur,
                rule_id=profile.rule_id,
                rule_version=VERSION,
                relation=selected.relation,
            )
            register_risk_policy(cur, policy=_policy_definition(profile))
            transition_risk_policy(
                cur,
                policy_id=profile.policy_id,
                policy_version=VERSION,
                target_status="validated",
            )
            transition_risk_policy(
                cur,
                policy_id=profile.policy_id,
                policy_version=VERSION,
                target_status="test",
            )
            job_ids = enqueue_candidate_risk_jobs(cur, candidate_id=candidate_id)
            if len(job_ids) != 1:
                raise RuntimeError("TEST calibration did not enqueue exactly one job")
        result = _execute_expected_job(conn, expected_job_id=job_ids[0])
    after = _snapshot()
    if result.evaluation_mode != "test" or result.scenario_id is not None:
        raise RuntimeError("TEST calibration unexpectedly persisted a scenario")
    if int(after["scenarios"]) != int(before["scenarios"]):
        raise RuntimeError("TEST calibration changed scenario count")
    if int(after["findings"]) != int(before["findings"]):
        raise RuntimeError("TEST calibration changed legacy findings")
    if int(after["risk_errors"]) != 0:
        raise RuntimeError("TEST calibration recorded risk errors")
    expected_after = dict(before)
    expected_after.update(
        normalized_events=int(before["normalized_events"]) + profile.evidence_count,
        candidates=int(before["candidates"]) + 1,
        risk_jobs=int(before["risk_jobs"]) + 1,
        risk_results=int(before["risk_results"]) + 1,
    )
    _assert_snapshot_matches(after, expected_after, fields=SNAPSHOT_COUNT_FIELDS)
    return {
        "package_type": "SEMANTIC_CALIBRATION_TEST",
        "status": "accepted",
        "generated_at_utc": _utc_now().isoformat(),
        "calibration_id": profile.calibration_id,
        "scenario_profile": profile.key,
        "evidence_fingerprint_sha256": selected.fingerprint_sha256,
        "source_event_ids": list(selected.source_event_ids),
        "candidate_id": candidate_id,
        "job_id": result.job_id,
        "evaluation_mode": result.evaluation_mode,
        "scenario_id": result.scenario_id,
        "risk_class": result.risk_class.value,
        "confidence": result.confidence.value,
        "confidence_score": result.confidence_score,
        "coverage_status": result.coverage_status.value,
        "findings_created": 0,
        "before": before,
        "after": after,
        "continuous_worker_started": False,
    }


def _disable_calibration(profile: CalibrationProfile) -> None:
    with _connect(role="adlog_storage_worker") as conn:
        with conn.transaction(), conn.cursor() as cur:
            cur.execute(
                "select lifecycle_status from semantic_risk_policies "
                "where policy_id=%s and policy_version=%s for update",
                (profile.policy_id, VERSION),
            )
            policy = dict(cur.fetchone() or {})
            if policy and policy.get("lifecycle_status") != "disabled":
                transition_risk_policy(
                    cur,
                    policy_id=profile.policy_id,
                    policy_version=VERSION,
                    target_status="disabled",
                )
            cur.execute(
                "select lifecycle_status from semantic_correlation_rules "
                "where rule_id=%s and rule_version=%s for update",
                (profile.rule_id, VERSION),
            )
            rule = dict(cur.fetchone() or {})
            if rule and rule.get("lifecycle_status") != "disabled":
                transition_correlation_rule(
                    cur,
                    rule_id=profile.rule_id,
                    rule_version=VERSION,
                    target_status="disabled",
                )


def _shadow(
    *,
    plan: Mapping[str, Any],
    test_evidence: Mapping[str, Any],
    max_age_minutes: int,
) -> dict[str, Any]:
    _ensure_execution_flags()
    _validate_artifact_age(plan, maximum_minutes=max_age_minutes)
    _validate_artifact_age(test_evidence, maximum_minutes=max_age_minutes)
    profile = _profile_from_plan(plan)
    if (
        test_evidence.get("package_type") != "SEMANTIC_CALIBRATION_TEST"
        or test_evidence.get("status") != "accepted"
        or test_evidence.get("scenario_id") is not None
        or int(test_evidence.get("findings_created") or 0) != 0
    ):
        raise RuntimeError("SHADOW requires an accepted findings-free TEST artifact")
    selected = _load_selected_from_plan(plan)
    if test_evidence.get("scenario_profile") != profile.key:
        raise RuntimeError("TEST and SHADOW scenario profiles differ")
    if selected.fingerprint_sha256 != test_evidence.get("evidence_fingerprint_sha256"):
        raise RuntimeError("TEST and SHADOW evidence fingerprints differ")
    before = _snapshot()
    _assert_runtime_safe(before)
    _assert_snapshot_matches(
        before,
        dict(test_evidence["after"]),
        fields=SNAPSHOT_COUNT_FIELDS,
    )
    scenario_id: str | None = None
    try:
        with _connect(role="adlog_storage_worker") as conn:
            with conn.transaction(), conn.cursor() as cur:
                transition_correlation_rule(
                    cur,
                    rule_id=profile.rule_id,
                    rule_version=VERSION,
                    target_status="shadow",
                )
                transition_risk_policy(
                    cur,
                    policy_id=profile.policy_id,
                    policy_version=VERSION,
                    target_status="shadow",
                )
                candidate_id = str(test_evidence["candidate_id"])
                job_ids = enqueue_candidate_risk_jobs(cur, candidate_id=candidate_id)
                if len(job_ids) != 1:
                    raise RuntimeError("SHADOW calibration did not enqueue exactly one job")
            result = _execute_expected_job(conn, expected_job_id=job_ids[0])
            scenario_id = result.scenario_id
        if result.evaluation_mode != "shadow" or scenario_id is None:
            raise RuntimeError("SHADOW calibration did not persist one scenario")
        with _connect(role="adlog_user", read_only=True) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select scenario.scenario_id::text,scenario.risk_class,
                           scenario.display_score,scenario.confidence,
                           scenario.confidence_score,scenario.coverage_status,
                           array_agg(normalized.source_event_id order by evidence.evidence_order)
                             as source_event_ids
                    from semantic_security_scenarios scenario
                    join semantic_scenario_evidence evidence
                      on evidence.scenario_id=scenario.scenario_id
                    join normalized_events normalized
                      on normalized.normalized_event_id=evidence.normalized_event_id
                    where scenario.scenario_id=%s
                    group by scenario.scenario_id,scenario.risk_class,
                             scenario.display_score,scenario.confidence,
                             scenario.confidence_score,scenario.coverage_status
                    """,
                    (scenario_id,),
                )
                scenario = dict(cur.fetchone() or {})
        if sorted(int(item) for item in scenario.get("source_event_ids") or []) != list(
            selected.source_event_ids
        ):
            raise RuntimeError("SHADOW scenario evidence does not match the exact plan")
    finally:
        _disable_calibration(profile)
    after = _snapshot()
    if int(after["findings"]) != int(before["findings"]):
        raise RuntimeError("SHADOW calibration changed legacy findings")
    if int(after["risk_errors"]) != 0:
        raise RuntimeError("SHADOW calibration recorded risk errors")
    if int(after["semantic_worker_heartbeats"]) != 0:
        raise RuntimeError("SHADOW calibration unexpectedly registered a worker")
    expected_after = dict(before)
    expected_after.update(
        risk_jobs=int(before["risk_jobs"]) + 1,
        risk_results=int(before["risk_results"]) + 1,
        scenarios=int(before["scenarios"]) + 1,
        shadow_results=int(before["shadow_results"]) + 1,
    )
    _assert_snapshot_matches(after, expected_after, fields=SNAPSHOT_COUNT_FIELDS)
    if int(after["shadow_results"]) > MAX_AUTHORISED_SHADOW_EVALUATIONS:
        raise RuntimeError("SHADOW calibration exceeded the authorised evaluation ceiling")
    with _connect(role="adlog_user", read_only=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "select lifecycle_status from semantic_risk_policies "
                "where policy_id=%s and policy_version=%s",
                (profile.policy_id, VERSION),
            )
            policy_status = str(dict(cur.fetchone() or {}).get("lifecycle_status") or "")
            cur.execute(
                "select lifecycle_status from semantic_correlation_rules "
                "where rule_id=%s and rule_version=%s",
                (profile.rule_id, VERSION),
            )
            rule_status = str(dict(cur.fetchone() or {}).get("lifecycle_status") or "")
    if policy_status != "disabled" or rule_status != "disabled":
        raise RuntimeError("calibration rule/policy did not return to disabled")
    return {
        "package_type": "SEMANTIC_CALIBRATION_SHADOW",
        "status": "accepted",
        "generated_at_utc": _utc_now().isoformat(),
        "calibration_id": profile.calibration_id,
        "scenario_profile": profile.key,
        "evidence_fingerprint_sha256": selected.fingerprint_sha256,
        "source_event_ids": list(selected.source_event_ids),
        "candidate_id": str(test_evidence["candidate_id"]),
        "job_id": result.job_id,
        "evaluation_mode": result.evaluation_mode,
        "scenario_id": scenario_id,
        "risk_class": scenario["risk_class"],
        "display_score": scenario["display_score"],
        "confidence": scenario["confidence"],
        "confidence_score": scenario["confidence_score"],
        "coverage_status": scenario["coverage_status"],
        "evaluations": MAX_EVALUATIONS,
        "maximum_evaluations": MAX_AUTHORISED_SHADOW_EVALUATIONS,
        "findings_created": 0,
        "policy_status": policy_status,
        "rule_status": rule_status,
        "before": before,
        "after": after,
        "continuous_worker_started": False,
        "collection_changed": False,
        "ad_queried": False,
    }


def _workspace_acceptance(shadow_evidence: Mapping[str, Any]) -> dict[str, Any]:
    if (
        shadow_evidence.get("package_type") != "SEMANTIC_CALIBRATION_SHADOW"
        or shadow_evidence.get("status") != "accepted"
        or shadow_evidence.get("policy_status") != "disabled"
        or shadow_evidence.get("rule_status") != "disabled"
    ):
        raise RuntimeError("workspace acceptance requires an accepted disabled SHADOW artifact")
    profile = _profile_from_plan(shadow_evidence)
    settings = SemanticFeatureSettings.from_env()
    if any(
        (
            settings.normalization_enabled,
            settings.assembly_enabled,
            settings.directory_state_enabled,
            settings.correlation_enabled,
            settings.risk_engine_enabled,
            settings.finding_creation_enabled,
        )
    ):
        raise RuntimeError("workspace acceptance must run with all semantic flags disabled")

    # Exercise the same bounded read models used by the HTTP handlers while
    # retaining the production runtime role.  The monkeypatch is process-local
    # and cannot alter the live HTTPS runtime.
    import server.sli.core.postgres_runtime_pipeline as runtime_pipeline
    import server.sli.ops.runtime_workers as runtime_workers

    runtime_connect = lambda: _connect(role="adlog_user", read_only=True)
    runtime_pipeline.connect = runtime_connect
    runtime_workers.connect = runtime_connect

    from server.sli.semantic.semantic_workspace import (
        get_semantic_actions_workspace_data,
        get_semantic_calibration_workspace_data,
        get_semantic_scenarios_workspace_data,
    )

    scenarios = get_semantic_scenarios_workspace_data(limit=5)
    actions = get_semantic_actions_workspace_data(limit=5)
    calibration = get_semantic_calibration_workspace_data(window_hours=24)
    if scenarios.get("state") != "available":
        raise RuntimeError("bounded scenario workspace did not expose the SHADOW result")
    matching = [
        dict(item)
        for item in scenarios.get("items") or []
        if str(item.get("scenario_id")) == str(shadow_evidence.get("scenario_id"))
    ]
    if len(matching) != 1:
        raise RuntimeError("workspace scenario identity differs from SHADOW evidence")
    scenario = matching[0]
    evidence_ids = sorted(int(item["event_db_id"]) for item in scenario.get("evidence") or [])
    if evidence_ids != sorted(int(item) for item in shadow_evidence["source_event_ids"]):
        raise RuntimeError("workspace exact evidence differs from SHADOW evidence")
    execution = dict(scenarios.get("execution") or {})
    worker = dict(execution.get("worker") or {})
    if (
        execution.get("state") != "disabled"
        or execution.get("finding_path_live") is True
        or worker.get("state") != "not_registered"
    ):
        raise RuntimeError("workspace execution contract is not fail-closed after SHADOW")
    jobs = calibration.get("jobs") or []
    results = calibration.get("results") or []
    expected_after = dict(shadow_evidence["after"])
    if sum(int(item.get("job_count") or 0) for item in jobs) != int(
        expected_after["risk_jobs"]
    ):
        raise RuntimeError("calibration workspace job aggregate differs from database state")
    if sum(int(item.get("errors") or 0) for item in jobs) != 0:
        raise RuntimeError("calibration workspace reports evaluation errors")
    if sum(int(item.get("result_count") or 0) for item in results) != int(
        expected_after["risk_results"]
    ):
        raise RuntimeError("calibration workspace result aggregate differs from database state")
    if sum(int(item.get("scenario_count") or 0) for item in results) != int(
        expected_after["shadow_results"]
    ):
        raise RuntimeError("calibration workspace scenario aggregate differs from SHADOW state")
    if actions.get("state") != "empty" or actions.get("items"):
        raise RuntimeError("correlation calibration unexpectedly created canonical actions")

    generated = _utc_now()
    with _connect(role="adlog_user", read_only=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select row_number() over (order by server_hostname) as server_ordinal,
                       last_successful_collection_utc,
                       last_event_time_utc,backfill_completed
                from collection_channel_state
                where channel=%s order by server_hostname
                """,
                ("Security",),
            )
            security_rows = [dict(item) for item in (cur.fetchall() or [])]
            cur.execute(
                """
                select worker_name,status,expected_interval_seconds,heartbeat_at
                from runtime_worker_heartbeats order by worker_name
                """
            )
            heartbeat_rows = [dict(item) for item in (cur.fetchall() or [])]
    # Report-local ordinals preserve per-row coverage without exposing or hashing names.
    security = []
    for item in security_rows:
        successful = parse_utc_timestamp(item["last_successful_collection_utc"])
        security.append(
            {
                "server": f"server-{int(item['server_ordinal'])}",
                "successful_collection_age_seconds": max(
                    0, int((generated - successful).total_seconds())
                ),
                "backfill_completed": bool(item.get("backfill_completed")),
            }
        )
    workers = []
    for item in heartbeat_rows:
        heartbeat = parse_utc_timestamp(item["heartbeat_at"])
        workers.append(
            {
                "worker_name": str(item["worker_name"]),
                "status": str(item["status"]),
                "heartbeat_age_seconds": max(
                    0, int((generated - heartbeat).total_seconds())
                ),
                "expected_interval_seconds": int(item["expected_interval_seconds"]),
            }
        )
    snapshot = _snapshot()
    if int(snapshot["findings"]) != int(dict(shadow_evidence["after"])["findings"]):
        raise RuntimeError("legacy findings changed after SHADOW acceptance")
    return {
        "package_type": "SEMANTIC_CALIBRATION_ACCEPTANCE",
        "status": "accepted",
        "generated_at_utc": generated.isoformat(),
        "calibration_id": profile.calibration_id,
        "scenario_profile": profile.key,
        "scenario": {
            "scenario_id": scenario["scenario_id"],
            "scenario_kind": scenario["scenario_kind"],
            "result_class": scenario["result_class"],
            "risk_class": scenario["risk_class"],
            "display_score": scenario["display_score"],
            "confidence": scenario["confidence"],
            "confidence_score": scenario["confidence_score"],
            "coverage_status": scenario["coverage_status"],
            "event_db_ids": evidence_ids,
        },
        "workspace": {
            "scenario_state": scenarios["state"],
            "actions_state": actions["state"],
            "calibration_state": calibration["state"],
            "jobs": jobs,
            "results": results,
            "policies": calibration.get("policies") or [],
            "execution_state": execution["state"],
            "worker_state": worker["state"],
            "finding_path_live": execution["finding_path_live"],
        },
        "security_collection": security,
        "workers": workers,
        "database": snapshot,
        "read_only": True,
        "payload_read": False,
        "continuous_worker_started": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run a bounded exact-evidence semantic calibration window."
    )
    parser.add_argument("phase", choices=("plan", "test", "shadow", "verify"))
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--test-evidence", type=Path)
    parser.add_argument("--shadow-evidence", type=Path)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--hours", type=int, default=24)
    parser.add_argument("--candidate-limit", type=int, default=512)
    parser.add_argument("--max-age-minutes", type=int, default=60)
    parser.add_argument(
        "--scenario-profile",
        choices=tuple(PROFILES),
        default=SESSION_PRIVILEGES.key,
        help="plan-only scenario selector; later phases trust the signed plan identity",
    )
    args = parser.parse_args()

    if args.phase in {"test", "shadow"} and not args.execute:
        payload: dict[str, Any] = {
            "package_type": "SEMANTIC_CALIBRATION_BLOCKED",
            "status": "blocked",
            "reason": "--execute is required for TEST/SHADOW",
            "connections": 0,
        }
    elif args.phase == "plan":
        payload = _plan(
            PROFILES[args.scenario_profile],
            hours=max(1, min(int(args.hours), 72)),
            candidate_limit=max(32, min(int(args.candidate_limit), 20000)),
        )
    elif args.phase == "test":
        if args.plan is None:
            parser.error("test requires --plan")
        payload = _test(
            plan=_read_json(args.plan),
            max_age_minutes=max(5, min(int(args.max_age_minutes), 240)),
        )
    elif args.phase == "shadow":
        if args.plan is None or args.test_evidence is None:
            parser.error("shadow requires --plan and --test-evidence")
        payload = _shadow(
            plan=_read_json(args.plan),
            test_evidence=_read_json(args.test_evidence),
            max_age_minutes=max(5, min(int(args.max_age_minutes), 240)),
        )
    else:
        if args.shadow_evidence is None:
            parser.error("verify requires --shadow-evidence")
        payload = _workspace_acceptance(_read_json(args.shadow_evidence))
    _write_json_atomic(args.result, payload)
    print(_canonical_json(payload))
    return 0 if payload.get("status") in {"planned_read_only", "accepted", "blocked"} else 1


if __name__ == "__main__":
    raise SystemExit(main())

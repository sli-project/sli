#!/usr/bin/env python3
"""Activate and manually poll the accepted Stage-8 production semantic path."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import time
from typing import Any, Iterator, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.maintenance.semantic_l1_shadow_control import (  # noqa: E402
    POLICY_VERSION,
    POLICIES,
    TARGET_KINDS,
    _connect_admin,
    _create_ephemeral_login,
    _drop_ephemeral_login,
    _load_environment,
    _worker_dsn,
)
from server.sli.ops.postgres_session_lock import session_advisory_lock  # noqa: E402
from server.sli.semantic.semantic_processing import (  # noqa: E402
    ASSEMBLER_ID,
    ASSEMBLER_VERSION,
    NORMALIZER_ID,
    NORMALIZER_VERSION,
    PROCESS_EPISODE_ASSEMBLER_ID,
    PROCESS_EPISODE_ASSEMBLER_VERSION,
    SEMANTIC_CONTRACT_VERSION,
    SemanticFeatureSettings,
)
from server.sli.semantic.semantic_producer import (  # noqa: E402
    MAX_PRODUCER_BATCH,
    publish_semantic_candidates,
)
from server.sli.semantic.semantic_calibration_contract import (  # noqa: E402
    MAX_AUTHORISED_SHADOW_EVALUATIONS,
)
from server.sli.semantic.semantic_production_runtime import (  # noqa: E402
    FACTS_MODE,
    INVESTIGATION_MODE,
    MAX_LIMIT as PRODUCTION_MAX_LIMIT,
    PRODUCTION_WORKER_LOCK_NAME,
    prepare_production_connection,
    run_once as run_production_once,
    semantic_runtime_mode_from_env,
    validate_semantic_runtime_settings,
)
from server.sli.semantic.semantic_investigation_backfill import (  # noqa: E402
    SECURITY_HISTORY_BATCH_MAX,
    SECURITY_HISTORY_LOCK_NAME,
    SECURITY_HISTORY_MANIFEST_TYPE,
    SECURITY_HISTORY_MANIFEST_TYPE_V1,
    SECURITY_HISTORY_MANIFEST_TYPE_V2,
    SECURITY_HISTORY_SUPERSEDE_REASON,
    SECURITY_HISTORY_EVENT_IDS,
    classify_security_history_v2_repair_row,
    new_security_history_manifest,
    new_security_history_manifest_v2,
    reconcile_security_history_event,
    reconcile_security_history_context_event,
    reconcile_security_history_v2_context_event,
    security_history_cohort_mismatches,
    security_history_cohort_digest,
    security_history_cohorts,
    security_history_selection_fingerprint,
    security_history_context_cohort,
    _iter_security_history_context_pairs,
    security_history_v2_selection_fingerprint,
    select_security_history_context_targets,
    select_security_history_targets,
    validate_security_history_manifest,
)
from server.sli.semantic.semantic_production_credentials import (  # noqa: E402
    ephemeral_worker_environment,
)
from server.sli.semantic.semantic_risk_runtime_repository import (  # noqa: E402
    claim_risk_evaluation_jobs,
    enqueue_risk_backlog,
    execute_risk_evaluation,
    fail_risk_evaluation_job,
    load_risk_evaluation_work_item,
    transition_risk_policy,
)
from server.sli.semantic.semantic_worker_connection import (  # noqa: E402
    connect_semantic_worker,
)
from server.sli.semantic.semantic_processing_repository import (  # noqa: E402
    PROCESSOR_ID,
    PROCESSOR_VERSION,
    SEMANTIC_REPAIR_JOB_KIND,
    SEMANTIC_V2_QUARANTINE_REPAIR_JOB_KIND,
    enqueue_semantic_job,
    lock_semantic_source,
)
from server.sli.semantic.semantic_worker_contract import semantic_worker_release_fingerprint  # noqa: E402
from server.sli.semantic.semantic_worker_runtime import (  # noqa: E402
    process_semantic_dispatch,
    process_semantic_outbox,
)
from server.sli.storage.storage_v2_archive import ArchiveReader  # noqa: E402
from server.sli.storage.storage_v2_config import load_storage_v2_settings  # noqa: E402
from server.sli.storage.storage_v2_repository import (  # noqa: E402
    PostgresArchiveManifestStore,
)
from server.sli.ops.worker_supervisor_secrets import load_supervisor_environment  # noqa: E402


ACTIVATE_CONFIRM = "ACTIVATE-STAGE8-PRODUCTION-FINDINGS"
POLL_CONFIRM = "POLL-STAGE8-PRODUCTION-FINDINGS"
FACTS_POLL_CONFIRM = "POLL-STAGE8-RETAINED-FACTS"
DEACTIVATE_CONFIRM = "DEACTIVATE-STAGE8-PRODUCTION-FINDINGS"
STOP_CONFIRM = "STOP-CONTINUOUS-SEMANTIC-PRODUCTION"
STOP_REQUEST_PATH = ROOT / "data/runtime/semantic-production-stop.json"
STATE_PATH = (
    ROOT / "artifacts/stage8/evidence/semantic-production-state.json"
)
FACTS_CHECKPOINT_PATH = (
    ROOT / "artifacts/stage8/evidence/semantic-retained-facts-checkpoint.json"
)
FACTS_CHECK_MANIFEST_PATH = (
    ROOT / "artifacts/stage8/evidence/semantic-exact-facts-check.json"
)
FACTS_LOCK_NAME = "semantic_retained_v2_facts_controller"
FACTS_CHECK_CONFIRM_PREFIX = "CHECK-STAGE8-EXACT-FACTS:"
SECURITY_HISTORY_MANIFEST_PATH = (
    ROOT / "artifacts/stage8/evidence/retained-security-history-vocabulary.json"
)
APPROVED_SECURITY_HISTORY_MANIFEST_SHA256 = (
    "e1040c58e1e38bc1c3bd8dfe9266f2e6a6c276c58e20160dcbc9f6fe7f655806"
)
APPROVED_SECURITY_HISTORY_MANIFEST_PLAN_DIGEST = (
    "c6c9d4aa697d3b90ba54d01dd6fa9ea33ab2d33efd82194780fd737363e6ea8a"
)
APPROVED_SECURITY_HISTORY_MANIFEST_SELECTION_FINGERPRINT = (
    "6c8bcaaa221096408ff3d1c4faa9ff8fde015c88595f582a70dd52c805e1aca1"
)
APPROVED_SECURITY_HISTORY_V2_REPAIR_PLAN_DIGEST = (
    "f83550b69c0423ffb3909440e5fd8d2ae1da469727b0e936fa70b1d8feb8a3b0"
)
APPROVED_SECURITY_HISTORY_V2_QUARANTINE_COHORT_COUNT = 260
SECURITY_HISTORY_V2_FROZEN_MANIFEST_ACTIONS = frozenset({
    "security-history-v2-quarantine-repair-plan",
    "security-history-v2-quarantine-repair",
})
SECURITY_HISTORY_POLL_CONFIRM_PREFIX = "POLL-SECURITY-HISTORY:"
SECURITY_HISTORY_CHECK_CONFIRM_PREFIX = "CHECK-SECURITY-HISTORY:"
SECURITY_HISTORY_REPAIR_CONFIRM_PREFIX = "REPAIR-SECURITY-HISTORY:"
SECURITY_HISTORY_V2_QUARANTINE_REPAIR_CONFIRM_PREFIX = "REPAIR-SECURITY-HISTORY-V2-QUARANTINE:"
SECURITY_HISTORY_SUPERSEDE_CONFIRM_PREFIX = "SUPERSEDE-SECURITY-HISTORY:"
MIGRATION = (
    ROOT
    / "config/postgres_migrations/055_semantic_finding_publication.sql"
)
ENABLED_POLICY_ID = "l1-audit-policy-changed"
MAX_LIMIT = 16


def _facts_catalog_fingerprint() -> list[dict[str, str]]:
    """Hash only shipped selector inputs, never event payloads or runtime data."""
    manifests = sorted((ROOT / "config/source_packs").glob("*.json"))
    catalog_paths = {ROOT / "config/event_catalog.json"}
    for manifest_path in manifests:
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError("semantic facts source-pack manifest is invalid") from exc
        if not isinstance(manifest, dict):
            raise RuntimeError("semantic facts source-pack manifest is invalid")
        catalog = manifest.get("event_catalog")
        if catalog is not None:
            if not isinstance(catalog, str) or not catalog.strip():
                raise RuntimeError("semantic facts source-pack catalog is invalid")
            path = (ROOT / "config" / catalog).resolve()
            if path.parent != (ROOT / "config").resolve():
                raise RuntimeError("semantic facts source-pack catalog escapes config")
            catalog_paths.add(path)
    paths = [*manifests, *sorted(catalog_paths)]
    fingerprints: list[dict[str, str]] = []
    for path in paths:
        try:
            relative = path.relative_to(ROOT).as_posix()
            raw = path.read_bytes().replace(b"\r\n", b"\n")
        except (OSError, ValueError) as exc:
            raise RuntimeError("semantic facts catalog input is unavailable") from exc
        fingerprints.append({"path": relative, "sha256": sha256(raw).hexdigest()})
    return fingerprints


def _facts_rules_fingerprint() -> str:
    """Bind a retained plan to the exact producer and semantic rule contract."""
    contract = {
        "selector": {
            "owner": "publish_semantic_candidates",
            "source": "events_v2_core",
            "ordered_by": "id_ascending",
            "include_context": True,
            "max_batch": MAX_PRODUCER_BATCH,
        },
        "catalog": _facts_catalog_fingerprint(),
        "normalizer": {
            "id": NORMALIZER_ID,
            "version": NORMALIZER_VERSION,
            "semantic_contract_version": SEMANTIC_CONTRACT_VERSION,
        },
        "assemblers": [
            {"id": ASSEMBLER_ID, "version": ASSEMBLER_VERSION},
            {
                "id": PROCESS_EPISODE_ASSEMBLER_ID,
                "version": PROCESS_EPISODE_ASSEMBLER_VERSION,
            },
        ],
    }
    encoded = json.dumps(contract, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256(encoded).hexdigest()


def _validate_facts_admission() -> None:
    """Retained publication is allowed only for explicitly admitted facts-v1."""
    mode = semantic_runtime_mode_from_env()
    if mode != FACTS_MODE:
        raise RuntimeError("retained facts requires explicit facts-v1 admission")
    validate_semantic_runtime_settings(mode, SemanticFeatureSettings.from_env())


def _read_facts_checkpoint() -> dict[str, Any] | None:
    if not FACTS_CHECKPOINT_PATH.exists():
        return None
    try:
        loaded = json.loads(FACTS_CHECKPOINT_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("retained facts checkpoint is invalid") from exc
    if not isinstance(loaded, dict):
        raise RuntimeError("retained facts checkpoint is invalid")
    return loaded


def _write_facts_checkpoint(payload: dict[str, Any]) -> None:
    """Atomically persist the local resume point while the session lock is held."""
    FACTS_CHECKPOINT_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = FACTS_CHECKPOINT_PATH.with_name(
        f".{FACTS_CHECKPOINT_PATH.name}.{os.getpid()}.tmp"
    )
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )
    os.replace(temporary, FACTS_CHECKPOINT_PATH)


def _facts_database_identity(cur: Any) -> dict[str, str]:
    """Extend the existing target guard with non-secret cluster/database identity."""
    identity = _security_history_database_identity(cur)
    from psycopg.errors import InsufficientPrivilege

    try:
        cur.execute(
            "select system_identifier::text as system_identifier, "
            "inet_server_port()::text as port, "
            "(select oid::text from pg_database where datname=current_database()) as database_oid "
            "from pg_control_system()"
        )
    except InsufficientPrivilege:
        raise RuntimeError(
            "retained facts identity requires read-only EXECUTE on pg_control_system(); "
            "ask the database administrator to review this prerequisite"
        ) from None
    row = dict(cur.fetchone() or {})
    for field in ("system_identifier", "port", "database_oid"):
        identity[field] = str(row.get(field) or "")
    if not all(identity.values()):
        raise RuntimeError("retained facts database identity is unavailable")
    return identity


def _facts_target_snapshot() -> tuple[dict[str, str], int]:
    with _connect_admin() as conn, conn.cursor() as cur:
        cur.execute("set transaction read only")
        identity = _facts_database_identity(cur)
        cur.execute("select coalesce(max(id),0) as high_watermark from events_v2_core")
        return identity, int(dict(cur.fetchone() or {}).get("high_watermark") or 0)


def _new_facts_checkpoint(*, high_watermark: int, fingerprint: str, database_identity: dict[str, str]) -> dict[str, Any]:
    return {
        "checkpoint_type": "retained_v2_semantic_facts",
        "database_identity": database_identity,
        "status": "active",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "range_start_event_id": 1,
        "frozen_high_watermark_event_id": high_watermark,
        "last_committed_event_id": 0,
        "rules_fingerprint": fingerprint,
        "batch_limit": MAX_PRODUCER_BATCH,
        "include_context": True,
    }


def _validate_facts_checkpoint(checkpoint: dict[str, Any], *, fingerprint: str) -> None:
    if checkpoint.get("checkpoint_type") != "retained_v2_semantic_facts":
        raise RuntimeError("retained facts checkpoint type is invalid")
    if checkpoint.get("rules_fingerprint") != fingerprint:
        raise RuntimeError("retained facts rules fingerprint mismatch")
    identity = checkpoint.get("database_identity")
    if not isinstance(identity, dict) or set(identity) != {
        "host", "database", "role", "system_identifier", "port", "database_oid",
    } or not all(isinstance(value, str) and value for value in identity.values()):
        raise RuntimeError(
            "retained facts checkpoint database identity is missing or invalid; "
            "legacy checkpoints require operator-reviewed restart: preserve the old file, "
            "review the target, then archive the checkpoint and restart from event 1"
        )
    if checkpoint.get("range_start_event_id") != 1:
        raise RuntimeError("retained facts checkpoint range is invalid")
    if checkpoint.get("batch_limit") != MAX_PRODUCER_BATCH:
        raise RuntimeError("retained facts checkpoint batch limit is invalid")
    if checkpoint.get("include_context") is not True:
        raise RuntimeError("retained facts checkpoint context contract is invalid")
    try:
        high = int(checkpoint["frozen_high_watermark_event_id"])
        committed = int(checkpoint["last_committed_event_id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError("retained facts checkpoint bounds are invalid") from exc
    if high < 0 or committed < 0 or committed > high:
        raise RuntimeError("retained facts checkpoint bounds are invalid")


def _facts_target_ids(cur: Any, *, after_id: int, high_watermark: int) -> list[int]:
    cur.execute(
        """
        select id
        from events_v2_core
        where id > %s and id <= %s
        order by id
        limit %s
        """,
        (after_id, high_watermark, MAX_PRODUCER_BATCH),
    )
    return [int(row["id"]) for row in (cur.fetchall() or [])]


def facts_plan() -> dict[str, Any]:
    """Read-only preview; it deliberately does not create or extend a plan."""
    _load_environment()
    _validate_facts_admission()
    fingerprint = _facts_rules_fingerprint()
    checkpoint = _read_facts_checkpoint()
    if checkpoint is not None:
        _validate_facts_checkpoint(checkpoint, fingerprint=fingerprint)
        with _connect_admin() as conn, conn.cursor() as cur:
            cur.execute("set transaction read only")
            if checkpoint["database_identity"] != _facts_database_identity(cur):
                raise RuntimeError("retained facts checkpoint database identity mismatch")
        return {
            "status": "retained_v2_facts_resume_ready",
            "checkpoint_path": str(FACTS_CHECKPOINT_PATH),
            "checkpoint": checkpoint,
            "production_changed": False,
            "consumer": "existing_managed_facts_worker",
        }
    database_identity, high_watermark = _facts_target_snapshot()
    return {
        "status": "retained_v2_facts_plan_ready",
        "range_start_event_id": 1,
        "observed_high_watermark_event_id": high_watermark,
        "database_identity": database_identity,
        "rules_fingerprint": fingerprint,
        "batch_limit": MAX_PRODUCER_BATCH,
        "include_context": True,
        "checkpoint_path": str(FACTS_CHECKPOINT_PATH),
        "production_changed": False,
        "consumer": "existing_managed_facts_worker",
    }


def facts_poll() -> dict[str, Any]:
    """Publish exactly one frozen retained range batch; consumption stays external."""
    _load_environment()
    with session_advisory_lock(_connect_admin, FACTS_LOCK_NAME) as acquired:
        if not acquired:
            raise RuntimeError("retained facts controller lock is busy")
        _validate_facts_admission()
        fingerprint = _facts_rules_fingerprint()
        checkpoint = _read_facts_checkpoint()
        if checkpoint is None:
            database_identity, high_watermark = _facts_target_snapshot()
            checkpoint = _new_facts_checkpoint(
                high_watermark=high_watermark,
                fingerprint=fingerprint,
                database_identity=database_identity,
            )
            _write_facts_checkpoint(checkpoint)
        _validate_facts_checkpoint(checkpoint, fingerprint=fingerprint)
        high_watermark = int(checkpoint["frozen_high_watermark_event_id"])
        committed = int(checkpoint["last_committed_event_id"])
        with _connect_admin() as conn:
            with conn.transaction(), conn.cursor() as cur:
                if checkpoint["database_identity"] != _facts_database_identity(cur):
                    raise RuntimeError("retained facts checkpoint database identity mismatch")
                cur.execute("set local role adlog_storage_worker")
                target_ids = _facts_target_ids(
                    cur,
                    after_id=committed,
                    high_watermark=high_watermark,
                )
                published = publish_semantic_candidates(
                    cur,
                    target_ids,
                    include_context=True,
                )
        next_committed = target_ids[-1] if target_ids else high_watermark
        checkpoint["last_committed_event_id"] = next_committed
        checkpoint["status"] = (
            "complete" if not target_ids or len(target_ids) < MAX_PRODUCER_BATCH else "active"
        )
        checkpoint["updated_at_utc"] = datetime.now(timezone.utc).isoformat()
        _write_facts_checkpoint(checkpoint)
    return {
        "status": "retained_v2_facts_poll_complete",
        "checkpoint_path": str(FACTS_CHECKPOINT_PATH),
        "from_event_id_exclusive": committed,
        "to_event_id_inclusive": next_committed,
        "target_events": len(target_ids),
        "producer": published,
        "consumer": "existing_managed_facts_worker",
        "production_changed": bool(target_ids),
    }


def _validate_security_history_admission() -> None:
    """Vocabulary publication is limited to the already admitted investigation worker."""
    mode = semantic_runtime_mode_from_env()
    if mode != INVESTIGATION_MODE:
        raise RuntimeError("security history requires explicit investigation-v1 admission")
    validate_semantic_runtime_settings(mode, SemanticFeatureSettings.from_env())


def _require_compatible_investigation_worker() -> None:
    """Fail closed unless the singleton worker advertises this claim contract."""
    with _connect_admin() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select status,phase,details_json
            from runtime_worker_heartbeats
            where worker_name='semantic'
              and status in ('running','idle')
              and heartbeat_at >= now() - (
                greatest(180,expected_interval_seconds*3) * interval '1 second'
              )
            """
        )
        row = dict(cur.fetchone() or {})
    details = row.get("details_json")
    if isinstance(details, str):
        try:
            details = json.loads(details)
        except json.JSONDecodeError:
            details = None
    contract = details.get("processing_contract") if isinstance(details, Mapping) else None
    if (
        not isinstance(contract, Mapping)
        or details.get("runtime_mode") != INVESTIGATION_MODE
        or details.get("manual_runtime") is not False
        or contract.get("claim_protocol_version") != 1
        or contract.get("semantic_contract_version") != SEMANTIC_CONTRACT_VERSION
        or contract.get("processor_id") != PROCESSOR_ID
        or contract.get("processor_version") != PROCESSOR_VERSION
        or contract.get("normalizer") != {"id": NORMALIZER_ID, "version": NORMALIZER_VERSION}
        or contract.get("assembler") != {"id": ASSEMBLER_ID, "version": ASSEMBLER_VERSION}
    ):
        raise RuntimeError("security history requires a fresh compatible managed investigation worker")


def _read_security_history_manifest() -> dict[str, Any] | None:
    if not SECURITY_HISTORY_MANIFEST_PATH.exists():
        return None
    try:
        payload = json.loads(SECURITY_HISTORY_MANIFEST_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("security history manifest is invalid") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("security history manifest is invalid")
    return payload


def _main_checkout_root() -> Path:
    """Locate Main without embedding a machine-specific checkout path."""
    return ROOT.parent.parent if ROOT.parent.name == ".worktrees" else ROOT


def _require_exact_main_frozen_security_history_manifest(value: str) -> Path:
    """Accept one explicit, existing Main frozen manifest and nothing else."""
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        raise RuntimeError("frozen_security_history_manifest_must_be_absolute")
    try:
        resolved = candidate.resolve(strict=True)
        expected = (
            _main_checkout_root()
            / "artifacts/stage8/evidence/retained-security-history-vocabulary.json"
        ).resolve(strict=True)
    except OSError as exc:
        raise RuntimeError("frozen_security_history_manifest_is_not_an_existing_main_file") from exc
    if not resolved.is_file() or resolved != expected:
        raise RuntimeError("frozen_security_history_manifest_is_not_the_exact_main_file")
    return resolved


def _read_approved_frozen_security_history_manifest() -> dict[str, Any]:
    """Read the one reviewed artifact only after its raw bytes prove identity."""
    path = (
        _main_checkout_root()
        / "artifacts/stage8/evidence/retained-security-history-vocabulary.json"
    )
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise RuntimeError("approved_security_history_manifest_is_unavailable") from exc
    if sha256(raw).hexdigest() != APPROVED_SECURITY_HISTORY_MANIFEST_SHA256:
        raise RuntimeError("approved_security_history_manifest_digest_mismatch")
    try:
        payload = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError("approved_security_history_manifest_is_invalid") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("approved_security_history_manifest_is_invalid")
    try:
        entry = dict(dict(payload["events"])["4624"])
        approved = (
            payload.get("manifest_type") == SECURITY_HISTORY_MANIFEST_TYPE_V2
            and payload.get("plan_digest")
            == APPROVED_SECURITY_HISTORY_MANIFEST_PLAN_DIGEST
            and payload.get("selection_fingerprint")
            == APPROVED_SECURITY_HISTORY_MANIFEST_SELECTION_FINGERPRINT
            and int(entry["count"])
            == APPROVED_SECURITY_HISTORY_V2_QUARANTINE_COHORT_COUNT
            and int(entry["semantic_expected_count"])
            == APPROVED_SECURITY_HISTORY_V2_QUARANTINE_COHORT_COUNT
        )
    except (KeyError, TypeError, ValueError):
        approved = False
    if not approved:
        raise RuntimeError("approved_security_history_manifest_contract_mismatch")
    return payload


def _write_security_history_manifest(payload: dict[str, Any]) -> None:
    """Use the existing same-directory atomic JSON pattern for local progress only."""
    SECURITY_HISTORY_MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = SECURITY_HISTORY_MANIFEST_PATH.with_name(
        f".{SECURITY_HISTORY_MANIFEST_PATH.name}.{os.getpid()}.tmp"
    )
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, default=str), encoding="utf-8"
    )
    os.replace(temporary, SECURITY_HISTORY_MANIFEST_PATH)


def _security_history_snapshot(
    *, high_watermarks: dict[int, int] | None = None,
) -> dict[str, Any]:
    """Read compact database identity and frozen cohort facts in one read-only scope."""
    with _connect_admin() as conn, conn.cursor() as cur:
        cur.execute("set transaction read only")
        identity = _security_history_database_identity(cur)
        cohorts = security_history_cohorts(cur, high_watermarks=high_watermarks)
    return {"database_identity": identity, "cohorts": cohorts}


def _security_history_v2_snapshot(
    *, high_watermarks: dict[int, int] | None = None,
) -> dict[str, Any]:
    """Read retained coverage and the narrower eligible 4624 cohort together."""
    with _connect_admin() as conn, conn.cursor() as cur:
        cur.execute("set transaction read only")
        identity = _security_history_database_identity(cur)
        cohorts = security_history_cohorts(cur, high_watermarks=high_watermarks)
        context = security_history_context_cohort(
            cur, high_watermark=int(cohorts[4624]["high_watermark"]),
            reset_high_watermark=int(cohorts[4724]["high_watermark"]),
        )
    return {
        "database_identity": identity,
        "cohorts": cohorts,
        "semantic_context_cohort": context,
    }


def _security_history_database_identity(cur: Any) -> dict[str, str]:
    """Read only the compact current database identity, never a source cohort."""
    cur.execute(
        "select coalesce(inet_server_addr()::text,'') as host, "
        "current_database() as database, session_user as role"
    )
    row = dict(cur.fetchone() or {})
    identity = {field: str(row.get(field) or "") for field in ("host", "database", "role")}
    if not all(identity.values()):
        raise RuntimeError("security history database identity is unavailable")
    return identity


def _security_history_current_database_identity() -> dict[str, str]:
    """Validate the current target database without scanning source cohorts."""
    with _connect_admin() as conn, conn.cursor() as cur:
        cur.execute("set transaction read only")
        return _security_history_database_identity(cur)


def _security_history_plan_digest(
    snapshot: Mapping[str, Any], *, batch_limit: int = SECURITY_HISTORY_BATCH_MAX,
) -> str:
    material = {
        "plan_type": SECURITY_HISTORY_MANIFEST_TYPE,
        "database_identity": snapshot["database_identity"],
        "cohorts": {
            str(event_id): snapshot["cohorts"].get(event_id, {
                "high_watermark": 0, "count": 0,
                "cohort_digest": security_history_cohort_digest(()),
                "min_id": None, "max_id": None,
            })
            for event_id in SECURITY_HISTORY_EVENT_IDS
        },
        "selection_fingerprint": security_history_selection_fingerprint(batch_limit=batch_limit),
        "runtime_mode": INVESTIGATION_MODE,
        "include_context": True,
    }
    return sha256(json.dumps(material, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")).hexdigest()


def _security_history_v2_plan_digest(
    snapshot: Mapping[str, Any], *, supersedes_plan_digest: str | None,
) -> str:
    """Bind the replacement to raw corpus, exact 4624 context, and v1 evidence."""
    material = {
        "plan_type": SECURITY_HISTORY_MANIFEST_TYPE_V2,
        "database_identity": snapshot["database_identity"],
        "cohorts": {
            str(event_id): snapshot["cohorts"].get(event_id, {
                "high_watermark": 0, "count": 0,
                "cohort_digest": security_history_cohort_digest(()),
                "min_id": None, "max_id": None,
            })
            for event_id in SECURITY_HISTORY_EVENT_IDS
        },
        "semantic_context_cohort": snapshot["semantic_context_cohort"],
        "selection_fingerprint": security_history_v2_selection_fingerprint(
            batch_limit=MAX_PRODUCER_BATCH,
        ),
        "runtime_mode": INVESTIGATION_MODE,
        "supersedes": (
            {
                "manifest_type": SECURITY_HISTORY_MANIFEST_TYPE_V1,
                "plan_digest": str(supersedes_plan_digest),
                "reason": SECURITY_HISTORY_SUPERSEDE_REASON,
            }
            if supersedes_plan_digest is not None else None
        ),
    }
    return sha256(json.dumps(material, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")).hexdigest()


def _security_history_frozen_high_watermarks(manifest: Mapping[str, Any]) -> dict[int, int]:
    events = manifest.get("events")
    if not isinstance(events, dict):
        raise RuntimeError("security history manifest events are invalid")
    return {event_id: int(dict(events[str(event_id)])["high_watermark"]) for event_id in SECURITY_HISTORY_EVENT_IDS}


def _security_history_manifest_batch_limit(manifest: Mapping[str, Any]) -> int:
    try:
        batch_limit = int(manifest["batch_limit"])
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError("security history manifest batch limit is invalid") from exc
    if not 1 <= batch_limit <= MAX_PRODUCER_BATCH:
        raise RuntimeError("security history manifest batch limit is invalid")
    return batch_limit


def _security_history_check_plan_for_manifest(manifest: Mapping[str, Any]) -> dict[str, Any]:
    """Bind a readback confirmation without re-reading every frozen source row."""
    _security_history_manifest_batch_limit(manifest)
    validate_security_history_manifest(
        manifest,
        database_identity=_security_history_current_database_identity(),
        cohorts=None,
        plan_digest=str(manifest.get("plan_digest") or ""),
    )
    digest = sha256(json.dumps(
        {"manifest_digest": manifest["plan_digest"], "events": manifest["events"]},
        sort_keys=True, separators=(",", ":"), default=str,
    ).encode("utf-8")).hexdigest()
    return {
        "status": "security_history_check_plan_ready",
        "plan_digest": digest,
        "confirmation": SECURITY_HISTORY_CHECK_CONFIRM_PREFIX + digest,
        "manifest_path": str(SECURITY_HISTORY_MANIFEST_PATH),
        "production_changed": False,
    }


def _security_history_wait_state(entry: Mapping[str, Any]) -> str:
    """Keep a cohort pollable until every frozen source row has been selected."""
    return (
        "publishing"
        if int(entry.get("cursor") or 0) < int(entry["high_watermark"])
        else "queued"
    )


def _security_history_v2_publication_is_exact(
    *, event_id: int, target_ids: Sequence[int], published: Mapping[str, Any],
) -> bool:
    """Accept exactly the controller-selected vocabulary batch, whatever its class."""
    expected = len(target_ids)
    if int(published.get("scanned") or 0) != expected:
        return False
    if any(int(published.get(field) or 0) != 0 for field in (
        "unknown_queued", "unknown_suppressed", "noise_skipped", "context_skipped",
    )):
        return False
    return int(published.get("queued") or 0) == expected


def _security_history_superseded_v1_path(manifest: Mapping[str, Any]) -> Path:
    """Keep immutable v1 evidence adjacent to the active versioned checkpoint."""
    digest = str(manifest.get("plan_digest") or "").casefold()
    if len(digest) != 64:
        raise RuntimeError("security history legacy manifest digest is invalid")
    return SECURITY_HISTORY_MANIFEST_PATH.with_name(
        f"{SECURITY_HISTORY_MANIFEST_PATH.stem}.v1-{digest}.json"
    )


def _write_security_history_v1_archive(manifest: Mapping[str, Any]) -> Path:
    """Create once; an existing different archive is evidence of a conflicting run."""
    archive_path = _security_history_superseded_v1_path(manifest)
    rendered = json.dumps(manifest, ensure_ascii=False, indent=2, default=str)
    try:
        with archive_path.open("x", encoding="utf-8") as handle:
            handle.write(rendered)
    except FileExistsError:
        try:
            existing = json.loads(archive_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError("security history v1 archive is invalid") from exc
        if existing != dict(manifest):
            raise RuntimeError("security history v1 archive conflicts with current manifest")
    return archive_path


def _security_history_require_repair_resolved(cur: Any, manifest: Mapping[str, Any]) -> None:
    """Do not supersede away the separately approved exact-100 repair incident."""
    rows = _security_history_repair_rows(cur, manifest)
    if rows:
        raise RuntimeError("security history exact-100 repair must finish before supersede")


def security_history_supersede_plan() -> dict[str, Any]:
    """Read a replacement proposal; no checkpoint or producer state changes here."""
    _load_environment()
    _validate_security_history_admission()
    manifest = _read_security_history_manifest()
    if manifest is None:
        raise RuntimeError("security history supersede requires an existing v1 manifest")
    validate_security_history_manifest(
        manifest, database_identity=_security_history_current_database_identity(),
        cohorts=None, plan_digest=str(manifest.get("plan_digest") or ""),
    )
    if manifest.get("manifest_type") != SECURITY_HISTORY_MANIFEST_TYPE_V1:
        raise RuntimeError("security history supersede requires a v1 manifest")
    with _connect_admin() as conn, conn.cursor() as cur:
        cur.execute("set transaction read only")
        _security_history_require_repair_resolved(cur, manifest)
    snapshot = _security_history_v2_snapshot(
        high_watermarks=_security_history_frozen_high_watermarks(manifest),
    )
    if snapshot["database_identity"] != manifest["database_identity"]:
        raise RuntimeError("security history database identity changed")
    if security_history_cohort_mismatches(manifest, snapshot["cohorts"]):
        raise RuntimeError("security history frozen v1 cohort changed before supersede")
    digest = _security_history_v2_plan_digest(
        snapshot, supersedes_plan_digest=str(manifest["plan_digest"]),
    )
    return {
        "status": "security_history_supersede_plan_ready",
        "legacy_plan_digest": str(manifest["plan_digest"]),
        "replacement_plan_digest": digest,
        "raw_cohorts": snapshot["cohorts"],
        "semantic_context_cohort": snapshot["semantic_context_cohort"],
        "batch_limit": MAX_PRODUCER_BATCH,
        "confirmation": SECURITY_HISTORY_SUPERSEDE_CONFIRM_PREFIX + digest,
        "manifest_path": str(SECURITY_HISTORY_MANIFEST_PATH),
        "production_changed": False,
    }


def security_history_supersede(*, plan_digest: str, confirmation: str) -> dict[str, Any]:
    """Atomically archive immutable v1 evidence then install the explicit v2 plan."""
    plan = security_history_supersede_plan()
    if plan_digest != plan["replacement_plan_digest"] or confirmation != plan["confirmation"]:
        raise RuntimeError("security history supersede confirmation required")
    with session_advisory_lock(_connect_admin, SECURITY_HISTORY_LOCK_NAME) as acquired:
        if not acquired:
            raise RuntimeError("security history controller lock is busy")
        _validate_security_history_admission()
        manifest = _read_security_history_manifest()
        if manifest is None:
            raise RuntimeError("security history supersede requires an existing v1 manifest")
        validate_security_history_manifest(
            manifest, database_identity=_security_history_current_database_identity(),
            cohorts=None, plan_digest=str(manifest.get("plan_digest") or ""),
        )
        if manifest.get("manifest_type") != SECURITY_HISTORY_MANIFEST_TYPE_V1:
            raise RuntimeError("security history supersede requires a v1 manifest")
        with _connect_admin() as conn, conn.cursor() as cur:
            cur.execute("set transaction read only")
            _security_history_require_repair_resolved(cur, manifest)
        snapshot = _security_history_v2_snapshot(
            high_watermarks=_security_history_frozen_high_watermarks(manifest),
        )
        if snapshot["database_identity"] != manifest["database_identity"]:
            raise RuntimeError("security history database identity changed")
        if security_history_cohort_mismatches(manifest, snapshot["cohorts"]):
            raise RuntimeError("security history frozen v1 cohort changed before supersede")
        actual_digest = _security_history_v2_plan_digest(
            snapshot, supersedes_plan_digest=str(manifest["plan_digest"]),
        )
        if actual_digest != plan_digest:
            raise RuntimeError("security history supersede plan changed")
        archive_path = _write_security_history_v1_archive(manifest)
        replacement = new_security_history_manifest_v2(
            database_identity=snapshot["database_identity"],
            cohorts=snapshot["cohorts"], plan_digest=actual_digest,
            semantic_context_cohort=snapshot["semantic_context_cohort"],
            supersedes={
                "manifest_type": SECURITY_HISTORY_MANIFEST_TYPE_V1,
                "plan_digest": manifest["plan_digest"],
                "reason": SECURITY_HISTORY_SUPERSEDE_REASON,
            },
        )
        _write_security_history_manifest(replacement)
    return {
        "status": "security_history_superseded_v2",
        "legacy_plan_digest": str(manifest["plan_digest"]),
        "replacement_plan_digest": plan_digest,
        "v1_archive_path": str(archive_path),
        "manifest_path": str(SECURITY_HISTORY_MANIFEST_PATH),
        "production_changed": False,
    }


def security_history_plan() -> dict[str, Any]:
    """Read-only compact vocabulary preview; it never creates its local manifest."""
    _load_environment()
    _validate_security_history_admission()
    manifest = _read_security_history_manifest()
    if manifest is None:
        snapshot = _security_history_v2_snapshot()
        digest = _security_history_v2_plan_digest(
            snapshot, supersedes_plan_digest=None,
        )
        return {
            "status": "security_history_v2_plan_ready",
            "database_identity": snapshot["database_identity"],
            "cohorts": snapshot["cohorts"],
            "semantic_context_cohort": snapshot["semantic_context_cohort"],
            "plan_digest": digest,
            "confirmation": SECURITY_HISTORY_POLL_CONFIRM_PREFIX + digest,
            "manifest_path": str(SECURITY_HISTORY_MANIFEST_PATH),
            "production_changed": False,
            "consumer": "existing_managed_investigation_worker",
        }
    validate_security_history_manifest(
        manifest,
        database_identity=_security_history_current_database_identity(),
        cohorts=None,
        plan_digest=str(manifest.get("plan_digest") or ""),
    )
    if manifest.get("manifest_type") == SECURITY_HISTORY_MANIFEST_TYPE_V1:
        return {
            "status": "security_history_explicit_supersede_required",
            "legacy_manifest_type": SECURITY_HISTORY_MANIFEST_TYPE_V1,
            "legacy_plan_digest": str(manifest["plan_digest"]),
            "manifest_path": str(SECURITY_HISTORY_MANIFEST_PATH),
            "production_changed": False,
        }
    return {
        "status": "security_history_resume_ready",
        "manifest": manifest,
        "plan_digest": str(manifest["plan_digest"]),
        "confirmation": SECURITY_HISTORY_POLL_CONFIRM_PREFIX + str(manifest["plan_digest"]),
        "manifest_path": str(SECURITY_HISTORY_MANIFEST_PATH),
        "production_changed": False,
        "consumer": "existing_managed_investigation_worker",
    }


def security_history_poll(*, confirmation: str) -> dict[str, Any]:
    """Publish one bounded exact cohort chunk; the existing worker consumes later."""
    plan = security_history_plan()
    if plan["status"] == "security_history_explicit_supersede_required":
        raise RuntimeError("security history v1 requires explicit supersede before poll")
    if confirmation != plan["confirmation"]:
        raise RuntimeError("security history poll confirmation required")
    with session_advisory_lock(_connect_admin, SECURITY_HISTORY_LOCK_NAME) as acquired:
        if not acquired:
            raise RuntimeError("security history controller lock is busy")
        _validate_security_history_admission()
        _require_compatible_investigation_worker()
        manifest = _read_security_history_manifest()
        if manifest is None:
            snapshot = _security_history_v2_snapshot()
            digest = _security_history_v2_plan_digest(
                snapshot, supersedes_plan_digest=None,
            )
            if confirmation != SECURITY_HISTORY_POLL_CONFIRM_PREFIX + digest:
                raise RuntimeError("security history poll plan changed")
            manifest = new_security_history_manifest_v2(
                database_identity=snapshot["database_identity"],
                cohorts=snapshot["cohorts"], plan_digest=digest,
                semantic_context_cohort=snapshot["semantic_context_cohort"],
                supersedes=None,
            )
            _write_security_history_manifest(manifest)
        else:
            validate_security_history_manifest(
                manifest,
                database_identity=_security_history_current_database_identity(),
                cohorts=None,
                plan_digest=str(manifest.get("plan_digest") or ""),
            )
        events = manifest["events"]
        if any(entry["state"] in {"queued", "processing"} for entry in events.values()):
            return {
                "status": "security_history_poll_waiting_for_managed_worker",
                "manifest_path": str(SECURITY_HISTORY_MANIFEST_PATH),
                "consumer": "existing_managed_investigation_worker",
                "production_changed": False,
            }
        candidate_id = next((event_id for event_id in SECURITY_HISTORY_EVENT_IDS if events[str(event_id)]["state"] in {"planned", "publishing"}), None)
        if candidate_id is None:
            return {
                "status": "security_history_poll_waiting_for_managed_worker",
                "manifest_path": str(SECURITY_HISTORY_MANIFEST_PATH),
                "consumer": "existing_managed_investigation_worker",
                "production_changed": False,
            }
        entry = events[str(candidate_id)]
        with _connect_admin() as conn:
            with conn.transaction(), conn.cursor() as cur:
                cur.execute("set local role adlog_storage_worker")
                target_ids = (
                    select_security_history_context_targets(
                        cur, after_id=int(entry["cursor"]),
                        high_watermark=int(entry["high_watermark"]),
                        reset_high_watermark=int(entry["semantic_context_reset_high_watermark"]),
                        limit=_security_history_manifest_batch_limit(manifest),
                    )
                    if (
                        manifest.get("manifest_type") == SECURITY_HISTORY_MANIFEST_TYPE_V2
                        and candidate_id == 4624
                    )
                    else select_security_history_targets(
                        cur, event_id=candidate_id, after_id=int(entry["cursor"]),
                        high_watermark=int(entry["high_watermark"]),
                        limit=_security_history_manifest_batch_limit(manifest),
                    )
                )
                published = (
                    publish_semantic_candidates(
                        cur, target_ids, include_context=True,
                        context_event_ids=target_ids,
                    )
                    if manifest.get("manifest_type") == SECURITY_HISTORY_MANIFEST_TYPE_V2
                    else publish_semantic_candidates(
                        cur, target_ids, include_context=True, context_event_ids=target_ids,
                    )
                )
        # This mutation is deliberately after the outbox transaction: a lost
        # local write repeats only the same idempotent source chunk.
        if target_ids:
            entry["cursor"] = int(target_ids[-1])
            entry["state"] = "queued"
            publication_is_exact = (
                _security_history_v2_publication_is_exact(
                    event_id=candidate_id, target_ids=target_ids, published=published,
                )
                if manifest.get("manifest_type") == SECURITY_HISTORY_MANIFEST_TYPE_V2
                else int(published.get("queued") or 0) == len(target_ids)
            )
            if not publication_is_exact:
                entry["state"] = "incomplete_normalization"
                entry["terminal_reason"] = "producer_did_not_queue_exact_selected_rows"
                entry["samples"]["incomplete_ids"] = list(target_ids[:10])
        else:
            # Selection excludes facts already normalized by the current
            # contract.  They are a recovered completed cursor, not an empty
            # chunk to retry forever; the managed worker/check owns final
            # reconciliation.
            entry["cursor"] = int(entry["high_watermark"])
            entry["state"] = "queued"
        manifest["updated_at_utc"] = datetime.now(timezone.utc).isoformat()
        _write_security_history_manifest(manifest)
    return {
        "status": "security_history_poll_complete",
        "event_id": candidate_id,
        "target_events": len(target_ids),
        "producer": published,
        "manifest_path": str(SECURITY_HISTORY_MANIFEST_PATH),
        "consumer": "existing_managed_investigation_worker",
        "production_changed": bool(target_ids),
    }


def security_history_check_plan() -> dict[str, Any]:
    """Read-only terminal comparison plan bound to the frozen vocabulary manifest."""
    _load_environment()
    manifest = _read_security_history_manifest()
    if manifest is None:
        raise RuntimeError("security history manifest does not exist")
    return _security_history_check_plan_for_manifest(manifest)


def security_history_check(*, plan_digest: str, confirmation: str) -> dict[str, Any]:
    """Record a plan-bound local readback; it never starts or impersonates a worker."""
    plan = security_history_check_plan()
    if plan_digest != plan["plan_digest"] or confirmation != plan["confirmation"]:
        raise RuntimeError("security history check confirmation required")
    with session_advisory_lock(_connect_admin, SECURITY_HISTORY_LOCK_NAME) as acquired:
        if not acquired:
            raise RuntimeError("security history controller lock is busy")
        manifest = _read_security_history_manifest()
        assert manifest is not None
        locked_plan = _security_history_check_plan_for_manifest(manifest)
        if (
            plan_digest != locked_plan["plan_digest"]
            or confirmation != locked_plan["confirmation"]
        ):
            raise RuntimeError("security history check plan changed")
        drift_event_ids: tuple[int, ...] = ()
        with _connect_admin() as conn, conn.cursor() as cur:
            cur.execute("set transaction isolation level repeatable read, read only")
            for event_id in SECURITY_HISTORY_EVENT_IDS:
                entry = manifest["events"][str(event_id)]
                v2_repair_states: Mapping[str, int] | None = None
                if (
                    manifest.get("manifest_type") == SECURITY_HISTORY_MANIFEST_TYPE_V2
                    and event_id == 4624
                ):
                    v2_reconciliation = reconcile_security_history_v2_context_event(
                        cur, high_watermark=int(entry["high_watermark"]),
                        reset_high_watermark=int(entry["semantic_context_reset_high_watermark"]),
                        history_plan_digest=str(manifest["plan_digest"]),
                    )
                    reconciliation = v2_reconciliation.current
                    v2_repair_states = v2_reconciliation.repair_states
                    entry["v2_repair_states"] = dict(v2_repair_states)
                else:
                    reconciliation = reconcile_security_history_event(
                        cur, event_id=event_id, high_watermark=int(entry["high_watermark"]),
                    )
                entry["normalized_count"] = reconciliation["normalized_count"]
                entry["outbox_count"] = sum(
                    reconciliation[name] for name in (
                        "outbox_queued", "outbox_leased", "outbox_completed",
                        "outbox_failed", "outbox_quarantined",
                    )
                )
                entry["action_count"] = reconciliation["action_evidence_count"]
                if entry["state"] == "no_retained_events":
                    continue
                if reconciliation["retained_count"] != int(entry["count"]):
                    entry["state"] = "incomplete_original"
                    entry["terminal_reason"] = "frozen_original_integrity_mismatch"
                elif v2_repair_states is not None:
                    if v2_repair_states.get("conflict", 0):
                        entry["state"] = "incomplete_normalization"
                        entry["terminal_reason"] = "current_version_non_unknown_normalization_missing"
                    elif v2_repair_states.get("quarantined", 0):
                        entry["state"] = "quarantined"
                        entry["terminal_reason"] = "quarantined_current_version_work"
                    elif v2_repair_states.get("failed", 0):
                        entry["state"] = "failed"
                        entry["terminal_reason"] = "failed_current_version_work"
                    elif v2_repair_states.get("leased", 0):
                        entry["state"] = "processing"
                        entry["terminal_reason"] = None
                    elif v2_repair_states.get("queued", 0):
                        entry["state"] = "queued"
                        entry["terminal_reason"] = None
                    elif v2_repair_states.get("absent", 0):
                        entry["state"] = "incomplete_normalization"
                        entry["terminal_reason"] = "current_version_non_unknown_normalization_missing"
                    elif v2_repair_states.get("completed", 0) == reconciliation["retained_count"]:
                        entry["state"] = "complete"
                        entry["terminal_reason"] = "current_version_normalized_hash_reconciled"
                    else:
                        entry["state"] = "incomplete_normalization"
                        entry["terminal_reason"] = "current_version_non_unknown_normalization_missing"
                elif reconciliation["normalization_quarantined"] or reconciliation["outbox_quarantined"]:
                    entry["state"] = "quarantined"
                    entry["terminal_reason"] = "quarantined_current_version_work"
                elif reconciliation["normalization_failed"] or reconciliation["outbox_failed"]:
                    entry["state"] = "failed"
                    entry["terminal_reason"] = "failed_current_version_work"
                elif reconciliation["outbox_leased"]:
                    entry["state"] = "processing"
                    entry["terminal_reason"] = None
                elif reconciliation["outbox_queued"]:
                    entry["state"] = "queued"
                    entry["terminal_reason"] = None
                elif reconciliation["normalized_count"] == reconciliation["retained_count"]:
                    entry["state"] = "complete"
                    entry["terminal_reason"] = "current_version_normalized_hash_reconciled"
                else:
                    if int(entry.get("cursor") or 0) < int(entry["high_watermark"]):
                        entry["state"] = "publishing"
                        entry["terminal_reason"] = None
                    else:
                        entry["state"] = "incomplete_normalization"
                        entry["terminal_reason"] = "current_version_non_unknown_normalization_missing"
        terminal = all(entry["state"] in {"complete", "no_retained_events"} for entry in manifest["events"].values())
        if terminal:
            high_watermarks = _security_history_frozen_high_watermarks(manifest)
            snapshot = (
                _security_history_v2_snapshot(high_watermarks=high_watermarks)
                if manifest.get("manifest_type") == SECURITY_HISTORY_MANIFEST_TYPE_V2
                else _security_history_snapshot(high_watermarks=high_watermarks)
            )
            if snapshot["database_identity"] != manifest["database_identity"]:
                raise RuntimeError("security history database identity changed")
            drift_event_ids = security_history_cohort_mismatches(
                manifest, snapshot["cohorts"],
            )
            if manifest.get("manifest_type") == SECURITY_HISTORY_MANIFEST_TYPE_V2:
                entry = manifest["events"]["4624"]
                observed_context = snapshot["semantic_context_cohort"]
                if any((
                    int(entry["semantic_expected_count"]) != int(observed_context["count"]),
                    str(entry["semantic_context_digest"]) != str(observed_context["cohort_digest"]),
                    int(entry["semantic_context_reset_high_watermark"])
                    != int(observed_context["reset_high_watermark"]),
                )):
                    drift_event_ids = tuple(sorted({*drift_event_ids, 4624}))
            for event_id in drift_event_ids:
                entry = manifest["events"][str(event_id)]
                entry["state"] = "incomplete_original"
                entry["terminal_reason"] = "frozen_original_integrity_mismatch"
            terminal = not drift_event_ids
        manifest["result"] = {
            "checked_at_utc": datetime.now(timezone.utc).isoformat(),
            "check_plan_digest": plan_digest,
            "terminal_success": terminal,
            "drift_event_ids": list(drift_event_ids),
        }
        manifest["updated_at_utc"] = datetime.now(timezone.utc).isoformat()
        _write_security_history_manifest(manifest)
    return {
        "status": "security_history_check_complete" if terminal else "security_history_check_incomplete",
        "terminal_success": terminal,
        "drift_event_ids": list(drift_event_ids),
        "manifest_path": str(SECURITY_HISTORY_MANIFEST_PATH),
        "production_changed": False,
    }


def _security_history_repair_rows(cur: Any, manifest: Mapping[str, Any]) -> list[dict[str, Any]]:
    events = manifest.get("events")
    if not isinstance(events, Mapping):
        raise RuntimeError("security history manifest events are invalid")
    event_ids = list(SECURITY_HISTORY_EVENT_IDS)
    high_watermarks = [int(dict(events[str(event_id)])["high_watermark"]) for event_id in event_ids]
    cur.execute(
        """
        with frozen(event_id,high_watermark) as (
          select * from unnest(%s::integer[],%s::bigint[])
        )
        select job.job_id::text as original_job_id,job.source_event_id,
               core.event_id as source_windows_event_id,
               job.source_identity_json->>'normalized_hash' as original_source_hash
        from public.semantic_processing_outbox job
        join public.events_v2_core core on core.id=job.source_event_id
        join frozen on frozen.event_id=core.event_id and core.id<=frozen.high_watermark
        join public.storage_v2_channel channel on channel.id=core.channel_id
        join public.storage_v2_provider provider on provider.id=core.provider_id
        where job.job_kind='normalize_event' and job.status='completed'
          and job.semantic_contract_version=%s
          and job.processor_id=%s and job.processor_version=%s
          and job.source_identity_json->>'normalized_hash'=encode(core.normalized_hash,'hex')
          and channel.value='Security'
          and provider.value=case core.event_id
            when 1102 then 'Microsoft-Windows-Eventlog'
            else 'Microsoft-Windows-Security-Auditing' end
          and not exists (
            select 1 from public.normalized_events normalized
            where normalized.source_event_id=core.id
              and normalized.semantic_contract_version=%s
              and normalized.normalizer_id=%s and normalized.normalizer_version=%s
              and normalized.processing_status='normalized'
              and normalized.source_event_sha256=core.normalized_hash
              and normalized.semantic_type<>'event.unknown'
          )
        order by job.source_event_id,job.job_id
        """,
        (
            event_ids, high_watermarks, SEMANTIC_CONTRACT_VERSION, PROCESSOR_ID,
            PROCESSOR_VERSION, SEMANTIC_CONTRACT_VERSION, NORMALIZER_ID,
            NORMALIZER_VERSION,
        ),
    )
    rows = [dict(row) for row in (cur.fetchall() or [])]
    for row in rows:
        source_hash = str(row.get("original_source_hash") or "").casefold()
        if (
            int(row.get("source_event_id") or 0) <= 0
            or int(row.get("source_windows_event_id") or 0) not in SECURITY_HISTORY_EVENT_IDS
            or not str(row.get("original_job_id") or "").strip()
            or len(source_hash) != 64
            or any(char not in "0123456789abcdef" for char in source_hash)
        ):
            raise RuntimeError("security history repair selection is invalid")
    return rows


def _security_history_repair_digest(manifest: Mapping[str, Any], rows: Sequence[Mapping[str, Any]]) -> str:
    material = {
        "repair_type": "semantic_current_version_completed_repair_v1",
        "history_plan_digest": manifest["plan_digest"],
        "processor": {"id": PROCESSOR_ID, "version": PROCESSOR_VERSION},
        "normalizer": {"id": NORMALIZER_ID, "version": NORMALIZER_VERSION},
        "rows": [
            [str(row["original_job_id"]), int(row["source_event_id"]),
             int(row["source_windows_event_id"]), str(row["original_source_hash"])]
            for row in rows
        ],
    }
    return sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def security_history_repair_plan(*, expected_count: int = 100) -> dict[str, Any]:
    """Read the exact completed-but-unmaterialized current-version repair set."""
    if int(expected_count) != 100:
        raise RuntimeError("security history repair requires exact expected count 100")
    _load_environment()
    _validate_security_history_admission()
    manifest = _read_security_history_manifest()
    if manifest is None:
        raise RuntimeError("security history repair requires an existing history manifest")
    validate_security_history_manifest(
        manifest, database_identity=_security_history_current_database_identity(),
        cohorts=None, plan_digest=str(manifest.get("plan_digest") or ""),
    )
    if manifest.get("manifest_type") != SECURITY_HISTORY_MANIFEST_TYPE_V1:
        raise RuntimeError("security history repair applies only to the archived v1 incident")
    with _connect_admin() as conn, conn.cursor() as cur:
        cur.execute("set transaction read only")
        rows = _security_history_repair_rows(cur, manifest)
    if len(rows) != 100:
        raise RuntimeError("security history repair selection is not exact 100 rows")
    digest = _security_history_repair_digest(manifest, rows)
    return {
        "status": "security_history_repair_plan_ready",
        "history_plan_digest": manifest["plan_digest"],
        "repair_plan_digest": digest,
        "confirmation": SECURITY_HISTORY_REPAIR_CONFIRM_PREFIX + digest,
        "target_events": len(rows),
        "production_changed": False,
    }


def security_history_repair(*, plan_digest: str, confirmation: str) -> dict[str, Any]:
    """Append exact repair jobs; the original completed jobs remain immutable evidence."""
    plan = security_history_repair_plan()
    if plan_digest != plan["repair_plan_digest"] or confirmation != plan["confirmation"]:
        raise RuntimeError("security history repair confirmation required")
    with session_advisory_lock(_connect_admin, SECURITY_HISTORY_LOCK_NAME) as acquired:
        if not acquired:
            raise RuntimeError("security history controller lock is busy")
        _validate_security_history_admission()
        _require_compatible_investigation_worker()
        manifest = _read_security_history_manifest()
        if manifest is None:
            raise RuntimeError("security history repair requires an existing history manifest")
        validate_security_history_manifest(
            manifest, database_identity=_security_history_current_database_identity(),
            cohorts=None, plan_digest=str(manifest.get("plan_digest") or ""),
        )
        if manifest.get("manifest_type") != SECURITY_HISTORY_MANIFEST_TYPE_V1:
            raise RuntimeError("security history repair applies only to the archived v1 incident")
        with _connect_admin() as conn:
            with conn.transaction(), conn.cursor() as cur:
                rows = _security_history_repair_rows(cur, manifest)
                if len(rows) != 100 or _security_history_repair_digest(manifest, rows) != plan_digest:
                    raise RuntimeError("security history repair plan changed")
                for row in rows:
                    enqueue_semantic_job(
                        cur, source_event_id=int(row["source_event_id"]),
                        job_kind=SEMANTIC_REPAIR_JOB_KIND,
                        payload={
                            "repair_plan_digest": plan_digest,
                            "history_plan_digest": manifest["plan_digest"],
                            "original_job_id": str(row["original_job_id"]),
                            "original_source_hash": str(row["original_source_hash"]),
                        },
                    )
        for event_id in {int(row["source_windows_event_id"]) for row in rows}:
            entry = manifest["events"][str(event_id)]
            entry["state"] = "queued"
            entry["terminal_reason"] = None
        manifest["updated_at_utc"] = datetime.now(timezone.utc).isoformat()
        _write_security_history_manifest(manifest)
        return {
            "status": "security_history_repair_queued",
            "history_plan_digest": manifest["plan_digest"],
            "repair_plan_digest": plan_digest,
            "target_events": len(rows),
            "production_changed": True,
        }


def _require_migration143(cur: Any) -> None:
    cur.execute("select name from public.schema_migrations where version=143")
    row = dict(cur.fetchone() or {})
    if row.get("name") != "semantic_v2_quarantine_repair":
        raise RuntimeError("security history v2 repair requires exact migration143 marker")


def _security_history_v2_quarantine_snapshot(cur: Any, manifest: Mapping[str, Any]) -> tuple[list[tuple[int, str]], dict[str, object]]:
    """Recheck frozen raw cohorts and select only the approved 4624 context."""
    high_watermarks = _security_history_frozen_high_watermarks(manifest)
    identity = _security_history_database_identity(cur)
    if identity != manifest.get("database_identity"):
        raise RuntimeError("security history database identity changed")
    cohorts = security_history_cohorts(cur, high_watermarks=high_watermarks)
    if security_history_cohort_mismatches(manifest, cohorts):
        raise RuntimeError("security history frozen raw cohort changed")
    entry = dict(dict(manifest["events"])["4624"])
    context = security_history_context_cohort(
        cur,
        high_watermark=int(entry["high_watermark"]),
        reset_high_watermark=int(entry["semantic_context_reset_high_watermark"]),
    )
    if any((
        int(context["count"]) != int(entry["semantic_expected_count"]),
        str(context["cohort_digest"]) != str(entry["semantic_context_digest"]),
        int(context["reset_high_watermark"]) != int(entry["semantic_context_reset_high_watermark"]),
    )):
        raise RuntimeError("security history frozen v2 context cohort changed")
    pairs = [
        (int(source_id), str(source_hash).casefold())
        for source_id, source_hash in _iter_security_history_context_pairs(
            cur, after_id=0, high_watermark=int(entry["high_watermark"]),
            reset_high_watermark=int(entry["semantic_context_reset_high_watermark"]),
        )
    ]
    if len(pairs) != 260 or security_history_cohort_digest(pairs) != str(context["cohort_digest"]):
        raise RuntimeError("security history v2 repair selection is not exact")
    return pairs, context


def _security_history_v2_quarantine_rows(cur: Any, manifest: Mapping[str, Any]) -> tuple[list[dict[str, Any]], dict[str, object]]:
    """Return exact immutable terminal originals; reject every near-match."""
    pairs, context = _security_history_v2_quarantine_snapshot(cur, manifest)
    source_ids = [source_id for source_id, _ in pairs]
    hashes = {source_id: source_hash for source_id, source_hash in pairs}
    cur.execute(
        """
        select job_id::text as original_job_id,source_event_id,
               source_identity_json->>'normalized_hash' as original_source_hash,
               status,attempt_count,max_attempts,last_error_code,last_error_detail
        from public.semantic_processing_outbox
        where source_event_id=any(%s) and job_kind='normalize_event'
          and semantic_contract_version=%s and processor_id=%s and processor_version=%s
        order by source_event_id,job_id
        """,
        (source_ids, SEMANTIC_CONTRACT_VERSION, PROCESSOR_ID, PROCESSOR_VERSION),
    )
    originals = [dict(row) for row in (cur.fetchall() or [])]
    if len(originals) != len(source_ids) or {int(row.get("source_event_id") or 0) for row in originals} != set(source_ids):
        raise RuntimeError("security history v2 repair originals are missing, extra, or duplicate")
    cur.execute(
        """select source_event_id,count(*) as normalized_count from public.normalized_events
           where source_event_id=any(%s) and semantic_contract_version=%s
             and normalizer_id=%s and normalizer_version=%s
           group by source_event_id""",
        (source_ids, SEMANTIC_CONTRACT_VERSION, NORMALIZER_ID, NORMALIZER_VERSION),
    )
    if cur.fetchall():
        raise RuntimeError("security history v2 repair selected rows are already normalized")
    rows: list[dict[str, Any]] = []
    for row in originals:
        source_id = int(row.get("source_event_id") or 0)
        source_hash = str(row.get("original_source_hash") or "").casefold()
        detail = str(row.get("last_error_detail") or "")
        if (
            source_id not in hashes or source_hash != hashes[source_id]
            or row.get("status") != "quarantined"
            or int(row.get("attempt_count") or -1) != int(row.get("max_attempts") or -2)
            or int(row.get("max_attempts") or 0) <= 0
            or row.get("last_error_code") != "UniqueViolation"
            or '"canonical_actions_pkey"' not in detail
            or not str(row.get("original_job_id") or "").strip()
        ):
            raise RuntimeError("security history v2 repair original terminal contract changed")
        rows.append({
            "original_job_id": str(row["original_job_id"]), "source_event_id": source_id,
            "original_source_hash": source_hash, "original_attempt_count": int(row["attempt_count"]),
            "original_max_attempts": int(row["max_attempts"]),
            "original_error_code": "UniqueViolation",
            "original_error_detail_sha256": sha256(detail.encode("utf-8")).hexdigest(),
        })
    return rows, context


def lock_semantic_sources(cur: Any, source_ids: Sequence[int]) -> None:
    """Acquire the worker-shared source locks in a global order to avoid deadlock."""
    for source_event_id in sorted({int(value) for value in source_ids}):
        lock_semantic_source(cur, source_event_id=source_event_id)


def _security_history_v2_quarantine_repair_digest(manifest: Mapping[str, Any], rows: Sequence[Mapping[str, Any]], context: Mapping[str, object]) -> str:
    material = {
        "repair_type": "semantic_v2_quarantine_repair_v1",
        "history_plan_digest": manifest["plan_digest"],
        "database_identity": manifest["database_identity"],
        "raw_cohorts": {
            event_id: {
                name: dict(entry)[name]
                for name in ("count", "high_watermark", "cohort_digest")
            }
            for event_id, entry in sorted(dict(manifest["events"]).items())
        },
        "context": {name: context[name] for name in ("count", "cohort_digest", "reset_high_watermark")},
        "processor": {"id": PROCESSOR_ID, "version": PROCESSOR_VERSION},
        "normalizer": {"id": NORMALIZER_ID, "version": NORMALIZER_VERSION},
        "assembler": {"id": ASSEMBLER_ID, "version": ASSEMBLER_VERSION},
        "worker_release_fingerprint": semantic_worker_release_fingerprint(),
        "rows": [[row[name] for name in (
            "original_job_id", "source_event_id", "original_source_hash", "original_attempt_count",
            "original_max_attempts", "original_error_code", "original_error_detail_sha256",
        )] for row in rows],
    }
    return sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _require_v2_repair_worker(
    cur: Any | None = None,
    *,
    repair_plan_digest: str,
) -> None:
    """An old compatible worker is not evidence that the conflict fix is deployed."""
    if cur is None:
        with _connect_admin() as conn, conn.cursor() as fresh_cur:
            return _require_v2_repair_worker(
                fresh_cur, repair_plan_digest=repair_plan_digest,
            )
    cur.execute("""select details_json from runtime_worker_heartbeats where worker_name='semantic'
                   and status in ('running','idle') and heartbeat_at >= now() -
                   (greatest(180,expected_interval_seconds*3) * interval '1 second')
                   for share""")
    row = dict(cur.fetchone() or {})
    details = row.get("details_json")
    if isinstance(details, str):
        try:
            details = json.loads(details)
        except json.JSONDecodeError:
            details = None
    contract = details.get("processing_contract") if isinstance(details, Mapping) else None
    if not isinstance(contract, Mapping) or contract.get("release_fingerprint") != semantic_worker_release_fingerprint():
        raise RuntimeError("security history v2 repair requires a fresh managed worker release fingerprint")
    if (
        not isinstance(contract, Mapping)
        or details.get("runtime_mode") != INVESTIGATION_MODE
        or details.get("manual_runtime") is not False
        or contract.get("claim_protocol_version") != 1
        or contract.get("semantic_contract_version") != SEMANTIC_CONTRACT_VERSION
        or contract.get("processor_id") != PROCESSOR_ID
        or contract.get("processor_version") != PROCESSOR_VERSION
        or contract.get("normalizer") != {"id": NORMALIZER_ID, "version": NORMALIZER_VERSION}
        or contract.get("assembler") != {"id": ASSEMBLER_ID, "version": ASSEMBLER_VERSION}
    ):
        raise RuntimeError("security history v2 repair requires a fresh compatible managed investigation worker")
    expected_scope = {
        "job_kind": SEMANTIC_V2_QUARANTINE_REPAIR_JOB_KIND,
        "repair_plan_digest": repair_plan_digest,
    }
    if details.get("repair_scope") != expected_scope:
        raise RuntimeError("security history v2 repair requires a fresh managed worker with exact scope")


def security_history_v2_quarantine_repair_plan() -> dict[str, Any]:
    """Read-only proposal for the frozen terminal 4624 context repair."""
    _load_environment()
    _validate_security_history_admission()
    manifest = _read_security_history_manifest()
    if manifest is None or manifest.get("manifest_type") != SECURITY_HISTORY_MANIFEST_TYPE_V2:
        raise RuntimeError("security history v2 repair requires the v2 manifest")
    validate_security_history_manifest(manifest, database_identity=_security_history_current_database_identity(), cohorts=None, plan_digest=str(manifest.get("plan_digest") or ""))
    with _connect_admin() as conn, conn.cursor() as cur:
        cur.execute("set transaction read only")
        _require_migration143(cur)
        rows, context = _security_history_v2_quarantine_rows(cur, manifest)
    digest = _security_history_v2_quarantine_repair_digest(manifest, rows, context)
    return {"status": "security_history_v2_quarantine_repair_plan_ready", "history_plan_digest": manifest["plan_digest"],
            "repair_plan_digest": digest, "confirmation": SECURITY_HISTORY_V2_QUARANTINE_REPAIR_CONFIRM_PREFIX + digest,
            "target_events": len(rows), "worker_release_fingerprint": semantic_worker_release_fingerprint(),
            "production_changed": False, "collection_changed": False}


def security_history_v2_quarantine_repair(*, plan_digest: str, confirmation: str) -> dict[str, Any]:
    """Append identity-only v2 repair jobs; never mutate the terminal originals."""
    plan = security_history_v2_quarantine_repair_plan()
    if plan_digest != plan["repair_plan_digest"] or confirmation != plan["confirmation"]:
        raise RuntimeError("security history v2 repair confirmation required")
    with session_advisory_lock(_connect_admin, SECURITY_HISTORY_LOCK_NAME) as acquired:
        if not acquired:
            raise RuntimeError("security history controller lock is busy")
        _validate_security_history_admission()
        manifest = _read_security_history_manifest()
        if manifest is None or manifest.get("manifest_type") != SECURITY_HISTORY_MANIFEST_TYPE_V2:
            raise RuntimeError("security history v2 repair requires the v2 manifest")
        validate_security_history_manifest(
            manifest,
            database_identity=_security_history_current_database_identity(),
            cohorts=None,
            plan_digest=str(manifest.get("plan_digest") or ""),
        )
        with _connect_admin() as conn:
            with conn.transaction(), conn.cursor() as cur:
                _require_migration143(cur)
                cur.execute("set local role adlog_storage_worker")
                selected_pairs, _ = _security_history_v2_quarantine_snapshot(cur, manifest)
                lock_semantic_sources(cur, [source_event_id for source_event_id, _ in selected_pairs])
                rows, context = _security_history_v2_quarantine_rows(cur, manifest)
                if _security_history_v2_quarantine_repair_digest(manifest, rows, context) != plan_digest:
                    raise RuntimeError("security history v2 repair plan changed")
                _require_v2_repair_worker(cur, repair_plan_digest=plan_digest)
                queued = 0
                for row in rows:
                    payload = {"repair_plan_digest": plan_digest, "history_plan_digest": manifest["plan_digest"], **row}
                    cur.execute("select payload_json from semantic_processing_outbox where source_event_id=%s and job_kind=%s", (row["source_event_id"], SEMANTIC_V2_QUARANTINE_REPAIR_JOB_KIND))
                    existing = [dict(item).get("payload_json") for item in (cur.fetchall() or [])]
                    for item in existing:
                        if isinstance(item, str):
                            item = json.loads(item)
                        if item != payload:
                            raise RuntimeError("security history v2 repair work conflicts with exact replay")
                    if len(existing) > 1:
                        raise RuntimeError("security history v2 repair work is duplicate")
                    existed = bool(existing)
                    enqueue_semantic_job(cur, source_event_id=int(row["source_event_id"]), job_kind=SEMANTIC_V2_QUARANTINE_REPAIR_JOB_KIND, payload=payload)
                    queued += 0 if existed else 1
    return {"status": "security_history_v2_quarantine_repair_queued", "history_plan_digest": manifest["plan_digest"],
            "repair_plan_digest": plan_digest, "target_events": len(rows), "newly_queued": queued,
            "production_changed": bool(queued), "collection_changed": False}


def _facts_check_ids(values: Sequence[int]) -> tuple[int, ...]:
    """Canonicalize only the owner-provided small exact ID set."""
    try:
        ids = tuple(int(value) for value in values)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("facts check IDs are invalid") from exc
    if (
        not ids
        or len(ids) > PRODUCTION_MAX_LIMIT
        or any(value <= 0 for value in ids)
        or len(set(ids)) != len(ids)
    ):
        raise RuntimeError("facts check IDs are invalid")
    return tuple(sorted(ids))


def _facts_check_database_identity_and_ids(event_ids: Sequence[int]) -> dict[str, str]:
    """Read just plan identity and exact V2 presence; no event payload leaves DB."""
    with _connect_admin() as conn, conn.cursor() as cur:
        cur.execute("set transaction read only")
        cur.execute(
            "select coalesce(inet_server_addr()::text,'') as host, "
            "current_database() as database, current_user as role"
        )
        row = dict(cur.fetchone() or {})
        identity = {field: str(row.get(field) or "") for field in ("host", "database", "role")}
        if not all(identity.values()):
            raise RuntimeError("facts check database identity is unavailable")
        cur.execute(
            "select id from events_v2_core where id=any(%s) order by id",
            (list(event_ids),),
        )
        found = tuple(int(item["id"]) for item in (cur.fetchall() or []))
    if found != tuple(event_ids):
        raise RuntimeError("facts check exact event IDs are unavailable")
    return identity


def _facts_check_digest(
    *, event_ids: Sequence[int], rules_fingerprint: str, database_identity: dict[str, str]
) -> str:
    material = {
        "check_type": "exact_retained_semantic_facts_v1",
        "event_ids": list(event_ids),
        "rules_fingerprint": rules_fingerprint,
        "database_identity": database_identity,
        "include_context": True,
        "runtime_mode": FACTS_MODE,
        "max_consume": PRODUCTION_MAX_LIMIT,
    }
    return sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def facts_check_plan(event_ids: Sequence[int]) -> dict[str, Any]:
    """Read-only exact retained-facts plan; it never creates its manifest."""
    exact_ids = _facts_check_ids(event_ids)
    _load_environment()
    fingerprint = _facts_rules_fingerprint()
    database_identity = _facts_check_database_identity_and_ids(exact_ids)
    digest = _facts_check_digest(
        event_ids=exact_ids,
        rules_fingerprint=fingerprint,
        database_identity=database_identity,
    )
    return {
        "status": "exact_retained_facts_check_plan_ready",
        "event_ids": list(exact_ids),
        "rules_fingerprint": fingerprint,
        "database_identity": database_identity,
        "plan_digest": digest,
        "confirmation": FACTS_CHECK_CONFIRM_PREFIX + digest,
        "manifest_path": str(FACTS_CHECK_MANIFEST_PATH),
        "production_changed": False,
    }


def _read_facts_check_manifest() -> dict[str, Any] | None:
    if not FACTS_CHECK_MANIFEST_PATH.exists():
        return None
    try:
        manifest = json.loads(FACTS_CHECK_MANIFEST_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("exact facts check manifest is invalid") from exc
    if not isinstance(manifest, dict):
        raise RuntimeError("exact facts check manifest is invalid")
    return manifest


def _write_facts_check_manifest(payload: dict[str, Any]) -> None:
    """Atomically update state while identity fields remain validated immutable."""
    FACTS_CHECK_MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = FACTS_CHECK_MANIFEST_PATH.with_name(
        f".{FACTS_CHECK_MANIFEST_PATH.name}.{os.getpid()}.tmp"
    )
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, default=str), encoding="utf-8"
    )
    os.replace(temporary, FACTS_CHECK_MANIFEST_PATH)


def _new_facts_check_manifest(
    *, event_ids: Sequence[int], rules_fingerprint: str,
    database_identity: dict[str, str], plan_digest: str,
) -> dict[str, Any]:
    return {
        "manifest_type": "exact_retained_semantic_facts_check_v1",
        "event_ids": list(event_ids),
        "rules_fingerprint": rules_fingerprint,
        "database_identity": database_identity,
        "plan_digest": plan_digest,
        "include_context": True,
        "runtime_mode": FACTS_MODE,
        "state": "intent",
        "result": None,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
    }


def _validate_facts_check_manifest(
    manifest: dict[str, Any], *, event_ids: Sequence[int], rules_fingerprint: str,
    database_identity: dict[str, str], plan_digest: str,
) -> None:
    expected = {
        "manifest_type": "exact_retained_semantic_facts_check_v1",
        "event_ids": list(event_ids),
        "rules_fingerprint": rules_fingerprint,
        "database_identity": database_identity,
        "plan_digest": plan_digest,
        "include_context": True,
        "runtime_mode": FACTS_MODE,
    }
    if any(manifest.get(key) != value for key, value in expected.items()):
        raise RuntimeError("exact facts check manifest does not match plan")
    if manifest.get("state") not in {
        "intent", "published", "partial", "processed", "no_admitted_events"
    }:
        raise RuntimeError("exact facts check manifest state is invalid")


def _facts_check_queue_status(event_ids: Sequence[int]) -> dict[str, int]:
    """Read the current exact contract; completed jobs also need normalization proof."""
    states = dict.fromkeys(("completed", "queued", "failed", "leased", "quarantined", "incomplete"), 0)
    seen: set[int] = set()
    with _connect_admin() as conn, conn.cursor() as cur:
        cur.execute("set transaction read only")
        cur.execute(
            """
            select job.source_event_id,job.status,
                   (job.source_identity_json->>'id'=core.id::text
                    and job.source_identity_json->>'normalized_hash'=encode(core.normalized_hash,'hex')) as identity_matches,
                   exists (
                       select 1 from public.normalized_events normalized
                       where normalized.source_event_id=core.id
                         and normalized.semantic_contract_version=%s
                         and normalized.normalizer_id=%s and normalized.normalizer_version=%s
                         and normalized.processing_status='normalized'
                         and normalized.source_event_sha256=core.normalized_hash
                   ) as normalized
            from public.semantic_processing_outbox job
            left join public.events_v2_core core on core.id=job.source_event_id
            where job.source_event_id=any(%s) and job.job_kind='normalize_event'
              and job.semantic_contract_version=%s
              and job.processor_id=%s and job.processor_version=%s
            """,
            (SEMANTIC_CONTRACT_VERSION, NORMALIZER_ID, NORMALIZER_VERSION,
             list(event_ids), SEMANTIC_CONTRACT_VERSION, PROCESSOR_ID, PROCESSOR_VERSION),
        )
        for row in cur.fetchall() or []:
            item = dict(row)
            source_event_id = int(item.get("source_event_id") or 0)
            status = str(item.get("status") or "")
            if source_event_id not in event_ids or source_event_id in seen or status not in states or status == "incomplete":
                raise RuntimeError("exact facts check queue coverage is ambiguous or invalid")
            seen.add(source_event_id)
            if item.get("identity_matches") is not True or (status == "completed" and item.get("normalized") is not True):
                states["incomplete"] += 1
            else:
                states[status] += 1
    states["not_enqueued"] = len(set(event_ids) - seen)
    return states


@contextmanager
def _facts_check_environment() -> Iterator[None]:
    """Use facts-only flags for one process, restoring every inherited value."""
    names = (
        "ADLOG_SEMANTIC_PRODUCTION_ENABLED", "ADLOG_SEMANTIC_RUNTIME_MODE",
        "ADLOG_SEMANTIC_NORMALIZATION_ENABLED", "ADLOG_SEMANTIC_ASSEMBLY_ENABLED",
        "ADLOG_SEMANTIC_DIRECTORY_STATE_ENABLED", "ADLOG_SEMANTIC_CORRELATION_ENABLED",
        "ADLOG_SEMANTIC_RISK_ENGINE_ENABLED", "ADLOG_SEMANTIC_FINDING_CREATION_ENABLED",
    )
    previous = {name: os.environ.get(name) for name in names}
    try:
        os.environ.update({
            "ADLOG_SEMANTIC_PRODUCTION_ENABLED": "1",
            "ADLOG_SEMANTIC_RUNTIME_MODE": FACTS_MODE,
            "ADLOG_SEMANTIC_NORMALIZATION_ENABLED": "1",
            "ADLOG_SEMANTIC_ASSEMBLY_ENABLED": "1",
            "ADLOG_SEMANTIC_DIRECTORY_STATE_ENABLED": "0",
            "ADLOG_SEMANTIC_CORRELATION_ENABLED": "0",
            "ADLOG_SEMANTIC_RISK_ENGINE_ENABLED": "0",
            "ADLOG_SEMANTIC_FINDING_CREATION_ENABLED": "0",
        })
        with ephemeral_worker_environment():
            yield
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _facts_check_execute(
    event_ids: tuple[int, ...], *, publish: bool
) -> dict[str, object]:
    """Publish and consume exact IDs while excluding the managed global worker."""
    with _facts_check_environment():
        with session_advisory_lock(
            connect_semantic_worker,
            PRODUCTION_WORKER_LOCK_NAME,
            prepare=prepare_production_connection,
        ) as acquired:
            if not acquired:
                return {"status": "blocked", "reason": "semantic_production_worker_lock_held"}
            producer: dict[str, object] | None = None
            if publish:
                with _connect_admin() as conn:
                    with conn.transaction(), conn.cursor() as cur:
                        cur.execute("set local role adlog_storage_worker")
                        producer = publish_semantic_candidates(
                            cur, event_ids, include_context=True
                        )
            runtime = run_production_once(
                limit=len(event_ids),
                connect_factory=connect_semantic_worker,
                archive=_archive_reader(),
                source_event_ids=event_ids,
            )
            return {"status": "executed", "producer": producer, "runtime": runtime}


def facts_check(
    event_ids: Sequence[int], *, plan_digest: str, confirmation: str | None,
) -> dict[str, Any]:
    """Manually process one plan-bound exact facts set; no global admission write."""
    exact_ids = _facts_check_ids(event_ids)
    digest = str(plan_digest or "")
    if confirmation != FACTS_CHECK_CONFIRM_PREFIX + digest:
        raise RuntimeError("exact facts check confirmation required")
    _load_environment()
    fingerprint = _facts_rules_fingerprint()
    database_identity = _facts_check_database_identity_and_ids(exact_ids)
    expected_digest = _facts_check_digest(
        event_ids=exact_ids,
        rules_fingerprint=fingerprint,
        database_identity=database_identity,
    )
    if digest != expected_digest:
        raise RuntimeError("exact facts check plan digest mismatch")
    manifest = _read_facts_check_manifest()
    if manifest is None:
        manifest = _new_facts_check_manifest(
            event_ids=exact_ids,
            rules_fingerprint=fingerprint,
            database_identity=database_identity,
            plan_digest=digest,
        )
        _write_facts_check_manifest(manifest)
    else:
        _validate_facts_check_manifest(
            manifest,
            event_ids=exact_ids,
            rules_fingerprint=fingerprint,
            database_identity=database_identity,
            plan_digest=digest,
        )
    if manifest["state"] in {"processed", "no_admitted_events"}:
        queue = _facts_check_queue_status(exact_ids)
        if queue["completed"] + queue["not_enqueued"] == len(exact_ids):
            return {"status": "exact_retained_facts_check_already_processed", **manifest}
    publish = manifest["state"] == "intent"
    execution = _facts_check_execute(exact_ids, publish=publish)
    if execution.get("status") == "blocked":
        manifest["result"] = execution
        manifest["updated_at_utc"] = datetime.now(timezone.utc).isoformat()
        _write_facts_check_manifest(manifest)
        return {"status": "exact_retained_facts_check_blocked", **manifest}
    runtime = dict(execution.get("runtime") or {})
    producer = execution.get("producer")
    if producer is None:
        producer = dict(manifest.get("result") or {}).get("producer")
    queue = _facts_check_queue_status(exact_ids)
    processing = dict(runtime.get("processing") or {})
    if (
        int(processing.get("failed") or 0)
        or queue["failed"]
        or queue.get("quarantined", 0)
        or queue.get("incomplete", 0)
    ):
        state = "partial"
    elif queue["queued"] or queue["leased"]:
        state = "partial"
    elif queue["not_enqueued"] == len(exact_ids) and not int(
        processing.get("completed") or 0
    ):
        state = "no_admitted_events"
    else:
        state = "processed"
    manifest["state"] = state
    manifest["result"] = {"producer": producer, "runtime": runtime, "queue": queue}
    manifest["updated_at_utc"] = datetime.now(timezone.utc).isoformat()
    _write_facts_check_manifest(manifest)
    return {"status": "exact_retained_facts_check_complete", **manifest}


def _is_lower_sha256(value: object) -> bool:
    rendered = str(value or "")
    return len(rendered) == 64 and all(character in "0123456789abcdef" for character in rendered)


def _classify_activation_v2_repair_coverage(
    *, manifest: Mapping[str, Any], pairs: Sequence[tuple[int, str]],
    rows: Sequence[Mapping[str, object]], migration_name: str,
) -> dict[str, int]:
    """Admit only the immutable Main v2 repair incident, never a lookalike."""
    total = APPROVED_SECURITY_HISTORY_V2_QUARANTINE_COHORT_COUNT
    unresolved = total
    if migration_name != "semantic_v2_quarantine_repair":
        return {"total": total, "covered": 0, "unresolved": unresolved}
    try:
        entry = dict(dict(manifest["events"])["4624"])
        if (
            manifest.get("manifest_type") != SECURITY_HISTORY_MANIFEST_TYPE_V2
            or not _is_lower_sha256(manifest.get("plan_digest"))
            or int(entry["count"]) != total
            or int(entry["semantic_expected_count"]) != total
            or not _is_lower_sha256(entry.get("semantic_context_digest"))
            or int(entry["semantic_context_reset_high_watermark"]) <= 0
        ):
            return {"total": total, "covered": 0, "unresolved": unresolved}
        normalized_pairs = [(int(source_id), str(source_hash).casefold()) for source_id, source_hash in pairs]
    except (KeyError, TypeError, ValueError):
        return {"total": total, "covered": 0, "unresolved": unresolved}
    if (
        len(normalized_pairs) != total
        or len({source_id for source_id, _ in normalized_pairs}) != total
        or any(not _is_lower_sha256(source_hash) for _, source_hash in normalized_pairs)
        or security_history_cohort_digest(normalized_pairs) != entry["semantic_context_digest"]
        or len(rows) != total
    ):
        return {"total": total, "covered": 0, "unresolved": unresolved}
    rows_by_source = {int(row.get("source_event_id") or 0): row for row in rows}
    if len(rows_by_source) != total or set(rows_by_source) != {source_id for source_id, _ in normalized_pairs}:
        return {"total": total, "covered": 0, "unresolved": unresolved}
    completed = sum(
        classify_security_history_v2_repair_row(
            rows_by_source[source_id], source_hash=source_hash,
            history_plan_digest=str(manifest["plan_digest"]).casefold(),
            repair_plan_digest=APPROVED_SECURITY_HISTORY_V2_REPAIR_PLAN_DIGEST,
        ) == "completed"
        for source_id, source_hash in normalized_pairs
    )
    return {"total": total, "covered": completed, "unresolved": total - completed}


def _activation_v2_repair_coverage(cur: Any) -> dict[str, int]:
    """Read the immutable Main cohort and classify every selected repair lineage."""
    fail_closed = {
        "total": APPROVED_SECURITY_HISTORY_V2_QUARANTINE_COHORT_COUNT,
        "covered": 0,
        "unresolved": APPROVED_SECURITY_HISTORY_V2_QUARANTINE_COHORT_COUNT,
    }
    try:
        manifest = _read_approved_frozen_security_history_manifest()
        pairs, _context = _security_history_v2_quarantine_snapshot(cur, manifest)
        cur.execute("select name from public.schema_migrations where version=143")
        migration_name = str(dict(cur.fetchone() or {}).get("name") or "")
        cur.execute(
            """
            with selected(source_event_id,source_hash) as (
              select * from unnest(%s::bigint[],%s::text[])
            )
            select selected.source_event_id,selected.source_hash,
              (select count(*) from semantic_processing_outbox job where job.source_event_id=selected.source_event_id and job.job_kind='normalize_event' and job.semantic_contract_version=%s and job.processor_id=%s and job.processor_version=%s) original_job_count,
              (select min(job.job_id::text) from semantic_processing_outbox job where job.source_event_id=selected.source_event_id and job.job_kind='normalize_event' and job.semantic_contract_version=%s and job.processor_id=%s and job.processor_version=%s) original_job_id,
              (select min(job.status) from semantic_processing_outbox job where job.source_event_id=selected.source_event_id and job.job_kind='normalize_event' and job.semantic_contract_version=%s and job.processor_id=%s and job.processor_version=%s) original_status,
              (select min(job.attempt_count) from semantic_processing_outbox job where job.source_event_id=selected.source_event_id and job.job_kind='normalize_event' and job.semantic_contract_version=%s and job.processor_id=%s and job.processor_version=%s) original_attempt_count,
              (select min(job.max_attempts) from semantic_processing_outbox job where job.source_event_id=selected.source_event_id and job.job_kind='normalize_event' and job.semantic_contract_version=%s and job.processor_id=%s and job.processor_version=%s) original_max_attempts,
              (select min(job.last_error_code) from semantic_processing_outbox job where job.source_event_id=selected.source_event_id and job.job_kind='normalize_event' and job.semantic_contract_version=%s and job.processor_id=%s and job.processor_version=%s) original_error_code,
              (select min(job.last_error_detail) from semantic_processing_outbox job where job.source_event_id=selected.source_event_id and job.job_kind='normalize_event' and job.semantic_contract_version=%s and job.processor_id=%s and job.processor_version=%s) original_error_detail,
              (select min(job.source_identity_json->>'normalized_hash') from semantic_processing_outbox job where job.source_event_id=selected.source_event_id and job.job_kind='normalize_event' and job.semantic_contract_version=%s and job.processor_id=%s and job.processor_version=%s) original_source_hash,
              (select count(*) from semantic_processing_outbox job where job.source_event_id=selected.source_event_id and job.job_kind=%s) repair_job_count,
              (select min(job.status) from semantic_processing_outbox job where job.source_event_id=selected.source_event_id and job.job_kind=%s) repair_status,
              (select min(job.processor_id) from semantic_processing_outbox job where job.source_event_id=selected.source_event_id and job.job_kind=%s) repair_processor_id,
              (select min(job.processor_version) from semantic_processing_outbox job where job.source_event_id=selected.source_event_id and job.job_kind=%s) repair_processor_version,
              (select min(job.source_identity_json->>'normalized_hash') from semantic_processing_outbox job where job.source_event_id=selected.source_event_id and job.job_kind=%s) repair_source_hash,
              (select min(job.payload_json->>'original_source_hash') from semantic_processing_outbox job where job.source_event_id=selected.source_event_id and job.job_kind=%s) repair_payload_source_hash,
              (select min(job.semantic_contract_version) from semantic_processing_outbox job where job.source_event_id=selected.source_event_id and job.job_kind=%s) repair_semantic_contract_version,
              (select min(job.payload_json->>'original_job_id') from semantic_processing_outbox job where job.source_event_id=selected.source_event_id and job.job_kind=%s) repair_original_job_id,
              (select min(job.payload_json->>'history_plan_digest') from semantic_processing_outbox job where job.source_event_id=selected.source_event_id and job.job_kind=%s) repair_history_plan_digest,
              (select min(job.payload_json->>'repair_plan_digest') from semantic_processing_outbox job where job.source_event_id=selected.source_event_id and job.job_kind=%s) repair_plan_digest,
              (select min(job.payload_json->>'original_attempt_count') from semantic_processing_outbox job where job.source_event_id=selected.source_event_id and job.job_kind=%s) repair_original_attempt_count,
              (select min(job.payload_json->>'original_max_attempts') from semantic_processing_outbox job where job.source_event_id=selected.source_event_id and job.job_kind=%s) repair_original_max_attempts,
              (select min(job.payload_json->>'original_error_code') from semantic_processing_outbox job where job.source_event_id=selected.source_event_id and job.job_kind=%s) repair_original_error_code,
              (select min(job.payload_json->>'original_error_detail_sha256') from semantic_processing_outbox job where job.source_event_id=selected.source_event_id and job.job_kind=%s) repair_original_error_detail_sha256,
              (select count(*) from normalized_events normalized where normalized.source_event_id=selected.source_event_id and normalized.semantic_contract_version=%s and normalized.normalizer_id=%s and normalized.normalizer_version=%s) normalized_current_count,
              (select count(*) from normalized_events normalized where normalized.source_event_id=selected.source_event_id and normalized.semantic_contract_version=%s and normalized.normalizer_id=%s and normalized.normalizer_version=%s and normalized.processing_status='normalized' and normalized.source_event_sha256=decode(selected.source_hash,'hex') and normalized.semantic_type<>'event.unknown') normalized_proof_count,
              (select min(encode(normalized.source_event_sha256,'hex')) from normalized_events normalized where normalized.source_event_id=selected.source_event_id and normalized.semantic_contract_version=%s and normalized.normalizer_id=%s and normalized.normalizer_version=%s and normalized.processing_status='normalized' and normalized.source_event_sha256=decode(selected.source_hash,'hex') and normalized.semantic_type<>'event.unknown') normalized_proof_hash,
              (select count(distinct evidence.canonical_action_id) from normalized_events normalized join canonical_action_evidence evidence on evidence.normalized_event_id=normalized.normalized_event_id where normalized.source_event_id=selected.source_event_id and normalized.semantic_contract_version=%s and normalized.normalizer_id=%s and normalized.normalizer_version=%s and normalized.processing_status='normalized' and normalized.source_event_sha256=decode(selected.source_hash,'hex') and normalized.semantic_type<>'event.unknown') normalized_action_count
            from selected order by selected.source_event_id
            """,
            ([source_id for source_id, _ in pairs], [source_hash for _, source_hash in pairs],
             *([SEMANTIC_CONTRACT_VERSION, PROCESSOR_ID, PROCESSOR_VERSION] * 8),
             *([SEMANTIC_V2_QUARANTINE_REPAIR_JOB_KIND] * 14),
             *([SEMANTIC_CONTRACT_VERSION, NORMALIZER_ID, NORMALIZER_VERSION] * 4)),
        )
        rows = [dict(row) for row in (cur.fetchall() or [])]
        for row in rows:
            row["original_error_detail_sha256"] = sha256(str(row.get("original_error_detail") or "").encode("utf-8")).hexdigest()
        return _classify_activation_v2_repair_coverage(
            manifest=manifest, pairs=pairs, rows=rows, migration_name=migration_name,
        )
    except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError):
        return fail_closed


def _snapshot(cur: Any) -> dict[str, Any]:
    cur.execute(
        """
        select
          coalesce((select max(version) from schema_migrations),0) as marker,
          (select coalesce(max(id),0) from events_v2_core) as max_event_id,
          (select count(*) from findings) as findings,
          (select count(*) from findings
             where fingerprint like 'semantic:%') as semantic_findings,
          exists(
            select 1 from runtime_worker_heartbeats
            where worker_name='semantic'
              and status not in ('stopped','disabled')
              and heartbeat_at >= now() - (
                greatest(180,expected_interval_seconds*3)
                * interval '1 second'
              )
          ) as semantic_worker_live,
          (select count(*) from semantic_processing_outbox
             where status='quarantined') as processing_quarantined,
          (select count(*) from semantic_correlation_dispatch_jobs
             where dispatch_status='quarantined') as dispatch_quarantined,
          (select count(*) from semantic_risk_evaluation_jobs
             where evaluation_status='quarantined') as risk_quarantined
        """,
    )
    result = dict(cur.fetchone())
    global_processing_quarantined = int(result["processing_quarantined"])
    coverage = _activation_v2_repair_coverage(cur)
    try:
        coverage_total = int(coverage["total"])
        covered = int(coverage["covered"])
        coverage_unresolved = int(coverage["unresolved"])
        coverage_valid = (
            coverage_total == APPROVED_SECURITY_HISTORY_V2_QUARANTINE_COHORT_COUNT
            and 0 <= covered <= coverage_total
            and coverage_unresolved >= coverage_total - covered
        )
    except (KeyError, TypeError, ValueError):
        coverage_total = APPROVED_SECURITY_HISTORY_V2_QUARANTINE_COHORT_COUNT
        covered = 0
        coverage_unresolved = coverage_total
        coverage_valid = False
    if not coverage_valid:
        covered = 0
        coverage_unresolved = max(coverage_unresolved, coverage_total)
    result["processing_quarantined_total"] = global_processing_quarantined
    result["processing_quarantined_coverage_total"] = coverage_total
    result["processing_quarantined_expected_cohort"] = (
        APPROVED_SECURITY_HISTORY_V2_QUARANTINE_COHORT_COUNT
    )
    result["processing_quarantined_covered"] = covered
    result["processing_quarantined_unresolved"] = max(
        global_processing_quarantined - covered,
        coverage_unresolved,
    )
    cur.execute(
        "select to_regclass('semantic_finding_publications') as publication_table"
    )
    if cur.fetchone()["publication_table"] is None:
        result["publications"] = 0
    else:
        cur.execute(
            "select count(*)::bigint as count "
            "from semantic_finding_publications"
        )
        result["publications"] = int(cur.fetchone()["count"])
    cur.execute(
        """
        select policy_id,policy_version,lifecycle_status,
               encode(definition_sha256,'hex') definition_sha256
        from semantic_risk_policies
        where policy_id=any(%s)
        order by policy_id,policy_version
        """,
        ([item[0] for item in POLICIES],),
    )
    result["policies"] = [dict(row) for row in (cur.fetchall() or [])]
    cur.execute(
        """
        with accepted as (
          select distinct scenario.scenario_id,scenario.evidence_count,
                 scenario.contribution_count
          from semantic_security_scenarios scenario
          join semantic_risk_contributions contribution
            on contribution.scenario_id=scenario.scenario_id
          where contribution.policy_id=%s
            and contribution.policy_version=%s
        )
        select
          (select count(*) from semantic_risk_evaluation_jobs
             where policy_id=%s and policy_version=%s
               and evaluation_mode='shadow'
               and evaluation_status='completed') as completed_jobs,
          (select count(*) from semantic_risk_evaluation_jobs
             where policy_id=%s and policy_version=%s
               and evaluation_mode='shadow'
               and evaluation_status<>'completed') as incomplete_jobs,
          count(*) as scenario_count,
          coalesce(sum(evidence_count),0) as evidence_count,
          coalesce(sum(contribution_count),0) as contribution_count,
          coalesce(min(evidence_count),0) as min_scenario_evidence
        from accepted
        """,
        (
            ENABLED_POLICY_ID,
            POLICY_VERSION,
            ENABLED_POLICY_ID,
            POLICY_VERSION,
            ENABLED_POLICY_ID,
            POLICY_VERSION,
        ),
    )
    result["calibration"] = dict(cur.fetchone())
    return result


def _assert_calibration(snapshot: dict[str, Any]) -> None:
    if bool(snapshot["semantic_worker_live"]):
        raise RuntimeError("another semantic worker is live")
    processing_total = int(
        snapshot.get(
            "processing_quarantined_total",
            snapshot.get("processing_quarantined", 0),
        )
    )
    processing_covered = int(snapshot.get("processing_quarantined_covered", 0))
    processing_unresolved = int(snapshot.get(
        "processing_quarantined_unresolved", snapshot.get("processing_quarantined", 0),
    ))
    processing_coverage_total = int(snapshot.get(
        "processing_quarantined_coverage_total",
        APPROVED_SECURITY_HISTORY_V2_QUARANTINE_COHORT_COUNT,
    ))
    processing_expected_cohort = int(snapshot.get(
        "processing_quarantined_expected_cohort",
        APPROVED_SECURITY_HISTORY_V2_QUARANTINE_COHORT_COUNT,
    ))
    if (
        int(snapshot.get("processing_quarantined", processing_total)) != processing_total
        or processing_total < 0
        or processing_covered < 0
        or processing_unresolved < 0
        or processing_covered > processing_total
        or processing_unresolved < processing_total - processing_covered
        or processing_expected_cohort
        != APPROVED_SECURITY_HISTORY_V2_QUARANTINE_COHORT_COUNT
        or processing_coverage_total != processing_expected_cohort
        or processing_unresolved != 0
        or int(snapshot["dispatch_quarantined"]) != 0
        or int(snapshot["risk_quarantined"]) != 0
    ):
        raise RuntimeError("semantic activation refuses quarantined work")
    calibration = snapshot["calibration"]
    completed = int(calibration["completed_jobs"])
    scenarios = int(calibration["scenario_count"])
    evidence = int(calibration["evidence_count"])
    if (
        completed != MAX_AUTHORISED_SHADOW_EVALUATIONS
        or int(calibration["incomplete_jobs"]) != 0
        or not 1 <= scenarios <= 10
        or evidence != completed
        or int(calibration["contribution_count"]) != completed
        or int(calibration["min_scenario_evidence"]) <= 0
        or completed / scenarios < 10
    ):
        raise RuntimeError(
            "production semantic activation lacks accepted SHADOW collapse"
        )
    current = [
        row
        for row in snapshot["policies"]
        if row["policy_id"] == ENABLED_POLICY_ID
        and int(row["policy_version"]) == POLICY_VERSION
    ]
    if len(current) != 1 or current[0]["lifecycle_status"] not in {
        "shadow",
        "enabled",
    }:
        raise RuntimeError("accepted production policy version is unavailable")
    unexpected_enabled = [
        row
        for row in snapshot["policies"]
        if row["lifecycle_status"] == "enabled"
        and (
            row["policy_id"] != ENABLED_POLICY_ID
            or int(row["policy_version"]) != POLICY_VERSION
        )
    ]
    if unexpected_enabled:
        raise RuntimeError("unexpected semantic policy is enabled")


def _assert_deactivation_preconditions(snapshot: dict[str, Any]) -> None:
    if bool(snapshot.get("semantic_worker_live")):
        raise RuntimeError("semantic worker must stop before deactivation")
    enabled = [
        row
        for row in snapshot.get("policies", [])
        if row.get("lifecycle_status") == "enabled"
    ]
    if len(enabled) != 1 or (
        enabled[0].get("policy_id") != ENABLED_POLICY_ID
        or int(enabled[0].get("policy_version") or 0) != POLICY_VERSION
    ):
        raise RuntimeError("semantic deactivation requires exact enabled policy")


def _apply_migration() -> bool:
    with _connect_admin(autocommit=True) as conn, conn.cursor() as cur:
        cur.execute(
            "select name from schema_migrations where version=55"
        )
        row = cur.fetchone()
        if row is not None:
            if str(row["name"]) != "semantic_finding_publication":
                raise RuntimeError("schema marker 55 differs from contract")
            return False
        cur.execute(MIGRATION.read_text(encoding="utf-8"))
    return True


def _feature_environment(worker_dsn: str) -> dict[str, str]:
    return {
        "ADLOG_SEMANTIC_WORKER_DSN": worker_dsn,
        "ADLOG_SEMANTIC_NORMALIZATION_ENABLED": "1",
        "ADLOG_SEMANTIC_ASSEMBLY_ENABLED": "1",
        "ADLOG_SEMANTIC_DIRECTORY_STATE_ENABLED": "0",
        "ADLOG_SEMANTIC_CORRELATION_ENABLED": "1",
        "ADLOG_SEMANTIC_RISK_ENGINE_ENABLED": "1",
        "ADLOG_SEMANTIC_FINDING_CREATION_ENABLED": "1",
    }


def _guard_production_scope(conn: Any) -> SemanticFeatureSettings:
    settings = SemanticFeatureSettings.from_env()
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
                     where lifecycle_status='enabled'
                     order by policy_id,policy_version
                   ) as enabled_policies,
                   exists(
                     select 1 from semantic_risk_policies
                     where lifecycle_status='test'
                   ) as test_policy_exists
            """
        )
        guard = dict(cur.fetchone() or {})
    if not bool(guard.get("schema_ready")):
        raise RuntimeError("semantic production schema marker 55 is required")
    expected = [f"{ENABLED_POLICY_ID}:{POLICY_VERSION}"]
    if list(guard.get("enabled_policies") or []) != expected:
        raise RuntimeError("semantic production enabled policy set differs")
    if bool(guard.get("test_policy_exists")):
        raise RuntimeError("semantic production refuses TEST policy")
    conn.commit()
    return settings


def _archive_reader() -> ArchiveReader:
    load_storage_v2_settings(strict=True)
    return ArchiveReader(
        PostgresArchiveManifestStore(connect_semantic_worker),
    )


def _run_worker_once(*, limit: int) -> dict[str, object]:
    conn = connect_semantic_worker()
    archive = _archive_reader()
    completed = failed = queued = findings_created = 0
    modes = {"test": 0, "shadow": 0, "enabled": 0}
    try:
        settings = _guard_production_scope(conn)
        processing = process_semantic_outbox(
            conn,
            archive=archive,
            settings=settings,
            limit=limit,
        )
        completed += int(processing["completed"])
        failed += int(processing["failed"])
        dispatch = process_semantic_dispatch(
            conn,
            archive=archive,
            settings=settings,
            limit=limit,
        )
        completed += int(dispatch["completed"])
        failed += int(dispatch["failed"])
        with conn.transaction(), conn.cursor() as cur:
            queued = len(enqueue_risk_backlog(cur, limit=limit))
        for _ in range(limit):
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
        "processing": processing,
        "dispatch": dispatch,
        "risk_queued": queued,
        "completed": completed,
        "failed": failed,
        "modes": modes,
        "findings_created": findings_created,
    }


def _run_ephemeral(*, limit: int) -> dict[str, object]:
    names = tuple(_feature_environment("").keys())
    previous = {name: os.environ.get(name) for name in names}
    role = ""
    try:
        with _connect_admin(autocommit=True) as conn, conn.cursor() as cur:
            role, password = _create_ephemeral_login(cur)
        os.environ.update(
            _feature_environment(_worker_dsn(role=role, password=password))
        )
        result = _run_worker_once(limit=limit)
        from server.sli.ops.runtime_workers import record_worker_heartbeat

        record_worker_heartbeat(
            worker_name="semantic",
            worker_id=f"semantic-production-manual-{os.getpid()}",
            status="stopped",
            phase="manual_production_poll_complete",
            expected_interval_seconds=180,
            started_at=datetime.now(timezone.utc),
            details={
                "last_result": result,
                "allowed_modes": ["shadow", "enabled"],
                "finding_creation": True,
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


def _write_state(payload: dict[str, Any]) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = STATE_PATH.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )
    os.replace(temporary, STATE_PATH)


def plan() -> dict[str, Any]:
    _load_environment()
    with _connect_admin() as conn, conn.cursor() as cur:
        cur.execute("set transaction read only")
        snapshot = _snapshot(cur)
    _assert_calibration(snapshot)
    return {
        "status": "ready_for_manual_activation",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "snapshot": snapshot,
        "enabled_policy_candidate": (
            f"{ENABLED_POLICY_ID}:{POLICY_VERSION}"
        ),
        "continuous_worker_started": False,
        "production_changed": False,
        "surveyed_servers_contacted": False,
    }


def _set_production_policy_status(cur: Any, *, enabled: bool) -> None:
    """Keep the explicit owner action and the publication admission atomic."""
    cur.execute("set local role adlog_storage_worker")
    transition_risk_policy(
        cur,
        policy_id=ENABLED_POLICY_ID,
        policy_version=POLICY_VERSION,
        target_status="enabled" if enabled else "disabled",
    )
    # The lifecycle writer cannot edit admissions. Use the existing admission
    # writer role; its trigger records the change in semantic_control_audit.
    cur.execute("set local role adlog_user")
    cur.execute(
        """insert into semantic_policy_admission(policy_id,policy_version,enabled,updated_by)
           values (%s,%s,%s,'semantic-production-control')
           on conflict(policy_id,policy_version) do update
           set enabled=excluded.enabled,updated_by=excluded.updated_by,updated_at=now()""",
        (ENABLED_POLICY_ID, POLICY_VERSION, enabled),
    )


def activate() -> dict[str, Any]:
    _load_environment()
    with _connect_admin() as conn, conn.cursor() as cur:
        before = _snapshot(cur)
    _assert_calibration(before)
    migration_applied = _apply_migration()
    with _connect_admin() as conn:
        with conn.transaction(), conn.cursor() as cur:
            _set_production_policy_status(cur, enabled=True)
    with _connect_admin() as conn, conn.cursor() as cur:
        after = _snapshot(cur)
    _assert_calibration(after)
    enabled = [
        row
        for row in after["policies"]
        if row["lifecycle_status"] == "enabled"
    ]
    if len(enabled) != 1:
        raise RuntimeError("semantic production activation is not exact")
    if int(after["findings"]) != int(before["findings"]):
        raise RuntimeError("activation changed findings before worker poll")
    state = {
        "package_type": "STAGE8_PRODUCTION_SEMANTIC_FINDINGS",
        "status": "active_manual",
        "activated_at_utc": datetime.now(timezone.utc).isoformat(),
        "watermark_event_id": int(after["max_event_id"]),
        "enabled_policy_id": ENABLED_POLICY_ID,
        "enabled_policy_version": POLICY_VERSION,
        "findings_baseline": int(after["findings"]),
        "manual_runtime": True,
        "continuous_worker_started": False,
        "polls": [],
        "last_snapshot": after,
    }
    _write_state(state)
    return {
        "status": "activated_manual",
        "migration_55_applied": migration_applied,
        "state_path": str(STATE_PATH),
        "enabled_policy": f"{ENABLED_POLICY_ID}:{POLICY_VERSION}",
        "findings_unchanged": True,
        "continuous_worker_started": False,
        "surveyed_servers_contacted": False,
    }


def deactivate() -> dict[str, Any]:
    _load_environment()
    with _connect_admin() as conn, conn.cursor() as cur:
        before = _snapshot(cur)
    _assert_deactivation_preconditions(before)
    with _connect_admin() as conn:
        with conn.transaction(), conn.cursor() as cur:
            _set_production_policy_status(cur, enabled=False)
    with _connect_admin() as conn, conn.cursor() as cur:
        after = _snapshot(cur)
    if any(
        row["lifecycle_status"] == "enabled"
        for row in after["policies"]
    ):
        raise RuntimeError("semantic production policy remains enabled")
    state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    state["status"] = "disabled"
    state["deactivated_at_utc"] = datetime.now(timezone.utc).isoformat()
    state["continuous_worker_started"] = False
    state["last_snapshot"] = after
    _write_state(state)
    return {
        "status": "deactivated",
        "state_path": str(STATE_PATH),
        "disabled_policy": f"{ENABLED_POLICY_ID}:{POLICY_VERSION}",
        "findings_preserved": int(after["findings"]),
        "continuous_worker_started": False,
        "surveyed_servers_contacted": False,
    }


def request_stop() -> dict[str, Any]:
    _load_environment()
    requested_at = datetime.now(timezone.utc)
    payload = {
        "requested_at_utc": requested_at.isoformat(),
        "reason": "operator_requested_semantic_production_stop",
    }
    STOP_REQUEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = STOP_REQUEST_PATH.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    os.replace(temporary, STOP_REQUEST_PATH)
    deadline = time.monotonic() + 60
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        with _connect_admin() as conn, conn.cursor() as cur:
            cur.execute(
                """
                select status,phase,heartbeat_at
                from runtime_worker_heartbeats where worker_name='semantic'
                """
            )
            last = dict(cur.fetchone() or {})
        if not last or last.get("status") == "stopped":
            return {
                "status": "stopped",
                "requested_at_utc": requested_at.isoformat(),
                "heartbeat": last,
                "policy_changed": False,
                "findings_changed": False,
            }
        time.sleep(2)
    raise RuntimeError("semantic production worker did not stop within 60 seconds")


def poll(*, limit: int) -> dict[str, Any]:
    _load_environment()
    state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    if state.get("status") != "active_manual":
        raise RuntimeError("semantic production state is not active_manual")
    watermark = int(state["watermark_event_id"])
    with _connect_admin() as conn, conn.cursor() as cur:
        before = _snapshot(cur)
        _assert_calibration(before)
        cur.execute(
            """
            select core.id
            from events_v2_core core
            join storage_v2_channel channel on channel.id=core.channel_id
            left join storage_v2_provider provider on provider.id=core.provider_id
            where core.id>%s and (
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
            (watermark, 5000),
        )
        target_ids = [int(row["id"]) for row in (cur.fetchall() or [])]
        upper_bound = int(before["max_event_id"])
    with _connect_admin() as conn:
        with conn.transaction(), conn.cursor() as cur:
            cur.execute("set local role adlog_storage_worker")
            published = publish_semantic_candidates(cur, target_ids)
    worker = _run_ephemeral(limit=max(1, min(int(limit), MAX_LIMIT)))
    with _connect_admin() as conn, conn.cursor() as cur:
        after = _snapshot(cur)
    if int(after["semantic_findings"]) != int(after["publications"]):
        raise RuntimeError("semantic findings lack exact publication links")
    if int(worker["findings_created"]) > MAX_LIMIT:
        raise RuntimeError("semantic production finding bound was exceeded")
    next_watermark = (
        target_ids[-1]
        if target_ids and len(target_ids) == 5000
        else upper_bound
    )
    item = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "from_event_id_exclusive": watermark,
        "to_event_id_inclusive": next_watermark,
        "target_new_events": len(target_ids),
        "producer": published,
        "worker": worker,
        "snapshot": after,
    }
    state["watermark_event_id"] = next_watermark
    state["polls"] = [*(state.get("polls") or []), item][-100:]
    state["last_snapshot"] = after
    _write_state(state)
    return {
        "status": "manual_poll_complete",
        "state_path": str(STATE_PATH),
        **item,
        "continuous_worker_started": False,
        "surveyed_servers_contacted": False,
    }


def main() -> int:
    global SECURITY_HISTORY_MANIFEST_PATH
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=(
            "plan",
            "activate",
            "poll",
            "stop",
            "deactivate",
            "facts-plan",
            "facts-poll",
            "facts-check-plan",
            "facts-check",
            "security-history-plan",
            "security-history-poll",
            "security-history-check-plan",
            "security-history-check",
            "security-history-repair-plan",
            "security-history-repair",
            "security-history-v2-quarantine-repair-plan",
            "security-history-v2-quarantine-repair",
            "security-history-supersede-plan",
            "security-history-supersede",
        ),
    )
    parser.add_argument("--confirm")
    parser.add_argument("--limit", type=int, default=MAX_LIMIT)
    parser.add_argument("--event-id", type=int, action="append", default=[])
    parser.add_argument("--plan-digest", default="")
    parser.add_argument(
        "--environment-file",
        help="Existing CurrentUser-DPAPI supervisor profile for an isolated worktree.",
    )
    parser.add_argument(
        "--frozen-security-history-manifest",
        help="Exact existing Main frozen history manifest for the v2 quarantine repair only.",
    )
    args = parser.parse_args()
    original_security_history_manifest_path: Path | None = None
    try:
        if args.frozen_security_history_manifest:
            if args.action not in SECURITY_HISTORY_V2_FROZEN_MANIFEST_ACTIONS:
                raise RuntimeError(
                    "frozen_security_history_manifest_requires_v2_quarantine_repair"
                )
            original_security_history_manifest_path = SECURITY_HISTORY_MANIFEST_PATH
            SECURITY_HISTORY_MANIFEST_PATH = _require_exact_main_frozen_security_history_manifest(
                args.frozen_security_history_manifest,
            )
        if args.environment_file:
            load_supervisor_environment(
                path=Path(args.environment_file).expanduser().resolve(),
                override_existing=True,
            )
        if args.action == "plan":
            payload = plan()
        elif args.action == "facts-plan":
            payload = facts_plan()
        elif args.action == "facts-poll":
            if args.confirm != FACTS_POLL_CONFIRM:
                raise RuntimeError("exact retained facts poll confirmation required")
            payload = facts_poll()
        elif args.action == "facts-check-plan":
            payload = facts_check_plan(args.event_id)
        elif args.action == "facts-check":
            payload = facts_check(
                args.event_id,
                plan_digest=args.plan_digest,
                confirmation=args.confirm,
            )
        elif args.action == "security-history-plan":
            payload = security_history_plan()
        elif args.action == "security-history-poll":
            payload = security_history_poll(confirmation=str(args.confirm or ""))
        elif args.action == "security-history-check-plan":
            payload = security_history_check_plan()
        elif args.action == "security-history-check":
            payload = security_history_check(
                plan_digest=args.plan_digest,
                confirmation=str(args.confirm or ""),
            )
        elif args.action == "security-history-repair-plan":
            payload = security_history_repair_plan()
        elif args.action == "security-history-repair":
            payload = security_history_repair(
                plan_digest=args.plan_digest,
                confirmation=str(args.confirm or ""),
            )
        elif args.action == "security-history-v2-quarantine-repair-plan":
            payload = security_history_v2_quarantine_repair_plan()
        elif args.action == "security-history-v2-quarantine-repair":
            payload = security_history_v2_quarantine_repair(
                plan_digest=args.plan_digest,
                confirmation=str(args.confirm or ""),
            )
        elif args.action == "security-history-supersede-plan":
            payload = security_history_supersede_plan()
        elif args.action == "security-history-supersede":
            payload = security_history_supersede(
                plan_digest=args.plan_digest,
                confirmation=str(args.confirm or ""),
            )
        elif args.action == "activate":
            if args.confirm != ACTIVATE_CONFIRM:
                raise RuntimeError("exact production activation confirmation required")
            payload = activate()
        elif args.action == "poll":
            if args.confirm != POLL_CONFIRM:
                raise RuntimeError("exact production poll confirmation required")
            payload = poll(limit=args.limit)
        elif args.action == "stop":
            if args.confirm != STOP_CONFIRM:
                raise RuntimeError("exact production stop confirmation required")
            payload = request_stop()
        else:
            if args.confirm != DEACTIVATE_CONFIRM:
                raise RuntimeError("exact production deactivation confirmation required")
            payload = deactivate()
        print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
        return 0
    except Exception as exc:
        exact_check = str(getattr(args, "action", "")).startswith("facts-check")
        print(
            json.dumps(
                {
                    "status": "blocked",
                    "error_type": type(exc).__name__,
                    "error": "exact_facts_check_failed" if exact_check else str(exc),
                },
                ensure_ascii=False,
            )
        )
        return 1
    finally:
        if original_security_history_manifest_path is not None:
            SECURITY_HISTORY_MANIFEST_PATH = original_security_history_manifest_path


if __name__ == "__main__":
    raise SystemExit(main())

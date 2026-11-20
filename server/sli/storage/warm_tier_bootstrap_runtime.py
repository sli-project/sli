#!/usr/bin/env python3
"""One bounded, sealed bootstrap for an absent or genuinely empty warm tier.

This module is deliberately separate from the ordinary incremental planner: it
creates the first v2 cursor only after an empty-target preflight and delegates
publication unchanged to ``warm_tier_incremental_copy_runtime``.  It never
starts workers, changes routing, plans retention, deletes source data, or uses
the retired whole-corpus copy manifest workflow.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from server.sli.storage.storage_lifecycle_io import (
    CONTAINER,
    DATABASE,
    _connect,
    _container_port,
    _http_query,
)
from server.sli.storage.storage_lifecycle_bounded_io import read_json
from server.sli.ops.postgres_session_lock import session_advisory_lock
from server.sli.storage import warm_tier_incremental_copy_runtime as copy_runtime
from server.sli.storage import warm_tier_incremental_plan_runtime as planner


ROOT = Path(__file__).resolve().parents[3]
EVIDENCE_ROOT = ROOT / "artifacts" / "stage7" / "evidence"
DEFAULT_PLAN = EVIDENCE_ROOT / "warm-tier-bootstrap-plan.json"
MAX_BATCH_ROWS = planner.MAX_BATCH_LIMIT
CREATE_BASE_PLACEMENT = f"""
CREATE TABLE IF NOT EXISTS {DATABASE}.event_placement
(
 event_id UInt64,session_uid Nullable(FixedString(16)),
 placement LowCardinality(String),archived_payload_path String,
 archived_payload_line UInt32,normalized_hash FixedString(32)
) ENGINE=MergeTree ORDER BY event_id
"""
CREATE_BASE_SESSIONS = f"""
CREATE TABLE IF NOT EXISTS {DATABASE}.sessions
(
 session_uid FixedString(16),logon_source_id Nullable(UInt64),
 logoff_source_id Nullable(UInt64),server_id UInt16,domain_id UInt16,
 channel_id UInt16,logon_time_utc DateTime64(6,'UTC'),
 logoff_time_utc Nullable(DateTime64(6,'UTC')),duration_s Nullable(UInt32),
 state Enum8('closed'=1,'open'=2,'orphan_logoff'=3),logon_id String
) ENGINE=MergeTree ORDER BY (session_uid)
"""
_OWNED_DATA_TABLES = frozenset({
    "event_placement",
    "sessions",
    "incremental_copy_manifest",
    "session_lifecycle_revisions",
    "event_session_placement_revisions",
    "authentication_session_derived_outputs",
})
_OWNED_VIEWS = frozenset({
    "sessions_effective_v1",
    "event_placement_effective_v1",
    "session_lifecycle_conflicts_v1",
})
_ALLOWED_TABLES = _OWNED_DATA_TABLES | _OWNED_VIEWS
_EXACT_BATCH_SESSION_TABLES = frozenset({
    "session_lifecycle_revisions", "event_session_placement_revisions",
})
STORAGE_LIFECYCLE_LOCK_NAME = "ad_log_reports_runtime_storage_lifecycle_process"
_READONLY_SETTINGS = {
    "readonly": "1", "max_execution_time": "30",
    "max_memory_usage": "536870912", "max_threads": "2",
}
_OWNED_TABLE_CONTRACTS = {
    "event_placement": {"event_id": "UInt64", "session_uid": "Nullable(FixedString(16))", "placement": "LowCardinality(String)", "archived_payload_path": "String", "archived_payload_line": "UInt32", "normalized_hash": "FixedString(32)"},
    "sessions": {"session_uid": "FixedString(16)", "logon_source_id": "Nullable(UInt64)", "logoff_source_id": "Nullable(UInt64)", "server_id": "UInt16", "domain_id": "UInt16", "channel_id": "UInt16", "logon_time_utc": "DateTime64(6,'UTC')", "logoff_time_utc": "Nullable(DateTime64(6,'UTC'))", "duration_s": "Nullable(UInt32)", "state": "Enum8('closed'=1,'open'=2,'orphan_logoff'=3)", "logon_id": "String"},
    "incremental_copy_manifest": {"batch_identity": "FixedString(64)", "plan_generated_at_utc": "DateTime64(6,'UTC')", "planned_rows": "UInt32", "first_event_id": "UInt64", "last_event_id": "UInt64", "archive_identity_sha256": "FixedString(64)", "selection_mode": "LowCardinality(String)", "selection_lower_utc": "Nullable(DateTime64(6,'UTC'))", "selection_upper_utc": "Nullable(DateTime64(6,'UTC'))", "published_at_utc": "DateTime64(6,'UTC')"},
    "session_lifecycle_revisions": {"session_uid": "FixedString(16)", "revision": "UInt32", "state": "Enum8('closed'=1,'open'=2,'orphan_logoff'=3)", "server_id": "UInt16", "domain_id": "UInt16", "channel_id": "UInt16", "logon_time_utc": "Nullable(DateTime64(6,'UTC'))", "logoff_time_utc": "Nullable(DateTime64(6,'UTC'))", "duration_s": "Nullable(UInt32)", "logon_id": "String", "logon_source_id": "Nullable(UInt64)", "logoff_source_id": "Nullable(UInt64)", "previous_revision_sha256": "Nullable(FixedString(64))", "revision_sha256": "FixedString(64)", "batch_identity": "FixedString(64)", "published_at_utc": "DateTime64(6,'UTC')"},
    "event_session_placement_revisions": {"event_id": "UInt64", "revision": "UInt32", "session_uid": "FixedString(16)", "placement": "LowCardinality(String)", "lifecycle_revision_sha256": "FixedString(64)", "batch_identity": "FixedString(64)", "published_at_utc": "DateTime64(6,'UTC')"},
    "authentication_session_derived_outputs": {"output_identity": "FixedString(64)", "batch_identity": "FixedString(64)", "candidate_identity_sha256": "FixedString(64)", "policy_fingerprint": "FixedString(64)", "derived_output_digest": "FixedString(64)", "source_reference_digest": "FixedString(64)", "manifest_digest": "FixedString(64)", "continuity_declaration_scope_identity": "String", "continuity_declaration_sha256": "FixedString(64)", "source_count": "UInt32", "observation_count": "UInt32", "payload_json": "String", "published_at_utc": "DateTime64(6,'UTC')"},
}


def _canonical_type(value: Any) -> str:
    return "".join(str(value or "").split())


def _owned_view_contracts() -> dict[str, str]:
    contracts: dict[str, str] = {}
    for statement in copy_runtime.SESSION_SCHEMA.read_text(encoding="utf-8").split(";"):
        for name in _OWNED_VIEWS:
            match = re.fullmatch(
                rf"\s*CREATE\s+VIEW\s+IF\s+NOT\s+EXISTS\s+"
                rf"sli_warm\.{re.escape(name)}\s+AS\s+(.*)\s*",
                statement,
                flags=re.IGNORECASE | re.DOTALL,
            )
            if match:
                contracts[name] = match.group(1)
    if set(contracts) != _OWNED_VIEWS:
        raise RuntimeError("warm_bootstrap_owned_view_contract_missing")
    return contracts


def _canonical_query(port: int, query: str) -> str:
    escaped = str(query).replace("'", "''")
    rows = _json_rows(
        port, f"SELECT formatQuery('{escaped}') AS canonical_query",
    )
    return str((rows[0] if rows else {}).get("canonical_query") or "")


def _validate_owned_schema(port: int, tables: list[dict[str, Any]]) -> None:
    """Fail closed on known-name objects that are not our canonical schema."""
    by_name = {str(row.get("name") or ""): row for row in tables}
    view_contracts = _owned_view_contracts()
    for name in _OWNED_VIEWS:
        if name in by_name:
            if (
                str(by_name[name].get("engine") or "") != "View"
                or _canonical_query(port, by_name[name].get("as_select"))
                != _canonical_query(port, view_contracts[name])
            ):
                raise RuntimeError("warm_bootstrap_target_schema_invalid")
    data_names = sorted(set(by_name).intersection(_OWNED_DATA_TABLES))
    for name in data_names:
        if str(by_name[name].get("engine") or "") != "MergeTree":
            raise RuntimeError("warm_bootstrap_target_schema_invalid")
    if not data_names:
        return
    wanted = ",".join(f"'{name}'" for name in data_names)
    columns = _json_rows(port, "SELECT table,name,type FROM system.columns " f"WHERE database='{DATABASE}' AND table IN ({wanted}) ORDER BY table,position")
    actual: dict[str, dict[str, str]] = {name: {} for name in data_names}
    for column in columns:
        table = str(column.get("table") or "")
        if table in actual:
            actual[table][str(column.get("name") or "")] = _canonical_type(column.get("type"))
    for name in data_names:
        expected = {column: _canonical_type(type_name) for column, type_name in _OWNED_TABLE_CONTRACTS[name].items()}
        if actual[name] != expected:
            raise RuntimeError("warm_bootstrap_target_schema_invalid")


def _canonical_plan_bytes(plan: dict[str, Any]) -> bytes:
    """Canonical, secret-free bytes excluding the self-referential digest."""
    payload = json.loads(json.dumps(plan, default=str))
    bootstrap = payload.get("bootstrap")
    if isinstance(bootstrap, dict):
        bootstrap.pop("plan_digest", None)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def plan_digest(plan: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_plan_bytes(plan)).hexdigest()


def _json_rows(port: int, query: str) -> list[dict[str, Any]]:
    payload = json.loads(_http_query(port, query + " FORMAT JSON", timeout=45, params=_READONLY_SETTINGS).decode("utf-8"))
    return [dict(row) for row in payload.get("data") or []]


def preflight_target(port: int) -> dict[str, Any]:
    """Read-only, fail-closed inventory of the bootstrap-owned target.

    An existing database is accepted only if it contains no foreign tables and
    every permitted table has zero rows.  Thus a torn empty schema can be
    initialized/recovered, but occupied, partial, or foreign targets cannot be
    repurposed by this workflow.
    """
    database_rows = _json_rows(
        port, "SELECT count() AS rows FROM system.databases "
        f"WHERE name='{DATABASE}'",
    )
    database_exists = bool(int((database_rows[0] if database_rows else {}).get("rows") or 0))
    if not database_exists:
        return {
            "status": "empty", "database_exists": False, "tables": [],
            "schema_fingerprint": None, "manifest_rows": 0,
        }
    tables = _json_rows(
        port, "SELECT name,engine,create_table_query,as_select FROM system.tables "
        f"WHERE database='{DATABASE}' ORDER BY name",
    )
    names = {str(row.get("name") or "") for row in tables}
    foreign = sorted(names.difference(_ALLOWED_TABLES))
    if foreign:
        raise RuntimeError("warm_bootstrap_target_foreign_tables")
    _validate_owned_schema(port, tables)
    table_rows: list[dict[str, Any]] = []
    for name in sorted(names.intersection(_OWNED_DATA_TABLES)):
        count = _json_rows(port, f"SELECT count() AS rows FROM {DATABASE}.{name}")
        rows = int((count[0] if count else {}).get("rows") or 0)
        table_rows.append({"name": name, "rows": rows})
        if rows:
            raise RuntimeError("warm_bootstrap_target_occupied")
    canonical_schema = json.dumps(tables, sort_keys=True, separators=(",", ":"), default=str)
    return {
        "status": "empty", "database_exists": True, "tables": table_rows,
        "schema_fingerprint": hashlib.sha256(canonical_schema.encode("utf-8")).hexdigest(),
        "manifest_rows": next((item["rows"] for item in table_rows if item["name"] == "incremental_copy_manifest"), 0),
    }


def initialize_empty_target(port: int) -> None:
    """The only bootstrap DDL: base tables plus the existing v2 manifest."""
    _http_query(port, f"CREATE DATABASE IF NOT EXISTS {DATABASE}")
    _http_query(port, CREATE_BASE_PLACEMENT)
    _http_query(port, CREATE_BASE_SESSIONS)
    copy_runtime._ensure_incremental_manifest_schema(port)


def _preflight_exact_recovery_target(port: int, frozen: dict[str, Any]) -> dict[str, Any]:
    """Allow only the publisher's exact manifest-last recovery boundary.

    Existing copy-runtime session rows are admissible only when every row has
    this sealed batch identity.  Derived-only output and staging databases are
    never part of the ordinary bootstrap anchor and therefore fail closed.
    """
    tables = _json_rows(
        port, "SELECT name,engine,create_table_query,as_select FROM system.tables "
        f"WHERE database='{DATABASE}' ORDER BY name",
    )
    names = {str(row.get("name") or "") for row in tables}
    if names.difference(_ALLOWED_TABLES):
        raise RuntimeError("warm_bootstrap_target_foreign_tables")
    _validate_owned_schema(port, tables)
    staging = _json_rows(
        port, "SELECT name FROM system.databases WHERE "
        "startsWith(name, 'sli_warm_incremental_') OR "
        "startsWith(name, 'sli_warm_derived_') ORDER BY name",
    )
    if staging:
        raise RuntimeError("warm_bootstrap_staging_residue")
    if "event_placement" not in names:
        raise RuntimeError("warm_bootstrap_target_occupied")
    if "sessions" in names:
        sessions = _json_rows(port, f"SELECT count() AS rows FROM {DATABASE}.sessions")
        if int((sessions[0] if sessions else {}).get("rows") or 0):
            raise RuntimeError("warm_bootstrap_target_foreign_session_rows")
    ids_csv = ",".join(str(int(value)) for value in frozen["event_ids"])
    placement = _json_rows(
        port,
        "SELECT count() AS total_rows,"
        f"countIf(event_id IN ({ids_csv})) AS matching_rows FROM {DATABASE}.event_placement",
    )
    placement_row = placement[0] if placement else {}
    total_rows = int(placement_row.get("total_rows") or 0)
    matching_rows = int(placement_row.get("matching_rows") or 0)
    if total_rows != int(frozen["rows"]) or matching_rows != int(frozen["rows"]):
        raise RuntimeError("warm_bootstrap_target_occupied")
    identity = str(frozen["identity_sha256"])
    if "incremental_copy_manifest" in names:
        manifests = _json_rows(
            port, "SELECT count() AS total_rows,"
            f"countIf(batch_identity='{identity}') AS matching_rows "
            f"FROM {DATABASE}.incremental_copy_manifest",
        )
        manifest_row = manifests[0] if manifests else {}
        total_manifests = int(manifest_row.get("total_rows") or 0)
        matching_manifests = int(manifest_row.get("matching_rows") or 0)
        if total_manifests not in {0, 1} or total_manifests != matching_manifests:
            raise RuntimeError("warm_bootstrap_target_foreign_manifest")
    for name in sorted(names.intersection(_EXACT_BATCH_SESSION_TABLES)):
        rows = _json_rows(
            port, "SELECT count() AS total_rows,"
            f"countIf(batch_identity='{identity}') AS matching_rows "
            f"FROM {DATABASE}.{name}",
        )
        row = rows[0] if rows else {}
        if int(row.get("total_rows") or 0) != int(row.get("matching_rows") or 0):
            raise RuntimeError("warm_bootstrap_target_foreign_session_batch")
    if "authentication_session_derived_outputs" in names:
        rows = _json_rows(
            port, f"SELECT count() AS total_rows FROM {DATABASE}.authentication_session_derived_outputs",
        )
        if int((rows[0] if rows else {}).get("total_rows") or 0):
            raise RuntimeError("warm_bootstrap_target_foreign_derived_output")
    return {"status": "exact_recovery", "placement_rows": total_rows}


def _bootstrap_assessment(
    policy: Any, *, planned_rows: int, eligible_rows: int,
    archive_missing: int, scan: dict[str, Any], batch_limit: int,
) -> tuple[str, list[str]]:
    blockers: list[str] = []
    if policy.db_retention_days != 7:
        blockers.append("hot_window_is_not_owner_approved_7_days")
    if policy.warm_retention_days != 365:
        blockers.append("warm_window_is_not_owner_approved_365_days")
    if policy.archive_auto_delete_enabled:
        blockers.append("archive_auto_delete_must_remain_disabled")
    if not scan["candidate_scan_complete"] and planned_rows < batch_limit:
        blockers.append("candidate_scan_limit_exceeded_before_exact_result")
    if planned_rows > eligible_rows:
        blockers.append("planned_batch_exceeds_candidate_rows")
    if archive_missing:
        blockers.append("planned_rows_missing_published_archive_coverage")
    if blockers:
        return "blocked", blockers
    if not planned_rows:
        return "waiting_for_data_accumulation", blockers
    return "ready_for_manual_bounded_copy", blockers


def build_bootstrap_plan(
    batch_limit: int = planner.DEFAULT_BATCH_LIMIT,
    scan_limit: int = planner.DEFAULT_SCAN_LIMIT,
    *, port: int | None = None,
    declaration_after_id: int = 0,
    processed_declaration_ids: set[int] | None = None,
) -> dict[str, Any]:
    """Freeze the first normal incremental v2 plan from an empty baseline."""
    if batch_limit < 1 or batch_limit > MAX_BATCH_ROWS:
        raise ValueError(f"batch_limit must be between 1 and {MAX_BATCH_ROWS}")
    if scan_limit < batch_limit or scan_limit > planner.MAX_SCAN_LIMIT:
        raise ValueError(f"scan_limit must be between batch_limit and {planner.MAX_SCAN_LIMIT}")
    if port is None:
        port = _container_port(CONTAINER)
    target_preflight = preflight_target(port)
    policy = planner.load_storage_policy()
    with _connect() as conn:
        conn.execute("begin transaction isolation level repeatable read read only")
        with conn.cursor() as cur:
            cur.execute("select now() as checked_at_utc")
            checked_at = cur.fetchone()["checked_at_utc"]
        hot_cutoff = checked_at - timedelta(days=policy.db_retention_days)
        warm_cutoff = checked_at - timedelta(days=policy.warm_retention_days)
        source = planner._source_summary(
            conn, warm_max_event_id=0, selection_lower_utc=warm_cutoff,
            hot_cutoff_utc=hot_cutoff, warm_cutoff_utc=warm_cutoff,
        )
        planned, scan = planner._scan_missing(
            conn, warm_max_event_id=0, selection_lower_utc=warm_cutoff,
            hot_cutoff_utc=hot_cutoff, warm_cutoff_utc=warm_cutoff,
            batch_limit=batch_limit, scan_limit=scan_limit, port=port,
            present_id_resolver=lambda _event_ids, _port: set(),
        )
        # Bootstrap establishes the first ordinary archive-backed v2 anchor.
        # Derived-only durable descriptors wait for ordinary incremental work
        # after the anchor exists.
        planned.sort(key=lambda row: int(row["id"]))
        scan["candidate_scan_complete"] = bool(scan["candidate_scan_complete"] or int(scan["scanned_rows"]) >= int(source.get("eligible_rows") or 0))
        scan["scan_limit_reached"] = bool(scan["scan_limit_reached"] and not scan["candidate_scan_complete"])
        coverage = planner._archive_coverage(conn, [int(row["id"]) for row in planned])
    status, blockers = _bootstrap_assessment(
        policy, planned_rows=len(planned), eligible_rows=int(source.get("eligible_rows") or 0),
        archive_missing=int(coverage["missing"]), scan=scan, batch_limit=batch_limit,
    )
    selection_lower = planner._effective_selection_lower(warm_cutoff, planned)
    result: dict[str, Any] = {
        "package_type": "WARM_TIER_INCREMENTAL_PLAN", "contract_version": 2,
        "status": status, "mode": "read_only_plan", "technical_gate_passed": not blockers,
        "blockers": blockers,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "policy": {"hot_days": policy.db_retention_days, "warm_days": policy.warm_retention_days, "archive_auto_delete_enabled": policy.archive_auto_delete_enabled},
        "measurements": {"warm_max_event_id": 0, "warm_rows": 0, "warm_available": True, "source_rows": int(source.get("source_rows") or 0), "source_max_event_id": int(source.get("source_max_event_id") or 0), "appended_rows": int(source.get("appended_rows") or 0), "eligible_rows": int(source.get("eligible_rows") or 0), "planned_rows": len(planned), "archive_missing": int(coverage["missing"]), "candidate_scan_complete": bool(scan["candidate_scan_complete"])},
        "warm": {"available": True, "rows": 0, "max_event_id": 0, "latest_v2_selection_upper_utc": None, "bootstrap_empty": True},
        "source": source,
        "selection": {"mode": planner.SELECTION_MODE, "legacy_mode_retired": planner.LEGACY_SELECTION_MODE, "anchor_kind": "bootstrap_warm_cutoff", "lower_utc": selection_lower, "eligibility_upper_utc": hot_cutoff, "checkpoint_upper_utc": scan["checkpoint_upper_utc"], "warm_cutoff_utc": warm_cutoff, "source_order": "time_created_utc,event_id", "exact_set_difference": True, "scan_limit": scan_limit, **scan},
        "planned_batch": {"limit": batch_limit, "rows": len(planned), "event_ids": [int(row["id"]) for row in planned], "first_event_id": int(planned[0]["id"]) if planned else None, "last_event_id": int(planned[-1]["id"]) if planned else None, "first_event_utc": min((row["time_created_utc"] for row in planned), default=None), "last_event_utc": max((row["time_created_utc"] for row in planned), default=None), "identity_sha256": planner._batch_identity(planned), "archive_coverage": coverage},
        "manual_action": {"required": bool(planned) and not blockers, "authorized_by_this_plan": False, "copy_performed": False, "routing_changed": False, "delete_performed": False},
        "safety": {"postgres_repeatable_read_only": True, "clickhouse_read_only": True, "working_data_changed": False, "workers_started": False, "production_routing_changed": False, "delete_performed": False},
        "bootstrap": {"contract": "sli.warm-tier-bootstrap.v1", "bounded_max_rows": MAX_BATCH_ROWS, "target_preflight": target_preflight, "plan_digest": ""},
    }
    result["bootstrap"]["plan_digest"] = plan_digest(result)
    return json.loads(json.dumps(result, default=str))


def plan_and_record(*, output_path: Path = DEFAULT_PLAN, **kwargs: Any) -> dict[str, Any]:
    output_path = output_path.resolve()
    if output_path.parent != EVIDENCE_ROOT.resolve():
        raise ValueError(f"output must be directly inside {EVIDENCE_ROOT}")
    result = build_bootstrap_plan(**kwargs)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return result


def _read_and_verify_bootstrap_plan(plan_path: Path) -> dict[str, Any]:
    plan = read_json(
        plan_path, max_bytes=copy_runtime.MAX_PLAN_JSON_BYTES,
        too_large="warm_bootstrap_plan_too_large",
    )
    if not isinstance(plan, dict):
        raise ValueError("bootstrap_plan_contract_invalid")
    if plan.get("package_type") != "WARM_TIER_INCREMENTAL_PLAN" or plan.get("contract_version") != 2:
        raise ValueError("bootstrap_plan_contract_invalid")
    bootstrap = plan.get("bootstrap")
    if not isinstance(bootstrap, dict) or bootstrap.get("contract") != "sli.warm-tier-bootstrap.v1":
        raise ValueError("bootstrap_plan_marker_missing")
    digest = str(bootstrap.get("plan_digest") or "")
    if len(digest) != 64 or digest != plan_digest(plan):
        raise ValueError("bootstrap_plan_digest_invalid")
    return plan


def _record_receipt(digest: str, receipt: dict[str, Any]) -> None:
    """Persist bootstrap admission and target-preflight evidence separately."""
    path = EVIDENCE_ROOT / f"warm-tier-bootstrap-receipt-{digest[:16]}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def execute_bootstrap(
    plan_path: Path, *, confirmation: str | None, execute: bool,
    port: int | None = None, output_path: Path | None = None,
) -> dict[str, Any]:
    """Admit an exact sealed plan before any target connection or write."""
    plan_path = plan_path.resolve()
    plan = _read_and_verify_bootstrap_plan(plan_path)
    digest = str(plan["bootstrap"]["plan_digest"])
    if execute and confirmation != digest:
        raise ValueError("bootstrap_plan_digest_confirmation_required")
    # Validate the ordinary v2 contract before opening a target connection or
    # creating even the empty base schema.  The publisher validates again from
    # disk immediately before it opens PostgreSQL; this early validation closes
    # the bootstrap-only DDL admission boundary.
    frozen = copy_runtime.validate_plan(plan)
    if port is None:
        port = _container_port(CONTAINER)
    if not execute:
        try:
            preflight = preflight_target(port)
        except RuntimeError as exc:
            if str(exc) != "warm_bootstrap_target_occupied":
                raise
            preflight = _preflight_exact_recovery_target(port, frozen)
        receipt = {"package_type": "WARM_TIER_BOOTSTRAP_RECEIPT", "status": "validated_not_executed", "bootstrap": {"plan_digest": digest, "target_preflight": preflight}, "safety": {"routing_changed": False, "delete_performed": False, "runtime_started": False}}
        _record_receipt(digest, receipt)
        return receipt
    with session_advisory_lock(_connect, STORAGE_LIFECYCLE_LOCK_NAME) as acquired:
        if not acquired:
            raise RuntimeError("warm_bootstrap_storage_lifecycle_lock_held")
        try:
            preflight = preflight_target(port)
            target_mode = "empty"
        except RuntimeError as exc:
            if str(exc) != "warm_bootstrap_target_occupied":
                raise
            preflight = _preflight_exact_recovery_target(port, frozen)
            target_mode = "exact_recovery"
        if target_mode == "empty":
            initialize_empty_target(port)
        receipt = copy_runtime.execute_and_record(
            plan_path, execute=True, output_path=output_path, port=port,
            plan_payload=plan,
        )
    receipt["bootstrap"] = {"plan_digest": digest, "target_preflight": preflight, "publisher": "warm_tier_incremental_copy_runtime"}
    _record_receipt(digest, receipt)
    return receipt

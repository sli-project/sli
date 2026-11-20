#!/usr/bin/env python3
"""Plan or run one bounded manual RADIUS Accounting worker invocation."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.maintenance.ad_context_live_canary import (  # noqa: E402
    current_windows_account,
    terminate_process_tree,
)
from scripts.maintenance.stage9_radius_registration_apply import (  # noqa: E402
    _live_acl_readback,
)
from scripts.maintenance.stage9_radius_identity_owner_migrate import (  # noqa: E402
    _attestation_migrations,
)
from server.sli.sources.radius_plugin_runtime import (  # noqa: E402
    RadiusAcquisitionRuntimeError as RadiusManualWorkerError,
    _resolve_acquisition_identity as _resolve_with_cursor,
    acquisition_organization_fqdn as _organization_fqdn,
    acquisition_subscription_id as _subscription_id,
    acquisition_worker_dsn as _worker_dsn,
    connect_acquisition_admin as _connect_admin,
    run_acquisition_cycle as run_internal,
)
from server.sli.ops.worker_supervisor_secrets import (  # noqa: E402
    load_supervisor_environment,
)
from server.sli.sources.windows_runtime_identity import (  # noqa: E402
    expected_collection_identity,
    verify_collection_identity,
)
from server.source_packs.radius.accounting_manual_control import (  # noqa: E402
    RadiusManualLease,
    bounded_manual_activation,
    inspect_manual_state,
    load_manual_control_contract,
)
from server.source_packs.radius.accounting_runtime_contract import (  # noqa: E402
    RadiusClassCacheEntry,
    RadiusFileCursor,
    plan_batch,
)
from server.source_packs.radius.accounting_tail import (  # noqa: E402
    read_bounded_tail,
)
from server.source_packs.radius.collection_routes import (  # noqa: E402
    load_radius_collection_routes,
    require_accounting_source,
)


CONFIRMATION = "RUN-STAGE9-RADIUS-MANUAL-ONCE"
DIAGNOSTIC_CONFIRMATION = "DIAGNOSE-STAGE9-RADIUS-TAIL-ONCE"
DISPOSABLE_ACCEPTANCE = (
    ROOT
    / "artifacts/stage9/evidence/"
    "radius-manual-control-disposable-pg18.json"
)
IDENTITY_APPLY = (
    ROOT
    / "artifacts/stage9/evidence/"
    "radius-identity-resolver59-production-apply.json"
)
IDENTITY_OWNER_ATTESTATION = (
    ROOT
    / "artifacts/stage9/evidence/"
    "radius-identity-owner60-production-attestation.json"
)
REGISTRATION_APPLY = (
    ROOT
    / "artifacts/stage9/evidence/"
    "radius-accounting-disabled-registration-radius01-production.json"
)
ACL_READBACK = (
    ROOT
    / "artifacts/stage9/evidence/"
    "radius-evidence-root-acl-readback.json"
)
DEFAULT_OUTPUT = (
    ROOT
    / "artifacts/stage9/evidence/"
    "radius-manual-worker-radius01-run-001.json"
)
_EPHEMERAL_ROLE = re.compile(r"^adlog_radius_manual_[a-z0-9_]{1,40}$")


def _expected_account() -> str:
    return expected_collection_identity()[0]


def _source_id() -> str:
    return str(load_radius_collection_routes()["source_instance_id"])


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RadiusManualWorkerError(
            f"prerequisite_invalid:{path.name}"
        ) from exc
    if not isinstance(value, dict):
        raise RadiusManualWorkerError(
            f"prerequisite_object_required:{path.name}"
        )
    return value


def _read_optional_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    return _read_json(path)


def _valid_identity_apply(value: Mapping[str, Any]) -> bool:
    return bool(
        value.get("status") == "passed"
        and value.get("action") == "apply"
        and dict(value.get("migration") or {}).get("version") == 59
        and value.get("production_database_changed") is True
        and value.get("runtime_enabled") is False
    )


def _valid_identity_attestation(value: Mapping[str, Any]) -> bool:
    migrations = dict(value.get("migrations") or {})
    postcondition = dict(value.get("postcondition") or {})
    required_postcondition = {
        "marker": True,
        "resolver_owner": "adlog_radius_identity_resolver",
        "resolver_owner_restricted_nologin": True,
        "domains_column_select": True,
        "aliases_column_select": True,
        "resolver_owner_schema_create": False,
        "worker_identity_select": False,
        "public_execute": False,
        "missing_identity_result": None,
    }
    return bool(
        value.get("status") == "passed"
        and value.get("action") == "finalize_applied_readback"
        and value.get("evidence_kind") == "production_current_state_attestation"
        and value.get("covers_migrations") == [59, 60]
        and migrations == _attestation_migrations()
        and postcondition == required_postcondition
        and value.get("production_migration_applied") is True
        and value.get("production_database_changed") is False
        and value.get("radius_source_contacted") is False
        and value.get("runtime_enabled") is False
    )


def _validate_identity_authority(
    identity_apply: Mapping[str, Any] | None,
    identity_attestation: Mapping[str, Any] | None,
) -> None:
    if identity_apply is None and identity_attestation is None:
        raise RadiusManualWorkerError("identity_resolver_evidence_invalid")
    if identity_apply is not None and not _valid_identity_apply(identity_apply):
        raise RadiusManualWorkerError("identity_resolver_apply_evidence_invalid")
    if identity_attestation is not None and not _valid_identity_attestation(identity_attestation):
        raise RadiusManualWorkerError("identity_resolver_attestation_invalid")
    if identity_apply is not None and identity_attestation is not None:
        legacy = dict(identity_apply.get("migration") or {})
        current = dict(
            dict(identity_attestation.get("migrations") or {}).get("59") or {}
        )
        if any(
            legacy.get(key) != current.get(key)
            for key in ("forward_sha256", "rollback_sha256")
        ):
            raise RadiusManualWorkerError("identity_resolver_evidence_hash_mismatch")


def validate_prerequisite_evidence(
    disposable: Mapping[str, Any],
    identity_apply: Mapping[str, Any] | None,
    registration: Mapping[str, Any],
    acl: Mapping[str, Any],
    identity_attestation: Mapping[str, Any] | None = None,
) -> None:
    acceptance = dict(disposable.get("acceptance") or {})
    if not (
        disposable.get("status") == "passed"
        and disposable.get("production_database_changed") is False
        and disposable.get("radius_source_contacted") is False
        and disposable.get("runtime_enabled") is False
        and acceptance.get("success_final_state") == "disabled"
        and acceptance.get("failure_final_state") == "disabled"
        and acceptance.get("success_ephemeral_login_dropped") is True
        and acceptance.get("failure_ephemeral_login_dropped") is True
        and acceptance.get("cursor_unchanged") is True
    ):
        raise RadiusManualWorkerError(
            "manual_disposable_acceptance_invalid"
        )
    _validate_identity_authority(identity_apply, identity_attestation)
    if not (
        registration.get("status") == "passed"
        and registration.get("action") == "disabled_registration"
        and registration.get("source_instance_id") == _source_id()
        and registration.get("subscription_id") == _subscription_id()
        and registration.get("desired_activation") == "disabled"
        and registration.get("cursor_revision") == 0
        and registration.get("worker_activated") is False
        and registration.get("runtime_enabled") is False
    ):
        raise RadiusManualWorkerError(
            "disabled_registration_evidence_invalid"
        )
    if not (
        acl.get("status") == "accepted"
        and acl.get("classification") == "protected_acl_exact"
        and acl.get("contract_id")
        == "sli.radius-acquisition-evidence-root.v2"
        and acl.get("node_count") == 4
        and acl.get("acl_entry_count") == 12
        and acl.get("activation_enabled") is False
        and acl.get("raw_path_persisted") is False
    ):
        raise RadiusManualWorkerError("protected_root_evidence_invalid")


def _load_environment() -> None:
    if not (
        os.getenv("ADLOG_PG_ADMIN_USER", "").strip()
        and os.getenv("ADLOG_PG_ADMIN_PASSWORD", "")
        and os.getenv("ADLOG_PG_DSN", "").strip()
        and os.getenv("ADLOG_COLLECTION_PRINCIPAL", "").strip()
        and os.getenv("ADLOG_COLLECTION_PRINCIPAL_SID", "").strip()
    ):
        load_supervisor_environment()


def _inspect_production() -> dict[str, Any]:
    with _connect_admin() as conn:
        state = inspect_manual_state(conn)
        with conn.transaction():
            with conn.cursor() as cur:
                cur.execute("set transaction read only")
                cur.execute(
                    """
                    select
                      current_setting('server_version_num')::integer,
                      current_database(),
                      exists(
                        select 1 from pg_roles
                        where rolname like 'adlog_radius_manual_%'
                      ),
                      exists(
                        select 1 from pg_stat_activity
                        where application_name=
                          'sli_stage9_radius_manual_worker'
                          and pid<>pg_backend_pid()
                      ),
                      has_function_privilege(
                        'adlog_radius_accounting_worker',
                        'sli_radius_resolve_principal_key(text,text)',
                        'EXECUTE'
                      ),
                      has_table_privilege(
                        'adlog_radius_accounting_worker',
                        'ad_context_entity_aliases','SELECT'
                      ),
                      (
                        select pg_get_userbyid(proowner)
                        from pg_proc
                        where oid='sli_radius_resolve_principal_key(text,text)'
                          ::regprocedure
                      ),
                      (
                        select pg_get_userbyid(relowner)
                        from pg_class
                        where oid='ad_context_entity_aliases'::regclass
                      ),
                      (
                        select pg_get_userbyid(relowner)
                        from pg_class
                        where oid='domains'::regclass
                      ),
                      exists(
                        select 1 from schema_migrations
                        where version=60
                          and name='radius_identity_resolver_owner'
                      ),
                      (
                        select not rolcanlogin and not rolsuper
                               and not rolinherit
                        from pg_roles
                        where rolname='adlog_radius_identity_resolver'
                      ),
                      has_column_privilege(
                        'adlog_radius_identity_resolver',
                        'ad_context_entity_aliases','entity_id','SELECT'
                      ) and has_column_privilege(
                        'adlog_radius_identity_resolver',
                        'ad_context_entity_aliases','domain_id','SELECT'
                      ) and has_column_privilege(
                        'adlog_radius_identity_resolver',
                        'ad_context_entity_aliases','alias_type','SELECT'
                      ) and has_column_privilege(
                        'adlog_radius_identity_resolver',
                        'ad_context_entity_aliases',
                        'normalized_value','SELECT'
                      ),
                      has_column_privilege(
                        'adlog_radius_identity_resolver',
                        'domains','id','SELECT'
                      ) and has_column_privilege(
                        'adlog_radius_identity_resolver',
                        'domains','fqdn','SELECT'
                      ),
                      has_schema_privilege(
                        'adlog_radius_identity_resolver','public','CREATE'
                      )
                    """
                )
                (
                    version,
                    database,
                    ephemeral_role_exists,
                    worker_session_exists,
                    resolver_execute,
                    identity_select,
                    resolver_owner,
                    aliases_owner,
                    domains_owner,
                    marker_60,
                    resolver_owner_restricted,
                    resolver_owner_aliases_columns,
                    resolver_owner_domains_columns,
                    resolver_owner_schema_create,
                ) = cur.fetchone()
    if int(version) // 10000 != 18:
        raise RadiusManualWorkerError("production_postgres_18_required")
    if ephemeral_role_exists:
        raise RadiusManualWorkerError("stale_ephemeral_login_exists")
    if worker_session_exists:
        raise RadiusManualWorkerError("manual_worker_already_running")
    if not resolver_execute or identity_select:
        raise RadiusManualWorkerError(
            "least_privilege_resolver_state_invalid"
        )
    if not state.migration_58 or not state.migration_59:
        raise RadiusManualWorkerError("required_migration_missing")
    if not marker_60:
        raise RadiusManualWorkerError("migration_60_required")
    if (
        str(resolver_owner) != "adlog_radius_identity_resolver"
        or not resolver_owner_restricted
        or not resolver_owner_aliases_columns
        or not resolver_owner_domains_columns
        or resolver_owner_schema_create
    ):
        raise RadiusManualWorkerError(
            "resolver_owner_least_privilege_invalid"
        )
    if (
        state.source_activation != "disabled"
        or state.subscription_activation != "disabled"
    ):
        raise RadiusManualWorkerError("registration_not_disabled")
    return {
        "database": str(database),
        "postgres_major": 18,
        "cursor_revision": state.cursor_revision,
        "source_activation": state.source_activation,
        "subscription_activation": state.subscription_activation,
        "ephemeral_role_exists": False,
        "worker_session_exists": False,
        "resolver_execute": True,
        "identity_spine_select": False,
        "resolver_owner": str(resolver_owner),
        "aliases_owner": str(aliases_owner),
        "domains_owner": str(domains_owner),
        "resolver_owner_restricted_nologin": bool(
            resolver_owner_restricted
        ),
        "resolver_owner_aliases_column_select": bool(
            resolver_owner_aliases_columns
        ),
        "resolver_owner_domains_column_select": bool(
            resolver_owner_domains_columns
        ),
        "resolver_owner_schema_create": bool(
            resolver_owner_schema_create
        ),
    }


def _load_disabled_cursor() -> RadiusFileCursor:
    with _connect_admin() as conn:
        with conn.transaction():
            with conn.cursor() as cur:
                cur.execute("set transaction read only")
                cur.execute(
                    """
                    select c.source_instance_id,c.stream_id,
                           c.transport_binding,c.file_generation,
                           c.byte_offset,c.last_record_sha256,
                           s.desired_activation,sub.desired_activation
                    from acquisition_stream_cursors c
                    join acquisition_source_instances s
                      on s.source_instance_id=c.source_instance_id
                    join acquisition_consumer_subscriptions sub
                      on sub.source_instance_id=c.source_instance_id
                     and sub.stream_id=c.stream_id
                     and sub.transport_binding=c.transport_binding
                    where c.source_instance_id=%s
                      and sub.subscription_id=%s
                    """,
                    (_source_id(), _subscription_id()),
                )
                row = cur.fetchone()
    if row is None:
        raise RadiusManualWorkerError("manual_registration_not_found")
    if str(row[6]) != "disabled" or str(row[7]) != "disabled":
        raise RadiusManualWorkerError("diagnostic_requires_disabled_state")
    return RadiusFileCursor(
        source_instance_id=str(row[0]),
        stream_id=str(row[1]),
        transport_binding=str(row[2]),
        file_generation=str(row[3]),
        byte_offset=int(row[4]),
        last_record_sha256=(
            str(row[5]) if row[5] is not None else None
        ),
    )


def _validate_live_acl() -> None:
    recorded = _read_json(ACL_READBACK)
    live = _live_acl_readback()
    if live.get("readback_sha256") != recorded.get("readback_sha256"):
        raise RadiusManualWorkerError("protected_root_acl_changed")


def _registration_apply_evidence_path() -> Path:
    return Path(
        os.environ.get("ADLOG_RADIUS_REGISTRATION_APPLY_EVIDENCE_PATH", "").strip()
        or REGISTRATION_APPLY
    )


def _plan_after_external_acl_preflight() -> dict[str, Any]:
    load_manual_control_contract()
    validate_prerequisite_evidence(
        _read_json(DISPOSABLE_ACCEPTANCE),
        _read_optional_json(IDENTITY_APPLY),
        _read_json(_registration_apply_evidence_path()),
        _read_json(ACL_READBACK),
        _read_optional_json(IDENTITY_OWNER_ATTESTATION),
    )
    production = _inspect_production()
    routes = load_radius_collection_routes()
    return {
        "status": (
            "ready" if routes["accounting_ready"]
            else "blocked_external_source_configuration"
        ),
        "action": "plan",
        "production": production,
        "collection_routes": routes,
        "source_contacted": False,
        "production_database_changed": False,
        "evidence_root_changed": False,
        "runtime_enabled": False,
        "autostart_enabled": False,
        "limits": {
            "runs": 1,
            "candidates": 20,
            "read_bytes": 4 * 1024 * 1024,
            "records": 1000,
            "runtime_seconds": 120,
        },
        "required_windows_account": _expected_account() or None,
        "required_confirmation": CONFIRMATION,
    }


def plan() -> dict[str, Any]:
    _validate_live_acl()
    return _plan_after_external_acl_preflight()


def contract_self_check() -> dict[str, Any]:
    """Validate the reviewed handler contract without DB, network or source."""
    load_manual_control_contract()
    validate_prerequisite_evidence(
        _read_json(DISPOSABLE_ACCEPTANCE),
        _read_optional_json(IDENTITY_APPLY),
        _read_json(_registration_apply_evidence_path()),
        _read_json(ACL_READBACK),
        _read_optional_json(IDENTITY_OWNER_ATTESTATION),
    )
    routes = load_radius_collection_routes()
    return {
        "status": "contract_valid",
        "action": "contract-self-check",
        "handler_id": "stage9-radius-manual-worker",
        "source_contacted": False,
        "database_accessed": False,
        "runtime_enabled": False,
        "autostart_enabled": False,
        "event_log_route_ready": routes["event_log_ready"],
        "accounting_route_ready": routes["accounting_ready"],
        "blockers": routes["blockers"],
    }


def _diagnose_tail_with_plan(
    planned: Mapping[str, Any],
    *,
    identity_prevalidated: bool = False,
) -> dict[str, Any]:
    if not identity_prevalidated and verify_collection_identity()["status"] != "ok":
        raise PermissionError("current_windows_account_is_not_approved_owner")
    directory, timezone_id, offset = require_accounting_source()
    cursor = _load_disabled_cursor()
    tail = read_bounded_tail(
        directory,
        cursor=cursor,
        allow_exact_boundary_recovery=True,
    )
    with _connect_admin() as conn:
        with conn.transaction():
            with conn.cursor() as cur:
                cur.execute("set transaction read only")
                cur.execute("set local role adlog_radius_accounting_worker")
                cur.execute(
                    """
                    select class_scope_sha256,exact_principal_key,
                           expires_at_utc
                    from radius_accounting_class_cache
                    where source_instance_id=%s and expires_at_utc>now()
                    order by class_scope_sha256
                    """,
                    (_source_id(),),
                )
                cache = {
                    str(item[0]): RadiusClassCacheEntry(
                        class_scope_sha256=str(item[0]),
                        exact_principal_key=str(item[1]),
                        expires_at_utc=item[2].astimezone(
                            timezone.utc
                        ).isoformat(),
                    )
                    for item in cur.fetchall()
                }
                planned_batch = plan_batch(
                    cursor=cursor,
                    class_cache=cache,
                    file_generation=tail.file_generation,
                    start_offset=tail.start_offset,
                    end_offset=tail.end_offset,
                    lines=tail.records,
                    identity_resolver=lambda dn: _resolve_with_cursor(cur, dn),
                    batch_observed_at_utc=datetime.now(timezone.utc),
                    source_timezone_id=timezone_id,
                    source_utc_offset_minutes=offset,
                    previous_generation_eof=tail.previous_generation_eof,
                )
    return {
        "status": "completed",
        "action": "bounded_read_only_tail_diagnostic",
        "source_contacted": True,
        "production_database_changed": False,
        "evidence_root_changed": False,
        "worker_activated": False,
        "cursor_revision": planned["production"]["cursor_revision"],
        "records_ready": len(tail.records),
        "plan_counters": dict(planned_batch.counters),
        "planned_evidence_rows": len(planned_batch.evidence_sha256),
        "planned_observation_rows": len(
            planned_batch.session_observations
        ),
        "candidate_count": tail.candidate_count,
        "bytes_read": tail.bytes_read,
        "partial_trailing_bytes": tail.partial_trailing_bytes,
        "rotation_from_eof": tail.previous_generation_eof,
        "rotation_backlog_generations": (
            tail.rotation_backlog_generations
        ),
        "cursor_generation_recovered": (
            tail.cursor_generation_recovered
        ),
        "source_timezone_id": timezone_id,
        "source_utc_offset_minutes": offset,
        "file_name_persisted": False,
        "file_path_persisted": False,
        "raw_record_persisted": False,
    }


def diagnose_tail() -> dict[str, Any]:
    return _diagnose_tail_with_plan(plan())


def diagnose_tail_after_external_measurement_preflight() -> dict[str, Any]:
    """Run the read-only workload after parent identity and ACL preflight.

    The split is used only by the one-process Job measurement: both ``whoami``
    and the ACL helper create child processes forbidden by that Job. The
    measured process inherits the parent's Windows token. Runtime and ordinary
    diagnostics continue to call ``diagnose_tail()`` and therefore cannot skip
    either live preflight.
    """
    return _diagnose_tail_with_plan(
        _plan_after_external_acl_preflight(),
        identity_prevalidated=True,
    )


def _child_environment(lease: RadiusManualLease) -> dict[str, str]:
    environment = dict(os.environ)
    for name in tuple(environment):
        upper = name.upper()
        if upper.startswith("ADLOG_") and any(
            marker in upper
            for marker in ("PASSWORD", "SECRET", "TOKEN", "DSN")
        ):
            environment.pop(name, None)
    environment["SLI_PLUGIN_PG_DSN"] = _worker_dsn(lease)
    return environment


def _run_child(lease: RadiusManualLease) -> dict[str, Any]:
    environment = _child_environment(lease)
    process = subprocess.Popen(
        [sys.executable, str(Path(__file__).resolve()), "--internal"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=environment,
    )
    try:
        stdout, _stderr = process.communicate(
            timeout=lease.maximum_runtime_seconds
        )
    except subprocess.TimeoutExpired as exc:
        terminate_process_tree(process)
        raise TimeoutError("manual_radius_worker_timed_out") from exc
    if process.returncode != 0:
        error_type = "InternalManualWorkerError"
        try:
            failure = json.loads(stdout.lstrip("\ufeff").strip())
            candidate = str(failure.get("error_type") or "")
            if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,127}", candidate):
                error_type = candidate
        except (json.JSONDecodeError, AttributeError):
            pass
        error_code = ""
        try:
            candidate_code = str(failure.get("error_code") or "")
            if re.fullmatch(r"[a-z][a-z0-9_:.-]{0,127}", candidate_code):
                error_code = candidate_code
        except (UnboundLocalError, AttributeError):
            pass
        suffix = f":{error_code}" if error_code else ""
        raise RadiusManualWorkerError(
            f"internal_worker_failed:{error_type}{suffix}"
        )
    try:
        result = json.loads(stdout.lstrip("\ufeff").strip())
    except json.JSONDecodeError as exc:
        raise RadiusManualWorkerError(
            "internal_worker_json_invalid"
        ) from exc
    if not isinstance(result, dict) or result.get("status") not in {
        "committed",
        "no_new_complete_records",
    }:
        raise RadiusManualWorkerError(
            "internal_worker_result_invalid"
        )
    return result


def execute() -> dict[str, Any]:
    from server.sli.sources.legacy_collection import require_legacy_collection

    require_legacy_collection()
    planned = plan()
    if verify_collection_identity()["status"] != "ok":
        raise PermissionError("current_windows_account_is_not_approved_owner")
    before_revision = int(planned["production"]["cursor_revision"])
    role = ""
    child_result: dict[str, Any] | None = None
    with _connect_admin() as admin:
        with bounded_manual_activation(admin) as lease:
            role = lease.login_role
            child_result = _run_child(lease)
        final_state = inspect_manual_state(admin)
        with admin.transaction():
            with admin.cursor() as cur:
                cur.execute("set transaction read only")
                cur.execute("select to_regrole(%s) is not null", (role,))
                role_exists = bool(cur.fetchone()[0])
    if (
        final_state.source_activation != "disabled"
        or final_state.subscription_activation != "disabled"
        or role_exists
    ):
        raise RadiusManualWorkerError("manual_final_state_invalid")
    expected_revision = int(child_result["cursor_revision_after"])
    if final_state.cursor_revision != expected_revision:
        raise RadiusManualWorkerError("manual_cursor_readback_mismatch")
    return {
        "status": "passed",
        "action": "bounded_manual_worker",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "windows_account": _expected_account(),
        "source_instance_id": _source_id(),
        "subscription_id": _subscription_id(),
        "source_contacted": True,
        "production_database_changed": (
            expected_revision != before_revision
        ),
        "worker_result": child_result,
        "final_source_activation": "disabled",
        "final_subscription_activation": "disabled",
        "ephemeral_login_dropped": True,
        "continuous_runtime_enabled": False,
        "autostart_enabled": False,
        "file_name_persisted": False,
        "file_path_persisted": False,
        "raw_record_persisted_in_report": False,
    }


def main() -> int:
    from server.sli.sources.legacy_collection import require_legacy_collection

    require_legacy_collection()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--action",
        choices=("contract-self-check", "plan", "diagnose-tail", "execute"),
        default="plan",
    )
    parser.add_argument("--confirmation", default="")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--load-supervisor-environment", action="store_true")
    parser.add_argument("--internal", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.internal:
        try:
            print(json.dumps(run_internal(), ensure_ascii=False))
            return 0
        except Exception as exc:
            print(
                json.dumps(
                    {
                        "error_type": type(exc).__name__,
                        "error_code": str(getattr(exc, "code", "")),
                    }
                )
            )
            return 1
    if args.load_supervisor_environment:
        _load_environment()
    if args.action == "contract-self-check":
        print(json.dumps(contract_self_check(), ensure_ascii=False))
        return 0
    if args.action == "plan":
        print(json.dumps(plan(), ensure_ascii=False, indent=2))
        return 0
    if args.action == "diagnose-tail":
        if args.confirmation != DIAGNOSTIC_CONFIRMATION:
            raise PermissionError(
                "diagnose-tail requires --confirmation "
                f"{DIAGNOSTIC_CONFIRMATION}"
            )
        try:
            diagnostic = diagnose_tail()
        except Exception as exc:
            diagnostic = {
                "status": "failed",
                "action": "bounded_read_only_tail_diagnostic",
                "error_type": type(exc).__name__,
                "error_code": str(getattr(exc, "code", "")),
                "source_contacted": True,
                "production_database_changed": False,
                "worker_activated": False,
            }
        print(json.dumps(diagnostic, ensure_ascii=False, indent=2))
        return 0 if diagnostic["status"] == "completed" else 1
    if args.confirmation != CONFIRMATION:
        raise PermissionError(
            f"execute requires --confirmation {CONFIRMATION}"
        )
    output = args.output.resolve()
    if (ROOT / "artifacts").resolve() not in output.parents:
        raise ValueError("output must stay under artifacts")
    if output.exists():
        raise FileExistsError("manual worker evidence already exists")
    try:
        result = execute()
    except Exception as exc:
        result = {
            "status": "failed",
            "action": "bounded_manual_worker",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "error_type": type(exc).__name__,
            "error_code": str(getattr(exc, "code", "")),
            "source_instance_id": _source_id(),
            "subscription_id": _subscription_id(),
            "continuous_runtime_enabled": False,
            "autostart_enabled": False,
            "raw_record_persisted_in_report": False,
        }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"status": result["status"], "output": str(output)}))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Plan or run one bounded production RADIUS session consumer pass."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.maintenance.ad_context_live_canary import (  # noqa: E402
    current_windows_account,
    terminate_process_tree,
)
from server.sli.ops.worker_supervisor_secrets import (  # noqa: E402
    load_supervisor_environment,
)
from server.sli.sources.windows_runtime_identity import (  # noqa: E402
    expected_collection_identity,
    verify_collection_identity,
)
from server.sli.sources.radius_plugin_runtime import (  # noqa: E402
    RadiusSessionConsumerRuntimeError as RadiusSessionConsumerManualError,
    connect_consumer_admin as _connect_admin,
    consumer_ephemeral_login as _ephemeral_login,
    consumer_worker_dsn as _worker_dsn,
    run_consumer_cycle as run_internal,
)
from server.source_packs.radius.session_consumer import (  # noqa: E402
    load_consumer_contract,
)
from server.source_packs.radius.accounting_manual_control import (  # noqa: E402
    load_manual_control_contract,
)


CONFIRMATION = "RUN-STAGE9-RADIUS-SESSION-CONSUMER-ONCE"
PRODUCTION_APPLY = (
    ROOT
    / "artifacts/stage9/evidence/"
    "radius-session-consumer61-production-apply.json"
)
DISPOSABLE_RUNTIME = (
    ROOT
    / "artifacts/stage9/evidence/"
    "radius-session-consumer-runtime-disposable-pg18.json"
)
DEFAULT_OUTPUT = (
    ROOT
    / "artifacts/stage9/evidence/"
    "radius-session-consumer-radius01-production-run-001.json"
)
def _source_id() -> str:
    return str(load_manual_control_contract()["source_instance_id"])


def _subscription_id() -> str:
    return str(load_manual_control_contract()["subscription_id"])


def _required_windows_account() -> str:
    return expected_collection_identity()[0]


def _load_environment() -> None:
    if not (
        os.getenv("ADLOG_PG_ADMIN_USER", "").strip()
        and os.getenv("ADLOG_PG_ADMIN_PASSWORD", "")
        and os.getenv("ADLOG_PG_DSN", "").strip()
    ):
        load_supervisor_environment()


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RadiusSessionConsumerManualError(
            f"prerequisite_invalid:{path.name}"
        ) from exc
    if not isinstance(value, dict):
        raise RadiusSessionConsumerManualError(
            f"prerequisite_object_required:{path.name}"
        )
    return value


def _validate_prerequisites() -> None:
    load_consumer_contract()
    applied = _read_json(PRODUCTION_APPLY)
    runtime = _read_json(DISPOSABLE_RUNTIME)
    post = dict(applied.get("postcondition") or {})
    acceptance = dict(runtime.get("acceptance") or {})
    if not (
        applied.get("status") == "passed"
        and applied.get("action") == "apply"
        and dict(applied.get("migration") or {}).get("version") == 61
        and applied.get("production_database_changed") is True
        and applied.get("radius_source_contacted") is False
        and post.get("marker_61") is True
        and post.get("untouched_queued_rows") == 15
        and post.get("receipt_rows") == 0
        and post.get("projection_rows") == 0
    ):
        raise RadiusSessionConsumerManualError(
            "production_apply_evidence_invalid"
        )
    if not (
        runtime.get("status") == "passed"
        and runtime.get("production_database_changed") is False
        and runtime.get("radius_source_contacted") is False
        and acceptance.get("core_evidence_select_denied") is True
        and acceptance.get("observation_update_denied") is True
        and acceptance.get("delivered_rows") == 3
        and acceptance.get("quarantined_attempt_count") == 5
    ):
        raise RadiusSessionConsumerManualError(
            "runtime_disposable_evidence_invalid"
        )


def contract_self_check() -> dict[str, Any]:
    """Validate the reviewed handler contract without DB, network or source."""
    _validate_prerequisites()
    return {
        "status": "contract_valid",
        "action": "contract-self-check",
        "handler_id": "stage9-radius-session-consumer-manual",
        "source_contacted": False,
        "database_accessed": False,
        "runtime_enabled": False,
        "autostart_enabled": False,
    }


def _inspect() -> dict[str, Any]:
    with _connect_admin() as conn, conn.cursor() as cur:
        cur.execute("begin read only")
        cur.execute(
            """
            select
              current_setting('server_version_num')::integer,
              exists(
                select 1 from schema_migrations
                where version=61
                  and name='radius_session_consumer_projection'
              ),
              (
                select count(*) from acquisition_source_instances
                where source_instance_id=%s
                  and desired_activation='disabled'
              ),
              (
                select count(*) from acquisition_consumer_subscriptions
                where subscription_id=%s
                  and desired_activation='disabled'
              ),
              (
                select revision from acquisition_stream_cursors
                where source_instance_id=%s
                  and stream_id='radius-accounting'
                  and transport_binding=
                    'windows-rpc-smb-readonly-tail-v1'
              ),
              (select count(*) from acquisition_delivery_outbox),
              (
                select count(*) from acquisition_delivery_outbox
                where delivery_state='queued'
              ),
              (
                select count(*) from acquisition_delivery_outbox
                where delivery_state='delivered'
              ),
              (
                select count(*) from acquisition_delivery_outbox
                where delivery_state in ('leased','failed','quarantined')
              ),
              (select count(*) from radius_session_projection_receipts),
              (select count(*) from radius_vpn_session_projection),
              exists(
                select 1 from pg_roles
                where rolname like 'adlog_radius_consumer_%%'
              ),
              exists(
                select 1 from pg_stat_activity
                where application_name=
                  'sli_stage9_radius_session_consumer_worker'
                  and pid<>pg_backend_pid()
              )
            """,
            (_source_id(), _subscription_id(), _source_id()),
        )
        row = cur.fetchone()
        cur.execute("rollback")
    return {
        "server_version_num": int(row[0]),
        "marker_61": bool(row[1]),
        "disabled_source_rows": int(row[2]),
        "disabled_subscription_rows": int(row[3]),
        "cursor_revision": int(row[4]),
        "outbox_rows": int(row[5]),
        "queued_rows": int(row[6]),
        "delivered_rows": int(row[7]),
        "failed_or_leased_or_quarantined_rows": int(row[8]),
        "receipt_rows": int(row[9]),
        "projection_rows": int(row[10]),
        "ephemeral_login_exists": bool(row[11]),
        "consumer_session_exists": bool(row[12]),
    }


def plan() -> dict[str, Any]:
    _validate_prerequisites()
    state = _inspect()
    blockers: list[str] = []
    if state["server_version_num"] // 10000 != 18:
        blockers.append("postgres_18_required")
    if not state["marker_61"]:
        blockers.append("migration_61_required")
    if state["disabled_source_rows"] != 1:
        blockers.append("disabled_source_required")
    if state["disabled_subscription_rows"] != 1:
        blockers.append("disabled_subscription_required")
    if state["cursor_revision"] < 1:
        blockers.append("initialized_cursor_required")
    if (
        not 1 <= state["queued_rows"] <= 50
        or state["outbox_rows"] != (
            state["queued_rows"] + state["delivered_rows"]
        )
        or state["failed_or_leased_or_quarantined_rows"] != 0
        or state["receipt_rows"] != state["delivered_rows"]
        or state["projection_rows"] > state["receipt_rows"]
    ):
        blockers.append("bounded_queued_delivery_state_required")
    if state["ephemeral_login_exists"] or state["consumer_session_exists"]:
        blockers.append("consumer_must_be_idle")
    return {
        "status": "ready" if not blockers else "blocked",
        "action": "plan",
        "production": state,
        "blockers": blockers,
        "source_contacted": False,
        "production_database_changed": False,
        "runtime_enabled": False,
        "autostart_enabled": False,
        "limits": {
            "runs": 1,
            "deliveries": 50,
            "runtime_seconds": 60,
            "maximum_attempts": 5,
        },
        "required_windows_account": _required_windows_account() or None,
        "required_confirmation": CONFIRMATION,
    }


def _child_environment(role: str, password: str) -> dict[str, str]:
    environment = dict(os.environ)
    for name in tuple(environment):
        upper = name.upper()
        if upper.startswith("ADLOG_") and any(
            marker in upper
            for marker in ("PASSWORD", "SECRET", "TOKEN", "DSN")
        ):
            environment.pop(name, None)
    environment["SLI_PLUGIN_PG_DSN"] = _worker_dsn(
        role, password
    )
    return environment


def _run_child(role: str, password: str) -> dict[str, Any]:
    process = subprocess.Popen(
        [sys.executable, str(Path(__file__).resolve()), "--internal"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=_child_environment(role, password),
    )
    try:
        stdout, _stderr = process.communicate(timeout=60)
    except subprocess.TimeoutExpired as exc:
        terminate_process_tree(process)
        raise TimeoutError("consumer_child_timed_out") from exc
    if process.returncode != 0:
        error_type = "InternalConsumerError"
        error_code = ""
        try:
            failure = json.loads(stdout.lstrip("\ufeff").strip())
            candidate = str(failure.get("error_type") or "")
            if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,127}", candidate):
                error_type = candidate
            candidate_code = str(failure.get("error_code") or "")
            if re.fullmatch(r"[a-z][a-z0-9_]{0,119}", candidate_code):
                error_code = candidate_code
        except (json.JSONDecodeError, AttributeError):
            pass
        raise RadiusSessionConsumerManualError(
            f"internal_consumer_failed:{error_type}:{error_code}"
        )
    try:
        value = json.loads(stdout.lstrip("\ufeff").strip())
    except json.JSONDecodeError as exc:
        raise RadiusSessionConsumerManualError(
            "internal_consumer_json_invalid"
        ) from exc
    if not isinstance(value, dict) or value.get("status") != "completed":
        raise RadiusSessionConsumerManualError(
            "internal_consumer_result_invalid"
        )
    return value


def execute() -> dict[str, Any]:
    from server.sli.sources.legacy_collection import require_legacy_collection

    require_legacy_collection()
    planned = plan()
    if planned["status"] != "ready":
        raise RadiusSessionConsumerManualError(
            "consumer_plan_not_ready"
        )
    if verify_collection_identity()["status"] != "ok":
        raise PermissionError(
            "current_windows_account_is_not_approved_owner"
        )
    before = dict(planned["production"])
    role = ""
    with _ephemeral_login() as lease:
        role, password = lease
        child = _run_child(role, password)
    after = _inspect()
    expected_after = {
        "outbox_rows": before["outbox_rows"],
        "queued_rows": 0,
        "delivered_rows": (
            before["delivered_rows"] + before["queued_rows"]
        ),
        "failed_or_leased_or_quarantined_rows": 0,
        "receipt_rows": (
            before["receipt_rows"] + before["queued_rows"]
        ),
        "ephemeral_login_exists": False,
        "consumer_session_exists": False,
    }
    for key, expected in expected_after.items():
        if after[key] != expected:
            raise RadiusSessionConsumerManualError(
                f"consumer_postcondition_failed:{key}"
            )
    outcomes = dict(child.get("outcomes") or {})
    if not (
        child.get("status") == "completed"
        and child.get("claimed") == before["queued_rows"]
        and child.get("processed") == before["queued_rows"]
        and sum(int(value) for value in outcomes.values())
            == before["queued_rows"]
        and set(outcomes).issubset({
            "projected",
            "identity_unresolved",
            "timestamp_unresolved",
        })
        and (
            int(outcomes.get("projected") or 0) == 0
            or after["projection_rows"] > 0
        )
    ):
        raise RadiusSessionConsumerManualError(
            "consumer_child_result_unexpected"
        )
    return {
        "status": "passed",
        "action": "bounded_manual_session_consumer",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "windows_account": _required_windows_account(),
        "subscription_id": _subscription_id(),
        "source_contacted": False,
        "production_database_changed": True,
        "worker_result": child,
        "outbox_rows": after["outbox_rows"],
        "delivered_rows": after["delivered_rows"],
        "receipt_rows": after["receipt_rows"],
        "projection_rows": after["projection_rows"],
        "ephemeral_login_dropped": True,
        "source_activation": "disabled",
        "subscription_activation": "disabled",
        "cursor_revision": after["cursor_revision"],
        "continuous_runtime_enabled": False,
        "autostart_enabled": False,
    }


def main() -> int:
    from server.sli.sources.legacy_collection import require_legacy_collection

    require_legacy_collection()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--action",
        choices=("contract-self-check", "plan", "execute"),
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
            print(json.dumps({
                "error_type": type(exc).__name__,
                "error_code": str(getattr(exc, "code", "")),
            }))
            return 1
    if args.load_supervisor_environment:
        _load_environment()
    if args.action == "contract-self-check":
        print(json.dumps(contract_self_check(), ensure_ascii=False))
        return 0
    if args.action == "plan":
        result = plan()
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["status"] == "ready" else 2
    if args.confirmation != CONFIRMATION:
        raise PermissionError(
            f"execute requires --confirmation {CONFIRMATION}"
        )
    output = args.output.resolve()
    if (ROOT / "artifacts").resolve() not in output.parents:
        raise ValueError("output must stay under artifacts")
    if output.exists():
        raise FileExistsError("manual consumer evidence already exists")
    try:
        result = execute()
    except Exception as exc:
        result = {
            "status": "failed",
            "action": "bounded_manual_session_consumer",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "error_type": type(exc).__name__,
            "error_code": str(getattr(exc, "code", "")),
            "source_contacted": False,
            "continuous_runtime_enabled": False,
            "autostart_enabled": False,
        }
    output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"status": result["status"], "output": str(output)}))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())

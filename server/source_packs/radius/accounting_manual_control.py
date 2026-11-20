from __future__ import annotations

"""Fail-closed control plane for one bounded manual RADIUS worker run.

This module does not contact RADIUS and does not run the worker. It creates a
temporary LOGIN role that can only SET ROLE to the dedicated NOLOGIN worker
role, enables the exact registered source/subscription around one caller-owned
operation, and restores both rows to ``disabled`` before dropping the login.

The loaded contract (``config/stage9_radius_manual_control_v1.json``) states
this module's scope directly, in two named blocks: ``host_runtime`` describes
the long-running, supervised, autostarted process that may call this module
(``scripts/runtime/remote_access_plugin_host.py``, the sole production
runtime owner), and ``lease`` describes the bounded unit of work this module
itself hands out -- one ``bounded_manual_activation()`` lease per call,
always torn down in ``finally`` regardless of outcome, never itself a
continuous worker, an autostart, or admin database access. See
``docs/adr/0007-radius-manual-control-contract-host-lease-split.md`` for why
the contract is shaped this way, and
``docs/adr/0001-radius-runtime-consolidation.md`` for the runtime history.
"""

from contextlib import contextmanager
from dataclasses import dataclass
import json
from pathlib import Path
import re
import secrets
from typing import Any, Callable, Iterator, Mapping

from server.source_packs.radius.accounting_registration import (
    load_registration_contract,
)


ROOT = Path(__file__).resolve().parents[3]
CONTRACT_PATH = ROOT / "config" / "stage9_radius_manual_control_v1.json"
CONTRACT_ID = "sli.radius-accounting-manual-control.v1"
WORKER_ROLE = "adlog_radius_accounting_worker"
ROLE_PREFIX = "adlog_radius_manual_"
_ROLE_NAME = re.compile(r"^adlog_radius_manual_[a-z0-9_]{1,40}$")
EPHEMERAL_DATABASE_CONNECT_ACL_LOCK = "sli.radius.ephemeral_database_connect_acl.v1"


class RadiusManualControlError(RuntimeError):
    """Closed-code control-plane failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class RadiusManualLease:
    login_role: str
    password: str
    source_instance_id: str
    subscription_id: str
    maximum_records: int = 1000
    maximum_runtime_seconds: int = 120


@dataclass(frozen=True)
class RadiusManualState:
    source_activation: str
    subscription_activation: str
    cursor_revision: int
    migration_58: bool
    migration_59: bool


def load_manual_control_contract(
    path: Path | None = None,
) -> dict[str, Any]:
    use_template = path is None
    path = path or CONTRACT_PATH
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RadiusManualControlError("manual_contract_invalid") from exc
    if use_template:
        source_id, subscription_id = _registration_identity()
        value.update(source_instance_id=source_id, subscription_id=subscription_id)
    return validate_manual_control_contract(value)


def _registration_identity() -> tuple[str, str]:
    registration = load_registration_contract()
    return (
        str(registration["source"]["source_instance_id"]),
        str(registration["subscription"]["subscription_id"]),
    )


def validate_manual_control_contract(
    contract: Mapping[str, Any],
) -> dict[str, Any]:
    value = dict(contract)
    source_id, subscription_id = _registration_identity()
    expected = {
        "schema_version": 2,
        "contract_id": CONTRACT_ID,
        "status": "accepted_for_supervised_host_bounded_lease_production",
        "source_instance_id": source_id,
        "subscription_id": subscription_id,
        "required_migrations": [58, 59],
        "planning_contract_id": "sli.radius-accounting-runtime.v1",
        "planning_contract_usage": "pure_batch_planning_only",
        "host_runtime": {
            "description": (
                "scripts/runtime/remote_access_plugin_host.py is the sole "
                "production runtime owner for this RADIUS component; it is "
                "a long-running process, supervised and autostarted by "
                "worker_supervisor.py, and runs bounded acquisition cycles "
                "indefinitely until stopped."
            ),
            "runtime_owner": "scripts/runtime/remote_access_plugin_host.py",
            "sole_runtime_owner": True,
            "long_running_supervised_host": True,
            "autostart_enabled": True,
            "supervised_by": "worker_supervisor.py",
        },
        "lease": {
            "description": (
                "Each acquisition cycle acquires exactly one bounded "
                "Postgres credential/activation lease via "
                "bounded_manual_activation(); it is created fresh, "
                "authorizes exactly one bounded worker invocation, and is "
                "torn down before the cycle ends regardless of outcome. A "
                "lease never itself grants a continuous worker, process "
                "autostart, or admin database access."
            ),
            "activation_mode": "single_invocation_per_lease",
            "maximum_runs_per_invocation": 1,
            "maximum_records_per_run": 1000,
            "maximum_runtime_seconds": 120,
            "ephemeral_login": {
                "role_prefix": ROLE_PREFIX,
                "member_of": WORKER_ROLE,
                "inherit": False,
                "drop_after_run": True,
            },
            "activation_state_during_run": "manual_enabled",
            "required_final_state": "disabled",
            "failure_protocol": [
                "disable_source_and_subscription",
                "drop_ephemeral_login",
                "preserve_published_evidence_for_idempotent_retry",
            ],
            "continuous_worker_enabled": False,
            "worker_autostart_enabled": False,
            "worker_admin_db_access_enabled": False,
            "prohibited_actions": [
                "continuous_worker",
                "autostart",
                "admin_dsn_for_worker",
                "identity_spine_select_grant",
                "source_configuration_change",
                "cursor_rewind",
                "evidence_delete",
            ],
        },
    }
    if value != expected:
        raise RadiusManualControlError("manual_contract_mismatch")
    return value


def inspect_manual_state(conn: Any) -> RadiusManualState:
    """Read the exact activation/cursor state without changing it."""

    source_id, subscription_id = _registration_identity()
    with conn.transaction():
        with conn.cursor() as cur:
            cur.execute("set transaction read only")
            cur.execute(
                """
                select
                  s.desired_activation,
                  sub.desired_activation,
                  c.revision,
                  exists(
                    select 1 from schema_migrations
                    where version=58
                      and name='radius_accounting_transaction_foundation'
                  ),
                  exists(
                    select 1 from schema_migrations
                    where version=59
                      and name='radius_identity_spine_resolver'
                  )
                from acquisition_source_instances s
                join acquisition_stream_cursors c
                  on c.source_instance_id=s.source_instance_id
                join acquisition_consumer_subscriptions sub
                  on sub.source_instance_id=c.source_instance_id
                 and sub.stream_id=c.stream_id
                 and sub.transport_binding=c.transport_binding
                where s.source_instance_id=%s
                  and sub.subscription_id=%s
                """,
                (source_id, subscription_id),
            )
            row = cur.fetchone()
    if row is None:
        raise RadiusManualControlError("manual_registration_not_found")
    return RadiusManualState(
        source_activation=str(row[0]),
        subscription_activation=str(row[1]),
        cursor_revision=int(row[2]),
        migration_58=bool(row[3]),
        migration_59=bool(row[4]),
    )


def require_ready_disabled(state: RadiusManualState) -> None:
    if not state.migration_58 or not state.migration_59:
        raise RadiusManualControlError("manual_required_migration_missing")
    if (
        state.source_activation != "disabled"
        or state.subscription_activation != "disabled"
    ):
        raise RadiusManualControlError("manual_activation_not_disabled")


def lock_ephemeral_database_connect_acl(cur: Any) -> None:
    """Serialize RADIUS ephemeral-role DDL around the database ACL catalog row."""
    cur.execute("set local lock_timeout='5s'")
    cur.execute(
        "select pg_advisory_xact_lock(hashtext(%s))",
        (EPHEMERAL_DATABASE_CONNECT_ACL_LOCK,),
    )


def _create_ephemeral_login(conn: Any) -> tuple[str, str]:
    from psycopg import sql

    role = f"{ROLE_PREFIX}{secrets.token_hex(8)}"
    password = secrets.token_urlsafe(36)
    with conn.transaction():
        with conn.cursor() as cur:
            lock_ephemeral_database_connect_acl(cur)
            cur.execute(
                sql.SQL(
                    "create role {} login noinherit nosuperuser nocreatedb "
                    "nocreaterole nobypassrls noreplication password {}"
                ).format(sql.Identifier(role), sql.Literal(password))
            )
            cur.execute(
                sql.SQL("grant {} to {}").format(
                    sql.Identifier(WORKER_ROLE),
                    sql.Identifier(role),
                )
            )
            database_name = str(cur.connection.info.dbname or "").strip()
            if not database_name:
                raise RadiusManualControlError("manual_database_identity_required")
            cur.execute(
                sql.SQL("grant connect on database {} to {}").format(
                    sql.Identifier(database_name),
                    sql.Identifier(role),
                )
            )
    return role, password


def _set_activation(conn: Any, target: str) -> None:
    if target not in {"disabled", "manual_enabled"}:
        raise RadiusManualControlError("manual_activation_target_invalid")
    source_id, subscription_id = _registration_identity()
    with conn.transaction():
        with conn.cursor() as cur:
            cur.execute("set local lock_timeout='5s'")
            cur.execute("set local statement_timeout='15s'")
            cur.execute("set local role adlog_storage_owner")
            cur.execute(
                """
                select s.desired_activation,sub.desired_activation
                from acquisition_source_instances s
                join acquisition_consumer_subscriptions sub
                  on sub.source_instance_id=s.source_instance_id
                where s.source_instance_id=%s
                  and sub.subscription_id=%s
                for update of s,sub
                """,
                (source_id, subscription_id),
            )
            row = cur.fetchone()
            if row is None:
                raise RadiusManualControlError(
                    "manual_registration_not_found"
                )
            current = (str(row[0]), str(row[1]))
            if target == "manual_enabled" and current != (
                "disabled",
                "disabled",
            ):
                raise RadiusManualControlError(
                    "manual_activation_not_disabled"
                )
            cur.execute(
                """
                update acquisition_source_instances
                set desired_activation=%s,updated_at=now()
                where source_instance_id=%s
                """,
                (target, source_id),
            )
            if cur.rowcount != 1:
                raise RadiusManualControlError(
                    "manual_source_activation_failed"
                )
            cur.execute(
                """
                update acquisition_consumer_subscriptions
                set desired_activation=%s
                where subscription_id=%s
                  and source_instance_id=%s
                """,
                (target, subscription_id, source_id),
            )
            if cur.rowcount != 1:
                raise RadiusManualControlError(
                    "manual_subscription_activation_failed"
                )


def _drop_ephemeral_login(conn: Any, role: str) -> None:
    from psycopg import sql

    if _ROLE_NAME.fullmatch(str(role)) is None:
        raise RadiusManualControlError("manual_login_role_name_invalid")
    with conn.transaction():
        with conn.cursor() as cur:
            lock_ephemeral_database_connect_acl(cur)
            database_name = str(cur.connection.info.dbname or "").strip()
            if not database_name:
                raise RadiusManualControlError("manual_database_identity_required")
            cur.execute(
                sql.SQL("revoke connect on database {} from {}").format(
                    sql.Identifier(database_name),
                    sql.Identifier(role),
                )
            )
            cur.execute(
                sql.SQL("drop role if exists {}").format(
                    sql.Identifier(role)
                )
            )


@contextmanager
def bounded_manual_activation(
    conn: Any,
    *,
    contract: Mapping[str, Any] | None = None,
) -> Iterator[RadiusManualLease]:
    """Open exactly one manual activation scope and always close it."""

    value = validate_manual_control_contract(
        contract or load_manual_control_contract()
    )
    require_ready_disabled(inspect_manual_state(conn))
    role = ""
    activated = False
    try:
        role, password = _create_ephemeral_login(conn)
        _set_activation(conn, "manual_enabled")
        activated = True
        yield RadiusManualLease(
            login_role=role,
            password=password,
            source_instance_id=str(value["source_instance_id"]),
            subscription_id=str(value["subscription_id"]),
            maximum_records=int(value["lease"]["maximum_records_per_run"]),
            maximum_runtime_seconds=int(
                value["lease"]["maximum_runtime_seconds"]
            ),
        )
    finally:
        cleanup_error: Exception | None = None
        if activated:
            try:
                _set_activation(conn, "disabled")
            except Exception as exc:  # noqa: BLE001
                cleanup_error = exc
        if role:
            try:
                _drop_ephemeral_login(conn, role)
            except Exception as exc:  # noqa: BLE001
                cleanup_error = cleanup_error or exc
        if cleanup_error is not None:
            raise RadiusManualControlError(
                "manual_cleanup_failed"
            ) from cleanup_error


def run_one_bounded_operation(
    conn: Any,
    operation: Callable[[RadiusManualLease], Any],
    *,
    contract: Mapping[str, Any] | None = None,
) -> Any:
    """Run one caller-supplied bounded operation inside the manual scope."""

    with bounded_manual_activation(conn, contract=contract) as lease:
        return operation(lease)

from __future__ import annotations

"""Durable outbox consumer for the RADIUS VPN session read model.

The consumer reads only typed immutable observations.  It never opens the
RADIUS source or core evidence objects.  Projection rebuild and delivery
completion are committed atomically under a dedicated least-privilege role.
"""

from dataclasses import dataclass
from datetime import datetime
import json
from pathlib import Path
import re
from typing import Any, Mapping
from uuid import UUID, uuid4

from server.source_packs.radius.session_read_model import (
    CONTRACT_ID as READ_MODEL_CONTRACT_ID,
    RadiusLifecycleInput,
    fold_radius_sessions,
)


ROOT = Path(__file__).resolve().parents[3]
CONTRACT_PATH = ROOT / "config/stage9_radius_session_consumer_v1.json"
CONTRACT_ID = "sli.radius-session-consumer.v1"
CONSUMER_ROLE = "adlog_radius_session_consumer"
_ERROR_CODE = re.compile(r"^[a-z][a-z0-9_]{0,119}$")
_SESSION_KEY = re.compile(r"^radius-session:[0-9a-f]{64}$")


class RadiusSessionConsumerError(ValueError):
    """Closed-code consumer error safe for operator evidence."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class ClaimedRadiusDelivery:
    delivery_id: int
    observation_id: UUID
    evidence_uid: UUID
    lease_token: UUID
    attempt_count: int


@dataclass(frozen=True)
class RadiusDeliveryReceipt:
    delivery_id: int
    observation_id: UUID
    outcome: str
    projected_row_count: int


@dataclass(frozen=True)
class ReconciledRadiusProjection:
    """One delivered observation whose append-only overlay is exact."""

    delivery_id: int
    session_identity_key: str


def load_consumer_contract(
    path: Path | None = None,
    *,
    subscription_id: str | None = None,
) -> dict[str, Any]:
    use_template = path is None
    path = path or CONTRACT_PATH
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RadiusSessionConsumerError(
            "consumer_contract_invalid"
        ) from exc
    if not isinstance(value, dict):
        raise RadiusSessionConsumerError(
            "consumer_contract_object_required"
        )
    if subscription_id is not None:
        if not isinstance(subscription_id, str) or not 1 <= len(subscription_id) <= 512:
            raise RadiusSessionConsumerError("consumer_subscription_invalid")
        value["subscription_id"] = subscription_id
    elif use_template:
        from server.source_packs.radius.accounting_registration import (
            load_registration_contract,
        )

        value["subscription_id"] = load_registration_contract()["subscription"]["subscription_id"]
    expected = {
        "schema_version": 1,
        "contract_id": CONTRACT_ID,
        "status": "prepared_disabled_only",
        "required_migration": 61,
        "consumer_role": CONSUMER_ROLE,
        "read_model_contract_id": READ_MODEL_CONTRACT_ID,
        "resource_group": "vpn.sessions",
        "maximum_deliveries_per_claim": 50,
        "maximum_observations_per_session_key": 10000,
        "lease_seconds": 120,
        "maximum_attempts": 5,
        "runtime_enabled": False,
        "autostart_enabled": False,
        "production_migration_applied": False,
        "source_contact_allowed": False,
    }
    for key, expected_value in expected.items():
        if value.get(key) != expected_value:
            raise RadiusSessionConsumerError(
                f"consumer_contract_{key}_invalid"
            )
    if set(value.get("outcomes") or []) != {
        "projected",
        "identity_unresolved",
        "timestamp_unresolved",
    }:
        raise RadiusSessionConsumerError(
            "consumer_contract_outcomes_invalid"
        )
    return value


def claim_radius_deliveries(
    conn: Any,
    *,
    limit: int = 50,
    contract: Mapping[str, Any] | None = None,
    activate_role: bool = True,
    delivery_ids: tuple[int, ...] | None = None,
) -> tuple[ClaimedRadiusDelivery, ...]:
    """Lease a bounded batch without holding DB locks during processing."""

    validated = dict(contract or load_consumer_contract())
    if activate_role:
        _validate_contract(validated)
    else:
        _validate_contract(validated, subscription_id=validated["subscription_id"])
    clean_limit = int(limit)
    maximum = int(validated["maximum_deliveries_per_claim"])
    if not 1 <= clean_limit <= maximum:
        raise RadiusSessionConsumerError("claim_limit_invalid")
    if delivery_ids is not None and (
        len(delivery_ids) > maximum or len(set(delivery_ids)) != len(delivery_ids)
        or any(type(item) is not int or _positive_id(item) != item for item in delivery_ids)
    ):
        raise RadiusSessionConsumerError("claim_ids_invalid")
    lease_token = uuid4()
    id_filter = "and delivery_id=any(%s)" if delivery_ids is not None else ""
    id_parameters = (list(delivery_ids),) if delivery_ids is not None else ()
    with conn.transaction():
        with conn.cursor() as cur:
            if activate_role:
                _activate_consumer_role(cur)
            cur.execute(
                """
                update acquisition_delivery_outbox
                set delivery_state='quarantined',
                    lease_token=null,lease_until=null,heartbeat_at=now(),
                    last_error_code='maximum_attempts_exhausted',
                    updated_at=now()
                where subscription_id=%s
                  and attempt_count >= %s
                  and (
                    delivery_state='failed'
                    or (
                      delivery_state='leased'
                      and lease_until<=now()
                    )
                  )
                """,
                (
                    validated["subscription_id"],
                    int(validated["maximum_attempts"]),
                ),
            )
            cur.execute(
                f"""
                with candidates as (
                  select delivery_id
                  from acquisition_delivery_outbox
                  where subscription_id=%s
                    and attempt_count < %s
                    and available_at<=now()
                    {id_filter}
                    and (
                      delivery_state in ('queued','failed')
                      or (
                        delivery_state='leased'
                        and lease_until<=now()
                      )
                    )
                  order by available_at,created_at,delivery_id
                  for update skip locked
                  limit %s
                )
                update acquisition_delivery_outbox delivery
                set delivery_state='leased',
                    attempt_count=delivery.attempt_count+1,
                    lease_token=%s,
                    lease_until=now()+(%s * interval '1 second'),
                    heartbeat_at=now(),
                    last_error_code=null,
                    updated_at=now()
                from candidates
                where delivery.delivery_id=candidates.delivery_id
                returning delivery.delivery_id,delivery.observation_id,
                          delivery.evidence_uid,delivery.attempt_count
                """,
                (
                    validated["subscription_id"],
                    int(validated["maximum_attempts"]),
                    *id_parameters,
                    clean_limit,
                    lease_token,
                    int(validated["lease_seconds"]),
                ),
            )
            rows = tuple(cur.fetchall())
    return tuple(
        ClaimedRadiusDelivery(
            delivery_id=int(row[0]),
            observation_id=UUID(str(row[1])),
            evidence_uid=UUID(str(row[2])),
            lease_token=lease_token,
            attempt_count=int(row[3]),
        )
        for row in rows
    )


def heartbeat_radius_delivery(
    conn: Any,
    *,
    delivery_id: int,
    lease_token: UUID,
    contract: Mapping[str, Any] | None = None,
) -> None:
    validated = dict(contract or load_consumer_contract())
    _validate_contract(validated)
    with conn.transaction():
        with conn.cursor() as cur:
            _activate_consumer_role(cur)
            cur.execute(
                """
                update acquisition_delivery_outbox
                set heartbeat_at=now(),
                    lease_until=now()+(%s * interval '1 second'),
                    updated_at=now()
                where delivery_id=%s and delivery_state='leased'
                  and lease_token=%s and lease_until>now()
                """,
                (
                    int(validated["lease_seconds"]),
                    _positive_id(delivery_id),
                    lease_token,
                ),
            )
            if cur.rowcount != 1:
                raise RadiusSessionConsumerError(
                    "delivery_lease_lost"
                )


def process_radius_delivery(
    conn: Any,
    *,
    delivery_id: int,
    lease_token: UUID,
    contract: Mapping[str, Any] | None = None,
    activate_role: bool = True,
    record_budget: list[int] | None = None,
) -> RadiusDeliveryReceipt:
    """Apply one leased delivery and mark it delivered atomically."""

    validated = dict(contract or load_consumer_contract())
    if activate_role:
        _validate_contract(validated)
    else:
        _validate_contract(validated, subscription_id=validated["subscription_id"])
    clean_delivery_id = _positive_id(delivery_id)
    with conn.transaction():
        with conn.cursor() as cur:
            if activate_role:
                _activate_consumer_role(cur)
            cur.execute(
                """
                select delivery.delivery_id,delivery.observation_id,
                       observation.identity_state,
                       observation.timestamp_state,
                       observation.session_identity_key
                from acquisition_delivery_outbox delivery
                join radius_accounting_session_observations observation
                  on observation.observation_id=delivery.observation_id
                where delivery.delivery_id=%s
                  and delivery.subscription_id=%s
                  and delivery.delivery_state='leased'
                  and delivery.lease_token=%s
                  and delivery.lease_until>now()
                for update of delivery
                """,
                (
                    clean_delivery_id,
                    validated["subscription_id"],
                    lease_token,
                ),
            )
            delivery = cur.fetchone()
            if delivery is None:
                raise RadiusSessionConsumerError(
                    "delivery_lease_lost"
                )
            observation_id = UUID(str(delivery[1]))
            identity_state = str(delivery[2])
            timestamp_state = str(delivery[3])
            session_key = str(delivery[4] or "").strip() or None

            cur.execute(
                """
                select outcome,projected_row_count
                from radius_session_projection_receipts
                where delivery_id=%s
                """,
                (clean_delivery_id,),
            )
            prior = cur.fetchone()
            if prior is not None:
                outcome = str(prior[0])
                projected_count = int(prior[1])
            elif identity_state != "exact":
                outcome = "identity_unresolved"
                projected_count = 0
            elif timestamp_state != "ready":
                outcome = "timestamp_unresolved"
                projected_count = 0
            else:
                if session_key is None:
                    raise RadiusSessionConsumerError(
                        "exact_session_key_required"
                    )
                cur.execute(
                    "select pg_advisory_xact_lock("
                    "hashtext('radius-session-projection:'||%s))",
                    (session_key,),
                )
                projection_rows = _rebuild_session_projection(
                    cur,
                    session_key=session_key,
                    current_delivery_id=clean_delivery_id,
                    subscription_id=str(
                        validated["subscription_id"]
                    ),
                    maximum_observations=int(
                        validated[
                            "maximum_observations_per_session_key"
                        ]
                    ),
                    record_budget=record_budget,
                )
                outcome = "projected"
                projected_count = projection_rows
            if prior is None:
                cur.execute(
                    """
                    insert into radius_session_projection_receipts(
                      delivery_id,observation_id,outcome,
                      projected_row_count,consumer_contract_id
                    ) values(%s,%s,%s,%s,%s)
                    """,
                    (
                        clean_delivery_id,
                        observation_id,
                        outcome,
                        projected_count,
                        CONTRACT_ID,
                    ),
                )
            cur.execute(
                """
                update acquisition_delivery_outbox
                set delivery_state='delivered',delivered_at=now(),
                    lease_token=null,lease_until=null,heartbeat_at=now(),
                    last_error_code=null,updated_at=now()
                where delivery_id=%s and delivery_state='leased'
                  and lease_token=%s
                """,
                (clean_delivery_id, lease_token),
            )
            if cur.rowcount != 1:
                raise RadiusSessionConsumerError(
                    "delivery_lease_lost"
                )
    return RadiusDeliveryReceipt(
        delivery_id=clean_delivery_id,
        observation_id=observation_id,
        outcome=outcome,
        projected_row_count=projected_count,
    )


def fail_radius_delivery(
    conn: Any,
    *,
    delivery_id: int,
    lease_token: UUID,
    error_code: str,
    retry_delay_seconds: int = 30,
    contract: Mapping[str, Any] | None = None,
) -> str:
    """Release a lease to bounded retry or terminal quarantine."""

    validated = dict(contract or load_consumer_contract())
    _validate_contract(validated)
    code = str(error_code or "").strip()
    if _ERROR_CODE.fullmatch(code) is None:
        raise RadiusSessionConsumerError("error_code_invalid")
    delay = int(retry_delay_seconds)
    if not 0 <= delay <= 3600:
        raise RadiusSessionConsumerError("retry_delay_invalid")
    with conn.transaction():
        with conn.cursor() as cur:
            _activate_consumer_role(cur)
            cur.execute(
                """
                update acquisition_delivery_outbox
                set delivery_state=case
                      when attempt_count >= %s
                      then 'quarantined' else 'failed' end,
                    available_at=case
                      when attempt_count >= %s then now()
                      else now()+(%s * interval '1 second') end,
                    lease_token=null,lease_until=null,heartbeat_at=now(),
                    last_error_code=%s,updated_at=now()
                where delivery_id=%s and delivery_state='leased'
                  and lease_token=%s
                returning delivery_state
                """,
                (
                    int(validated["maximum_attempts"]),
                    int(validated["maximum_attempts"]),
                    delay,
                    code,
                    _positive_id(delivery_id),
                    lease_token,
                ),
            )
            row = cur.fetchone()
            if row is None:
                raise RadiusSessionConsumerError(
                    "delivery_lease_lost"
                )
            return str(row[0])


def rebuild_reconciled_radius_projections(
    conn: Any,
    *,
    subscription_id: str,
    projections: tuple[ReconciledRadiusProjection, ...],
    contract: Mapping[str, Any] | None = None,
) -> int:
    """Rebuild bounded derived rows without leasing or updating a delivery."""

    validated = dict(contract or load_consumer_contract())
    _validate_contract(validated)
    clean_subscription = str(subscription_id or "").strip()
    if clean_subscription != str(validated["subscription_id"]):
        raise RadiusSessionConsumerError("reconciliation_subscription_invalid")
    values = tuple(projections)
    maximum = int(validated["maximum_deliveries_per_claim"])
    if not 1 <= len(values) <= maximum:
        raise RadiusSessionConsumerError("reconciliation_projection_count_invalid")
    seen: set[tuple[int, str]] = set()
    normalized: list[ReconciledRadiusProjection] = []
    for value in values:
        delivery_id = _positive_id(value.delivery_id)
        session_key = str(value.session_identity_key or "").strip()
        if _SESSION_KEY.fullmatch(session_key) is None:
            raise RadiusSessionConsumerError("reconciliation_session_key_invalid")
        identity = (delivery_id, session_key)
        if identity in seen:
            raise RadiusSessionConsumerError("reconciliation_projection_duplicate")
        seen.add(identity)
        normalized.append(ReconciledRadiusProjection(delivery_id, session_key))

    rebuilt = 0
    with conn.transaction():
        with conn.cursor() as cur:
            _activate_consumer_role(cur)
            for value in sorted(
                normalized,
                key=lambda item: (item.session_identity_key, item.delivery_id),
            ):
                cur.execute(
                    "select pg_advisory_xact_lock("
                    "hashtext('radius-session-projection:'||%s))",
                    (value.session_identity_key,),
                )
                rebuilt += _rebuild_session_projection(
                    cur,
                    session_key=value.session_identity_key,
                    current_delivery_id=value.delivery_id,
                    subscription_id=clean_subscription,
                    maximum_observations=int(
                        validated["maximum_observations_per_session_key"]
                    ),
                )
    return rebuilt


def _rebuild_session_projection(
    cur: Any,
    *,
    session_key: str,
    current_delivery_id: int,
    subscription_id: str,
    maximum_observations: int,
    record_budget: list[int] | None = None,
) -> int:
    if record_budget is not None:
        if len(record_budget) != 1 or record_budget[0] < 0:
            raise RadiusSessionConsumerError("session_record_budget_invalid")
        maximum_observations = min(maximum_observations, record_budget[0])
    cur.execute(
        """
        select coalesce(
          has_table_privilege(
            current_user,
            to_regclass('public.radius_session_identity_overlays'),
            'SELECT'
          ),
          false
        )
        """
    )
    overlay_readable = bool(cur.fetchone()[0])
    if overlay_readable:
        observation_query = """
        select observation.observation_id::text,
               observation.lifecycle_event,
               case
                 when overlay.observation_id is not null then 'exact'
                 else observation.identity_state
               end as identity_state,
               observation.timestamp_state,
               coalesce(
                 overlay.session_identity_key,
                 observation.session_identity_key
               ) as session_identity_key,
               coalesce(
                 overlay.exact_principal_key,
                 observation.exact_principal_key
               ) as exact_principal_key,
               observation.observed_at_utc,
               manifest.canonical_record_sha256
        from acquisition_delivery_outbox delivery
        join radius_accounting_session_observations observation
          on observation.observation_id=delivery.observation_id
        join core_evidence_manifests manifest
          on manifest.evidence_uid=observation.evidence_uid
        left join radius_session_identity_overlays overlay
          on overlay.observation_id=observation.observation_id
        where delivery.subscription_id=%s
          and coalesce(
            overlay.session_identity_key,
            observation.session_identity_key
          )=%s
          and observation.timestamp_state='ready'
          and (
            observation.identity_state='exact'
            or overlay.observation_id is not null
          )
          and (
            delivery.delivery_state='delivered'
            or delivery.delivery_id=%s
          )
        order by observation.observed_at_utc,
                 observation.observation_id
        limit %s
        """
    else:
        observation_query = """
        select observation.observation_id::text,
               observation.lifecycle_event,
               observation.identity_state,
               observation.timestamp_state,
               observation.session_identity_key,
               observation.exact_principal_key,
               observation.observed_at_utc,
               manifest.canonical_record_sha256
        from acquisition_delivery_outbox delivery
        join radius_accounting_session_observations observation
          on observation.observation_id=delivery.observation_id
        join core_evidence_manifests manifest
          on manifest.evidence_uid=observation.evidence_uid
        where delivery.subscription_id=%s
          and observation.session_identity_key=%s
          and observation.timestamp_state='ready'
          and observation.identity_state='exact'
          and (
            delivery.delivery_state='delivered'
            or delivery.delivery_id=%s
          )
        order by observation.observed_at_utc,
                 observation.observation_id
        limit %s
        """
    cur.execute(
        observation_query,
        (
            subscription_id,
            session_key,
            current_delivery_id,
            maximum_observations + 1,
        ),
    )
    rows = tuple(cur.fetchall())
    if len(rows) > maximum_observations:
        raise RadiusSessionConsumerError(
            "session_observation_limit_exceeded"
        )
    if record_budget is not None:
        record_budget[0] -= len(rows)
    inputs = tuple(
        RadiusLifecycleInput(
            observation_id=str(row[0]),
            lifecycle_event=str(row[1]),
            identity_state=str(row[2]),
            timestamp_state=str(row[3]),
            session_identity_key=(
                str(row[4]) if row[4] is not None else None
            ),
            exact_principal_key=(
                str(row[5]) if row[5] is not None else None
            ),
            observed_at_utc=(
                row[6] if isinstance(row[6], datetime) else str(row[6])
            ),
            evidence_sha256=str(row[7]),
        )
        for row in rows
    )
    folded = fold_radius_sessions(inputs)
    cur.execute(
        """
        delete from radius_vpn_session_projection
        where session_identity_key=%s
        """,
        (session_key,),
    )
    for row in folded.sessions:
        cur.execute(
            """
            insert into radius_vpn_session_projection(
              session_row_id,session_identity_key,exact_principal_key,
              generation,lifecycle_state,completeness,
              started_at_utc,last_observed_at_utc,stopped_at_utc,
              duration_seconds,observation_count,anomalies,
              read_model_contract_id,updated_at
            ) values(
              %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,now()
            )
            """,
            (
                row.session_row_id,
                row.session_identity_key,
                row.exact_principal_key,
                row.generation,
                row.lifecycle_state,
                row.completeness,
                row.started_at_utc,
                row.last_observed_at_utc,
                row.stopped_at_utc,
                row.duration_seconds,
                row.observation_count,
                list(row.anomalies),
                READ_MODEL_CONTRACT_ID,
            ),
        )
    return len(folded.sessions)


def _activate_consumer_role(cur: Any) -> None:
    cur.execute("set local role adlog_radius_session_consumer")


def _validate_contract(contract: Mapping[str, Any], *, subscription_id: str | None = None) -> None:
    expected = load_consumer_contract() if subscription_id is None else load_consumer_contract(subscription_id=subscription_id)
    if dict(contract) != expected:
        raise RadiusSessionConsumerError("consumer_contract_mismatch")


def _positive_id(value: int) -> int:
    clean = int(value)
    if clean <= 0:
        raise RadiusSessionConsumerError("delivery_id_invalid")
    return clean

from __future__ import annotations

"""PostgreSQL transaction boundary for the Stage 9 RADIUS pilot.

The module never opens a RADIUS source and never starts a worker.  It accepts
an already validated :class:`RadiusBatchPlan` plus externally persisted and
verified evidence references, then commits evidence, typed observations,
consumer outbox rows, the hashed Class cache and the acquisition cursor in one
database transaction.
"""

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any, Iterable, Mapping
from uuid import UUID, uuid5

from server.source_packs.radius.accounting_runtime_contract import (
    CONTRACT_ID as RUNTIME_CONTRACT_ID,
    RadiusBatchPlan,
    RadiusClassCacheEntry,
    RadiusFileCursor,
)


ROOT = Path(__file__).resolve().parents[3]
CONTRACT_PATH = ROOT / "config" / "stage9_radius_postgres_contract_v1.json"
POSTGRES_CONTRACT_ID = "sli.radius-accounting-postgres.v1"
WORKER_ROLE = "adlog_radius_accounting_worker"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_EVIDENCE_REFERENCE = re.compile(r"^evidence:[A-Za-z0-9_.:-]{1,500}$")


class RadiusPostgresContractError(ValueError):
    """Closed-code persistence failure safe for aggregate diagnostics."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class RadiusEvidenceObject:
    """One verified core-owned evidence object; no raw record is accepted."""

    evidence_uid: UUID
    canonical_record_sha256: str
    object_reference: str
    object_sha256: str
    object_size_bytes: int
    verified_at_utc: datetime


@dataclass(frozen=True)
class RadiusPostgresRuntimeState:
    cursor_epoch: UUID
    revision: int
    cursor: RadiusFileCursor
    class_cache: Mapping[str, RadiusClassCacheEntry]
    exact_boundary_recovery: bool = True


@dataclass(frozen=True)
class RadiusCommitReceipt:
    source_instance_id: str
    stream_id: str
    subscription_id: str
    evidence_rows: int
    observation_rows: int
    outbox_rows: int
    class_cache_rows: int
    cursor_revision: int
    cursor_file_generation: str
    cursor_byte_offset: int


def load_postgres_contract(path: Path = CONTRACT_PATH) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RadiusPostgresContractError("postgres_contract_invalid") from exc
    if not isinstance(value, dict):
        raise RadiusPostgresContractError(
            "postgres_contract_object_required"
        )
    if value.get("schema_version") != 1:
        raise RadiusPostgresContractError(
            "postgres_contract_schema_unsupported"
        )
    if value.get("contract_id") != POSTGRES_CONTRACT_ID:
        raise RadiusPostgresContractError(
            "postgres_contract_id_unexpected"
        )
    if value.get("status") != "accepted_for_disposable_only":
        raise RadiusPostgresContractError(
            "postgres_contract_disposable_only_required"
        )
    if value.get("runtime_enabled") is not False:
        raise RadiusPostgresContractError(
            "postgres_contract_runtime_must_be_disabled"
        )
    if value.get("production_migration_applied") is not False:
        raise RadiusPostgresContractError(
            "postgres_contract_production_must_be_false"
        )
    if value.get("source_contact_allowed") is not False:
        raise RadiusPostgresContractError(
            "postgres_contract_source_contact_must_be_false"
        )
    if int(value.get("maximum_records_per_commit") or 0) != 1000:
        raise RadiusPostgresContractError(
            "postgres_contract_batch_limit_invalid"
        )
    if int(value.get("maximum_evidence_object_bytes") or 0) != 65536:
        raise RadiusPostgresContractError(
            "postgres_contract_evidence_limit_invalid"
        )
    if set(value.get("forbidden_persisted_fields") or []) != {
        "raw_record",
        "class_attribute",
        "distinguished_name",
        "user_name",
        "account_session_id",
        "nas_identity",
    }:
        raise RadiusPostgresContractError(
            "postgres_contract_forbidden_fields_invalid"
        )
    protocol = list(value.get("commit_protocol") or [])
    if protocol != [
        "verified_evidence_manifest",
        "typed_session_observation",
        "consumer_outbox",
        "hashed_class_cache",
        "cursor_compare_and_swap",
    ]:
        raise RadiusPostgresContractError(
            "postgres_contract_commit_protocol_invalid"
        )
    return value


def load_runtime_state(
    conn: Any,
    *,
    subscription_id: str,
    contract: Mapping[str, Any] | None = None,
) -> RadiusPostgresRuntimeState:
    """Read one enabled subscription's locked-free planning snapshot."""

    validate = dict(contract or load_postgres_contract())
    _validate_postgres_contract(validate)
    with conn.transaction():
        with conn.cursor() as cur:
            _activate_worker_role(cur)
            cur.execute(
                """
                select
                  c.source_instance_id,c.stream_id,c.transport_binding,
                  c.cursor_epoch,c.file_generation,c.byte_offset,
                  c.last_record_sha256,c.revision,
                  s.desired_activation,sub.desired_activation,
                  c.previous_generation_last_record_sha256
                from acquisition_consumer_subscriptions sub
                join acquisition_stream_cursors c
                  on c.source_instance_id=sub.source_instance_id
                 and c.stream_id=sub.stream_id
                 and c.transport_binding=sub.transport_binding
                join acquisition_source_instances s
                  on s.source_instance_id=c.source_instance_id
                where sub.subscription_id=%s
                """,
                (subscription_id,),
            )
            row = cur.fetchone()
            if row is None:
                raise RadiusPostgresContractError(
                    "subscription_not_found"
                )
            if row[8] != "manual_enabled" or row[9] != "manual_enabled":
                raise RadiusPostgresContractError(
                    "subscription_not_manually_enabled"
                )
            cur.execute(
                """
                select class_scope_sha256,exact_principal_key,expires_at_utc
                from radius_accounting_class_cache
                where source_instance_id=%s and expires_at_utc>now()
                order by class_scope_sha256
                """,
                (row[0],),
            )
            cache = {
                str(item[0]): RadiusClassCacheEntry(
                    class_scope_sha256=str(item[0]),
                    exact_principal_key=str(item[1]),
                    expires_at_utc=_aware(item[2]).isoformat(),
                )
                for item in cur.fetchall()
            }
    return RadiusPostgresRuntimeState(
        cursor_epoch=UUID(str(row[3])),
        revision=int(row[7]),
        cursor=RadiusFileCursor(
            source_instance_id=str(row[0]),
            stream_id=str(row[1]),
            transport_binding=str(row[2]),
            file_generation=str(row[4]),
            byte_offset=int(row[5]),
            last_record_sha256=(
                str(row[6]) if row[6] is not None else None
            ),
        ),
        class_cache=cache,
        # Equal historical/current hashes cannot prove a new-generation anchor.
        # Repeated identical real rows remain conservatively nonrecoverable if
        # that generation disappears; exact-generation reads are unaffected.
        exact_boundary_recovery=(row[6] is not None and (row[10] is None or str(row[6]) != str(row[10]))),
    )


def commit_radius_batch(
    conn: Any,
    *,
    subscription_id: str,
    cursor_epoch: UUID,
    expected_revision: int,
    plan: RadiusBatchPlan,
    evidence_objects: Iterable[RadiusEvidenceObject],
    fail_after: str | None = None,
    contract: Mapping[str, Any] | None = None,
) -> RadiusCommitReceipt:
    """Commit one bounded batch atomically under the dedicated worker role."""

    validated = dict(contract or load_postgres_contract())
    _validate_postgres_contract(validated)
    evidence = tuple(evidence_objects)
    _validate_batch(plan, evidence, validated)
    if fail_after not in {None, "evidence", "outbox", "cache"}:
        raise RadiusPostgresContractError("failure_phase_invalid")

    with conn.transaction():
        with conn.cursor() as cur:
            _activate_worker_role(cur)
            row = _lock_cursor(
                cur,
                subscription_id=subscription_id,
                plan=plan,
            )
            _require_current_cursor(
                row,
                plan=plan,
                cursor_epoch=cursor_epoch,
                expected_revision=expected_revision,
            )
            for ordinal, item in enumerate(evidence):
                cur.execute(
                    """
                    insert into core_evidence_manifests(
                      evidence_uid,source_instance_id,stream_id,
                      transport_binding,cursor_epoch,file_generation,
                      cursor_start_byte_offset,batch_record_ordinal,
                      canonical_record_sha256,object_reference,object_sha256,
                      object_size_bytes,verified_at_utc
                    ) values(
                      %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s
                    )
                    """,
                    (
                        item.evidence_uid,
                        plan.current_cursor.source_instance_id,
                        plan.current_cursor.stream_id,
                        plan.current_cursor.transport_binding,
                        cursor_epoch,
                        plan.next_cursor.file_generation,
                        plan.current_cursor.byte_offset,
                        ordinal,
                        item.canonical_record_sha256,
                        item.object_reference,
                        item.object_sha256,
                        item.object_size_bytes,
                        _aware(item.verified_at_utc),
                    ),
                )
            if fail_after == "evidence":
                raise RuntimeError("injected_after_evidence")

            by_hash: dict[str, deque[RadiusEvidenceObject]] = defaultdict(
                deque
            )
            for item in evidence:
                by_hash[item.canonical_record_sha256].append(item)
            observation_rows = 0
            outbox_rows = 0
            for observation in plan.session_observations:
                candidates = by_hash[observation.canonical_record_sha256]
                if not candidates:
                    raise RadiusPostgresContractError(
                        "observation_evidence_missing"
                    )
                item = candidates.popleft()
                observation_id = uuid5(
                    item.evidence_uid,
                    "sli.radius-accounting-session-observation.v1",
                )
                identity_state = (
                    "exact"
                    if observation.session_identity_ready
                    else "unresolved"
                )
                timestamp_state = (
                    "ready" if observation.timestamp_ready else "unresolved"
                )
                provenance = json.dumps(
                    {
                        "adapter_contract_id": (
                            observation.adapter_contract_id
                        ),
                        "postgres_contract_id": POSTGRES_CONTRACT_ID,
                        "runtime_contract_id": RUNTIME_CONTRACT_ID,
                        "source_instance_id": (
                            observation.source_instance_id
                        ),
                        "canonical_record_sha256": (
                            observation.canonical_record_sha256
                        ),
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                cur.execute(
                    """
                    insert into radius_accounting_session_observations(
                      observation_id,evidence_uid,lifecycle_event,
                      session_identity_key,exact_principal_key,identity_state,
                      observed_at_utc,timestamp_basis,timestamp_state,
                      session_confirmed_by_accounting,producer_contract_id,
                      resource_groups,row_sensitivity,field_categories,
                      evidence_access_requirement,label_policy_version,
                      provenance_json
                    ) values(
                      %s,%s,%s,%s,%s,%s,%s,%s,%s,true,%s,%s,%s,%s,%s,%s,
                      %s::jsonb
                    )
                    """,
                    (
                        observation_id,
                        item.evidence_uid,
                        observation.lifecycle_event,
                        observation.session_identity_key,
                        observation.exact_principal_key,
                        identity_state,
                        observation.observed_at_utc,
                        observation.timestamp_basis,
                        timestamp_state,
                        observation.adapter_contract_id,
                        ["vpn.sessions"],
                        "restricted",
                        ["identity", "authentication", "network"],
                        "vpn.session.evidence.read",
                        "sli.access-labels.v1",
                        provenance,
                    ),
                )
                observation_rows += 1
                idempotency_key = sha256(
                    (
                        f"{subscription_id}\0{observation_id}\0"
                        f"{RUNTIME_CONTRACT_ID}"
                    ).encode("utf-8")
                ).hexdigest()
                cur.execute(
                    """
                    insert into acquisition_delivery_outbox(
                      subscription_id,evidence_uid,observation_id,
                      idempotency_key
                    ) values(%s,%s,%s,%s)
                    """,
                    (
                        subscription_id,
                        item.evidence_uid,
                        observation_id,
                        idempotency_key,
                    ),
                )
                outbox_rows += 1
            if fail_after == "outbox":
                raise RuntimeError("injected_after_outbox")

            cur.execute(
                """
                delete from radius_accounting_class_cache
                where source_instance_id=%s and expires_at_utc<=now()
                """,
                (plan.current_cursor.source_instance_id,),
            )
            for key, entry in plan.proposed_class_cache.items():
                if key != entry.class_scope_sha256:
                    raise RadiusPostgresContractError(
                        "class_cache_key_mismatch"
                    )
                cur.execute(
                    """
                    insert into radius_accounting_class_cache(
                      source_instance_id,class_scope_sha256,
                      exact_principal_key,expires_at_utc
                    ) values(%s,%s,%s,%s)
                    on conflict(source_instance_id,class_scope_sha256)
                    do update set
                      exact_principal_key=excluded.exact_principal_key,
                      expires_at_utc=excluded.expires_at_utc,
                      updated_at=now()
                    """,
                    (
                        plan.current_cursor.source_instance_id,
                        key,
                        entry.exact_principal_key,
                        _parse_utc(entry.expires_at_utc),
                    ),
                )
            if fail_after == "cache":
                raise RuntimeError("injected_after_cache")

            _advance_cursor(cur, plan=plan, cursor_epoch=cursor_epoch, expected_revision=expected_revision)
    return RadiusCommitReceipt(
        source_instance_id=plan.current_cursor.source_instance_id,
        stream_id=plan.current_cursor.stream_id,
        subscription_id=subscription_id,
        evidence_rows=len(evidence),
        observation_rows=observation_rows,
        outbox_rows=outbox_rows,
        class_cache_rows=len(plan.proposed_class_cache),
        cursor_revision=expected_revision + 1,
        cursor_file_generation=plan.next_cursor.file_generation,
        cursor_byte_offset=plan.next_cursor.byte_offset,
    )


def commit_admitted_empty_radius_progress(
    conn: Any, *, subscription_id: str, cursor_epoch: UUID, expected_revision: int,
    current_cursor: RadiusFileCursor, next_cursor: RadiusFileCursor,
    skipped_bytes: int, physical_lines: int,
    maximum_physical_lines: int = 128,
) -> None:
    """Commit only admitted empty progress from an attested or local read.

    Agent callers must authenticate the accepted receipt and exact packet digest
    in the same inbox transaction. The legacy caller binds its local tail and
    explicitly retains its existing physical-line bound. This is not an
    evidence-batch escape hatch: it cannot publish evidence, observations,
    outbox rows or Class cache changes. Source whitespace/EOF remain assertions
    of the authenticated producer or the successful local tail read.
    """
    from sli_collect.radius_tail import MAXIMUM_READ_BYTES, MAXIMUM_RECORDS

    rotation = next_cursor.file_generation != current_cursor.file_generation
    start = 0 if rotation else current_cursor.byte_offset
    if (any(getattr(next_cursor, key) != getattr(current_cursor, key) for key in (
            "source_instance_id", "stream_id", "transport_binding", "last_record_sha256"))
            or type(skipped_bytes) is not int or type(physical_lines) is not int
            or type(maximum_physical_lines) is not int
            or not 1 <= maximum_physical_lines <= MAXIMUM_RECORDS
            or not 0 <= skipped_bytes <= MAXIMUM_READ_BYTES
            or not 0 <= physical_lines <= min(maximum_physical_lines, skipped_bytes)
            or bool(skipped_bytes) != bool(physical_lines)
            or type(next_cursor.byte_offset) is not int
            or not 0 <= next_cursor.byte_offset <= 2**63 - 1
            or next_cursor.byte_offset - start != skipped_bytes
            or not skipped_bytes and not rotation):
        raise RadiusPostgresContractError("empty_progress_invalid")
    plan = RadiusBatchPlan(RUNTIME_CONTRACT_ID, current_cursor, next_cursor, rotation, (), (), {}, {"records": 0})
    with conn.transaction(), conn.cursor() as cur:
        _activate_worker_role(cur)
        row = _lock_cursor(cur, subscription_id=subscription_id, plan=plan)
        _require_current_cursor(row, plan=plan, cursor_epoch=cursor_epoch, expected_revision=expected_revision)
        _advance_cursor(cur, plan=plan, cursor_epoch=cursor_epoch, expected_revision=expected_revision)


def _advance_cursor(cur, *, plan, cursor_epoch, expected_revision):
    cur.execute(
        """
        update acquisition_stream_cursors
        set file_generation=%s,
            byte_offset=%s,
            last_record_sha256=%s,
            previous_file_generation=case
              when %s then %s else previous_file_generation end,
            previous_generation_last_record_sha256=case
              when %s then %s
              else previous_generation_last_record_sha256 end,
            revision=revision+1,
            updated_at=now()
        where source_instance_id=%s and stream_id=%s
          and transport_binding=%s and cursor_epoch=%s
          and revision=%s and file_generation=%s
          and byte_offset=%s
          and last_record_sha256 is not distinct from %s
        """,
        (
            plan.next_cursor.file_generation,
            plan.next_cursor.byte_offset,
            plan.next_cursor.last_record_sha256,
            plan.rotation_from_eof,
            plan.current_cursor.file_generation,
            plan.rotation_from_eof,
            plan.current_cursor.last_record_sha256,
            plan.current_cursor.source_instance_id,
            plan.current_cursor.stream_id,
            plan.current_cursor.transport_binding,
            cursor_epoch,
            expected_revision,
            plan.current_cursor.file_generation,
            plan.current_cursor.byte_offset,
            plan.current_cursor.last_record_sha256,
        ),
    )
    if cur.rowcount != 1:
        raise RadiusPostgresContractError(
            "cursor_compare_and_swap_failed"
        )


def _validate_postgres_contract(contract: Mapping[str, Any]) -> None:
    loaded = load_postgres_contract()
    if dict(contract) != loaded:
        raise RadiusPostgresContractError("postgres_contract_mismatch")


def _validate_batch(
    plan: RadiusBatchPlan,
    evidence: tuple[RadiusEvidenceObject, ...],
    contract: Mapping[str, Any],
) -> None:
    if plan.contract_id != RUNTIME_CONTRACT_ID:
        raise RadiusPostgresContractError("runtime_contract_id_invalid")
    current = plan.current_cursor
    next_cursor = plan.next_cursor
    if (
        next_cursor.source_instance_id != current.source_instance_id
        or next_cursor.stream_id != current.stream_id
        or next_cursor.transport_binding != current.transport_binding
    ):
        raise RadiusPostgresContractError("cursor_owner_changed_in_batch")
    rotation = next_cursor.file_generation != current.file_generation
    if bool(plan.rotation_from_eof) != rotation:
        raise RadiusPostgresContractError("rotation_claim_mismatch")
    if not rotation and next_cursor.byte_offset < current.byte_offset:
        raise RadiusPostgresContractError("cursor_offset_regressed")
    maximum = int(contract["maximum_records_per_commit"])
    if not 0 < len(evidence) <= maximum:
        raise RadiusPostgresContractError("evidence_batch_size_invalid")
    if len(evidence) != len(plan.evidence_sha256):
        raise RadiusPostgresContractError("evidence_count_mismatch")
    seen: set[UUID] = set()
    maximum_bytes = int(contract["maximum_evidence_object_bytes"])
    for expected_hash, item in zip(plan.evidence_sha256, evidence):
        if item.evidence_uid in seen:
            raise RadiusPostgresContractError("evidence_uid_duplicate")
        seen.add(item.evidence_uid)
        if (
            not _SHA256.fullmatch(item.canonical_record_sha256)
            or item.canonical_record_sha256 != expected_hash
        ):
            raise RadiusPostgresContractError("evidence_hash_mismatch")
        if _EVIDENCE_REFERENCE.fullmatch(item.object_reference) is None:
            raise RadiusPostgresContractError(
                "evidence_reference_invalid"
            )
        if _SHA256.fullmatch(item.object_sha256) is None:
            raise RadiusPostgresContractError(
                "evidence_object_hash_invalid"
            )
        if not 1 <= int(item.object_size_bytes) <= maximum_bytes:
            raise RadiusPostgresContractError(
                "evidence_object_size_invalid"
            )
        _aware(item.verified_at_utc)


def _activate_worker_role(cur: Any) -> None:
    cur.execute("set local lock_timeout='5s'")
    cur.execute("set local statement_timeout='30s'")
    cur.execute(f"set local role {WORKER_ROLE}")
    cur.execute("select current_role")
    if str(cur.fetchone()[0]) != WORKER_ROLE:
        raise RadiusPostgresContractError(
            "least_privilege_role_activation_failed"
        )


def _lock_cursor(
    cur: Any,
    *,
    subscription_id: str,
    plan: RadiusBatchPlan,
) -> Any:
    cur.execute(
        """
        select
          c.cursor_epoch,c.file_generation,c.byte_offset,
          c.last_record_sha256,c.revision,
          s.desired_activation,sub.desired_activation
        from acquisition_consumer_subscriptions sub
        join acquisition_stream_cursors c
          on c.source_instance_id=sub.source_instance_id
         and c.stream_id=sub.stream_id
         and c.transport_binding=sub.transport_binding
        join acquisition_source_instances s
          on s.source_instance_id=c.source_instance_id
        where sub.subscription_id=%s
          and c.source_instance_id=%s and c.stream_id=%s
          and c.transport_binding=%s
        for update of c
        """,
        (
            subscription_id,
            plan.current_cursor.source_instance_id,
            plan.current_cursor.stream_id,
            plan.current_cursor.transport_binding,
        ),
    )
    row = cur.fetchone()
    if row is None:
        raise RadiusPostgresContractError("subscription_cursor_not_found")
    if row[5] != "manual_enabled" or row[6] != "manual_enabled":
        raise RadiusPostgresContractError(
            "subscription_not_manually_enabled"
        )
    return row


def _require_current_cursor(
    row: Any,
    *,
    plan: RadiusBatchPlan,
    cursor_epoch: UUID,
    expected_revision: int,
) -> None:
    actual = (
        UUID(str(row[0])),
        str(row[1]),
        int(row[2]),
        str(row[3]) if row[3] is not None else None,
        int(row[4]),
    )
    expected = (
        cursor_epoch,
        plan.current_cursor.file_generation,
        plan.current_cursor.byte_offset,
        plan.current_cursor.last_record_sha256,
        int(expected_revision),
    )
    if actual != expected:
        raise RadiusPostgresContractError("stale_batch_cursor")


def _aware(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise RadiusPostgresContractError("aware_utc_required")
    return value.astimezone(timezone.utc)


def _parse_utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError as exc:
        raise RadiusPostgresContractError(
            "class_cache_expiry_invalid"
        ) from exc
    return _aware(parsed)

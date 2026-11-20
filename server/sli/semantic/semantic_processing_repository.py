# ruff: noqa: F401 -- re-export hub (plan 7.2b): split-out modules read these
# names through ``semantic_processing_repository`` at call time.
"""PostgreSQL access primitives for migration 022; not wired into runtime."""
from __future__ import annotations

import json
import uuid
from collections.abc import Mapping, Sequence
from datetime import timedelta
from hashlib import sha256
from typing import Any

from server.sli.entities.identity_resolution import IDENTITY_RESOLUTION_VERSION
from server.sli.semantic.semantic_processing import (
    ASSEMBLER_ID,
    ASSEMBLER_VERSION,
    NORMALIZER_ID,
    NORMALIZER_VERSION,
    SEMANTIC_CONTRACT_VERSION,
    CanonicalAction,
    NormalizedEvent,
    ProcessEpisode,
)
from server.sli.sources.process_identity_contract import (
    bounded_process_text,
    windows_process_id,
)
from server.sli.storage.event_source_identity import (
    RepresentationConflict,
    preferred_representation,
)
from server.sli.storage.event_source_representation import verified_preferred_row
from server.sli.storage.storage_v2_archive import ArchiveIntegrityError, ArchiveReader
from server.sli.storage.storage_v2_models import parse_utc_timestamp
from server.sli.storage.storage_v2_runtime import StorageV2RuntimeReader

PROCESSOR_ID = "semantic-shadow"
PROCESSOR_VERSION = NORMALIZER_VERSION
MAX_CLAIM = 16
INVESTIGATION_CONTEXT_JOB_KIND = "investigation_context"
SEMANTIC_REPAIR_JOB_KIND = "semantic_repair"
SEMANTIC_V2_QUARANTINE_REPAIR_JOB_KIND = "semantic_v2_quarantine_repair"
SOURCE_IDENTITY_FIELDS = (
    "id",
    "server_id",
    "domain_id",
    "log_source_id",
    "event_id",
    "time_created_utc",
    "normalized_hash",
    "correlation_id",
    "migrated_at",
    "provider_name",
    "channel",
    "computer",
)


def semantic_source_identity(value: Mapping[str, Any] | str) -> dict[str, Any]:
    """Return the bounded archive-verification identity, never event payload."""
    parsed: Any = value
    if isinstance(value, str):
        parsed = json.loads(value)
    if not isinstance(parsed, Mapping):
        raise RuntimeError("semantic source identity must be an object")
    missing = [
        field for field in (
            "id", "server_id", "domain_id", "log_source_id", "event_id",
            "time_created_utc", "normalized_hash", "migrated_at", "channel",
        ) if parsed.get(field) is None
    ]
    if missing:
        raise RuntimeError(
            "semantic source identity is incomplete: " + ",".join(missing)
        )
    raw_hash = parsed["normalized_hash"]
    if isinstance(raw_hash, (bytes, bytearray, memoryview)):
        hash_hex = bytes(raw_hash).hex()
    else:
        hash_hex = str(raw_hash).casefold()
    if len(hash_hex) != 64 or any(char not in "0123456789abcdef" for char in hash_hex):
        raise RuntimeError("semantic source identity hash is invalid")

    def json_value(item: Any) -> Any:
        if hasattr(item, "isoformat"):
            return item.isoformat()
        if isinstance(item, uuid.UUID):
            return str(item)
        return item

    result = {
        field: json_value(parsed.get(field)) for field in SOURCE_IDENTITY_FIELDS
    }
    for field in ("id", "server_id", "domain_id", "log_source_id", "event_id"):
        result[field] = int(result[field])
    result["normalized_hash"] = hash_hex
    encoded = json.dumps(result, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > 4096:
        raise RuntimeError("semantic source identity exceeds 4096 bytes")
    return result


def _identity(
    *,
    source_event_id: int,
    job_kind: str,
    processor_id: str,
    processor_version: str,
    identity_resolution_version: str = IDENTITY_RESOLUTION_VERSION,
) -> bytes:
    value = json.dumps(
        {"event": int(source_event_id), "kind": job_kind, "contract": SEMANTIC_CONTRACT_VERSION,
         "processor": processor_id, "version": processor_version,
         "identity_resolution_version": identity_resolution_version},
        sort_keys=True, separators=(",", ":")
    )
    return sha256(value.encode("utf-8")).digest()


def enqueue_semantic_job(
    cur: Any, *, source_event_id: int, job_kind: str = "normalize_event",
    processor_id: str = PROCESSOR_ID, processor_version: str = PROCESSOR_VERSION,
    payload: Mapping[str, Any] | None = None,
) -> str:
    """Enqueue an identity-only job in the caller transaction, idempotently."""
    if job_kind not in {
        "normalize_event",
        "assemble_action",
        "semantic_replay",
        INVESTIGATION_CONTEXT_JOB_KIND,
        SEMANTIC_REPAIR_JOB_KIND,
        SEMANTIC_V2_QUARANTINE_REPAIR_JOB_KIND,
    }:
        raise ValueError("unsupported semantic job kind")
    key = _identity(source_event_id=source_event_id, job_kind=job_kind, processor_id=processor_id, processor_version=processor_version)
    job_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"adlog:semantic:{key.hex()}"))
    encoded = json.dumps(dict(payload or {}), sort_keys=True, separators=(",", ":"))
    cur.execute(
        """
        insert into semantic_processing_outbox(
            job_id,source_event_id,job_kind,semantic_contract_version,
            processor_id,processor_version,idempotency_key,payload_json,
            source_id,domain_id,partition_key,occurred_at_utc,
            source_identity_json
        )
        select %s,%s,%s,%s,%s,%s,%s,%s::jsonb,
               source.log_source_id,source.domain_id,
               source.server_id::text || ':' || source.channel_id::text,
               source.time_created_utc,
               jsonb_build_object(
                   'id',source.id,
                   'server_id',source.server_id,
                   'domain_id',source.domain_id,
                   'log_source_id',source.log_source_id,
                   'event_id',source.event_id,
                   'time_created_utc',source.time_created_utc,
                   'normalized_hash',encode(source.normalized_hash,'hex'),
                   'correlation_id',source.correlation_id,
                   'migrated_at',source.migrated_at,
                   'provider_name',provider.value,
                   'channel',channel.value,
                   'computer',computer.value
               )
        from events_v2_core source
        join storage_v2_channel channel on channel.id=source.channel_id
        left join storage_v2_provider provider on provider.id=source.provider_id
        left join storage_v2_computer computer on computer.id=source.computer_id
        where source.id=%s
        on conflict(idempotency_key) do nothing
        """,
        (
            job_id,
            int(source_event_id),
            job_kind,
            SEMANTIC_CONTRACT_VERSION,
            processor_id,
            processor_version,
            key,
            encoded,
            int(source_event_id),
        ),
    )
    cur.execute(
        "select job_id,payload_json,source_identity_json "
        "from semantic_processing_outbox where idempotency_key=%s",
        (key,),
    )
    row = dict(cur.fetchone() or {})
    if not row:
        raise LookupError("semantic source event is missing from events_v2_core")
    existing = row.get("payload_json")
    if isinstance(existing, str):
        existing = json.loads(existing)
    if existing != dict(payload or {}):
        raise RuntimeError("semantic job identity replay payload conflict")
    identity = semantic_source_identity(row.get("source_identity_json") or {})
    if identity["id"] != int(source_event_id):
        raise RuntimeError("semantic job source identity conflict")
    return str(row.get("job_id") or job_id)


def lock_semantic_source(cur: Any, *, source_event_id: int) -> None:
    """Serialize a source's normalization against controller recovery work."""
    cur.execute(
        "select pg_advisory_xact_lock(hashtextextended(%s,0))",
        (f"semantic_source:{int(source_event_id)}",),
    )


def claim_semantic_jobs(
    cur: Any,
    *,
    limit: int = 1,
    lease_seconds: int = 300,
    source_event_ids: Sequence[int] | None = None,
    repair_plan_digest: str | None = None,
) -> list[dict[str, Any]]:
    """Bounded at-least-once claim; v2 repairs require their exact recovery scope."""
    requested = max(1, min(int(limit), MAX_CLAIM))
    lease = max(60, min(int(lease_seconds), 3600))
    token = str(uuid.uuid4())
    scoped_digest = str(repair_plan_digest or "").strip()
    if scoped_digest and (
        len(scoped_digest) != 64
        or any(char not in "0123456789abcdef" for char in scoped_digest)
    ):
        raise ValueError("semantic v2 quarantine repair digest is invalid")
    exact_source_ids = (
        sorted({int(value) for value in source_event_ids})
        if source_event_ids is not None
        else None
    )
    source_filter = (
        "and source_event_id=any(%s)" if exact_source_ids is not None else ""
    )
    job_filter = (
        "and job_kind=%s and payload_json->>'repair_plan_digest'=%s"
        if scoped_digest
        else "and job_kind<>%s"
    )
    filter_params: tuple[Any, ...] = (
        (SEMANTIC_V2_QUARANTINE_REPAIR_JOB_KIND, scoped_digest)
        if scoped_digest
        else (SEMANTIC_V2_QUARANTINE_REPAIR_JOB_KIND,)
    )
    params: tuple[Any, ...] = (
        SEMANTIC_CONTRACT_VERSION,
        PROCESSOR_ID,
        f"{PROCESSOR_VERSION}+r7-%",
        PROCESSOR_VERSION,
        *(() if exact_source_ids is None else (exact_source_ids,)),
        *filter_params,
        requested,
        token,
        lease,
    )
    # Match the ordered partial index even with the expired-lease OR below.
    # LIMIT must not require sorting every live job on each single-row claim.
    cur.execute(
        f"""
        with candidates as (
          select job_id from semantic_processing_outbox
          where semantic_contract_version=%s and attempt_count < max_attempts
            and status in ('queued','failed','leased')
            and processor_id=%s
            and (
              (job_kind='semantic_replay' and processor_version like %s)
              or (job_kind<>'semantic_replay' and processor_version=%s)
            )
            and available_at <= now()
            and (status in ('queued','failed') or (status='leased' and lease_until < now()))
            {source_filter}
            {job_filter}
          order by available_at,created_at,job_id for update skip locked limit %s
        ) update semantic_processing_outbox job
          set status='leased',attempt_count=attempt_count+1,lease_token=%s,
              lease_until=now()+(%s * interval '1 second'),heartbeat_at=now(),updated_at=now(),
              last_error_code=null,last_error_detail=null
          from candidates where job.job_id=candidates.job_id returning job.*
        """,
        params,
    )
    return [dict(item) for item in (cur.fetchall() or [])]


def heartbeat_semantic_job(cur: Any, *, job_id: str, lease_token: str, lease_seconds: int = 300) -> bool:
    lease = max(60, min(int(lease_seconds), 3600))
    cur.execute(
        """update semantic_processing_outbox set heartbeat_at=now(),lease_until=now()+(%s * interval '1 second'),updated_at=now()
           where job_id=%s and status='leased' and lease_token=%s returning job_id""",
        (lease, job_id, lease_token),
    )
    return cur.fetchone() is not None


def complete_semantic_job(cur: Any, *, job_id: str, lease_token: str) -> None:
    cur.execute(
        """update semantic_processing_outbox set status='completed',completed_at=now(),lease_token=null,lease_until=null,heartbeat_at=now(),updated_at=now()
           where job_id=%s and status='leased' and lease_token=%s returning job_id""",
        (job_id, lease_token),
    )
    if cur.fetchone() is None:
        raise RuntimeError("semantic processing lease was lost")


def defer_semantic_job(
    cur: Any,
    *,
    job_id: str,
    lease_token: str,
    delay_seconds: int = 1,
) -> None:
    """Release a successful bounded continuation without spending retry budget."""
    delay = max(1, min(int(delay_seconds), 60))
    cur.execute(
        """update semantic_processing_outbox
           set status='queued',attempt_count=greatest(attempt_count-1,0),
               available_at=now()+(%s * interval '1 second'),
               lease_token=null,lease_until=null,heartbeat_at=now(),updated_at=now()
           where job_id=%s and status='leased' and lease_token=%s returning job_id""",
        (delay, job_id, lease_token),
    )
    if cur.fetchone() is None:
        raise RuntimeError("semantic processing lease was lost while deferring")


def fail_semantic_job(cur: Any, *, job_id: str, lease_token: str, attempt_count: int, max_attempts: int, error_code: str, error_detail: str) -> str:
    terminal = int(attempt_count) >= int(max_attempts)
    status = "quarantined" if terminal else "failed"
    retry = min(3600, 30 * (2 ** min(max(0, int(attempt_count) - 1), 7)))
    cur.execute(
        """update semantic_processing_outbox set status=%s,available_at=now()+(%s * interval '1 second'),lease_token=null,lease_until=null,
           last_error_code=%s,last_error_detail=%s,updated_at=now() where job_id=%s and status='leased' and lease_token=%s returning status""",
        (status, retry, error_code[:160], error_detail[:1000], job_id, lease_token),
    )
    if cur.fetchone() is None:
        raise RuntimeError("semantic processing lease was lost while recording failure")
    return status


def load_agent_semantic_source_event(
    cur: Any, *, source_event_id: int, summary: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Verify one exact imported inbox row against its immutable event/job hash."""
    cur.execute(
        "select public.read_agent_semantic_source_v190(%s) as source",
        (int(source_event_id),),
    )
    source = dict(cur.fetchone() or {}).get("source")
    if source is None:
        return None
    core, row = source["core"], source["event_row"]
    core_hash = core["normalized_hash"]
    core_hash = bytes(core_hash).hex() if isinstance(core_hash, (bytes, bytearray, memoryview)) else str(core_hash).removeprefix("\\x")
    if core_hash != summary["normalized_hash"]:
        raise ArchiveIntegrityError("agent semantic source hash mismatch")
    StorageV2RuntimeReader._verify_core_identity(summary, core)
    stored = source.get("preferred")
    if stored is not None:
        # V2 binds native identity, not XML/properties. Verify the separately
        # retained full body before using it, including for a richer v1 source.
        stored = dict(stored)
        if int(stored["event_id"]) != int(source_event_id):
            raise ArchiveIntegrityError("agent semantic representation identity mismatch")
        for field in ("normalized_hash", "canonical_hash", "representation_sha256"):
            stored[field] = bytes.fromhex(stored[field].removeprefix("\\x"))
        preferred = verified_preferred_row({"normalized_hash": bytes.fromhex(core_hash)}, stored)
        try:
            preferred_representation(preferred, row)
        except RepresentationConflict:
            raise ArchiveIntegrityError("agent semantic source representation mismatch") from None
        row = preferred
    else:
        # A legacy source without an additive representation still requires
        # its complete v1 digest; native identity alone cannot attest its body.
        digest = sha256(json.dumps(row, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()
        if digest != core_hash:
            raise ArchiveIntegrityError("agent semantic source hash mismatch")
    if (
        int(row["record_id"]) != int(core["event_record_id"])
        or int(row["event_id"]) != int(core["event_id"])
        # Windows carries 100 ns fractions; PostgreSQL and Python can round
        # differently by one microsecond. The complete body and the exact
        # core/job identity have already been verified above.
        or abs(parse_utc_timestamp(row["time_created"]) - parse_utc_timestamp(core["time_created_utc"])) > timedelta(microseconds=1)
        or row["channel"] != summary["channel"]
        or (row.get("machine_name") or row["computer_name"]) != summary["computer"]
    ):
        raise ArchiveIntegrityError("agent semantic source identity mismatch")
    # Reuse the importer's bounded XML parser, including UserData/Execution.
    from importlib import import_module

    parse_event_data = import_module("scripts.import.import_event_jsonl_to_postgres").parse_event_data
    return {**core, "event_data_json": parse_event_data(row.get("xml")),
            "keywords": row.get("keywords")}


def load_semantic_source_event(
    cur: Any,
    *,
    source_event_id: int,
    archive: ArchiveReader,
    source_identity: Mapping[str, Any] | str | None = None,
) -> dict[str, Any] | None:
    """Load a V2 core identity and hydrate its exact published archive row."""
    if source_identity is None:
        cur.execute(
            """
            select core.id,core.server_id,core.domain_id,core.log_source_id,
                   core.event_id,core.time_created_utc,core.normalized_hash,
                   core.correlation_id,core.migrated_at,
                   provider.value as provider_name,
                   channel.value as channel,
                   computer.value as computer
            from events_v2_core core
            left join storage_v2_provider provider on provider.id=core.provider_id
            join storage_v2_channel channel on channel.id=core.channel_id
            left join storage_v2_computer computer on computer.id=core.computer_id
            where core.id=%s
            """,
            (int(source_event_id),),
        )
        row = cur.fetchone()
        if not row:
            return None
        summary = semantic_source_identity(dict(row))
    else:
        summary = semantic_source_identity(source_identity)
        if summary["id"] != int(source_event_id):
            raise RuntimeError("semantic source identity id does not match job")
    try:
        payload = dict(archive.read_event(archive_kind="event", event_id=int(source_event_id)))
    except KeyError as exc:
        if exc.args != (f"published archive block not found for event {source_event_id}",):
            raise
        payload = load_agent_semantic_source_event(cur, source_event_id=source_event_id, summary=summary)
        if payload is None:
            raise
    StorageV2RuntimeReader._verify_core_identity(summary, payload)
    payload.setdefault("provider_name", summary.get("provider_name"))
    payload.setdefault("channel", summary.get("channel"))
    payload.setdefault("computer", summary.get("computer"))
    payload["source_host_id"] = int(summary["server_id"])
    payload["source_ingested_at"] = summary["migrated_at"]
    payload["source_event_sha256"] = bytes.fromhex(summary["normalized_hash"])
    return payload


def normalized_event_id(
    event: NormalizedEvent,
    *,
    semantic_contract_version: int = SEMANTIC_CONTRACT_VERSION,
    normalizer_id: str = NORMALIZER_ID,
    normalizer_version: str = NORMALIZER_VERSION,
) -> str:
    return str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            "adlog:normalized:"
            f"{event.source_event_id}:{semantic_contract_version}:"
            f"{normalizer_id}:{normalizer_version}:{event.semantic_sha256}",
        )
    )


def load_retained_normalized_event(
    cur: Any, *, source_event_id: int, source_identity: Mapping[str, Any] | str,
) -> NormalizedEvent | None:
    """Resume current normalization without its source, never reinterpret it."""
    identity = semantic_source_identity(source_identity)
    if identity["id"] != int(source_event_id):
        raise RuntimeError("retained normalization source identity conflict")
    cur.execute(
        """select normalized_event_id,source_event_sha256,semantic_sha256,
                  semantic_type,occurred_at_utc,roles_json,facts_json,quality_json
           from normalized_events
           where source_event_id=%s and semantic_contract_version=%s
             and normalizer_id=%s and normalizer_version=%s
             and processing_status='normalized'""",
        (int(source_event_id), SEMANTIC_CONTRACT_VERSION, NORMALIZER_ID, NORMALIZER_VERSION),
    )
    row = cur.fetchone()
    if row is None:
        return None
    event = NormalizedEvent(
        source_event_id=int(source_event_id),
        semantic_type=str(row["semantic_type"]),
        occurred_at_utc=parse_utc_timestamp(row["occurred_at_utc"]),
        roles=_json_object(row["roles_json"]),
        facts=_json_object(row["facts_json"]),
        quality=_json_object(row["quality_json"]),
        semantic_sha256=bytes(row["semantic_sha256"]).hex(),
    )
    material = {
        "source_event_id": event.source_event_id,
        "semantic_type": event.semantic_type,
        "roles": dict(event.roles),
        "facts": dict(event.facts),
        "identity_resolution_version": IDENTITY_RESOLUTION_VERSION,
    }
    digest = sha256(json.dumps(
        material, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str,
    ).encode("utf-8")).hexdigest()
    if (
        bytes(row["source_event_sha256"]).hex() != identity["normalized_hash"]
        or event.occurred_at_utc != parse_utc_timestamp(identity["time_created_utc"])
        or event.quality.get("identity_resolution_version") != IDENTITY_RESOLUTION_VERSION
        or event.semantic_sha256 != digest
        or str(row["normalized_event_id"]) != normalized_event_id(event)
    ):
        raise RuntimeError("retained normalization integrity conflict")
    return event


def load_identity_role_overrides(
    cur: Any,
    *,
    event: NormalizedEvent,
    required_merge_id: str | None = None,
) -> dict[str, dict[str, str]]:
    """Load exact immutable R7 mappings for provisional semantic roles."""

    identity_roles = event.quality.get("identity_roles")
    provisional_keys = {
        str(value.get("key") or "")
        for value in identity_roles.values()
        if isinstance(identity_roles, Mapping)
        and isinstance(value, Mapping)
        and value.get("state") == "provisional"
        and bool(value.get("provisional"))
    } if isinstance(identity_roles, Mapping) else set()
    if not provisional_keys:
        if required_merge_id:
            raise RuntimeError("semantic replay source no longer has a provisional role")
        return {}
    role_keys = sorted({str(value) for value in event.roles.values() if value})
    if not role_keys:
        return {}
    cur.execute(
        "select to_regclass('entity_identity_merges_v2') is not null as available"
    )
    available = bool(dict(cur.fetchone() or {}).get("available"))
    if not available:
        if required_merge_id:
            raise RuntimeError("semantic replay requires migration 068")
        return {}
    cur.execute(
        """
        select merge_id::text,source_natural_key,target_natural_key
        from entity_identity_merges_v2
        where source_natural_key=any(%s)
          and (%s::uuid is null or merge_id=%s::uuid)
        order by source_natural_key
        """,
        (sorted(set(role_keys) & provisional_keys), required_merge_id, required_merge_id),
    )
    result: dict[str, dict[str, str]] = {}
    for raw in cur.fetchall() or []:
        row = dict(raw)
        source_key = str(row["source_natural_key"])
        candidate = {
            "target_key": str(row["target_natural_key"]),
            "merge_id": str(row["merge_id"]),
        }
        if source_key in result and result[source_key] != candidate:
            raise RuntimeError("identity merge source has conflicting targets")
        result[source_key] = candidate
    if required_merge_id and not result:
        raise RuntimeError("semantic replay has no matching R7 identity merge")
    return result


def prior_identity_normalized_events(
    cur: Any,
    *,
    source_event_id: int,
    source_keys: Sequence[str],
) -> tuple[str, ...]:
    """Return prior facts that contain one of the provisional role keys."""

    keys = sorted({str(value) for value in source_keys if str(value)})
    if not keys:
        return ()
    cur.execute(
        """
        select distinct normalized.normalized_event_id::text
        from normalized_events normalized
        cross join lateral jsonb_each_text(normalized.roles_json) role
        where normalized.source_event_id=%s and role.value=any(%s)
        order by normalized.normalized_event_id::text
        """,
        (int(source_event_id), keys),
    )
    return tuple(str(row["normalized_event_id"]) for row in (cur.fetchall() or []))


def record_identity_semantic_replay(
    cur: Any,
    *,
    merge_id: str,
    source_event_id: int,
    old_normalized_event_ids: Sequence[str],
    new_normalized_event_id: str,
    replay_job_id: str,
) -> None:
    """Append exact old→new semantic evidence for one R7 replay."""

    old_ids = sorted({str(value) for value in old_normalized_event_ids})
    if not old_ids or new_normalized_event_id in old_ids:
        raise RuntimeError("identity semantic replay did not create a new fact")
    for old_id in old_ids:
        cur.execute(
            """
            insert into entity_identity_semantic_replays_v2(
                merge_id,source_event_id,old_normalized_event_id,
                new_normalized_event_id,replay_job_id,
                source_event_sha256,source_occurred_at_utc
            )
            select %s,%s,%s,%s,%s,source.source_event_sha256,
                   source.occurred_at_utc
            from normalized_events source
            where source.normalized_event_id=%s
            on conflict(merge_id,source_event_id,old_normalized_event_id)
            do nothing
            """,
            (
                merge_id,
                int(source_event_id),
                old_id,
                new_normalized_event_id,
                replay_job_id,
                old_id,
            ),
        )
        cur.execute(
            """
            select new_normalized_event_id::text,replay_job_id::text
            from entity_identity_semantic_replays_v2
            where merge_id=%s and source_event_id=%s
              and old_normalized_event_id=%s
            """,
            (merge_id, int(source_event_id), old_id),
        )
        row = dict(cur.fetchone() or {})
        if (
            row.get("new_normalized_event_id") != new_normalized_event_id
            or row.get("replay_job_id") != replay_job_id
        ):
            raise RuntimeError("identity semantic replay evidence conflict")


def persist_normalized_event(
    cur: Any,
    *,
    event: NormalizedEvent,
    normalizer_version: str = NORMALIZER_VERSION,
    source_identity: Mapping[str, Any] | str | None = None,
) -> str:
    """Persist the complete semantic fact and reject conflicting identity replay."""
    normalized_id = normalized_event_id(
        event,
        semantic_contract_version=SEMANTIC_CONTRACT_VERSION,
        normalizer_id=NORMALIZER_ID,
        normalizer_version=normalizer_version,
    )
    facts = json.dumps(dict(event.facts), sort_keys=True, separators=(",", ":"))
    roles = json.dumps(dict(event.roles), sort_keys=True, separators=(",", ":"))
    quality = json.dumps(dict(event.quality), sort_keys=True, separators=(",", ":"))
    if source_identity is not None:
        identity = semantic_source_identity(source_identity)
        if identity["id"] != int(event.source_event_id):
            raise RuntimeError("normalized source identity id does not match event")
        cur.execute(
            """
            insert into normalized_events(
                normalized_event_id,source_event_id,semantic_contract_version,
                normalizer_id,normalizer_version,processing_status,
                source_event_sha256,semantic_sha256,semantic_type,
                occurred_at_utc,source_ingested_at,roles_json,facts_json,
                quality_json,source_identity_json
            ) values(
                %s,%s,%s,%s,%s,'normalized',decode(%s,'hex'),decode(%s,'hex'),
                %s,%s,%s,%s::jsonb,%s::jsonb,%s::jsonb,%s::jsonb
            )
            on conflict(source_event_id,semantic_contract_version,normalizer_id,normalizer_version)
            do nothing
            """,
            (
                normalized_id,
                event.source_event_id,
                SEMANTIC_CONTRACT_VERSION,
                NORMALIZER_ID,
                normalizer_version,
                identity["normalized_hash"],
                event.semantic_sha256,
                event.semantic_type,
                event.occurred_at_utc,
                identity["migrated_at"],
                roles,
                facts,
                quality,
                json.dumps(identity, sort_keys=True, separators=(",", ":")),
            ),
        )
    else:
        cur.execute(
            """
        insert into normalized_events(
            normalized_event_id,source_event_id,semantic_contract_version,
            normalizer_id,normalizer_version,processing_status,
            source_event_sha256,semantic_sha256,semantic_type,
            occurred_at_utc,source_ingested_at,roles_json,facts_json,quality_json,
            source_identity_json
        )
        select %s,%s,%s,%s,%s,'normalized',source.normalized_hash,decode(%s,'hex'),
               %s,%s,source.migrated_at,%s::jsonb,%s::jsonb,%s::jsonb,
               jsonb_build_object(
                   'id',source.id,
                   'server_id',source.server_id,
                   'domain_id',source.domain_id,
                   'log_source_id',source.log_source_id,
                   'event_id',source.event_id,
                   'time_created_utc',source.time_created_utc,
                   'normalized_hash',encode(source.normalized_hash,'hex'),
                   'correlation_id',source.correlation_id,
                   'migrated_at',source.migrated_at,
                   'provider_name',provider.value,
                   'channel',channel.value,
                   'computer',computer.value
               )
        from events_v2_core source
        join storage_v2_channel channel on channel.id=source.channel_id
        left join storage_v2_provider provider on provider.id=source.provider_id
        left join storage_v2_computer computer on computer.id=source.computer_id
        where source.id=%s
        on conflict(source_event_id,semantic_contract_version,normalizer_id,normalizer_version)
        do nothing
        """,
        (
            normalized_id,
            event.source_event_id,
            SEMANTIC_CONTRACT_VERSION,
            NORMALIZER_ID,
            normalizer_version,
            event.semantic_sha256,
            event.semantic_type,
            event.occurred_at_utc,
            roles,
            facts,
            quality,
            event.source_event_id,
        ),
        )
    cur.execute(
        """
        select normalized_event_id,semantic_sha256,semantic_type,
               occurred_at_utc,roles_json,facts_json,quality_json
        from normalized_events
        where source_event_id=%s and semantic_contract_version=%s
          and normalizer_id=%s and normalizer_version=%s
        """,
        (
            event.source_event_id,
            SEMANTIC_CONTRACT_VERSION,
            NORMALIZER_ID,
            normalizer_version,
        ),
    )
    row = dict(cur.fetchone() or {})
    actual = {
        "semantic_sha256": bytes(row.get("semantic_sha256") or b"").hex(),
        "semantic_type": row.get("semantic_type"),
        "occurred_at_utc": row.get("occurred_at_utc"),
        "roles_json": _json_object(row.get("roles_json")),
        "facts_json": _json_object(row.get("facts_json")),
        "quality_json": _json_object(row.get("quality_json")),
    }
    expected = {
        "semantic_sha256": event.semantic_sha256.casefold(),
        "semantic_type": event.semantic_type,
        "occurred_at_utc": event.occurred_at_utc,
        "roles_json": dict(event.roles),
        "facts_json": dict(event.facts),
        "quality_json": dict(event.quality),
    }
    if actual != expected or str(row.get("normalized_event_id")) != normalized_id:
        raise RuntimeError("normalized event identity replay conflict")
    return normalized_id


def _json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    parsed = json.loads(str(value or "{}"))
    if not isinstance(parsed, Mapping):
        raise RuntimeError("semantic persistence JSON must contain an object")
    return dict(parsed)


from server.sli.semantic.semantic_processing_repository_persist import (
    _action_sha256,
    _merge_action_attributes,
    _reinterpreted_single_source_attributes,
    persist_canonical_actions,
    persist_process_episode_revision,
)

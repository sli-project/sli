"""Bounded PostgreSQL hot-retention executor for the resolved storage policy.

This is deliberately not a scheduler or a connection factory.  A caller must
provide an already-authorized PostgreSQL connection, and apply remains gated by
the existing ``retention_apply_by_default`` setting.  It never touches cutover,
archive, cursor, finding, or other control-plane relations.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime, timedelta, timezone
from typing import Any

from server.sli.core.app_config import AdLogConfig, load_config
from server.sli.events.event_catalog import all_event_catalog_entries
from server.sli.storage.storage_policy import StoragePolicy, load_storage_policy
from server.source_packs.windows_ad_dc import SECURITY_ROUTINE_SESSION_EVENT_KEYS

MAX_BATCH_SIZE = 10_000
NOISE_DELETE_EVENT_KEYS = SECURITY_ROUTINE_SESSION_EVENT_KEYS
# Only the V2 hot event root is a deletion target.  Its ``ON DELETE CASCADE``
# fact rows are the explicit compatible data-plane dependency; every other
# reference blocks the run rather than widening the deletion surface.
DATA_PLANE_RELATIONS: Mapping[str, Mapping[str, str]] = {
    "events_v2_core": {
        "timestamp_column": "time_created_utc",
        "compatible_dependency": "event_facts_v2 on delete cascade",
    },
}
REQUIRED_V2_GUARD_RELATIONS = (
    "event_entity_link_blocks_v2",
    "storage_v2_archive_blocks",
)
ELIGIBLE = "eligible"
HOLD_REASONS = (
    "held_by_relationship_horizon",
    "held_by_archive_gap",
    "held_by_other_dependency",
)
DIRECT_NO_ARCHIVE_KNOWN_DEPENDENCIES = frozenset({
    "detections",
    "entity_state_current",
    "entity_states",
    "event_links",
    "finding_evidence",
})


def _as_utc(value: datetime | None) -> datetime:
    current = value or datetime.now(timezone.utc)
    return current.replace(tzinfo=timezone.utc) if current.tzinfo is None else current.astimezone(timezone.utc)


def build_postgres_profile_retention_plan(
    *, policy: StoragePolicy, now: datetime | None = None
) -> dict[str, Any]:
    """Produce a dry-run-first bounded plan without contacting PostgreSQL."""
    days = int(policy.db_retention_days)
    if days <= 0:
        return {
            "status": "blocked",
            "reason": "db_retention_days_must_be_positive",
            "relations": {},
            "rows_selected": {},
            "rows_deleted": {},
        }
    cutoff = _as_utc(now) - timedelta(days=days)
    return {
        "status": "ready",
        "mode": "dry-run",
        "cutoff_utc": cutoff.isoformat(),
        "db_retention_days": days,
        "relations": dict(DATA_PLANE_RELATIONS),
        "rows_selected": {name: 0 for name in DATA_PLANE_RELATIONS},
        "rows_deleted": {name: 0 for name in DATA_PLANE_RELATIONS},
        "selected_count": 0,
        "eligible_count": 0,
        "held_count": 0,
        "deleted_count": 0,
        "held_by_reason": {reason: 0 for reason in HOLD_REASONS},
        "physical_reclaim_performed": False,
        "safety": {
            "drop_executed": False,
            "truncate_executed": False,
            "cascade_keyword_used": False,
            "control_plane_deleted": False,
        },
    }


def _row_value(row: Any, name: str, default: Any = None) -> Any:
    if isinstance(row, Mapping):
        return row.get(name, default)
    return default


def _candidate_classifications(
    cur: Any,
    *,
    cutoff: datetime,
    relationship_cutoff: datetime,
    batch: int,
) -> list[dict[str, Any]]:
    """Classify a bounded V2 batch without treating one hold as a global stop.

    Link blocks intentionally have their own relationship horizon.  A linked
    event younger than that horizon is held; an older linked event remains a
    fail-closed other-dependency hold until V2 finalizer evidence authorizes a
    separate lifecycle for the link relation.
    """
    cur.execute(
        """
        with selected_candidates as (
            select id, time_created_utc
            from events_v2_core
            where time_created_utc < %s
            order by time_created_utc, id
            limit %s
        ), candidate_classification as (
            select candidate.id,
                   case
                     when exists (
                       select 1
                       from event_entity_link_blocks_v2 link_block
                       where candidate.id=any(link_block.event_ids)
                     ) and candidate.time_created_utc >= %s
                       then 'held_by_relationship_horizon'
                     when exists (
                       select 1
                       from event_entity_link_blocks_v2 link_block
                       where candidate.id=any(link_block.event_ids)
                     ) then 'held_by_other_dependency'
                     when not exists (
                       select 1
                       from storage_v2_archive_blocks archive_block
                       where archive_block.archive_kind='event'
                         and archive_block.state='published'
                         and candidate.id between archive_block.first_event_id
                                              and archive_block.last_event_id
                     ) then 'held_by_archive_gap'
                     else 'eligible'
                   end as classification
            from selected_candidates candidate
        )
        select id, classification
        from candidate_classification
        order by id
        """,
        (cutoff, batch, relationship_cutoff),
    )
    rows = cur.fetchall()
    return [dict(row) if isinstance(row, Mapping) else {} for row in rows]


def direct_no_archive_descriptors(
    policy: StoragePolicy,
    *,
    event_keys: frozenset[str] | None = None,
) -> list[dict[str, Any]]:
    descriptors: list[dict[str, Any]] = []
    for entry in all_event_catalog_entries():
        lifecycle = entry.get("lifecycle")
        if not isinstance(lifecycle, Mapping):
            continue
        promotion = lifecycle.get("promotion")
        if not isinstance(promotion, Mapping):
            continue
        if (
            promotion.get("executable_lifecycle")
            != "semantic_then_direct_retention_executor"
            or promotion.get("archive_requirement") != "no_archive"
            or int(lifecycle.get("record_days") or 0) != int(policy.db_retention_days)
        ):
            continue
        if event_keys is not None and str(entry.get("event_key") or entry.get("event_id")) not in event_keys:
            continue
        descriptors.append({
            "source": str(entry.get("source") or ""),
            "stream": str(entry.get("stream") or entry.get("channel") or ""),
            "event_key": str(entry.get("event_key") or entry.get("event_id") or ""),
            "provider_name": str(entry.get("provider_name") or ""),
        })
    return sorted(
        descriptors,
        key=lambda item: (item["source"], item["stream"], item["event_key"]),
    )


def _no_archive_prefilter_reconciliation(
    cur: Any,
    *,
    sources: list[str],
    event_ids: list[int],
    channels: list[str],
    providers: list[str],
    cutoff: datetime,
) -> dict[str, int]:
    """Account for every expired direct-retention row before continuity filtering."""
    cur.execute(
        """
        /* direct_no_archive_prefilter_reconciliation */
        with descriptor(source,event_id,channel,provider_name) as (
            select * from unnest(%s::text[],%s::integer[],%s::text[],%s::text[])
        ), expired_candidate as (
            select event.id,
                   exists (
                       select 1
                       from source_capture_continuity_declarations source_declaration
                       where source_declaration.log_source_id=event.log_source_id
                         and source_declaration.descriptor_source=descriptor.source
                         and source_declaration.descriptor_stream=descriptor.channel
                         and source_declaration.provider_name=descriptor.provider_name
                         and source_declaration.channel_value=descriptor.channel
                   ) as continuity_covered,
                   case
                     when not exists (
                       select 1 from semantic_processing_outbox semantic
                       where semantic.source_event_id=event.id
                     ) then 'blocked_by_restrictive_reference'
                     when exists (
                       select 1 from semantic_processing_outbox semantic
                       where semantic.source_event_id=event.id
                         and semantic.status <> 'completed'
                     ) then 'blocked_by_restrictive_reference'
                     when exists (
                       select 1 from event_entity_link_blocks_v2 link_block
                       where event.id=any(link_block.event_ids)
                     ) or exists (
                       select 1 from event_links link
                       where link.source_event_id=event.id
                          or link.target_event_id=event.id
                     ) then 'blocked_by_relationship'
                     when exists (
                       select 1 from entity_state_current state
                       where state.source_event_db_id=event.id
                     ) or exists (
                       select 1 from entity_states state
                       where state.evidence_event_id=event.id
                     ) or exists (
                       select 1 from detections detection
                       where detection.primary_event_id=event.id
                     ) or exists (
                       select 1 from finding_evidence evidence
                       where evidence.event_id=event.id
                     ) or exists (
                       select 1 from investigation_events investigation
                       where investigation.event_db_id=event.id
                     ) then 'blocked_by_restrictive_reference'
                     else 'eligible'
                   end as classification
            from events_v2_core event
            join storage_v2_channel channel on channel.id=event.channel_id
            left join storage_v2_provider provider on provider.id=event.provider_id
            join descriptor on descriptor.event_id=event.event_id
                and descriptor.channel=channel.value
                and descriptor.provider_name=coalesce(provider.value,'')
            where event.time_created_utc < %s
        )
        select count(*)::bigint as expired_total_count,
               count(*) filter (where continuity_covered)::bigint
                   as covered_by_continuity_count,
               count(*) filter (where not continuity_covered)::bigint
                   as blocked_without_continuity_count,
               count(*) filter (
                   where continuity_covered and classification='blocked_by_relationship'
               )::bigint as blocked_by_relationship_count,
               0::bigint as blocked_by_archive_gap_count,
               count(*) filter (
                   where continuity_covered
                     and classification='blocked_by_restrictive_reference'
               )::bigint as blocked_by_restrictive_reference_count,
               count(*) filter (
                   where continuity_covered and classification='eligible'
               )::bigint as eligible_count
        from expired_candidate
        """,
        (sources, event_ids, channels, providers, cutoff),
    )
    row = cur.fetchone()
    fields = (
        "expired_total_count",
        "covered_by_continuity_count",
        "blocked_without_continuity_count",
        "blocked_by_relationship_count",
        "blocked_by_archive_gap_count",
        "blocked_by_restrictive_reference_count",
        "eligible_count",
    )
    return {field: int(_row_value(row, field, 0) or 0) for field in fields}


def execute_no_archive_retention(
    connection: Any,
    *,
    cutoff: datetime,
    apply: bool = False,
    admitted: bool = False,
    batch_size: int = 1_000,
    policy: StoragePolicy | None = None,
    preservation_check: Callable[[list[Mapping[str, Any]]], None] | None = None,
) -> dict[str, Any]:
    """Inspect or apply one bounded explicit no-archive batch."""
    resolved_policy = policy or load_storage_policy()
    descriptors = direct_no_archive_descriptors(
        resolved_policy, event_keys=NOISE_DELETE_EVENT_KEYS,
    )
    frozen_cutoff = _as_utc(cutoff)
    result: dict[str, Any] = {
        "status": "blocked" if not descriptors else "working",
        "mode": "apply" if apply else "dry-run",
        "cutoff_utc": frozen_cutoff.isoformat(),
        "descriptor_identities": [
            {key: descriptor[key] for key in ("source", "stream", "event_key")}
            for descriptor in descriptors
        ],
        "selected_count": 0,
        "eligible_count": 0,
        "held_count": 0,
        "expired_total_count": 0,
        "covered_by_continuity_count": 0,
        "blocked_without_continuity_count": 0,
        "blocked_by_relationship_count": 0,
        "blocked_by_archive_gap_count": 0,
        "blocked_by_restrictive_reference_count": 0,
        "remaining_count": 0,
        "deleted_count": 0,
        "archive_rows_written": 0,
        "delete_performed": False,
        "archive_write_performed": False,
        "dc_mutated": False,
    }
    if not descriptors:
        result["reason"] = "direct_no_archive_descriptors_missing"
        return result
    if apply and not admitted:
        result.update(
            status="blocked",
            reason="direct_no_archive_admission_missing",
        )
        return result
    if apply and preservation_check is None:
        result.update(status="blocked", reason="clickhouse_fact_preservation_check_missing")
        return result
    batch = min(MAX_BATCH_SIZE, max(1, int(batch_size)))
    sources = [descriptor["source"] for descriptor in descriptors]
    event_ids = [int(descriptor["event_key"]) for descriptor in descriptors]
    channels = [descriptor["stream"] for descriptor in descriptors]
    providers = [descriptor["provider_name"] for descriptor in descriptors]
    with connection.cursor() as cur:
        if apply:
            # Rechecks must see holds committed before the table fence. Do not
            # silently alter a caller's transaction or accept a stale snapshot.
            cur.execute("show transaction_isolation")
            isolation = _row_value(cur.fetchone(), "transaction_isolation", "")
            if isolation != "read committed":
                result.update(status="blocked", reason="direct_no_archive_requires_read_committed")
                return result
        reconciliation = _no_archive_prefilter_reconciliation(
            cur,
            sources=sources,
            event_ids=event_ids,
            channels=channels,
            providers=providers,
            cutoff=frozen_cutoff,
        )
        result.update(reconciliation)
        result["remaining_count"] = result["expired_total_count"]
        if (
            result["covered_by_continuity_count"]
            + result["blocked_without_continuity_count"]
            != result["expired_total_count"]
        ):
            raise RuntimeError("direct_no_archive_reconciliation_mismatch")

        if (
            result["blocked_without_continuity_count"]
            + result["blocked_by_relationship_count"]
            + result["blocked_by_archive_gap_count"]
            + result["blocked_by_restrictive_reference_count"]
            + result["eligible_count"]
            != result["expired_total_count"]
        ):
            raise RuntimeError("direct_no_archive_reconciliation_category_mismatch")

        if result["expired_total_count"] and not result["covered_by_continuity_count"]:
            result.update(
                status="blocked",
                reason="expired_rows_without_continuity_declarations",
            )
            return result
        cur.execute(
            """
            /* direct_no_archive_restrictive_dependencies */
            select con.conrelid::regclass::text as dependent_relation
            from pg_constraint con
            where con.contype='f'
              and con.confrelid=to_regclass('events_v2_core')
              and con.confdeltype <> 'c'
            order by dependent_relation
            """
        )
        dependency_rows = [
            dict(row) if isinstance(row, Mapping) else {}
            for row in cur.fetchall()
        ]
        dependency_names = {
            str(row.get("dependent_relation") or "").rsplit(".", 1)[-1].strip('"')
            for row in dependency_rows
        }
        unknown_dependencies = sorted(
            name for name in dependency_names
            if name and name not in DIRECT_NO_ARCHIVE_KNOWN_DEPENDENCIES
        )
        if unknown_dependencies:
            result.update(
                status="blocked",
                reason="unknown_restrictive_dependency",
                unknown_dependencies=unknown_dependencies,
            )
            return result
        if apply:
            # Packed links have no FK to events_v2_core. Hold their base table
            # before classifying candidates, so a concurrent writer cannot add
            # a link after the dependency check and before DELETE. This path
            # must run through the existing privileged maintenance connection.
            cur.execute("lock table event_entity_link_blocks_v2 in share mode nowait")
            # Case references have no event FK. Fence validation and insertion
            # together; writers take ROW EXCLUSIVE before validating evidence.
            cur.execute("lock table investigation_events in share mode nowait")
        cur.execute(
            """
            /* direct_no_archive_candidate_classification */
            with descriptor(source,event_id,channel,provider_name) as (
                select * from unnest(%s::text[],%s::integer[],%s::text[],%s::text[])
            ), selected_candidate as (
                select event.id,event.normalized_hash
                from events_v2_core event
                join storage_v2_channel channel on channel.id=event.channel_id
                left join storage_v2_provider provider on provider.id=event.provider_id
                join descriptor on descriptor.event_id=event.event_id
                    and descriptor.channel=channel.value
                    and descriptor.provider_name=coalesce(provider.value,'')
                    where event.time_created_utc < %s
                      and exists (
                        select 1
                        from source_capture_continuity_declarations source_declaration
                        where source_declaration.log_source_id=event.log_source_id
                          and source_declaration.descriptor_source=descriptor.source
                          and source_declaration.descriptor_stream=descriptor.channel
                          and source_declaration.provider_name=descriptor.provider_name
                          and source_declaration.channel_value=descriptor.channel
                      )
                order by event.time_created_utc,event.id
                limit %s
            )
            select candidate.id,candidate.normalized_hash,
                   case
                     when not exists (
                       select 1 from semantic_processing_outbox semantic
                       where semantic.source_event_id=candidate.id
                     ) then 'held_by_semantic_missing'
                     when exists (
                       select 1 from semantic_processing_outbox semantic
                       where semantic.source_event_id=candidate.id
                         and semantic.status <> 'completed'
                     ) then 'held_by_semantic_pending'
                     when exists (
                       select 1 from event_entity_link_blocks_v2 link_block
                       where candidate.id=any(link_block.event_ids)
                     ) or exists (
                       select 1 from event_links link
                       where link.source_event_id=candidate.id
                          or link.target_event_id=candidate.id
                     ) or exists (
                       select 1 from entity_state_current state
                       where state.source_event_db_id=candidate.id
                     ) or exists (
                       select 1 from entity_states state
                       where state.evidence_event_id=candidate.id
                     ) or exists (
                       select 1 from detections detection
                       where detection.primary_event_id=candidate.id
                     ) or exists (
                       select 1 from finding_evidence evidence
                       where evidence.event_id=candidate.id
                     ) or exists (
                       select 1 from investigation_events investigation
                       where investigation.event_db_id=candidate.id
                     ) then 'held_by_other_dependency'
                     else 'eligible'
                   end as classification
            from selected_candidate candidate
            order by candidate.id
            """,
            (sources, event_ids, channels, providers, frozen_cutoff, batch),
        )
        candidates = [
            dict(row) if isinstance(row, Mapping) else {}
            for row in cur.fetchall()
        ]
        result["selected_count"] = len(candidates)
        selected_eligible_count = sum(
            1 for candidate in candidates
            if candidate.get("classification") == ELIGIBLE
        )
        result["held_count"] = result["selected_count"] - selected_eligible_count
        result["candidate_classifications"] = candidates
        if not result["selected_count"] and result["expired_total_count"]:
            result.update(
                status="blocked",
                reason="expired_rows_blocked_by_reconciliation",
            )
            return result
        if not apply:
            if result["blocked_without_continuity_count"]:
                result.update(
                    status="partial",
                    reason="expired_rows_without_continuity_declarations",
                )
            else:
                result["status"] = "ok"
            return result
        eligible = [
            candidate for candidate in candidates
            if candidate.get("classification") == ELIGIBLE
        ]
        if eligible:
            assert preservation_check is not None
            ids = [int(candidate["id"]) for candidate in eligible]
            # Keep the exact source snapshot stable through the independent
            # ClickHouse readback and the final cascading DELETE. Existing
            # fact/link updates need row locks; the core lock blocks new facts
            # through their FK. NOWAIT avoids a writer/retention deadlock.
            cur.execute(
                "select id,normalized_hash from events_v2_core "
                "where id=any(%s::bigint[]) order by id for update nowait",
                (ids,),
            )
            locked = {int(row["id"]): bytes(row["normalized_hash"]) for row in cur.fetchall()}
            if locked != {
                int(row["id"]): bytes(row["normalized_hash"]) for row in eligible
            }:
                raise RuntimeError("direct_no_archive_candidate_changed_before_lock")
            cur.execute(
                "/* direct_no_archive_locked_investigation_holds */ "
                "select event_db_id from investigation_events "
                "where event_db_id=any(%s::bigint[])",
                (ids,),
            )
            if cur.fetchall():
                raise RuntimeError("direct_no_archive_investigation_evidence_changed")
            cur.execute(
                "select event_id from event_facts_v2 "
                "where event_id=any(%s::bigint[]) order by event_id for update nowait",
                (ids,),
            )
            cur.fetchall()
            preservation_check(eligible)
        deleted_ids: list[int] = []
        if eligible:
            ids = [int(candidate["id"]) for candidate in eligible]
            hashes = [candidate["normalized_hash"] for candidate in eligible]
            cur.execute(
                """
                with manifest_row as (
                    select * from unnest(%s::bigint[],%s::bytea[])
                        as value(event_id,normalized_hash)
                )
                delete from events_v2_core event using manifest_row
                where event.id=manifest_row.event_id
                  and event.normalized_hash=manifest_row.normalized_hash
                  and event.time_created_utc < %s
                returning event.id
                """,
                (ids, hashes, frozen_cutoff),
            )
            deleted_ids = sorted(int(row["id"]) for row in cur.fetchall())
            if deleted_ids != sorted(ids):
                raise RuntimeError("direct_no_archive_atomic_delete_mismatch")
        cur.execute(
            """
            /* direct_no_archive_remaining_readback */
            with descriptor(source,event_id,channel,provider_name) as (
                select * from unnest(%s::text[],%s::integer[],%s::text[],%s::text[])
            )
            select count(*)::bigint as remaining
            from events_v2_core event
            join storage_v2_channel channel on channel.id=event.channel_id
            left join storage_v2_provider provider on provider.id=event.provider_id
            join descriptor on descriptor.event_id=event.event_id
                and descriptor.channel=channel.value
                and descriptor.provider_name=coalesce(provider.value,'')
            where event.time_created_utc < %s
            """,
            (sources, event_ids, channels, providers, frozen_cutoff),
        )
        remaining = int(_row_value(cur.fetchone(), "remaining", 0) or 0)
    connection.commit()
    result["deleted_count"] = len(deleted_ids)
    result["remaining_count"] = remaining
    result["batches_committed"] = 1 if deleted_ids else 0
    result["delete_performed"] = bool(deleted_ids)
    if remaining == 0:
        result["status"] = "complete"
    elif result["blocked_without_continuity_count"]:
        result.update(
            status="partial",
            reason="expired_rows_without_continuity_declarations",
        )
    else:
        result["status"] = "partial"
    return result


def execute_postgres_profile_retention(
    connection: Any,
    *,
    policy: StoragePolicy,
    now: datetime | None = None,
    apply: bool = False,
    retention_apply_by_default: bool = False,
    batch_size: int = 1_000,
) -> dict[str, Any]:
    """Inspect or apply a narrow V2 retention plan, failing closed on doubt."""
    result = build_postgres_profile_retention_plan(policy=policy, now=now)
    result["mode"] = "apply" if apply else "dry-run"
    result["apply_requested"] = bool(apply)
    result["retention_apply_by_default"] = bool(retention_apply_by_default)
    if result["status"] != "ready":
        return result
    cutoff = datetime.fromisoformat(str(result["cutoff_utc"]))
    relation = "events_v2_core"
    batch = min(MAX_BATCH_SIZE, max(1, int(batch_size)))
    try:
        with connection.cursor() as cur:
            for required_relation in (relation, *REQUIRED_V2_GUARD_RELATIONS):
                cur.execute("select to_regclass(%s) as relation", (required_relation,))
                if not _row_value(cur.fetchone(), "relation"):
                    result.update(
                        status="blocked",
                        reason="required_v2_guard_relation_missing",
                        missing_relation=required_relation,
                    )
                    return result
            relationship_days = int(policy.relationship_retention_days)
            if relationship_days <= int(policy.db_retention_days):
                result.update(
                    status="blocked",
                    reason="relationship_retention_days_must_exceed_db_retention_days",
                )
                return result
            relationship_cutoff = _as_utc(now) - timedelta(days=relationship_days)
            candidates = _candidate_classifications(
                cur,
                cutoff=cutoff,
                relationship_cutoff=relationship_cutoff,
                batch=batch,
            )
            result["relationship_horizon_days"] = relationship_days
            result["logical_link_lifecycle"] = "separate_unmodified_lifecycle"
            result["candidate_classifications"] = candidates
            result["selected_count"] = len(candidates)
            result["rows_selected"][relation] = len(candidates)
            held_by_reason = dict(result["held_by_reason"])
            for candidate in candidates:
                classification = str(candidate.get("classification") or "held_by_other_dependency")
                if classification != ELIGIBLE:
                    held_by_reason[classification if classification in held_by_reason else "held_by_other_dependency"] += 1
            result["held_by_reason"] = held_by_reason
            result["held_count"] = sum(held_by_reason.values())
            result["eligible_count"] = len(candidates) - result["held_count"]
            # The data-plane compatibility contract is intentionally strict:
            # only ON DELETE CASCADE children may accompany the V2 root.
            cur.execute(
                """
                select con.conname as constraint_name,
                       conrelid::regclass::text as dependent_relation,
                       con.confdeltype as delete_action
                from pg_constraint con
                where con.contype='f'
                  and con.confrelid=to_regclass(%s)
                  and con.confdeltype <> 'c'
                order by con.conname
                """,
                (relation,),
            )
            blockers = [dict(row) if isinstance(row, Mapping) else row for row in cur.fetchall()]
            if blockers:
                result.update(status="blocked", reason="restrictive_dependency_blocks_retention", dependency_blockers=blockers)
                return result
            if not apply:
                result["status"] = "ok"
                return result
            if not retention_apply_by_default:
                result.update(status="blocked", reason="retention_apply_by_default_disabled")
                return result
            cur.execute("set local statement_timeout = '180000ms'")
            cur.execute("set local lock_timeout = '3000ms'")
            eligible_ids = [int(candidate["id"]) for candidate in candidates if candidate.get("classification") == ELIGIBLE]
            if eligible_ids:
                cur.execute(
                    "delete from events_v2_core where id=any(%s) returning id",
                    (eligible_ids,),
                )
                result["rows_deleted"][relation] = int(getattr(cur, "rowcount", 0) or 0)
            result["deleted_count"] = result["rows_deleted"][relation]
        connection.commit()
    except Exception as exc:
        result.update(status="blocked", reason="retention_execution_ambiguous", error_type=type(exc).__name__, error=str(exc))
        return result
    result["status"] = "ok"
    result["batches_committed"] = 1
    result["batch_size"] = batch
    return result


def execute_configured_postgres_profile_retention(
    connection: Any,
    *,
    config: AdLogConfig | None = None,
    now: datetime | None = None,
    apply: bool = False,
    batch_size: int = 1_000,
) -> dict[str, Any]:
    """Use the resolved policy and the existing apply-default admission gate."""
    cfg = config or load_config()
    return execute_postgres_profile_retention(
        connection,
        policy=load_storage_policy(cfg),
        now=now,
        apply=apply,
        retention_apply_by_default=cfg.retention_apply_by_default,
        batch_size=batch_size,
    )

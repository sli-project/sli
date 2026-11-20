"""Transactional Stage 8 I3 provisional→canonical merge executor.

The module owns no connection and never commits.  Its caller must supply one
already-open PostgreSQL transaction under an approved migration identity.
Every mutation, R7 evidence row and semantic replay enqueue succeeds together
or rolls back together.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from hashlib import sha256
import json
import uuid
from typing import Any, Mapping, Sequence

from psycopg import sql

from server.sli.semantic.semantic_processing_repository import (
    PROCESSOR_VERSION,
    enqueue_semantic_job,
)
from server.sli.storage.storage_v2_link_blocks import build_link_blocks


MAX_LINKS_PER_MERGE = 50_000
CONFIRMATION_PREFIX = "MERGE-PROVISIONAL-R7"


@dataclass(frozen=True)
class IdentityMergeResult:
    merge_id: str
    source_entity_id: int
    target_entity_id: int
    source_links_before: int
    target_links_before: int
    target_links_after: int
    affected_events: int
    semantic_replay_events: int
    semantic_jobs_enqueued: int
    target_links_after_sha256: str

    def public_dict(self) -> dict[str, Any]:
        return {
            "status": "merged",
            "merge_id": self.merge_id,
            "source_entity_id": self.source_entity_id,
            "target_entity_id": self.target_entity_id,
            "source_links_before": self.source_links_before,
            "target_links_before": self.target_links_before,
            "target_links_after": self.target_links_after,
            "affected_events": self.affected_events,
            "semantic_replay_events": self.semantic_replay_events,
            "semantic_jobs_enqueued": self.semantic_jobs_enqueued,
            "target_links_after_sha256": self.target_links_after_sha256,
            "source_entity_deleted": False,
            "r7_evidence_immutable": True,
        }


def confirmation_token(source_entity_id: int, target_entity_id: int) -> str:
    return f"{CONFIRMATION_PREFIX}-{int(source_entity_id)}-INTO-{int(target_entity_id)}"


def _digest_rows(rows: Sequence[tuple[int, int, int]]) -> bytes:
    digest = sha256()
    for event_id, entity_id, role_id in sorted(rows):
        digest.update(f"{event_id}:{entity_id}:{role_id}\n".encode("ascii"))
    return digest.digest()


def _digest_event_ids(event_ids: Sequence[int]) -> bytes:
    digest = sha256()
    for event_id in sorted({int(value) for value in event_ids}):
        digest.update(f"{event_id}\n".encode("ascii"))
    return digest.digest()


def _json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    parsed = json.loads(str(value or "{}"))
    if not isinstance(parsed, Mapping):
        raise RuntimeError("entity attributes must be a JSON object")
    return dict(parsed)


def _entity_rows(cur: Any, source_id: int, target_id: int) -> tuple[dict[str, Any], dict[str, Any]]:
    cur.execute(
        """
        select entity.id,entity_type.value as entity_type,entity.natural_key,
               details.attributes_json,entity.entity_type_id,
               entity.source_core_sha256
        from entities_v2 entity
        join storage_v2_entity_type entity_type on entity_type.id=entity.entity_type_id
        left join entity_details_v2 details on details.entity_id=entity.id
        where entity.id=any(%s::integer[])
        order by entity.id
        for update of entity
        """,
        ([source_id, target_id],),
    )
    rows = {int(row["id"]): dict(row) for row in (cur.fetchall() or [])}
    if set(rows) != {source_id, target_id}:
        raise RuntimeError("merge source or target is missing from shared identity spine")
    return rows[source_id], rows[target_id]


def _validate_candidate(source: Mapping[str, Any], target: Mapping[str, Any]) -> None:
    if source["entity_type"] != target["entity_type"]:
        raise RuntimeError("merge source and target entity types differ")
    if int(source["entity_type_id"]) != int(target["entity_type_id"]):
        raise RuntimeError("canonical merge source and target types differ")
    source_attributes = _json_object(source.get("attributes_json"))
    target_attributes = _json_object(target.get("attributes_json"))
    if source_attributes.get("identity_state") != "provisional":
        raise RuntimeError("merge source is not a provisional identity")
    if target_attributes.get("identity_state") not in {"resolved", "external"}:
        raise RuntimeError("merge target is not a permanent identity")
    aliases = {
        str(value) for value in target_attributes.get("identity_aliases", [])
        if str(value)
    }
    if str(source["natural_key"]) not in aliases:
        raise RuntimeError("merge target does not carry the provisional alias")


def _validate_single_target(cur: Any, source: Mapping[str, Any], target_id: int) -> None:
    cur.execute(
        """
        select resolved.id
        from entities_v2 resolved
        join entity_details_v2 details on details.entity_id=resolved.id
        cross join lateral jsonb_array_elements_text(
            coalesce(details.attributes_json->'identity_aliases','[]'::jsonb)
        ) alias(value)
        where resolved.entity_type_id=%s
          and details.attributes_json->>'identity_state' in ('resolved','external')
          and alias.value=%s
        order by resolved.id
        """,
        (int(source["entity_type_id"]), source["natural_key"]),
    )
    candidates = [int(row["id"]) for row in (cur.fetchall() or [])]
    if candidates != [target_id]:
        raise RuntimeError("provisional identity no longer has one exact target")


def _canonical_links(cur: Any, entity_ids: Sequence[int]) -> dict[int, list[tuple[int, int, int]]]:
    cur.execute(
        """
        select block.entity_id,expanded.event_id,expanded.role_id
        from event_entity_link_blocks_v2 block
        cross join lateral unnest(block.event_ids,block.role_ids)
             expanded(event_id,role_id)
        where block.entity_id=any(%s::integer[])
        order by block.entity_id,expanded.event_id,expanded.role_id
        for update of block
        """,
        (list(entity_ids),),
    )
    result: dict[int, list[tuple[int, int, int]]] = defaultdict(list)
    for row in cur.fetchall() or []:
        entity_id = int(row["entity_id"])
        result[entity_id].append(
            (int(row["event_id"]), entity_id, int(row["role_id"]))
        )
    return result


def _reject_external_references(cur: Any, source_id: int) -> None:
    cur.execute(
        """
        select child_ns.nspname as schema_name,child.relname as table_name,
               child_att.attname as column_name
        from pg_constraint constraint_row
        join pg_class child on child.oid=constraint_row.conrelid
        join pg_namespace child_ns on child_ns.oid=child.relnamespace
        join unnest(constraint_row.conkey) with ordinality child_key(attnum,ord) on true
        join unnest(constraint_row.confkey) with ordinality parent_key(attnum,ord)
          on parent_key.ord=child_key.ord
        join pg_attribute child_att on child_att.attrelid=child.oid
          and child_att.attnum=child_key.attnum
        where constraint_row.contype='f'
          and constraint_row.confrelid='entities_v2'::regclass
        order by child_ns.nspname,child.relname,child_att.attname
        """
    )
    allowed = {
        ("public", "entity_details_v2", "entity_id"),
        ("public", "event_entity_link_blocks_v2", "entity_id"),
        ("public", "entity_identity_merges_v2", "source_entity_id"),
        ("public", "entity_identity_merges_v2", "target_entity_id"),
    }
    for raw in cur.fetchall() or []:
        row = dict(raw)
        identity = (row["schema_name"], row["table_name"], row["column_name"])
        if identity in allowed:
            continue
        cur.execute(
            sql.SQL("select count(*)::bigint as rows from {}.{} where {}=%s").format(
                sql.Identifier(row["schema_name"]),
                sql.Identifier(row["table_name"]),
                sql.Identifier(row["column_name"]),
            ),
            (source_id,),
        )
        if int(cur.fetchone()["rows"] or 0):
            raise RuntimeError(f"merge source has external reference {identity}")


def execute_identity_merge(
    cur: Any,
    *,
    source_entity_id: int,
    target_entity_id: int,
    plan_sha256_hex: str,
    confirmation: str,
) -> IdentityMergeResult:
    """Execute one bounded merge inside the caller's transaction."""

    source_id = int(source_entity_id)
    target_id = int(target_entity_id)
    if source_id <= 0 or target_id <= 0 or source_id == target_id:
        raise ValueError("merge entity ids must be distinct positive integers")
    if confirmation != confirmation_token(source_id, target_id):
        raise PermissionError("identity merge confirmation does not match exact ids")
    try:
        plan_sha256 = bytes.fromhex(plan_sha256_hex)
    except ValueError as exc:
        raise ValueError("plan SHA-256 is invalid") from exc
    if len(plan_sha256) != 32:
        raise ValueError("plan SHA-256 must contain 32 bytes")

    cur.execute(
        "select pg_advisory_xact_lock(hashtext('entity_identity_merge_r7'))"
    )
    cur.execute(
        "select merge_id::text from entity_identity_merges_v2 where source_entity_id=%s",
        (source_id,),
    )
    existing = cur.fetchone()
    if existing:
        raise RuntimeError(f"provisional entity already merged as {existing['merge_id']}")

    source, target = _entity_rows(cur, source_id, target_id)
    _validate_candidate(source, target)
    _validate_single_target(cur, source, target_id)
    _reject_external_references(cur, source_id)

    canonical = _canonical_links(cur, [source_id, target_id])
    source_links = canonical.get(source_id, [])
    target_links = canonical.get(target_id, [])
    if len(source_links) > MAX_LINKS_PER_MERGE:
        raise RuntimeError("identity merge exceeds the 50000-link bound")
    source_pairs = {(event_id, role_id) for event_id, _, role_id in source_links}
    target_pairs = {(event_id, role_id) for event_id, _, role_id in target_links}
    if source_pairs & target_pairs:
        raise RuntimeError("canonical merge link collisions require a new reviewed plan")

    merged_rows = [
        {"event_id": event_id, "entity_id": target_id, "role_id": role_id}
        for event_id, role_id in sorted(source_pairs | target_pairs)
    ]
    rebuilt = build_link_blocks(merged_rows)
    affected_event_ids = sorted({event_id for event_id, _ in source_pairs})
    role_ids_by_event: dict[int, list[int]] = defaultdict(list)
    for event_id, role_id in sorted(source_pairs):
        role_ids_by_event[event_id].append(role_id)

    cur.execute(
        """
        select distinct normalized.source_event_id
        from normalized_events normalized
        cross join lateral jsonb_each_text(normalized.roles_json) role
        where normalized.source_event_id=any(%s::bigint[])
          and role.value=%s
        order by normalized.source_event_id
        """,
        (affected_event_ids or [0], source["natural_key"]),
    )
    replay_event_ids = [int(row["source_event_id"]) for row in (cur.fetchall() or [])]

    source_digest = _digest_rows(source_links)
    target_before_digest = _digest_rows(target_links)
    target_after_rows = [
        (int(row["event_id"]), target_id, int(row["role_id"]))
        for row in merged_rows
    ]
    target_after_digest = _digest_rows(target_after_rows)
    events_digest = _digest_event_ids(affected_event_ids)
    merge_id = str(uuid.uuid5(
        uuid.NAMESPACE_URL,
        f"adlog:identity-merge-r7:{source_id}:{target_id}:{plan_sha256.hex()}",
    ))
    evidence = {
        "contract": "entity_identity_merge_r7/v1",
        "collision_policy": "fail_closed_zero_only",
        "canonical_authority": "event_entity_link_blocks_v2",
        # Storage V1 links no longer exist (migration 097); key kept for evidence stability.
        "legacy_source_links_before": 0,
        "source_entity_deleted": False,
        "read_boundary": "entities_v2_active",
        "future_write_boundary": "resolve_entity_identity_v2",
        "semantic_replay": "versioned_identity_merge",
    }

    cur.execute(
        "delete from event_entity_link_blocks_v2 where entity_id=any(%s::integer[])",
        ([source_id, target_id],),
    )
    for block in rebuilt:
        cur.execute(
            """
            insert into event_entity_link_blocks_v2(
                entity_id,block_no,first_event_id,last_event_id,
                event_ids,role_ids,identity_sha256
            ) values(%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                block.entity_id,
                block.block_no,
                block.first_event_id,
                block.last_event_id,
                list(block.event_ids),
                list(block.role_ids),
                block.identity_sha256,
            ),
        )
    cur.execute(
        """
        insert into entity_identity_merges_v2(
            merge_id,source_entity_id,target_entity_id,
            source_natural_key,target_natural_key,plan_sha256,
            source_core_sha256_before,target_core_sha256_before,
            source_links_before,target_links_before,target_links_after,
            source_links_sha256,target_links_before_sha256,
            target_links_after_sha256,affected_events,affected_events_sha256,
            semantic_replay_events,evidence_json
        ) values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
        """,
        (
            merge_id,
            source_id,
            target_id,
            source["natural_key"],
            target["natural_key"],
            plan_sha256,
            bytes(source["source_core_sha256"]),
            bytes(target["source_core_sha256"]),
            len(source_links),
            len(target_links),
            len(target_after_rows),
            source_digest,
            target_before_digest,
            target_after_digest,
            len(affected_event_ids),
            events_digest,
            len(replay_event_ids),
            json.dumps(evidence, sort_keys=True, separators=(",", ":")),
        ),
    )
    replay_set = set(replay_event_ids)
    for event_id in affected_event_ids:
        cur.execute(
            """
            insert into entity_identity_merge_events_v2(
                merge_id,source_event_id,source_role_ids,semantic_replay_required,
                source_event_sha256,source_occurred_at_utc
            )
            select %s,source.id,%s,%s,source.normalized_hash,
                   source.time_created_utc
            from events_v2_core source where source.id=%s
            """,
            (
                merge_id,
                sorted(set(role_ids_by_event[event_id])),
                event_id in replay_set,
                event_id,
            ),
        )
        if getattr(cur, "rowcount", 1) != 1:
            raise RuntimeError("merge source event disappeared before R7 evidence")
    processor_version = f"{PROCESSOR_VERSION}+r7-{merge_id.replace('-', '')[:12]}"
    job_ids = []
    for event_id in replay_event_ids:
        job_ids.append(enqueue_semantic_job(
            cur,
            source_event_id=event_id,
            job_kind="semantic_replay",
            processor_version=processor_version,
            payload={"identity_merge_id": merge_id},
        ))

    cur.execute(
        "select count(*)::bigint as rows from event_entity_link_blocks_v2 where entity_id=%s",
        (source_id,),
    )
    if int(cur.fetchone()["rows"] or 0) != 0:
        raise RuntimeError("merged source link blocks survived transaction")
    cur.execute(
        """
        select expanded.event_id,block.entity_id,expanded.role_id
        from event_entity_link_blocks_v2 block
        cross join lateral unnest(block.event_ids,block.role_ids)
             expanded(event_id,role_id)
        where block.entity_id=%s
        order by expanded.event_id,expanded.role_id
        """,
        (target_id,),
    )
    readback = [
        (int(row["event_id"]), int(row["entity_id"]), int(row["role_id"]))
        for row in (cur.fetchall() or [])
    ]
    if readback != sorted(target_after_rows):
        raise RuntimeError("identity merge target link readback mismatch")

    return IdentityMergeResult(
        merge_id=merge_id,
        source_entity_id=source_id,
        target_entity_id=target_id,
        source_links_before=len(source_links),
        target_links_before=len(target_links),
        target_links_after=len(target_after_rows),
        affected_events=len(affected_event_ids),
        semantic_replay_events=len(replay_event_ids),
        semantic_jobs_enqueued=len(job_ids),
        target_links_after_sha256=target_after_digest.hex(),
    )


def record_scenario_identity_supersessions(cur: Any, *, new_scenario_id: str) -> int:
    """Append old→new scenario evidence after a replayed risk evaluation."""

    cur.execute(
        "select to_regclass('entity_identity_scenario_supersessions_v2') is not null as available"
    )
    if not bool(dict(cur.fetchone() or {}).get("available")):
        return 0
    cur.execute(
        """
        insert into entity_identity_scenario_supersessions_v2(
            merge_id,old_scenario_id,new_scenario_id
        )
        select distinct replay.merge_id,old_evidence.scenario_id,%s::uuid
        from semantic_scenario_evidence new_evidence
        join entity_identity_semantic_replays_v2 replay
          on replay.new_normalized_event_id=new_evidence.normalized_event_id
        join semantic_scenario_evidence old_evidence
          on old_evidence.normalized_event_id=replay.old_normalized_event_id
        join semantic_security_scenarios old_scenario
          on old_scenario.scenario_id=old_evidence.scenario_id
        join semantic_security_scenarios new_scenario
          on new_scenario.scenario_id=%s::uuid
        where new_evidence.scenario_id=%s::uuid
          and old_evidence.scenario_id<>%s::uuid
          and old_scenario.scenario_kind=new_scenario.scenario_kind
          and old_scenario.result_class=new_scenario.result_class
        on conflict do nothing
        """,
        (new_scenario_id, new_scenario_id, new_scenario_id, new_scenario_id),
    )
    return max(0, int(getattr(cur, "rowcount", 0) or 0))


def record_finding_identity_supersessions(
    cur: Any,
    *,
    new_scenario_id: str,
    new_finding_id: int,
) -> int:
    """Append old→new finding evidence after the new publication exists."""

    cur.execute(
        "select to_regclass('entity_identity_finding_supersessions_v2') "
        "is not null as available"
    )
    if not bool(dict(cur.fetchone() or {}).get("available")):
        return 0
    cur.execute(
        """
        insert into entity_identity_finding_supersessions_v2(
            merge_id,old_scenario_id,new_scenario_id,
            old_finding_id,new_finding_id
        )
        select supersession.merge_id,supersession.old_scenario_id,
               supersession.new_scenario_id,old_publication.finding_id,%s
        from entity_identity_scenario_supersessions_v2 supersession
        join semantic_finding_publications old_publication
          on old_publication.scenario_id=supersession.old_scenario_id
        where supersession.new_scenario_id=%s
          and old_publication.finding_id<>%s
        on conflict do nothing
        """,
        (int(new_finding_id), new_scenario_id, int(new_finding_id)),
    )
    return max(0, int(getattr(cur, "rowcount", 0) or 0))

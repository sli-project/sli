"""PostgreSQL persistence for the core identity API, in a caller transaction."""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from server.sli.entities.core_identity import EntityIdentifier, EntityObservation, IdentityResolution


class PostgresIdentityRepository:
    def __init__(self, cursor: Any, *, identifier_adapters=()):
        self.cursor = cursor
        self.identifier_adapters = tuple(identifier_adapters)

    def find_identifier(self, kind: str, identifier: EntityIdentifier) -> tuple[int, ...]:
        self.cursor.execute(
            """select entity_id from core_entity_identifiers
               where entity_kind=%s and namespace=%s and scope_id=%s and value=%s and strength='stable'
               order by entity_id""",
            (kind, identifier.namespace, identifier.scope_id, identifier.value),
        )
        ids = {int(row["entity_id"]) for row in self.cursor.fetchall()}
        for adapter in self.identifier_adapters:
            ids.update(adapter(self.cursor, kind, identifier))
        return tuple(sorted(ids))

    def ensure_entity(self, kind: str, key: str, observation: EntityObservation) -> int:
        cur = self.cursor
        cur.execute("insert into storage_v2_entity_type(value) values(%s) on conflict(value) do update set value=excluded.value returning id", (kind,))
        type_id = int(cur.fetchone()["id"])
        # Reuse the canonical allocator (090), which superseded the shared
        # sequence introduced by 034/045. Never mint an independent entity ID.
        cur.execute(
            """insert into storage_v2_entity_identity_allocations(entity_type_id,natural_key)
               values(%s,%s) on conflict(entity_type_id,natural_key) do nothing""", (type_id, key),
        )
        cur.execute("select id from storage_v2_entity_identity_allocations where entity_type_id=%s and natural_key=%s", (type_id, key))
        entity_id = int(cur.fetchone()["id"])
        cur.execute(
            """insert into entities_v2(id,entity_type_id,natural_key,display_name,first_seen_utc,last_seen_utc,source_core_sha256)
               values(%s,%s,%s,%s,%s,%s,%s)
               on conflict(entity_type_id,natural_key) do update set
                   first_seen_utc=least(entities_v2.first_seen_utc,excluded.first_seen_utc),
                   last_seen_utc=greatest(entities_v2.last_seen_utc,excluded.last_seen_utc)
               returning id""",
            (entity_id, type_id, key, f"{kind} identity", observation.observed_at_utc, observation.observed_at_utc, bytes.fromhex(observation.fingerprint)),
        )
        actual_id = int(cur.fetchone()["id"])
        if actual_id != entity_id:
            raise ValueError("core_identity_allocation_conflict")
        return entity_id

    def add_identifier(self, entity_id: int, kind: str, identifier: EntityIdentifier) -> None:
        cur = self.cursor
        cur.execute(
            """insert into core_entity_identifiers(entity_id,entity_kind,namespace,scope_id,value,strength)
               values(%s,%s,%s,%s,%s,%s) on conflict do nothing""",
            (entity_id, kind, identifier.namespace, identifier.scope_id, identifier.value, identifier.strength),
        )
        if identifier.strength == "stable":
            cur.execute(
                """select entity_id from core_entity_identifiers
                   where entity_kind=%s and namespace=%s and scope_id=%s and value=%s and strength='stable'""",
                (kind, identifier.namespace, identifier.scope_id, identifier.value),
            )
            if int(cur.fetchone()["entity_id"]) != entity_id:
                raise ValueError("core_identity_identifier_conflict")

    def record_observation(self, observation: EntityObservation, resolution: IdentityResolution) -> None:
        if resolution.entity_id is not None:
            self.cursor.execute(
                """update entities_v2 set first_seen_utc=least(first_seen_utc,%s),last_seen_utc=greatest(last_seen_utc,%s)
                   where id=%s""", (observation.observed_at_utc, observation.observed_at_utc, resolution.entity_id),
            )
        self.cursor.execute(
            """insert into core_entity_observations(
                   observation_sha256,plugin_id,source_instance_id,entity_kind,entity_id,
                   observed_at_utc,identifiers_json,evidence_refs,resolution,candidate_ids,reason)
               values(%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s,%s,%s)
               on conflict(observation_sha256) do nothing""",
            (bytes.fromhex(observation.fingerprint), observation.plugin_id, observation.source_instance_id, observation.kind,
             resolution.entity_id, observation.observed_at_utc, json.dumps([asdict(item) for item in observation.identifiers]),
             list(observation.evidence_refs), resolution.state, list(resolution.candidate_ids), resolution.reason),
        )

    def association_targets(self, entity_id: int, relation: str) -> list[int]:
        cur = self.cursor
        cur.execute("select pg_advisory_xact_lock(hashtext('core_identity_association'),%s)", (entity_id,))
        cur.execute("select id from entities_v2 where id=%s", (entity_id,))
        if cur.fetchone() is None:
            raise ValueError("identity_entity_not_found")
        cur.execute("select distinct target_entity_id from core_entity_associations where source_entity_id=%s and relation=%s order by target_entity_id", (entity_id, relation))
        return [int(row["target_entity_id"]) for row in cur.fetchall()]

    def record_association(self, source: int, target: int, relation: str, actor_id: int, evidence_refs: tuple[str, ...]) -> None:
        cur = self.cursor
        cur.execute(
            """select e.id,t.value as kind from entities_v2 e
               join storage_v2_entity_type t on t.id=e.entity_type_id where e.id=any(%s)""", ([source, target],),
        )
        kinds = {int(row["id"]): row["kind"] for row in cur.fetchall()}
        if kinds.get(source) not in {"device", "asset", "workstation"} or kinds.get(target) != "ad_computer":
            raise ValueError("directory_computer_association_requires_devices")
        cur.execute(
            """insert into core_entity_associations(source_entity_id,target_entity_id,relation,actor_id,evidence_refs)
               values(%s,%s,%s,%s,%s)""", (source, target, relation, actor_id, list(evidence_refs)),
        )

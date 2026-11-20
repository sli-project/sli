from __future__ import annotations

import json
from datetime import datetime
from hashlib import sha256
from typing import Any

from server.sli.plugins.ad.context.contracts import (
    canonical_sha256,
    record_content_sha256,
    validate_bundle,
)
from server.sli.plugins.ad.snapshots.store import (
    publish_snapshot_manifest, load_projection_manifest, load_exact_projection_source,
    _resolve_manifest_source,
)
from server.sli.entities.context_identity import (
    _resolve_domain, _preload_existing_entity_ids, _require_entity_identity,
    persist_entity_identity,
)
from server.sli.plugins.gpo.snapshot_store import _store_gpo_v2_snapshot
from server.sli.plugins.ad.snapshots.manifest import (
    SnapshotManifestError, snapshot_composition, validate_snapshot_manifest,
)
from server.sli.plugins.ad.snapshots.projection import insert_projection_receipts
from server.sli.sources.gpo_v2_source import canonical_snapshot, redact_gpo_snapshot

SUPPLEMENTAL_ENTITY_ATTRIBUTE_SECTIONS = frozenset(
    {
        "directory_group_graph",
        "directory_exact_logon",
        "privileged_membership",
        "vpn_membership",
    }
)


class AdContextOutOfOrderError(ValueError):
    """A newer completed observation already owns the affected sections."""


def materialize_entity_attributes(
    existing: dict[str, Any],
    incoming: dict[str, Any],
    *,
    section: str,
) -> dict[str, Any]:
    if section not in SUPPLEMENTAL_ENTITY_ATTRIBUTE_SECTIONS:
        return dict(incoming)
    return {**existing, **incoming}


def import_bundle(conn: Any, bundle: dict[str, Any]) -> dict[str, int]:
    """Import one validated bundle into schema 17 in a single transaction.

    The caller owns the connection transaction. This function performs no DDL,
    does not collect from AD, and does not start or change a schedule.
    """
    normalized = validate_bundle(bundle)
    with conn.cursor() as cur:
        domain_id = _resolve_domain(cur, normalized["domain"])
        replay = _start_run(cur, domain_id, normalized)
        if replay:
            return {
                "replayed": 1,
                "entities_changed": 0,
                "entities_closed": 0,
                "relations_changed": 0,
                "relations_closed": 0,
            }
        # Preserve validated input and its hash; only persisted section metadata
        # and absence reconciliation use the conservative effective status.
        declared_sections = {}
        for declared_section in normalized["sections"]:
            section = dict(declared_section)
            # Older exporters promoted incomplete native acquisition to complete.
            # Legacy sections without a native snapshot keep their own status.
            if (
                section["name"] == "gpo_governance"
                and section["status"] == "complete"
                and normalized.get("gpo_v2_snapshot") is not None
            ):
                snapshot = normalized["gpo_v2_snapshot"]
                states = snapshot.get("source_states", {})
                if (
                    snapshot.get("collection_status") != "complete"
                    or any(
                        states.get(name, {}).get("status") != "observed"
                        for name in ("gpo_list", "gpc_directory")
                    )
                ):
                    section["status"] = "partial"
            declared_sections[section["name"]] = section
            cur.execute(
                """
                insert into ad_context_sections(
                    run_id, section_name, status, record_count, duration_ms, error_code
                ) values (%s, %s, %s, %s, %s, %s)
                """,
                (
                    normalized["run_id"], section["name"], section["status"],
                    section["record_count"], section["duration_ms"], section["error_code"],
                ),
            )

        entity_ids: dict[str, int] = {}
        existing_entity_ids = _preload_existing_entity_ids(
            cur, domain_id, normalized["records"]
        )
        entities_changed = 0
        entities_closed = 0
        relations_changed = 0
        relations_closed = 0
        # Batch lookups predate every write. Exact-logon records can repeat a
        # newly inserted account GUID under a different sectional record key.
        observed_entities: dict[str, tuple[int, dict[str, Any]]] = {}
        for record in normalized["records"]:
            if record["record_type"] != "entity":
                continue
            identity = record["identity"]
            guid = identity["object_guid"]
            existing_entity_id = existing_entity_ids.get(record["record_key"])
            if guid in observed_entities:
                observed_id, observed_identity = observed_entities[guid]
                if (
                    observed_identity["kind"] != identity["kind"]
                    or (observed_identity.get("object_sid") and identity.get("object_sid")
                        and observed_identity["object_sid"].casefold() != identity["object_sid"].casefold())
                    or (existing_entity_id is not None and existing_entity_id != observed_id)
                ):
                    raise ValueError("stable GUID alias conflicts with entity identity")
                existing_entity_id = observed_id
                identity = {**identity, "object_sid": observed_identity.get("object_sid") or identity.get("object_sid")}
            entity_id = _upsert_entity(
                cur,
                domain_id,
                normalized["run_id"],
                record,
                existing_entity_id=existing_entity_id,
                lookup_complete=True,
            )
            observed_entities[guid] = (entity_id, identity)
            entity_ids[record["record_key"]] = entity_id
            entities_changed += _observe_entity(cur, entity_id, normalized["run_id"], record)
            _write_evidence(cur, normalized, record)

        for section_name in (
            "directory_accounts",
            "directory_group_graph",
            "directory_exact_logon",
            "gpo_governance",
        ):
            section = declared_sections.get(section_name)
            if (
                not section
                or section["status"] != "complete"
                or normalized["mode"] not in {"full", "reconcile"}
            ):
                continue
            seen_entity_ids = sorted(
                entity_ids[record["record_key"]]
                for record in normalized["records"]
                if record["record_type"] == "entity"
                and record["section"] == section_name
            )
            cur.execute(
                """
                update ad_context_entity_versions version
                set valid_to_utc=%s
                from entities_v2 entity
                where version.entity_id=entity.id
                  and entity.domain_id=%s
                  and version.source_section=%s
                  and version.valid_to_utc is null
                  and not (version.entity_id = any(%s))
                """,
                (
                    normalized["observed_at_utc"],
                    domain_id,
                    section_name,
                    seen_entity_ids,
                ),
            )
            entities_closed += cur.rowcount

        seen_relations: set[str] = set()
        for record in normalized["records"]:
            if record["record_type"] == "data_quality":
                _write_evidence(cur, normalized, record)
                continue
            if record["record_type"] != "relation":
                continue
            try:
                source_id = entity_ids[record["source_record_key"]]
                target_id = entity_ids[record["target_record_key"]]
            except KeyError as exc:
                raise ValueError("relation endpoints must be present in the same first-slice bundle") from exc
            relations_changed += _observe_relation(
                cur, domain_id, source_id, target_id, normalized["run_id"], record
            )
            seen_relations.add(record["record_key"])
            _write_evidence(cur, normalized, record)

        for section_name, scope_key in (
            ("privileged_membership", "privileged_group_sids"),
            ("vpn_membership", "vpn_group_sids"),
        ):
            section = declared_sections.get(section_name)
            if not section or section["status"] != "complete" or normalized["mode"] not in {"full", "reconcile"}:
                continue
            scoped_group_sids = {value.casefold() for value in normalized["scope"].get(scope_key, [])}
            scoped_target_keys = {
                record["record_key"]
                for record in normalized["records"]
                if record["record_type"] == "entity"
                and record["identity"]["kind"] == "ad_group"
                and str(record["identity"].get("object_sid") or "").casefold() in scoped_group_sids
            }
            section_relations = [
                record for record in normalized["records"]
                if record["record_type"] == "relation" and record["section"] == section_name
            ]
            scoped_target_keys.update(record["target_record_key"] for record in section_relations)
            scoped_group_ids = sorted(entity_ids[key] for key in scoped_target_keys)
            section_seen_relations = sorted(record["record_key"] for record in section_relations)
            cur.execute(
                """
                update ad_context_relation_versions
                set valid_to_utc=%s
                where domain_id=%s and source_section=%s
                  and target_entity_id = any(%s)
                  and valid_to_utc is null and not (relation_key = any(%s))
                """,
                (normalized["observed_at_utc"], domain_id, section_name, scoped_group_ids, section_seen_relations),
            )
            relations_closed += cur.rowcount

        graph_section = declared_sections.get("directory_group_graph")
        if (
            graph_section
            and graph_section["status"] == "complete"
            and normalized["mode"] in {"full", "reconcile"}
        ):
            graph_seen_relations = sorted(
                record["record_key"]
                for record in normalized["records"]
                if record["record_type"] == "relation"
                and record["section"] == "directory_group_graph"
            )
            cur.execute(
                """
                update ad_context_relation_versions
                set valid_to_utc=%s
                where domain_id=%s and source_section='directory_group_graph'
                  and valid_to_utc is null and not (relation_key = any(%s))
                """,
                (normalized["observed_at_utc"], domain_id, graph_seen_relations),
            )
            relations_closed += cur.rowcount

        if normalized.get("gpo_v2_snapshot") is not None:
            _store_gpo_v2_snapshot(
                cur,
                domain_id=domain_id,
                run_id=normalized["run_id"],
                snapshot=normalized["gpo_v2_snapshot"],
            )

        cur.execute(
            "update ad_context_runs set status='completed', completed_at=now() where run_id=%s",
            (normalized["run_id"],),
        )
    return {
        "replayed": 0,
        "entities_changed": entities_changed,
        "entities_closed": entities_closed,
        "relations_changed": relations_changed,
        "relations_closed": relations_closed,
    }


def _start_run(cur: Any, domain_id: int, bundle: dict[str, Any]) -> bool:
    digest = bytes.fromhex(bundle["bundle_sha256"])
    cur.execute("select bundle_sha256, status from ad_context_runs where run_id=%s", (bundle["run_id"],))
    existing = cur.fetchone()
    if existing:
        if bytes(existing["bundle_sha256"]) != digest:
            raise ValueError("run_id replay has a different bundle hash")
        if existing["status"] != "completed":
            raise ValueError("an incomplete import with this run_id already exists")
        return True
    cur.execute(
        """
        select section.section_name, max(run.observed_at_utc) as latest
        from ad_context_runs run
        join ad_context_sections section on section.run_id=run.run_id
        where run.domain_id=%s and run.source_pack_id=%s
          and run.status='completed' and section.section_name=any(%s)
        group by section.section_name
        """,
        (
            domain_id,
            bundle["source_pack_id"],
            sorted(item["name"] for item in bundle["sections"]),
        ),
    )
    latest_by_section = {
        str(row["section_name"]): row.get("latest")
        for row in cur.fetchall()
    }
    observed_at = datetime.fromisoformat(bundle["observed_at_utc"].replace("Z", "+00:00"))
    stale_sections = sorted(
        section
        for section, latest in latest_by_section.items()
        if latest is not None and observed_at < latest
    )
    if stale_sections:
        raise AdContextOutOfOrderError(
            "out-of-order AD Context bundle is not allowed for sections: "
            + ",".join(stale_sections)
        )
    cur.execute(
        """
        insert into ad_context_runs(
            run_id, source_pack_id, source_pack_version, domain_id, mode,
            observed_at_utc, bundle_sha256, scope_json, status
        ) values (%s, %s, %s, %s, %s, %s, %s, %s::jsonb, 'importing')
        """,
        (
            bundle["run_id"], bundle["source_pack_id"], bundle["source_pack_version"], domain_id,
            bundle["mode"], bundle["observed_at_utc"], digest,
            json.dumps(bundle["scope"], ensure_ascii=False, sort_keys=True),
        ),
    )
    return False


def _upsert_entity(
    cur: Any,
    domain_id: int,
    run_id: str,
    record: dict[str, Any],
    *,
    existing_entity_id: int | None = None,
    lookup_complete: bool = False,
) -> int:
    identity = record["identity"]
    object_sid = identity.get("object_sid")
    entity_id = existing_entity_id
    if object_sid and entity_id is None and not lookup_complete:
        cur.execute(
            """
            select alias.entity_id, entity.domain_id, entity.natural_key,
                   entity_type.value as entity_type,
                   guid_alias.entity_id as guid_entity_id
            from ad_context_entity_aliases alias
            join entities_v2 entity on entity.id=alias.entity_id
            join storage_v2_entity_type entity_type
              on entity_type.id=entity.entity_type_id
            left join ad_context_entity_aliases guid_alias
              on guid_alias.domain_id=alias.domain_id
             and guid_alias.alias_type='object_guid'
             and guid_alias.normalized_value=lower(%s)
            where alias.domain_id=%s and alias.alias_type='object_sid'
              and alias.normalized_value=lower(%s)
            """,
            (identity.get("object_guid"), domain_id, object_sid),
        )
        alias = cur.fetchone()
        if alias:
            _require_entity_identity(
                alias,
                domain_id,
                record,
                guid_entity_id=(
                    int(alias["guid_entity_id"])
                    if alias.get("guid_entity_id") is not None
                    else None
                ),
            )
            entity_id = int(alias["entity_id"])
    if entity_id is None and not lookup_complete:
        cur.execute(
            """
            select entity.id from entities_v2 entity
            join storage_v2_entity_type entity_type on entity_type.id=entity.entity_type_id
            where entity.domain_id=%s
              and entity_type.value=%s and entity.natural_key=%s limit 1
            """,
            (domain_id, identity["kind"], record["record_key"]),
        )
        exact = cur.fetchone()
        if exact:
            entity_id = int(exact["id"])
    if object_sid and entity_id is None and not lookup_complete:
        cur.execute(
            """
            select entity.id as entity_id, entity.domain_id, entity.natural_key,
                   entity_type.value as entity_type,
                   guid_alias.entity_id as guid_entity_id
            from entities_v2 entity
            join entity_details_v2 details on details.entity_id=entity.id
            join storage_v2_entity_type entity_type
              on entity_type.id=entity.entity_type_id
            left join ad_context_entity_aliases guid_alias
              on guid_alias.domain_id=entity.domain_id
             and guid_alias.alias_type='object_guid'
             and guid_alias.normalized_value=lower(%s)
            where entity.domain_id=%s and lower(details.attributes_json->>'sid')=lower(%s)
            order by entity.id limit 2
            """,
            (identity.get("object_guid"), domain_id, object_sid),
        )
        matches = list(cur.fetchall())
        if len(matches) == 1:
            _require_entity_identity(
                matches[0],
                domain_id,
                record,
                guid_entity_id=(
                    int(matches[0]["guid_entity_id"])
                    if matches[0].get("guid_entity_id") is not None
                    else None
                ),
            )
            entity_id = int(matches[0]["entity_id"])
    incoming_attributes = {
        **record["attributes"],
        "object_guid": identity["object_guid"],
        "sid": object_sid,
    }
    existing_attributes: dict[str, Any] = {}
    section_name = str(record["section"])
    if section_name in SUPPLEMENTAL_ENTITY_ATTRIBUTE_SECTIONS:
        cur.execute(
            "select attributes_json from entity_details_v2 where entity_id=%s",
            (entity_id,),
        )
        existing_details = cur.fetchone()
        if existing_details:
            existing_attributes = dict(existing_details["attributes_json"] or {})
    attributes = materialize_entity_attributes(
        existing_attributes,
        incoming_attributes,
        section=section_name,
    )
    if identity["kind"] in {"ad_user", "ad_computer"} and section_name in SUPPLEMENTAL_ENTITY_ATTRIBUTE_SECTIONS:
        attributes.pop("display_name", None)
        if "display_name" in existing_attributes:
            attributes["display_name"] = existing_attributes["display_name"]
    entity_id = persist_entity_identity(
        cur, domain_id, record, entity_id=entity_id, attributes=attributes,
    )
    aliases = {
        "object_guid": identity["object_guid"],
        "object_sid": object_sid,
        "distinguished_name": record["attributes"].get("distinguished_name"),
        # Production AD contains distinct group objects with the same
        # sAMAccountName.  GUID/SID/DN remain authoritative group identities;
        # keep the name as an attribute without claiming global uniqueness.
        "sam_account_name": (
            record["attributes"].get("sam_account_name")
            if identity["kind"] in {"ad_user", "ad_computer"}
            else None
        ),
    }
    for alias_type, alias_value in aliases.items():
        if not alias_value:
            continue
        normalized = str(alias_value).strip().casefold()
        cur.execute(
            """
            insert into ad_context_entity_aliases(
                entity_id, domain_id, alias_type, alias_value, normalized_value,
                first_seen_utc, last_seen_utc, source_run_id
            ) values (%s, %s, %s, %s, %s, %s, %s, %s)
            on conflict(domain_id, alias_type, normalized_value) do update set
                last_seen_utc=greatest(ad_context_entity_aliases.last_seen_utc, excluded.last_seen_utc),
                source_run_id=excluded.source_run_id
            where ad_context_entity_aliases.entity_id=excluded.entity_id
            """,
            (entity_id, domain_id, alias_type, str(alias_value), normalized, record["observed_at_utc"], record["observed_at_utc"], run_id),
        )
        if cur.rowcount != 1:
            raise ValueError(f"stable alias {alias_type} already belongs to a different SLI entity")
    return entity_id


def _observe_entity(cur: Any, entity_id: int, run_id: str, record: dict[str, Any]) -> int:
    digest = bytes.fromhex(record_content_sha256(record))
    cur.execute(
        "select id, content_sha256 from ad_context_entity_versions where entity_id=%s and source_section=%s and valid_to_utc is null",
        (entity_id, record["section"]),
    )
    current = cur.fetchone()
    if current and bytes(current["content_sha256"]) == digest:
        cur.execute(
            "update ad_context_entity_versions set last_observed_at_utc=greatest(last_observed_at_utc, %s) where id=%s",
            (record["observed_at_utc"], current["id"]),
        )
        return 0
    if current:
        cur.execute("update ad_context_entity_versions set valid_to_utc=%s where id=%s", (record["observed_at_utc"], current["id"]))
    cur.execute(
        """
        insert into ad_context_entity_versions(
            entity_id, source_section, valid_from_utc, last_observed_at_utc,
            content_sha256, attributes_json, source_run_id
        ) values (%s, %s, %s, %s, %s, %s::jsonb, %s)
        """,
        (entity_id, record["section"], record["observed_at_utc"], record["observed_at_utc"], digest, json.dumps(record, ensure_ascii=False), run_id),
    )
    return 1


def _observe_relation(cur: Any, domain_id: int, source_id: int, target_id: int, run_id: str, record: dict[str, Any]) -> int:
    digest = bytes.fromhex(record_content_sha256(record))
    cur.execute(
        "select id, content_sha256 from ad_context_relation_versions where domain_id=%s and relation_key=%s and valid_to_utc is null",
        (domain_id, record["record_key"]),
    )
    current = cur.fetchone()
    if current and bytes(current["content_sha256"]) == digest:
        cur.execute(
            "update ad_context_relation_versions set last_observed_at_utc=greatest(last_observed_at_utc, %s) where id=%s",
            (record["observed_at_utc"], current["id"]),
        )
        return 0
    if current:
        cur.execute("update ad_context_relation_versions set valid_to_utc=%s where id=%s", (record["observed_at_utc"], current["id"]))
    cur.execute(
        """
        insert into ad_context_relation_versions(
            relation_key, relation_kind, source_entity_id, target_entity_id, source_section,
            domain_id, valid_from_utc, last_observed_at_utc, content_sha256, attributes_json, source_run_id
        ) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s)
        """,
        (
            record["record_key"], record["relation_kind"], source_id, target_id, record["section"], domain_id,
            record["observed_at_utc"], record["observed_at_utc"], digest, json.dumps(record, ensure_ascii=False), run_id,
        ),
    )
    return 1


def _write_evidence(cur: Any, bundle: dict[str, Any], record: dict[str, Any]) -> None:
    evidence_type = {
        "entity": "entity_observation", "relation": "relation_observation", "data_quality": "data_quality"
    }[record["record_type"]]
    locator = {"run_id": bundle["run_id"], "record_key": record["record_key"], "section": record["section"]}
    evidence_key = f"adctx:{bundle['run_id']}:{record['record_key']}"
    cur.execute(
        """
        insert into ad_context_evidence(
            evidence_key, evidence_type, source_pack_id, source_run_id,
            observed_at_utc, locator_json, integrity_sha256
        ) values (%s, %s, %s, %s, %s, %s::jsonb, %s)
        on conflict(evidence_key) do nothing
        """,
        (
            evidence_key, evidence_type, bundle["source_pack_id"], bundle["run_id"], record["observed_at_utc"],
            json.dumps(locator, ensure_ascii=False), bytes.fromhex(canonical_sha256(record)),
        ),
    )

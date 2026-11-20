"""Shared domain resolution and entity identity persistence for context imports."""
from __future__ import annotations

import json
from hashlib import sha256
from typing import Any

def _resolve_domain(cur: Any, domain: dict[str, str]) -> int:
    cur.execute(
        "select id, domain_sid from domains where lower(fqdn)=lower(%s) order by id",
        (domain["dns_name"],),
    )
    rows = list(cur.fetchall())
    if len(rows) != 1:
        raise ValueError("AD Context requires exactly one pre-existing SLI domain matched by FQDN")
    row = rows[0]
    configured_sid = str(row.get("domain_sid") or "").strip()
    if configured_sid and configured_sid.casefold() != domain["sid"].casefold():
        raise ValueError("bundle domain SID conflicts with the configured SLI domain")
    if not configured_sid:
        cur.execute("update domains set domain_sid=%s where id=%s and domain_sid is null", (domain["sid"], row["id"]))
    return int(row["id"])


def _preload_existing_entity_ids(
    cur: Any,
    domain_id: int,
    records: list[dict[str, Any]],
) -> dict[str, int]:
    """Resolve a whole bundle without repeating a JSON scan for every entity."""
    entities = [record for record in records if record["record_type"] == "entity"]
    if not entities:
        return {}

    resolved: dict[str, int] = {}
    keys_by_sid: dict[str, list[str]] = {}
    keys_by_guid: dict[str, list[str]] = {}
    for record in entities:
        object_sid = str(record["identity"].get("object_sid") or "").strip().casefold()
        if object_sid:
            keys_by_sid.setdefault(object_sid, []).append(record["record_key"])
        object_guid = str(record["identity"].get("object_guid") or "").strip().casefold()
        if object_guid:
            keys_by_guid.setdefault(object_guid, []).append(record["record_key"])

    sid_rows: list[dict[str, Any]] = []
    if keys_by_sid:
        cur.execute(
            """
            select alias.normalized_value, alias.entity_id, entity.domain_id,
                   entity.natural_key, entity_type.value as entity_type
            from ad_context_entity_aliases alias
            join entities_v2 entity on entity.id=alias.entity_id
            join storage_v2_entity_type entity_type
              on entity_type.id=entity.entity_type_id
            where alias.domain_id=%s and alias.alias_type='object_sid'
              and alias.normalized_value = any(%s)
            """,
            (domain_id, sorted(keys_by_sid)),
        )
        sid_rows = [dict(row) for row in cur.fetchall()]

    entity_ids_by_guid: dict[str, int] = {}
    if keys_by_guid:
        cur.execute(
            """
            select normalized_value, entity_id
            from ad_context_entity_aliases
            where domain_id=%s and alias_type='object_guid'
              and normalized_value = any(%s)
            """,
            (domain_id, sorted(keys_by_guid)),
        )
        entity_ids_by_guid = {
            str(row["normalized_value"]).casefold(): int(row["entity_id"])
            for row in cur.fetchall()
        }

    for row in sid_rows:
        sid = str(row["normalized_value"]).casefold()
        for record_key in keys_by_sid.get(sid, []):
            record = next(
                item for item in entities if item["record_key"] == record_key
            )
            object_guid = (
                str(record["identity"].get("object_guid") or "")
                .strip()
                .casefold()
            )
            _require_entity_identity(
                row,
                domain_id,
                record,
                guid_entity_id=entity_ids_by_guid.get(object_guid),
            )
            resolved[record_key] = int(row["entity_id"])

    unresolved = [record for record in entities if record["record_key"] not in resolved]
    if unresolved:
        natural_keys = sorted({record["record_key"] for record in unresolved})
        cur.execute(
            """
            select entity.id, entity.natural_key, entity_type.value as entity_type
            from entities_v2 entity
            join storage_v2_entity_type entity_type
              on entity_type.id=entity.entity_type_id
            where entity.natural_key = any(%s)
            """,
            (natural_keys,),
        )
        exact_ids = {
            (str(row["entity_type"]), str(row["natural_key"])): int(row["id"])
            for row in cur.fetchall()
        }
        for record in unresolved:
            entity_id = exact_ids.get(
                (record["identity"]["kind"], record["record_key"])
            )
            if entity_id is not None:
                resolved[record["record_key"]] = entity_id

    unresolved_sids = {
        str(record["identity"].get("object_sid") or "").strip().casefold()
        for record in entities
        if record["record_key"] not in resolved
        and str(record["identity"].get("object_sid") or "").strip()
    }
    if unresolved_sids:
        cur.execute(
            """
            select lower(details.attributes_json->>'sid') as normalized_sid,
                   entity.id as entity_id, entity.domain_id,
                   entity.natural_key, entity_type.value as entity_type
            from entities_v2 entity
            join storage_v2_entity_type entity_type
              on entity_type.id=entity.entity_type_id
            join entity_details_v2 details on details.entity_id=entity.id
            where entity.domain_id=%s
              and lower(details.attributes_json->>'sid') = any(%s)
            """,
            (domain_id, sorted(unresolved_sids)),
        )
        # Legacy JSON attributes are only a fallback hint. A SID attached to
        # another entity type must not resolve (or make ambiguous) this object.
        matches_by_identity: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for row in cur.fetchall():
            matches_by_identity.setdefault(
                (str(row["normalized_sid"]).casefold(), str(row["entity_type"])), []
            ).append(dict(row))
        for sid, record_keys in keys_by_sid.items():
            for record_key in record_keys:
                if record_key not in resolved:
                    record = next(
                        item
                        for item in entities
                        if item["record_key"] == record_key
                    )
                    matches = matches_by_identity.get((sid, record["identity"]["kind"]), [])
                    if len(matches) != 1:
                        continue
                    object_guid = (
                        str(record["identity"].get("object_guid") or "")
                        .strip()
                        .casefold()
                    )
                    _require_entity_identity(
                        matches[0],
                        domain_id,
                        record,
                        guid_entity_id=entity_ids_by_guid.get(object_guid),
                    )
                    resolved[record_key] = int(matches[0]["entity_id"])
    return resolved


def _require_entity_identity(
    row: dict[str, Any] | Any,
    domain_id: int,
    record: dict[str, Any],
    *,
    guid_entity_id: int | None = None,
) -> None:
    entity_id = int(row["entity_id"])
    if (
        int(row["domain_id"]) != domain_id
        or str(row["entity_type"]) != str(record["identity"]["kind"])
        or (guid_entity_id is not None and guid_entity_id != entity_id)
    ):
        raise ValueError("stable SID alias conflicts with entity identity")


def persist_entity_identity(
    cur: Any, domain_id: int, record: dict[str, Any], *,
    entity_id: int | None, attributes: dict[str, Any],
) -> int:
    """Write the shared catalog without committing or claiming context aliases."""
    identity = record["identity"]
    # Supplemental account observations own their fields, never the directory name.
    owns_name = identity["kind"] not in {"ad_user", "ad_computer"} or record["section"] == "directory_accounts"
    display_name = record["attributes"].get("display_name") or record["record_key"]
    cur.execute(
        "insert into storage_v2_entity_type(value) values(%s) on conflict(value) do update set value=excluded.value returning id",
        (identity["kind"],),
    )
    entity_type_id = int(cur.fetchone()["id"])
    core_payload = {
        "entity_type": identity["kind"], "natural_key": record["record_key"],
        "display_name": display_name, "domain_id": domain_id,
        "observed_at_utc": record["observed_at_utc"],
    }
    core_sha256 = sha256(json.dumps(core_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).digest()
    if entity_id is None:
        cur.execute(
            """
            insert into entities_v2(
                entity_type_id,natural_key,display_name,domain_id,
                first_seen_utc,last_seen_utc,source_core_sha256
            ) values (%s,%s,%s,%s,%s,%s,%s)
            on conflict(entity_type_id,natural_key) do update set
                display_name=case when %s then excluded.display_name else entities_v2.display_name end,
                last_seen_utc=greatest(entities_v2.last_seen_utc,excluded.last_seen_utc),
                source_core_sha256=case when %s then excluded.source_core_sha256 else entities_v2.source_core_sha256 end,
                migrated_at=now()
            returning id
            """,
            (
                entity_type_id,record["record_key"],display_name,domain_id,
                record["observed_at_utc"],record["observed_at_utc"],core_sha256,owns_name,owns_name,
            ),
        )
        entity_id = int(cur.fetchone()["id"])
    elif not owns_name:
        cur.execute(
            "update entities_v2 set last_seen_utc=greatest(last_seen_utc, %s),migrated_at=now() where id=%s",
            (record["observed_at_utc"], entity_id),
        )
    else:
        cur.execute(
            """
            update entities_v2 set
                display_name=%s, last_seen_utc=greatest(last_seen_utc, %s),
                source_core_sha256=%s,migrated_at=now()
            where id=%s
            """,
            (
                display_name,record["observed_at_utc"],core_sha256,entity_id,
            ),
        )
    details_json = json.dumps(attributes, ensure_ascii=False, sort_keys=True)
    details_sha256 = sha256(details_json.encode("utf-8")).digest()
    cur.execute(
        """
        insert into entity_details_v2(entity_id,attributes_json,source_details_sha256)
        values(%s,%s::jsonb,%s)
        on conflict(entity_id) do update set
            attributes_json=excluded.attributes_json,
            source_details_sha256=%s,migrated_at=now()
        """,
        (entity_id,details_json,details_sha256,details_sha256),
    )
    return entity_id

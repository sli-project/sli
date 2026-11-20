"""Evidence-bound AD projection for the sibling Users V2 report.

This module reads only the canonical AD Context store.  It keeps direct,
primary and nested group relations distinct, rejects stale remnants of a
partial graph run, resolves managers only inside the authorized user set and
preserves per-source states instead of fabricating absent values.
"""
from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
import json
import re
from typing import Any, Mapping

from server.sli.core.database import query_rows_bounded


SOURCE_SECTIONS = (
    "directory_accounts",
    "directory_group_graph",
    "directory_exact_logon",
)
MAX_GRAPH_ROWS = 50_000
MAX_NESTED_DEPTH = 16
MAX_EFFECTIVE_GROUPS_PER_USER = 2_048

# DnsAdmins is allocated a domain-specific RID; its invariant sAMAccountName
# is used only with a domain SID. Other standard groups have fixed SID/RIDs.
STANDARD_ADMIN_DOMAIN_RIDS = frozenset({512, 518, 519, 520})
STANDARD_ADMIN_BUILTIN_RIDS = frozenset({544, 548, 549, 550, 551})


def _standard_admin_group(attrs: Mapping[str, Any], aliases: Mapping[str, str]) -> bool:
    sid = str(aliases.get("object_sid") or attrs.get("sid") or "").casefold()
    domain = re.fullmatch(r"s-1-5-21-\d+-\d+-\d+-(\d+)", sid)
    if domain:
        return int(domain[1]) in STANDARD_ADMIN_DOMAIN_RIDS or str(attrs.get("sam_account_name") or aliases.get("sam_account_name") or "").casefold() == "dnsadmins"
    builtin = re.fullmatch(r"s-1-5-32-(\d+)", sid)
    return bool(builtin and int(builtin[1]) in STANDARD_ADMIN_BUILTIN_RIDS)


def _mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {}
        return dict(parsed) if isinstance(parsed, Mapping) else {}
    return {}


def _attributes(value: Any) -> dict[str, Any]:
    raw = _mapping(value)
    nested = raw.get("attributes")
    return dict(nested) if isinstance(nested, Mapping) else raw


def _iso(value: Any) -> str | None:
    stamp = _timestamp(value)
    return stamp.isoformat().replace("+00:00", "Z") if stamp else None


def _timestamp(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        stamp = value
    else:
        try:
            stamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp.astimezone(timezone.utc)


def _version_at_least(value: Any, expected: tuple[int, int, int]) -> bool:
    try:
        parts = tuple(int(item) for item in str(value or "").split(".")[:3])
    except ValueError:
        return False
    return parts + (0,) * (3 - len(parts)) >= expected


def _section_status(value: Any) -> str:
    return {
        "complete": "observed",
        "partial": "partial",
        "failed": "failed",
        "skipped": "not_collected",
    }.get(str(value or ""), "not_collected")


def source_state(
    status: str,
    source: str,
    observed_at: Any,
    *,
    value: Any = None,
    detail: str | None = None,
    coverage: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "status": status,
        "source": source,
        "value": value,
        "observed_at": _iso(observed_at),
        "detail": detail,
        "error": None,
        "coverage": dict(coverage) if coverage else None,
    }


def _latest_sections(domain_ids: list[int]) -> dict[tuple[int, str], dict[str, Any]]:
    scope_sql = " and run.domain_id=any(?)" if domain_ids else ""
    params: list[Any] = [list(SOURCE_SECTIONS)]
    if domain_ids:
        params.append(domain_ids)
    rows = query_rows_bounded(
        f"""/* users_v2_latest_source_sections */
            select distinct on (run.domain_id,section.section_name)
                   run.domain_id,section.section_name,section.status,
                   section.record_count,section.error_code,
                   run.observed_at_utc,run.source_pack_version,run.run_id
            from ad_context_runs run
            join ad_context_sections section on section.run_id=run.run_id
            where run.status='completed' and section.section_name=any(?){scope_sql}
            order by run.domain_id,section.section_name,
                     run.observed_at_utc desc,run.completed_at desc""",
        tuple(params),
        statement_timeout_ms=5_000,
    )
    return {
        (int(row["domain_id"]), str(row["section_name"])): {
            "status": _section_status(row.get("status")),
            "raw_status": str(row.get("status") or ""),
            "observed_at": row.get("observed_at_utc"),
            "source_pack_version": str(row.get("source_pack_version") or ""),
            "record_count": int(row.get("record_count") or 0),
            "error_code": row.get("error_code"),
            "run_id": str(row.get("run_id") or ""),
        }
        for row in rows
    }


def _entity_versions(
    entity_ids: list[int],
) -> tuple[dict[int, dict[str, dict[str, Any]]], dict[int, int]]:
    if not entity_ids:
        return {}, {}
    rows = query_rows_bounded(
        """/* users_v2_current_source_versions */
           select version.entity_id,entity.domain_id,version.source_section,
                  version.attributes_json,version.last_observed_at_utc,
                  version.source_run_id
           from ad_context_entity_versions version
           join entities_v2 entity on entity.id=version.entity_id
           where version.valid_to_utc is null
             and version.source_section=any(?) and version.entity_id=any(?)
           order by version.entity_id,version.source_section""",
        (list(SOURCE_SECTIONS), entity_ids),
        statement_timeout_ms=10_000,
    )
    versions: dict[int, dict[str, dict[str, Any]]] = {}
    domain_by_entity: dict[int, int] = {}
    for row in rows:
        entity_id = int(row["entity_id"])
        domain_by_entity[entity_id] = int(row["domain_id"])
        versions.setdefault(entity_id, {})[str(row["source_section"])] = {
            "attributes": _attributes(row.get("attributes_json")),
            "observed_at": row.get("last_observed_at_utc"),
            "run_id": str(row.get("source_run_id") or ""),
        }
    return versions, domain_by_entity


def _aliases(entity_ids: list[int]) -> dict[int, dict[str, str]]:
    if not entity_ids:
        return {}
    rows = query_rows_bounded(
        """/* users_v2_stable_aliases */
           select entity_id,alias_type,alias_value
           from ad_context_entity_aliases
           where entity_id=any(?)
             and alias_type in ('object_guid','object_sid','distinguished_name','sam_account_name')
           order by entity_id,alias_type""",
        (entity_ids,),
        statement_timeout_ms=5_000,
    )
    result: dict[int, dict[str, str]] = {}
    for row in rows:
        result.setdefault(int(row["entity_id"]), {})[str(row["alias_type"])] = str(
            row["alias_value"]
        )
    return result


def _fresh_version(
    versions: Mapping[str, dict[str, Any]],
    source_meta: Mapping[tuple[int, str], dict[str, Any]],
    domain_id: int,
    section: str,
) -> dict[str, Any]:
    version = dict(versions.get(section) or {})
    meta = source_meta.get((domain_id, section))
    if not version or not meta:
        return {}
    observed = _timestamp(version.get("observed_at"))
    latest = _timestamp(meta.get("observed_at"))
    if observed is None or latest is None or observed < latest:
        return {}
    return version


def _aggregate_status(
    source_meta: Mapping[tuple[int, str], dict[str, Any]],
    domain_ids: list[int],
    section: str,
) -> str:
    states = [
        str((source_meta.get((domain_id, section)) or {}).get("status") or "not_collected")
        for domain_id in domain_ids
    ]
    if not states:
        return "not_collected"
    if all(value == "observed" for value in states):
        return "observed"
    if all(value == "failed" for value in states):
        return "failed"
    if all(value == "not_collected" for value in states):
        return "not_collected"
    return "partial"


def _aggregate_observed_at(
    source_meta: Mapping[tuple[int, str], dict[str, Any]],
    domain_ids: list[int],
    section: str,
) -> Any:
    values = [
        (source_meta.get((domain_id, section)) or {}).get("observed_at")
        for domain_id in domain_ids
    ]
    observed = [value for value in values if _timestamp(value) is not None]
    return (
        max(observed, key=lambda value: _timestamp(value) or datetime.min.replace(tzinfo=timezone.utc))
        if observed
        else None
    )


def _field_family_status(states: list[str]) -> str:
    if not states or all(value == "not_collected" for value in states):
        return "not_collected"
    if all(value == "failed" for value in states):
        return "failed"
    if all(value in {"observed", "not_applicable"} for value in states):
        return "observed"
    return "partial"


def _group_reference(
    entity_id: int,
    attrs: Mapping[str, Any],
    aliases: Mapping[str, str],
    *,
    watch_group: bool,
) -> dict[str, Any]:
    name = str(
        attrs.get("display_name")
        or attrs.get("sam_account_name")
        or aliases.get("sam_account_name")
        or entity_id
    )
    return {
        "id": f"group:{entity_id}",
        "entityId": entity_id,
        "objectGuid": aliases.get("object_guid"),
        "sid": aliases.get("object_sid"),
        "name": name,
        "samAccountName": attrs.get("sam_account_name") or aliases.get("sam_account_name"),
        "distinguishedName": attrs.get("distinguished_name") or aliases.get("distinguished_name"),
        "canonicalName": attrs.get("canonical_name"),
        "category": attrs.get("group_category"),
        "scope": attrs.get("group_scope"),
        "watchGroup": watch_group or _standard_admin_group(attrs, aliases),
    }


def _load_graph(
    *,
    user_entity_ids: list[int],
    domain_ids: list[int],
    source_meta: Mapping[tuple[int, str], dict[str, Any]],
    watch_group_ids: set[int],
) -> dict[str, Any]:
    scope_sql = " and relation.domain_id=any(?)" if domain_ids else ""
    params: list[Any] = []
    if domain_ids:
        params.append(domain_ids)
    relation_rows = query_rows_bounded(
        f"""/* users_v2_group_graph_relations */
            select relation.domain_id,relation.source_entity_id,relation.target_entity_id,
                   relation.attributes_json,relation.last_observed_at_utc,
                   source_type.value as source_kind,target_type.value as target_kind
            from ad_context_relation_versions relation
            join entities_v2 source_entity on source_entity.id=relation.source_entity_id
            join storage_v2_entity_type source_type on source_type.id=source_entity.entity_type_id
            join entities_v2 target_entity on target_entity.id=relation.target_entity_id
            join storage_v2_entity_type target_type on target_type.id=target_entity.entity_type_id
            where relation.valid_to_utc is null
              and relation.source_section='directory_group_graph'{scope_sql}
            order by relation.source_entity_id,relation.target_entity_id
            limit {MAX_GRAPH_ROWS}""",
        tuple(params),
        statement_timeout_ms=15_000,
    )
    if len(relation_rows) >= MAX_GRAPH_ROWS:
        graph_query_truncated = True
    else:
        graph_query_truncated = False

    user_id_set = set(user_entity_ids)
    user_edges: dict[int, list[tuple[int, str]]] = {}
    parent_edges: dict[int, list[int]] = {}
    group_ids: set[int] = set()
    for row in relation_rows:
        domain_id = int(row["domain_id"])
        meta = source_meta.get((domain_id, "directory_group_graph"))
        latest = _timestamp((meta or {}).get("observed_at"))
        observed = _timestamp(row.get("last_observed_at_utc"))
        if latest is None or observed is None or observed < latest:
            continue
        source_id = int(row["source_entity_id"])
        target_id = int(row["target_entity_id"])
        relation_attrs = _attributes(row.get("attributes_json"))
        membership_type = str(relation_attrs.get("membership_type") or "direct")
        if str(row.get("source_kind")) == "ad_user" and source_id in user_id_set:
            user_edges.setdefault(source_id, []).append((target_id, membership_type))
            group_ids.add(target_id)
        elif str(row.get("source_kind")) == "ad_group":
            parent_edges.setdefault(source_id, []).append(target_id)
            group_ids.update((source_id, target_id))

    group_scope_sql = " and entity.domain_id=any(?)" if domain_ids else ""
    group_params: list[Any] = []
    if domain_ids:
        group_params.append(domain_ids)
    group_rows = query_rows_bounded(
        f"""/* users_v2_group_graph_entities */
            select version.entity_id,entity.domain_id,entity.display_name,
                   version.attributes_json,version.last_observed_at_utc
            from ad_context_entity_versions version
            join entities_v2 entity on entity.id=version.entity_id
            join storage_v2_entity_type entity_type on entity_type.id=entity.entity_type_id
            where version.valid_to_utc is null
              and version.source_section='directory_group_graph'
              and entity_type.value='ad_group'{group_scope_sql}
            order by version.entity_id limit {MAX_GRAPH_ROWS}""",
        tuple(group_params),
        statement_timeout_ms=10_000,
    )
    group_attrs: dict[int, dict[str, Any]] = {}
    group_domains: dict[int, int] = {}
    for row in group_rows:
        entity_id = int(row["entity_id"])
        domain_id = int(row["domain_id"])
        meta = source_meta.get((domain_id, "directory_group_graph"))
        latest = _timestamp((meta or {}).get("observed_at"))
        observed = _timestamp(row.get("last_observed_at_utc"))
        if latest is None or observed is None or observed < latest:
            continue
        attrs = _attributes(row.get("attributes_json"))
        attrs.setdefault("display_name", row.get("display_name"))
        group_attrs[entity_id] = attrs
        group_domains[entity_id] = domain_id
        group_ids.add(entity_id)

    group_aliases = _aliases(sorted(group_ids))
    references = {
        entity_id: _group_reference(
            entity_id,
            group_attrs.get(entity_id, {}),
            group_aliases.get(entity_id, {}),
            watch_group=entity_id in watch_group_ids,
        )
        for entity_id in sorted(group_ids)
        if entity_id in group_attrs
    }
    for values in parent_edges.values():
        values.sort()
    for values in user_edges.values():
        values.sort(key=lambda item: (0 if item[1] == "primary" else 1, item[0]))

    groups = []
    for entity_id, reference in sorted(references.items()):
        domain_id = group_domains.get(entity_id)
        meta = source_meta.get((domain_id, "directory_group_graph")) if domain_id else None
        status = str((meta or {}).get("status") or "not_collected")
        attrs = group_attrs.get(entity_id, {})
        groups.append(
            {
                **reference,
                "parentGroupIds": [
                    f"group:{parent_id}"
                    for parent_id in parent_edges.get(entity_id, [])
                    if parent_id in references
                ],
                "unresolvedParentDns": list(attrs.get("unresolved_parent_dns") or []),
                "sourceState": source_state(
                    status,
                    "directory_group_graph",
                    (meta or {}).get("observed_at"),
                    detail=(
                        "Граф ограничен или содержит неразрешённые внешние ссылки."
                        if status == "partial"
                        else None
                    ),
                ),
            }
        )
    return {
        "references": references,
        "groups": groups,
        "user_edges": user_edges,
        "parent_edges": parent_edges,
        "query_truncated": graph_query_truncated,
    }


def _memberships(
    *,
    user_id: int,
    user_name: str,
    user_attrs: Mapping[str, Any],
    graph: Mapping[str, Any],
    graph_status: str,
) -> dict[str, Any]:
    references: Mapping[int, dict[str, Any]] = graph["references"]
    parent_edges: Mapping[int, list[int]] = graph["parent_edges"]
    starts = list(graph["user_edges"].get(user_id, []))
    primary_id = next((group_id for group_id, relation in starts if relation == "primary"), None)
    direct_ids = sorted({group_id for group_id, relation in starts if relation == "direct"})
    primary = (
        {**references[primary_id], "relation": "primary"}
        if primary_id in references
        else None
    )
    direct = [
        {**references[group_id], "relation": "direct"}
        for group_id in direct_ids
        if group_id in references
    ]

    unresolved = [str(value) for value in user_attrs.get("unresolved_group_dns") or []]
    unresolved_primary = user_attrs.get("unresolved_primary_group_sid")
    if unresolved_primary:
        unresolved.append(str(unresolved_primary))
    incomplete = graph_status != "observed" or bool(unresolved) or bool(graph.get("query_truncated"))

    queue: deque[tuple[int, str, tuple[int, ...]]] = deque()
    if primary_id is not None:
        queue.append((primary_id, "primary", (primary_id,)))
    for group_id in direct_ids:
        queue.append((group_id, "direct", (group_id,)))
    best_depth: dict[int, int] = {}
    effective: dict[int, dict[str, Any]] = {}
    paths: dict[int, dict[str, Any]] = {}
    while queue:
        group_id, relation, path = queue.popleft()
        if group_id not in references:
            incomplete = True
            unresolved.append(f"group:{group_id}")
            continue
        depth = len(path)
        prior_depth = best_depth.get(group_id)
        if prior_depth is not None and prior_depth <= depth:
            continue
        best_depth[group_id] = depth
        effective[group_id] = {**references[group_id], "relation": relation}
        paths[group_id] = {
            "groupId": references[group_id]["id"],
            "relation": relation,
            "nodes": [
                {"id": f"user:{user_id}", "name": user_name},
                *[
                    {"id": references[node_id]["id"], "name": references[node_id]["name"]}
                    for node_id in path
                    if node_id in references
                ],
            ],
            "source": "directory_group_graph",
        }
        if len(effective) >= MAX_EFFECTIVE_GROUPS_PER_USER:
            incomplete = True
            unresolved.append("Достигнут предел эффективных групп пользователя.")
            break
        parents = parent_edges.get(group_id, [])
        if parents and depth >= MAX_NESTED_DEPTH:
            incomplete = True
            unresolved.append(f"Достигнута глубина {MAX_NESTED_DEPTH}: {references[group_id]['name']}")
            continue
        for parent_id in parents:
            if parent_id in path:
                incomplete = True
                unresolved.append(f"Цикл групп: {references[group_id]['name']}")
                continue
            queue.append((parent_id, "nested", (*path, parent_id)))

    if not incomplete:
        membership_status = "observed"
    elif graph_status in {"not_collected", "failed"} and not starts and not unresolved:
        membership_status = graph_status
    else:
        membership_status = "partial"
    return {
        "status": membership_status,
        "primary": primary,
        "direct": direct,
        "effective": [effective[key] for key in sorted(effective)],
        "paths": [paths[key] for key in sorted(paths)],
        "unresolved": sorted(set(unresolved), key=str.casefold),
    }


def build_directory_projection(
    *,
    items: list[Mapping[str, Any]],
    coverage: Mapping[str, Any],
    requested_domain_ids: list[int] | None,
    exact_inputs: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if requested_domain_ids is not None and not any(int(value) > 0 for value in requested_domain_ids):
        return {"users": [], "groups": [], "sources": [], "collection_status": "partial",
                "observed_at": None, "domain_ids": [], "source_meta": {}}
    entity_ids = sorted({int(item["entity_id"]) for item in items})
    if exact_inputs is None:
        versions_by_id, domain_by_entity = _entity_versions(entity_ids)
        aliases_by_id = _aliases(entity_ids)
    else:
        versions_by_id = exact_inputs["versions"]
        domain_by_entity = exact_inputs["domains"]
        aliases_by_id = exact_inputs["aliases"]
    domain_ids = sorted(
        set(int(value) for value in requested_domain_ids or [] if int(value) > 0)
        or set(domain_by_entity.values())
        or {int(item.get("domain_id")) for item in items if item.get("domain_id")}
    )
    source_meta = _latest_sections(domain_ids) if exact_inputs is None else exact_inputs["sections"]

    attrs_by_id: dict[int, dict[str, Any]] = {}
    per_section_by_id: dict[int, dict[str, dict[str, Any]]] = {}
    for entity_id in entity_ids:
        domain_id = domain_by_entity.get(entity_id, int(items[0].get("domain_id") or 0) if items else 0)
        current: dict[str, dict[str, Any]] = {}
        merged: dict[str, Any] = {}
        for section in SOURCE_SECTIONS:
            version = _fresh_version(
                versions_by_id.get(entity_id, {}), source_meta, domain_id, section
            )
            if not version:
                continue
            current[section] = version
            incoming = dict(version.get("attributes") or {})
            if section != "directory_accounts":
                incoming.pop("display_name", None)
            merged.update(incoming)
        attrs_by_id[entity_id] = merged
        per_section_by_id[entity_id] = current

    watch_group_ids = {
        int(group.get("group_entity_id"))
        for item in items
        for group in item.get("direct_privileges") or []
        if group.get("group_entity_id")
    }
    graph_status = _aggregate_status(source_meta, domain_ids, "directory_group_graph")
    graph = exact_inputs["graph"] if exact_inputs is not None else _load_graph(
        user_entity_ids=entity_ids,
        domain_ids=domain_ids,
        source_meta=source_meta,
        watch_group_ids=watch_group_ids,
    )

    user_seed: dict[int, dict[str, Any]] = {}
    user_by_dn: dict[str, dict[str, Any]] = {}
    for item in items:
        entity_id = int(item["entity_id"])
        attrs = attrs_by_id.get(entity_id, {})
        aliases = aliases_by_id.get(entity_id, {})
        natural_key = str(item.get("natural_key") or "")
        sam = str(attrs.get("sam_account_name") or natural_key.rsplit("\\", 1)[-1] or "")
        display_name = str(item.get("display_name") or attrs.get("display_name") or sam or entity_id)
        seed = {
            "id": f"user:{entity_id}",
            "entityId": entity_id,
            "objectGuid": aliases.get("object_guid"),
            "sid": aliases.get("object_sid"),
            "displayName": display_name,
            "samAccountName": sam,
            "distinguishedName": attrs.get("distinguished_name") or aliases.get("distinguished_name"),
        }
        user_seed[entity_id] = seed
        if seed["distinguishedName"]:
            user_by_dn[str(seed["distinguishedName"]).casefold()] = seed

    users: list[dict[str, Any]] = []
    password_states: list[str] = []
    exact_states: list[str] = []
    manager_states: list[str] = []
    for item in items:
        entity_id = int(item["entity_id"])
        domain_id = domain_by_entity.get(entity_id, int(item.get("domain_id") or 0))
        attrs = attrs_by_id.get(entity_id, {})
        sections = per_section_by_id.get(entity_id, {})
        aliases = aliases_by_id.get(entity_id, {})
        seed = user_seed[entity_id]
        directory_meta = source_meta.get((domain_id, "directory_accounts")) or {}
        graph_meta = source_meta.get((domain_id, "directory_group_graph")) or {}
        exact_meta = source_meta.get((domain_id, "directory_exact_logon")) or {}
        directory_status = str(directory_meta.get("status") or "not_collected")
        exact_status = str(attrs.get("exact_last_logon_status") or exact_meta.get("status") or "not_collected")
        password_status = str(attrs.get("password_expiry_status") or "not_collected")
        if (
            password_status == "not_collected"
            and _version_at_least(directory_meta.get("source_pack_version"), (0, 8, 0))
            and "directory_accounts" in sections
        ):
            password_status = "missing_in_source"

        manager_dn = attrs.get("manager")
        manager = None
        if manager_dn:
            manager_seed = user_by_dn.get(str(manager_dn).casefold())
            if manager_seed:
                manager = {
                    "id": manager_seed["id"],
                    "entityId": manager_seed["entityId"],
                    "objectGuid": manager_seed["objectGuid"],
                    "name": manager_seed["displayName"],
                    "samAccountName": manager_seed["samAccountName"],
                    "distinguishedName": manager_seed["distinguishedName"],
                }
                manager_status = "observed"
            else:
                manager = {"name": None, "distinguishedName": manager_dn}
                manager_status = "partial" if directory_status == "partial" else "no_record"
        elif (
            _version_at_least(directory_meta.get("source_pack_version"), (0, 8, 0))
            and "directory_accounts" in sections
        ):
            manager_status = "not_applicable"
        else:
            manager_status = "not_collected"

        memberships = _memberships(
            user_id=entity_id,
            user_name=seed["displayName"],
            user_attrs=attrs,
            graph=graph,
            graph_status=str(graph_meta.get("status") or graph_status),
        )
        effective_policy = None
        if attrs.get("effective_password_policy_dn") or attrs.get("effective_password_policy_name"):
            effective_policy = {
                "name": attrs.get("effective_password_policy_name"),
                "distinguishedName": attrs.get("effective_password_policy_dn"),
                "source": attrs.get("effective_password_policy_source"),
            }

        source_states = {
            "directory": source_state(
                directory_status,
                "directory_accounts",
                directory_meta.get("observed_at") or item.get("observed_at_utc"),
                detail=f"source pack {directory_meta.get('source_pack_version')}" if directory_meta else None,
            ),
            "group_graph": source_state(
                memberships["status"],
                "directory_group_graph",
                graph_meta.get("observed_at"),
                detail=(
                    "Прямые, primary и вложенные связи разделены; неполные пути перечислены отдельно."
                    if memberships["status"] == "partial"
                    else None
                ),
            ),
            "exact_last_logon": source_state(
                exact_status,
                "lastLogon across discovered DCs",
                exact_meta.get("observed_at"),
                value=_iso(attrs.get("exact_last_logon_utc")),
                coverage={
                    "discovered_dc_count": attrs.get("exact_last_logon_discovered_dc_count"),
                    "successful_dc_count": attrs.get("exact_last_logon_successful_dc_count"),
                    "failed_dcs": list(attrs.get("exact_last_logon_failed_dcs") or []),
                },
            ),
            "password_expiry": source_state(
                password_status,
                "msDS-UserPasswordExpiryTimeComputed",
                directory_meta.get("observed_at"),
                value=_iso(attrs.get("password_expiry_utc")),
            ),
            "manager_resolution": source_state(
                manager_status,
                "manager DN + authorized directory user index",
                directory_meta.get("observed_at"),
                value=manager,
            ),
        }
        password_states.append(password_status)
        exact_states.append(exact_status)
        manager_states.append(manager_status)
        users.append(
            {
                "id": seed["id"],
                "entityId": entity_id,
                "objectGuid": seed["objectGuid"] or f"entity:{entity_id}",
                "domainId": domain_id,
                "sid": seed["sid"],
                "displayName": seed["displayName"],
                "name": seed["displayName"],
                "givenName": attrs.get("given_name"),
                "surname": attrs.get("surname"),
                "samAccountName": seed["samAccountName"],
                "userPrincipalName": attrs.get("user_principal_name"),
                "distinguishedName": seed["distinguishedName"],
                "canonicalName": attrs.get("canonical_name"),
                "ou": str(item.get("ou_path") or "Расположение не получено"),
                "enabled": item.get("enabled"),
                "lockedOut": item.get("locked_out"),
                "accountExpirationDate": _iso(item.get("account_expiration_utc")),
                "whenCreated": _iso(item.get("created_utc") or attrs.get("when_created_utc")),
                "whenChanged": _iso(attrs.get("when_changed_utc") or attrs.get("modified_utc")),
                "department": item.get("department") or attrs.get("department"),
                "title": item.get("title") or attrs.get("title"),
                "company": attrs.get("company"),
                "office": attrs.get("office"),
                "description": attrs.get("description"),
                "employeeID": attrs.get("employee_id"),
                "employeeNumber": attrs.get("employee_number"),
                "manager": manager,
                "mail": item.get("email") or attrs.get("mail") or attrs.get("email"),
                "proxyAddresses": list(attrs.get("proxy_addresses") or []),
                "telephoneNumber": attrs.get("telephone_number"),
                "otherTelephones": list(attrs.get("other_telephones") or []),
                "mobile": attrs.get("mobile"),
                "ipPhone": attrs.get("ip_phone"),
                "fax": attrs.get("fax"),
                "streetAddress": attrs.get("street_address"),
                "city": attrs.get("city"),
                "state": attrs.get("state"),
                "postalCode": attrs.get("postal_code"),
                "country": attrs.get("country"),
                "scriptPath": attrs.get("script_path"),
                "homeDirectory": attrs.get("home_directory"),
                "homeDrive": attrs.get("home_drive"),
                "profilePath": attrs.get("profile_path"),
                "passwordLastSet": _iso(item.get("password_last_set_utc")),
                "passwordExpiry": _iso(attrs.get("password_expiry_utc")),
                "effectivePasswordPolicy": effective_policy,
                "passwordExpired": attrs.get("password_expired"),
                "passwordNeverExpires": item.get("password_never_expires"),
                "passwordNotRequired": attrs.get("password_not_required"),
                "cannotChangePassword": attrs.get("cannot_change_password"),
                "lastLogonTimestamp": _iso(
                    attrs.get("last_logon_timestamp_utc") or item.get("last_logon_utc")
                ),
                "exactLastLogon": _iso(attrs.get("exact_last_logon_utc")),
                "lastBadPasswordAttempt": _iso(attrs.get("last_bad_password_attempt_utc")),
                "badPasswordCountAtQueryDc": (
                    attrs.get("bad_password_count_at_query_dc")
                    if attrs.get("bad_password_count_at_query_dc") is not None
                    else attrs.get("bad_password_count")
                ),
                "smartcardLogonRequired": attrs.get("smartcard_logon_required"),
                "accountNotDelegated": attrs.get("account_not_delegated"),
                "allowReversiblePasswordEncryption": attrs.get(
                    "allow_reversible_password_encryption"
                ),
                "trustedForDelegation": attrs.get("trusted_for_delegation"),
                "trustedToAuthForDelegation": attrs.get("trusted_to_auth_for_delegation"),
                "doesNotRequirePreAuth": attrs.get("does_not_require_preauth"),
                "useDesKeyOnly": attrs.get("use_des_key_only"),
                "adminCount": attrs.get("admin_count"),
                "objectClasses": list(attrs.get("object_classes") or []),
                "servicePrincipalNames": list(attrs.get("service_principal_names") or []),
                "userAccountControl": attrs.get("user_account_control"),
                "msDSSupportedEncryptionTypes": attrs.get("msds_supported_encryption_types"),
                "memberships": memberships,
                "privilegedMemberships": [
                    {"group_id": group.get("group_entity_id"), "group": group.get("group_name"),
                     "relation": "direct", "basis": "privileged_membership"}
                    for group in item.get("direct_privileges") or []
                ],
                "sourceStates": source_states,
                "collectionErrors": [],
            }
        )

    observed_values = [
        meta.get("observed_at") for meta in source_meta.values() if meta.get("observed_at")
    ]
    observed_at = max(observed_values, key=lambda value: _timestamp(value) or datetime.min.replace(tzinfo=timezone.utc)) if observed_values else coverage.get("latest_observed_at_utc")
    directory_status = _aggregate_status(source_meta, domain_ids, "directory_accounts")
    directory_observed_at = _aggregate_observed_at(
        source_meta, domain_ids, "directory_accounts"
    )
    graph_observed_at = _aggregate_observed_at(
        source_meta, domain_ids, "directory_group_graph"
    )
    exact_aggregate = _aggregate_status(source_meta, domain_ids, "directory_exact_logon")
    exact_observed_at = _aggregate_observed_at(
        source_meta, domain_ids, "directory_exact_logon"
    )
    if graph_status in {"not_collected", "failed"}:
        graph_aggregate = graph_status
    elif any(user["memberships"]["status"] == "partial" for user in users):
        graph_aggregate = "partial"
    else:
        graph_aggregate = graph_status
    password_aggregate = _field_family_status(password_states)
    manager_aggregate = _field_family_status(manager_states)
    source_versions = sorted(
        {
            str(meta.get("source_pack_version"))
            for (domain_id, section), meta in source_meta.items()
            if domain_id in domain_ids
            and section == "directory_accounts"
            and meta.get("source_pack_version")
        }
    )
    source_rows = [
        {
            "name": "directory",
            "status": directory_status,
            "observed_at": _iso(directory_observed_at),
            "detail": (
                f"AD attributes; source pack {', '.join(source_versions)}."
                if source_versions
                else "Источник directory_accounts ещё не наблюдался."
            ),
        },
        {
            "name": "group_graph",
            "status": graph_aggregate,
            "observed_at": _iso(graph_observed_at),
            "detail": f"Глубина обхода ограничена {MAX_NESTED_DEPTH}; циклы и нерешённые ссылки сохраняются.",
        },
        {
            "name": "exact_last_logon",
            "status": exact_aggregate,
            "observed_at": _iso(exact_observed_at),
            "detail": "Максимум lastLogon по всем успешно опрошенным DC; отдельный суточный цикл.",
        },
        {
            "name": "password_expiry",
            "status": password_aggregate,
            "observed_at": _iso(directory_observed_at),
            "detail": "msDS-UserPasswordExpiryTimeComputed; resultant PSO указывается только при фактическом наличии.",
        },
        {
            "name": "manager_resolution",
            "status": manager_aggregate,
            "observed_at": _iso(directory_observed_at),
        },
    ]
    complete = bool(users) and all(row["status"] == "observed" for row in source_rows)
    return {
        "users": users,
        "groups": graph["groups"],
        "sources": source_rows,
        "collection_status": "complete" if complete else "partial",
        "observed_at": observed_at,
        "domain_ids": domain_ids,
        "source_meta": source_meta,
    }

"""Bounded GPO DACL observations joined to one domain-scoped AD graph run.

This is an ACL eligibility report, not RSoP or a Windows access-token check.
"""
from __future__ import annotations

from collections import defaultdict, deque
import json
from typing import Any

from server.sli.reporting.reporting_common import get_runtime_connection, format_iso

MAX_ENTITIES = 20_000
MAX_RELATIONS = 50_000
MAX_DEPTH = 16
MAX_STEPS = 200_000
MAX_ROWS = 2000
APPLY_GUID = "edacfd8f-ffb3-11d1-b41d-00a0c968f939"
EMPTY_GUID = "00000000-0000-0000-0000-000000000000"
BROAD_SIDS = frozenset({"S-1-1-0", "S-1-5-11", "S-1-5-32-545"})


def load_directory_graph(snapshot: dict, *, domain_ids: list[int] | None, connection=None) -> dict:
    """Pin a preceding graph run by domain identity, before reading evidence.

    Evidence locators admit only records observed in that run; open versions
    alone would mix separate snapshots and could resurrect absent members.
    """
    if domain_ids == []:
        raise PermissionError("gpo_domain_scope_required")
    domain = snapshot.get("domain") or {}
    if not domain.get("sid") or not domain.get("dns_name") or not snapshot.get("observed_at"):
        return {"state": "not_collected", "entities": [], "relations": []}
    if connection is None:
        with get_runtime_connection() as conn:
            return load_directory_graph(snapshot, domain_ids=domain_ids, connection=conn)
    with connection.cursor() as cur:
        cur.execute("set transaction read only")
        cur.execute("set local statement_timeout = '10s'")
        cur.execute(
            """select run.run_id::text, run.domain_id, run.observed_at_utc,
                      section.status as section_status, section.record_count,
                      run.scope_json, run.source_pack_version
               from ad_context_runs run
               join domains domain on domain.id=run.domain_id
               join ad_context_sections section on section.run_id=run.run_id
               where run.status='completed' and run.mode in ('full','reconcile')
                 and section.section_name='directory_group_graph'
                 and domain.domain_sid=%s and lower(domain.fqdn)=lower(%s)
                 and run.observed_at_utc<=%s
                 and (%s::bigint[] is null or run.domain_id=any(%s))
               order by run.observed_at_utc desc,run.created_at desc,run.run_id desc limit 1""",
            (domain["sid"], domain["dns_name"], snapshot["observed_at"], domain_ids, domain_ids),
        )
        source = cur.fetchone()
        if not source:
            return {"state": "not_collected", "entities": [], "relations": []}
        source = dict(source)
        params = (source["run_id"], source["domain_id"])
        cur.execute(
            """select distinct version.attributes_json
               from ad_context_evidence evidence
               join ad_context_entity_versions version
                 on version.attributes_json->>'record_key'=evidence.locator_json->>'record_key'
                and version.source_section=evidence.locator_json->>'section'
                and version.valid_from_utc<=evidence.observed_at_utc
                and (version.valid_to_utc is null or version.valid_to_utc>evidence.observed_at_utc)
               join entities_v2 entity on entity.id=version.entity_id and entity.domain_id=%s
               where evidence.source_run_id=%s::uuid and evidence.evidence_type='entity_observation'
                 and evidence.locator_json->>'section' in ('directory_accounts','directory_group_graph')
               order by version.attributes_json limit %s""",
            (params[1], params[0], MAX_ENTITIES + 1),
        )
        entities = [dict(row)["attributes_json"] for row in cur.fetchall()]
        cur.execute(
            """select distinct version.attributes_json
               from ad_context_evidence evidence
               join ad_context_relation_versions version
                 on version.relation_key=evidence.locator_json->>'record_key'
                and version.domain_id=%s and version.source_section='directory_group_graph'
                and version.valid_from_utc<=evidence.observed_at_utc
                and (version.valid_to_utc is null or version.valid_to_utc>evidence.observed_at_utc)
               where evidence.source_run_id=%s::uuid and evidence.evidence_type='relation_observation'
                 and evidence.locator_json->>'section'='directory_group_graph'
               order by version.attributes_json limit %s""",
            (params[1], params[0], MAX_RELATIONS + 1),
        )
        relations = [dict(row)["attributes_json"] for row in cur.fetchall()]
    truncated = len(entities) > MAX_ENTITIES or len(relations) > MAX_RELATIONS
    graph_entity_count = sum(item.get("section") == "directory_group_graph" for item in entities)
    missing_records = int(source.get("record_count") or 0) > graph_entity_count + len(relations)
    complete = source["section_status"] == "complete" and not truncated and not missing_records
    # Old collectors did not put computer membership into the graph.
    computers_collected = (source.get("scope_json") or {}).get("computer_membership_collected") is True
    return {"state": "ok" if complete else "partial", "entities": entities[:MAX_ENTITIES],
            "relations": relations[:MAX_RELATIONS], "computers_collected": computers_collected,
            "source": {**source, "observed_at_utc": format_iso(source["observed_at_utc"])},
            "truncated": truncated, "missing_records": missing_records}


def resolve_membership(entities: list[dict], relations: list[dict], *, max_depth=MAX_DEPTH, max_steps=MAX_STEPS) -> dict:
    """Return one shortest SID path per principal/ancestor, with bounded work."""
    by_key = {item["record_key"]: item for item in entities}
    parents = defaultdict(set)
    incomplete = False
    for relation in relations:
        child, parent = relation.get("source_record_key"), relation.get("target_record_key")
        target = by_key.get(parent, {})
        category = (target.get("attributes") or {}).get("group_category")
        if child not in by_key or not target or category not in {"Security", "Distribution"}:
            incomplete = True
            continue
        if category == "Security":
            parents[child].add(parent)
    paths = {}
    steps = 0
    cycles = 0
    depth_limited = False
    for key, principal in sorted(by_key.items()):
        if (principal.get("identity") or {}).get("kind") not in {"ad_user", "ad_computer"}:
            continue
        found = {}
        queue = deque([(key, [key])])
        visited = {key}
        while queue:
            current, path = queue.popleft()
            steps += 1
            if steps > max_steps:
                return {"paths": paths, "incomplete": True, "depth_limited": depth_limited,
                        "cycles": cycles, "truncated": True}
            sid = (by_key[current].get("identity") or {}).get("object_sid")
            if sid:
                found[str(sid).upper()] = path
            else:
                incomplete = True
            attrs = by_key[current].get("attributes") or {}
            incomplete |= any(bool(attrs.get(name)) for name in (
                "unresolved_group_dns", "unresolved_parent_dns", "unresolved_primary_group_sid"))
            for parent in sorted(parents[current]):
                if parent in path:
                    cycles += 1
                    continue
                if parent in visited:
                    continue
                if len(path) - 1 >= max_depth:
                    depth_limited = True
                    continue
                visited.add(parent)
                queue.append((parent, [*path, parent]))
        paths[key] = found
    return {"paths": paths, "incomplete": incomplete or depth_limited,
            "depth_limited": depth_limited, "cycles": cycles, "truncated": False}


def ace_rights(ace: dict) -> set[str]:
    """Supported AD GPC rights; attribute-specific writes stay unsupported."""
    if int(ace.get("propagation_flags") or 0) & 2:  # InheritOnly
        return set()
    mask = int(ace.get("access_mask") or 0)
    # Generic bits can occur in raw descriptors as well as mapped AD masks.
    if mask & 0x10000000:
        mask |= 0xF01FF
    if mask & 0x80000000:
        mask |= 0x20094
    if mask & 0x40000000:
        mask |= 0x20028
    object_type = str(ace.get("object_type") or EMPTY_GUID).lower()
    all_properties = object_type == EMPTY_GUID
    rights = set()
    if mask & 0x20000:
        rights.add("read_control")
    if mask & 0x10 and all_properties:
        rights.add("read_property")
    if mask & 0x100 and object_type in {EMPTY_GUID, APPLY_GUID}:
        rights.add("apply")
    if mask & 0x20 and all_properties:
        rights.add("edit")
    if mask & 0x40000:
        rights.add("modify_permissions")
    if mask & 0x80000:
        rights.add("modify_owner")
    return rights


def delegation_risk(sid: str, kind: str, *, domain_sid: str) -> str:
    sid = sid.upper()
    if sid in BROAD_SIDS or sid in {f"{domain_sid}-513", f"{domain_sid}-515"}:
        return "broad_edit"
    if sid in {"S-1-5-18", "S-1-5-32-544", *(f"{domain_sid}-{rid}" for rid in (500, 512, 518, 519))}:
        return "admin_edit"
    return "non_admin_group_edit" if kind == "ad_group" else "direct_principal_edit" if kind in {"ad_user", "ad_computer"} else "unknown_trustee_edit"


def analyze_access(snapshot: dict, graph: dict, *, mode: str, query="", max_rows=MAX_ROWS, max_depth=MAX_DEPTH) -> dict[str, Any]:
    entities = graph.get("entities") or []
    by_key = {item["record_key"]: item for item in entities}
    by_sid = {str((item.get("identity") or {}).get("object_sid")).upper(): item for item in entities}
    resolved = resolve_membership(entities, graph.get("relations") or [], max_depth=max_depth)
    needle = query.strip().casefold()
    matching_principals = set()
    if needle:
        for key, token in resolved["paths"].items():
            nodes = {node for path in token.values() for node in path}
            if needle in json.dumps([key, list(token), [(by_key[node].get("attributes") or {}).get("display_name") for node in nodes]], ensure_ascii=False).casefold():
                matching_principals.add(key)

    def append(row):
        if not needle or needle in json.dumps(row, ensure_ascii=False).casefold():
            rows.append(row)

    graph_partial = graph.get("state") != "ok" or resolved["incomplete"] or not graph.get("computers_collected")
    partial = graph_partial
    rows = []
    truncated = False
    evaluations = 0
    domain_sid = str((snapshot.get("domain") or {}).get("sid") or "").upper()
    acl_by_gpo = defaultdict(list)
    for ace in snapshot.get("acl") or []:
        acl_by_gpo[ace["gpo_id"]].append(ace)
    for gpo in snapshot.get("gpos") or []:
        acl_state = (gpo.get("source_states") or {}).get("acl", {}).get("status", "not_collected")
        aces = sorted(acl_by_gpo[gpo["id"]], key=lambda ace: ace["ace_index"])
        unsupported = any(int(ace.get("access_mask") or 0) & 0x30 and ace.get("object_type") != EMPTY_GUID for ace in aces)
        partial |= unsupported
        base = {"gpo_id": gpo["id"], "gpo_guid": gpo.get("guid"), "gpo_name": gpo.get("display_name"), "wmi_filter_id": gpo.get("wmi_filter_id"),
                "graph_run_id": (graph.get("source") or {}).get("run_id"),
                "graph_observed_at": (graph.get("source") or {}).get("observed_at_utc")}
        if acl_state != "observed" or graph.get("state") == "not_collected":
            partial = True
            append({**base, "id": f"{gpo['id']}:unknown", "outcome": "not_collected" if acl_state == "not_collected" or graph.get("state") == "not_collected" else "unknown"})
            if len(rows) >= max_rows:
                truncated = True
                break
            continue
        emitted = set()
        trustee_names = [(by_sid.get(ace["trustee_sid"].upper(), {}).get("attributes") or {}).get("display_name") for ace in aces]
        gpo_matches = not needle or needle in json.dumps([base, aces, trustee_names], ensure_ascii=False).casefold()
        for key, token in resolved["paths"].items():
            if not gpo_matches and key not in matching_principals:
                continue
            principal = by_key[key]
            token = {**token, "S-1-1-0": [key], "S-1-5-11": [key]}
            decisions = {}
            for ace in aces:
                evaluations += 1
                if evaluations > MAX_STEPS:
                    truncated = True
                    break
                sid = ace["trustee_sid"].upper()
                if sid not in token:
                    continue
                emitted.add(ace["id"])
                # DACL order matters: explicit allows can precede inherited denies.
                for right in ace_rights(ace):
                    decisions.setdefault(right, (ace["access_control_type"] == "Allow", ace, token[sid]))
            if truncated:
                break
            rights = ("apply",) if mode == "filtering" else ("edit", "modify_permissions", "modify_owner")
            for right in rights:
                if right not in decisions:
                    continue
                allowed, ace, path = decisions[right]
                read_ok = all(decisions.get(read, (False,))[0] for read in ("read_control", "read_property"))
                outcome = "allowed" if allowed and (mode != "filtering" or read_ok) else "denied"
                if graph_partial or unsupported:
                    outcome = "unknown"
                trustee = by_sid.get(ace["trustee_sid"].upper(), {})
                names = [(by_key[node].get("attributes") or {}).get("display_name") or (by_key[node].get("identity") or {}).get("object_sid") or node for node in path]
                if ace["trustee_sid"].upper() in {"S-1-1-0", "S-1-5-11"}:
                    names.append(ace["trustee_sid"])
                names.append(f"{gpo.get('display_name')} [ACE {ace['ace_index']}]")
                append({**base, "id": f"{gpo['id']}:{key}:{right}", "principal": (principal.get("attributes") or {}).get("display_name") or key,
                             "principal_sid": principal["identity"].get("object_sid"), "principal_type": principal["identity"]["kind"],
                             "trustee_sid": ace["trustee_sid"], "right": right, "outcome": outcome,
                             "path": " → ".join(names), "path_keys": path, "ace_id": ace["id"], "ace_index": ace["ace_index"],
                             "read_ace_ids": sorted({decisions[read][1]["id"] for read in ("read_control", "read_property") if read in decisions}) if mode == "filtering" else [],
                             "inherited": ace.get("inherited"), "risk": delegation_risk(ace["trustee_sid"], (trustee.get("identity") or {}).get("kind", ""), domain_sid=domain_sid) if mode != "filtering" and allowed else "none"})
                if len(rows) >= max_rows:
                    truncated = True
                    break
            if truncated:
                break
        if truncated:
            break
        if not gpo_matches:
            continue
        # Retain grant evidence for empty/unresolved groups, including foreign SIDs.
        for ace in aces:
            rights = ace_rights(ace) & ({"apply"} if mode == "filtering" else {"edit", "modify_permissions", "modify_owner"})
            if not rights or ace["id"] in emitted:
                continue
            trustee = by_sid.get(ace["trustee_sid"].upper(), {})
            partial = True
            for right in sorted(rights):
                append({**base, "id": f"{ace['id']}:{right}", "trustee_sid": ace["trustee_sid"], "right": right,
                             "outcome": "unknown", "ace_id": ace["id"], "ace_index": ace["ace_index"], "inherited": ace.get("inherited"),
                             "path": f"{(trustee.get('attributes') or {}).get('display_name') or ace['trustee_sid']} → {gpo.get('display_name')} [ACE {ace['ace_index']}]",
                             "risk": delegation_risk(ace["trustee_sid"], (trustee.get("identity") or {}).get("kind", ""), domain_sid=domain_sid) if mode != "filtering" and ace["access_control_type"] == "Allow" else "none"})
                if len(rows) >= max_rows:
                    truncated = True
                    break
            if truncated:
                break
        if truncated:
            break
    return {"items": rows[:max_rows], "state": "partial" if partial or truncated else "ok" if rows else "empty",
            "coverage": {"graph": graph.get("source"), "graph_state": graph.get("state"), "computers_collected": graph.get("computers_collected", False),
                         "cycles": resolved["cycles"], "depth_limited": resolved["depth_limited"], "max_depth": max_depth,
                         "truncated": truncated or resolved["truncated"] or graph.get("truncated", False),
                         "missing_records": graph.get("missing_records", False)}}


def _dn_suffixes(dn: str) -> list[str]:
    suffixes = [dn]
    escaped = False
    quoted = False
    for index, char in enumerate(dn):
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif char == "," and not quoted:
            suffixes.append(dn[index + 1:])
    return suffixes


def linked_scopes(snapshot: dict, *, query="", max_rows=MAX_ROWS) -> dict:
    """Project domain/OU inheritance, preserving block/enforce observations.

    Sites have direct links only: computer-to-site membership is not collected.
    Link precedence and policy settings conflicts are deliberately not RSoP.
    """
    scopes = {scope["id"]: scope for scope in snapshot.get("scopes") or []}
    by_dn = {str(scope.get("distinguished_name") or "").casefold(): scope for scope in scopes.values()}
    gpos = {gpo["id"]: gpo for gpo in snapshot.get("gpos") or []}
    filters = {item["id"]: item for item in snapshot.get("wmi_filters") or []}
    rows = []
    links_observed = (snapshot.get("source_states") or {}).get("links", {}).get("status") == "observed"
    partial = not links_observed
    truncated = False
    evaluations = 0
    needle = query.strip().casefold()
    for link in snapshot.get("links") or []:
        root = scopes.get(link.get("scope_id"))
        gpo = gpos.get(link.get("gpo_id"))
        if root is None or gpo is None:
            partial = True
            continue
        root_dn = str(root.get("distinguished_name") or "").casefold()
        for scope in scopes.values():
            evaluations += 1
            if evaluations > MAX_STEPS:
                truncated = True
                break
            dn = str(scope.get("distinguished_name") or "").casefold()
            direct = scope["id"] == root["id"]
            descendant = root.get("scope_type") in {"domain", "ou"} and scope.get("scope_type") == "ou" and root_dn and dn.endswith("," + root_dn)
            if not direct and not descendant:
                continue
            suffixes = _dn_suffixes(dn)
            relevant = suffixes[:suffixes.index(root_dn) + 1] if root_dn in suffixes else [root_dn]
            chain = [by_dn[value] for value in reversed(relevant) if value in by_dn]
            blocked = not direct and any(candidate.get("gpo_inheritance_blocked") is True for candidate in chain if candidate["id"] != root["id"])
            known = len(chain) == len(relevant) and link.get("enabled") is not None and link.get("enforced") is not None and all(isinstance(candidate.get("gpo_inheritance_blocked"), bool) for candidate in chain)
            outcome = "unknown" if not known or not links_observed else "disabled" if not link["enabled"] else "blocked" if blocked and not link["enforced"] else "linked"
            wmi = filters.get(gpo.get("wmi_filter_id"), {})
            wmi_state = "not_applicable" if not gpo.get("wmi_filter_id") else (wmi.get("source_state") or {}).get("status", "not_collected")
            partial |= not known or wmi_state not in {"observed", "not_applicable"}
            row = {"id": f"{link['id']}:{scope['id']}", "gpo_id": gpo["id"], "gpo_guid": gpo.get("guid"), "gpo_name": gpo.get("display_name"),
                         "scope_name": scope.get("name"), "scope_type": scope.get("scope_type"), "scope_dn": scope.get("distinguished_name"),
                         "link_id": link["id"], "order": link.get("order"), "enabled": link.get("enabled"), "enforced": link.get("enforced"),
                         "inherited": not direct, "inheritance_blocked": scope.get("gpo_inheritance_blocked"), "outcome": outcome,
                         "path": " → ".join(candidate.get("name") or candidate["id"] for candidate in chain) or root.get("name"),
                         "gpo_status": gpo.get("gpo_status"), "wmi_filter_id": gpo.get("wmi_filter_id"), "wmi_name": wmi.get("name"),
                         "wmi_queries": [f"{query.get('namespace') or ''}: {query.get('query') or ''}" for query in wmi.get("queries") or []],
                         "wmi_state": wmi_state}
            if not needle or needle in json.dumps(row, ensure_ascii=False).casefold():
                rows.append(row)
            if len(rows) >= max_rows:
                truncated = True
                break
        if truncated:
            break
    return {"items": rows, "state": "partial" if partial or truncated else "ok" if rows else "empty",
            "coverage": {"links_state": (snapshot.get("source_states") or {}).get("links"), "truncated": truncated}}

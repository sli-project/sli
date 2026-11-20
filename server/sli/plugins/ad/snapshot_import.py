"""Exact agent cycles into the existing AD store, snapshots and projections."""
from __future__ import annotations

import hashlib
from copy import deepcopy
from datetime import datetime, timezone

from server.sli.plugins.ad.snapshots.coordinator import (
    AD_FAMILY_SPECS,
    _computer_rows,
    _source_descriptor,
    _qualify_base_bundle,
    run_one_shot,
    scheduled_slot_from_utc,
    ScheduledSlot,
)
from server.sli.plugins.ad.snapshot_persistence import persist_computers_v6_source_snapshot
from server.sli.plugins.ad.snapshot_persistence import _canonical, persist_users_v2_snapshot
from server.sli.plugins.ad.context.contracts import validate_bundle
from server.sli.plugins.ad.context.repository import AdContextOutOfOrderError, import_bundle, publish_snapshot_manifest
from server.sli.plugins.ad.snapshots.manifest import V2_CONTRACT_VERSION, V3_CONTRACT_VERSION, agent_schedule_header
from server.sli.agents.import_authorization import PacketPending
from server.sli.entities import users_v2_directory_projection as directory
from server.sli.reports.users_reporting import normalize_ou_path
from server.sli.reports.users_v2_reporting import snapshot_from_directory_projection
from server.sli.plugins.ad.snapshots.projection import run_exact_manifest_projection_cycle
from server.sli.sources.computers_v6_source import validate_computers_v6_snapshot
from sli_agent.envelope import canonical
from sli_agent.snapshot_stream import MODULE_FAMILIES, due_slot


def prepare_ad_cycle(cycle, families):
    """Validate the entire cycle before its first mutation, including scope."""
    config = cycle["policy"]
    if set(families) != set(MODULE_FAMILIES["sli.ad-snapshot"]):
        raise PacketPending("agent_ad_required_families_missing")
    bundles = {}
    stamp = None
    run_ids = set()
    count = size = 0
    for family in MODULE_FAMILIES["sli.ad-snapshot"]:
        if family == "computers_v6":
            continue
        bundle = validate_bundle(families[family])
        if (bundle["domain"] != {"sid": config["domain_sid"], "dns_name": config["domain_dns"]}
                or tuple(s["name"] for s in bundle["sections"]) != AD_FAMILY_SPECS[family][1]
                or bundle["run_id"] in run_ids):
            raise ValueError("agent_ad_family_invalid")
        if stamp is not None and stamp != bundle["observed_at_utc"]:
            raise ValueError("agent_ad_observation_mismatch")
        stamp = bundle["observed_at_utc"]
        run_ids.add(bundle["run_id"])
        bundles[family] = bundle
        count += len(bundle["records"])
        size += len(canonical(families[family]))
    base = bundles["ad_context_base"]
    sections = {s["name"]: s for s in base["sections"]}
    if base["mode"] not in ({"targeted"} if config["search_bases"] else {"full", "reconcile"}):
        raise PacketPending("agent_ad_base_incomplete")
    exact_required = config["expensive_flags"].get("exact_last_logon", False)
    if sections["directory_exact_logon"]["status"] != ("complete" if exact_required else "skipped"):
        raise PacketPending("agent_ad_exact_logon_incomplete")
    qualification_input = deepcopy(base)
    if not exact_required:
        qualification_input["sections"][2].update(status="complete", error_code=None)
    # Excluding source secrets is a privacy receipt, not evidence that the
    # account population is truncated. All legacy blocking/unknown codes stay.
    qualification_input["records"] = [r for r in qualification_input["records"]
        if r.get("code") != "sensitive_fields_masked"]
    if not _qualify_base_bundle(qualification_input)["usable"]:
        raise PacketPending("agent_ad_base_incomplete")
    if config["search_bases"] and config["search_bases"] != [base["scope"]["search_base"]]:
        raise PacketPending("agent_ad_scope_incomplete")
    if any(b["scope"]["search_base"] != base["scope"]["search_base"] for b in bundles.values()):
        raise ValueError("agent_ad_scope_mismatch")
    for family, bundle in bundles.items():
        for scope_key, allowed_family in (("privileged_group_sids", "ad_privileged_membership"),
                                          ("vpn_group_sids", "ad_vpn_membership")):
            if family != allowed_family and bundle["scope"][scope_key]:
                raise ValueError("agent_ad_group_scope_mismatch")
    expected_search_base = config["search_bases"][0] if config["search_bases"] else ",".join("DC=" + label for label in config["domain_dns"].split("."))
    if base["scope"]["search_base"].casefold() != expected_search_base.casefold():
        raise ValueError("agent_ad_scope_mismatch")
    selected_groups = {"privileged_membership": [], "vpn_membership": []}
    for reference in config["groups"]:
        area, _, value = reference.partition(":")
        selected_groups["vpn_membership" if area == "vpn" else "privileged_membership"].append(
            value if area in {"vpn", "privileged"} else reference)
    for family, section, scope_key in (
        ("ad_privileged_membership", "privileged_membership", "privileged_group_sids"),
        ("ad_vpn_membership", "vpn_membership", "vpn_group_sids"),
    ):
        bundle = bundles[family]
        refs = {ref.casefold() for ref in selected_groups[section]}
        groups = [r for r in bundle["records"] if r["record_type"] == "entity" and r["identity"]["kind"] == "ad_group"]
        resolved = {str(r["identity"].get("object_sid") or "").casefold() for r in groups
                    if str(r["identity"].get("object_sid") or "").casefold() in refs
                    or str(r["attributes"].get("distinguished_name") or "").casefold() in refs}
        if resolved != {sid.casefold() for sid in bundle["scope"][scope_key]}:
            raise ValueError("agent_ad_group_scope_mismatch")
        if refs and (bundle["sections"][0]["status"] != "complete" or any(
                not any(ref in {str(r["identity"].get("object_sid") or "").casefold(),
                               str(r["attributes"].get("distinguished_name") or "").casefold()} for r in groups) for ref in refs)):
            raise PacketPending("agent_ad_membership_incomplete")
        if not refs and (bundle["sections"][0]["status"] != "skipped" or bundle["records"]):
            raise ValueError("agent_ad_group_scope_mismatch")
    computer = validate_computers_v6_snapshot(families["computers_v6"])
    if (computer["metadata"]["domain"] != config["domain_dns"]
            or computer["metadata"]["completed_at"] != stamp
            or computer["metadata"]["search_base"] != base["scope"]["search_base"]
            or computer["metadata"]["collection_status"] == "failed"):
        raise ValueError("agent_ad_computers_invalid")
    expected = {r["identity"]["object_guid"] for r in base["records"]
                if r["record_type"] == "entity" and r["section"] == "directory_accounts" and r["identity"]["kind"] == "ad_computer"}
    if expected != {r["objectGuid"] for r in computer["objects"]}:
        raise ValueError("agent_ad_computer_population_mismatch")
    count += len(computer["objects"])
    if count > config["max_objects"] or size > config["max_bytes"]:
        raise ValueError("agent_ad_size_limit")
    return bundles, computer


def exact_directory_inputs(bundles, *, domain_id, entity_ids):
    """No latest reads: all attributes, edges and sectional states are frozen."""
    base = bundles["ad_context_base"]
    versions, aliases, domains, sections = {}, {}, {}, {}
    records = [r for b in bundles.values() for r in b["records"]]
    graph_records = []
    items = []
    for section in base["sections"]:
        sections[(domain_id, section["name"])] = {
            "status": directory._section_status(section["status"]), "raw_status": section["status"],
            "observed_at": base["observed_at_utc"], "source_pack_version": base["source_pack_version"],
            "record_count": section["record_count"], "error_code": section["error_code"], "run_id": base["run_id"],
        }
    for record in records:
        if record["record_type"] != "entity":
            continue
        entity_id = entity_ids[record["identity"]["object_guid"]]
        attrs = record["attributes"]
        if record["section"] in directory.SOURCE_SECTIONS:
            versions.setdefault(entity_id, {})[record["section"]] = {
                "attributes": attrs, "observed_at": record["observed_at_utc"], "run_id": base["run_id"],
            }
        aliases.setdefault(entity_id, {}).update({key: value for key, value in {
            "object_guid": record["identity"]["object_guid"], "object_sid": record["identity"].get("object_sid"),
            "distinguished_name": attrs.get("distinguished_name")}.items() if value is not None})
        domains[entity_id] = domain_id
        if record["section"] == "directory_accounts" and record["identity"]["kind"] == "ad_user":
            items.append({**attrs, "entity_id": entity_id, "domain_id": domain_id,
                          "natural_key": record["record_key"], "display_name": attrs.get("display_name"),
                          "ou_path": normalize_ou_path(attrs.get("distinguished_name")),
                          "created_utc": attrs.get("when_created_utc"), "email": attrs.get("mail"),
                          "direct_privileges": []})
        if record["section"] == "directory_group_graph" and record["identity"]["kind"] == "ad_group":
            graph_records.append((entity_id, record))
    by_key = {r["record_key"]: entity_ids[r["identity"]["object_guid"]] for r in base["records"] if r["record_type"] == "entity"}
    kinds = {entity_ids[r["identity"]["object_guid"]]: r["identity"]["kind"] for r in base["records"] if r["record_type"] == "entity"}
    privileged = bundles["ad_privileged_membership"]
    watch = set()
    by_user = {item["entity_id"]: item for item in items}
    for relation in privileged["records"]:
        if relation["record_type"] != "relation":
            continue
        source, target = by_key.get(relation["source_record_key"]), by_key.get(relation["target_record_key"])
        if target:
            watch.add(target)
        if source in by_user and target:
            group = next(r for eid, r in graph_records if eid == target)
            by_user[source]["direct_privileges"].append({"group_entity_id": target, "group_name": group["attributes"].get("display_name")})
    references = {eid: directory._group_reference(eid, r["attributes"], aliases[eid], watch_group=eid in watch)
                  for eid, r in graph_records}
    user_edges, parent_edges = {}, {}
    for relation in base["records"]:
        if relation["record_type"] != "relation":
            continue
        source, target = by_key[relation["source_record_key"]], by_key[relation["target_record_key"]]
        if kinds[source] == "ad_user":
            user_edges.setdefault(source, []).append((target, relation["attributes"].get("membership_type", "direct")))
        elif kinds[source] == "ad_group":
            parent_edges.setdefault(source, []).append(target)
    for edges in user_edges.values():
        edges.sort(key=lambda item: (0 if item[1] == "primary" else 1, item[0]))
    for edges in parent_edges.values():
        edges.sort()
    meta = sections[(domain_id, "directory_group_graph")]
    groups = [{**references[eid], "parentGroupIds": [f"group:{parent}" for parent in parent_edges.get(eid, []) if parent in references],
               "unresolvedParentDns": list(r["attributes"].get("unresolved_parent_dns") or []),
               "sourceState": directory.source_state(meta["status"], "directory_group_graph", meta["observed_at"],
                   detail="Граф ограничен или содержит неразрешённые внешние ссылки." if meta["status"] == "partial" else None)}
              for eid, r in sorted(graph_records)]
    graph = {"references": references, "groups": groups, "user_edges": user_edges, "parent_edges": parent_edges, "query_truncated": False}
    return items, {"versions": versions, "domains": domains, "aliases": aliases, "sections": sections, "graph": graph}


def build_exact_users(conn, bundles, domain):
    guids = sorted({r["identity"]["object_guid"] for b in bundles.values() for r in b["records"] if r["record_type"] == "entity"})
    with conn.cursor() as cur:
        cur.execute("""select alias_value,entity_id from ad_context_entity_aliases
            where domain_id=%s and alias_type='object_guid' and normalized_value=any(%s)""", (domain["id"], guids))
        entity_ids = {str(r["alias_value"]).lower(): int(r["entity_id"]) for r in cur.fetchall()}
    if set(entity_ids) != set(guids):
        raise ValueError("agent_ad_import_identity_missing")
    items, inputs = exact_directory_inputs(bundles, domain_id=int(domain["id"]), entity_ids=entity_ids)
    base = bundles["ad_context_base"]
    coverage = {"domains": [{"domain_id": int(domain["id"]), "domain_name": domain["dns"]}],
                "latest_observed_at_utc": base["observed_at_utc"]}
    projection = directory.build_directory_projection(items=items, coverage=coverage,
        requested_domain_ids=[int(domain["id"])], exact_inputs=inputs)
    return snapshot_from_directory_projection(projection, coverage=coverage, active={"state": "ready", "limitations": []})


def import_ad_cycle(conn, cycle, families):
    """Caller holds lifecycle locks and owns the single publication transaction."""
    bundles, computer = prepare_ad_cycle(cycle, families)
    try:
        stamp = datetime.fromisoformat(cycle["slot_start_utc"])
        if stamp.tzinfo is None or datetime.fromisoformat(due_slot(cycle["policy"], stamp)) != stamp:
            raise ValueError("agent_slot_not_scheduled")
        default_schedule = cycle["policy"]["schedule"] == {"timezone": "Asia/Novosibirsk", "hours": [6, 18]}
        contract_version = V2_CONTRACT_VERSION if default_schedule else V3_CONTRACT_VERSION
        slot = (scheduled_slot_from_utc(stamp) if default_schedule else
                ScheduledSlot(**agent_schedule_header(stamp),
                              slot_start_utc=stamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")))
    except ValueError:
        raise PacketPending("agent_ad_schedule_unsupported") from None
    if slot.slot_start_utc != cycle["slot_start_utc"].replace("+00:00", "Z"):
        raise PacketPending("agent_ad_schedule_unsupported")
    with conn.cursor() as cur:
        cur.execute("select pg_advisory_xact_lock(hashtext('sli_agent_ad_snapshot'),hashtext(%s))", (cycle["domain_sid"],))
        cur.execute("select id,domain_sid as sid,fqdn as dns from domains where domain_sid=%s and lower(fqdn)=%s for update",
                    (cycle["domain_sid"], cycle["policy"]["domain_dns"]))
        domain = cur.fetchone()
    if not domain:
        raise PacketPending("agent_ad_domain_not_bound")
    # Import all families before Users assembly, using one connection. The
    # source hash and run IDs below never come from a global latest selector.
    for bundle in bundles.values():
        try:
            import_bundle(conn, bundle)
        except AdContextOutOfOrderError:
            raise PacketPending("agent_ad_snapshot_superseded") from None
    descriptors = {family: _source_descriptor(conn, family, bundle["run_id"]) for family, bundle in bundles.items()}
    stamp = datetime.fromisoformat(bundles["ad_context_base"]["observed_at_utc"].replace("Z", "+00:00"))

    def persist_users(_base):
        snapshot = build_exact_users(conn, bundles, domain)
        persisted = persist_users_v2_snapshot(conn, snapshot=snapshot, domain_id=int(domain["id"]), captured_at=stamp)
        source_id = persisted.get("snapshot_id")
        if source_id is None:
            _, sha = _canonical(snapshot)
            with conn.cursor() as cur:
                cur.execute("""select snapshot_id from users_report_v2_snapshots where domain_id=%s
                    and contract_id='sli.users-report.v2' and source_observed_at_utc=%s and payload_sha256=%s""",
                    (domain["id"], stamp, sha))
                rows = cur.fetchall()
            if len(rows) != 1:
                raise ValueError("agent_ad_users_readback_invalid")
            source_id = rows[0]["snapshot_id"]
        return _source_descriptor(conn, "users_v2", str(source_id))

    def persist_computers(_rows):
        persisted = persist_computers_v6_source_snapshot(conn, snapshot=computer, captured_at=stamp,
            capture_options={"server": computer["metadata"]["query_dc"], "search_base": bundles["ad_context_base"]["scope"]["search_base"],
                "skip_dns": not cycle["policy"]["expensive_flags"].get("dns", False),
                "collect_ad_site": cycle["policy"]["expensive_flags"].get("ad_site", False),
                "collect_exact_last_logon": cycle["policy"]["expensive_flags"].get("exact_last_logon", False)},
            collector_exit_code=0, collector_sha256=hashlib.sha256(b"sli-agent/ad-snapshot/1").digest())
        return _source_descriptor(conn, "computers_v6", persisted["snapshot_uuid"])

    def acquire(family):
        bundle = bundles[family]
        if family != "ad_context_base":
            return {"bundle": bundle}
        return {"bundle": bundle, "base_complete": True, "acquisition": {
            "profile": "ad_snapshot_base_v1", "user_full_queries": 1, "computer_full_queries": 1},
            "computer_rows": _computer_rows(bundle)}

    def publish(manifest):
        result = publish_snapshot_manifest(conn, manifest)
        from server.sli.plugins.ad.context.repository import load_projection_manifest
        readback = load_projection_manifest(conn, manifest["manifest_id"])
        if readback["manifest_sha256"] != manifest["manifest_sha256"]:
            raise ValueError("agent_ad_manifest_readback_invalid")
        return {**result, "readback_verified": True}

    result = run_one_shot(slot_start_utc=slot.slot_start_utc, domain=domain, execute=True,
        acquire_ad_family=acquire, import_ad_family=lambda bundle, family: descriptors[family],
        persist_users=persist_users, persist_computers=persist_computers, publish=publish,
        import_gpo=lambda _: None, assembled_at_utc=stamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        contract_version=contract_version, schedule_timezone=slot.schedule_timezone,
        scheduled_local_at=slot.scheduled_local_at, gpo_enabled=False)
    projection = run_exact_manifest_projection_cycle(conn, manifest_id=result["manifest_id"],
        worker_id="agent-ad-snapshot", projection_keys=("ad.state", "ad.users.v2", "ad.computers.v6"))
    if projection["status"] != "completed":
        raise PacketPending("agent_ad_projection_pending")
    return result

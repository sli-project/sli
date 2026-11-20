"""GPO plugin owns agent snapshot and governance publication into legacy storage."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime

from server.ad_context.contracts import validate_bundle
from server.ad_context.repository import AdContextOutOfOrderError, import_bundle
from server.sli.agents.import_authorization import PacketPending
from server.sli.sources.gpo_v2_source import canonical_snapshot, redact_gpo_snapshot, validate_snapshot
from sli_agent.envelope import canonical
from sli_agent.snapshot_stream import MODULE_FAMILIES


def prepare_gpo_cycle(cycle, families):
    """Validate both frozen representations before any database mutation."""
    config = cycle["policy"]
    if set(families) != set(MODULE_FAMILIES["sli.gpo-snapshot"]):
        raise PacketPending("agent_gpo_required_families_missing")
    snapshot = validate_snapshot(families["gpo_v2"])
    raw_bundle = deepcopy(families["ad_gpo_governance"])
    if "gpo_v2_snapshot" in raw_bundle:
        raise ValueError("agent_gpo_duplicate_snapshot")
    raw_bundle["gpo_v2_snapshot"] = snapshot
    bundle = validate_bundle(raw_bundle)
    expected_base = ",".join("DC=" + label for label in config["domain_dns"].split("."))
    if (cycle["domain_sid"] != config["domain_sid"]
            or bundle["domain"] != {"sid": config["domain_sid"], "dns_name": config["domain_dns"]}
            or snapshot["domain"].get("dns_name", "").casefold() != config["domain_dns"]
            or snapshot["domain"].get("sid") != config["domain_sid"]
            or snapshot["domain"].get("distinguished_name", "").casefold() != expected_base.casefold()
            or bundle["scope"]["search_base"].casefold() != expected_base.casefold()
            or config["search_bases"] not in ([], [expected_base])
            or bundle["scope"].get("collection_profile") != "gpo_governance_v4"
            or bundle["scope"]["privileged_group_sids"] or bundle["scope"]["vpn_group_sids"]
            or [s["name"] for s in bundle["sections"]] != ["gpo_governance"]):
        raise ValueError("agent_gpo_domain_scope_invalid")
    if (datetime.fromisoformat(snapshot["observed_at"].replace("Z", "+00:00")) !=
            datetime.fromisoformat(bundle["observed_at_utc"].replace("Z", "+00:00")) or config["dc"] and
            snapshot["domain"].get("query_dc", "").casefold() != config["dc"][0].casefold()):
        raise ValueError("agent_gpo_observation_invalid")
    if (max(len(snapshot["gpos"]), len(bundle["records"])) > config["max_objects"]
            or sum(len(canonical(data)) for data in families.values()) > config["max_bytes"]):
        raise ValueError("agent_gpo_size_limit")
    if (snapshot["source_states"]["gpo_list"]["status"] != "observed"
            or snapshot["source_states"]["gpc_directory"]["status"] != "observed"
            or any(error.get("code") == "agent_gpo_size_limit" for error in snapshot["collection_errors"])):
        raise PacketPending("agent_gpo_population_incomplete")
    gpos = {(str(gpo.get("gpc", {}).get("object_guid") or gpo["guid"]).lower(), gpo["display_name"])
            for gpo in snapshot["gpos"]}
    records = set()
    for record in bundle["records"]:
        if (record["record_type"] != "entity" or record["identity"]["kind"] != "gpo"
                or record["attributes"].get("gpo_security_filtering_effective_evaluated") is not False):
            raise ValueError("agent_gpo_governance_invalid")
        records.add((record["identity"]["object_guid"], record["attributes"]["display_name"]))
    if gpos != records or len(gpos) != len(bundle["records"]):
        raise ValueError("agent_gpo_population_mismatch")
    if snapshot["collection_status"] != "complete" or bundle["sections"][0]["status"] != "complete":
        bundle["mode"] = "targeted"
        bundle["sections"][0].update(status="partial", error_code="agent_gpo_source_partial")
        bundle.pop("bundle_sha256")
        bundle = validate_bundle(bundle)
    elif bundle["mode"] not in {"full", "reconcile"}:
        raise PacketPending("agent_gpo_population_incomplete")
    return bundle


def import_gpo_cycle(conn, cycle, families):
    """Caller holds agent/plugin lifecycle locks and the publication transaction."""
    bundle = prepare_gpo_cycle(cycle, families)
    with conn.cursor() as cur:
        # Share the domain lock with AD imports, without adding to their manifest.
        cur.execute("select pg_advisory_xact_lock(hashtext('sli_agent_ad_snapshot'),hashtext(%s))", (cycle["domain_sid"],))
        cur.execute("select id from domains where domain_sid=%s and lower(fqdn)=%s for update",
                    (cycle["domain_sid"], cycle["policy"]["domain_dns"]))
        domain = cur.fetchone()
    if not domain:
        raise PacketPending("agent_gpo_domain_not_bound")
    try:
        import_bundle(conn, bundle)
    except AdContextOutOfOrderError:
        raise PacketPending("agent_gpo_snapshot_superseded") from None
    # The legacy importer stores both governance and the v2 source together.
    with conn.cursor() as cur:
        cur.execute("""select source_run_id::text,encode(payload_sha256,'hex') as payload_sha256
            from gpo_report_v2_source_snapshots where domain_id=%s and source_run_id=%s and import_status='completed'""",
                    (domain["id"], bundle["run_id"]))
        stored = cur.fetchone()
    _, expected_sha = canonical_snapshot(redact_gpo_snapshot(bundle["gpo_v2_snapshot"]))
    if not stored or stored["source_run_id"] != bundle["run_id"] or stored["payload_sha256"] != expected_sha:
        raise ValueError("agent_gpo_import_readback_invalid")
    return {"source_run_id": bundle["run_id"], "status": "published"}

"""Narrow SID-only contract over retained AD observations; no directory calls."""
from datetime import datetime, timedelta, timezone

from sli_agent.envelope import timestamp
from sli_agent.file_audit_policy import SID


def _stamp(value):
    if isinstance(value, datetime):
        if value.utcoffset() is None:
            raise ValueError("file_audit_enrichment_invalid")
        value = value.astimezone(timezone.utc).isoformat()
    return timestamp(value)


def principals(cur, *, domain_id, sids, at):
    if (type(domain_id) is not int or domain_id <= 0 or not isinstance(sids, list) or len(sids) > 2048
            or any(not isinstance(sid, str) or not SID.fullmatch(sid) for sid in sids)):
        raise ValueError("file_audit_enrichment_invalid")
    instant = timestamp(at)
    cur.execute("""
        select a.normalized_value as sid,v.entity_id,v.attributes_json,
               v.valid_from_utc,v.last_observed_at_utc,v.source_run_id
        from ad_context_entity_aliases a
        join ad_context_entity_versions v on v.entity_id=a.entity_id
        join ad_context_runs r on r.run_id=v.source_run_id and r.status='completed'
        where a.domain_id=%s and a.alias_type='object_sid' and a.normalized_value=any(%s)
          and v.source_section in ('directory_accounts','directory_group_graph')
          and v.valid_from_utc<=%s and (v.valid_to_utc is null or v.valid_to_utc>%s)
        order by a.normalized_value,v.valid_from_utc desc limit 2049
        """, (domain_id, [sid.lower() for sid in sids], instant, instant))
    rows = cur.fetchall()
    if len(rows) > 2048:
        return {}
    result = {}
    for row in rows:
        record = row["attributes_json"]
        identity, attributes = record.get("identity", {}), record.get("attributes", {})
        sid = identity.get("object_sid")
        if sid not in sids or sid in result or identity.get("kind") not in ("ad_user", "ad_group"):
            continue
        observed = min(_stamp(row["last_observed_at_utc"]), instant)
        # The current version may have been refreshed later than this snapshot.
        # Its valid_from proves the old value, but not historical freshness.
        fresh = _stamp(row["last_observed_at_utc"]) <= instant and instant - observed <= timedelta(days=1)
        item = {"kind": "user" if identity["kind"] == "ad_user" else "group",
                "enabled": attributes.get("enabled") if fresh and type(attributes.get("enabled")) is bool else None,
                "domain_users": identity["kind"] == "ad_group" and sid.endswith("-513"),
                "group_sids": [], "complete": False, "observed_at": observed.isoformat(),
                "evidence_ref": f"ad-context:{row['source_run_id']}:{row['entity_id']}"}
        # Refreshed unchanged versions keep their original source_run_id. Use
        # the latest graph receipt and its observation time, not that old ID.
        if fresh and item["kind"] == "user":
            cur.execute("""
                with recursive graph as (
                    select r.run_id,r.observed_at_utc,r.mode,s.status
                    from ad_context_runs r join ad_context_sections s on s.run_id=r.run_id
                    where r.domain_id=%s and r.status='completed' and s.section_name='directory_group_graph'
                      and r.observed_at_utc between %s-interval '1 day' and %s
                    order by r.observed_at_utc desc,r.run_id limit 1
                ), membership(entity_id,depth,visited) as (
                    select %s::bigint,0,array[%s::bigint] from graph
                    union all
                    select relation.target_entity_id,m.depth+1,m.visited||relation.target_entity_id
                    from graph,membership m join ad_context_relation_versions relation
                      on relation.source_entity_id=m.entity_id
                    where relation.domain_id=%s and relation.source_section='directory_group_graph'
                      and relation.last_observed_at_utc>=graph.observed_at_utc
                      and relation.valid_from_utc<=graph.observed_at_utc
                      and (relation.valid_to_utc is null or relation.valid_to_utc>graph.observed_at_utc)
                      and m.depth<16 and not relation.target_entity_id=any(m.visited)
                )
                select m.depth,a.normalized_value as sid,
                       (graph.status='complete' and graph.mode in ('full','reconcile')) as complete,
                       graph.run_id as graph_run_id
                from graph,membership m
                left join ad_context_entity_aliases a on a.entity_id=m.entity_id
                  and a.alias_type='object_sid' and a.domain_id=%s
                order by m.depth,a.normalized_value limit 2049
                """, (domain_id, instant, instant, row["entity_id"], row["entity_id"], domain_id, domain_id))
            groups = cur.fetchall()
            item["complete"] = bool(groups) and len(groups) <= 2048 and all(
                group["complete"] is True and group["sid"] is not None and group["depth"] < 16 for group in groups)
            item["group_sids"] = sorted({group["sid"].upper() for group in groups if group["depth"] and group["sid"]})
            if groups and groups[0].get("graph_run_id"):
                item["membership_evidence_ref"] = f"ad-context:{groups[0]['graph_run_id']}:directory_group_graph"
            primary = attributes.get("primary_group_id")
            if primary is not None and str(primary).isdecimal():
                item["group_sids"].append(sid.rsplit("-", 1)[0] + "-" + str(primary))
            else:
                item["complete"] = False
            if attributes.get("unresolved_group_dns") or attributes.get("unresolved_primary_group_sid"):
                item["complete"] = False
        result[sid] = item
    return result

"""Finite rule evaluations within the core's admitted transaction."""
from datetime import timedelta
import json

from server.sli.core.working_time import SETTING_KEY, validate
from server.sli.plugins.file_audit.acl import parse_dacl
from server.sli.plugins.file_audit.rules import activity_findings, permission_findings
from server.sli.plugins.registry import plugin_hook
from sli_agent.envelope import timestamp


def _publish(cur, results, *, agent_id, packet_id=None, command_id=None):
    if results:
        cur.execute("select sli_plugin_file_audit.publish_rules(%s,%s,%s,%s::jsonb)",
                    (agent_id, packet_id, command_id, json.dumps(results)))
    return len(results)


def evaluate_packet(cur, *, envelope, actions, config):
    if not actions:
        return 0
    start = min(timestamp(row["observed_at"]) for row in actions) - timedelta(seconds=config["mass_operation_seconds"])
    # Late arrivals must also see already admitted witnesses in the next
    # source-time window; activity_findings still enforces the original width.
    end = max(timestamp(row["observed_at"]) for row in actions) + timedelta(seconds=config["mass_operation_seconds"])
    if end - start > timedelta(days=2):
        return 0  # bounded historical replay, not a fabricated complete window
    cur.execute("select sli_plugin_file_audit.rule_context(%s,%s,%s,%s) as context",
                (envelope["agent_id"], envelope["packet_id"], start, end))
    context = cur.fetchone()["context"]
    cur.execute("select value from platform_settings where key=%s", (SETTING_KEY,))
    stored = cur.fetchone()
    calendar = None
    if stored:
        try:
            calendar = validate(json.loads(stored["value"]))
        except (ValueError, TypeError):
            pass  # invalid/missing settings must not invent working hours
    candidates = context["actions"] if context["complete"] else actions
    # Partial native correlation cannot be repaired by object type alone when
    # the context itself is truncated or has a continuity gap.
    if not context["complete"]:
        candidates = [row for row in candidates if row["correlation_state"] == "complete"]
    results = activity_findings(candidates, config=config, agent_id=envelope["agent_id"],
        source_instance_id=envelope["source_instance_id"], snapshots=context["snapshots"], working_time=calendar)
    current_ids = {row["action_id"] for row in actions}
    results = [row for row in results if current_ids.intersection(row["action_ids"])]
    return _publish(cur, results, agent_id=envelope["agent_id"], packet_id=envelope["packet_id"])


def evaluate_snapshots(cur, *, agent_id, source_instance_id, command_id, config, snapshots, domain_id=None):
    enrich = plugin_hook("sli.ad", "file_audit_principals")
    results = []
    for snapshot in snapshots:
        bound = {**snapshot, "agent_id": agent_id, "source_instance_id": source_instance_id}
        sids = set()
        for obj in [snapshot["share"], *snapshot["objects"]]:
            aces, _ = parse_dacl(obj["dacl"])
            sids.update(ace.sid for ace in aces)
        principals = enrich(cur, domain_id=domain_id, sids=sorted(sids), at=snapshot["observed_at_utc"]) if enrich and domain_id and len(sids) <= 2048 else {}
        results.extend(permission_findings(bound, config=config, principals=principals))
    return _publish(cur, results, agent_id=agent_id, command_id=command_id)

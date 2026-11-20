"""N08 local, opt-in NPS reader; one scope/checkpoint per transaction."""
from dataclasses import asdict
from datetime import timedelta
from ipaddress import ip_address
import json

from server.sli.semantic.nps_threshold import Denial, MAX_EVENTS, evaluate, utc
from server.sli.semantic.qw_input import enqueue_qw_signal_risk_jobs
from server.sli.storage.evidence_ref import EvidenceRef


def read_denials(cur, rule, *, end):
    """The SQL capability reads only the login's administrator-bound source.

    Legacy packets declare continuity=not_proven. Updated collectors attest
    intervals only after reaching a verified local tail with continuous cursors.
    """
    scope = rule.scope
    now = end
    cur.execute("select public.nps_threshold_watermark(%s,%s,%s,%s,%s) as watermark", (
        scope.installation_id, scope.plugin_id, scope.source_instance_id, scope.source_generation, now))
    end = (cur.fetchone() or {}).get("watermark") or now
    cur.execute("select * from public.read_nps_threshold_events(%s,%s,%s,%s,%s,%s)", (
        scope.installation_id, scope.plugin_id, scope.source_instance_id, scope.source_generation,
        end - timedelta(seconds=2 * rule.window_seconds), end))
    rows = list(cur.fetchall() or [])
    truncated = len(rows) > MAX_EVENTS
    events = []
    for row in rows[:MAX_EVENTS]:
        facts, roles, quality = row["facts_json"] or {}, row["roles_json"] or {}, row["quality_json"] or {}
        if rule.dimension == "account":
            identity = quality.get("identity_roles", {}).get("affected_entity", {})
            value = roles.get("affected_entity") if identity.get("state") == "resolved" and not identity.get("provisional") else None
        elif rule.dimension == "client_ip":
            # NPS normalizes CallingStationID as source_ip. A MAC/phone value
            # is not an IP; ClientIPAddress/NAS address identifies the gateway.
            try:
                value = str(ip_address(roles.get("source_ip")))
            except ValueError:
                value = None
        else:
            value = facts.get(rule.dimension)
        value = str(value).strip() if value is not None else None
        if value in {"", "-", "N/A"}:
            value = None
        events.append(Denial(utc(row["occurred_at_utc"]),
            EvidenceRef("core_event", str(row["source_event_id"]), row["sha256"], scope), value))
    qualities = []
    window = timedelta(seconds=rule.window_seconds)
    for start, finish in ((end - window, end), (end - 2 * window, end - window)):
        cur.execute("select public.nps_threshold_window_quality(%s,%s,%s,%s,%s,%s,%s) as quality", (
            scope.installation_id, scope.plugin_id, scope.source_instance_id, scope.source_generation, start, finish, now))
        quality = (cur.fetchone() or {}).get("quality", "partial")
        qualities.append("truncated" if truncated else quality)
    return events, *qualities, end


def run_once(cur, *, rule, now, reader=read_denials):
    """No commit or network: failure rolls back both cursor and all QW jobs.

    The source-time watermark advances only with durable admission. Every poll
    rereads two whole windows (bounded overlap) to include delayed collection.
    Diagnostic rows contain opaque group keys, counts and fixed quality codes.
    """
    now = utc(now)
    scope = asdict(rule.scope)
    cur.execute("""insert into semantic_nps_threshold_state(checkpoint_key,scope_json,checkpoint_json)
        values(%s,%s::jsonb,'{}'::jsonb) on conflict do nothing""",
        (rule.checkpoint_key, json.dumps(scope, sort_keys=True)))
    cur.execute("select checkpoint_json from semantic_nps_threshold_state where checkpoint_key=%s for update",
                (rule.checkpoint_key,))
    row = cur.fetchone()
    if not row:
        raise RuntimeError("nps_threshold_checkpoint_denied")
    checkpoint = row["checkpoint_json"]
    if isinstance(checkpoint, str):
        checkpoint = json.loads(checkpoint)
    if checkpoint.get("state") == "not_proven" and not checkpoint.get("episodes"):
        # Before the first NPS receipt there was no source watermark. The
        # first collected tail may precede that diagnostic poll by seconds.
        checkpoint = {}
    batch = reader(cur, rule, end=now)
    events, current_quality, previous_quality = batch[:3]
    end = batch[3] if len(batch) == 4 else now
    updated, signals = evaluate(rule, events, end=end, now=now, checkpoint=checkpoint,
                               current_quality=current_quality, previous_quality=previous_quality)
    jobs = set()
    for signal in signals:
        admitted = enqueue_qw_signal_risk_jobs(cur, signal=signal)
        if not admitted:
            # Do not consume the threshold when policy/mode/revision is absent.
            raise RuntimeError("nps_threshold_policy_unavailable")
        jobs.update(admitted)
    cur.execute("""update semantic_nps_threshold_state set checkpoint_json=%s::jsonb,
        updated_at=clock_timestamp() where checkpoint_key=%s""",
                (json.dumps(updated, sort_keys=True), rule.checkpoint_key))
    return {"state": updated["state"], "rows": updated["rows"], "jobs": len(jobs)}

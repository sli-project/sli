"""Bounded D02 reader/checkpoint and QW admission share the caller transaction."""
from dataclasses import asdict
import json

from server.sli.semantic.account_decoy import DecoyRule, evaluate, utc
from server.sli.semantic.qw_input import enqueue_qw_signal_risk_jobs


def read_events(cur, rule, *, normalized_event_id=None):
    scope = rule.scope
    cur.execute("select * from public.read_account_decoy_events(%s,%s,%s,%s,%s,%s::uuid)", (
        scope.installation_id, scope.plugin_id, scope.source_instance_id, scope.source_generation,
        rule.checkpoint_key, normalized_event_id))
    return list(cur.fetchall() or [])


def verify_signal(cur, signal):
    rule = DecoyRule(scope=signal.evidence_refs[0].scope, policy_revision=signal.policy_revision,
                     evaluation_mode=signal.evaluation_mode, processing_mode=signal.processing_mode)
    rows = read_events(cur, rule, normalized_event_id=signal.decoy_context["normalized_event_id"])
    if len(rows) != 1:
        raise RuntimeError("account_decoy_source_mismatch")
    expected, _ = evaluate(rule, rows[0], now=signal.received_at_utc)
    if not any(item.document == signal.document for item in expected):
        raise RuntimeError("account_decoy_source_mismatch")


def run_once(cur, *, rule, now, reader=read_events):
    now = utc(now)
    cur.execute("select pg_advisory_xact_lock(hashtextextended(%s,0))", (rule.checkpoint_key,))
    rows = reader(cur, rule)
    if len(rows) > 128:
        raise ValueError("account_decoy_batch_invalid")
    jobs, states = set(), {}
    for row in rows:
        signals, state = evaluate(rule, row, now=now)
        for signal in signals:
            admitted = enqueue_qw_signal_risk_jobs(cur, signal=signal)
            if not admitted:
                raise RuntimeError("account_decoy_policy_unavailable")
            jobs.update(admitted)
        cur.execute("""insert into semantic_account_decoy_checks(
            checkpoint_key,normalized_event_id,scope_json,result_code)
            values(%s,%s,%s::jsonb,%s) on conflict do nothing""", (
                rule.checkpoint_key, row["normalized_event_id"], json.dumps(asdict(rule.scope)), state))
        states[state] = states.get(state, 0) + 1
    return {"state": "processed", "events": len(rows), "results": states, "jobs": len(jobs)}

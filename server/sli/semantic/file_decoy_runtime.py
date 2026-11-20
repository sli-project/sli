"""Bounded D03 processing; evidence, checkpoints and jobs share a transaction."""
from dataclasses import asdict
import json

from server.sli.semantic.account_decoy import utc
from server.sli.semantic.file_decoy import FileDecoyRule, evaluate
from server.sli.semantic.qw_input import enqueue_qw_signal_risk_jobs


def read_observations(cur, rule, *, observation_key=None):
    cur.execute("select * from public.read_file_decoy_observations(%s::jsonb,%s,%s,%s)", (
        json.dumps(asdict(rule.scope)), rule.agent_id, rule.checkpoint_key, observation_key))
    return list(cur.fetchall() or [])


def verify_signal(cur, signal):
    context = signal.file_decoy_context
    rule = FileDecoyRule(scope=signal.evidence_refs[0].scope, agent_id=context["agent_id"],
                         policy_revision=signal.policy_revision, evaluation_mode=signal.evaluation_mode,
                         processing_mode=signal.processing_mode)
    rows = read_observations(cur, rule, observation_key=context["observation_key"])
    if len(rows) != 1:
        raise RuntimeError("file_decoy_source_mismatch")
    expected, _ = evaluate(rule, rows[0], now=signal.received_at_utc)
    if not any(item.document == signal.document for item in expected):
        raise RuntimeError("file_decoy_source_mismatch")


def run_once(cur, *, rule, now, reader=read_observations):
    now = utc(now)
    cur.execute("select pg_advisory_xact_lock(hashtextextended(%s,0))", (rule.checkpoint_key,))
    rows = reader(cur, rule)
    if len(rows) > 128:
        raise ValueError("file_decoy_batch_invalid")
    jobs, states = set(), {}
    for row in rows:
        signals, state = evaluate(rule, row, now=now)
        for signal in signals:
            admitted = enqueue_qw_signal_risk_jobs(cur, signal=signal)
            if not admitted:
                raise RuntimeError("file_decoy_policy_unavailable")
            jobs.update(admitted)
        cur.execute("""insert into semantic_file_decoy_checks(checkpoint_key,observation_key,scope_json,result_code)
            values(%s,%s,%s::jsonb,%s) on conflict do nothing""", (
                rule.checkpoint_key, row["observation"]["evidence_key"], json.dumps(asdict(rule.scope)), state))
        states[state] = states.get(state, 0) + 1
    return {"state": "processed", "observations": len(rows), "results": states, "jobs": len(jobs)}

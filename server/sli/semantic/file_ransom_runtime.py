"""R01 bounded worker: durable episodes/members and QW admission in one transaction."""
from dataclasses import asdict
from datetime import timedelta
import json

from server.sli.semantic.file_ransom import exclusion_for, mass_window, signals
from server.sli.semantic.qw_input import _digest, enqueue_qw_signal_risk_jobs
from server.sli.storage.evidence_ref import EvidenceRef


def read_results(cur, rule):
    cur.execute("select * from public.read_file_ransom_results(%s::jsonb,%s,%s,%s,%s,%s)", (
        json.dumps(asdict(rule.scope)), rule.agent_id, rule.source_policy_revision,
        rule.checkpoint_key, rule.threshold, rule.window_seconds))
    return list(cur.fetchall() or [])


def run_once(cur, *, rule, now, reader=read_results):
    """No commit, source activation or transport calls. Serialize the whole scope.

    A member is marked processed only after every evidence portion has a job.
    Unknown continuity keeps the episode incomplete, without claiming quiet.
    """
    cur.execute("select pg_advisory_xact_lock(hashtextextended(%s,0))", (rule.checkpoint_key,))
    rows = reader(cur, rule)
    if len(rows) > 32:
        raise ValueError("file_ransom_batch_invalid")
    admitted = members = 0
    scope_json = json.dumps(asdict(rule.scope), sort_keys=True)
    for row in rows:
        result = row["result"]
        start, end, entity = mass_window(rule, result)
        cur.execute("select 1 from semantic_file_ransom_members where checkpoint_key=%s and result_id=%s",
                    (rule.checkpoint_key, result["result_id"]))
        if cur.fetchone():
            continue
        exclusion = exclusion_for(rule, result)
        if exclusion:
            cur.execute("""insert into semantic_file_ransom_members(
                checkpoint_key,result_id,episode_key,scope_json,exclusion_json,evaluation_mode)
                values(%s,%s,null,%s::jsonb,%s::jsonb,%s)""", (
                    rule.checkpoint_key, result["result_id"], scope_json,
                    json.dumps(asdict(exclusion)), rule.evaluation_mode))
            members += 1
            continue
        cur.execute("""select * from semantic_file_ransom_episodes
            where checkpoint_key=%s and entity_key=%s
              and (incomplete or %s or (first_seen<=%s and last_seen>=%s))
            order by first_seen,episode_key for update""", (
                rule.checkpoint_key, entity, not row["complete"],
                end + timedelta(seconds=rule.window_seconds), start - timedelta(seconds=rule.window_seconds)))
        episodes = list(cur.fetchall() or [])
        if len(episodes) > 1:
            # A late bridge cannot silently detach already published evidence.
            raise RuntimeError("file_ransom_episode_conflict")
        episode = episodes[0] if episodes else None
        key = episode["episode_key"] if episode else _digest([rule.checkpoint_key, entity, result["result_id"]])
        complete = row["complete"] and not (episode and episode["incomplete"])
        refs = tuple(EvidenceRef("file_audit_observation", ref["native_id"], ref["sha256"], rule.scope)
                     for ref in row["evidence"])
        for signal in signals(rule, result, refs, episode_key=key, now=now, complete=complete):
            jobs = enqueue_qw_signal_risk_jobs(cur, signal=signal)
            if not jobs:
                raise RuntimeError("file_ransom_policy_unavailable")
            admitted += len(jobs)
        cur.execute("""insert into semantic_file_ransom_episodes(
            episode_key,checkpoint_key,scope_json,entity_key,first_seen,last_seen,incomplete)
            values(%s,%s,%s::jsonb,%s,%s,%s,%s) on conflict(episode_key) do update
            set first_seen=least(semantic_file_ransom_episodes.first_seen,excluded.first_seen),
                last_seen=greatest(semantic_file_ransom_episodes.last_seen,excluded.last_seen),
                incomplete=semantic_file_ransom_episodes.incomplete or excluded.incomplete""",
                    (key, rule.checkpoint_key, scope_json, entity, start, end, not complete))
        cur.execute("""insert into semantic_file_ransom_members(checkpoint_key,result_id,episode_key,scope_json,evaluation_mode)
            values(%s,%s,%s,%s::jsonb,%s)""", (rule.checkpoint_key, result["result_id"], key, scope_json, rule.evaluation_mode))
        members += 1
    return {"state": "processed", "members": members, "jobs": admitted}

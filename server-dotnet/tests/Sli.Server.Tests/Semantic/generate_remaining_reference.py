"""Synthetic file-decoy and threshold cases evaluated by the local Python reference."""
import json
from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from server.sli.semantic import file_decoy, file_ransom, nps_threshold
from server.sli.semantic.qw_input import _digest
from server.sli.storage.evidence_ref import EvidenceRef, EvidenceScope

now = datetime(2026, 1, 1, 0, 10, tzinfo=timezone.utc)
agent = "11111111-1111-1111-1111-111111111111"
scope = EvidenceScope(agent, "sli.file-audit", "synthetic", "1", "root")
identity = dict(agent_id=agent, source_instance_id="synthetic", collection_scope_id="root", path="c:\\share\\decoy.txt")
observation = dict(evidence_key="a" * 64, payload_sha256="b" * 64, agent_id=agent,
    source_instance_id="synthetic", generation="1", policy_revision="1", record_id=10, event_id=4663,
    observed_at=(now - timedelta(seconds=1)).isoformat(), path="C:\\share\\decoy.txt",
    scopes=[dict(collection_scope_id="root")], facts=dict(outcome="success", object_type="File", access_mask=1,
        subject_user_sid="S-1-5-21-100000001-200000002-300000003-1001", logon_id_numeric=1, server_process_id=2, handle_id=3))
label = dict(id="22222222-2222-2222-2222-222222222222", revision=1, kind="file", active=True,
    active_from="2025-01-01T00:00:00+00:00", active_to=None, identity=identity)
vectors = []
for case in ("read", "access_check", "denied", "delete_right", "deleted", "handle_closed", "handle_zero", "ambiguous", "future", "wrong_source", "outside_root", "expired", "provenance"):
    row = dict(observation=deepcopy(observation), labels=[deepcopy(label)], contexts=[])
    obs = row["observation"]
    if case in ("access_check", "denied"): obs["event_id"] = 4656
    if case == "denied": obs["facts"]["outcome"] = "failure"
    if case == "delete_right": obs["facts"]["access_mask"] = 65536
    if case in ("deleted", "handle_closed", "handle_zero", "ambiguous"):
        context = deepcopy(obs); context.update(record_id=9, evidence_key="c" * 64)
        row["contexts"].append(context); obs.update(event_id=4660, path=None)
        if case == "handle_closed":
            closed = deepcopy(context); closed.update(event_id=4658, record_id=9, path=None)
            context["record_id"] = 8; row["contexts"].append(closed)
        if case == "handle_zero": obs["facts"]["handle_id"] = context["facts"]["handle_id"] = 0
        if case == "ambiguous":
            other = deepcopy(context); other.update(path="C:\\share\\other.txt", record_id=8); row["contexts"].append(other)
    if case == "future": obs["observed_at"] = (now + timedelta(seconds=1)).isoformat()
    if case == "wrong_source": obs["source_instance_id"] = "other"
    if case == "outside_root": obs["scopes"] = []
    if case == "expired": row["labels"][0]["active_to"] = obs["observed_at"]
    rule = file_decoy.FileDecoyRule(scope=scope, agent_id=agent, evaluation_mode="enabled", processing_mode="historical_replay" if case == "provenance" else "live")
    signals, state = file_decoy.evaluate(rule, row, now=now)
    vectors.append(dict(case=case, kind="file-decoy", rule=asdict(rule), now=now.isoformat(), row=row, expected=[s.document for s in signals], state=state))

for case in ("threshold", "surge", "new_activity", "partial", "unknown_identity", "client_ip", "nas_identifier", "network_policy", "reason_code", "below"):
    scope = EvidenceScope(agent, "sli.vpn-nps", "synthetic", "1")
    dimension = case if case in ("client_ip", "nas_identifier", "network_policy", "reason_code") else "account"
    rule = nps_threshold.ThresholdRule(scope=scope, evaluation_mode="enabled", dimension=dimension, threshold=3, window_seconds=120, surge_factor=2)
    rows, denials = [], []
    previous = 1 if case == "surge" else 0 if case == "new_activity" else 3
    for i in range((2 if case == "below" else 3) + previous):
        at = now - timedelta(seconds=10 + i if i < (2 if case == "below" else 3) else 140+i)
        value = None if case == "unknown_identity" else "192.0.2.2" if dimension == "client_ip" else "synthetic"
        roles = {"affected_entity": value, "source_ip": value}; facts = {dimension: value}
        quality = {"identity_roles": {"affected_entity": {"state": "resolved", "provisional": False}}}
        rows.append(dict(occurred_at_utc=at.isoformat(), source_event_id=i+1, sha256="a"*64, roles_json=roles, facts_json=facts, quality_json=quality))
        denials.append(nps_threshold.Denial(at, EvidenceRef("core_event", str(i+1), "a"*64, scope), value))
    quality = "partial" if case == "partial" else "good"
    checkpoint, signals = nps_threshold.evaluate(rule, denials, end=now, now=now, current_quality=quality, previous_quality=quality)
    vectors.append(dict(case=case, kind="nps-threshold", rule=asdict(rule), now=now.isoformat(), rows=rows, quality=quality, expected=[s.document for s in signals], checkpoint=checkpoint))
for case in ("complete", "partial", "exclusion", "partial_exclusion", "portions", "replay"):
    scope = EvidenceScope(agent, "sli.file-audit", "synthetic", "1", "root")
    exclusion = file_ransom.RansomExclusion(subject_sid=observation["facts"]["subject_user_sid"], collection_scope_id="root",
        reason="Synthetic approval", approved_by="synthetic", active_from="2026-01-01T00:00:00Z",
        active_to="2026-01-01T00:20:00Z" if case == "exclusion" else "2026-01-01T00:09:00Z")
    rule = file_ransom.RansomRule(scope=scope, agent_id=agent, source_policy_revision="1", threshold=2,
        evaluation_mode="enabled", exclusions=(exclusion,) if case in ("exclusion", "partial_exclusion") else ())
    result = dict(result_id="c"*64, rule_code="file-audit.mass-write", rule_version=1, conclusion_state="observed",
        agent_id=agent, source_instance_id="synthetic", collection_scope_id="root", subject_sid=exclusion.subject_sid,
        action_ids=["a", "b"], details=dict(threshold=2, window_seconds=300, distinct_files=2,
        window_start="2026-01-01T00:08:00Z", window_end="2026-01-01T00:09:00Z"))
    refs = [EvidenceRef("file_audit_observation", f"{i+1:064x}", "a"*64, scope) for i in range(257 if case == "portions" else 2)]
    key = _digest([rule.checkpoint_key, _digest([rule.checkpoint_key, result["subject_sid"]]), result["result_id"]])
    signals = () if case == "replay" or file_ransom.exclusion_for(rule, result) else file_ransom.signals(rule, result, refs, episode_key=key, now=now, complete=case != "partial")
    row = dict(result=result, complete=case != "partial", evidence=[dict(native_id=r.native_id, sha256=r.sha256) for r in refs])
    vectors.append(dict(case=case, kind="file-ransom", rule=asdict(rule), now=now.isoformat(), row=row,
        expected=[s.document for s in signals]))
Path(__file__).with_name("remaining-reference.json").write_text(json.dumps(vectors, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

"""Bounded managed execution of explicitly admitted, pinned Sigma revisions."""
from dataclasses import asdict
from datetime import datetime
import json

from server.sli.ops import shutdown
from server.sli.semantic.qw_input import _digest
from server.sli.sigma.compiler import compile_rule
from server.sli.sigma.detection_input import DetectionMatch, enqueue_detection_match_risk_jobs
from server.sli.sigma.lifecycle import execution_pin_sha256
from server.sli.sigma.matcher import match_rule
from server.sli.sigma.windows_mapping import EventScope, SigmaMappingError, map_windows_event
from server.sli.storage.evidence_ref import EvidenceRef, EvidenceScope


def evaluate_revision(cur, *, policy_id, version):
    cur.execute("select public.read_admitted_sigma_revision(%s,%s) as revision", (policy_id, version))
    revision = (cur.fetchone() or {}).get("revision")
    if not revision:
        return 0
    pin = revision["execution"]
    execution_pin_sha256(pin, rule_id=pin["rule_id"])
    scope = EvidenceScope(**pin["scope"])
    rule = compile_rule(revision["raw_yaml"].encode(), source_uri=revision["source_uri"],
                        upstream_commit=revision["upstream_commit"], license_id=revision["license"])
    if (rule.source_sha256 != pin["rule_sha256"] or rule.rule_id != pin["rule_id"]
            or rule.compiler_version != pin["compiler_version"] or rule.mapping_version != pin["mapping_version"]):
        raise RuntimeError("sigma_live_revision_mismatch")
    # Empty overlays are explicit, content-bound pins. Other overlays require
    # their retained predicate, never silently run the unmodified base rule.
    if pin["overlay_sha256"] != _digest({}):
        raise RuntimeError("sigma_live_overlay_unavailable")
    cur.execute("""insert into semantic_sigma_live_cursors(policy_id,policy_version,last_event_id)
        values(%s,%s,0) on conflict do nothing""", (policy_id, version))
    cur.execute("""select last_event_id from semantic_sigma_live_cursors
        where policy_id=%s and policy_version=%s for update""", (policy_id, version))
    after = cur.fetchone()["last_event_id"]
    cur.execute("select * from public.read_admitted_sigma_events(%s::jsonb,%s)", (json.dumps(asdict(scope)), after))
    rows = list(cur.fetchall() or [])
    jobs = 0
    for row in rows:
        try:
            event = map_windows_event(row["source_xml"], scope=EventScope(scope.installation_id,
                scope.source_instance_id, scope.source_generation))
        except SigmaMappingError:
            continue  # unsupported native versions are not positive matches
        matched = match_rule(rule, event.fields, unavailable=event.unavailable)
        if matched.status == "matched":
            match = DetectionMatch(rule_id=rule.rule_id, rule_sha256=rule.source_sha256,
                manifest_sha256=pin["manifest_sha256"], compiler_version=rule.compiler_version,
                mapping_version=rule.mapping_version, overlay_sha256=pin["overlay_sha256"],
                evidence=EvidenceRef("core_event", str(row["source_event_id"]), row["sha256"], scope),
                entity_key=_digest([scope.source_instance_id, event.identity.computer]),
                occurred_at_utc=datetime.fromisoformat(event.identity.occurred_at.replace("Z", "+00:00")),
                evaluation_mode="enabled")
            jobs += len(enqueue_detection_match_risk_jobs(cur, match=match))
    if rows:
        cur.execute("""update semantic_sigma_live_cursors set last_event_id=%s
            where policy_id=%s and policy_version=%s""", (rows[-1]["source_event_id"], policy_id, version))
    return jobs


def run_sigma_detections(conn):
    with conn.transaction(), conn.cursor() as cur:
        cur.execute("""select p.policy_id,p.policy_version from semantic_risk_policies p
            join semantic_policy_admission a using(policy_id,policy_version)
            where p.source_kind='detection_match' and a.enabled
              and semantic_policy_mode_v160(p.policy_id,p.policy_version,p.lifecycle_status)='enabled'
            order by p.policy_id,p.policy_version limit 25""")
        policies = list(cur.fetchall() or [])
    jobs = failed = 0
    for policy in policies:
        if shutdown.requested():
            break
        try:
            with conn.transaction(), conn.cursor() as cur:
                jobs += evaluate_revision(cur, policy_id=policy["policy_id"], version=policy["policy_version"])
        except Exception:
            failed += 1
    return {"policies": len(policies), "jobs": jobs, "failed": failed}

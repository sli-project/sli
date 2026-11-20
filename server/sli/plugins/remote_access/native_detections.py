"""Remote-access native detection through the existing reviewed plugin hook."""
from dataclasses import asdict

from server.sli.semantic import nps_threshold, nps_threshold_runtime


def run_once(cur, scope, *, now, admit, policy_id):
    rule = nps_threshold.ThresholdRule(scope=scope, evaluation_mode="enabled")
    policy = nps_threshold.risk_policy(rule, policy_id=policy_id({
        "rule_id": "qw.nps-denials", "scope": asdict(scope), "rule_sha256": rule.rule_sha256}))
    if not admit(cur, policy):
        return 0
    return nps_threshold_runtime.run_once(cur, rule=rule, now=now)["jobs"]

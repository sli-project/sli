from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts" / "maintenance" / "run_semantic_risk_shadow_once.py"


def test_risk_runner_is_connection_free_and_blocked_by_default() -> None:
    env = dict(os.environ)
    for name in tuple(env):
        if name.startswith("ADLOG_SEMANTIC_"):
            env.pop(name)
    result = subprocess.run(
        [sys.executable, str(RUNNER)],
        cwd=ROOT.parent,
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "blocked"
    assert payload["connections"] == 0


def test_risk_runner_requires_explicit_execute_and_full_dependency_chain() -> None:
    source = RUNNER.read_text(encoding="utf-8")
    assert 'parser.add_argument("--execute", action="store_true")' in source
    assert "settings.risk_engine_enabled" in source
    assert "version=29 and name='semantic_risk_runtime'" in source
    assert "findings_created" in source
    assert "Path(__file__).resolve().parents[2]" in source


def test_backlog_query_excludes_sources_already_evaluated_in_current_mode() -> None:
    from server.sli.semantic import semantic_risk_runtime_repository as runtime

    class Cursor:
        def execute(self, sql, params):
            self.sql = sql
            self.params = params

        def fetchall(self):
            return []

    cur = Cursor()
    assert runtime.enqueue_risk_backlog(cur, limit=7) == ()
    backlog = cur.sql
    assert backlog.count("not exists (") == 5
    assert "subscription.source_kind='canonical_action'" in backlog
    effective_mode = "policy.effective_mode"
    assert backlog.count(f"job.evaluation_mode={effective_mode}") == 3
    assert backlog.count(f"{effective_mode}=any(%s)") == 3
    # Detection matches retain the evaluation mode in which the rule matched.
    detection_backlog = next(
        branch for branch in backlog.split("union all")
        if "from semantic_detection_matches detection" in branch
    )
    assert "from semantic_detection_matches detection" in detection_backlog
    assert "subscription.source_kind='detection_match'" in detection_backlog
    assert "subscription.selector_value=detection.rule_id" in detection_backlog
    assert f"{effective_mode}=detection.evaluation_mode" in detection_backlog
    assert detection_backlog.count("not exists (") == 1
    assert "job.source_kind='detection_match'" in detection_backlog
    assert "job.source_reference=detection.match_id" in detection_backlog
    assert "job.evaluation_mode=detection.evaluation_mode" in detection_backlog
    # QW signals also retain their source mode and exclude existing jobs.
    qw_backlog = next(
        branch for branch in backlog.split("union all")
        if "from semantic_qw_signals signal" in branch
    )
    assert "subscription.source_kind='qw_signal'" in qw_backlog
    assert "subscription.selector_value=signal.document_json->>'rule_id'" in qw_backlog
    assert f"{effective_mode}=signal.evaluation_mode" in qw_backlog
    assert qw_backlog.count("not exists (") == 1
    assert "job.policy_id=policy.policy_id and job.policy_version=policy.policy_version" in qw_backlog
    assert "job.source_kind='qw_signal'" in qw_backlog
    assert "job.source_reference=signal.signal_id" in qw_backlog
    assert "job.evaluation_mode=signal.evaluation_mode" in qw_backlog
    assert cur.params == (7,) + (sorted(runtime.EXECUTABLE_POLICY_STATES),) * 3 + (7,)


def test_action_backlog_is_bounded_per_subscription_before_global_ordering() -> None:
    from server.sli.semantic import semantic_risk_runtime_repository as runtime

    class Cursor:
        def execute(self, sql, params):
            self.sql, self.params = " ".join(sql.split()), params

        def fetchall(self):
            return []

    cur = Cursor()
    runtime.enqueue_risk_backlog(cur, limit=10000)
    action_branch = cur.sql.split("union all", 1)[0]
    assert "select distinct 'canonical_action'" in action_branch
    assert "from semantic_risk_policy_subscriptions subscription" in action_branch
    assert "cross join lateral (" in action_branch
    assert "subscription.selector_value=action.action_kind" in action_branch
    assert "order by action.occurred_at_utc,action.canonical_action_id limit %s" in action_branch
    assert "job.policy_id=policy.policy_id" in action_branch
    assert "job.policy_version=policy.policy_version" in action_branch
    assert "job.source_reference=action.canonical_action_id::text" in action_branch
    assert cur.params[0] == cur.params[-1] == 1000

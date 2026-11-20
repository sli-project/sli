from __future__ import annotations

import copy
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from scripts.dev.ui_audit import scenarios as s
from scripts.dev.ui_audit.passport import CATEGORIES, field_category, verify_dataset

ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts/dev/ui_audit/scenario_runner.cjs"


@pytest.fixture
def dataset():
    return {
        "problems": [
            {"id": 1, "scope_id": 1, "severity": "high", "state": "active", "observed_at": "2026-10-07T01:00:00Z", "next_step": 0},
            {"id": 2, "scope_id": 2, "severity": "critical", "state": "active", "observed_at": "2026-10-07T00:00:00Z", "next_step": 2},
            {"id": 3, "scope_id": 1, "severity": "critical", "state": "closed", "observed_at": "2026-10-07T01:00:00Z", "next_step": 0},
        ],
        "membership_changes": [
            {"id": "anon_id_1", "scope_id": 1, "member": "anon_login_1", "group": "anon_name_1", "privileged": True,
             "added": True, "observed_at": "2026-10-07T01:00:00Z"},
            {"id": "anon_id_2", "scope_id": 2, "member": "anon_login_2", "group": "anon_name_2", "privileged": True,
             "added": True, "observed_at": "2026-10-07T01:00:00Z"},
            {"id": "anon_id_3", "scope_id": 1, "member": "anon_login_3", "group": "anon_name_1", "privileged": True,
             "added": False, "observed_at": "2026-10-07T01:00:00Z"},
        ],
        "lockout_events": [
            {"id": "anon_id_11", "scope_id": 1, "account": "anon_login_1", "caller": "anon_host_1", "event_code": 4625,
             "observed_at": "2026-10-07T00:59:00Z"},
            {"id": "anon_id_12", "scope_id": 1, "account": "anon_login_1", "caller": "anon_host_1", "event_code": 4740,
             "observed_at": "2026-10-07T01:00:00Z", "raw_evidence": "[redacted]"},
            {"id": "anon_id_13", "scope_id": 1, "account": "anon_login_1", "caller": "anon_host_1", "event_code": 4767,
             "observed_at": "2026-10-07T01:01:00Z"},
            {"id": "anon_id_14", "scope_id": 1, "account": "anon_login_1", "caller": "anon_host_1", "event_code": 4740,
             "observed_at": "2026-10-07T01:02:00Z"},
        ],
        "sources": [{"id": "anon_id_21", "scope_id": 1, "read": 100, "delivered": 90, "imported": 80,
                     "processed": 70, "collection_running": True, "pending_read": 0}],
        "snapshots": [{"scope_id": 1, "observed_at": "2026-10-05T02:00:00Z", "state": "ok", "failed": 2, "not_evaluated": 3}],
    }


def scenario(kind, level="full", locale="en"):
    return next(r for r in s.catalog() if r["id"] == kind and r["access_level"] == level and r["locale"] == locale)


def transcript(spec, blocks, refusal=None):
    plan = s.public_plan(spec)
    records = []
    screen = "/app/"
    for index, step in enumerate([{"action": "goto", "target": plan["start_page"]}, *plan["route"]]):
        target = step.get("target", screen)
        records.append({"scenario_id": spec["run_id"], "locale": spec["locale"], "screen": screen,
                        "next_screen": target, "action": step["action"], "elapsed_ms": 100 * index,
                        "answer": {"blocks": blocks, "refusal": refusal} if step["action"] == "answer" else None})
        screen = target
    return records


def test_catalog_is_one_persona_with_six_scenarios_three_access_levels_and_two_locales():
    expanded = s.catalog()
    assert len(expanded) == len({r["run_id"] for r in expanded}) == 36
    assert {r["persona"] for r in expanded} == {"information_security_specialist"}
    assert {r["access_level"] for r in expanded} == {"full", "limited-scope", "no-raw-evidence"}
    for entry in expanded:
        plan = s.public_plan(entry)
        assert "expected_answer" not in plan and "claims" not in plan and "route_overrides" not in plan
        assert entry["expected_answer"]["hidden"] is True
        assert entry["start_page"] == "/app/"
        assert entry["fixed_time"] == "2026-10-07T02:00:00Z"
        assert entry["time_zone"] == "Asia/Bangkok"
        assert entry["data_snapshot_id"] == "synthetic_l06_2:v1"
        assert entry["goal"] and entry["completion_criteria"]
        assert len(entry["route"]) + 1 <= entry["max_steps"]


def test_morning_prioritizes_allowed_problems_and_distinguishes_visibility_from_threats(dataset):
    full = s.expected_answer(dataset, scenario("morning_decisions"))["answer"]
    limited = s.expected_answer(dataset, scenario("morning_decisions", "limited-scope"))["answer"]
    assert full == {"decision_ids": [2, 1], "observation": "partial", "status_message": "Requires a decision: 2. Observation: incomplete data."}
    assert limited == {"decision_ids": [1], "observation": "partial", "status_message": "Requires a decision: 1. Observation: incomplete data."}
    dataset["problems"] = []
    assert s.expected_answer(dataset, scenario("morning_decisions"))["answer"]["observation"] == "partial"


def test_top_five_is_computed_after_scope_before_limiting(dataset):
    dataset["problems"] += [{"id": i, "scope_id": 2, "severity": "critical", "state": "active",
                             "observed_at": "2026-10-07T01:00:00Z", "next_step": 0} for i in range(4, 20)]
    expected = s.expected_answer(dataset, scenario("morning_decisions", "limited-scope"))
    assert expected["answer"]["decision_ids"] == [1]
    assert len(s.expected_answer(dataset, scenario("morning_decisions"))["answer"]["decision_ids"]) == 5


def test_membership_window_excludes_boundary_future_removals_and_nonprivileged(dataset):
    base = dataset["membership_changes"][0]
    dataset["membership_changes"] += [{**base, "id": f"anon_id_{i}", **extra} for i, extra in enumerate([
        {"observed_at": "2026-10-06T02:00:00Z"}, {"observed_at": "2026-10-07T02:00:01Z"}, {"privileged": False}], 40)]
    expected = s.expected_answer(dataset, scenario("privileged_membership_24h", "limited-scope"))
    assert expected["answer"]["changes"] == [{"id": "anon_id_1", "member": "anon_login_1", "group": "anon_name_1",
                                               "observed_at": "2026-10-07T01:00:00Z"}]
    assert s.time_terms(base["observed_at"], scenario("privileged_membership_24h"))[1] == "07.10.26, 08:00:00"


def test_lockout_correlation_is_bounded_by_time_caller_and_account(dataset):
    base = dataset["lockout_events"][0]
    dataset["lockout_events"] += [{**base, "id": f"anon_id_{i}", **extra} for i, extra in enumerate([
        {"caller": "anon_host_2"}, {"account": "anon_login_2"}, {"observed_at": "2026-10-07T01:03:00Z"},
        {"observed_at": "2026-10-07T00:50:00Z"}], 50)]
    expected = s.expected_answer(dataset, scenario("account_lockout"))
    assert expected["answer"]["accounts"] == [{"account": "anon_login_1", "lockouts": 2, "preceding_failures": 1,
                                               "callers": ["anon_host_1"]}]
    assert expected["limitations"] == ["correlation"]
    assert expected["refusal"] is None


def test_no_raw_slice_does_not_mutate_dataset_and_changes_only_access_limitations(dataset):
    untouched = copy.deepcopy(dataset)
    spec = scenario("account_lockout", "no-raw-evidence")
    projected = s.allowed_slice(dataset, spec)
    assert "raw_evidence" not in projected["lockout_events"][1]
    expected = s.expected_answer(dataset, spec)
    assert expected["refusal"] == "raw_evidence_denied"
    assert expected["limitations"] == ["correlation", "raw"]
    assert expected["answer"] == s.expected_answer(dataset, scenario("account_lockout"))["answer"]
    assert dataset == untouched


@pytest.mark.parametrize("level,problem,step", [("full", 2, "visibility"), ("limited-scope", 1, "review"), ("no-raw-evidence", 2, "request")])
def test_problem_next_step_respects_access(dataset, level, problem, step):
    assert s.expected_answer(dataset, scenario("problem_next_step", level))["answer"] == {"problem_id": problem, "next_step": step}


def test_source_lag_is_four_independent_stages_not_event_age(dataset):
    spec = scenario("source_lag")
    answer = s.expected_answer(dataset, spec)["answer"]
    assert answer["sources"][0]["stages"] == {"collection": False, "delivery": True, "import": True, "processing": True}
    dataset["sources"][0].update(read=100, delivered=100, imported=100, processed=100, collection_running=False,
                                 last_event_at="2026-10-01T00:00:00Z")
    assert s.expected_answer(dataset, spec)["answer"]["sources"][0]["stages"] == {
        "collection": True, "delivery": False, "import": False, "processing": False}
    dataset["sources"][0]["delivered"] = 101
    expected = s.expected_answer(dataset, spec)
    assert expected["answer"]["sources"][0]["stages"] is None
    assert expected["limitations"] == ["lag_unknown"]


def test_stale_future_and_missing_ad_snapshot_are_not_current_safety(dataset):
    spec = scenario("stale_ad_snapshot")
    expected = s.expected_answer(dataset, spec)
    assert expected["answer"]["snapshots"][0]["state"] == "stale"
    assert expected["limitations"] == ["not_current", "stale"]
    dataset["snapshots"][0]["observed_at"] = "2026-10-07T02:00:01Z"
    assert s.expected_answer(dataset, spec)["limitations"] == ["not_current", "unknown"]
    dataset["snapshots"] = []
    assert s.expected_answer(dataset, spec)["limitations"] == ["not_current", "unknown"]


def test_metrics_success_correct_refusal_wrong_and_blocked(dataset):
    spec = scenario("problem_next_step", "limited-scope")
    records = transcript(spec, ["problem 1", "review evidence", "within the authorized scope"])
    result = s.metrics(dataset, spec, records)
    assert result["outcome"] == "success" and result["accuracy"] == 1
    assert result["steps"] == 4 and result["time_ms"] == 300 and result["backtracks"] == 0
    assert result["honest_limitations"] and not result["scope_leak"]
    records[-1]["answer"]["blocks"][0] = "problem 10"
    assert s.metrics(dataset, spec, records)["outcome"] == "wrong"
    assert s.metrics(dataset, spec, records)["accuracy"] == .5
    assert s.metrics(dataset, spec, records[:-1])["outcome"] == "blocked"
    spec = scenario("account_lockout", "no-raw-evidence")
    records = transcript(spec, ["anon_login_1 lockouts 2", "anon_login_1 failures 1", "anon_login_1 anon_host_1",
                                "raw evidence access denied", "does not prove cause"], "raw_evidence_denied")
    assert s.metrics(dataset, spec, records)["outcome"] == "correct_refusal"
    records[-1]["answer"]["refusal"] = None
    assert s.metrics(dataset, spec, records)["outcome"] == "wrong"


def test_correct_claim_does_not_hide_conflicting_count(dataset):
    spec = scenario("account_lockout", "no-raw-evidence")
    records = transcript(spec, ["anon_login_1 lockouts 2", "anon_login_1 failures 1", "anon_login_1 anon_host_1",
                                "raw evidence access denied", "does not prove cause", "anon_login_1 lockouts 10"], "raw_evidence_denied")
    result = s.metrics(dataset, spec, records)
    assert result["accuracy"] == 1
    assert result["outcome"] == "wrong"


@pytest.mark.parametrize("fault", ["scope_token", "scope_metadata", "hidden_problem", "raw", "dishonest", "contradiction", "timeout", "route", "missing"])
def test_violations_cannot_be_hidden_by_accuracy_or_partial_run(dataset, fault):
    spec = scenario("problem_next_step", "limited-scope")
    records = transcript(spec, ["problem 1", "review evidence", "within the authorized scope"])
    if fault == "scope_token":
        records[0]["text"] = "anon_login_2"
    elif fault == "scope_metadata":
        records[0]["observed_scopes"] = [2]
    elif fault == "hidden_problem":
        records[0]["observed_problem_ids"] = [2]
    elif fault == "raw":
        spec = scenario("problem_next_step", "no-raw-evidence")
        records = transcript(spec, ["problem 2", "request evidence", "raw evidence access denied"])
        records[0]["raw_evidence_observed"] = True
    elif fault == "dishonest":
        records[-1]["answer"]["blocks"].pop()
    elif fault == "contradiction":
        records[-1]["answer"]["blocks"].append("everything is fine")
    elif fault == "timeout":
        records[-1]["elapsed_ms"] = 90001
    elif fault == "route":
        records[1]["action"] = "goto"
    else:
        records = []
    result = s.metrics(dataset, spec, records)
    assert result["outcome"] == ("blocked" if fault in {"timeout", "route", "missing"} else "wrong")
    if fault in {"scope_token", "scope_metadata", "hidden_problem", "raw"}:
        assert result["accuracy"] == 1
        assert "scope_leak" in result["violations"]


def test_claims_require_one_block_and_token_boundaries():
    claim = s.claim("change", "anon_login_1", "anon_name_1")
    assert not s.claim_matches(claim, ["anon_login_1", "anon_name_1"])
    assert not s.claim_matches(claim, ["anon_login_10 anon_name_1"])
    assert s.claim_matches(claim, ["anon_login_1 → anon_name_1"])


def test_backtracks_use_path_transitions(dataset):
    spec = scenario("problem_next_step", "limited-scope")
    records = transcript(spec, ["problem 1", "review evidence", "within the authorized scope"])
    records[2].update(screen="/app/report/security.problems", next_screen="/app/")
    assert s.metrics(dataset, spec, records)["backtracks"] == 1


@pytest.mark.parametrize("field,category", [
    ("not_evaluated", None), ("notEvaluated", None),
    ("note", "free_text"), ("notes", "free_text"),
    ("audit_note", "free_text"), ("auditNote", "free_text"),
    ("raw_evidence", "free_text"), ("rawEvidence", "free_text"),
    ("user_name", "logins"), ("host_name", "hostnames"),
])
def test_passport_field_category_distinguishes_snapshot_counter_from_free_text(field, category):
    assert field_category(field) == category


def test_snapshot_binding_and_passport_accept_synthetic_scenario_schema(tmp_path, dataset):
    fields = ("display_name", "login", "email", "ip", "dn", "hostname", "sid", "description", "password")
    manifest = {"dataset_id": "synthetic_l06_2", "snapshot_version": "v1", "kind": "synthetic", "mapping_present": False,
                "transformed_fields": [{"category": category, "field": f"records.{field}", "method": "synthetic"}
                                       for category, field in zip(CATEGORIES, fields, strict=True)] +
                                      [{"category": "free_text", "field": "lockout_events.raw_evidence", "method": "redacted"}]}
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    (tmp_path / "scenario_data.json").write_text(json.dumps(dataset))
    spec = scenario("source_lag")
    passport = verify_dataset(tmp_path)
    assert passport["findings"] == {}
    assert passport["status"] == "pass"
    assert s.load_dataset(tmp_path, spec) == dataset
    manifest["snapshot_version"] = "v2"
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="snapshot_mismatch"):
        s.load_dataset(tmp_path, spec)


def node(script, payload):
    executable = shutil.which("node")
    assert executable, "node is required for the deterministic crawler tests"
    result = subprocess.run([executable, "-e", f"const runner = require({json.dumps(str(RUNNER))});\n" + script],
                            input=json.dumps(payload), text=True, capture_output=True, check=True)
    return json.loads(result.stdout)


def test_runner_on_fake_crawler_records_complete_path_without_oracle():
    plan = s.public_plan(scenario("problem_next_step", "limited-scope"))
    result = node("""
    const plan = JSON.parse(require('fs').readFileSync(0, 'utf8'));
    let screen = '/app/'; let tick = 0; const written = [];
    const driver = {
      currentScreen: () => screen, safeLink: () => true,
      goto: async (target) => { screen = target; },
      describe: async (step) => step.action === 'link' ? {visible:true, target:'/app/report/security.problems'} :
        {tag:'TR', clickable:true, inTable:true},
      click: async () => { screen = '/app/report/security.problems'; },
      observe: async () => ({blocks:['problem 1', 'review evidence', 'within the authorized scope']}),
      write: async (record) => written.push(record),
    };
    runner.runScenario(plan, driver, () => tick++).then(result => process.stdout.write(JSON.stringify({result, written})));
    """, plan)
    assert result["result"]["completed"]
    assert result["result"]["records"] == result["written"]
    assert [r["action"] for r in result["written"]] == ["goto", "link", "row", "answer"]
    assert result["written"][1]["screen"] == "/app/"
    assert result["written"][1]["next_screen"] == "/app/report/security.problems"
    assert result["written"][-1]["answer"] == {"blocks": ["problem 1", "review evidence", "within the authorized scope"], "refusal": None}


@pytest.mark.parametrize("fault", ["foreign_target", "mutation", "oracle", "budget"])
def test_runner_rejects_invalid_plans_before_driver(fault):
    plan = s.public_plan(scenario("source_lag"))
    if fault == "foreign_target":
        plan["route"][0]["target"] = "/app/../../api/write"
    elif fault == "mutation":
        plan["route"][0]["action"] = "save"
    elif fault == "oracle":
        plan["expected_answer"] = {"answer": "hidden"}
    else:
        plan["max_steps"] = 1
    assert node("""
    const plan = JSON.parse(require('fs').readFileSync(0, 'utf8'));
    let rejected = false; try { runner.validatePlan(plan); } catch { rejected = true; }
    process.stdout.write(JSON.stringify(rejected));
    """, plan)


def test_runner_whitelist_blocks_mutating_element_and_budget_exhaustion():
    plan = s.public_plan(scenario("problem_next_step"))
    result = node("""
    const plan = JSON.parse(require('fs').readFileSync(0, 'utf8'));
    let tick = 0; let clicks = 0;
    const driver = {currentScreen:()=>'/app/', safeLink:()=>false, goto:async()=>{},
      describe:async()=>({visible:true,target:'/api/write'}), click:async()=>clicks++,
      observe:async()=>({blocks:[]}), write:async()=>{}};
    (async () => {
      const invalid = await runner.runScenario(plan, driver, () => tick++);
      tick = 0;
      const timeout = await runner.runScenario(plan, driver, () => (tick++) * 90001);
      process.stdout.write(JSON.stringify({invalid, timeout, clicks}));
    })();
    """, plan)
    assert result["clicks"] == 0
    assert not result["invalid"]["completed"] and result["invalid"]["records"][-1]["blocked"]
    assert result["timeout"]["records"][0]["error"] == "scenario_budget_exceeded"


def test_network_metadata_detects_nested_scope_and_raw_leaks():
    assert node("""
    const data = JSON.parse(require('fs').readFileSync(0, 'utf8'));
    process.stdout.write(JSON.stringify(runner.observationMetadata(data)));
    """, {"items": [{"domain_id": 2, "collection_scope_ids": ["ad-domain:1"], "account": "anon_login_2", "raw_xml": "[redacted]"}]}) == {
        "observed_scopes": [1, 2], "raw_evidence_observed": True, "observed_tokens": ["anon_login_2"], "observed_problem_ids": []}


def test_cli_plan_hides_oracle_and_score_binds_dataset_and_full_transcript(tmp_path, dataset, monkeypatch, capsys):
    candidate = tmp_path / "dataset"
    candidate.mkdir()
    (candidate / "manifest.json").write_text(json.dumps({"dataset_id": "synthetic_l06_2", "snapshot_version": "v1"}))
    (candidate / "scenario_data.json").write_text(json.dumps(dataset))
    out = tmp_path / "artifacts"
    out.mkdir()
    monkeypatch.setenv("SLI_AUDIT_DATASET", str(candidate))
    admission = {"access_level": "limited", "dataset_sha256": "synthetic_digest", "accounts_sha256": "synthetic_accounts"}
    monkeypatch.setattr(s, "validate_gate", lambda *args: admission)
    args = ["scenario", "plan", "--scenario", "problem_next_step", "--locale", "en", "--base", "http://127.0.0.1:18086", "--out", str(out)]
    monkeypatch.setattr("sys.argv", args)
    assert s.main() == 0
    plan = json.loads(capsys.readouterr().out)
    assert "expected_answer" not in plan and "claims" not in plan
    assert "synthetic_digest" not in json.dumps(plan)
    spec = scenario("problem_next_step", "limited-scope")
    records = transcript(spec, ["problem 1", "review evidence", "within the authorized scope"])
    for r in records:
        r.update(fixed_time=spec["fixed_time"], time_zone=spec["time_zone"], data_snapshot_id=spec["data_snapshot_id"])
    evidence = out / "evidence.jsonl"
    evidence.write_text("".join(json.dumps(r) + "\n" for r in records))
    run = {**admission, "status": "completed", "scenario_id": spec["run_id"],
           "evidence_sha256": hashlib.sha256(evidence.read_bytes()).hexdigest()}
    (out / "run.json").write_text(json.dumps(run))
    args[1] = "score"
    assert s.main() == 0
    assert json.loads((out / "metrics.json").read_text())["outcome"] == "success"
    run["dataset_sha256"] = "changed_digest"
    (out / "run.json").write_text(json.dumps(run))
    assert s.main() == 2
    assert json.loads((out / "metrics.json").read_text())["outcome"] == "blocked"
    evidence.write_text(evidence.read_text() + "{}\n")
    (out / "run.json").write_text(json.dumps({**run, "dataset_sha256": "synthetic_digest"}))
    assert s.main() == 2

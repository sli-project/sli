from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.dev.ui_audit import model_review as review
from scripts.dev.ui_audit import scenarios
from scripts.dev.ui_audit.model_adapter import FakeModel, OperatorModel

ROOT = Path(__file__).resolve().parents[2]
WALKER = ROOT / "scripts/dev/ui_audit/model_walker.cjs"


@pytest.fixture
def spec():
    return next(s for s in scenarios.catalog() if s["id"] == "problem_next_step" and s["access_level"] == "full" and s["locale"] == "en")


@pytest.fixture
def dataset():
    return {"problems": [{"id": 1, "scope_id": 1, "severity": "high", "state": "active",
                          "observed_at": "2026-10-07T01:00:00Z", "next_step": 0}],
            "membership_changes": [], "lockout_events": [], "sources": [], "snapshots": []}


@pytest.fixture
def records(spec):
    # A valid discovered path intentionally differs from the fixed L06-2 route.
    return [{"id": str(i), "scenario_id": spec["run_id"], "locale": spec["locale"],
             "fixed_time": spec["fixed_time"], "time_zone": spec["time_zone"], "data_snapshot_id": spec["data_snapshot_id"],
             "screen": "/app/", "next_screen": "/app/", "action": action, "elapsed_ms": 100 * i,
             "observation": {"blocks": ["problem 1; review evidence"]},
             "answer": {"blocks": ["problem 1; review evidence"], "refusal": None} if action == "answer" else None}
            for i, action in enumerate(("goto", "answer"))]


def rating(scores=None, violations=None, findings=None):
    return {"scores": {d: 4 for d in review.DIMENSIONS} if scores is None else scores,
            "reasons": {d: "Supported by the visible evidence." for d in review.DIMENSIONS},
            "violations": violations or [], "findings": findings or []}


def node(code, payload):
    executable = shutil.which("node")
    assert executable, "node is required for fake-model controller tests"
    script = f"const walker = require({json.dumps(str(WALKER))});\n" + code
    result = subprocess.run([executable, "-e", script], input=json.dumps(payload), text=True, capture_output=True, check=True, timeout=10)
    return json.loads(result.stdout)


DRIVER = """
const plan = JSON.parse(require('fs').readFileSync(0, 'utf8'));
let screen = '/app/'; let clicks = 0; const written = [];
const driver = {
  currentScreen: () => screen, safeLink: (target) => target.startsWith('/app/'),
  goto: async (target) => { screen = target; },
  offerActions: async () => [
    {action:'save', index:0},
    {action:'link', selector:'a[href]', index:0, label:'Read problem'},
    {action:'link', selector:'a[href]', index:1, label:'Forbidden'},
    {action:'row', index:0, label:'Inactive row'},
  ],
  describe: async (step) => step.action === 'row' ? {visible:true,tag:'TR',clickable:false,inTable:true} :
    {visible:true,target:step.index === 1 ? '/app/../../api/write' : '/app/report/security.problems'},
  click: async () => { clicks++; screen = '/app/report/security.problems'; },
  observe: async () => ({blocks:['problem 1; review evidence']}),
  write: async (record) => written.push(JSON.parse(JSON.stringify(record))),
};
"""


def test_fake_walker_receives_only_goal_screen_and_offered_actions_and_records_full_path(spec):
    result = node(DRIVER + """
    const model = new walker.FakeModel([{action_id:'a0'}, {action_id:'answer',answer:{blocks:['problem 1; review evidence'],refusal:null}}]);
    walker.runModelScenario(plan, driver, model).then(result => process.stdout.write(JSON.stringify({result,written,clicks,requests:model.requests})));
    """, scenarios.public_plan(spec))
    assert result["result"]["completed"]
    assert result["result"]["model_calls"] == 2
    assert result["clicks"] == 1
    assert result["result"]["records"] == result["written"]
    assert [r["action"] for r in result["written"]] == ["goto", "link", "answer"]
    assert [a["action"] for a in result["requests"][0]["actions"]] == ["link", "answer"]
    assert result["requests"][1]["screen"]["url"] == "/app/report/security.problems"
    assert result["requests"][0]["goal"] == spec["goal"]
    assert not {"route", "expected_answer", "claims", "dataset", "completion_criteria"} & result["requests"][0].keys()
    assert result["written"][-1]["answer"]["blocks"] == ["problem 1; review evidence"]


@pytest.mark.parametrize("decision", [
    {"action_id": "save"}, {"action_id": "a99"}, {"action_id": "a0", "target": "/api/write"},
    {"action_id": "answer", "answer": {"blocks": [], "refusal": None}},
])
def test_walker_rejects_unoffered_actions_and_model_supplied_targets(spec, decision):
    result = node(DRIVER + f"""
    const model = new walker.FakeModel([{json.dumps(decision)}]);
    walker.runModelScenario(plan, driver, model).then(result => process.stdout.write(JSON.stringify({{result,clicks,written}})));
    """, scenarios.public_plan(spec))
    assert not result["result"]["completed"]
    assert result["clicks"] == 0
    assert result["written"][-1]["blocked"]


def test_walker_rechecks_dom_before_execution(spec):
    result = node(DRIVER + """
    const model = {choose:async()=> {driver.describe=async()=>({visible:true,target:'/api/write'});return {action_id:'a0'};}};
    walker.runModelScenario(plan, driver, model).then(result => process.stdout.write(JSON.stringify({result,clicks})));
    """, scenarios.public_plan(spec))
    assert result["clicks"] == 0
    assert result["result"]["records"][-1]["error"] == "walker_action_rejected"


def test_walker_step_and_wall_time_limits_cover_stalled_models(spec):
    plan = scenarios.public_plan(spec)
    plan.update(max_steps=4, max_seconds=.02)
    result = node(DRIVER + """
    (async()=>{
      const model=new walker.FakeModel([{action_id:'a0'}, {action_id:'a0'}, {action_id:'a0'}]);
      const steps=await walker.runModelScenario({...plan,max_seconds:1},driver,model);
      const stalled=await walker.runModelScenario(plan,driver,{choose:()=>new Promise(()=>{})});
      process.stdout.write(JSON.stringify({steps,stalled,written}));
    })();
    """, plan)
    assert len(result["steps"]["records"]) == 4
    assert result["steps"]["records"][-1]["error"] == "walker_step_limit"
    assert result["written"][3]["error"] == "walker_step_limit"
    assert result["stalled"]["records"][-1]["error"] == "walker_time_limit"


def test_model_metrics_allow_discovered_path_but_require_observed_support(dataset, spec, records):
    assert scenarios.metrics(dataset, spec, records)["outcome"] == "blocked"
    assert scenarios.metrics(dataset, spec, records, mode="model")["outcome"] == "success"
    for record in records:
        record["observation"]["blocks"] = []
    result = scenarios.metrics(dataset, spec, records, mode="model")
    assert result["accuracy"] == 1
    assert result["evidence_accuracy"] == 0
    assert result["outcome"] == "wrong"


@pytest.mark.parametrize("fault,code", [("wrong", "wrong_answer"), ("scope", "scope_leak"),
                                      ("safe_en", "false_all_good"), ("safe_ru", "false_all_good")])
def test_mandatory_violations_survive_perfect_rubric_scores(dataset, spec, records, fault, code):
    if fault == "wrong":
        records[-1]["answer"]["blocks"] = ["problem 2; review evidence"]
    elif fault == "scope":
        spec.update(account="limited", access_level="limited-scope")
        records[0]["observed_scopes"] = [2]
        records[-1]["answer"]["blocks"].append("within the authorized scope")
    else:
        records[-1]["answer"]["blocks"].append("everything is fine" if fault == "safe_en" else "всё хорошо")
    result = review.evaluate(dataset, spec, records, FakeModel([rating()]))
    assert result["rubric"]["scores"]["trust"] == 4
    assert code in result["mandatory_violations"]
    assert not result["accepted"]


def test_separate_evaluator_receives_private_oracle_and_rubric(dataset, spec, records):
    model = FakeModel([rating()])
    result = review.evaluate(dataset, spec, records, model)
    assert result["accepted"]
    request = model.requests[0]
    assert request["role"] == "evaluator"
    assert request["request"]["expected_answer"] == scenarios.expected_answer(dataset, spec)
    assert set(request["request"]["rubric"]) == set(review.DIMENSIONS)
    assert request["timeout_seconds"] == spec["max_seconds"]


def test_low_dimension_cannot_be_averaged_away(dataset, spec, records):
    response = rating()
    response["scores"]["trust"] = 0
    result = review.evaluate(dataset, spec, records, FakeModel([response]))
    assert result["deterministic"]["outcome"] == "success"
    assert not result["rubric_sufficient"]
    assert not result["accepted"]


def test_time_limit_includes_evidence_recording(dataset, spec, records):
    result = review.evaluate(dataset, spec, records, FakeModel([rating()]), spec["max_seconds"] * 1000 + 1)
    assert result["deterministic"]["time_ms"] == spec["max_seconds"] * 1000 + 1
    assert result["deterministic"]["outcome"] == "blocked"
    assert not result["accepted"]


@pytest.mark.parametrize("fault", ["missing_dimension", "bool", "out_of_range", "unanchored", "exhausted"])
def test_evaluator_errors_are_not_silent_success(dataset, spec, records, fault):
    response = rating()
    if fault == "missing_dimension":
        response["scores"].pop("trust")
    elif fault == "bool":
        response["scores"]["trust"] = True
    elif fault == "out_of_range":
        response["scores"]["trust"] = 5
    elif fault == "unanchored":
        response["findings"] = [{"dimension": "clarity", "evidence_id": "0", "quote": "not visible", "message": "Unclear."}]
    result = review.evaluate(dataset, spec, records, FakeModel([] if fault == "exhausted" else [response]))
    assert result["evaluation_status"] == "infra_failure"
    assert not result["accepted"]


def test_top_ten_is_prioritized_and_only_confirmed_findings_get_unpublished_drafts():
    results, records = [], []
    for index in range(12):
        ident = f"synthetic_scenario_{index:02d}"
        results.append({"scenario_id": ident, "deterministic": {"violations": ["wrong_answer"]}, "rubric": None})
        records.append({"id": str(index), "scenario_id": ident, "answer": {"blocks": ["Observed wrong answer."]}})
    results[-1]["deterministic"]["violations"].append("scope_leak")
    results[0]["rubric"] = rating(findings=[{"dimension": "clarity", "evidence_id": "0", "quote": "Observed", "message": "Unclear."}])
    report = review.findings(results, records)
    assert len(report["top_10"]) == 10
    assert report["confirmed_count"] == 13
    assert report["top_10"][0]["kind"] == "scope_leak"
    assert all(not f["task_draft"]["published"] and f["evidence_ids"] for f in report["top_10"])
    assert report["candidates"][0]["status"] == "needs_confirmation"
    assert report["publication_status"] == "not_published"


def test_calibration_checks_every_dimension_and_exact_mandatory_violations():
    spec = json.loads(review.CALIBRATION.read_text(encoding="utf-8"))
    responses = [rating(scores=c["scores"], violations=c["violations"]) for c in spec["cases"]]
    model = FakeModel(responses)
    assert review.calibrate(model)["passed"]
    assert len(model.requests) == 6
    responses[1]["violations"] = []
    result = review.calibrate(FakeModel(responses))
    assert not result["passed"]
    assert not result["results"][1]["passed"]
    assert set().union(*(set(c["violations"]) for c in spec["cases"])) == review.MANDATORY


def save_run(out, spec, records):
    out.mkdir(exist_ok=True)
    raw = "".join(json.dumps(r) + "\n" for r in records).encode()
    (out / "evidence.jsonl").write_bytes(raw)
    run = {"mode": "model", "status": "completed", "model_status": "walker_finished", "states": len(records),
           "scenario_id": spec["run_id"], "evidence_sha256": hashlib.sha256(raw).hexdigest(), "dataset_sha256": "synthetic_digest"}
    (out / "run.json").write_text(json.dumps(run))
    return run


def test_all_five_outputs_are_bound_to_transcript_and_evaluator_failure_is_recorded(tmp_path, dataset, spec, records):
    run = save_run(tmp_path, spec, records)
    result = review.score_run(tmp_path, {"dataset_sha256": "synthetic_digest"}, spec, dataset, FakeModel([rating()]))
    assert result["accepted"]
    assert {p.name for p in tmp_path.iterdir()} == {"run.json", "evidence.jsonl", "scenario_results.json", "findings.json", "review.md"}
    final = json.loads((tmp_path / "run.json").read_text())
    assert final["model_status"] == "completed" and final["accepted"]
    assert final["evidence_sha256"] == run["evidence_sha256"]
    assert "consolidation/codex-l06b" in (tmp_path / "review.md").read_text()
    save_run(tmp_path, spec, records)
    review.score_run(tmp_path, {"dataset_sha256": "synthetic_digest"}, spec, dataset, FakeModel([]))
    assert json.loads((tmp_path / "run.json").read_text())["status"] == "infra_failure"
    assert not json.loads((tmp_path / "scenario_results.json").read_text())["results"][0]["accepted"]


@pytest.mark.parametrize("fault", ["hash", "snapshot", "persona", "states", "mode", "symlink"])
def test_score_rejects_unbound_runs_before_model_invocation(tmp_path, dataset, spec, records, fault):
    run = save_run(tmp_path, spec, records)
    if fault == "hash":
        (tmp_path / "evidence.jsonl").write_text("{}\n")
    elif fault == "snapshot":
        records[0]["data_snapshot_id"] = "synthetic_changed:v2"
        run = save_run(tmp_path, spec, records)
    elif fault == "persona":
        run["dataset_sha256"] = "different_digest"
    elif fault == "states":
        run["states"] += 1
    elif fault == "mode":
        run["mode"] = "deterministic"
    else:
        target = tmp_path / "elsewhere"
        target.write_text("{}")
        (tmp_path / "run.json").unlink()
        (tmp_path / "run.json").symlink_to(target)
    if fault != "symlink":
        (tmp_path / "run.json").write_text(json.dumps(run))
    model = FakeModel([rating()])
    with pytest.raises(ValueError):
        review.score_run(tmp_path, {"dataset_sha256": "synthetic_digest"}, spec, dataset, model)
    assert not model.requests
    if fault != "symlink":
        assert json.loads((tmp_path / "run.json").read_text())["accepted"] is False
        assert json.loads((tmp_path / "scenario_results.json").read_text())["results"] == []


@pytest.mark.parametrize("fault", ["passport", "runtime", "configuration"])
def test_cli_requires_passport_and_isolated_runtime_before_model(tmp_path, monkeypatch, capsys, fault):
    calls = []
    def gate(*args):
        calls.append("gate")
        if fault == "passport":
            raise ValueError("dataset_passport_rejected")
        return {"dataset_sha256": "synthetic_digest"}
    def runtime(*args):
        calls.append("runtime")
        if fault == "runtime":
            raise ValueError("isolated_runtime_required")
    monkeypatch.setattr(review, "validate_gate", gate)
    monkeypatch.setattr(review, "require_runtime", runtime)
    monkeypatch.delenv("SLI_AUDIT_WALKER_COMMAND", raising=False)
    monkeypatch.delenv("SLI_AUDIT_EVALUATOR_COMMAND", raising=False)
    monkeypatch.setattr(sys, "argv", ["review", "configure", "--base", "http://127.0.0.1:18086", "--out", str(tmp_path)])
    assert review.main() == 2
    assert calls == (["gate"] if fault == "passport" else ["gate", "runtime"])
    assert json.loads(capsys.readouterr().out)["status"] == "blocked"
    assert not list(tmp_path.iterdir())


def test_operator_adapter_uses_external_json_protocol_and_sanitizes_failure(tmp_path):
    script = tmp_path / "synthetic_adapter.py"
    script.write_text("import json, sys\nr=json.load(sys.stdin)\nprint(json.dumps({'role':r['role'],'goal':r['goal']}))\n")
    command = json.dumps([sys.executable, str(script)])
    model = OperatorModel({"SLI_AUDIT_WALKER_COMMAND": command, "SLI_AUDIT_EVALUATOR_COMMAND": command})
    assert model.invoke("evaluator", {"goal": "Synthetic goal."}, 3) == {"role": "evaluator", "goal": "Synthetic goal."}
    script.write_text("import sys\nsys.stderr.write('synthetic private failure')\nsys.exit(1)\n")
    with pytest.raises(RuntimeError, match="^model_adapter_failed$"):
        model.invoke("evaluator", {}, 3)
    script.write_text("import time\ntime.sleep(2)\n")
    with pytest.raises(RuntimeError, match="^model_adapter_failed$"):
        model.invoke("evaluator", {}, .02)


def test_node_operator_adapter_times_out_and_sanitizes_failure():
    result = node("""
    const command=JSON.stringify([process.execPath,'-e','setTimeout(()=>{},2000)']);
    const model=walker.operatorModel({SLI_AUDIT_WALKER_COMMAND:command});
    model.choose({goal:'Synthetic goal'},20).then(()=>process.stdout.write('false')).catch(e=>process.stdout.write(JSON.stringify(e.message)));
    """, {})
    assert result == "walker_adapter_failed"


def test_aggregate_preserves_separate_paths_and_rejects_tampered_scores(tmp_path, dataset, spec, records):
    candidate = tmp_path / "dataset"
    candidate.mkdir()
    (candidate / "manifest.json").write_text(json.dumps({"dataset_id": "synthetic_l06_2", "snapshot_version": "v1"}))
    (candidate / "scenario_data.json").write_text(json.dumps(dataset))
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    admission = {"dataset_sha256": "synthetic_digest", "access_level": "full"}
    paths = []
    for index in range(2):
        path = artifacts / str(index)
        run = save_run(path, spec, records)
        run.update(admission)
        (path / "run.json").write_text(json.dumps(run))
        review.score_run(path, admission, spec, dataset, FakeModel([rating()]))
        paths.append(path)
    out = artifacts / "combined"
    env = {"SLI_AUDIT_ARTIFACTS": str(artifacts), "SLI_AUDIT_DATASET": str(candidate)}
    result = review.aggregate_runs(out, paths, admission, env)
    assert result["accepted"] and result["source_runs"] == 2
    combined = [json.loads(line) for line in (out / "evidence.jsonl").read_text().splitlines()]
    assert len(combined) == len({r["id"] for r in combined}) == 4
    assert {r["scenario_id"] for r in combined} == {f"{i}:{spec['run_id']}" for i in range(2)}
    assert {r["source_evidence_id"] for r in combined} == {"0", "1"}
    (paths[0] / "scenario_results.json").write_text('{"results":[]}')
    with pytest.raises(ValueError, match="model_aggregate_run_mismatch"):
        review.aggregate_runs(out, paths, admission, env)


def test_false_all_good_on_screen_and_scope_in_answer_are_mandatory(dataset, spec, records):
    records[0]["observation"]["blocks"].append("всё хорошо")
    assert "false_all_good" in scenarios.metrics(dataset, spec, records, mode="model")["violations"]
    records[0]["observation"]["blocks"].pop()
    spec.update(account="limited", access_level="limited-scope")
    dataset["problems"].append({**dataset["problems"][0], "id": 2, "scope_id": 2})
    records[-1]["answer"]["blocks"].append("problem 2")
    assert "scope_leak" in scenarios.metrics(dataset, spec, records, mode="model")["violations"]

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "scripts/dev/ui_audit/policy.cjs"


def evaluate(expression, setup=""):
    node = shutil.which("node")
    assert node, "node is required for L06 policy unit tests"
    result = subprocess.run([node, "-e", f"const policy = require({json.dumps(str(POLICY))});\n{setup}\n"
                             f"process.stdout.write(JSON.stringify({expression}));"],
                            capture_output=True, text=True, check=True)
    return json.loads(result.stdout)


@pytest.mark.parametrize("kind,element,allowed", [
    ("tab", {"role": "tab"}, True), ("tab", {"role": "button", "label": "View"}, False),
    ("tab", {"role": "tab", "disabled": True}, False),
    ("row", {"tag": "TR", "clickable": True, "inTable": True}, True),
    ("row", {"tag": "TR", "clickable": True, "inTable": False}, False),
    ("row", {"tag": "TR", "inTable": True}, False),
    ("close", {"dialogOpen": True}, True), ("close", {}, False),
    ("save", {"label": "Read"}, False), ("unknown", {"role": "tab"}, False),
])
def test_explicit_action_whitelist(kind, element, allowed):
    assert evaluate(f"policy.allowAction({json.dumps(kind)}, {json.dumps(element)})") is allowed


@pytest.mark.parametrize("url,method,login,redirected,allowed", [
    ("http://127.0.0.1:18086/api/read", "GET", False, False, True),
    ("http://127.0.0.1:18086/app/", "HEAD", False, False, True),
    ("http://127.0.0.1:18086/app/", "GET", False, True, False),
    ("https://external.example.test/api/read", "GET", False, False, False),
    ("http://127.0.0.1:18087/api/read", "GET", False, False, False),
    ("http://127.0.0.1:18086/api/read", "POST", False, False, False),
    ("http://127.0.0.1:18086/api/read", "PUT", False, False, False),
    ("http://127.0.0.1:18086/api/read", "PATCH", False, False, False),
    ("http://127.0.0.1:18086/api/read", "DELETE", False, False, False),
    ("http://127.0.0.1:18086/api/read", "OPTIONS", False, False, False),
    ("http://127.0.0.1:18086/api/auth/login", "POST", True, False, True),
    ("http://127.0.0.1:18086/api/auth/login", "POST", False, False, False),
    ("http://127.0.0.1:18086/api/auth/login", "POST", True, True, False),
    ("http://127.0.0.1:18086/api/auth/login?next=write", "POST", True, False, False),
    ("http://127.0.0.1:18086/api/auth/%6cogin", "POST", True, False, False),
    ("http://127.0.0.1:18086/api/auth/logout", "POST", True, False, False),
    ("file:///tmp/synthetic", "GET", False, False, False),
    ("ws://127.0.0.1:18086/socket", "GET", False, False, False),
    ("http://synthetic@127.0.0.1:18086/app/", "GET", False, False, False),
])
def test_network_guard(url, method, login, redirected, allowed):
    args = [url, method, "http://127.0.0.1:18086", login, redirected]
    assert evaluate(f"policy.allowRequest(...{json.dumps(args)}).allowed") is allowed


@pytest.mark.parametrize("state,status", [
    ({}, "not_run"), ({"blocked": True}, "blocked"), ({"started": True}, "completed"),
    ({"started": True, "failures": 1}, "infra_failure"),
    ({"started": True, "remaining": 1}, "blocked"),
    ({"started": True, "blocked": True, "failures": 1}, "blocked"),
])
def test_completion_never_treats_partial_or_failed_run_as_completed(state, status):
    assert evaluate(f"policy.completionStatus({json.dumps(state)})") == status


def access(level):
    spec = json.loads((ROOT / "scripts/dev/ui_audit/access_levels.json").read_text())
    account = spec["accounts"][level]
    value = {"subject": {"coarse_role": "viewer", "username": account["username"]}, "platform_owner": False,
             "capabilities": ["workspace.view", "reports.catalog", "field.security"],
             "reports": [{"allowed": True, "grants": [{"allowed_actions": ["view"],
                           "field_categories": ["security"], "scope": account["scope"]}]}]}
    if "raw_evidence" in account["field_classes"]:
        value["capabilities"].append("field.raw_evidence")
        value["resource_bound_capabilities"] = ["evidence.exact"]
        value["capability_policies"] = [{"effect": "allow", "capability_key": "evidence.exact", "scope": account["scope"]}]
    return value, account


@pytest.mark.parametrize("level", ["full", "limited", "without_raw_evidence"])
def test_live_effective_access_accepts_only_read_only_selected_variant(level):
    value, account = access(level)
    assert evaluate(f"policy.allowAccess({json.dumps(value)}, {json.dumps(account)})") is True


@pytest.mark.parametrize("fault", ["admin", "owner", "capability", "action", "field", "global_scope", "other_domain", "raw_capability", "other_user", "global_data_capability", "global_data_policy"])
def test_live_access_gate_rejects_writes_or_scope_and_field_leaks(fault):
    level = "without_raw_evidence" if fault in {"field", "raw_capability"} else "limited"
    value, account = access(level)
    grant = value["reports"][0]["grants"][0]
    if fault == "admin":
        value["subject"]["coarse_role"] = "admin"
    elif fault == "owner":
        value["platform_owner"] = True
    elif fault == "capability":
        value["capabilities"].append("tasks.create")
    elif fault == "action":
        grant["allowed_actions"].append("create_task")
    elif fault == "field":
        grant["field_categories"].append("raw_evidence")
    elif fault == "global_scope":
        grant["scope"] = {"kind": "all"}
    elif fault == "other_domain":
        grant["scope"] = {"mode": "restricted", "clauses": [{"collection_scope_ids": ["ad-domain:2"]}]}
    elif fault == "raw_capability":
        value["capabilities"].append("evidence.exact")
    elif fault == "global_data_capability":
        value["capabilities"].append("events.view")
    elif fault == "global_data_policy":
        value["capability_policies"] = [{"effect": "allow", "capability_key": "events.view", "scope": {"kind": "all"}}]
    else:
        value["subject"]["username"] = "audit_full"
    assert evaluate(f"policy.allowAccess({json.dumps(value)}, {json.dumps(account)})") is False


@pytest.mark.parametrize("entrypoint", ["crawler", "reviewer"])
def test_missing_passport_blocks_before_browser_or_model(tmp_path, entrypoint):
    env = {key: value for key, value in os.environ.items() if not key.startswith("SLI_AUDIT_")}
    env["SLI_AUDIT_PYTHON"] = os.environ.get("SLI_TEST_PYTHON", sys.executable)
    env["SLI_AUDIT_PROJECT"] = "sli-audit-l06"
    env["SLI_AUDIT_ORIGIN"] = "http://127.0.0.1:18086"
    env["SLI_AUDIT_ARTIFACTS"] = str(tmp_path)
    env["SLI_AUDIT_DATASET"] = str(tmp_path / "missing")
    env["SLI_AUDIT_PASSPORT"] = str(tmp_path / "missing-passport.json")
    if entrypoint == "crawler":
        command = [shutil.which("node"), str(ROOT / "scripts/dev/ui_audit/crawl.cjs"), env["SLI_AUDIT_ORIGIN"], str(tmp_path / "run"), "ru"]
    else:
        command = ["bash", str(ROOT / "scripts/dev/ui_audit/run_review.sh"), str(tmp_path / "run")]
    result = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True)
    assert result.returncode == 2
    assert "blocked" in result.stdout + result.stderr
    assert "Playwright" not in result.stdout + result.stderr
    assert not (tmp_path / "run").exists()

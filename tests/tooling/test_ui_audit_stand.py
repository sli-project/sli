from __future__ import annotations

import copy
import hashlib
import json
import subprocess
from pathlib import Path

import pytest
import yaml

from scripts.dev.ui_audit import stand


@pytest.mark.parametrize("project", ["sli", "sli-dev", "sli-linux-stand", "production", "SLI", "", "sli-audit-../sli"])
def test_refuses_production_or_non_audit_project(project):
    with pytest.raises(ValueError, match="isolated_audit_project_required"):
        stand.require_project(project)


def test_accepts_separate_audit_project():
    assert stand.require_project("sli-audit-l06") == "sli-audit-l06"


def test_artifacts_cannot_be_inside_checkout_or_primary_checkout(tmp_path, monkeypatch):
    root = tmp_path / "source" / ".claude" / "worktrees" / "audit"
    root.mkdir(parents=True)
    gitdir = tmp_path / "source" / ".git" / "worktrees" / "audit"
    gitdir.mkdir(parents=True)
    (root / ".git").write_text(f"gitdir: {gitdir.as_posix()}\n")
    (gitdir / "commondir").write_text("../..\n")
    monkeypatch.setattr(stand, "ROOT", root)
    for folder in (root / "artifacts", tmp_path / "source" / "artifacts"):
        with pytest.raises(ValueError, match="outside_checkouts"):
            stand.require_external_path(folder)
    assert stand.require_external_path(tmp_path / "external") == tmp_path / "external"


def test_gate_requires_passing_passport_before_any_runtime_call(tmp_path, monkeypatch):
    env = {"SLI_AUDIT_PROJECT": "sli-audit-l06", "SLI_AUDIT_ORIGIN": "http://127.0.0.1:18086",
           "SLI_AUDIT_ARTIFACTS": str(tmp_path), "SLI_AUDIT_DATASET": str(tmp_path / "missing"),
           "SLI_AUDIT_PASSPORT": str(tmp_path / "missing-passport.json"), "SLI_AUDIT_USER": "audit_full",
           "SLI_AUDIT_ACCESS_LEVEL": "full"}
    with pytest.raises((OSError, ValueError)):
        stand.validate_gate(env["SLI_AUDIT_ORIGIN"], tmp_path / "run", env)


def test_seed_image_is_immutable_and_bound_to_dataset_and_access_policy():
    admission = {"dataset_sha256": "dataset", "accounts_sha256": "accounts"}
    seed = "audit-seed@sha256:" + "a" * 64
    inspect = lambda _: {"sli.audit.dataset.sha256": "dataset", "sli.audit.accounts.sha256": "accounts"}
    stand.seed_admission(seed, admission, inspect)
    with pytest.raises(ValueError, match="immutable"):
        stand.seed_admission("audit-seed:latest", admission, inspect)
    with pytest.raises(ValueError, match="mismatch"):
        stand.seed_admission(seed, {**admission, "dataset_sha256": "changed"}, inspect)


def runtime():
    admission = {"project": "sli-audit-l06", "origin": "http://127.0.0.1:18086"}
    env = {"SLI_AUDIT_SEED_IMAGE": "seed", "SLI_AUDIT_APP_IMAGE": "app"}
    containers = [{"Config": {"Image": image, "Labels": {"com.docker.compose.project": admission["project"],
                    "com.docker.compose.service": service}}, "State": {"Running": True},
                   "NetworkSettings": {"Networks": {"sli-audit-l06_audit": {}}, "Ports": ports}}
                  for service, image, ports in (("api", "app", {"8443/tcp": [{"HostIp": "127.0.0.1", "HostPort": "18086"}]}),
                                                ("postgres", "seed", {}))]
    containers[0]["Config"]["Env"] = [f"{key}={value}" for key, value in stand.DISABLED_JOBS.items()]
    return containers, admission, env


@pytest.mark.parametrize("fault", ["project", "network", "worker", "listener", "image", "stopped", "missing", "outbound", "volume"])
def test_runtime_gate_checks_project_isolation_and_actual_listener(fault):
    containers, admission, env = runtime()
    stand.validate_runtime(containers, admission, env)
    if fault == "project":
        containers[0]["Config"]["Labels"]["com.docker.compose.project"] = "sli"
    elif fault == "network":
        containers[0]["NetworkSettings"]["Networks"]["external"] = {}
    elif fault == "worker":
        containers.append(copy.deepcopy(containers[1]))
        containers[-1]["Config"]["Labels"]["com.docker.compose.service"] = "collector"
    elif fault == "listener":
        containers[0]["NetworkSettings"]["Ports"]["8443/tcp"][0]["HostIp"] = "0.0.0.0"
    elif fault == "image":
        containers[0]["Config"]["Image"] = "other"
    elif fault == "stopped":
        containers[0]["State"]["Running"] = False
    elif fault == "outbound":
        containers[0]["Config"]["Env"] = ["SLI_CORE_JOB_RADIUS_PILOT=1"]
    elif fault == "volume":
        containers[1]["Mounts"] = [{"Type": "volume", "Destination": "/var/lib/postgresql"}]
    else:
        containers.pop()
    with pytest.raises(ValueError):
        stand.validate_runtime(containers, admission, env)


@pytest.mark.parametrize("status", ["blocked", "infra_failure", "not_run", "completed"])
def test_reviewer_requires_completed_matching_evidence(tmp_path, status):
    admission = {"project": "sli-audit-l06", "dataset_sha256": "dataset", "access_level": "full"}
    folder = tmp_path / "ru"
    folder.mkdir()
    evidence = folder / "evidence.jsonl"
    evidence.write_text('{"state":"page","id":"0001","locale":"ru","url":"/app/"}\n')
    completed = {**admission, "status": status, "states": 1, "evidence_sha256": hashlib.sha256(evidence.read_bytes()).hexdigest()}
    (folder / "run.json").write_text(json.dumps(completed))
    if status == "completed":
        assert stand.review_evidence(tmp_path, admission) == [evidence]
        (folder / "run.json").write_text(json.dumps({**completed, "dataset_sha256": "other"}))
    with pytest.raises(ValueError, match="review_evidence_rejected"):
        stand.review_evidence(tmp_path, admission)


def test_compose_has_only_internal_api_and_disposable_postgres():
    compose = yaml.safe_load((stand.ROOT / "deploy/audit/docker-compose.yml").read_text())
    assert set(compose["services"]) == {"api", "postgres"}
    assert compose["networks"] == {"audit": {"internal": True}}
    assert "volumes" not in compose
    api = compose["services"]["api"]
    assert api["ports"] == ["127.0.0.1:${SLI_AUDIT_PORT:-18086}:8443"]
    assert "ports" not in compose["services"]["postgres"]
    assert api["environment"]["ADLOG_ACQUISITION_DISABLED"] == "1"
    assert api["environment"]["ADLOG_DISABLE_SCHEDULER"] == "1"
    assert api["environment"]["SLI_AD_DC_AGENT_IMPORT_ENABLED"] == "0"
    assert all(api["environment"].get(key) == value for key, value in stand.DISABLED_JOBS.items())


def test_access_levels_are_one_persona_and_read_only():
    spec = json.loads((stand.HERE / "access_levels.json").read_text())
    assert spec["persona"] == "information_security_specialist"
    assert set(spec["accounts"]) == {"full", "limited", "without_raw_evidence"}
    for account in spec["accounts"].values():
        assert account["role"] == "viewer"
        assert account["allowed_actions"] == ["view"]
    assert spec["accounts"]["limited"]["scope"]["mode"] == "restricted"
    assert "raw_evidence" not in spec["accounts"]["without_raw_evidence"]["field_classes"]


def test_reviewer_script_has_linux_line_endings_and_no_model_execution():
    script = (stand.HERE / "run_review.sh").read_bytes()
    assert b"\r\n" not in script
    assert b"agy" not in script
    assert b"scripts.dev.ui_audit.stand review" in script


def test_docker_unavailable_is_infrastructure_failure_without_secret_output(monkeypatch):
    def unavailable(*args, **kwargs):
        raise subprocess.CalledProcessError(1, ["docker"], stderr="synthetic-private-error")
    monkeypatch.setattr(stand.subprocess, "run", unavailable)
    with pytest.raises(RuntimeError, match="audit_runtime_infrastructure_failed") as error:
        stand.docker_json(["ps"])
    assert "synthetic-private-error" not in str(error.value)


def test_docker_inventory_accepts_multiple_json_lines(monkeypatch):
    monkeypatch.setattr(stand.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(["docker"], 0, '"first"\n"second"\n'))
    assert stand.docker_json(["ps"]) == ["first", "second"]


@pytest.mark.parametrize("fault", ["edited", "invalid_json", "missing_fields", "count", "crawler_error"])
def test_reviewer_rejects_corrupt_or_partial_evidence(tmp_path, fault):
    folder = tmp_path / "ru"
    folder.mkdir()
    evidence = folder / "evidence.jsonl"
    record = {"id": "0001", "locale": "ru", "url": "/app/", "state": "page"}
    evidence.write_text(json.dumps(record) + "\n")
    completed = {"status": "completed", "states": 1, "evidence_sha256": hashlib.sha256(evidence.read_bytes()).hexdigest()}
    if fault == "edited":
        evidence.write_text(json.dumps({**record, "state": "tab"}) + "\n")
    elif fault == "invalid_json":
        evidence.write_text("{\n")
    elif fault == "missing_fields":
        evidence.write_text('{"state":"page"}\n')
    elif fault == "count":
        completed["states"] = 2
    else:
        evidence.write_text(json.dumps({**record, "state": "crawler-error"}) + "\n")
    if fault != "edited":
        completed["evidence_sha256"] = hashlib.sha256(evidence.read_bytes()).hexdigest()
    (folder / "run.json").write_text(json.dumps(completed))
    with pytest.raises(ValueError):
        stand.review_evidence(tmp_path, {})

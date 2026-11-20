#!/usr/bin/env python3
"""L06 stand admission and launcher. No production Compose files are inherited.

The seed image is prepared OUTSIDE the checkout from the certified export, with
the existing schema and access_levels.json applied as server-side grants. It
must carry sli.audit.dataset.sha256 and sli.audit.accounts.sha256 labels. The
immutable image reference binds that preparation to this run. Passwords are
supplied separately through secret files/environment, never through the export.
This command does not provision a database or certify an opaque database dump.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
DISABLED_JOBS = {
    "ADLOG_DISABLE_SCHEDULER": "1", "ADLOG_ACQUISITION_DISABLED": "1",
    "ADLOG_ENABLE_POSTGRES_COLLECTION": "0", "ADLOG_POSTGRES_RUNTIME_COLLECTION": "0",
    "ADLOG_NPS_EVENTLOG_ENABLED": "0", "ADLOG_ENABLE_INPROCESS_COLLECTION_SCHEDULER": "0",
    "ADLOG_ENABLE_INPROCESS_POST_COLLECTION": "0", "ADLOG_EXTERNAL_POST_COLLECTION_WORKER": "1",
    "ADLOG_EXTERNAL_STORAGE_V2_OUTBOX_WORKER": "1", "ADLOG_SEMANTIC_PRODUCTION_ENABLED": "0",
    "ADLOG_STORAGE_LIFECYCLE_AUTOMATION_ENABLED": "0", "ADLOG_STORAGE_LIFECYCLE_DELETE_EXECUTION_ENABLED": "0",
    "SLI_CORE_JOB_RADIUS_PILOT": "0", "SLI_CORE_JOB_AD_GPO_PILOT": "0", "SLI_AD_DC_AGENT_IMPORT_ENABLED": "0",
}


def require_project(project: str) -> str:
    if not re.fullmatch(r"sli-audit-[a-z0-9][a-z0-9-]{0,40}", project):
        raise ValueError("isolated_audit_project_required")
    return project


def require_external_path(value: Path) -> Path:
    resolved = value.resolve()
    roots = [ROOT]
    # A linked worktree must not write artifacts into the primary checkout.
    gitfile = ROOT / ".git"
    if gitfile.is_file():
        line = gitfile.read_text(encoding="utf-8").strip()
        if line.startswith("gitdir: "):
            gitdir = (ROOT / line[8:]).resolve()
            common = gitdir / "commondir"
            if common.is_file():
                roots.append((gitdir / common.read_text().strip()).resolve().parent)
    if any(resolved.is_relative_to(root.resolve()) for root in roots):
        raise ValueError("artifacts_must_be_outside_checkouts")
    return resolved


def validate_gate(base: str, out: Path, env: dict) -> dict:
    from scripts.dev.ui_audit.passport import require_passport

    project = require_project(env.get("SLI_AUDIT_PROJECT", ""))
    origin = urlsplit(base)
    expected = env.get("SLI_AUDIT_ORIGIN", "")
    if (base != expected or origin.scheme != "http" or origin.hostname != "127.0.0.1"
            or origin.username or origin.password or origin.path or origin.query or origin.fragment
            or origin.port != int(env.get("SLI_AUDIT_PORT", "18086"))):
        raise ValueError("isolated_audit_origin_required")
    require_external_path(out)
    artifacts = require_external_path(Path(env["SLI_AUDIT_ARTIFACTS"]))
    if not out.resolve().is_relative_to(artifacts):
        raise ValueError("run_must_be_inside_artifact_root")
    candidate = require_external_path(Path(env["SLI_AUDIT_DATASET"]))
    passport = require_external_path(Path(env["SLI_AUDIT_PASSPORT"]))
    if (out.resolve().is_relative_to(candidate) or candidate.is_relative_to(out.resolve())
            or passport.is_relative_to(candidate)):
        raise ValueError("dataset_and_artifacts_must_be_separate")
    admission = require_passport(candidate, passport)
    levels = json.loads((HERE / "access_levels.json").read_text(encoding="utf-8"))
    level = env.get("SLI_AUDIT_ACCESS_LEVEL", "")
    account = levels["accounts"].get(level)
    if not account or env.get("SLI_AUDIT_USER") != account["username"]:
        raise ValueError("audit_access_level_required")
    return {"project": project, "origin": base, "persona": levels["persona"], "access_level": level,
            "dataset_sha256": admission["sha256"],
            "accounts_sha256": hashlib.sha256((HERE / "access_levels.json").read_bytes()).hexdigest()}


def seed_admission(seed: str, admission: dict, inspect) -> None:
    if not re.fullmatch(r"[^\s]+@sha256:[a-f0-9]{64}", seed):
        raise ValueError("immutable_audit_seed_required")
    labels = inspect(seed)
    if (labels.get("sli.audit.dataset.sha256") != admission["dataset_sha256"]
            or labels.get("sli.audit.accounts.sha256") != admission["accounts_sha256"]):
        raise ValueError("audit_seed_passport_mismatch")


def validate_runtime(containers: list[dict], admission: dict, env: dict) -> None:
    """Bind the loopback listener to this project, not merely a supplied URL."""
    services = {}
    for container in containers:
        config = container.get("Config", {})
        labels = config.get("Labels") or {}
        service = labels.get("com.docker.compose.service")
        if (labels.get("com.docker.compose.project") != admission["project"]
                or service not in {"api", "postgres"} or service in services
                or not container.get("State", {}).get("Running")
                or set(container.get("NetworkSettings", {}).get("Networks", {})) != {admission["project"] + "_audit"}):
            raise ValueError("isolated_runtime_required")
        for mount in container.get("Mounts", []):
            if mount.get("Type") != "tmpfs" and not (mount.get("Type") == "bind" and
                    mount.get("Destination") in {"/run/secrets/runtime_password", "/run/secrets/postgres_password"}
                    and mount.get("RW") is False):
                raise ValueError("shared_runtime_mount_forbidden")
        services[service] = container
    if set(services) != {"api", "postgres"}:
        raise ValueError("isolated_runtime_required")
    api_env = dict(item.split("=", 1) for item in services["api"]["Config"].get("Env", []) if "=" in item)
    if any(api_env.get(key) != value for key, value in DISABLED_JOBS.items()):
        raise ValueError("audit_outbound_jobs_must_be_disabled")
    for service, setting in (("postgres", "SLI_AUDIT_SEED_IMAGE"), ("api", "SLI_AUDIT_APP_IMAGE")):
        if services[service]["Config"].get("Image") != env.get(setting):
            raise ValueError("isolated_runtime_image_mismatch")
    bindings = services["api"]["NetworkSettings"].get("Ports", {})
    if bindings != {"8443/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(urlsplit(admission["origin"]).port)}]}:
        raise ValueError("isolated_listener_required")


def docker_json(arguments: list[str]):
    try:
        result = subprocess.run(["docker", *arguments], capture_output=True, check=True, text=True)
        try:
            return json.loads(result.stdout)
        except ValueError:
            return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    except (OSError, ValueError, subprocess.SubprocessError):
        raise RuntimeError("audit_runtime_infrastructure_failed") from None


def require_runtime(admission: dict, env: dict) -> None:
    seed_admission(env.get("SLI_AUDIT_SEED_IMAGE", ""), admission,
                   lambda seed: docker_json(["image", "inspect", seed])[0]["Config"]["Labels"] or {})
    # Inspect every project container so extra collectors/workers cannot hide.
    containers = docker_json(["ps", "--filter", f"label=com.docker.compose.project={admission['project']}",
                              "--format", "{{json .ID}}", "--no-trunc"])
    ids = [containers] if isinstance(containers, str) else containers
    if not ids:
        raise ValueError("isolated_runtime_required")
    inspected = docker_json(["inspect", *ids])
    validate_runtime(inspected, admission, env)
    network = docker_json(["network", "inspect", admission["project"] + "_audit"])
    if len(network) != 1 or network[0].get("Internal") is not True:
        raise ValueError("internal_audit_network_required")


def review_evidence(out: Path, admission: dict) -> list[Path]:
    paths = []
    for locale in ("ru", "en"):
        folder = out / locale
        if not folder.exists():
            continue
        if folder.is_symlink():
            raise ValueError("review_evidence_rejected")
        completed = json.loads((folder / "run.json").read_text(encoding="utf-8"))
        if (folder / "run.json").is_symlink():
            raise ValueError("review_evidence_rejected")
        evidence = folder / "evidence.jsonl"
        if (completed.get("status") != "completed" or any(completed.get(k) != v for k, v in admission.items())
                or evidence.is_symlink() or not evidence.is_file() or not evidence.stat().st_size):
            raise ValueError("review_evidence_rejected")
        raw = evidence.read_bytes()
        if completed.get("evidence_sha256") != hashlib.sha256(raw).hexdigest():
            raise ValueError("review_evidence_rejected")
        records = [json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()]
        if (not records or len(records) != completed.get("states")
                or any(not isinstance(record, dict) or not {"id", "locale", "url", "state"} <= record.keys()
                       or record["locale"] != locale or not str(record["url"]).startswith("/app")
                       or record.get("error") or record["state"] == "crawler-error" for record in records)):
            raise ValueError("review_evidence_rejected")
        paths.append(evidence)
    if not paths:
        raise ValueError("review_evidence_required")
    return paths


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "start", "review"))
    parser.add_argument("--base", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        admission = validate_gate(args.base, args.out, dict(os.environ))
        if args.action in {"check", "review"}:
            require_runtime(admission, dict(os.environ))
        if args.action == "review":
            paths = review_evidence(args.out, admission)
            from scripts.dev.ui_audit.rules import run
            result = {**admission, "status": "not_run", "model_status": "not_run"}
            try:
                summary = run(paths, args.out)
                result.update(status="completed", summary=summary)
            except (OSError, ValueError, KeyError, TypeError):
                result.update(status="infra_failure", reason="deterministic_review_failed")
            (args.out / "review_run.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            print(json.dumps({"status": result["status"], "model_status": "not_run"}))
            return 0 if result["status"] == "completed" else 1
        if args.action == "start":
            require_external_path(Path(os.environ["SLI_AUDIT_SECRETS"]))
            seed_admission(os.environ.get("SLI_AUDIT_SEED_IMAGE", ""), admission,
                           lambda seed: docker_json(["image", "inspect", seed])[0]["Config"]["Labels"] or {})
            result = subprocess.run(["docker", "compose", "-p", admission["project"], "-f",
                                     str(ROOT / "deploy/audit/docker-compose.yml"), "up", "-d"],
                                    capture_output=True, check=False)
            if result.returncode:
                raise RuntimeError("audit_runtime_infrastructure_failed")
            print(json.dumps({"status": "not_run", "reason": "stand_started_reviewer_not_run"}))
            return 0
        print(json.dumps(admission))
        return 0
    except RuntimeError:
        print(json.dumps({"status": "infra_failure", "reason": "audit_runtime_infrastructure_failed"}))
        return 3
    except (KeyError, IndexError, TypeError, OSError, ValueError, subprocess.SubprocessError):
        print(json.dumps({"status": "blocked", "reason": "audit_admission_rejected"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

"""Owner-selected agent releases; independent client verification remains mandatory."""
from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path

from server.sli.agents import registry, update_waves
from server.sli.agents.ca import AgentError, uuid_text
from server.sli.release_package import PackageError, PackageLimits, verify_package
from sli_agent.updates import REASONS, validate_payload

MAX_PACKAGE_BYTES = PackageLimits().max_archive_bytes


def digest(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise AgentError("agent_package_invalid")
    return value


def upload(cur, raw, *, actor):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_PACKAGE_BYTES:
        raise AgentError("agent_package_invalid")
    try:
        trust = Path(os.environ["SLI_AGENT_UPDATE_TRUST_FILE"])
        with tempfile.TemporaryDirectory() as folder:
            archive = Path(folder) / "agent.zip"
            archive.write_bytes(raw)
            verified = verify_package(archive, trust)
        manifest = verified.manifest
        if (manifest.get("schema_version") != 2 or manifest.get("component") != "agent"
                or "agent_api" not in manifest["compatibility"]):
            raise PackageError("agent_package_contract_required")
        validate_payload({item["path"] for item in manifest["files"]})
    except (PackageError, OSError, KeyError):
        raise AgentError("agent_package_verification_failed") from None
    cur.execute("""insert into sli_agent_update_packages(sha256,version,manifest,archive)
        values(%s,%s,%s::jsonb,%s) on conflict(sha256) do nothing""",
        (verified.archive_sha256, manifest["version"], json.dumps(manifest), verified.archive_bytes))
    registry.audit(cur, "update_upload", actor, verified.archive_sha256)
    return {"sha256": verified.archive_sha256, "version": manifest["version"]}


def list_packages(cur, *, actor):
    cur.execute("select sha256,version,manifest,created_at from sli_agent_update_packages order by created_at desc,sha256 limit 100")
    items = [dict(row) for row in cur.fetchall()]
    cur.execute("select agent_id,package_sha256 from sli_agent_update_policy order by agent_id limit 100")
    policies = [dict(row) for row in cur.fetchall()]
    cur.execute("select agent_id,package_sha256,status,reason,version,observed_at from sli_agent_update_results order by observed_at desc limit 100")
    results = [dict(row) for row in cur.fetchall()]
    registry.audit(cur, "update_list", actor, "agent-packages")
    return {"items": items, "policies": policies, "results": results}


def assign(cur, body, *, actor):
    if set(body) != {"agent_id", "sha256"}:
        raise AgentError("agent_update_policy_invalid")
    agent = uuid_text(body.get("agent_id"))
    package = body.get("sha256")
    update_waves.lock(cur)
    if package is not None:
        digest(package)
        cur.execute("select sha256 from sli_agent_update_packages where sha256=%s", (package,))
        if not cur.fetchone():
            raise AgentError("agent_package_not_found", 404)
    cur.execute("select id from sli_agents where id=%s and status='active' for update", (agent,))
    if not cur.fetchone():
        raise AgentError("agent_not_found", 404)
    update_waves.require_unreserved(cur, [agent])
    cur.execute("""insert into sli_agent_update_policy(agent_id,package_sha256) values(%s,%s)
        on conflict(agent_id) do update set package_sha256=excluded.package_sha256""", (agent, package))
    registry.audit(cur, "update_assign", actor, agent, sha256=package)
    return {"status": "assigned"}


def advertisement(cur, agent):
    update_waves.lock(cur)
    cur.execute("""select p.sha256,p.version from sli_agent_update_packages p
        join sli_agent_update_policy a on a.package_sha256=p.sha256 where a.agent_id=%s""", (str(agent["id"]),))
    row = cur.fetchone()
    return dict(row) if row else None


def download(cur, agent, value):
    package = digest(value)
    update_waves.lock(cur)
    cur.execute("""select p.archive from sli_agent_update_packages p
        join sli_agent_update_policy a on a.package_sha256=p.sha256
        where a.agent_id=%s and p.sha256=%s""", (str(agent["id"]), package))
    row = cur.fetchone()
    if not row:
        raise AgentError("agent_package_not_assigned", 404)
    return bytes(row["archive"])


def report(cur, agent, body):
    package = digest(body.get("sha256"))
    status, reason, version = body.get("status"), body.get("reason"), body.get("version")
    if (not isinstance(status, str) or status not in {"updated", "rejected", "rolled_back"}
            or (reason is not None and (not isinstance(reason, str) or reason not in REASONS))
            or (status == "updated") != (reason is None)
            or not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version)
            or set(body) != {"sha256", "status", "reason", "version"}):
        raise AgentError("agent_update_result_invalid")
    agent_id = str(agent["id"])
    update_waves.lock(cur)
    # Retain authority for delayed offline results after an owner changes policy.
    # Another enrolled agent cannot report success for an unassigned package.
    cur.execute("""select p.sha256 from sli_agent_update_packages p where p.sha256=%s and
        (exists(select 1 from sli_agent_update_policy a where a.agent_id=%s and a.package_sha256=p.sha256)
         or exists(select 1 from sli_agent_audit a where a.action='update_assign' and a.target=%s
             and a.details->>'sha256'=p.sha256))""", (package, agent_id, agent_id))
    if not cur.fetchone():
        raise AgentError("agent_package_not_assigned", 404)
    cur.execute("""insert into sli_agent_update_results(agent_id,package_sha256,status,reason,version)
        values(%s,%s,%s,%s,%s) on conflict(agent_id,package_sha256,status,reason_key) do nothing returning agent_id""",
        (agent_id, package, status, reason, version))
    if cur.fetchone():
        registry.audit(cur, "update_result", "agent:" + agent_id, package, status=status, reason=reason)
    update_waves.record(cur, agent_id, package, status, reason, version)
    return {"status": "recorded"}

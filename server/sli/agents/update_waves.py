"""Transactional, bounded rollout of an owner-selected agent package."""
from __future__ import annotations

from uuid import uuid4

from server.sli.agents import registry
from server.sli.agents.ca import AgentError, uuid_text

MAX_AGENTS = 1000
MAX_BATCH = 100


def lock(cur):
    # Take this before authenticating/locking an agent. All update operations
    # share the order: rollout lock, then agent locks (never the reverse).
    cur.execute("select pg_advisory_xact_lock(hashtext('sli_agent_update_waves'))")


def require_unreserved(cur, agent_ids):
    cur.execute("""select agent_id from sli_agent_update_wave_members
        where agent_id=any(%s::uuid[]) and reserved""", (agent_ids,))
    if cur.fetchone():
        raise AgentError("agent_update_wave_conflict", 409)


def _body(body):
    from server.sli.agents.updates import digest

    if (not isinstance(body, dict) or set(body) not in (
            {"agent_ids", "sha256", "batch_size", "error_threshold"},
            {"group_token_id", "sha256", "batch_size", "error_threshold"})):
        raise AgentError("agent_update_wave_invalid")
    package = digest(body["sha256"])
    size, threshold = body["batch_size"], body["error_threshold"]
    if (type(size) is not int or not 1 <= size <= MAX_BATCH
            or type(threshold) is not int or not 0 <= threshold <= MAX_AGENTS):
        raise AgentError("agent_update_wave_invalid")
    group = uuid_text(body["group_token_id"]) if "group_token_id" in body else None
    ids = None
    if group is None:
        values = body["agent_ids"]
        if not isinstance(values, list) or not 1 <= len(values) <= MAX_AGENTS:
            raise AgentError("agent_update_wave_invalid")
        ids = sorted(uuid_text(value) for value in values)
        if len(set(ids)) != len(ids):
            raise AgentError("agent_update_wave_invalid")
    return package, size, threshold, group, ids


def create(cur, body, *, actor):
    package, size, threshold, group, ids = _body(body)
    lock(cur)
    cur.execute("select sha256,version from sli_agent_update_packages where sha256=%s", (package,))
    release = cur.fetchone()
    if not release:
        raise AgentError("agent_package_not_found", 404)
    if group is not None:
        # Migration 175 groups are registration groups. Only independently
        # approved, consumed single-use enrollments establish membership.
        cur.execute("""select a.id from sli_agents a where a.status='active' and exists(
            select 1 from sli_agent_group_approval_links c
            join sli_agent_group_requests r on r.id=c.request_id
            join sli_agent_enrollment_tokens t on t.id=c.enrollment_token_id
            where r.token_id=%s and r.status='approved' and t.used_at is not null
              and t.key_fingerprint=r.key_fingerprint and a.host_id=t.host_id
              and a.instance_name is not distinct from t.instance_name
              and exists(select 1 from sli_agent_audit e where e.action='issue'
                  and e.actor='enrollment:' || t.id::text and e.target=a.id::text))
            order by a.id limit 1001 for update of a""", (group,))
        ids = [str(row["id"]) for row in cur.fetchall()]
        if not 1 <= len(ids) <= MAX_AGENTS:
            raise AgentError("agent_update_wave_selection_invalid")
    else:
        cur.execute("""select id from sli_agents where id=any(%s::uuid[]) and status='active'
            order by id for update""", (ids,))
        if {str(row["id"]) for row in cur.fetchall()} != set(ids):
            raise AgentError("agent_not_found", 404)
    require_unreserved(cur, ids)
    cur.execute("""select agent_id from sli_agent_update_policy
        where agent_id=any(%s::uuid[]) and package_sha256 is not null""", (ids,))
    if cur.fetchone():
        raise AgentError("agent_update_policy_conflict", 409)
    # The existing agent protocol identifies attempts by package digest only.
    # Do not reuse an attempt: an old offline success must not ACK a new wave.
    cur.execute("""select 1 from sli_agent_update_wave_members
        where agent_id=any(%s::uuid[]) and package_sha256=%s limit 1""", (ids, package))
    if cur.fetchone():
        raise AgentError("agent_update_package_already_attempted", 409)
    cur.execute("""select 1 from sli_agent_audit where action='update_assign'
        and target=any(%s::text[]) and details->>'sha256'=%s limit 1""", (ids, package))
    if cur.fetchone():
        raise AgentError("agent_update_package_already_attempted", 409)
    wave_id = str(uuid4())
    cur.execute("""insert into sli_agent_update_waves
        (id,package_sha256,version,batch_size,error_threshold,group_token_id,created_by)
        values(%s,%s,%s,%s,%s,%s,%s)""", (wave_id, package, release["version"], size, threshold, group, actor))
    for index, agent_id in enumerate(ids):
        cur.execute("""insert into sli_agent_update_wave_members(wave_id,agent_id,package_sha256,batch_number)
            values(%s,%s,%s,%s)""", (wave_id, agent_id, package, index // size + 1))
    registry.audit(cur, "update_wave_create", actor, wave_id, sha256=package, batch_size=size,
                   error_threshold=threshold, group_token_id=group, count=len(ids))
    wave = _wave(cur, wave_id)
    _issue(cur, wave, _members(cur, wave_id), 1, actor)
    return _view(wave, _members(cur, wave_id))


def _wave(cur, wave_id):
    cur.execute("select * from sli_agent_update_waves where id=%s", (wave_id,))
    row = cur.fetchone()
    if not row:
        raise AgentError("agent_update_wave_not_found", 404)
    return dict(row)


def _members(cur, wave_id):
    cur.execute("""select m.agent_id,m.batch_number,m.state,m.reason,m.had_error,a.status as agent_status
        from sli_agent_update_wave_members m join sli_agents a on a.id=m.agent_id
        where m.wave_id=%s order by m.batch_number,m.agent_id""", (wave_id,))
    return [dict(row) for row in cur.fetchall()]


def _view(wave, members):
    errors = sum(row["had_error"] for row in members)
    return {**wave, "id": str(wave["id"]), "errors": errors,
            "confirmed": sum(row["state"] == "updated" for row in members),
            "waiting_reason": "agent_update_awaiting_version" if wave["status"] == "running" else None,
            "members": members}


def _issue(cur, wave, members, batch, actor):
    wave_id, package = str(wave["id"]), wave["package_sha256"]
    issued = [m for m in members if m["batch_number"] == batch]
    for member in issued:
        agent_id = str(member["agent_id"])
        cur.execute("""update sli_agent_update_wave_members set state='pending',issued_at=clock_timestamp()
            where wave_id=%s and agent_id=%s""", (wave_id, agent_id))
        cur.execute("""insert into sli_agent_update_policy(agent_id,package_sha256) values(%s,%s)
            on conflict(agent_id) do update set package_sha256=excluded.package_sha256""", (agent_id, package))
        registry.audit(cur, "update_assign", actor, agent_id, sha256=package, wave_id=wave_id, batch=batch)
    cur.execute("update sli_agent_update_waves set current_batch=%s where id=%s", (batch, wave_id))
    wave["current_batch"] = batch
    registry.audit(cur, "update_wave_batch", actor, wave_id, batch=batch, count=len(issued))


def _finish(cur, wave, status, reason, actor, *, errors=0):
    wave_id = str(wave["id"])
    cur.execute("""update sli_agent_update_waves set status=%s,reason=%s,finished_at=clock_timestamp()
        where id=%s returning finished_at""", (status, reason, wave_id))
    finished_at = cur.fetchone()["finished_at"]
    # Withdraw outstanding offers/download authority, including on manual stop.
    # Packages already downloaded may finish; their late reports stay audited.
    cur.execute("""update sli_agent_update_policy set package_sha256=null
        where agent_id in (select agent_id from sli_agent_update_wave_members where wave_id=%s)
          and package_sha256=%s""", (wave_id, wave["package_sha256"]))
    cur.execute("update sli_agent_update_wave_members set reserved=false where wave_id=%s", (wave_id,))
    wave.update(status=status, reason=reason, finished_at=finished_at)
    registry.audit(cur, "update_wave_complete" if status == "completed" else "update_wave_stop",
                   actor, wave_id, reason=reason, errors=errors, batch=wave["current_batch"])


def _advance(cur, wave, actor):
    members = _members(cur, str(wave["id"]))
    errors = sum(member["had_error"] for member in members)
    if errors > wave["error_threshold"]:
        _finish(cur, wave, "stopped", "agent_update_error_threshold_exceeded", actor, errors=errors)
    elif any(member["agent_status"] != "active" for member in members):
        _finish(cur, wave, "stopped", "agent_update_agent_inactive", actor, errors=errors)
    elif all(member["state"] == "updated" for member in members):
        _finish(cur, wave, "completed", None, actor, errors=errors)
    elif all(member["state"] == "updated" for member in members if member["batch_number"] <= wave["current_batch"]):
        _issue(cur, wave, members, wave["current_batch"] + 1, actor)


def record(cur, agent_id, package, status, reason, version):
    # Caller holds the rollout lock and has authenticated the reporting agent.
    cur.execute("""select w.*,m.state as member_state,m.reason as member_reason from sli_agent_update_waves w
        join sli_agent_update_wave_members m on m.wave_id=w.id
        where m.agent_id=%s and m.package_sha256=%s and m.state<>'queued' and w.status='running'""",
        (agent_id, package))
    row = cur.fetchone()
    if not row:
        return
    wave = dict(row)
    success = status == "updated" and version == wave["version"]
    failure = reason if status != "updated" else "agent_update_version_mismatch"
    state, safe_reason = ("updated", None) if success else ("failed", failure)
    if wave["member_state"] == state and wave["member_reason"] == safe_reason:
        return
    cur.execute("""update sli_agent_update_wave_members set state=%s,reason=%s,
        had_error=had_error or %s,reported_at=clock_timestamp() where wave_id=%s and agent_id=%s""",
        (state, safe_reason, not success, str(wave["id"]), agent_id))
    registry.audit(cur, "update_wave_result", "agent:" + agent_id, str(wave["id"]),
                   agent_id=agent_id, status=state, reason=safe_reason, version=version)
    _advance(cur, wave, "agent:" + agent_id)


def stop(cur, body, *, actor):
    if not isinstance(body, dict) or set(body) != {"wave_id"}:
        raise AgentError("agent_update_wave_invalid")
    wave_id = uuid_text(body["wave_id"])
    lock(cur)
    wave = _wave(cur, wave_id)
    if wave["status"] == "running":
        errors = sum(member["had_error"] for member in _members(cur, wave_id))
        _finish(cur, wave, "stopped", "agent_update_stopped_by_admin", actor, errors=errors)
    return _view(wave, _members(cur, wave_id))


def list_waves(cur, *, actor, wave_id=None):
    if wave_id is not None:
        wave_id = uuid_text(wave_id)
    lock(cur)
    if wave_id is not None:
        waves = [_wave(cur, wave_id)]
    else:
        cur.execute("select * from sli_agent_update_waves order by created_at desc,id limit 100")
        waves = [dict(row) for row in cur.fetchall()]
    # An offline participant keeps its batch pending. A disabled participant
    # stops the wave on the next administration read or authenticated report.
    for wave in waves:
        if wave["status"] == "running":
            members = _members(cur, str(wave["id"]))
            if any(member["agent_status"] != "active" for member in members):
                _finish(cur, wave, "stopped", "agent_update_agent_inactive", actor,
                        errors=sum(member["had_error"] for member in members))
    registry.audit(cur, "update_wave_list", actor, wave_id or "agent-update-waves")
    return {"items": [_view(wave, _members(cur, str(wave["id"]))) for wave in waves]}

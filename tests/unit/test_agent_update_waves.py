"""Bounded update waves using stateful cursor fakes, never a live database."""
import json
from copy import deepcopy
from datetime import datetime, timezone
from uuid import UUID

import pytest

from server.sli.agents import update_waves, updates
from server.sli.agents.ca import AgentError

PACKAGE = "a" * 64


def uid(number):
    return str(UUID(int=number))


class Cursor:
    def __init__(self, count=3):
        self.agents = {uid(i): {"id": uid(i), "status": "active"} for i in range(1, count + 1)}
        self.packages = {PACKAGE: {"sha256": PACKAGE, "version": "1.1.0"}}
        self.waves, self.members, self.policies = {}, {}, {}
        self.audits, self.calls, self.results = [], [], set()
        self.rows = []
        self.group_ids = list(self.agents)

    def execute(self, sql, args=()):
        sql = " ".join(sql.split())
        self.calls.append((sql, args))
        self.rows = []
        if "pg_advisory_xact_lock" in sql:
            return
        if sql.startswith("insert into sli_agent_audit"):
            self.audits.append(dict(action=args[0], actor=args[1], target=args[2], details=json.loads(args[3])))
        elif sql.startswith("select sha256,version from sli_agent_update_packages"):
            self.rows = [self.packages[args[0]]] if args[0] in self.packages else []
        elif sql.startswith("select sha256 from sli_agent_update_packages"):
            self.rows = [self.packages[args[0]]] if args[0] in self.packages else []
        elif sql.startswith("select id from sli_agents where id=%s"):
            agent = self.agents.get(args[0])
            self.rows = [agent] if agent and agent["status"] == "active" else []
        elif sql.startswith("select id from sli_agents where id=any"):
            self.rows = [a for a in self.agents.values() if a["id"] in args[0] and a["status"] == "active"]
        elif sql.startswith("select a.id from sli_agents a"):
            self.rows = [self.agents[i] for i in self.group_ids if self.agents[i]["status"] == "active"][:1001]
        elif sql.startswith("select agent_id from sli_agent_update_wave_members"):
            self.rows = [m for m in self.members.values() if m["agent_id"] in args[0] and m["reserved"]]
        elif sql.startswith("select agent_id from sli_agent_update_policy"):
            self.rows = [{"agent_id": i} for i in args[0] if self.policies.get(i)]
        elif sql.startswith("select 1 from sli_agent_update_wave_members"):
            self.rows = [m for m in self.members.values() if m["agent_id"] in args[0] and m["package_sha256"] == args[1]]
        elif sql.startswith("select 1 from sli_agent_audit"):
            self.rows = [a for a in self.audits if a["action"] == "update_assign" and a["target"] in args[0]
                         and a["details"]["sha256"] == args[1]]
        elif sql.startswith("insert into sli_agent_update_waves"):
            wave, package, version, size, threshold, group, actor = args
            self.waves[wave] = dict(id=wave, package_sha256=package, version=version, batch_size=size,
                                    error_threshold=threshold, group_token_id=group, created_by=actor,
                                    status="running", reason=None, current_batch=0)
        elif sql.startswith("insert into sli_agent_update_wave_members"):
            wave, agent, package, batch = args
            self.members[wave, agent] = dict(wave_id=wave, agent_id=agent, package_sha256=package, batch_number=batch,
                                           state="queued", reason=None, had_error=False, reserved=True)
        elif sql.startswith("select * from sli_agent_update_waves"):
            self.rows = ([self.waves[args[0]]] if args[0] in self.waves else []) if args else list(self.waves.values())
        elif sql.startswith("select w.*,m.state"):
            self.rows = [{**self.waves[m["wave_id"]], "member_state": m["state"], "member_reason": m["reason"]}
                         for m in self.members.values()
                         if m["agent_id"] == args[0] and m["package_sha256"] == args[1]
                         and m["state"] != "queued" and self.waves[m["wave_id"]]["status"] == "running"]
        elif sql.startswith("select m.agent_id"):
            self.rows = [{**deepcopy(m), "agent_status": self.agents[m["agent_id"]]["status"]}
                         for m in self.members.values() if m["wave_id"] == args[0]]
        elif sql.startswith("update sli_agent_update_waves set current_batch"):
            self.waves[args[1]]["current_batch"] = args[0]
        elif sql.startswith("update sli_agent_update_waves set status"):
            finished_at = datetime.now(timezone.utc)
            self.waves[args[2]].update(status=args[0], reason=args[1], finished_at=finished_at)
            self.rows = [{"finished_at": finished_at}]
        elif sql.startswith("update sli_agent_update_wave_members set state='pending'"):
            self.members[args[0], args[1]]["state"] = "pending"
        elif sql.startswith("update sli_agent_update_wave_members set state=%s"):
            state, reason, error, wave, agent = args
            member = self.members[wave, agent]
            member.update(state=state, reason=reason, had_error=member["had_error"] or error)
        elif sql.startswith("update sli_agent_update_wave_members set reserved=false"):
            for m in self.members.values():
                if m["wave_id"] == args[0]:
                    m["reserved"] = False
        elif sql.startswith("insert into sli_agent_update_policy"):
            self.policies[args[0]] = args[1]
        elif sql.startswith("update sli_agent_update_policy set package_sha256=null"):
            for m in self.members.values():
                if m["wave_id"] == args[0] and self.policies.get(m["agent_id"]) == args[1]:
                    self.policies[m["agent_id"]] = None
        elif sql.startswith("select p.sha256 from sli_agent_update_packages"):
            package, agent, _ = args
            assigned = self.policies.get(agent) == package or any(a["action"] == "update_assign" and a["target"] == agent
                        and a["details"]["sha256"] == package for a in self.audits)
            self.rows = [{"sha256": package}] if assigned else []
        elif sql.startswith("select p.sha256,p.version") or sql.startswith("select p.archive"):
            package = self.policies.get(args[0])
            if package is not None and (len(args) == 1 or args[1] == package):
                self.rows = [{**self.packages[package], "archive": b"synthetic-package"}]
        elif sql.startswith("insert into sli_agent_update_results"):
            key = tuple(args[:4])
            if key not in self.results:
                self.results.add(key)
                self.rows = [{"agent_id": args[0]}]
        else:
            raise AssertionError(sql)

    def fetchone(self):
        return self.rows.pop(0) if self.rows else None

    def fetchall(self):
        rows, self.rows = self.rows, []
        return rows


def start(cur, **changes):
    return update_waves.create(cur, {"agent_ids": list(cur.agents), "sha256": PACKAGE,
                               "batch_size": 2, "error_threshold": 0, **changes}, actor="session:1")


def report(cur, number, status="updated", version="1.1.0", reason=None):
    return updates.report(cur, {"id": uid(number)}, {"sha256": PACKAGE, "status": status,
                          "version": version, "reason": reason})


def test_next_batch_waits_for_every_exact_version_ack_and_finishes_with_audit():
    cur = Cursor()
    wave = start(cur)
    assert wave["current_batch"] == 1 and wave["status"] == "running"
    assert cur.policies == {uid(1): PACKAGE, uid(2): PACKAGE}
    report(cur, 1)
    assert uid(3) not in cur.policies
    report(cur, 1)  # replay cannot release or count twice
    assert uid(3) not in cur.policies
    report(cur, 2)
    assert cur.policies[uid(3)] == PACKAGE
    assert cur.waves[wave["id"]]["current_batch"] == 2
    report(cur, 3)
    assert cur.waves[wave["id"]]["status"] == "completed"
    assert all(value is None for value in cur.policies.values())
    assert all(not m["reserved"] for m in cur.members.values())
    assert [a["action"] for a in cur.audits].count("update_wave_batch") == 2
    assert cur.audits[-1]["action"] == "update_wave_complete"


def test_failure_stops_wave_clears_offers_and_late_success_cannot_restart_it():
    cur = Cursor()
    wave = start(cur)
    report(cur, 1, "rolled_back", "1.0.0", "agent_update_timeout")
    assert cur.waves[wave["id"]]["status"] == "stopped"
    assert cur.waves[wave["id"]]["reason"] == "agent_update_error_threshold_exceeded"
    assert all(value is None for value in cur.policies.values())
    report(cur, 1)
    report(cur, 2)
    assert uid(3) not in cur.policies
    assert cur.audits[-1]["action"] == "update_result"


def test_threshold_counts_distinct_error_agents_across_batches_and_retries():
    cur = Cursor(4)
    wave = start(cur, error_threshold=1)
    report(cur, 1, "rejected", "1.0.0", "agent_update_download_failed")
    report(cur, 1, "rejected", "1.0.0", "agent_update_download_failed")
    report(cur, 2)
    assert wave["current_batch"] == 1 and uid(3) not in cur.policies
    report(cur, 1)
    assert cur.policies[uid(3)] == PACKAGE
    report(cur, 3, "rejected", "1.0.0", "agent_update_download_failed")
    assert cur.waves[wave["id"]]["status"] == "stopped"
    assert cur.audits[-1]["details"]["errors"] == 2


def test_wrong_version_is_a_wave_error_never_an_ack():
    cur = Cursor()
    wave = start(cur)
    report(cur, 1, version="1.0.0")
    member = cur.members[wave["id"], uid(1)]
    assert member["state"] == "failed" and member["reason"] == "agent_update_version_mismatch"
    assert cur.waves[wave["id"]]["status"] == "stopped"
    assert uid(3) not in cur.policies


def test_unissued_member_cannot_report_or_download_using_its_wave_reservation():
    cur = Cursor()
    start(cur)
    with pytest.raises(AgentError, match="agent_package_not_assigned"):
        report(cur, 3)
    assert updates.advertisement(cur, {"id": uid(3)}) is None
    with pytest.raises(AgentError, match="agent_package_not_assigned"):
        updates.download(cur, {"id": uid(3)}, PACKAGE)
    assert not cur.results


def test_group_selection_is_a_bounded_snapshot_of_approved_enrollment():
    cur = Cursor(5)
    cur.group_ids = [uid(1), uid(3)]
    result = update_waves.create(cur, {"group_token_id": uid(99), "sha256": PACKAGE,
                                "batch_size": 1, "error_threshold": 0}, actor="session:1")
    assert [m["agent_id"] for m in result["members"]] == [uid(1), uid(3)]
    sql = next(sql for sql, _ in cur.calls if sql.startswith("select a.id"))
    assert "sli_agent_group_approval_links c" in sql
    assert "r.status='approved'" in sql and "t.used_at is not null" in sql
    assert "t.key_fingerprint=r.key_fingerprint" in sql and "is not distinct from" in sql
    assert "e.action='issue'" in sql and "e.target=a.id::text" in sql
    cur.group_ids.append(uid(4))
    assert len(cur.members) == 2


@pytest.mark.parametrize("change", [{"agent_ids": []}, {"agent_ids": [uid(1)] * 2},
    {"agent_ids": [uid(i) for i in range(1001)]}, {"agent_ids": "all"}, {"agent_ids": ["bad"]},
    {"batch_size": 0}, {"batch_size": 101}, {"batch_size": True}, {"error_threshold": -1},
    {"error_threshold": True}, {"error_threshold": 1001}, {"group_token_id": uid(99)},
    {"extra": "private-diagnostic"}, {"sha256": "bad"}])
def test_invalid_request_does_not_write(change):
    cur = Cursor()
    with pytest.raises(AgentError):
        start(cur, **change)
    assert not cur.calls


@pytest.mark.parametrize("conflict", ["inactive", "missing", "policy", "wave", "prior_assignment", "prior_wave"])
def test_conflicting_selection_rejected_atomically_before_creation(conflict):
    cur = Cursor()
    ids = list(cur.agents)
    if conflict == "inactive":
        cur.agents[uid(2)]["status"] = "disabled"
    elif conflict == "missing":
        ids.append(uid(99))
    elif conflict == "policy":
        cur.policies[uid(2)] = "b" * 64
    elif conflict in {"wave", "prior_wave"}:
        wave = start(cur)
        if conflict == "prior_wave":
            update_waves.stop(cur, {"wave_id": wave["id"]}, actor="session:1")
    else:
        cur.audits.append(dict(action="update_assign", target=uid(1), details={"sha256": PACKAGE}))
    before = deepcopy((cur.waves, cur.members, cur.policies))
    with pytest.raises(AgentError):
        start(cur, agent_ids=ids)
    assert (cur.waves, cur.members, cur.policies) == before


def test_individual_assignment_cannot_override_a_wave_even_for_queued_agent():
    cur = Cursor()
    start(cur)
    with pytest.raises(AgentError, match="agent_update_wave_conflict"):
        updates.assign(cur, {"agent_id": uid(3), "sha256": None}, actor="session:1")


def test_manual_stop_is_idempotent_and_preserves_history():
    cur = Cursor()
    wave = start(cur)
    assert updates.download(cur, {"id": uid(1)}, PACKAGE) == b"synthetic-package"
    result = update_waves.stop(cur, {"wave_id": wave["id"]}, actor="session:1")
    assert result["status"] == "stopped" and result["reason"] == "agent_update_stopped_by_admin"
    assert result["finished_at"] == cur.waves[wave["id"]]["finished_at"]
    count = len(cur.audits)
    update_waves.stop(cur, {"wave_id": wave["id"]}, actor="session:1")
    assert len(cur.audits) == count
    assert len(cur.members) == 3 and all(not m["reserved"] for m in cur.members.values())
    assert updates.advertisement(cur, {"id": uid(1)}) is None
    with pytest.raises(AgentError, match="agent_package_not_assigned"):
        updates.download(cur, {"id": uid(1)}, PACKAGE)


def test_1000_synthetic_agents_never_receive_more_than_one_batch():
    cur = Cursor(1000)
    wave = start(cur, batch_size=100)
    assert len(cur.members) == 1000 and len(cur.policies) == 100
    assert wave["current_batch"] == 1
    for i in range(1, 100):
        report(cur, i)
    assert len(cur.policies) == 100
    report(cur, 100)
    assert len(cur.policies) == 200 and cur.waves[wave["id"]]["current_batch"] == 2


def test_disabled_member_stops_progress_before_another_batch_is_issued():
    cur = Cursor()
    wave = start(cur)
    cur.agents[uid(3)]["status"] = "disabled"
    report(cur, 1)
    assert cur.waves[wave["id"]]["reason"] == "agent_update_agent_inactive"
    assert uid(3) not in cur.policies


def test_list_shows_offline_pending_without_releasing_more_and_audits_read():
    cur = Cursor()
    wave = start(cur)
    result = update_waves.list_waves(cur, actor="session:1", wave_id=wave["id"])
    assert result["items"][0]["waiting_reason"] == "agent_update_awaiting_version"
    assert [m["state"] for m in result["items"][0]["members"]] == ["pending", "pending", "queued"]
    assert len(cur.policies) == 2
    assert cur.audits[-1]["action"] == "update_wave_list"
    assert "archive" not in repr(result) and "key_fingerprint" not in repr(result)


def test_msi_zip_rejection_stops_wave_before_next_batch():
    cur = Cursor()
    wave = start(cur, batch_size=1, error_threshold=0)
    updates.report(cur, {"id": uid(1)}, {"sha256": PACKAGE, "status": "rejected",
        "reason": "agent_update_msi_required", "version": "2026.10.1"})
    assert cur.members[(wave["id"], uid(1))]["reason"] == "agent_update_msi_required"
    assert cur.waves[wave["id"]]["status"] == "stopped"
    assert uid(2) not in cur.policies


def test_list_detects_disabled_member_and_withdraws_outstanding_downloads():
    cur = Cursor()
    wave = start(cur)
    cur.agents[uid(1)]["status"] = "disabled"
    result = update_waves.list_waves(cur, actor="session:1")
    assert result["items"][0]["reason"] == "agent_update_agent_inactive"
    assert cur.waves[wave["id"]]["status"] == "stopped"
    assert all(value is None for value in cur.policies.values())


@pytest.mark.parametrize("group_ids", [[], [uid(i) for i in range(1, 1002)]])
def test_group_is_never_silently_truncated_or_empty(group_ids):
    cur = Cursor(1001)
    cur.group_ids = group_ids
    with pytest.raises(AgentError, match="agent_update_wave_selection_invalid"):
        update_waves.create(cur, {"group_token_id": uid(99), "sha256": PACKAGE,
                            "batch_size": 100, "error_threshold": 0}, actor="session:1")
    assert not cur.waves and not cur.policies


def test_unknown_wave_and_package_are_safe_errors_without_mutation():
    cur = Cursor()
    with pytest.raises(AgentError, match="agent_update_wave_not_found"):
        update_waves.stop(cur, {"wave_id": uid(99)}, actor="session:1")
    with pytest.raises(AgentError, match="agent_package_not_found"):
        start(cur, sha256="b" * 64)
    assert not cur.waves and not cur.policies

"""R01 simulated native rules, durable episodes and the real QW publication code."""
from copy import deepcopy
from dataclasses import asdict, replace
from datetime import timedelta
import json

import pytest

from server.sli.semantic import file_ransom as ransom, file_ransom_runtime as worker, qw_input as qw
from server.sli.semantic.semantic_risk_policy import compile_risk_policy
from tests.unit.test_file_audit_rules import AGENT, START, action, config
from tests.unit.test_finding_evidence_refs import reference
from tests.unit.test_qw_publication import Cursor as PublicationCursor, evaluate as publish, no_database as no_database
from sli_agent.envelope import timestamp

NOW = timestamp(START)


def rule(**changes):
    scope = replace(reference("file_audit_observation").scope,
                    source_instance_id=AGENT, collection_scope_id="scope:one")
    return ransom.RansomRule(scope=scope, agent_id=AGENT, source_policy_revision="1", **changes)


def results(count=100, *, operation="write", threshold=100, start=NOW, offset=0, **changes):
    from server.sli.plugins.file_audit.rules import activity_findings

    cfg = config()
    cfg["mass_operation_files"] = threshold
    if "collection_scope_id" in changes:
        cfg["roots"][0]["collection_scope_id"] = changes["collection_scope_id"]
    rows = [action(i + offset, operation=operation, observed_at=start.isoformat(), **changes)
            for i in range(1, count + 1)]
    return activity_findings(rows, config=cfg, agent_id=AGENT, source_instance_id=AGENT)


def batch(result, *, complete=True):
    return {"result": result, "complete": complete,
            "evidence": [{"native_id": value, "sha256": "b" * 64} for value in result["action_ids"]]}


def inputs(selected, row, key="1" * 64):
    refs = tuple(replace(reference("file_audit_observation"), native_id=ref["native_id"],
                         scope=selected.scope) for ref in row["evidence"])
    return ransom.signals(selected, row["result"], refs, episode_key=key, now=NOW, complete=row["complete"])


class Cursor(PublicationCursor):
    def __init__(self, selected, row):
        super().__init__(inputs(selected, row)[0])
        self.policies = [(ransom.risk_policy(selected, policy_id="fixture-qw"), selected.evaluation_mode)]
        self.episodes = {}
        self.members = {}
        self.data = []

    def execute(self, sql, params=()):
        normalized = " ".join(sql.split()).lower()
        if "pg_advisory_xact_lock" in normalized:
            self.rows = []
        elif "select 1 from semantic_file_ransom_members" in normalized:
            self.rows = [self.members[params]] if params in self.members else []
        elif "select * from semantic_file_ransom_episodes" in normalized:
            checkpoint, entity, incomplete, end, start = params
            self.rows = [deepcopy(row) for row in self.episodes.values()
                         if row["checkpoint_key"] == checkpoint and row["entity_key"] == entity
                         and (row["incomplete"] or incomplete or row["first_seen"] <= end and row["last_seen"] >= start)]
        elif "insert into semantic_file_ransom_episodes" in normalized:
            key, checkpoint, scope, entity, start, end, incomplete = params
            row = self.episodes.setdefault(key, {"episode_key": key, "checkpoint_key": checkpoint,
                "scope_json": json.loads(scope), "entity_key": entity,
                "first_seen": start, "last_seen": end, "incomplete": incomplete})
            row.update(first_seen=min(row["first_seen"], start), last_seen=max(row["last_seen"], end),
                       incomplete=row["incomplete"] or incomplete)
        elif "insert into semantic_file_ransom_members" in normalized:
            self.members[params[:2]] = {"episode_key": None if "null," in normalized else params[2]}
        else:
            return super().execute(sql, params)
        self.calls.append((normalized, params))


def run(cur, selected, rows):
    for row in rows:
        cur.allowed.update(ref.params for ref in inputs(selected, row)[0].evidence_refs)
        for item in inputs(selected, row)[1:]:
            cur.allowed.update(ref.params for ref in item.evidence_refs)
    return worker.run_once(cur, rule=selected, now=NOW, reader=lambda *_: deepcopy(rows))


@pytest.mark.parametrize("threshold", [20, 100])
@pytest.mark.parametrize("operation", ["write", "delete"])
def test_n_minus_one_n_native_rows_and_one_high_problem(threshold, operation):
    selected = rule(threshold=threshold, evaluation_mode="enabled")
    assert not results(threshold - 1, threshold=threshold, operation=operation)
    result, = results(threshold, threshold=threshold, operation=operation)
    row = batch(result)
    cur = Cursor(selected, row)
    assert run(cur, selected, [row]) == {"state": "processed", "members": 1, "jobs": 1}
    item = qw.load_qw_signal(cur, signal_id=next(iter(cur.signals)))
    first = publish(cur, item)
    assert first.finding_created and first.risk_class.value == "high"
    assert len(cur.findings) == len(cur.publications) == len(cur.outbox) == 1
    assert item.kind == "ransom" and item.base_severity == item.effective_severity == "high"
    assert all(ref.storage_kind == "file_audit_observation" for ref in item.evidence_refs)
    assert run(cur, selected, [row])["jobs"] == 0
    assert len(cur.episodes) == len(cur.members) == 1


@pytest.mark.parametrize("operation,changes", [
    ("read", {}), ("delete_right", {}), ("delete", {"correlation_state": "partial"}),
    ("delete", {"correlation_state": "ambiguous"}), ("write", {"outcome": "failure"}),
])
def test_read_rights_and_unproven_delete_never_become_ransom(operation, changes):
    found = results(operation=operation, **changes)
    if found:
        with pytest.raises(ValueError, match="file_ransom_result_invalid"):
            inputs(rule(), batch(found[0]))


def test_expanding_write_delete_late_window_and_restart_keep_one_episode_and_alert():
    selected = rule(evaluation_mode="enabled")
    first = batch(results()[0])
    cur = Cursor(selected, first)
    run(cur, selected, [first])
    for at, op, offset in [(240, "write", 100), (480, "delete", 200), (-30, "delete", 300)]:
        row = batch(results(operation=op, start=NOW + timedelta(seconds=at), offset=offset)[0])
        run(cur, selected, [row])
    assert len(cur.episodes) == 1 and len(cur.members) == 4
    assert len({qw.load_qw_signal(cur, signal_id=key).episode_key for key in cur.signals}) == 1
    for key in list(cur.signals):
        publish(cur, qw.load_qw_signal(cur, signal_id=key))
    assert len(cur.scenarios) == len(cur.findings) == len(cur.outbox) == 1
    restarted = Cursor(selected, first)
    restarted.episodes, restarted.members = deepcopy(cur.episodes), deepcopy(cur.members)
    assert run(restarted, selected, [first])["jobs"] == 0
    assert not any("commit" in sql.lower() for sql, _ in cur.calls)


@pytest.mark.parametrize("complete,expected", [(True, 2), (False, 1)])
def test_only_proven_quiet_splits_episodes(complete, expected):
    selected = rule()
    row = batch(results()[0], complete=complete)
    cur = Cursor(selected, row)
    run(cur, selected, [row])
    late = batch(results(start=NOW + timedelta(hours=1), offset=100)[0], complete=complete)
    run(cur, selected, [late])
    assert len(cur.episodes) == expected
    assert all(item["incomplete"] == (not complete) for item in cur.episodes.values())


def test_257_native_witnesses_are_complete_before_publication():
    selected = rule(evaluation_mode="enabled")
    row = batch(results(257)[0])
    cur = Cursor(selected, row)
    assert run(cur, selected, [row])["jobs"] == 2
    items = [qw.load_qw_signal(cur, signal_id=key) for key in cur.signals]
    assert [len(item.evidence_refs) for item in items] == [256, 1]
    assert publish(cur, items[0]).publication_state == "evidence_pending"
    assert not cur.outbox and not cur.findings
    assert publish(cur, items[1]).finding_created
    assert len(cur.outbox) == len(cur.findings) == 1 and len(cur.links) == 257


@pytest.mark.parametrize("mode", ["test", "shadow"])
def test_diagnostic_modes_do_not_publish(mode):
    selected = rule(evaluation_mode=mode)
    row = batch(results()[0])
    cur = Cursor(selected, row)
    run(cur, selected, [row])
    item = qw.load_qw_signal(cur, signal_id=next(iter(cur.signals)))
    assert publish(cur, item).finding_id is None
    assert not cur.outbox and not cur.findings


def test_missing_policy_or_bad_native_evidence_never_consumes_member():
    selected = rule(evaluation_mode="enabled")
    row = batch(results()[0])
    cur = Cursor(selected, row)
    cur.policies = []
    with pytest.raises(RuntimeError, match="file_ransom_policy_unavailable"):
        run(cur, selected, [row])
    assert not cur.members and not cur.episodes
    cur = Cursor(selected, row)
    cur.allowed.clear()
    with pytest.raises(RuntimeError):
        worker.run_once(cur, rule=selected, now=NOW, reader=lambda *_: [row])
    assert not cur.members and not cur.episodes


def test_high_cannot_be_downgraded_by_signal_or_policy():
    selected = rule(evaluation_mode="enabled")
    row = batch(results()[0])
    item, = inputs(selected, row)
    with pytest.raises(ValueError, match="file_ransom_signal_invalid"):
        replace(item, base_severity="medium", effective_severity="medium")
    cur = Cursor(selected, row)
    qw.enqueue_qw_signal_risk_jobs(cur, signal=item)
    definition = ransom.risk_policy(selected, policy_id="fixture-qw")
    definition = replace(definition, definition=definition.definition | {
        "risk": {"class": "medium", "raw_score": "25", "display_points": 25, "rationale": "Synthetic"}})
    with pytest.raises(RuntimeError, match="file_ransom_policy_invalid"):
        qw.qw_signal_proposal(cur, policy=compile_risk_policy(definition), source_id=item.signal_id)


@pytest.mark.parametrize("changes", [{"threshold": 0}, {"window_seconds": True},
    {"agent_id": "invalid"}, {"source_policy_revision": "01"}, {"evaluation_mode": "invalid"}])
def test_rule_validation(changes):
    with pytest.raises(ValueError, match="file_ransom_rule_invalid"):
        replace(rule(), **changes)


def test_cli_redacts_failure(tmp_path, monkeypatch, capsys):
    from scripts.runtime import file_ransom_worker as cli

    path = tmp_path / "rule.json"
    path.write_text('{"private":"synthetic-sensitive-marker"}', encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["file_ransom_worker", "--rule-file", str(path)])
    assert cli.main() == 1
    assert capsys.readouterr().out == '{"state": "failed", "code": "file_ransom_unavailable"}\n'


def test_cli_uses_explicit_rule_and_commits_only_success(tmp_path, monkeypatch, capsys):
    from contextlib import contextmanager
    from scripts.runtime import file_ransom_worker as cli

    selected = rule()
    path = tmp_path / "rule.json"
    path.write_text(json.dumps(asdict(selected)), encoding="utf-8")
    committed = []

    class Connection:
        @contextmanager
        def cursor(self):
            yield "synthetic-cursor"

        def commit(self):
            committed.append(True)

    @contextmanager
    def connect():
        yield Connection()

    def evaluate(cur, *, rule, now):
        assert cur == "synthetic-cursor" and rule == selected and now.tzinfo is not None
        return {"state": "processed", "members": 1, "jobs": 1}

    monkeypatch.setattr("sys.argv", ["file_ransom_worker", "--rule-file", str(path)])
    monkeypatch.setattr(cli, "connect_semantic_worker", connect)
    monkeypatch.setattr(cli, "run_once", evaluate)
    assert cli.main() == 0 and committed == [True]
    assert json.loads(capsys.readouterr().out) == {"state": "processed", "members": 1, "jobs": 1}

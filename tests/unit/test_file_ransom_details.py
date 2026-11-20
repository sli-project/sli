"""R02 scoped approvals, isolation, replay and explainable normal bursts."""
from dataclasses import asdict, replace
from datetime import timedelta

import pytest

from server.sli.semantic import file_ransom as ransom, qw_input as qw
from tests.unit.test_file_audit_rules import AGENT, SID, action, config
from tests.unit.test_file_ransom import NOW, Cursor, batch, results, rule, run
from tests.unit.test_qw_publication import evaluate as publish, no_database as no_database


def approval(**changes):
    return ransom.RansomExclusion(**({"subject_sid": SID, "collection_scope_id": "scope:one",
        "reason": "Synthetic backup window", "approved_by": "synthetic-admin",
        "active_from": NOW.isoformat(), "active_to": (NOW + timedelta(hours=1)).isoformat()} | changes))


@pytest.mark.parametrize("changes", [
    {"active_to": NOW.isoformat()}, {"active_to": (NOW + timedelta(days=32)).isoformat()},
    {"active_from": "invalid"}, {"subject_sid": "*"}, {"reason": ""}, {"approved_by": ""},
    {"reason": "line\nbreak"}, {"active_to": "2026-01-05T12:00:00+03:00"},
])
def test_approval_requires_exact_identity_reason_owner_and_bounded_utc_interval(changes):
    with pytest.raises(ValueError, match="file_ransom_exclusion_invalid"):
        approval(**changes)


def test_other_root_and_unbounded_approval_lists_are_rejected():
    for entries in ((approval(collection_scope_id="scope:other"),), (approval(),) * 101, ({} ,)):
        with pytest.raises(ValueError, match="file_ransom_exclusion_invalid"):
            rule(exclusions=entries)


def test_approval_retains_file_result_and_replay_checkpoint_without_signal_or_outbox():
    original = rule(evaluation_mode="enabled")
    selected = replace(original, exclusions=(approval(),))
    assert original.checkpoint_key == selected.checkpoint_key
    assert original.rule_sha256 == selected.rule_sha256
    row = batch(results(110)[0])
    cur = Cursor(selected, row)
    assert run(cur, selected, [row]) == {"state": "processed", "members": 1, "jobs": 0}
    assert not cur.signals and not cur.episodes and not cur.outbox
    assert row["result"]["details"]["distinct_files"] == 110
    assert run(cur, original, [row])["members"] == 0
    insert = next(params for sql, params in cur.calls if "insert into semantic_file_ransom_members" in sql)
    import json
    assert json.loads(insert[3]) == asdict(approval())


@pytest.mark.parametrize("changes", [
    {"active_to": NOW.isoformat()},
    {"active_from": (NOW + timedelta(seconds=1)).isoformat()},
    {"subject_sid": "S-1-5-21-1-2-3-9999"},
])
def test_boundary_partial_window_and_other_sid_never_suppress(changes):
    entry = approval(**changes) if changes.get("active_to") != NOW.isoformat() else approval(
        active_from=(NOW - timedelta(hours=1)).isoformat(), active_to=NOW.isoformat())
    selected = rule(exclusions=(entry,))
    assert ransom.exclusion_for(selected, results()[0]) is None


def test_two_sids_two_roots_and_replay_keep_four_independent_episodes():
    selected = rule(evaluation_mode="enabled")
    first = batch(results()[0])
    cur = Cursor(selected, first)
    keys = set()
    for root in ("scope:one", "scope:two"):
        scoped = replace(selected, scope=replace(selected.scope, collection_scope_id=root))
        cur.policies = [(ransom.risk_policy(scoped, policy_id="fixture-qw"), scoped.evaluation_mode)]
        for index, sid in enumerate((SID, "S-1-5-21-1-2-3-9999")):
            from server.sli.plugins.file_audit.rules import activity_findings
            cfg = config()
            cfg["roots"][0]["collection_scope_id"] = root
            native = [action(number + index * 100, operation="write", subject_sid=sid, collection_scope_id=root)
                      for number in range(1, 101)]
            row = batch(activity_findings(native, config=cfg, agent_id=AGENT, source_instance_id=AGENT)[0])
            assert run(cur, scoped, [row])["jobs"] == 1
            assert run(cur, scoped, [row])["jobs"] == 0
            keys.add(next(reversed(cur.signals)))
    assert len(cur.episodes) == len(cur.members) == len(keys) == 4
    assert len({qw.load_qw_signal(cur, signal_id=key).episode_key for key in keys}) == 4


def test_normal_110_file_burst_is_high_without_explicit_approval():
    selected = rule(evaluation_mode="enabled")
    row = batch(results(110)[0])
    cur = Cursor(selected, row)
    run(cur, selected, [row])
    item = qw.load_qw_signal(cur, signal_id=next(iter(cur.signals)))
    outcome = publish(cur, item)
    assert outcome.finding_created and outcome.risk_class.value == "high"
    assert len(cur.findings) == len(cur.outbox) == 1

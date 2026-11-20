"""W02 native-source, severity, episode and publication contracts with fakes."""
from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
from uuid import uuid4

import pytest

from server.sli.semantic import account_watch as watch, account_watch_runtime as worker, qw_input as qw
from server.sli.semantic import account_watch_projection as projection
from server.sli.semantic.event_card_semantics import build_event_card
from server.sli.core import notification_smtp as smtp, notification_telegram as telegram
from tests.unit.test_account_decoy import event as decoy_event, IDENTITY, NOW
from tests.unit.test_qw_publication import Cursor as PublicationCursor, evaluate as publish, no_database as no_database
from tests.unit.test_qw_semantic_input import signal as generic_signal
from tests.unit.test_notification_smtp import delivery as smtp_delivery, channel as smtp_channel
from tests.unit.test_notification_telegram import delivery as telegram_delivery, channel as telegram_channel


def rule(**changes):
    return watch.WatchRule(scope=generic_signal().evidence_refs[0].scope, **changes)


def event():
    row = decoy_event()
    row.pop("labels")
    row["entries"] = [{"id": "00000000-0000-0000-0000-000000000043", "revision": 1,
        "identity": deepcopy(IDENTITY), "active": True, "active_from": NOW - timedelta(hours=1),
        "expires_at": NOW + timedelta(days=1), "valid_from": NOW - timedelta(hours=1), "valid_to": None}]
    row["event_item"] = {"event_id": 4624, "channel": "Security",
                         "provider_name": "Microsoft-Windows-Security-Auditing"}
    return row


def evaluate(row=None, selected=None):
    return watch.evaluate(selected or rule(), row or event(), now=NOW)


class Cursor(PublicationCursor):
    def __init__(self, selected=None, rows=None):
        selected = selected or rule(evaluation_mode="enabled")
        self.events = rows if rows is not None else [event()]
        item, = evaluate(self.events[0], selected)[0]
        super().__init__(item)
        self.policies = [(watch.risk_policy(selected, policy_id="fixture-qw"), selected.evaluation_mode)]
        self.allowed.update(ref.params for row in self.events
                            for signal in evaluate(row, selected)[0] for ref in signal.evidence_refs)
        self.checks = {}

    def execute(self, sql, params=()):
        normalized = " ".join(sql.split()).lower()
        if "read_account_watch_events(" in normalized:
            self.calls.append((normalized, params))
            self.rows = [row for row in self.events if (str(row["normalized_event_id"]) == params[-1]
                if params[-1] else (params[-2], row["normalized_event_id"]) not in self.checks)]
        elif "insert into semantic_account_watch_checks(" in normalized:
            self.checks[(params[0], params[1])] = params[-1]
            self.rows = []
        elif "pg_advisory_xact_lock(" in normalized:
            self.rows = []
        else:
            super().execute(sql, params)


@pytest.mark.parametrize(("base", "expected"), list(zip(qw.SEVERITIES, (*qw.SEVERITIES[1:], "critical"))))
def test_server_increases_one_level_and_caps_at_critical(base, expected):
    assert watch.effective_severity(base) == expected


def test_same_action_only_selected_account_is_raised_without_private_reason():
    selected = event()
    ordinary = deepcopy(selected)
    ordinary["identities"][0]["identity"]["entity_id"] += 1
    item, = evaluate(selected)[0]
    assert item.base_severity == "low" and item.effective_severity == "medium"
    assert item.severity_reasons == ("watch",)
    assert not evaluate(ordinary)[0]
    assert IDENTITY["sid"] not in str(item.document) and "reason" not in item.watch_context


@pytest.mark.parametrize(("event_id", "semantic", "base", "final"), [
    (4648, "authentication.explicit_credentials.used", "info", "low"),
    (4722, "directory.account.enabled", "medium", "high"),
    (4724, "account.password.reset.attempted", "high", "critical"),
])
def test_catalog_base_severity_is_raised_before_semantic_publication(event_id, semantic, base, final):
    row = event()
    row.update(event_id=event_id, semantic_type=semantic)
    row["event_item"]["event_id"] = event_id
    selected = rule(evaluation_mode="enabled")
    cur = Cursor(selected, [row])
    item, = evaluate(row, selected)[0]
    assert (item.base_severity, item.effective_severity) == (base, final)
    assert publish(cur, item).risk_class.value == final


def test_both_exact_roles_share_one_signal_and_expanding_episode_one_problem():
    row = event()
    row["roles_json"]["actor"] = row["roles_json"]["affected_entity"]
    row["quality_json"]["identity_roles"]["actor"] = row["quality_json"]["identity_roles"]["affected_entity"]
    row["identities"].append(row["identities"][0] | {"role": "actor"})
    assert len(evaluate(row)[0]) == 1
    other = deepcopy(row)
    other["normalized_event_id"] = str(uuid4())
    other["source_event_id"] += 1
    cur = Cursor(rows=[row, other])
    selected = rule(evaluation_mode="enabled")
    assert worker.run_once(cur, rule=selected, now=NOW)["jobs"] == 2
    outcomes = [publish(cur, qw.load_qw_signal(cur, signal_id=key)) for key in list(cur.signals)]
    assert outcomes[0].finding_id == outcomes[1].finding_id
    assert len(cur.findings) == len(cur.outbox) == 1 and len(cur.links) == 2


@pytest.mark.parametrize("change", ["role", "provisional", "ambiguous", "inactive", "before", "expired", "snapshot", "other_domain"])
def test_non_exact_identity_inventory_and_inactive_watch_do_not_trigger(change):
    row = event()
    if change == "role":
        row["quality_json"]["identity_roles"]["affected_entity"]["key"] = "wrong"
    elif change == "provisional":
        row["quality_json"]["identity_roles"]["affected_entity"]["provisional"] = True
    elif change == "ambiguous":
        row["identities"].append(deepcopy(row["identities"][0]))
    elif change == "inactive":
        row["entries"][0]["active"] = False
    elif change == "before":
        row["entries"][0]["active_from"] = NOW + timedelta(seconds=1)
    elif change == "expired":
        row["entries"][0]["expires_at"] = NOW
    elif change == "snapshot":
        row["semantic_type"] = "inventory.snapshot"
    else:
        row["entries"][0]["identity"]["domain_id"] += 1
    assert not evaluate(row)[0]


def test_five_minute_episode_is_stable_and_source_account_and_family_are_isolated():
    row = event()
    initial, = evaluate(row)[0]
    other = deepcopy(row)
    other["normalized_event_id"] = str(uuid4())
    other["source_event_id"] += 1
    other["occurred_at_utc"] = NOW + timedelta(seconds=1)
    repeated, = watch.evaluate(rule(), other, now=NOW + timedelta(seconds=1))[0]
    assert repeated.episode_key == initial.episode_key and repeated.signal_id != initial.signal_id
    other["occurred_at_utc"] = NOW + timedelta(minutes=5)
    assert watch.evaluate(rule(), other, now=NOW + timedelta(minutes=5))[0][0].episode_key != initial.episode_key
    changed_scope = replace(rule(), scope=replace(rule().scope, source_generation="synthetic-next"))
    assert evaluate(row, changed_scope)[0][0].episode_key != initial.episode_key
    other = deepcopy(row)
    other["event_id"] = 4722
    other["semantic_type"] = "directory.account.enabled"
    other["event_item"]["event_id"] = 4722
    assert evaluate(other)[0][0].episode_key != initial.episode_key


def test_enabled_watch_publishes_one_problem_both_message_formats_and_replay(smtp_delivery, telegram_delivery):
    selected = rule(evaluation_mode="enabled")
    cur = Cursor(selected)
    assert worker.run_once(cur, rule=selected, now=NOW)["jobs"] == 1
    item = qw.load_qw_signal(cur, signal_id=next(iter(cur.signals)))
    outcome = publish(cur, item)
    assert outcome.finding_created and outcome.risk_class.value == item.effective_severity == "medium"
    assert len(cur.findings) == len(cur.outbox) == len(cur.links) == 1
    job = {"id": str(uuid4()), "object_id": str(outcome.scenario_id), "object_kind": "semantic_finding",
           "finding_id": outcome.finding_id, "recipient_user_id": 2, "object_severity": "medium",
           "created_at": NOW.isoformat()}
    assert smtp.send(job | {"channel": "smtp"}, smtp_channel()) == "accepted"
    assert telegram.send(job | {"channel": "telegram"}, telegram_channel()) == telegram.Outcome("accepted")
    for text in (smtp_delivery[-1][0].get_content(), telegram_delivery[-1][0]["text"]):
        assert "Severity: medium" in text and f"/report/security.problems?id={outcome.finding_id}" in text
        assert IDENTITY["sid"] not in text
    restarted = Cursor(selected, cur.events)
    restarted.checks = cur.checks
    assert worker.run_once(restarted, rule=selected, now=NOW)["jobs"] == 0
    assert not publish(cur, item).finding_created
    assert len(cur.findings) == len(cur.outbox) == 1


@pytest.mark.parametrize("mode", ["test", "shadow"])
def test_preview_never_publishes_or_sends(mode):
    selected = rule(evaluation_mode=mode)
    cur = Cursor(selected)
    worker.run_once(cur, rule=selected, now=NOW)
    outcome = publish(cur, qw.load_qw_signal(cur, signal_id=next(iter(cur.signals))))
    assert outcome.finding_id is None and not cur.outbox


def test_registry_rechecked_before_publication_and_failed_policy_does_not_consume():
    selected = rule(evaluation_mode="enabled")
    cur = Cursor(selected)
    cur.admitted = False
    with pytest.raises(RuntimeError, match="account_watch_policy_unavailable"):
        worker.run_once(cur, rule=selected, now=NOW)
    assert not cur.checks and not cur.findings and not cur.outbox
    cur = Cursor(selected)
    worker.run_once(cur, rule=selected, now=NOW)
    item = qw.load_qw_signal(cur, signal_id=next(iter(cur.signals)))
    cur.events[0]["identities"] = []
    with pytest.raises(RuntimeError, match="account_watch_source_mismatch"):
        publish(cur, item)
    assert not cur.findings and not cur.outbox


def test_forged_context_and_severity_are_rejected():
    item, = evaluate()[0]
    with pytest.raises(ValueError, match="account_watch_signal_invalid"):
        replace(item, effective_severity="high")
    with pytest.raises(ValueError, match="account_watch_signal_invalid"):
        replace(item, watch_context=item.watch_context | {"source_event_id": 99})
    with pytest.raises(ValueError, match="account_watch_context_invalid"):
        replace(item, watch_context=item.watch_context | {"reason": "private"})
    with pytest.raises(ValueError, match="account_watch_context_invalid"):
        replace(item, watch_context=None)


def test_event_card_and_search_filter_use_published_priority_and_keep_confidence():
    from server.sli.events.event_search import _normalize_search_row
    from server.sli.events.event_search_projection import _semantic_filter_matches

    row = {**event()["event_item"], "id": 42, "time_created_utc": NOW.isoformat()}
    before = build_event_card(row)
    row["watch_priority"] = {"base_severity": "info", "effective_severity": "low", "reason": "watch"}
    card = build_event_card(row)
    assert card["severity"] == card["final_risk"] == card["final_security_severity"] == "low"
    assert card["base_risk"] == "info" and "watch" in card["reasons"]
    assert card["classification_origin"] == "contextual_rule"
    assert card["assessment_confidence"] == before["assessment_confidence"]
    projected = _normalize_search_row(row)
    assert _semantic_filter_matches(projected, {"risk": "low"})
    assert not _semantic_filter_matches(projected, {"risk": "info"})


def test_projection_is_bounded_hash_bound_and_does_not_disclose_registry(monkeypatch):
    calls = []
    priority = {"base_severity": "info", "effective_severity": "low", "reason": "watch"}
    def query(sql, params, **kwargs):
        calls.append((sql, params))
        return [{"id": 42, "watch_priority": priority}, {"id": 43, "watch_priority": None}]
    monkeypatch.setattr(projection, "query_rows_bounded", query)
    rows = [{"id": 42, "normalized_hash": bytes.fromhex("a" * 64)},
            {"id": 43, "normalized_hash": "B" * 64}]
    result = projection.attach_event_priorities(rows)
    assert result[0]["watch_priority"] == priority and result[1]["watch_priority"] is None
    assert calls[0][1] == (42, "a" * 64, 43, "b" * 64)
    assert "watch_entry_versions" not in calls[0][0]
    assert projection.attach_event_priorities([{"id": 42}]) == [{"id": 42}]
    assert len(calls) == 1
    with pytest.raises(ValueError, match="projection_limit"):
        projection.attach_event_priorities([{}] * 1002)
    assert len(projection.attach_event_priorities([{}] * 1001)) == 1001


def test_exact_details_apply_priority_after_storage_hydration(monkeypatch):
    from server.sli.events import event_details

    row = {**event()["event_item"], "id": 42, "time_created_utc": NOW.isoformat(), "normalized_hash": "A"*64}
    monkeypatch.setattr(event_details, "_get_v2_event_detail_by_id", lambda *a, **kw: row)
    monkeypatch.setattr(projection, "query_rows_bounded", lambda *a, **kw: [{
        "id": 42, "watch_priority": {"base_severity": "low", "effective_severity": "medium", "reason": "watch"}}])
    item, = event_details.get_event_detail_report_data(event_db_id=42)["items"]
    assert build_event_card(item)["final_security_severity"] == "medium"


def test_worker_entrypoint_commits_once_and_masks_private_errors(tmp_path, monkeypatch, capsys):
    from contextlib import contextmanager
    from dataclasses import asdict
    import json
    from scripts.runtime import account_watch_worker as command

    path = tmp_path / "synthetic-rule.json"
    path.write_text(json.dumps(asdict(rule())), encoding="utf-8")
    monkeypatch.setattr(command.sys, "argv", ["account_watch_worker", "--rule-file", str(path)])
    calls = []
    class Connection:
        @contextmanager
        def cursor(self):
            yield object()

        def commit(self):
            calls.append("commit")

    @contextmanager
    def connect():
        yield Connection()

    monkeypatch.setattr(command, "connect_semantic_worker", connect)
    monkeypatch.setattr(command, "run_once", lambda *a, **kw: {"state": "processed", "events": 1, "jobs": 1})
    assert command.main() == 0 and calls == ["commit"]
    assert json.loads(capsys.readouterr().out) == {"state": "processed", "events": 1, "jobs": 1}
    def fail():
        raise RuntimeError("synthetic-private-error")
    monkeypatch.setattr(command, "connect_semantic_worker", fail)
    assert command.main() == 1
    assert json.loads(capsys.readouterr().out) == {"state": "failed", "code": "account_watch_unavailable"}
    assert calls == ["commit"]

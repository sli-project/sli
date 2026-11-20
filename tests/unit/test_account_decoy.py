"""D02 account authentication, temporal identity and publication with fakes only."""
from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
from uuid import uuid4

import pytest

from server.sli.semantic import account_decoy as decoy, account_decoy_runtime as worker, qw_input as qw
from server.sli.core import notification_smtp as smtp, notification_telegram as telegram
from server.sli.semantic.semantic_risk_policy import compile_risk_policy
from tests.unit.test_qw_publication import Cursor as PublicationCursor, evaluate as publish, no_database as no_database
from tests.unit.test_qw_semantic_input import signal as generic_signal
from tests.unit.test_notification_smtp import delivery as smtp_delivery, channel as smtp_channel
from tests.unit.test_notification_telegram import delivery as telegram_delivery, channel as telegram_channel

NOW = generic_signal().occurred_at_utc
IDENTITY = {"domain_id": 7, "entity_id": 41, "sid": "S-1-5-21-100-200-300-9001",
            "guid": "00000000-0000-0000-0000-000000000041"}


def rule(**changes):
    return decoy.DecoyRule(scope=generic_signal().evidence_refs[0].scope, **changes)


def event(event_id=4624):
    key = "sid:" + IDENTITY["sid"]
    return {"normalized_event_id": "00000000-0000-0000-0000-000000000042", "source_event_id": 42,
            "event_id": event_id, "semantic_type": decoy.AUTHENTICATION[event_id], "occurred_at_utc": NOW,
            "roles_json": {"affected_entity": key}, "sha256": "a" * 64,
            "quality_json": {"identity_roles": {"affected_entity": {
                "key": key, "state": "resolved", "provisional": False}}},
            "identities": [{"role": "affected_entity", "key": key, "identity": deepcopy(IDENTITY)}],
            "labels": [{"id": "00000000-0000-0000-0000-000000000043", "revision": 1,
                        "kind": "account", "identity": deepcopy(IDENTITY), "active": True,
                        "active_from": (NOW-timedelta(hours=1)).isoformat(), "active_to": None}]}


def evaluate(row=None, selected=None):
    return decoy.evaluate(selected or rule(), row or event(), now=NOW)


class Cursor(PublicationCursor):
    def __init__(self, selected=None, rows=None):
        selected = selected or rule(evaluation_mode="enabled")
        self.events = rows if rows is not None else [event()]
        item, = evaluate(self.events[0], selected)[0]
        super().__init__(item)
        self.policies = [(decoy.risk_policy(selected, policy_id="fixture-qw"), selected.evaluation_mode)]
        self.allowed.update(ref.params for ref in item.evidence_refs)
        self.checks = {}

    def execute(self, sql, params=()):
        normalized = " ".join(sql.split()).lower()
        if "read_account_decoy_events(" in normalized:
            self.calls.append((normalized, params))
            self.rows = [row for row in self.events if (str(row["normalized_event_id"]) == params[-1]
                         if params[-1] else (params[-2], row["normalized_event_id"]) not in self.checks)]
        elif "insert into semantic_account_decoy_checks(" in normalized:
            self.checks[(params[0], params[1])] = params[-1]
            self.rows = []
        elif "pg_advisory_xact_lock(" in normalized:
            self.rows = []
        else:
            super().execute(sql, params)


@pytest.mark.parametrize("event_id", decoy.AUTHENTICATION)
@pytest.mark.parametrize("role", ["actor", "affected_entity"])
def test_exact_authentication_is_high_for_either_role(event_id, role):
    row = event(event_id)
    if role == "actor":
        row["roles_json"][role] = row["roles_json"].pop("affected_entity")
        row["quality_json"]["identity_roles"][role] = row["quality_json"]["identity_roles"].pop("affected_entity")
        row["identities"][0]["role"] = role
    items, state = evaluate(row)
    assert state == "observed" and len(items) == 1
    assert items[0].kind == "decoy" and items[0].base_severity == items[0].effective_severity == "high"
    assert items[0].decoy_context["label_revision"] == 1
    assert IDENTITY["sid"] not in str(items[0].document)


@pytest.mark.parametrize("change", ["snapshot", "other_sid", "other_guid", "other_entity", "other_domain",
    "inactive", "before", "end", "role_key", "unresolved", "no_candidate"])
def test_inventory_names_other_objects_and_inactive_intervals_do_not_trigger(change):
    row = event()
    if change == "snapshot":
        row["semantic_type"] = "directory.account.snapshot"
    elif change.startswith("other_"):
        key = change.removeprefix("other_")
        key = {"entity": "entity_id", "domain": "domain_id"}.get(key, key)
        row["identities"][0]["identity"][key] = 99 if key.endswith("_id") else "synthetic-other"
    elif change == "inactive":
        row["labels"][0]["active"] = False
    elif change == "before":
        row["labels"][0]["active_from"] = (NOW + timedelta(seconds=1)).isoformat()
    elif change == "end":
        row["labels"][0]["active_to"] = NOW.isoformat()
    elif change == "role_key":
        row["quality_json"]["identity_roles"]["affected_entity"]["key"] = "synthetic-other"
    elif change == "unresolved":
        row["quality_json"]["identity_roles"]["affected_entity"]["state"] = "unresolved"
    else:
        row["identities"] = []
    assert not evaluate(row)[0]


def name_only(row):
    key = "sam:synthetic.invalid:decoy-test"
    row["roles_json"]["affected_entity"] = key
    row["quality_json"]["identity_roles"]["affected_entity"] = {
        "key": key, "state": "provisional", "provisional": True}
    row["identities"][0]["key"] = key
    return row


def test_sidless_4625_requires_one_temporal_domain_name_match():
    row = name_only(event(4625))
    assert evaluate(row)[1] == "observed"
    row["identities"].append(deepcopy(row["identities"][0]))
    row["identities"][-1]["identity"]["guid"] = "synthetic-other"
    assert evaluate(row) == ((), "requires_review")
    assert evaluate(name_only(event(4624)))[0] == ()


def test_revision_and_every_source_dimension_are_part_of_signal_identity():
    initial, = evaluate()[0]
    for field, value in (("source_instance_id", "synthetic-other"), ("source_generation", "next"),
                         ("installation_id", "00000000-0000-0000-0000-000000000099")):
        other, = evaluate(selected=replace(rule(), scope=replace(rule().scope, **{field: value})))[0]
        assert other.signal_id != initial.signal_id and other.episode_key != initial.episode_key
    row = event()
    row["labels"][0]["revision"] = 2
    assert evaluate(row)[0][0].episode_key != initial.episode_key


def test_closed_label_version_is_used_for_late_events_and_replay_is_stable():
    row = event()
    row["labels"][0]["active_to"] = (NOW + timedelta(seconds=1)).isoformat()
    first, = evaluate(row)[0]
    later, = decoy.evaluate(rule(), row, now=NOW + timedelta(days=1))[0]
    assert first.signal_id == later.signal_id


@pytest.mark.parametrize("event_id", [4624, 4625])
def test_enabled_worker_publication_both_transports_and_restart_replay(event_id, smtp_delivery, telegram_delivery):
    selected = rule(evaluation_mode="enabled")
    cur = Cursor(selected, [event(event_id)])
    assert worker.run_once(cur, rule=selected, now=NOW)["jobs"] == 1
    item = qw.load_qw_signal(cur, signal_id=next(iter(cur.signals)))
    outcome = publish(cur, item)
    assert outcome.finding_created and outcome.risk_class.value == "high"
    assert len(cur.findings) == len(cur.outbox) == 1 and len(cur.links) == 1
    job = {"id": str(uuid4()), "object_id": str(outcome.scenario_id), "object_kind": "semantic_finding",
           "finding_id": outcome.finding_id, "recipient_user_id": 2, "object_severity": "high",
           "created_at": NOW.isoformat(), "decoy": "synthetic-private-account"}
    assert smtp.send(job | {"channel": "smtp"}, smtp_channel()) == "accepted"
    assert telegram.send(job | {"channel": "telegram"}, telegram_channel()) == telegram.Outcome("accepted")
    for text in (smtp_delivery[-1][0].get_content(), telegram_delivery[-1][0]["text"]):
        assert "Severity: high" in text and f"/report/security.problems?id={outcome.finding_id}" in text
        assert "synthetic-private" not in text and IDENTITY["sid"] not in text
    restarted = Cursor(selected, cur.events)
    restarted.checks = cur.checks
    assert worker.run_once(restarted, rule=selected, now=NOW)["jobs"] == 0
    assert not publish(cur, item).finding_created
    assert len(cur.findings) == len(cur.outbox) == 1


@pytest.mark.parametrize("mode", ["test", "shadow"])
def test_diagnostic_modes_do_not_publish_or_send(mode):
    selected = rule(evaluation_mode=mode)
    cur = Cursor(selected)
    assert worker.run_once(cur, rule=selected, now=NOW)["jobs"] == 1
    outcome = publish(cur, qw.load_qw_signal(cur, signal_id=next(iter(cur.signals))))
    assert outcome.finding_id is None and not cur.findings and not cur.outbox


def test_failed_policy_admission_does_not_consume_event():
    selected = rule(evaluation_mode="enabled")
    cur = Cursor(selected)
    cur.admitted = False
    with pytest.raises(RuntimeError, match="account_decoy_policy_unavailable"):
        worker.run_once(cur, rule=selected, now=NOW)
    assert not cur.checks and not cur.findings and not cur.outbox


def test_evidence_and_label_are_rechecked_before_publication():
    selected = rule(evaluation_mode="enabled")
    cur = Cursor(selected)
    worker.run_once(cur, rule=selected, now=NOW)
    item = qw.load_qw_signal(cur, signal_id=next(iter(cur.signals)))
    cur.events[0]["identities"] = []
    with pytest.raises(RuntimeError, match="account_decoy_source_mismatch"):
        publish(cur, item)
    assert not cur.findings and not cur.outbox


def test_native_hash_or_source_access_denial_happens_before_any_durable_admission():
    from server.sli.storage.evidence_ref import EvidenceRefError

    selected = rule(evaluation_mode="enabled")
    cur = Cursor(selected)
    cur.allowed.clear()
    with pytest.raises(EvidenceRefError):
        worker.run_once(cur, rule=selected, now=NOW)
    assert not cur.checks and not cur.signals and not cur.jobs


def test_unambiguous_guid_is_supported_but_arbitrary_role_text_is_not():
    row = event()
    key = "guid:" + IDENTITY["guid"]
    row["roles_json"]["affected_entity"] = key
    row["quality_json"]["identity_roles"]["affected_entity"]["key"] = key
    row["identities"][0]["key"] = key
    assert evaluate(row)[1] == "observed"
    row["roles_json"]["affected_entity"] = "arbitrary-mention"
    row["quality_json"]["identity_roles"]["affected_entity"]["key"] = "arbitrary-mention"
    row["identities"][0]["key"] = "arbitrary-mention"
    assert evaluate(row) == ((), "requires_review")


def test_both_roles_in_one_event_produce_one_touch_and_ambiguous_match_is_diagnostic():
    row = event()
    row["roles_json"]["actor"] = row["roles_json"]["affected_entity"]
    row["quality_json"]["identity_roles"]["actor"] = row["quality_json"]["identity_roles"]["affected_entity"]
    row["identities"].append(row["identities"][0] | {"role": "actor"})
    assert len(evaluate(row)[0]) == 1
    cur = Cursor()
    cur.events = [name_only(event(4625))]
    cur.events[0]["identities"].append(deepcopy(cur.events[0]["identities"][0]))
    result = worker.run_once(cur, rule=rule(evaluation_mode="enabled"), now=NOW)
    assert result["results"] == {"requires_review": 1} and result["jobs"] == 0
    assert not cur.signals and not cur.findings and not cur.outbox


def test_reader_binds_every_source_dimension_and_specific_normalization_for_rechecks():
    class Reader:
        def execute(self, sql, params):
            self.sql, self.params = sql, params

        def fetchall(self):
            return []

    cur, selected = Reader(), rule()
    assert worker.read_events(cur, selected, normalized_event_id=event()["normalized_event_id"]) == []
    scope = selected.scope
    assert cur.params == (scope.installation_id, scope.plugin_id, scope.source_instance_id, scope.source_generation,
                          selected.checkpoint_key, event()["normalized_event_id"])


def test_late_normalizer_revision_preserves_one_problem_and_independent_event_is_separate():
    selected = rule(evaluation_mode="enabled")
    cur = Cursor(selected)
    worker.run_once(cur, rule=selected, now=NOW)
    first = publish(cur, qw.load_qw_signal(cur, signal_id=next(iter(cur.signals))))
    cur.events[0]["normalized_event_id"] = "00000000-0000-0000-0000-000000000099"
    revised, = decoy.evaluate(selected, cur.events[0], now=NOW)[0]
    assert publish(cur, revised).finding_id == first.finding_id
    assert len(cur.findings) == len(cur.outbox) == 1
    cur.events[0]["source_event_id"] = 43
    cur.events[0]["normalized_event_id"] = "00000000-0000-0000-0000-000000000100"
    other, = decoy.evaluate(selected, cur.events[0], now=NOW)[0]
    assert publish(cur, other).finding_id != first.finding_id
    assert len(cur.findings) == len(cur.outbox) == 2


def test_worker_entrypoint_uses_one_transaction_and_does_not_expose_connection_errors(tmp_path, monkeypatch, capsys):
    from contextlib import contextmanager
    from dataclasses import asdict
    import json
    from scripts.runtime import account_decoy_worker as command

    path = tmp_path / "synthetic-rule.json"
    path.write_text(json.dumps(asdict(rule())), encoding="utf-8")
    monkeypatch.setattr(command.sys, "argv", ["account_decoy_worker", "--rule-file", str(path)])
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
        raise RuntimeError("synthetic-private-connection")

    monkeypatch.setattr(command, "connect_semantic_worker", fail)
    assert command.main() == 1
    assert json.loads(capsys.readouterr().out) == {"state": "failed", "code": "account_decoy_unavailable"}
    assert calls == ["commit"]


def test_policy_cannot_downgrade_high_and_contract_cannot_drop_context():
    item, = evaluate()[0]
    with pytest.raises(ValueError, match="account_decoy_context_invalid"):
        replace(item, decoy_context=None)
    with pytest.raises(ValueError, match="account_decoy_signal_invalid"):
        replace(item, effective_severity="medium", base_severity="medium")
    cur = Cursor(rule())
    policy = decoy.risk_policy(rule(), policy_id="fixture-qw")
    policy = replace(policy, definition=policy.definition | {"risk": {
        "class": "medium", "raw_score": "25", "display_points": 25, "rationale": "synthetic"}})
    qw.enqueue_qw_signal_risk_jobs(cur, signal=item)
    with pytest.raises(RuntimeError, match="account_decoy_policy_invalid"):
        qw.qw_signal_proposal(cur, policy=compile_risk_policy(policy), source_id=item.signal_id)


@pytest.mark.parametrize("mode", ["live", "historical_replay", "history_import"])
def test_processing_provenance_survives_detector_admission_and_native_recheck(mode):
    selected = rule(evaluation_mode="enabled", processing_mode=mode)
    cur = Cursor(selected)
    assert worker.run_once(cur, rule=selected, now=NOW + timedelta(hours=2))["jobs"] == 1
    item = qw.load_qw_signal(cur, signal_id=next(iter(cur.signals)))
    assert item.processing_mode == mode
    worker.verify_signal(cur, item)
    assert item.received_at_utc - item.occurred_at_utc == timedelta(hours=2)
    assert ("processing_mode" in item.document) == (mode != "live")
    assert item.decoy_context["label_id"] == event()["labels"][0]["id"]
    assert item.decoy_context["label_revision"] == 1


def test_live_checkpoints_and_signal_ids_remain_compatible():
    from dataclasses import asdict
    selected = rule()
    old_document = asdict(selected)
    old_document.pop("processing_mode")
    assert selected.checkpoint_key == qw._digest(old_document)
    item = evaluate()[0][0]
    assert "processing_mode" not in item.document
    assert item.signal_id == qw._digest({key: value for key, value in item.document.items() if key != "received_at_utc"})


@pytest.mark.parametrize("mode", ["unknown", "pipeline_delay"])
def test_invalid_processing_provenance_is_rejected(mode):
    with pytest.raises(ValueError):
        rule(processing_mode=mode)

"""D03 native file touches, publication and replay; no real database."""
from copy import deepcopy
from dataclasses import replace
from datetime import timedelta

import pytest

from server.sli.semantic import file_decoy as decoy, file_decoy_runtime as worker, qw_input as qw
from tests.unit.test_qw_publication import Cursor as PublicationCursor, evaluate as publish, no_database as no_database
from tests.unit.test_qw_semantic_input import signal as generic_signal
from tests.unit.test_notification_smtp import delivery as smtp_delivery, channel as smtp_channel
from tests.unit.test_notification_telegram import delivery as telegram_delivery, channel as telegram_channel

NOW = generic_signal().occurred_at_utc
AGENT = "00000000-0000-4000-8000-000000000001"
LABEL = "00000000-0000-4000-8000-000000000003"
PATH = r"c:\synthetic-decoys\bait.txt"


def rule(**changes):
    return decoy.FileDecoyRule(scope=generic_signal("file_audit_observation").evidence_refs[0].scope,
                               agent_id=AGENT, **changes)


def event(event_id=4663, outcome="success", **changes):
    selected = rule()
    observation = {"evidence_key": "a" * 64, "payload_sha256": "b" * 64, "event_id": event_id,
        "agent_id": AGENT, "source_instance_id": selected.scope.source_instance_id,
        "generation": selected.scope.source_generation, "policy_revision": "4", "record_id": 10,
        "observed_at": NOW.isoformat(), "path": PATH, "excluded": True,
        "scopes": [{"collection_scope_id": selected.scope.collection_scope_id, "important": False}],
        "facts": {"outcome": outcome, "access_mask": 1, "object_type": "File", "subject_user_sid": "S-1-5-18",
                  "logon_id_numeric": 42, "server_process_id": 7, "handle_id": 9}}
    observation.update(changes)
    identity = {"agent_id": AGENT, "source_instance_id": selected.scope.source_instance_id,
                "collection_scope_id": selected.scope.collection_scope_id, "path": PATH}
    return {"observation": observation, "contexts": [], "labels": [{"id": LABEL, "revision": 1,
        "kind": "file", "identity": identity, "active": True,
        "active_from": (NOW-timedelta(hours=1)).isoformat(), "active_to": None}]}


def evaluate(row=None, selected=None):
    return decoy.evaluate(selected or rule(), row or event(), now=NOW)


class Cursor(PublicationCursor):
    def __init__(self, selected=None, row=None):
        selected = selected or rule(evaluation_mode="enabled")
        self.events = [row or event()]
        item, = evaluate(self.events[0], selected)[0]
        super().__init__(item)
        self.policies = [(decoy.risk_policy(selected, policy_id="fixture-qw"), selected.evaluation_mode)]
        self.checks = set()

    def execute(self, sql, params=()):
        normalized = " ".join(sql.split()).lower()
        if "read_file_decoy_observations(" in normalized:
            self.rows = [row for row in self.events if (row["observation"]["evidence_key"] == params[-1]
                         if params[-1] else (params[-2], row["observation"]["evidence_key"]) not in self.checks)]
        elif "insert into semantic_file_decoy_checks(" in normalized:
            self.checks.add((params[0], params[1]))
            self.rows = []
        elif "pg_advisory_xact_lock(" in normalized:
            self.rows = []
        else:
            super().execute(sql, params)


@pytest.mark.parametrize("event_id,outcome,meaning", [
    (4663, "success", "read"), (4656, "success", "access_check"), (5145, "success", "access_check"),
    (4656, "failure", "access_denied"), (5145, "failure", "access_denied"),
    (4670, "success", "permissions_changed"),
])
def test_native_touch_is_high_before_mass_action_exclusions(event_id, outcome, meaning):
    items, state = evaluate(event(event_id, outcome))
    assert state == "observed" and len(items) == 1
    item = items[0]
    assert item.base_severity == item.effective_severity == "high"
    assert item.file_decoy_context["meaning"] == meaning
    assert item.evidence_refs[0].storage_kind == "file_audit_observation"
    assert PATH not in str(item.document) and "S-1-5-18" not in str(item.document)


@pytest.mark.parametrize("change", ["inventory", "neighbor", "other_agent", "other_source", "other_generation",
    "other_root", "inactive", "before", "end", "future", "unproven_delete", "unknown_outcome", "directory"])
def test_non_touches_and_unrelated_scopes_are_not_decoy_use(change):
    row = event()
    obs = row["observation"]
    if change == "inventory":
        obs["event_id"] = 0
    elif change == "neighbor":
        obs["path"] += ".neighbor"
    elif change.startswith("other_"):
        key = {"agent": "agent_id", "source": "source_instance_id", "generation": "generation"}.get(change[6:])
        if key:
            obs[key] = "synthetic-other"
        else:
            obs["scopes"][0]["collection_scope_id"] = "synthetic-other"
    elif change == "inactive":
        row["labels"][0]["active"] = False
    elif change == "before":
        row["labels"][0]["active_from"] = NOW + timedelta(seconds=1)
    elif change == "end":
        row["labels"][0]["active_to"] = NOW
    elif change == "future":
        obs["observed_at"] = (NOW+timedelta(seconds=1)).isoformat()
    elif change == "unproven_delete":
        obs.update(event_id=4660, path=None, scopes=[])
    elif change == "unknown_outcome":
        obs["facts"]["outcome"] = "unknown"
    else:
        obs["facts"]["object_type"] = "Directory"
    assert evaluate(row)[0] == ()


def test_read_right_and_delete_right_are_never_promoted_to_completed_operations():
    row = event()
    row["observation"]["facts"]["access_mask"] = 0x10000
    assert evaluate(row)[0][0].file_decoy_context["meaning"] == "file_action"
    assert evaluate(event(4656))[0][0].file_decoy_context["meaning"] == "access_check"
    row["observation"]["facts"].pop("object_type")
    row["observation"]["facts"]["access_mask"] = 1
    assert evaluate(row)[0][0].file_decoy_context["meaning"] == "file_action"


def test_confirmed_delete_keeps_both_witnesses_and_rejects_reused_handle():
    row = event(4660, path=None, scopes=[])
    prior = deepcopy(event()["observation"])
    prior.update(evidence_key="c"*64, record_id=9)
    row["contexts"] = [prior]
    item, = evaluate(row)[0]
    assert item.file_decoy_context["meaning"] == "deleted" and len(item.evidence_refs) == 2
    reused = deepcopy(prior)
    reused.update(evidence_key="d"*64, record_id=8, path=PATH+".other")
    row["contexts"].append(reused)
    assert not evaluate(row)[0]


@pytest.mark.parametrize("event_id,outcome", [(4663, "success"), (4656, "failure")])
def test_enabled_publication_and_restart_replay(event_id, outcome):
    selected = rule(evaluation_mode="enabled")
    cur = Cursor(selected, event(event_id, outcome))
    assert worker.run_once(cur, rule=selected, now=NOW)["jobs"] == 1
    item = qw.load_qw_signal(cur, signal_id=next(iter(cur.signals)))
    result = publish(cur, item)
    assert result.finding_created and result.risk_class.value == "high"
    assert len(cur.findings) == len(cur.outbox) == 1
    assert worker.run_once(cur, rule=selected, now=NOW)["jobs"] == 0
    restarted = Cursor(selected, cur.events[0])
    restarted.checks = cur.checks
    assert worker.run_once(restarted, rule=selected, now=NOW)["jobs"] == 0
    assert not publish(cur, item).finding_created
    assert len(cur.findings) == len(cur.outbox) == 1


def test_historical_label_interval_is_used_after_disable_and_path_case_is_normalized():
    row = event(path="C:/SYNTHETIC-DECOYS/BAIT.txt")
    row["labels"][0]["active_to"] = (NOW+timedelta(seconds=1)).isoformat()
    item, = evaluate(row)[0]
    later = decoy.evaluate(rule(), row, now=NOW+timedelta(days=1))[0][0]
    assert later.signal_id == item.signal_id
    row["observation"]["observed_at"] = (NOW+timedelta(seconds=1)).isoformat()
    assert decoy.evaluate(rule(), row, now=NOW+timedelta(days=1))[0] == ()


@pytest.mark.parametrize("mode", ["test", "shadow"])
def test_diagnostic_modes_do_not_publish(mode):
    selected = rule(evaluation_mode=mode)
    cur = Cursor(selected)
    worker.run_once(cur, rule=selected, now=NOW)
    result = publish(cur, qw.load_qw_signal(cur, signal_id=next(iter(cur.signals))))
    assert result.finding_id is None and not cur.findings and not cur.outbox


def test_label_and_native_evidence_are_rechecked_before_publication():
    cur = Cursor()
    worker.run_once(cur, rule=rule(evaluation_mode="enabled"), now=NOW)
    item = qw.load_qw_signal(cur, signal_id=next(iter(cur.signals)))
    cur.events[0]["labels"] = []
    with pytest.raises(RuntimeError, match="file_decoy_source_mismatch"):
        publish(cur, item)
    assert not cur.findings and not cur.outbox


def test_high_and_required_context_are_bound_to_rule():
    item, = evaluate()[0]
    for changes in ({"file_decoy_context": None}, {"base_severity": "medium", "effective_severity": "medium"}):
        with pytest.raises(ValueError):
            replace(item, **changes)


def test_session_witnesses_group_but_subjects_roots_and_label_versions_are_isolated():
    first = evaluate()[0][0]
    row = event(4656)
    row["observation"]["evidence_key"] = "c"*64
    assert evaluate(row)[0][0].episode_key == first.episode_key
    row["observation"]["facts"]["subject_user_sid"] = "S-1-5-19"
    assert evaluate(row)[0][0].episode_key != first.episode_key
    selected = rule()
    other = replace(selected, scope=replace(selected.scope, collection_scope_id="synthetic-other-root"))
    row = event()
    row["observation"]["scopes"][0]["collection_scope_id"] = other.scope.collection_scope_id
    row["labels"][0]["identity"]["collection_scope_id"] = other.scope.collection_scope_id
    assert evaluate(row, other)[0][0].episode_key != first.episode_key
    row = event()
    row["labels"][0]["revision"] = 2
    assert evaluate(row)[0][0].episode_key != first.episode_key


def test_both_transports_accept_only_safe_summary(smtp_delivery, telegram_delivery):
    from server.sli.core import notification_smtp as smtp, notification_telegram as telegram
    from uuid import uuid4

    cur = Cursor()
    result = publish(cur, evaluate(selected=rule(evaluation_mode="enabled"))[0][0])
    job = {"id": str(uuid4()), "object_id": str(result.scenario_id), "object_kind": "semantic_finding",
        "finding_id": result.finding_id, "recipient_user_id": 2, "object_severity": "high", "created_at": NOW.isoformat(),
        "private_path": PATH}
    assert smtp.send(job | {"channel": "smtp"}, smtp_channel()) == "accepted"
    assert telegram.send(job | {"channel": "telegram"}, telegram_channel()) == telegram.Outcome("accepted")
    for text in (smtp_delivery[-1][0].get_content(), telegram_delivery[-1][0]["text"]):
        assert "Severity: high" in text and f"/report/security.problems?id={result.finding_id}" in text
        assert PATH not in text and AGENT not in text


def test_policy_and_hash_failures_do_not_consume_observation():
    from server.sli.storage.evidence_ref import EvidenceRefError

    cur = Cursor()
    cur.admitted = False
    with pytest.raises(RuntimeError, match="file_decoy_policy_unavailable"):
        worker.run_once(cur, rule=rule(evaluation_mode="enabled"), now=NOW)
    assert not cur.checks and not cur.findings and not cur.outbox
    cur = Cursor()
    cur.allowed.clear()
    with pytest.raises(EvidenceRefError):
        worker.run_once(cur, rule=rule(evaluation_mode="enabled"), now=NOW)
    assert not cur.checks and not cur.signals


def test_native_admission_read_is_detected_even_when_action_projection_excludes_it():
    from server.sli.plugins.file_audit.correlation import project_actions
    from tests.unit.test_file_audit_correlation import observation

    obs = observation(1, mask="0x1", ObjectType="File")
    assert project_actions(obs) == []
    selected = rule()
    selected = replace(selected, agent_id=obs["agent_id"], scope=replace(selected.scope,
        source_instance_id=obs["source_instance_id"], source_generation=obs["generation"],
        collection_scope_id=obs["scopes"][0]["collection_scope_id"]))
    row = event()
    row["observation"] = obs
    row["labels"][0]["identity"] = {"agent_id": selected.agent_id,
        "source_instance_id": selected.scope.source_instance_id, "collection_scope_id": selected.scope.collection_scope_id,
        "path": obs["path"].lower()}
    row["labels"][0]["active_from"] = utc_time = decoy.utc(obs["observed_at"])
    items, state = decoy.evaluate(selected, row, now=utc_time)
    assert state == "observed" and items[0].file_decoy_context["meaning"] == "read"


def test_worker_entrypoint_commits_one_transaction_and_hides_exceptions(tmp_path, monkeypatch, capsys):
    from contextlib import contextmanager
    from dataclasses import asdict
    import json
    from scripts.runtime import file_decoy_worker as command

    path = tmp_path / "synthetic-rule.json"
    path.write_text(json.dumps(asdict(rule())), encoding="utf-8")
    monkeypatch.setattr(command.sys, "argv", ["file_decoy_worker", "--rule-file", str(path)])
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
    monkeypatch.setattr(command, "run_once", lambda *a, **kw: {"state": "processed", "jobs": 1})
    assert command.main() == 0 and calls == ["commit"]
    assert json.loads(capsys.readouterr().out) == {"state": "processed", "jobs": 1}

    def fail():
        raise RuntimeError("synthetic-private-connection")

    monkeypatch.setattr(command, "connect_semantic_worker", fail)
    assert command.main() == 1
    assert json.loads(capsys.readouterr().out) == {"state": "failed", "code": "file_decoy_unavailable"}


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
    assert item.file_decoy_context["label_id"] == LABEL
    assert item.file_decoy_context["label_revision"] == 1


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


@pytest.mark.parametrize("locale,wording", [("ru", "с задержкой 120 мин"), ("en", "delayed by 120 min")])
def test_pipeline_delay_is_delivered_with_safe_delay_notice_in_both_channels(locale, wording, smtp_delivery, telegram_delivery):
    from uuid import uuid4
    from server.sli.core import notification_smtp as smtp, notification_telegram as telegram
    item = {"id": str(uuid4()), "object_id": str(uuid4()), "object_kind": "semantic_finding",
            "finding_id": 42, "recipient_user_id": 2, "object_severity": "high", "created_at": NOW.isoformat(),
            "delivery_reason": "pipeline_delay", "delay_minutes": 120, "language": locale, "private_path": PATH}
    assert smtp.send(item | {"channel": "smtp"}, smtp_channel()) == "accepted"
    assert telegram.send(item | {"channel": "telegram"}, telegram_channel()) == telegram.Outcome("accepted")
    assert wording in str(smtp_delivery[-1][0]["Subject"])
    for text in (smtp_delivery[-1][0].get_content(), telegram_delivery[-1][0]["text"]):
        assert wording in text and "Problem: 42" in text
        assert PATH not in text and AGENT not in text

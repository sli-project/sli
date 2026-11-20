"""Attested packet contracts, ingress receipts and core dispatcher routing."""
from copy import deepcopy

from cryptography.hazmat.primitives.asymmetric import ec
import pytest

from server.sli.agent_ingest import receive_packet
from server.sli.plugins.file_audit.agent_ingest import packet_rows
from sli_agent.envelope import make_packet
from tests.unit.test_agent_ingest import Ledger
from tests.unit.test_file_audit_collection import NOW, collector, xml
from tests.unit.test_file_audit_contracts import AGENT, settings


def packet():
    key = ec.generate_private_key(ec.SECP256R1())
    sample = collector(reader=lambda *_: [(xml(1), "b1")], path_check=lambda *_: "file").collect(now=NOW)
    value = make_packet(key, agent_id=AGENT, sequence=1, sample=sample, now=NOW)
    assignment = {"module_id": "sli.file-audit", "enabled": True, "config": settings()}
    identity = {"id": AGENT, "host_id": AGENT, "assigned_modules": [assignment]}
    return key, value, identity, assignment


def test_initial_empty_window_is_attested_and_cannot_be_forged():
    import json
    from datetime import timedelta
    from sli_agent.envelope import canonical
    config = {**settings(), 'initial_read_hours': 0}
    key = ec.generate_private_key(ec.SECP256R1())
    sample = collector(config, reader=lambda *_: []).collect(now=NOW)
    value = make_packet(key, agent_id=AGENT, sequence=1, sample=sample, now=NOW)
    assignment = {'module_id': 'sli.file-audit', 'enabled': True, 'config': config}
    identity = {'id': AGENT, 'host_id': AGENT}
    assert packet_rows(identity, assignment, value['envelope'], value['payload']) == []
    cursor = json.loads(value['envelope']['cursor_after']['token'])
    cursor['since_utc'] = (NOW + timedelta(minutes=1)).isoformat()
    value['envelope']['cursor_after']['token'] = canonical(cursor).decode()
    with pytest.raises(ValueError, match='initial_window_invalid'):
        packet_rows(identity, assignment, value['envelope'], value['payload'])


def test_capture_receipt_replay_and_pending_core_import():
    key, value, identity, _ = packet()
    ledger = Ledger()
    result = receive_packet(ledger, identity=identity, public_key=key.public_key(), value=value, now=NOW)
    assert result["status"] == "committed"
    assert len(ledger.imports) == 1
    retry = receive_packet(ledger, identity=identity, public_key=key.public_key(), value=value, now=NOW)
    assert retry["status"] == "duplicate" and len(ledger.imports) == 1


@pytest.mark.parametrize("change", [
    lambda v: v["envelope"].update(source_instance_id="synthetic-other"),
    lambda v: v["envelope"].update(policy_revision="2"),
    lambda v: v["envelope"].update(filtered_count=1),
    lambda v: v["payload"]["records"][0]["payload"].update(event_id=4670),
    lambda v: v["payload"]["records"][0]["payload"].update(xml=xml(1, path=r"C:\other\item")),
    lambda v: v["payload"]["context"].update(lost_count=-1),
])
def test_signed_fields_cannot_override_native_identity_policy_or_scope(change):
    _, value, identity, assignment = packet()
    change(value)
    with pytest.raises(ValueError):
        packet_rows(identity, assignment, value["envelope"], value["payload"])


def test_dispatch_uses_plugin_hook_without_starting_plugin_worker(monkeypatch):
    from server.sli.agents import consumer
    seen = []
    monkeypatch.setattr(consumer, "plugin_hook", lambda plugin, hook: lambda *args, **kwargs: seen.append((plugin, hook)))
    consumer.dispatch_packet(None, [], packet={}, envelope={"module_id": "sli.file-audit"})
    assert seen == [("sli.file-audit", "import_file_audit_agent_packet")]


def test_old_revision_requires_retained_owner_assignment():
    from server.sli.plugins.file_audit.agent_ingest import admitted_rows
    _, value, identity, assignment = packet()
    identity = deepcopy(identity)
    identity["assigned_modules"][0]["config"]["policy_revision"] = "2"
    with pytest.raises(ValueError):
        admitted_rows(Ledger(), identity, value["envelope"], value["payload"])
    ledger = Ledger()
    ledger.policy_assignment = lambda *_: assignment
    assert admitted_rows(ledger, identity, value["envelope"], value["payload"])


def test_assignment_is_revisioned_and_private_source_settings_are_only_hashed():
    import hashlib
    import json

    from server.sli.agents import policies
    from tests.unit.test_agent_policies import Cursor
    cur = Cursor()
    body = {"agent_id": str(cur.agent["id"]), "module_id": "sli.file-audit",
        "enabled": True, "expected_revision": 1, "config": {**settings(), "source_name": "synthetic-source"}}
    result = policies.assign_module(cur, body, actor="session:1")
    assert result["policy_revision"] == 2
    issued = result["assigned_modules"][0]
    assert issued["config"]["policy_revision"] == "2"
    assert issued["config"]["source_name"] == "synthetic-source"
    assert cur.history[(body["agent_id"], 1)] == []
    assert cur.history[(body["agent_id"], 2)] == result["assigned_modules"]
    retention = [(index, params) for index, (sql, params) in enumerate(cur.calls)
        if sql == "select sli_plugin_file_audit.retain_assignment_policy(%s,%s,%s)"]
    assert len(retention) == 1
    retained_at, retained_params = retention[0]
    assert retained_params == (body["agent_id"], "session", 1)
    assignment_at = next(index for index, (sql, _) in enumerate(cur.calls)
        if sql.startswith("update sli_agents set assigned_modules"))
    audit_at = next(index for index, (sql, _) in enumerate(cur.calls)
        if sql.startswith("insert into sli_agent_audit"))
    assert assignment_at < retained_at < audit_at
    assert cur.retained_policies == [{"params": retained_params, "call_index": retained_at,
        "policy_revision": 2, "assigned_modules": result["assigned_modules"], "audit_count": 0}]
    digest = hashlib.sha256(json.dumps(issued["config"], sort_keys=True).encode()).hexdigest()
    assert cur.audits == [("module_assign", {"module_id": "sli.file-audit", "enabled": True,
        "policy_sha256": digest, "revision": 2, "channels": ["Security"],
        "changed_fields": sorted(body["config"])})]
    assert cur.calls[audit_at][1][1:3] == ("session:1", body["agent_id"])
    assert "synthetic-source" not in str(cur.audits)


def test_xml_prefix_spelling_does_not_change_native_field_admission():
    _, value, identity, assignment = packet()
    row = value["payload"]["records"][0]["payload"]
    row["xml"] = row["xml"].replace("ns0:", "file:").replace("xmlns:ns0=", "xmlns:file=")
    assert packet_rows(identity, assignment, value["envelope"], value["payload"]) == [row]

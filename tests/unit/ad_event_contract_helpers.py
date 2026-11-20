"""Fixed synthetic inputs for the PR 3 pre-relocation contract snapshot."""
from copy import deepcopy
from dataclasses import asdict, is_dataclass, replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from unittest.mock import patch
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric import ec

from server.sli import agent_ingest
from sli_agent.ad_dc import ADDCModule
from sli_agent.envelope import EnvelopeError, make_packet

NOW = datetime(2026, 10, 9, 12, tzinfo=timezone.utc)
AGENT = "00000000-0000-4000-8000-000000000001"
HOST = "00000000-0000-4000-8000-000000000002"
CONFIG = {"source_name": "fixture-dc", "connect_address": "fixture-endpoint"}


def event_xml(event_id, record_id):
    return (f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
            '<Provider Name="Microsoft-Windows-Security-Auditing"/>'
            f'<EventID>{event_id}</EventID><EventRecordID>{record_id}</EventRecordID>'
            '<Channel>Security</Channel><Computer>fixture-dc</Computer>'
            '<TimeCreated SystemTime="2026-10-09T12:00:00Z"/></System><EventData>'
            '<Data Name="TargetUserName">fixture-account</Data>'
            '<Data Name="TargetUserSid">S-1-5-21-100-200-300-1001</Data>'
            '<Data Name="LogonType">3</Data></EventData></Event>')


class Ledger:
    """Ingress storage with real signature checks and no database."""
    def __init__(self):
        self.entries = []
        self.retained = None
        self.history_reads = []

    def get(self, agent, module, sequence):
        return next((item for item in self.entries if item["envelope"]["sequence"] == sequence), None)

    def packet_exists(self, packet_id):
        return any(item["envelope"]["packet_id"] == packet_id for item in self.entries)

    def latest(self, *_):
        return self.entries[-1]["envelope"] if self.entries else None

    def binding(self, *_):
        return {"source_instance_id": HOST, "source_name": CONFIG["source_name"], "channel": "ad-dc",
                "module_version": "1.0.0", "policy_revision": "1"}

    def policy_assignment(self, agent, module, revision):
        self.history_reads.append([agent, module, revision])
        return self.retained

    def quota_error(self, *_):
        return None

    def commit(self, value, receipt, envelope_hash, rows):
        self.entries.append(deepcopy({"envelope": value["envelope"], "payload": value["payload"],
                                     "receipt": receipt, "envelope_sha256": envelope_hash, "rows": rows}))


def packet_contract_snapshot(build_policy, event_rows):
    """Only random signatures are omitted; payloads, hashes and evidence stay exact."""
    key = ec.generate_private_key(ec.SECP256R1())
    policies = {}
    for name, extra in (("default", {}), ("filtered", {"channels": {"System": False}, "allow_event_ids": [4624]}),
                        ("disabled", {"channels": dict.fromkeys(("Security", "System", "Directory Service"), False)}),
                        ("revision", {"policy_revision": "3", "batch_size": 1}),
                        ("invalid", {"allow_event_ids": [65535]})):
        try:
            policies[name] = build_policy(HOST, {**CONFIG, **extra})
        except ValueError as exc:
            policies[name] = {"error": str(exc)}
    outcomes = {}
    for case in ("events", "zero", "partial", "read_error", "old_revision", "missing_revision",
                 "assignment", "channel", "source", "native_channel", "bad_signature", "replay", "cursor_fork"):
        ledger = Ledger()
        identity = {"id": AGENT, "host_id": HOST, "assigned_modules": [
            {"module_id": "sli.windows.ad-dc", "enabled": True, "config": deepcopy(CONFIG)}]}

        def reader(*_):
            if case == "read_error":
                raise RuntimeError("synthetic read unavailable")
            if case == "zero":
                return []
            return [(event_xml(4624, 1), "fixture-bookmark-1"),
                    (event_xml(65535 if case == "partial" else 4625, 2), "fixture-bookmark-2")]

        collector = ADDCModule(HOST, CONFIG, reader=reader)
        sample = collector.collect(now=NOW)
        if case == "channel":
            sample = replace(sample, channel="Security")
        elif case == "source":
            sample = replace(sample, source_instance_id=AGENT)
        elif case == "native_channel":
            sample.payload["records"][0]["payload"]["xml"] = event_xml(4624, 1).replace(
                "<Channel>Security</Channel>", "<Channel>System</Channel>")
        elif case == "assignment":
            identity["assigned_modules"] = []
        elif case in ("old_revision", "missing_revision"):
            ledger.retained = deepcopy(identity["assigned_modules"][0]) if case == "old_revision" else None
            identity["assigned_modules"][0]["config"].update(policy_revision="3", allow_event_ids=[4625])
        with patch("sli_agent.envelope.uuid4", return_value=UUID("00000000-0000-4000-8000-000000000003")):
            value = make_packet(key, agent_id=AGENT, sequence=1, sample=sample, now=NOW)
        binding = ledger.binding()
        try:
            validated = event_rows(value["envelope"], value["payload"], binding, policies["default"])
        except ValueError as exc:
            validated = {"error": str(exc)}
        if case == "bad_signature":
            value["signature"] = "AAAA"

        def receive(packet, received_at=NOW):
            try:
                return agent_ingest.receive_packet(ledger, identity=identity, public_key=key.public_key(),
                                                   value=packet, now=received_at)
            except EnvelopeError as exc:
                return {"error": str(exc)}

        receipt = receive(value, NOW + timedelta(days=8) if case == "replay" else NOW)
        duplicate = receive(value) if receipt.get("status") == "committed" else None
        fork = None
        if case == "cursor_fork":
            with patch("sli_agent.envelope.uuid4", return_value=UUID("00000000-0000-4000-8000-000000000004")):
                fork = receive(make_packet(key, agent_id=AGENT, sequence=2, sample=sample, now=NOW))
        outcomes[case] = {"envelope": value["envelope"], "payload": value["payload"], "validated": validated,
                          "receipt": receipt, "duplicate": duplicate, "fork": fork,
                          "entries": ledger.entries, "history_reads": ledger.history_reads}
    return {"policies": policies, "packets": outcomes}


def _plain(value):
    if is_dataclass(value):
        return _plain(asdict(value))
    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain(item) for item in value]
    return value


def normalization_snapshot(normalizer):
    """Compare facts, semantic observations, entities, states and Russian labels."""
    from sli_collect.eventlog import parse_event_xml

    outputs = {}
    for event_id in (4624, 4625, 4722, 4725, 4740, 65535):
        row = parse_event_xml(event_xml(event_id, 1), source_name=CONFIG["source_name"],
                              connect_address=CONFIG["connect_address"], channel="Security")
        data = {"TargetUserName": "fixture-account", "TargetUserSid": "S-1-5-21-100-200-300-1001", "LogonType": "3"}
        outputs[str(event_id)] = {
            "facts": normalizer.event_facts(row=row, event_data=data),
            "semantic": normalizer.semantic_projection(event_id=event_id, channel="Security",
                provider=row["provider_name"], event_data=data, correlation_id=None, source_host=CONFIG["source_name"]),
            "entities": normalizer.entity_semantics(event_id=event_id, channel="Security"),
            "state": normalizer.state_semantics(event_id=event_id, channel="Security"),
            "labels": {lang: normalizer.event_label(event_id, lang) for lang in ("ru", "en")},
        }
    return _plain(outputs)


def assignment_snapshot():
    """Capture revision, retained history, SQL arguments and safe audit fields."""
    from server.sli.agents import policies

    class Cursor:
        def __init__(self):
            self.agent = {"id": AGENT, "host_id": HOST, "status": "active", "assigned_modules": [],
                          "policy_revision": 1, "applied_policy_revision": 0, "rights_probe": {}}
            self.calls = []

        def execute(self, sql, params=()):
            self.calls.append([sql, _plain(params)])
            if sql.startswith("update sli_agents set assigned_modules"):
                self.agent.update(assigned_modules=json.loads(params[0]), policy_revision=params[1])

        def fetchone(self):
            return deepcopy(self.agent)

    cur = Cursor()
    results = []
    for enabled in (True, False):
        results.append(policies.assign_module(cur, {"agent_id": AGENT, "module_id": "sli.windows.ad-dc",
            "enabled": enabled, "config": CONFIG, "expected_revision": cur.agent["policy_revision"]}, actor="session:1"))
    return {"results": results, "calls": cur.calls, "agent": cur.agent}


def initial_read_contract_baseline(baseline):
    """Apply only the reviewed initial-read additions to the frozen PR 3 capture."""
    expected = deepcopy(baseline)

    def policy(config):
        # Preserve issuance order because the fixture also captures SQL JSON.
        return {"policy_revision": config["policy_revision"], "batch_size": config["batch_size"],
                "channel_generations": config["channel_generations"], "initial_read_hours": 24, **config}

    def canonical(value):
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                          allow_nan=False).encode("ascii")

    def digest(value):
        return hashlib.sha256(canonical(value)).hexdigest()

    def packet(envelope, payload):
        payload["context"]["ad_dc"].update(
            channels=deepcopy(expected["policies"]["default"]["channels"]), channel_generations={})
        state = json.loads(envelope["cursor_after"]["token"])
        observed = datetime.fromisoformat(payload["header"]["observed_at_utc"])
        state["channels"][payload["header"]["channel"]]["since_utc"] = (observed - timedelta(hours=24)).isoformat()
        envelope["cursor_after"]["token"] = canonical(state).decode("ascii")
        envelope["payload_sha256"] = digest(payload)
        envelope["payload_bytes"] = len(canonical(payload))

    for name, config in expected["policies"].items():
        if name != "invalid":
            expected["policies"][name] = policy(config)
    for outcome in expected["packets"].values():
        packet(outcome["envelope"], outcome["payload"])
        for receipt in (outcome["receipt"], outcome["duplicate"], outcome["fork"]):
            if receipt is not None and "payload_sha256" in receipt:
                receipt["payload_sha256"] = outcome["envelope"]["payload_sha256"]
                if receipt["committed_cursor"] is not None:
                    receipt["committed_cursor"] = deepcopy(outcome["envelope"]["cursor_after"])
        for entry in outcome["entries"]:
            packet(entry["envelope"], entry["payload"])
            entry["envelope_sha256"] = digest(entry["envelope"])
            entry["receipt"] = deepcopy(outcome["receipt"])

    assignment = expected["assignment"]
    for result in [*assignment["results"], assignment["agent"]]:
        for module in result["assigned_modules"]:
            module["config"] = policy(module["config"])
    for sql, params in assignment["calls"]:
        index = (2 if sql.startswith("insert into sli_agent_policy_history") else
                 0 if sql.startswith("update sli_agents set assigned_modules") else None)
        if index is not None:
            modules = json.loads(params[index])
            for module in modules:
                module["config"] = policy(module["config"])
            params[index] = json.dumps(modules)
        elif sql.startswith("insert into sli_agent_audit"):
            details = json.loads(params[3])
            config = next(result["assigned_modules"][0]["config"] for result in assignment["results"]
                          if result["policy_revision"] == details["revision"])
            details["policy_sha256"] = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
            params[3] = json.dumps(details)
    return expected

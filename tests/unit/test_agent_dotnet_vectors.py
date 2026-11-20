"""The .NET agent (agent-dotnet/) and this server must agree byte for byte; synthetic data only.

Three checks, none needs a database or Windows:

* the committed vectors are exactly what today's Python code produces (so a contract change shows up here first);
* the server's own code accepts the Python-signed vectors and rejects the invalid ones with the same codes;
* packets and an enrollment request written by the .NET tests (``SLI_DOTNET_INTEROP_DIR``, set in CI) are accepted by
  ``receive_packet`` and ``parse_csr``.
"""
import base64
import importlib.util
import json
import os
from datetime import datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from server.sli.agent_ingest import receive_packet
from server.sli.agents.ca import AgentError, fingerprint, parse_csr
from sli_agent.envelope import EnvelopeError, verify_packet

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "agent-dotnet" / "tools" / "make_vectors.py"
VECTORS = ROOT / "agent-dotnet" / "tests" / "vectors"


def load_generator():
    spec = importlib.util.spec_from_file_location("agent_dotnet_make_vectors", TOOLS)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def public_key(spki_b64):
    return serialization.load_der_public_key(base64.b64decode(spki_b64))


class Ledger:
    """The few ledger calls ``receive_packet`` makes, kept in memory (as the server's own unit tests do)."""

    def __init__(self):
        self.entries = []

    def binding(self, *_):
        return None

    def get(self, _agent, _module, sequence):
        return next((item for item in self.entries if item["envelope"]["sequence"] == sequence), None)

    def latest(self, *_):
        return self.entries[-1]["envelope"] if self.entries else None

    def packet_exists(self, *_):
        return False

    def quota_error(self, *_):
        return None

    def workstation_counts(self, _agent, _window_seconds):
        from collections import Counter

        return dict(Counter(str(record["payload"]["event_id"])
                            for item in self.entries for record in item.get("records", [])))

    def commit(self, value, receipt, envelope_hash, rows):
        self.entries.append({"envelope": value["envelope"], "receipt": receipt, "envelope_sha256": envelope_hash,
                             "records": value["payload"].get("records", [])})


def test_committed_vectors_are_what_the_python_code_produces():
    generator = load_generator()
    built = {VECTORS / name: value for name, value in generator.build().items()}
    built[generator.CATALOG] = generator.catalog_snapshot()
    stale = []
    for path, value in built.items():
        current = json.loads(path.read_text("utf-8"))
        if generator.strip_signatures(current) != generator.strip_signatures(json.loads(generator.dump(value))):
            stale.append(path.name)
    assert not stale, "run agent-dotnet/tools/make_vectors.py: " + ", ".join(stale)


def test_server_code_accepts_the_python_signed_vectors_and_rejects_the_invalid_ones():
    document = json.loads((VECTORS / "packets.json").read_text("utf-8"))
    key = public_key(document["public_key_spki_b64"])
    for item in document["packets"]:
        assert verify_packet(item["packet"], key)["packet_id"] == item["packet_id"]
    for item in document["invalid"]:
        with pytest.raises(EnvelopeError) as raised:
            verify_packet(item["packet"], key)
        assert str(raised.value) == item["error"], item["name"]


def test_server_ingest_commits_the_vector_security_packet():
    document = json.loads((VECTORS / "packets.json").read_text("utf-8"))
    packet = next(item for item in document["packets"] if item["name"] == "ad-dc-security")
    identity = {"id": document["agent_id"], "host_id": document["host_id"], "assigned_modules": [
        {"module_id": "sli.windows.ad-dc", "enabled": True,
         "config": {"source_name": "fixture-dc", "connect_address": "fixture-endpoint",
                    "channels": {"System": False, "Directory Service": False}, "batch_size": 3}}]}
    now = datetime.fromisoformat(packet["now"])
    receipt = receive_packet(Ledger(), identity=identity, public_key=public_key(document["public_key_spki_b64"]),
                             value=packet["packet"], now=now)
    assert receipt["status"] == "committed", receipt


INTEROP = Path(os.environ.get("SLI_DOTNET_INTEROP_DIR", "")) / "dotnet-packets.json"


@pytest.mark.skipif(not os.environ.get("SLI_DOTNET_INTEROP_DIR"), reason="set SLI_DOTNET_INTEROP_DIR after running the .NET interop test")
def test_server_code_accepts_what_the_dotnet_agent_produces():
    export = json.loads(INTEROP.read_text("utf-8"))
    key = public_key(export["public_key_spki_b64"])
    now = datetime.fromisoformat(export["now"])

    # The enrollment request: the server's own CSR rules, and the fingerprint an administrator binds a token to.
    csr = parse_csr(export["csr_pem"], export["host_id"])
    assert fingerprint(csr.public_key()) == export["key_fingerprint"]
    assert fingerprint(key) == export["key_fingerprint"]

    assert export["streams"], "the export must contain at least one stream"
    for stream in export["streams"]:
        ledger = Ledger()
        identity = {"id": stream["agent_id"], "host_id": export["host_id"], "assigned_modules": [
            {"module_id": stream.get("module_id", "sli.windows.ad-dc"), "enabled": True, "config": stream["config"]}]}
        assert stream["packets"], "a stream needs packets"
        for packet in stream["packets"]:
            receipt = receive_packet(ledger, identity=identity, public_key=key, value=packet, now=now)
            assert receipt["status"] == "committed", (receipt, packet["envelope"]["sequence"])
        # A repeat of the last packet is answered with the stored receipt as a duplicate, never imported again.
        again = receive_packet(ledger, identity=identity, public_key=key, value=stream["packets"][-1], now=now)
        assert again["status"] == "duplicate"
        assert len(ledger.entries) == len(stream["packets"])

    with pytest.raises(AgentError):
        parse_csr(export["csr_pem"], "00000000-0000-4000-8000-000000000000")

    from server.sli.agents.windows_audit import validate_report

    assert export["audit_reports"]
    for item in export["audit_reports"]:
        agent = {"policy_revision": 1, "assigned_modules": [
            {"module_id": "sli.workstations", "enabled": True, "config": item["config"]}]}
        validate_report(item["report"]["windows_audit"], agent, 1)

#!/usr/bin/env python3
"""Generate cross-language test vectors from the Python reference implementation.

The .NET agent must produce byte-identical canonical JSON, envelopes and
Security packets. Nothing here is hand-written expectation: every expected value
is computed by the current ``sli_agent`` / ``server`` code, so a change of the
server contract changes the vectors (and ``tests/unit/test_agent_dotnet_vectors.py``
tells you which side moved).

Usage (from the repository root)::

    python agent-dotnet/tools/make_vectors.py            # rewrite tests/vectors
    python agent-dotnet/tools/make_vectors.py --check    # fail if deterministic parts differ

Only synthetic data is used. The signing key is derived from a public constant and is
never written out; the vectors contain the public key only. ECDSA signatures are
randomized, so ``--check`` compares everything except the ``signature`` fields.
"""
from __future__ import annotations

import argparse
import ast
import base64
import copy
import json
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from sli_agent import ad_dc, envelope
from sli_agent.ad_dc import ADDCModule, event_identities
from sli_agent.envelope import (
    EnvelopeError,
    canonical,
    make_packet,
    verify_packet,
)
from sli_agent.modules import HeartbeatModule
from sli_agent.spool import Spool
from sli_collect.bookmarked_eventlog import BookmarkRecoveryBatch
from sli_collect.eventlog import parse_event_xml

AGENT_DIR = Path(__file__).resolve().parents[1]
VECTORS = AGENT_DIR / "tests" / "vectors"
# The agent embeds this snapshot; it lives next to the code that reads it.
CATALOG = AGENT_DIR / "src" / "Sli.Agent.Core" / "Resources" / "dc-event-catalog.json"
NOW = datetime(2026, 10, 7, 12, 0, 0, tzinfo=timezone.utc)
NOW_MICRO = datetime(2026, 10, 7, 12, 0, 0, 123456, tzinfo=timezone.utc)
HOST = "6f1c2d3e-4a5b-4c6d-8e7f-0a1b2c3d4e5f"
AGENT = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"
SECURITY = "Microsoft-Windows-Security-Auditing"
NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def signing_key():
    # Derived from a public constant: a fixture identity, not a secret.
    return ec.derive_private_key(0x5EED_0F_5110_A9E7, ec.SECP256R1())


def public_spki_b64(key) -> str:
    der = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(der).decode("ascii")


def iso(value: datetime) -> str:
    return value.isoformat()


def fixed_ids(prefix="00000000-0000-4000-8000-"):
    counter = {"n": 0}

    def make():
        counter["n"] += 1
        from uuid import UUID
        return UUID(f"{prefix}{counter['n']:012d}")
    return make


# --------------------------------------------------------------------------- canonical JSON

def canonical_cases():
    big = 9007199254740993  # 2**53 + 1: still an exact integer on the wire
    cases = [
        ("empty-object", {}), ("empty-array", []), ("null", None), ("true", True), ("false", False),
        ("integers", [0, 1, -1, 42, big, -big, 2**63 - 1]),
        ("key-order", {"b": 1, "a": 2, "B": 3, "aa": 4, "": 5, "_": 6, "1": 7}),
        # Code-point order differs from UTF-16 order for U+10000 vs U+FFFF.
        ("key-order-astral", {"\U00010000": 1, "￿": 2, "": 3, "z": 4}),
        ("nested", {"z": {"y": [1, {"b": None, "a": [True, False]}], "x": ""}, "a": {}}),
        ("escapes", "quote\" backslash\\ slash/ \n \r \t \b \f \x00 \x01 \x1f del\x7f"),
        ("non-ascii", "Пользователь café — ü ß"),
        ("astral", "emoji \U0001F600 and \U00010348 end"),
        ("bmp-boundary", "\u007f\u0080߿ࠀ￿퟿"),
        ("whitespace-keys", {" a": 1, "a ": 2, "a\tb": 3}),
        ("unicode-key", {"ключ": "значение", "\U0001F600": [1]}),
        ("long-string", "x" * 5000),
    ]
    return [{"name": name, "value": value, "canonical": canonical(value).decode("ascii")} for name, value in cases]


# --------------------------------------------------------------------------- events

def sys_xml(event_id, record_id, *, channel="Security", provider=SECURITY, computer="dc1.example.test",
            version="2", user_id="S-1-5-18", time="2026-10-07T00:00:00.1234567Z", keywords="0x8020000000000000"):
    parts = [f"<Provider Name='{escape(provider)}' Guid='{{54849625-5478-4994-a5ba-3e3b0328c30d}}'/>",
             f"<EventID>{event_id}</EventID>", f"<Version>{version}</Version>", "<Level>0</Level>",
             "<Task>12544</Task>", "<Opcode>0</Opcode>", f"<Keywords>{keywords}</Keywords>",
             f"<TimeCreated SystemTime='{time}'/>", f"<EventRecordID>{record_id}</EventRecordID>", "<Correlation/>",
             "<Execution ProcessID='664' ThreadID='3092'/>", f"<Channel>{escape(channel)}</Channel>",
             f"<Computer>{escape(computer)}</Computer>"]
    if user_id is not None:
        parts.append(f"<Security UserID='{user_id}'/>")
    return "<System>" + "".join(parts) + "</System>"


def event(event_id, record_id, data=None, **kwargs):
    data = data if data is not None else [("SubjectUserSid", "S-1-5-18"), ("TargetUserName", "fixture-account")]
    body = "".join(f"<Data Name='{name}'>{escape(value)}</Data>" if value is not None else f"<Data Name='{name}' />"
                   for name, value in data)
    return f"<Event xmlns='{NS}'>{sys_xml(event_id, record_id, **kwargs)}<EventData>{body}</EventData></Event>"


def parse_cases():
    """XML strings with the row Python produces (or the error it raises)."""
    cases = [
        ("typical", event(4624, 101), "Security"),
        ("empty-data-and-nonascii", event(4625, 102, data=[("A", None), ("B", "Пользователь"), ("C", "emoji \U0001F600"),
                                                          ("D", "a&b <c> \"q\" 'r'"), ("E", "  spaced  ")]), "Security"),
        ("no-user-id", event(4634, 103, user_id=None), "Security"),
        ("other-provider", event(4624, 104, provider="Some-Other-Provider"), "Security"),
        ("version-empty", event(4672, 105, version=""), "Security"),
        ("plus-sign-and-zeros", event("+4624", "0000106"), "Security"),
        ("underscore-digits", event("4_624", 107), "Security"),
        ("spaces-around-number", event(" 4624 ", 108), "Security"),
        ("non-numeric-id", event("abc", 109), "Security"),
        ("empty-id", event("", 110), "Security"),
        ("negative-id", event(4624, -5), "Security"),
        ("big-record-id", event(4624, 123456789012345678901234567890), "Security"),
        ("arabic-indic-digits", event("٤٦٢٤", 111), "Security"),
        ("no-event-data", f"<Event xmlns='{NS}'>{sys_xml(4624, 112)}</Event>", "Security"),
        ("data-with-child", f"<Event xmlns='{NS}'>{sys_xml(4624, 113)}<EventData><Data Name='A'>text<b>child</b>tail</Data></EventData></Event>", "Security"),
        ("data-with-comment-and-cdata", f"<Event xmlns='{NS}'>{sys_xml(4624, 114)}<EventData><Data Name='A'>x<!--c-->y<![CDATA[<z>]]></Data></EventData></Event>", "Security"),
        ("two-event-data", f"<Event xmlns='{NS}'>{sys_xml(4624, 115)}<EventData><Data>1</Data></EventData><EventData><Data>2</Data><Data>3</Data></EventData></Event>", "Security"),
        ("other-channel", event(1102, 116, channel="System", provider="Microsoft-Windows-Eventlog"), "System"),
        ("no-namespace", f"<Event>{sys_xml(4624, 117)}</Event>", "Security"),
        ("crlf-in-text", f"<Event xmlns='{NS}'>{sys_xml(4624, 118)}<EventData><Data>a\r\nb</Data></EventData></Event>", "Security"),
    ]
    out = []
    for name, xml, channel in cases:
        item = {"name": name, "xml": xml, "channel": channel, "source_name": "fixture-dc", "connect_address": "fixture-endpoint"}
        try:
            item["row"] = parse_event_xml(xml, source_name="fixture-dc", connect_address="fixture-endpoint", channel=channel)
        except Exception as exc:  # noqa: BLE001 - the vector records only the failure class
            item["error"] = type(exc).__name__
        out.append(item)
    rejected = [
        ("doctype", f"<!DOCTYPE x [<!ENTITY a 'b'>]><Event xmlns='{NS}'>{sys_xml(4624, 1)}</Event>"),
        ("entity-lowercase", f"<Event xmlns='{NS}'><!-- <!entity x> -->{sys_xml(4624, 1)}</Event>"),
        ("not-xml", "not xml"),
        ("depth-65", "<a>" * 65 + "</a>" * 65),
    ]
    for name, xml in rejected:
        item = {"name": "reject-" + name, "xml": xml, "channel": "Security", "source_name": "fixture-dc",
                "connect_address": "fixture-endpoint"}
        try:
            parse_event_xml(xml, source_name="fixture-dc", connect_address="fixture-endpoint", channel="Security")
            raise AssertionError("expected a parse failure: " + name)
        except AssertionError:
            raise
        except Exception as exc:  # noqa: BLE001
            item["error"] = type(exc).__name__
        out.append(item)
    return out


# --------------------------------------------------------------------------- AD DC scenarios

class ScriptedReader:
    def __init__(self):
        self.script = None
        self.calls = []

    def __call__(self, channel, cursor, limit):
        self.calls.append({"channel": channel, "cursor": copy.deepcopy(cursor), "limit": limit})
        mode = self.script["mode"]
        if mode == "error":
            raise RuntimeError("agent_ad_dc_read_failed")
        rows = [(item["xml"], item["bookmark"]) for item in self.script["rows"]]
        return BookmarkRecoveryBatch(rows) if mode == "recovered" else rows


def big_event(record_id, size=7000):
    return event(4625, record_id, data=[("Description", "x" * size)])


SECURITY_ONLY = {"Security": True, "System": False, "Directory Service": False}


def ad_dc_scenarios():
    def rows(*pairs):
        return [{"xml": xml, "bookmark": f"<BookmarkList><Bookmark Channel='Security' RecordId='{rid}' IsCurrent='true'/></BookmarkList>"}
                for rid, xml in pairs]

    scenarios = []

    def run(name, config, steps, *, description):
        reader = ScriptedReader()
        module = ADDCModule(HOST, config, reader=reader)
        captured = None
        recorded = []
        for step in steps:
            reader.script = step["reader"]
            reader.calls.clear()
            catch_up = module.catch_up_channel if step.get("catch_up") else None
            sample = module.collect(captured, now=step["now"], **({"channel": catch_up} if catch_up else {}))
            record = {"now": iso(step["now"]), "captured": copy.deepcopy(captured), "channel_override": catch_up,
                      "reader": step["reader"], "expected_reads": copy.deepcopy(reader.calls)}
            if sample is None:
                record["expected"] = None
            else:
                record["expected"] = {
                    "module_id": sample.module_id, "source_instance_id": sample.source_instance_id,
                    "channel": sample.channel, "generation": sample.generation,
                    "cursor_before": sample.cursor_before, "cursor_after": sample.cursor_after,
                    "payload_canonical": canonical(sample.payload).decode("ascii"),
                    "module_version": sample.module_version, "policy_revision": sample.policy_revision,
                    "continuity_state": sample.continuity_state, "filtered_count": sample.filtered_count,
                    "lost_count": sample.lost_count, "catch_up_channel": module.catch_up_channel}
                captured = {"generation": sample.generation, "cursor_after": sample.cursor_after}
            recorded.append(record)
        scenarios.append({"name": name, "description": description, "host_id": HOST, "config": config,
                          "normalized_config": module.config, "steps": recorded})

    base = {"source_name": "fixture-dc", "connect_address": "fixture-endpoint", "channels": SECURITY_ONLY, "batch_size": 3}
    t = lambda minutes=0: NOW + timedelta(minutes=minutes)
    run("security-backlog-and-catch-up", base, [
        {"now": t(), "reader": {"mode": "rows", "rows": rows((101, event(4624, 101)), (102, event(4625, 102)),
                                                              (103, event(65535, 103)))}},
        {"now": t(1), "catch_up": True, "reader": {"mode": "rows", "rows": rows((104, event(4634, 104, data=[("A", None), ("B", "Пользователь")])))}},
        {"now": t(2), "reader": {"mode": "rows", "rows": []}},
    ], description="Full batch starts a catch-up; filtered events advance the cursor; an empty read still produces a packet.")
    run("security-read-error", base, [
        {"now": t(), "reader": {"mode": "rows", "rows": rows((10, event(4624, 10)))}},
        {"now": t(1), "reader": {"mode": "error"}},
        {"now": t(2), "reader": {"mode": "rows", "rows": rows((11, event(4625, 11)))}},
    ], description="A native read failure is a gap packet with no records; the cursor does not move.")
    run("security-bookmark-recovered", base, [
        {"now": t(), "reader": {"mode": "rows", "rows": rows((20, event(4624, 20)))}},
        {"now": t(1), "reader": {"mode": "recovered", "rows": rows((30, event(4624, 30)), (31, event(4672, 31)))}},
    ], description="A lost anchor resumes by RecordID and declares an unknown gap.")
    run("security-generation-reset", {**base, "channel_generations": {"Security": "gen-2"}}, [
        {"now": t(), "reader": {"mode": "rows", "rows": rows((5, event(4624, 5)))}},
    ], description="First read uses the configured channel generation.")
    run("security-initial-window-all", {**base, "initial_read_hours": "all"}, [
        {"now": t(), "reader": {"mode": "rows", "rows": rows((1, event(4624, 1)))}},
    ], description="initial_read_hours = all sends no since_utc.")
    run("security-allow-list", {**base, "allow_event_ids": [4624]}, [
        {"now": t(), "reader": {"mode": "rows", "rows": rows((1, event(4624, 1)), (2, event(4625, 2)))}},
    ], description="Events outside allow_event_ids are filtered but consumed.")
    run("security-wire-limit", {**base, "batch_size": 128}, [
        {"now": t(), "reader": {"mode": "rows", "rows": rows(*[(i, big_event(i)) for i in range(1, 9)])}},
        {"now": t(1), "catch_up": True, "reader": {"mode": "rows", "rows": rows(*[(i, big_event(i)) for i in range(7, 9)])}},
    ], description="A packet over the 44 KiB wire budget stops early; the omitted event is read again.")
    three = {"source_name": "fixture-dc", "connect_address": "fixture-endpoint", "batch_size": 2,
             "channels": {"Security": True, "System": True, "Directory Service": True}}
    def bm(channel, rid):
        return f"<BookmarkList><Bookmark Channel='{channel}' RecordId='{rid}' IsCurrent='true'/></BookmarkList>"
    system = lambda rid, eid=6013, provider="EventLog": {"xml": event(eid, rid, channel="System", provider=provider), "bookmark": bm("System", rid)}
    ds = lambda rid, eid=1162: {"xml": event(eid, rid, channel="Directory Service", provider="Microsoft-Windows-ActiveDirectory_DomainService"), "bookmark": bm("Directory Service", rid)}
    run("three-channel-rotation", three, [
        {"now": t(), "reader": {"mode": "rows", "rows": rows((1, event(4624, 1)))}},
        {"now": t(1), "reader": {"mode": "rows", "rows": [system(7), system(8, 99999)]}},
        {"now": t(2), "reader": {"mode": "rows", "rows": [ds(3)]}},
        {"now": t(3), "reader": {"mode": "rows", "rows": rows((2, event(4625, 2)))}},
    ], description="All three channels share one cursor and rotate in the fixed order; System and Directory Service are unfiltered at the source but admitted by the catalog.")
    run("security-microseconds", base, [
        {"now": NOW_MICRO, "reader": {"mode": "rows", "rows": rows((1, event(4624, 1)))}},
    ], description="Timestamps with microseconds keep six digits (isoformat).")
    return scenarios


def selector_cases():
    """Final XPath passed to the Event Log for representative cursors (Python reference)."""
    import types
    queries = []

    class Stop(Exception):
        pass

    fake = types.ModuleType("win32evtlog")
    fake.EvtQueryChannelPath, fake.EvtQueryForwardDirection = 1, 2
    fake.error = type("error", (Exception,), {})

    def evt_query(channel, flags, xpath, session):
        queries.append({"channel": channel, "xpath": xpath})
        return types.SimpleNamespace(Close=lambda: None)

    def create_bookmark(_):
        raise Stop()

    fake.EvtQuery, fake.EvtCreateBookmark = evt_query, create_bookmark
    previous = sys.modules.get("win32evtlog")
    sys.modules["win32evtlog"] = fake
    cases = []
    cursors = [
        ("fresh", {"record_id": None, "bookmark": ""}),
        ("fresh-since", {"record_id": None, "bookmark": "", "since_utc": "2026-10-06T12:00:00+00:00"}),
        ("record-id-no-bookmark", {"record_id": 500, "bookmark": ""}),
        ("bookmark", {"record_id": 500, "bookmark": "<BookmarkList/>"}),
        ("bookmark-with-since", {"record_id": 500, "bookmark": "<BookmarkList/>", "since_utc": "2026-10-06T12:00:00+00:00"}),
        ("since-and-record-id", {"record_id": 500, "bookmark": "", "since_utc": "2026-10-06T12:00:00Z"}),
    ]
    try:
        for channel in ("Security", "System", "Directory Service"):
            for label, cursor in cursors:
                queries.clear()
                try:
                    ad_dc.read_local(channel, {**cursor, "generation": HOST}, 32)
                except Exception:  # noqa: BLE001 - the fake stops after recording the query
                    assert queries, "fake reader must record the query before stopping"
                cases.append({"name": f"{channel}:{label}", "channel": channel, "cursor": {**cursor, "generation": HOST},
                              "expected": queries[-1]})
    finally:
        if previous is None:
            sys.modules.pop("win32evtlog", None)
        else:
            sys.modules["win32evtlog"] = previous
    return cases


# --------------------------------------------------------------------------- packets and receipts

def packet_vectors():
    key = signing_key()
    ids = fixed_ids()
    original = envelope.uuid4
    envelope.uuid4 = ids
    try:
        heartbeat = HeartbeatModule(HOST).collect(None, now=NOW)
        heartbeat2 = HeartbeatModule(HOST).collect({"cursor_after": heartbeat.cursor_after}, now=NOW_MICRO)
        reader = ScriptedReader()
        module = ADDCModule(HOST, {"source_name": "fixture-dc", "connect_address": "fixture-endpoint",
                                   "channels": SECURITY_ONLY, "batch_size": 3}, reader=reader)
        reader.script = {"mode": "rows", "rows": [
            {"xml": event(4624, 101), "bookmark": "<BookmarkList><Bookmark Channel='Security' RecordId='101' IsCurrent='true'/></BookmarkList>"},
            {"xml": event(65535, 102), "bookmark": "<BookmarkList><Bookmark Channel='Security' RecordId='102' IsCurrent='true'/></BookmarkList>"}]}
        dc = module.collect(None, now=NOW)
        samples = [("heartbeat-1", heartbeat, 1, NOW), ("heartbeat-2-microseconds", heartbeat2, 2, NOW_MICRO),
                   ("ad-dc-security", dc, 1, NOW)]
        packets = []
        for name, sample, sequence, now in samples:
            packet = make_packet(key, agent_id=AGENT, sequence=sequence, sample=sample, now=now)
            packets.append({
                "name": name, "packet": packet,
                "canonical_envelope": canonical(packet["envelope"]).decode("ascii"),
                "canonical_payload": canonical(packet["payload"]).decode("ascii"),
                "sample": {"module_id": sample.module_id, "source_instance_id": sample.source_instance_id,
                           "channel": sample.channel, "generation": sample.generation,
                           "cursor_before": sample.cursor_before, "cursor_after": sample.cursor_after,
                           "policy_revision": sample.policy_revision, "module_version": sample.module_version,
                           "continuity_state": sample.continuity_state, "filtered_count": sample.filtered_count,
                           "lost_count": sample.lost_count, "payload_canonical": canonical(sample.payload).decode("ascii")},
                "sequence": sequence, "now": iso(now), "packet_id": packet["envelope"]["packet_id"]})
        return key, packets
    finally:
        envelope.uuid4 = original


def invalid_packets(good):
    """Packets Python rejects, with the stable error code."""
    key = signing_key()
    base = copy.deepcopy(good["packet"])
    cases = []

    def add(name, packet, error):
        try:
            verify_packet(packet, key.public_key())
            raise AssertionError("expected rejection: " + name)
        except EnvelopeError as exc:
            assert str(exc) == error, (name, str(exc))
        cases.append({"name": name, "packet": packet, "error": error})

    def mutated(fn):
        value = copy.deepcopy(base)
        fn(value)
        return value

    add("payload-changed", mutated(lambda p: p["payload"].__setitem__("status", "changed")), "agent_payload_hash_mismatch")
    add("signature-changed", mutated(lambda p: p.__setitem__("signature", base64.b64encode(b"\x00" * 70).decode())), "agent_signature_invalid")
    add("signature-not-base64", mutated(lambda p: p.__setitem__("signature", "***")), "agent_signature_invalid")
    add("extra-top-level-key", mutated(lambda p: p.__setitem__("extra", 1)), "agent_packet_invalid")
    add("extra-envelope-key", mutated(lambda p: p["envelope"].__setitem__("extra", 1)), "agent_packet_invalid")
    add("missing-envelope-key", mutated(lambda p: p["envelope"].pop("lost_count")), "agent_packet_invalid")
    add("agent-id-not-uuid", mutated(lambda p: p["envelope"].__setitem__("agent_id", "not-a-uuid")), "agent_packet_invalid")
    add("agent-id-uppercase", mutated(lambda p: p["envelope"].__setitem__("agent_id", p["envelope"]["agent_id"].upper())), "agent_packet_invalid")
    add("sequence-zero", mutated(lambda p: p["envelope"].__setitem__("sequence", 0)), "agent_packet_invalid")
    add("sequence-boolean", mutated(lambda p: p["envelope"].__setitem__("sequence", True)), "agent_packet_invalid")
    add("bad-contract", mutated(lambda p: p["envelope"].__setitem__("contract_id", "sli.agent-envelope.v2")), "agent_packet_invalid")
    add("bad-module-id", mutated(lambda p: p["envelope"].__setitem__("module_id", "Bad Module")), "agent_packet_invalid")
    add("bad-version", mutated(lambda p: p["envelope"].__setitem__("module_version", "1.0")), "agent_packet_invalid")
    add("bad-continuity", mutated(lambda p: p["envelope"].__setitem__("continuity_state", "unknown")), "agent_packet_invalid")
    add("bad-cursor-strategy", mutated(lambda p: p["envelope"]["cursor_after"].__setitem__("strategy", "offset")), "agent_packet_invalid")
    add("cursor-token-too-long", mutated(lambda p: p["envelope"]["cursor_after"].__setitem__("token", "x" * 4097)), "agent_packet_invalid")
    add("bad-timestamp-offset", mutated(lambda p: p["envelope"].__setitem__("observed_at_utc", "2026-10-07T12:00:00+03:00")), "agent_packet_invalid")
    add("naive-timestamp", mutated(lambda p: p["envelope"].__setitem__("observed_at_utc", "2026-10-07T12:00:00")), "agent_packet_invalid")
    add("record-count-mismatch", mutated(lambda p: p["envelope"].__setitem__("record_count", 5)), "agent_payload_hash_mismatch")
    add("payload-bytes-mismatch", mutated(lambda p: p["envelope"].__setitem__("payload_bytes", 1)), "agent_payload_hash_mismatch")
    huge = mutated(lambda p: p["payload"].__setitem__("filler", "x" * 70000))
    add("oversized", huge, "agent_packet_size_limit")
    return cases


def receipt_cases():
    """Receipt variants and whether the Python spool treats them as delivery proof."""
    key = signing_key()
    cases = []
    env_ids = fixed_ids("00000000-0000-4000-9000-")
    original = envelope.uuid4
    envelope.uuid4 = env_ids
    try:
        sample = HeartbeatModule(HOST).collect(None, now=NOW)
        packet = make_packet(key, agent_id=AGENT, sequence=1, sample=sample, now=NOW)
    finally:
        envelope.uuid4 = original
    e = packet["envelope"]
    good = {"contract_id": "sli.agent-receipt.v1", "packet_id": e["packet_id"], "payload_sha256": e["payload_sha256"],
            "status": "committed", "committed_cursor": e["cursor_after"], "evidence_ref": "agent-packet:" + e["packet_id"],
            "committed_at_utc": iso(NOW), "error_code": None}
    variants = [
        ("committed", {}), ("duplicate", {"status": "duplicate"}),
        ("rejected", {"status": "rejected", "committed_cursor": None, "evidence_ref": None, "committed_at_utc": None,
                      "error_code": "agent_cursor_mismatch"}),
        ("retry-later", {"status": "retry_later", "committed_cursor": None, "evidence_ref": None, "committed_at_utc": None,
                         "error_code": "agent_sequence_gap"}),
        ("wrong-contract", {"contract_id": "sli.agent-receipt.v2"}),
        ("wrong-packet", {"packet_id": "00000000-0000-4000-9000-999999999999"}),
        ("wrong-hash", {"payload_sha256": "0" * 64}),
        ("wrong-cursor", {"committed_cursor": {"strategy": "record_id", "token": "99"}}),
        ("no-evidence", {"evidence_ref": None}), ("empty-evidence", {"evidence_ref": ""}),
        ("bad-time", {"committed_at_utc": "invalid"}), ("no-time", {"committed_at_utc": None}),
        ("naive-time", {"committed_at_utc": "2026-10-07T12:00:00"}),
        ("error-code-present", {"error_code": "agent_replay_window"}),
        ("unknown-status", {"status": "accepted"}),
    ]
    for name, change in variants:
        receipt = {**good, **change}
        with tempfile.TemporaryDirectory() as folder:
            spool = Spool(Path(folder), max_bytes=100000, max_age_seconds=86400 * 365 * 10)
            envelope.uuid4 = fixed_ids("00000000-0000-4000-a000-")
            try:
                captured = spool.capture(key, agent_id=AGENT, sample=sample, now=NOW)
            finally:
                envelope.uuid4 = original
            # capture() builds its own packet_id; align the receipt to the stored packet.
            stored = captured["envelope"]
            aligned = {**receipt}
            if "packet_id" not in change:
                aligned["packet_id"] = stored["packet_id"]
            if "payload_sha256" not in change:
                aligned["payload_sha256"] = stored["payload_sha256"]
            if "committed_cursor" not in change and receipt["committed_cursor"] is not None:
                aligned["committed_cursor"] = stored["cursor_after"]
            if "evidence_ref" not in change:
                aligned["evidence_ref"] = "agent-packet:" + stored["packet_id"]
            accepted = spool.acknowledge(captured, aligned)
        cases.append({"name": name, "receipt": aligned, "packet_envelope_cursor_after": stored["cursor_after"],
                      "payload_sha256": stored["payload_sha256"], "packet_id": stored["packet_id"], "accepted": accepted})
    cases.append({"name": "not-an-object", "receipt": "oops", "accepted": False, "packet_id": None,
                  "payload_sha256": None, "packet_envelope_cursor_after": None})
    return cases


def catalog_snapshot():
    """Event identities of the DC pack channels, in a form the .NET agent embeds."""
    entries = sorted(event_identities())
    return {"pack_id": ad_dc.PACK_ID, "channels": list(ad_dc.CHANNELS),
            "events": [{"channel": channel, "provider": provider, "event_id": event_id} for channel, provider, event_id in entries]}


# --------------------------------------------------------------------------- output

def build():
    key, packets = packet_vectors()
    return {
        **snapshot_vectors(),
        "canonical.json": canonical_cases(),
        "event-xml.json": parse_cases(),
        "ad-dc-scenarios.json": ad_dc_scenarios(),
        "event-selectors.json": selector_cases(),
        "workstations-scenarios.json": workstations_scenarios(),
        "file-audit-scenarios.json": file_audit_scenarios(),
        "file-audit-inventory.json": file_audit_inventory(),
        **nps_vectors(),
        "receipts.json": receipt_cases(),
        "packets.json": {"public_key_spki_b64": public_spki_b64(key), "agent_id": AGENT, "host_id": HOST,
                         "packets": packets, "invalid": invalid_packets(packets[0])},
    }


def snapshot_vectors():
    """All snapshot expectations come from the shipped Python normalizers and stream."""
    from uuid import UUID

    from sli_agent import ad_snapshot as ad
    from sli_agent import ad_snapshot_computers as computers
    from sli_agent import gpo_snapshot as gpo
    from sli_agent.snapshot_stream import SnapshotStream, policy

    # Constants are extracted from the reference, including the Computers V6 mapping.
    tree = ast.parse(Path(ad.__file__).read_text("utf-8"))
    sources = next(ast.literal_eval(n.value) for n in ast.walk(tree) if isinstance(n, ast.Assign)
                   and any(isinstance(t, ast.Name) and t.id == "sources" for t in n.targets))
    tree = ast.parse(Path(computers.__file__).read_text("utf-8"))
    fields = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        for key, value in zip(node.keys, node.values):
            if (isinstance(key, ast.Constant) and isinstance(value, ast.Call)
                    and isinstance(value.func, ast.Attribute) and isinstance(value.func.value, ast.Name)
                    and value.func.value.id == "attrs" and value.func.attr == "get" and len(value.args) == 1):
                fields[key.value] = ast.literal_eval(value.args[0])
    # Only the final computer object fields, not temporary source-state dictionaries.
    fields = {key: value for key, value in fields.items() if key not in {"value"}}
    fields.update(osName="operating_system", osVersion="operating_system_version", distinguishedName="distinguished_name")
    schema = {"attributes": ad.ATTRIBUTE_MAP, "attribute_order": list(ad.ATTRIBUTE_MAP), "dates": ad.DATE_MAP, "intervals": ad.INTERVAL_MAP, "interval_order": list(ad.INTERVAL_MAP),
              "uac": ad.UAC_FLAGS, "multi": sorted(ad.MULTI), "ldap_attributes": list(ad.LDAP_ATTRIBUTES),
              "computer_sources": sources, "computer_source_order": list(sources), "computer_fields": fields}
    sid, dns, dn = "S-1-5-21-100000001-200000002-300000003", "directory.invalid", "DC=directory,DC=invalid"
    stamp = iso(NOW).replace("+00:00", "Z")
    def obj(index, kind, **props):
        return {"kind": kind, "properties": {"objectguid": str(UUID(int=index)), "objectsid": f"{sid}-{index}",
                "distinguishedname": f"CN=object-{index},{dn}", "name": f"object-{index}", **props}}
    raw_ad = {"domain": {"sid": sid, "dns_name": dns, "default_nc": dn, "forest_nc": dn},
        "objects": [obj(1, "ad_user", samaccountname="Synthetic", displayname="Сотрудник", useraccountcontrol=512,
                        primarygroupid=513, memberof=[f"CN=object-512,{dn}"], objectclass=["top", "person", "user"],
                        pwdlastset=134040528000000000, unicodepwd="never-persist-this"),
                    obj(2, "ad_computer", dnshostname="host.directory.invalid", useraccountcontrol=8192,
                        operatingsystem="Windows Server", operatingsystemversion="10.0 (20348)", primarygroupid=513,
                        objectclass=["top", "computer"], **{"mslaps-passwordexpirationtime": "bad-date",
                        "msds-allowedtoactonbehalfofotheridentity": {"present": True, "status": "partial", "sids": [sid + "-512"], "descriptor_sha256": "a" * 64}}),
                    obj(513, "ad_group", grouptype=-2147483646, member=[]),
                    obj(512, "ad_group", grouptype=-2147483646, **{"member;range=0-*": [f"CN=object-1,{dn}", f"CN=missing,{dn}"]}),
                    obj(3, "domain", minpwdlength=14, maxpwdage=-864000000000, lockoutthreshold=5)],
        "states": {}, "schema_attributes": {"ms-mcs-admpwdexpirationtime": "absent"},
        "surveys": [{"dc": "dc-a.invalid", "status": "complete", "values": {str(UUID(int=1)): 134040528000000000}},
                    {"dc": "dc-b.invalid", "status": "failed", "values": {}}],
        "optional": {"dns": {"status": "observed", "values": {str(UUID(int=2)): {"status": "observed", "value": ["192.0.2.1", "2001:db8::1"]}}},
                     "ad_site": {"status": "observed", "subnets": [{"name": "192.0.2.0/24", "siteobject": "CN=Synthetic,CN=Sites," + dn}]}},
        "fsmo": {"pdc_emulator": "dc-a.invalid"}, "query_dc": "dc-a.invalid"}
    raw_gpo = {"domain": {"sid": sid, "dns_name": dns, "default_nc": dn}, "records": [], "snapshot": {
        "schema_version": "sli.ad-gpo.snapshot/1.0", "collector_version": "sli-agent/gpo-snapshot/1", "demo": False,
        "started_at": stamp, "completed_at": stamp, "observed_at": stamp, "collection_status": "complete",
        "domain": {"sid": sid, "dns_name": dns, "query_dc": "dc-a.invalid"}, "scope": {"domain": dns}, "source_states": {},
        **{key: [] for key in gpo.ARRAYS}, "gpos": [{"id": "gpo-1", "guid": str(UUID(int=100)), "display_name": "Synthetic policy"}],
        "settings": [{"setting_name": "apiKey", "value_display": "never-persist-this"},
                     {"path": "Scripts/Command", "value_display": "never-persist-this"},
                     {"value_display": "password=never-persist-this", "raw_xml": "<secret/>"}],
        "acl": [{"trustee_sid": sid + "-512", "access_control_type": "Allow", "access_mask": 256}]}}
    raw_gpo["records"] = [{"record_type": "entity", "record_key": "fixture-gpo", "section": "gpo_governance", "observed_at_utc": stamp,
        "identity": {"kind": "gpo", "domain_sid": sid, "object_guid": str(UUID(int=100)), "object_sid": None},
        "attributes": {"display_name": "Synthetic policy", "gpo_settings": [{"scope": "computer", "kind": "Registry", "path": "Registry/Properties",
            "properties": {"key": "Software\\Synthetic", "name": "password", "value": "never-persist-this", "cpassword": "never-persist-this"},
            "sha256": "a" * 64, "redacted_fields": [], "truncated_fields": [], "sensitive_value_present": False}]}}]
    raw_ad["health"] = [{"properties": copy.deepcopy(raw_ad["objects"][1]["properties"]), "checks": {"advertising_state": "passed", "dns_state": "timeout"},
                          "metadata": {"site_name": "Synthetic", "is_global_catalog": True, "is_read_only": False, "operation_master_roles": ["pdc_emulator"]}}]
    raw_ad["replication"] = [{"source_dc": "dc-a.invalid", "destination_dc": "dc-b.invalid", "naming_context": dn,
                              "last_replication_attempt_utc": stamp, "last_replication_success_utc": stamp, "consecutive_failure_count": 0, "last_replication_result": 0}]
    large_ad = copy.deepcopy(raw_ad)
    large_ad["objects"] += [obj(1000 + i, "ad_user", useraccountcontrol=512, primarygroupid=513, objectclass=["top", "user"]) for i in range(70)]
    members = [o["properties"]["distinguishedname"] for o in large_ad["objects"] if o["kind"] == "ad_user"]
    large_ad["objects"][3]["properties"].pop("member;range=0-*")
    large_ad["objects"][3]["properties"].update({"member;range=0-49": members[:50], "member;range=50-*": members[50:]})
    base = {"source_instance_id": HOST, "domain_sid": sid, "domain_dns": dns, "scope": dn,
            "dc": ["dc-a.invalid"], "schedule": {"timezone": "UTC", "hours": [6, 18]}}
    cases = [("ad-full", ad, raw_ad, {"expensive_flags": {"exact_last_logon": True, "dns": True, "ad_site": True}, "groups": ["privileged:" + sid + "-512", "vpn:" + sid + "-513"]}),
             ("ad-default", ad, raw_ad, {}), ("ad-limit", ad, raw_ad, {"max_objects": 1}),
             ("ad-chunks-and-ranges", ad, large_ad, {"families": ["ad_context_base"], "groups": []}),
             ("gpo-full", gpo, raw_gpo, {}), ("gpo-limit", gpo, {**raw_gpo, "overflow": True}, {})]
    result = []
    original_ad, original_computers, original_gpo = ad.uuid4, computers.uuid4, gpo.uuid4
    ad.uuid4 = computers.uuid4 = gpo.uuid4 = lambda: UUID(int=42)
    try:
        for name, module, raw, changes in cases:
            module_id = "sli.ad-snapshot" if module is ad else "sli.gpo-snapshot"
            cfg = policy(module_id, {**base, **changes})
            families = module.normalize_capture(copy.deepcopy(raw), cfg, **({"observed_at": NOW} if module is ad else {}))
            samples = []
            with tempfile.TemporaryDirectory() as folder:
                stream = SnapshotStream(Path(folder), module_id)
                state = stream.begin(cfg, now=NOW)
                state["cycle_id"] = str(UUID(int=43))
                from sli_agent.protection import atomic_write
                atomic_write(stream.root / "cycle.json", canonical(state))
                stream.freeze(state, families)
                captured = None
                while (sample := stream.next_sample(captured)) is not None:
                    samples.append({"payload_canonical": canonical(sample.payload).decode("ascii"), "cursor_before": sample.cursor_before, "cursor_after": sample.cursor_after})
                    captured = {"cursor_after": sample.cursor_after}
            result.append({"name": name, "module_id": module_id, "config": cfg, "raw": raw, "now": iso(NOW),
                           "families": {key: {"data_canonical": canonical(data).decode("ascii"), "count": count} for key, (data, count) in families.items()}, "samples": samples})
    finally:
        ad.uuid4, computers.uuid4, gpo.uuid4 = original_ad, original_computers, original_gpo
    return {"ad-schema.json": schema, "snapshot-scenarios.json": result}


def workstations_scenarios():
    """Stage-2 workstation behavior comes from the shipped Python collector."""
    from sli_agent.workstations import WorkstationsModule

    logons = {"logons": True, "processes": False, "usb": False, "local_admins": False, "protection": False}
    cases = [
        ("filtered-rate-recovery", {"families": logons, "batch_size": 3, "rate_limits": {"4624": 1}}, [
            {"mode": "rows", "rows": [(1, event(4624, 1)), (2, event(4624, 2)), (3, event(4688, 3))]},
            {"mode": "recovered", "rows": [(4, event(4625, 4))]},
            {"mode": "error", "rows": []},
        ]),
        ("rotation", {"batch_size": 4}, [
            {"mode": "rows", "rows": [(1, event(4624, 1))]},
            {"mode": "rows", "rows": [(2, event(7045, 2, channel="System", provider="Service Control Manager"))]},
            {"mode": "rows", "rows": []},
            {"mode": "rows", "rows": []},
            {"mode": "rows", "rows": []},
            {"mode": "rows", "rows": []},
        ]),
        ("process-filters", {"families": {**logons, "logons": False, "processes": True},
                             "allow_process_paths": ["c:/app[12]/*.exe"], "deny_process_paths": ["*/secret.exe"]}, [
            {"mode": "rows", "rows": [(1, event(4688, 1, data=[("NewProcessName", "C:\\app1\\safe.exe")])),
                                       (2, event(4688, 2, data=[("NewProcessName", "C:\\app2\\secret.exe")]))]},
        ]),
        ("tamper", {"families": {**logons, "logons": False, "protection": True}}, [
            {"mode": "rows", "rows": [(1, event(1102, 1, provider="Microsoft-Windows-Eventlog"))]},
            {"mode": "rows", "rows": [
                (2, event(7036, 2, channel="System", provider="Service Control Manager", data=[("param1", "SLI Agent .NET"), ("param2", "stopped")])),
                (3, event(7040, 3, channel="System", provider="Service Control Manager", data=[("param1", "WinDefend"), ("param3", "disabled")])),
                (4, event(7036, 4, channel="System", provider="Service Control Manager", data=[("param1", "Spooler")]))]},
            {"mode": "rows", "rows": []},
            {"mode": "rows", "rows": []},
            {"mode": "rows", "rows": [(5, event(4104, 5, channel="Microsoft-Windows-PowerShell/Operational", provider="Microsoft-Windows-PowerShell", data=[("ScriptBlockText", "fixture-script")]))]},
        ]),
    ]
    result = []
    components = ("antivirus_enabled", "real_time_protection_enabled", "behavior_monitor_enabled",
                  "ioav_protection_enabled", "nis_enabled", "tamper_protected")
    for name, config, scripts in cases:
        reader = ScriptedReader()
        module = WorkstationsModule(HOST, config, reader=reader,
            protection_reader=lambda: {"state": "unavailable", "components": dict.fromkeys(components)})
        captured, steps = None, []
        for index, script in enumerate(scripts):
            reader.script = {"mode": script["mode"], "rows": [
                {"xml": xml, "bookmark": f"<BookmarkList><Bookmark RecordId='{rid}'/></BookmarkList>"}
                for rid, xml in script["rows"]]}
            now = NOW + timedelta(seconds=index)
            sample = module.collect(captured, now=now)
            steps.append({"now": iso(now), "reader": copy.deepcopy(reader.script),
                          "payload_canonical": canonical(sample.payload).decode("ascii"),
                          "cursor_before": sample.cursor_before, "cursor_after": sample.cursor_after,
                          "continuity_state": sample.continuity_state, "filtered_count": sample.filtered_count,
                          "lost_count": sample.lost_count, "catch_up_channel": module.catch_up_channel})
            captured = {"generation": sample.generation, "cursor_after": sample.cursor_after}
        result.append({"name": name, "host_id": HOST, "config": config, "steps": steps})
    return result


def file_audit_scenarios():
    """File evidence, privacy, cursor and limits from the unmodified Python agent."""
    from unittest.mock import patch
    from uuid import UUID

    from sli_agent.file_audit import desired_aces
    from sli_agent.file_audit_collection import FileAuditModule
    from sli_agent.file_audit_journal import JournalGap
    from sli_agent.file_audit_policy import audit_requirements, policy

    root = {"collection_scope_id": "scope:one", "share_name": "synthetic", "path": r"C:\synthetic",
            "important": False, "sacl": {"trustee_sids": ["S-1-1-0"], "inherit_files": True, "inherit_directories": True}}
    fields = [("SubjectUserSid", "S-1-5-21-100000001-200000002-300000003-1000"), ("SubjectUserName", "private-account"),
              ("ObjectName", r"C:\synthetic\item"), ("ObjectType", "File"), ("HandleId", "0x44"),
              ("ProcessId", "0x10"), ("AccessMask", "0x10000"), ("Password", "private-secret")]
    cases = [
        ("events-restart-filter", {}, [[event(e, i + 1, data=fields) for i, e in enumerate((4663, 4656, 4660, 4670))],
            [event(4624, 5, data=[("LogonType", "2")]), event(4624, 6, data=[("LogonType", "3")])], []]),
        ("handle-negative-evidence", {}, [[event(4656, 1, data=[(k, r"C:\outside\private" if k == "ObjectName" else v) for k, v in fields])]]),
        ("workstation-accounts", {"source_kind": "workstation"}, [[event(4663, 1, data=fields), event(4663, 2, data=[(k, "S-1-5-18" if k == "SubjectUserSid" else v) for k, v in fields])]]),
        ("initial-bound", {"initial_read_hours": 2}, [[]]),
        ("read-error", {}, [None]),
        ("path-unavailable", {}, [[event(4663, 1, data=fields)]]),
        ("clear-event", {}, [[event(1102, 1, data=[], provider="Microsoft-Windows-Eventlog")]]),
        ("xml-whitespace-privacy", {}, [[event(4663, 1, data=fields).replace("<EventData>", "<EventData>\n  ").replace("</Data>", "</Data>\n  ")]]),
        ("journal-gap", {}, [[event(4663, 1, data=fields)], "gap", []]),
        ("important-optional", {"optional_events": True}, [[event(e, i + 1, data=fields) for i, e in enumerate((4658, 4664, 5145))]]),
    ]
    result = []
    for name, extra, batches in cases:
        config = {"roots": [{**root, **({"share_name": ""} if extra.get("source_kind") == "workstation" else {})}], **extra}
        if name == "important-optional":
            config["roots"][0]["important"] = True
        current = {"rows": []}
        def reader(channel, progress, limit, current=current):
            current["progress"] = copy.deepcopy(progress)
            if current["rows"] is None:
                raise RuntimeError("synthetic-private-error")
            if current["rows"] == "gap":
                raise JournalGap()
            return [(row["xml"], row["bookmark"]) for row in current["rows"]]
        def path_check(path, scope, name=name):
            if name == "path-unavailable":
                raise OSError("synthetic-private-path")
        module = FileAuditModule(HOST, config, reader=reader, path_check=path_check, account_check=lambda sid: True)
        captured, steps = None, []
        for index, batch in enumerate(batches):
            current["rows"] = batch if batch is None or batch == "gap" else [{"xml": raw, "bookmark": f"bookmark-{index}-{i}"} for i, raw in enumerate(batch)]
            with patch("sli_agent.file_audit_collection.uuid4", return_value=UUID("00000000-0000-4000-8000-000000000001")):
                sample = module.collect(captured, now=NOW + timedelta(seconds=index))
            steps.append({"now": iso(NOW + timedelta(seconds=index)), "rows": current["rows"], "progress": current["progress"],
                          "payload_canonical": canonical(sample.payload).decode("ascii"), "cursor_before": sample.cursor_before,
                          "cursor_after": sample.cursor_after, "continuity_state": sample.continuity_state,
                          "filtered_count": sample.filtered_count, "lost_count": sample.lost_count})
            captured = {"generation": sample.generation, "cursor_after": sample.cursor_after}
        result.append({"name": name, "host_id": HOST, "config": config, "normalized": policy(config),
                       "aces": desired_aces(config["roots"][0]), "required_masks": audit_requirements(config), "steps": steps})
    return result


def file_audit_inventory():
    from contextlib import contextmanager

    from sli_agent.control import collection_policy
    from sli_agent.file_audit import FileAuditManager
    from sli_agent.windows_audit import AuditManager

    config = file_audit_scenarios()[0]["config"]
    class Audit:
        def is_system(self): return True
        def ownership(self): return "ok"
        def command_line(self): return None
        def query(self, guids): return dict.fromkeys(guids, 3)
        def set(self, changes): raise AssertionError("all masks already present")
    class Object:
        def __init__(self):
            self.row = {"object_id": "1:2:3", "object_type": "directory", "owner_sid": "S-1-5-18",
                        "dacl": "D:(A;;FA;;;SY)", "sacl": "S:old", "sacl_protected": False}
        def describe(self): return copy.deepcopy(self.row)
        def plan(self, aces): return "S:exact-inheritance"
        def expected_sacl(self, value): return value if value == "S:old" else "S:exact-inheritance"
        def set_sacl(self, value): self.row["sacl"] = value
        def children(self): return iter(())
        def inherited_from(self, previous, applied): return False
    class API:
        def __init__(self): self.obj = Object()
        def preflight(self, roots): return "ok"
        @contextmanager
        def open(self, path, root): yield self.obj
        def share(self, name, root): return {"name": name, "path": root, "dacl": "D:(A;;FA;;;SY)", "complete": True}
        def local_groups(self, limit): return {"complete": True, "groups": []}
    result = []
    with tempfile.TemporaryDirectory() as directory:
        for action in ("check", "apply", "restore"):
            root = Path(directory) / action
            api = API()
            manager = FileAuditManager(root / "file", AuditManager(root / "audit", api=Audit()), api=api)
            steps = []
            actions = ("apply", "restore") if action == "restore" else (action,)
            for index, verb in enumerate(actions):
                request = {"config": config, "command": {"contract_id": "sli.file-audit.audit-command.v1", "command_id": f"inventory-{verb}",
                    "action": verb, "policy_revision": "1", "collection_scope_ids": ["scope:one"]}}
                _, report = manager.reconcile([], collection_policy({"manage_windows_audit": True}), 1, request, now=NOW)
                steps.append({"request": request, "report_canonical": canonical(report).decode("ascii")})
                manager.acknowledge(report)
            result.append({"name": action, "now": iso(NOW), "steps": steps})
    return result


def nps_vectors():
    """NPS and the real bounded Accounting tail with deterministic, synthetic file metadata."""
    import csv
    import io
    from dataclasses import asdict
    from hashlib import sha256
    from unittest.mock import patch

    from sli_agent.nps import AccountingModule, NPSModule, policy
    from sli_collect import radius_tail as tail
    from sli_collect.radius_accounting import DATABASE_COMPATIBLE_COLUMNS
    from sli_collect.radius_contract import initial_cursor

    def sample_value(sample):
        return {"payload_canonical": canonical(sample.payload).decode("ascii"), "cursor_before": sample.cursor_before,
                "cursor_after": sample.cursor_after, "continuity_state": sample.continuity_state,
                "filtered_count": sample.filtered_count, "lost_count": sample.lost_count}

    fields = [("SubjectUserName", "synthetic-user"), ("CallingStationID", "192.0.2.44"),
              ("NASIdentifier", "synthetic-gateway"), ("ReasonCode", "16")]
    def evt(eid, rid, extra=(), **kwargs):
        return event(eid, rid, data=fields + list(extra), **kwargs)

    first = evt(6272, 1)
    secret = evt(6273, 2, [("SharedSecret", "never-persist-this"), ("Password", "never-persist-this")])
    whitespace = secret.replace("<EventData>", "<EventData>\n  ").replace("</Data>", "</Data>\n  ")
    namespace = secret.replace("<Event ", '<Event xmlns:x="urn:synthetic" x:flag="yes" ').replace("</Event>", '<x:Private>never-persist-this</x:Private></Event>')
    cases = [
        ("nps-filter-privacy", {"batch_size": 4}, [{"rows": [evt(4624, 1), secret, evt(6274, 3), evt(6272, 4, provider="Other-Provider")]}, {"rows": []}]),
        ("nps-continuity-restart", {}, [{"rows": [first]}, {"rows": [first, evt(6273, 2)]}, {"rows": [first, evt(6273, 2)]}]),
        ("nps-backlog", {"batch_size": 2}, [{"rows": [evt(6272, n) for n in range(1, 5)]}] * 2),
        ("nps-record-gap", {}, [{"rows": [first]}, {"rows": [first, evt(6273, 4)]}]),
        ("nps-policy-reset", {}, [{"rows": [first]}, {"rows": [first], "config": {"event_generation": "2"}}]),
        ("nps-whitespace", {}, [{"rows": [whitespace]}]),
        ("nps-namespace", {}, [{"rows": [namespace]}]),
        ("nps-read-error", {}, [{"rows": [first]}, {"error": "agent_nps_read_failed"}, {"rows": [first]}]),
        ("nps-size-budget", {}, [{"rows": [evt(6272, n, [("Reason", "я" * 1800)]) for n in range(1, 4)]}] * 2),
        ("nps-duplicate-field", {}, [{"rows": [evt(6272, 1, [("SubjectUserName", "other")])]}]),
        ("nps-wrong-channel", {}, [{"rows": [evt(6272, 1, channel="System")]}]),
        ("nps-size-error", {}, [{"rows": [evt(6272, 1, [("Reason", "a" * 44000)])]}]),
    ]
    scenarios = []
    for name, changes, scripts in cases:
        config = {"source_instance_id": "synthetic-radius", "source_name": "synthetic-nps", "connect_address": "synthetic.invalid", **changes}
        captured, steps = None, []
        for i, script in enumerate(scripts):
            config = {**config, **script.get("config", {})}
            rows = [{"xml": xml, "bookmark": f"bookmark-{i}-{n}", "record_id": parse_event_xml(xml, source_name="", connect_address="", channel="Security")["record_id"]}
                    for n, xml in enumerate(script.get("rows", []))]
            # Bookmarks for retained events stay stable across source snapshots.
            for row in rows:
                row["bookmark"] = f"bookmark-{row['record_id']}"
            def reader(_channel, progress, limit, rows=rows, script=script):
                if "error" in script:
                    raise ValueError(script["error"])
                return [(r["xml"], r["bookmark"]) for r in rows if progress["record_id"] is None or r["record_id"] > progress["record_id"]][:limit]
            now = NOW + timedelta(minutes=i)
            step = {"now": iso(now), "config": policy("sli.vpn-nps", config), "rows": rows, **({"read_error": script["error"]} if "error" in script else {})}
            try:
                sample = NPSModule(HOST, config, reader=reader).collect(captured, now=now)
                step.update(sample_value(sample))
                captured = {"generation": HOST, "cursor_after": sample.cursor_after}
            except ValueError as exc:
                step["error"] = str(exc)
            steps.append(step)
        scenarios.append({"name": name, "module_id": "sli.vpn-nps", "host_id": HOST, "steps": steps})

    def line(status="1", extra=""):
        row = [""] * len(DATABASE_COMPATIBLE_COLUMNS)
        for key, value in {"ComputerName": "synthetic-nps", "ServiceName": "IAS", "Record-Date": "10/07/2026", "Record-Time": "12:00:00",
                           "Packet-Type": "4", "Acct-Status-Type": status, "NAS-Identifier": "synthetic-gateway", "Acct-Session-Id": "synthetic-session",
                           "User-Name": "synthetic-user" + extra, "Class": "synthetic-class"}.items():
            row[DATABASE_COMPATIBLE_COLUMNS.index(key)] = value
        output = io.StringIO()
        csv.writer(output).writerow(row)
        return output.getvalue().rstrip("\r\n")

    record = line().encode()
    digest = sha256(record).hexdigest()
    def file(n, data):
        return {"name": f"IN{n:06}.log", "creation_time_ns": 1700000000000000000 + n * 100,
                "modified_time_ns": 1700000000000000000 + n * 1000, "data_b64": base64.b64encode(data).decode("ascii")}
    base = file(0, b"")
    blank = file(0, b" \r\n\t\n" + record + b"\n")
    rotations = [base, file(1, b""), file(2, b" \n"), file(3, record + b"\n")]
    anchored = file(0, record + b"\n")
    old_blanks = file(1, b" " * len(record) + b"\n")
    partial = [base, file(1, record[:-5])]
    complete = [base, file(1, record + b"\n")]
    large = (line(extra="я" * 3000).encode() + b"\n") * 2
    cases = [
        ("radius-blank-progress", {"batch_size": 2}, [[blank]] * 3),
        ("radius-empty-rotations", {"batch_size": 2}, [rotations] * 4),
        ("radius-partial-append", {}, [partial, complete, complete]),
        ("radius-unanchored-lost", {"offset": len(record) + 1, "hash": digest}, [[anchored, old_blanks], [anchored]]),
        ("radius-empty-initial-lost", {}, [[base], []]),
        ("radius-legacy-recovery", {"generation": "legacy-missing", "offset": len(record) + 1, "hash": digest}, [[anchored]]),
        ("radius-ambiguous-recovery", {"generation": "legacy-missing", "offset": len(record) + 1, "hash": digest}, [[anchored, file(1, record + b"\n")]]),
        ("radius-same-generation-blanks", {"offset": len(record) + 1, "hash": digest, "recovery": True}, [[file(0, record + b"\n \n")]]),
        ("radius-budget", {}, [[file(0, large)]] * 2),
        ("radius-bom-quoted-unicode", {}, [[file(0, b"\xef\xbb\xbf" + line(extra='я,"quote"').encode() + b"\r\n")]]),
        ("radius-invalid-csv", {}, [[file(0, b"User-Password,never-persist-this\n")]]),
        ("radius-invalid-encoding", {}, [[file(0, b"\xff\n")]]),
        ("radius-blank-large", {"batch_size": 1}, [[file(0, b" " * 100000 + b"\n" + record + b"\n")]] * 2),
        ("radius-incomplete-large", {}, [[file(0, b"x" * 65537)]]),
        ("radius-past-eof", {"offset": 100}, [[base]]),
    ]
    for name, changes, scripts in cases:
        first_file = scripts[0][0]
        cursor = asdict(initial_cursor(source_instance_id="synthetic-radius", transport_binding="synthetic-tail",
            file_generation=changes.get("generation", tail.derive_file_generation(source_instance_id="synthetic-radius", file_name=first_file["name"], file_creation_time_ns=first_file["creation_time_ns"]))))
        cursor.update(byte_offset=changes.get("offset", 0), last_record_sha256=changes.get("hash"))
        if "recovery" in changes:
            cursor["exact_boundary_recovery"] = changes["recovery"]
        config = {"source_instance_id": "synthetic-radius", "accounting_directory": "synthetic-accounting", "initial_cursor": cursor,
                  "subscription_id": "synthetic-subscription", "source_timezone_id": "UTC", "source_utc_offset_minutes": 0, "batch_size": changes.get("batch_size", 32)}
        captured, steps = None, []
        with tempfile.TemporaryDirectory() as directory:
            for i, specs in enumerate(scripts):
                def inventory(_directory, source, specs=specs):
                    for spec in specs:
                        path = Path(directory) / spec["name"]
                        path.write_bytes(base64.b64decode(spec["data_b64"]))
                        stat = path.stat()
                        yield tail._Candidate(path, tail.derive_file_generation(source_instance_id=source, file_name=spec["name"], file_creation_time_ns=spec["creation_time_ns"]),
                            spec["creation_time_ns"], stat.st_dev, stat.st_ino, spec["modified_time_ns"], stat.st_size)
                def reader(_directory, config=config, **kwargs):
                    return tail.read_bounded_tail(Path(directory), maximum_records=config["batch_size"], maximum_payload_bytes=44 * 1024 - 4096, **kwargs)
                now = NOW + timedelta(minutes=i)
                step = {"now": iso(now), "config": policy("sli.radius-accounting", config), "files": specs}
                with patch.object(tail, "_inventory", inventory):
                    try:
                        sample = AccountingModule(HOST, config, reader=reader).collect(captured, now=now)
                        step.update(sample_value(sample))
                        captured = {"generation": HOST, "cursor_after": sample.cursor_after}
                    except (ValueError, tail.RadiusTailReadError) as exc:
                        step["error"] = str(exc)
                steps.append(step)
        scenarios.append({"name": name, "module_id": "sli.radius-accounting", "host_id": HOST, "steps": steps})
    return {"nps-scenarios.json": scenarios}


def strip_signatures(value):
    if isinstance(value, dict):
        return {k: ("<signature>" if k == "signature" else strip_signatures(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [strip_signatures(v) for v in value]
    return value


def dump(value) -> str:
    return json.dumps(value, ensure_ascii=False, indent=1, sort_keys=True) + "\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="compare with the committed vectors (signatures ignored)")
    parser.add_argument("--snapshots", action="store_true", help="generate/check only stage-3 snapshot vectors")
    parser.add_argument("--file-audit", action="store_true", help="generate/check only file-audit vectors")
    parser.add_argument("--nps", action="store_true", help="generate/check only NPS/Accounting vectors")
    args = parser.parse_args()
    selected = ({"file-audit-scenarios.json": file_audit_scenarios(), "file-audit-inventory.json": file_audit_inventory()}
                if args.file_audit else nps_vectors() if args.nps else snapshot_vectors() if args.snapshots else build())
    built = {VECTORS / name: value for name, value in selected.items()}
    if not args.snapshots and not args.file_audit and not args.nps:
        built[CATALOG] = catalog_snapshot()
    VECTORS.mkdir(parents=True, exist_ok=True)
    CATALOG.parent.mkdir(parents=True, exist_ok=True)
    stale = []
    for path, value in built.items():
        name = path.name
        if args.check:
            current = json.loads(path.read_text("utf-8")) if path.exists() else None
            if current is None or strip_signatures(current) != strip_signatures(json.loads(dump(value))):
                stale.append(name)
        else:
            path.write_text(dump(value), encoding="utf-8")
    if args.check:
        if stale:
            print("stale vectors: " + ", ".join(stale) + "; run agent-dotnet/tools/make_vectors.py", file=sys.stderr)
            return 1
        print("vectors are current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

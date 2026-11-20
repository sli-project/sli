"""Contract test of the reference Linux auth.log pack (ADR 0012, point 5)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from server.sli.events.event_catalog_quality import validate_catalog_data
from server.source_packs import normalizers, registry
from server.source_packs.contracts import EventEntitySemantics
from server.source_packs.examples import linux_auth

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "config" / "source_packs" / "examples" / "linux_auth.json"
FIXTURE = ROOT / "tests" / "fixtures" / "linux_auth" / "auth.log.txt"


@pytest.fixture
def pack(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(normalizers, "_ENTRY_NORMALIZERS", {})
    return registry._load_manifest(MANIFEST)


def _events() -> tuple[list[dict], int]:
    lines = FIXTURE.read_text(encoding="utf-8").splitlines()
    parsed = [linux_auth.parse_line(line, 2026, "UTC") for line in lines]
    return [event for event in parsed if event], len(lines)


def test_manifest_loads_through_v2_entry_and_is_not_a_product_pack(pack) -> None:
    assert pack.pack_id == "example.linux-auth"
    assert pack.normalizer_id == "example-linux-auth-v1"
    assert pack.channels == ("linux:auth",)
    assert pack.capabilities == ("authentication", "privilege_use")
    assert normalizers.get_source_normalizer("example-linux-auth-v1") is not None
    assert "example.linux-auth" not in {item.pack_id for item in registry._source_packs()}
    catalog = json.loads(pack.catalog_path.read_text(encoding="utf-8"))
    assert validate_catalog_data(catalog)["valid"] is True
    assert {code for _, _, code in pack.event_identities} == {str(i) for i in linux_auth.EVENT_IDS}


def test_only_required_handlers_are_defined_and_defaults_cover_the_rest(pack) -> None:
    normalizer = normalizers.get_source_normalizer("example-linux-auth-v1")
    assert normalizer.event_facts is linux_auth.event_facts
    assert normalizer.entity_semantics is linux_auth.entity_semantics
    assert normalizer.event_label is linux_auth.event_label
    for name in normalizers._OPTIONAL_DEFAULTS:
        assert not hasattr(linux_auth, name), name
    assert normalizer.finding_rules() == {}
    assert normalizer.event_ids_for_search_family("authentication") == ()
    assert normalizer.state_semantics(channel="linux:auth", event_id=100) is None


def test_fixture_is_parsed_honestly_and_unknown_lines_are_skipped() -> None:
    events, total = _events()
    assert total == 15
    assert [e["event_id"] for e in events] == [100, 120, 110, 101, 101, 100, 100, 121, 121]
    first = events[0]
    assert (first["user"], first["source_ip"], first["auth_method"], first["host"]) == (
        "alice", "192.0.2.10", "publickey", "web01.example.test")
    assert first["time"] == datetime(2026, 9, 30, 10, 15, 1, tzinfo=timezone.utc)
    assert events[2]["command"] == "/usr/bin/apt update" and events[2]["user"] == "alice"
    assert events[4]["user"] == "admin"  # "invalid user" prefix is not part of the name
    assert events[6]["time"].day == 1  # single-digit day padded with two spaces
    # cron session, sudo PAM session, preauth close, garbage, kernel, Feb 30: never guessed
    assert linux_auth.parse_line("", 2026) is None
    assert linux_auth.parse_line("Feb 30 10:34:00 h sshd[1]: Accepted password for a from 192.0.2.1 port 1", 2026) is None


def test_parse_line_converts_timezone_to_utc() -> None:
    line = "Sep 30 10:00:00 h.example.test sshd[1]: Accepted password for alice from 192.0.2.1 port 22 ssh2"
    event = linux_auth.parse_line(line, 2026, timezone(timedelta(hours=3)))
    assert event["time"] == datetime(2026, 9, 30, 7, 0, tzinfo=timezone.utc)


def test_handlers_follow_the_event_model(pack) -> None:
    normalizer = normalizers.get_source_normalizer("example-linux-auth-v1")
    events, _ = _events()
    for event in events:
        facts = normalizer.event_facts(row=event, event_data=event)
        assert set(facts) == {
            "process_name", "process_id", "target_server_name", "service_name", "task_name",
            "task_action", "task_author", "run_as", "logon_type", "result_code", "object_name",
            "share_name", "message_sample",
        }
        assert facts["target_server_name"] == event["host"]
        assert normalizer.entity_semantics(channel="linux:auth", event_id=event["event_id"]) == EventEntitySemantics()
        assert normalizer.event_label(event["event_id"], "ru")
        assert normalizer.event_label(event["event_id"], "en") != normalizer.event_label(event["event_id"], "ru")
    accepted, sudo = events[0], events[2]
    assert normalizer.event_facts(row=accepted, event_data=accepted)["result_code"] == "success"
    assert normalizer.event_facts(row=events[3], event_data=events[3])["result_code"] == "failure"
    assert normalizer.event_facts(row=sudo, event_data=sudo)["object_name"] == "/usr/bin/apt update"
    assert normalizer.event_facts(row={"event_id": 4624}, event_data={}) == {}
    assert normalizer.event_label(4624, "ru") is None

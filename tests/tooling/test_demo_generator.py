"""Offline tests of the synthetic demo event generator (plan 9.4).

No database is used.  The importer's pure per-record functions are called
directly; steps that need a disposable PostgreSQL (insert, entity upsert,
capture-declaration persistence) are deliberately not exercised here.
"""
from __future__ import annotations

import importlib
import ipaddress
import json
import re
from itertools import pairwise
from pathlib import Path

import pytest

from server.sli.sources.source_capture_continuity import (
    build_capture_declaration,
    capture_scope_from_collection_summary,
)
from server.source_packs.registry import resolve_source_pack

generator = importlib.import_module("scripts.demo.generate_demo_events")
importer = importlib.import_module("scripts.import.import_event_jsonl_to_postgres")

RFC5737 = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
HOSTLIKE = re.compile(r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}\b", re.IGNORECASE)
EXPECTED_SYSTEM_IDS = {142, 5805, 6013, 7036, 7040, 7045}
EXPECTED_IDS = {
    4624, 4625, 4634, 4672, 4719, 4720, 4722, 4723, 4724, 4726, 4728, 4729,
    4732, 4733, 4740, 4756, 4767, 6272, 6273,
}


def _generate(tmp_path: Path, name: str = "out", **kwargs):
    result = generator.generate(tmp_path / name, **kwargs)
    return tmp_path / name, result


def _files(root: Path) -> dict[str, bytes]:
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


def _rows(batch: Path, channel: str = "Security") -> list[dict]:
    return list(importer.iter_jsonl(batch / f"{channel}.jsonl"))


@pytest.fixture(scope="module")
def default_out(tmp_path_factory):
    root = tmp_path_factory.mktemp("demo")
    out, result = _generate(root)
    return out, result


def test_output_is_deterministic_and_seed_sensitive(tmp_path, default_out) -> None:
    out, _ = default_out
    again, _ = _generate(tmp_path, "again")
    assert _files(out) == _files(again)
    other, _ = _generate(tmp_path, "other", seed=2)
    assert _files(out) != _files(other)
    assert set(_files(out)) == set(_files(other))


def test_out_inside_data_is_refused(tmp_path) -> None:
    target = generator.ROOT / "data" / "demo_refused_probe"
    with pytest.raises(ValueError, match="out_dir_inside_data_refused"):
        generator.generate(target)
    assert not target.exists()
    assert generator.main(["--out", str(generator.ROOT / "data")]) == 2
    assert generator.main(["--out", str(tmp_path / "ok"), "--users", "1"]) == 2


def test_batch_layout_and_event_mix(default_out) -> None:
    out, result = default_out
    assert sorted(p.name for p in out.iterdir()) == ["DC01-20260115-000000", "DC02-20260115-000000"]
    seen: set[int] = set()
    for dc in ("DC01", "DC02"):
        batch = out / f"{dc}-20260115-000000"
        assert sorted(p.name for p in batch.iterdir()) == [
            "Security.jsonl", "System.jsonl", "collection-summary.json"]
        seen |= {int(k) for k in result[dc]["by_event_id"]}
    assert seen == EXPECTED_IDS
    for event_id in seen:
        pack = resolve_source_pack("Security", generator.PROVIDER, str(event_id))
        assert pack is not None, event_id


def test_system_channel_rows_and_catalog(default_out) -> None:
    out, result = default_out
    seen: set[int] = set()
    for dc in ("DC01", "DC02"):
        batch = out / f"{dc}-20260115-000000"
        rows = _rows(batch, "System")
        assert rows and len(rows) == result[dc]["system_events"]
        ids = [r["record_id"] for r in rows]
        times = [r["time_created"] for r in rows]
        assert ids == sorted(set(ids)) and all(a < b for a, b in pairwise(times))
        for row in rows:
            seen.add(row["event_id"])
            assert row["channel"] == "System" and row["machine_name"] == f"{dc}.example.test"
            assert "<Channel>System</Channel>" in row["xml"]
            assert resolve_source_pack("System", row["provider_name"], str(row["event_id"])) is not None
            data = importer.parse_event_data(row["xml"])
            assert "_sli_data_quality" not in data
            assert data.pop("SystemExecutionProcessId") == str(generator.SYSTEM_PROCESS_ID)
            assert [str(v) for v in data.values()] == row["properties"]
    assert seen == EXPECTED_SYSTEM_IDS
    install = [r for r in _rows(out / "DC01-20260115-000000", "System") if r["event_id"] == 7045]
    assert len(install) == 1
    assert importer.parse_event_data(install[0]["xml"])["ServiceName"] == "Demo Inventory Agent"


def test_system_channel_does_not_change_security_output(tmp_path, default_out) -> None:
    out, _ = default_out
    end = generator._utc(generator.DEFAULT_END)
    events = generator.generate_events(days=7, seed=1, users=25, end=end)
    again = tmp_path / "sec-only"
    generator.write_batches(again, events, start=end - generator.timedelta(days=7), end=end, days=7)
    for dc in ("DC01", "DC02"):
        name = f"{dc}-20260115-000000"
        assert (again / name / "Security.jsonl").read_bytes() == (out / name / "Security.jsonl").read_bytes()
        assert not (again / name / "System.jsonl").exists()


def test_record_ids_and_timestamps_are_monotonic(default_out) -> None:
    out, _ = default_out
    for batch in out.iterdir():
        rows = _rows(batch)
        assert rows
        ids = [r["record_id"] for r in rows]
        times = [r["time_created"] for r in rows]
        assert ids == sorted(set(ids))
        assert all(a < b for a, b in pairwise(times))  # fixed-width ISO strings


def test_brute_force_burst_then_lockout(default_out) -> None:
    out, _ = default_out
    rows = _rows(out / "DC01-20260115-000000")
    burst = [r for r in rows if r["event_id"] == 4625 and generator.ATTACKER_IP in r["xml"]]
    lock = [r for r in rows if r["event_id"] == 4740]
    assert len(burst) == 60 and len(lock) == 1
    assert len({importer.parse_event_data(r["xml"])["TargetUserName"] for r in burst}) == 1
    assert lock[0]["time_created"] > burst[9]["time_created"]


def test_only_reserved_names_and_addresses(default_out) -> None:
    out, _ = default_out
    for path in out.rglob("*"):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8").replace(generator.EVENT_NS, "").replace(
            "sli.source-capture-continuity.v1", "")
        for ip in IPV4.findall(text):
            address = ipaddress.ip_address(ip)
            assert address.is_loopback or any(address in net for net in RFC5737), ip
        for host in HOSTLIKE.findall(text):
            if host.lower() in {"security.jsonl", "system.jsonl", "collection-summary.json", "agent.exe"}:
                continue
            assert host.lower() == "example.test" or host.lower().endswith(".example.test"), host
        for sid in re.findall(r"S-1-5-21-[\d-]+", text):
            assert sid.startswith(generator.SID_PREFIX + "-"), sid


def test_every_record_passes_importer_parsing(default_out) -> None:
    out, _ = default_out
    total = 0
    for batch in out.iterdir():
        for row in _rows(batch):
            total += 1
            data = importer.parse_event_data(row["xml"])
            assert "_sli_data_quality" not in data
            assert data.pop("SystemExecutionProcessId") == "672"
            assert [str(v) for v in data.values()] == row["properties"]
            data["SystemExecutionProcessId"] = "672"
            params = dict(zip(
                importer.EVENT_COLUMNS,
                importer._event_params(
                    raw_log_file_id=1, server_id=2, domain_id=3, site_id=4, log_source_id=5,
                    row=row, event_data=data,
                ),
                strict=True,
            ))
            assert params["event_id"] == row["event_id"]
            assert params["event_record_id"] == row["record_id"]
            assert params["channel"] == "Security"
            assert params["provider_name"] == generator.PROVIDER
            assert params["computer"] == row["machine_name"]
            assert len(params["normalized_hash"]) == 64
            assert importer.event_normalized_hash(row) == params["normalized_hash"]
            assert importer._event_key("Security", row["record_id"], row["time_created"])[1] == row["record_id"]
            assert params["logon_id"] is not None or row["event_id"] in {4625, 4719, 4720, 4722,
                4723, 4724, 4726, 4728, 4729, 4732, 4733, 4740, 4756, 4767, 6272, 6273}
            entities = importer.extract_event_entities(row, data)
            assert any(link["entity_type"] == "asset" for link in entities)
    assert total > 300


def test_actor_and_target_fields_match_what_was_generated(default_out) -> None:
    out, _ = default_out
    rows = _rows(out / "DC01-20260115-000000") + _rows(out / "DC02-20260115-000000")

    def params_for(row):
        data = importer.parse_event_data(row["xml"])
        return dict(zip(importer.EVENT_COLUMNS, importer._event_params(
            raw_log_file_id=1, server_id=2, domain_id=3, site_id=4, log_source_id=5,
            row=row, event_data=data), strict=True))

    sid_prefix = generator.SID_PREFIX
    logon = next(r for r in rows if r["event_id"] == 4624 and "user001" in r["properties"])
    p = params_for(logon)
    assert p["subject_user_sid"] == "S-1-5-18" and p["subject_user_name"].endswith("$")
    assert p["target_user_name"] == "user001" and p["target_user_sid"] == f"{sid_prefix}-1100"
    assert p["target_domain_name"] == "EXAMPLE" and p["workstation_name"] == "WS001"
    assert ipaddress.ip_address(p["ip_address"]) in RFC5737[0] or ipaddress.ip_address(p["ip_address"]) in RFC5737[1]
    assert p["logon_id"].startswith("0x")

    created = next(r for r in rows if r["event_id"] == 4720)
    p = params_for(created)
    assert p["subject_user_name"] == "adm001" and p["subject_user_sid"] == f"{sid_prefix}-1001"
    assert p["target_user_name"].startswith("demo") and p["target_user_sid"].startswith(sid_prefix)

    lockout = next(r for r in rows if r["event_id"] == 4740)
    p = params_for(lockout)
    assert p["target_user_name"] == "user003" and p["target_user_sid"] == f"{sid_prefix}-1102"

    failure = next(r for r in rows if r["event_id"] == 4625 and generator.ATTACKER_IP in r["xml"])
    assert params_for(failure)["ip_address"] == generator.ATTACKER_IP

    nps = next(r for r in rows if r["event_id"] == 6272)
    p = params_for(nps)
    assert p["correlation_id"]  # AccountSessionIdentifier via the NPS source normalizer
    assert p["subject_user_name"].startswith("user")


def test_collector_row_shape_matches_collector_parser(default_out) -> None:
    collector = pytest.importorskip("scripts.collect.collect_windows_events")
    out, _ = default_out
    row = _rows(out / "DC01-20260115-000000")[0]
    parsed = collector.parse_event_xml(
        row["xml"], source_name=row["computer_name"], connect_address=row["connect_address"],
        channel="Security",
    )
    assert parsed == row
    for system_row in _rows(out / "DC02-20260115-000000", "System"):
        assert collector.parse_event_xml(
            system_row["xml"], source_name=system_row["computer_name"],
            connect_address=system_row["connect_address"], channel="System",
        ) == system_row


@pytest.mark.parametrize("dc", ["DC01", "DC02"])
def test_collection_summary_accepted_by_capture_continuity(default_out, dc) -> None:
    out, _ = default_out
    batch = out / f"{dc}-20260115-000000"
    summary = json.loads((batch / "collection-summary.json").read_text(encoding="utf-8"))
    assert importer._collection_summary(batch / "Security.jsonl") == summary
    assert [c["channel"] for c in summary["channels"]] == ["Security", "System"]
    assert [c["file"] for c in summary["channels"]] == ["Security.jsonl", "System.jsonl"]
    assert summary["channels"][1]["count"] == len(_rows(batch, "System"))
    for channel in ("Security", "System"):
        _check_capture(summary, batch, channel)


def _check_capture(summary, batch, channel) -> None:
    rows = _rows(batch, channel)
    provider = generator.PROVIDER if channel == "Security" else generator.SCM_PROVIDER
    source_events = [
        {
            "id": index + 1, "record_id": row["record_id"], "event_key": row["event_id"],
            "normalized_hash": importer.event_normalized_hash(row),
        }
        for index, row in enumerate(rows)
    ]
    scope = capture_scope_from_collection_summary(
        summary, raw_file_name=f"{channel}.jsonl",
        base_scope={
            "collection_run_id": 1, "raw_log_file_id": 1, "raw_log_sha256": "0" * 64,
            "server_id": 1, "log_source_id": 1, "descriptor_source": "sli.windows.ad-dc",
            "descriptor_stream": channel, "provider_name": provider,
            "channel_value": channel,
        },
        source_events=source_events,
    )
    assert scope is not None
    assert scope["capture_latest_record_id"] == rows[-1]["record_id"]
    assert scope["capture_after_record_id"] < rows[0]["record_id"]
    declaration = build_capture_declaration(scope)
    assert declaration.complete and len(declaration.source_record_ids) == len(rows)

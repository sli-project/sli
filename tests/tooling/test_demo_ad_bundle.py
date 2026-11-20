"""Synthetic AD Context bundle for the demo (plan 9.4): offline, deterministic, contract-valid."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from scripts.demo import generate_demo_ad_bundle as generator
from scripts.demo.generate_demo_events import SID_PREFIX, _World
from server.ad_context.contracts import load_bundle


def test_bundle_is_deterministic_and_accepted_by_the_product_loader(tmp_path: Path) -> None:
    first = generator.write_bundle(tmp_path / "a", users=12)
    second = generator.write_bundle(tmp_path / "b", users=12)
    assert first.read_bytes() == second.read_bytes()
    bundle = load_bundle(first)
    assert bundle["domain"] == {"sid": SID_PREFIX, "dns_name": "example.test"}
    assert {section["name"]: section["record_count"] for section in bundle["sections"]} == {
        "directory_accounts": 2 + 12 + len(generator.GROUPS) + len(generator.computer_accounts(12)),
        "privileged_membership": 2,
        "vpn_membership": 6,
    }


def test_bundle_accounts_match_the_demo_event_world(tmp_path: Path) -> None:
    bundle = load_bundle(generator.write_bundle(tmp_path, users=8))
    world = _World(8)
    users = {
        record["identity"]["object_sid"]: record["attributes"]["sam_account_name"]
        for record in bundle["records"]
        if record["record_type"] == "entity" and record["identity"]["kind"] == "ad_user"
    }
    assert users == {account["sid"]: account["name"] for account in [*world.admins, *world.users]}
    groups = {
        record["attributes"]["sam_account_name"]: record["identity"]["object_sid"]
        for record in bundle["records"]
        if record["record_type"] == "entity" and record["identity"]["kind"] == "ad_group"
    }
    # The groups the demo events add to and remove from.
    assert groups["Staff"] == f"{SID_PREFIX}-1500" and groups["Ops-Universal"] == f"{SID_PREFIX}-1501"
    privileged = {
        record["source_record_key"] for record in bundle["records"]
        if record["record_type"] == "relation" and record["section"] == "privileged_membership"
    }
    assert privileged == {f"entity:{account['sid']}" for account in world.admins}


def test_bundle_has_computers_consistent_with_the_demo_events(tmp_path: Path) -> None:
    bundle = load_bundle(generator.write_bundle(tmp_path, users=12))
    world = _World(12)
    computers = {
        record["attributes"]["sam_account_name"]: record
        for record in bundle["records"]
        if record["record_type"] == "entity" and record["identity"]["kind"] == "ad_computer"
    }
    names = {name.rstrip("$") for name in computers}
    assert {"DC01", "DC02", "FS01", "WS900", "WS901", "WS001", "WS003"} <= names
    # Workstations the demo events name (admin hosts and the first users' hosts).
    assert {account["host"] for account in world.admins} <= names
    assert {account["host"] for account in world.users[:3]} <= names
    sids = [record["identity"]["object_sid"] for record in computers.values()]
    assert len(sids) == len(set(sids)) and all(sid.startswith(f"{SID_PREFIX}-") for sid in sids)
    user_sids = {account["sid"] for account in [*world.admins, *world.users]}
    assert not user_sids & set(sids)
    for sam, record in computers.items():
        attributes = record["attributes"]
        assert record["section"] == "directory_accounts"
        assert attributes["dns_host_name"] == f"{sam.rstrip('$').lower()}.example.test"
        assert attributes["distinguished_name"].endswith("DC=example,DC=test")
        assert attributes["object_class"] == "computer"
        assert set(attributes["computer_reference_attribute_states"]) >= {"enabled", "dns_host_name"}
    assert computers["DC01$"]["attributes"]["trusted_for_delegation"] is True
    assert computers["WS001$"]["attributes"]["trusted_for_delegation"] is False


def test_bundle_uses_only_reserved_identifiers(tmp_path: Path) -> None:
    text = generator.write_bundle(tmp_path).read_text(encoding="utf-8")
    scanned = text.replace("sli.windows.ad-context", "")  # the product's pack id, not a host name
    domains = set(re.findall(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[a-z]{2,}", scanned))
    assert {domain.lower() for domain in domains if not domain.lower().endswith("example.test")} == set()
    assert re.findall(r"S-1-5-21-\d+-\d+-\d+", text) and all(
        sid.startswith(SID_PREFIX) for sid in re.findall(r"S-1-5-21-\d+-\d+-\d+", text)
    )
    assert json.loads(text)["source_pack_id"] == "sli.windows.ad-context"


def test_output_inside_data_is_refused() -> None:
    with pytest.raises(ValueError, match="out_dir_inside_data_refused"):
        generator.write_bundle(generator.ROOT / "data" / "demo_refused_probe")
    assert generator.main(["--out", str(generator.ROOT / "data")]) == 2

#!/usr/bin/env python3
"""Validate synthetic .NET file evidence and inventories with the unchanged Python server."""
from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives.serialization import load_der_public_key

from server.sli.plugins.file_audit.agent_ingest import packet_rows
from server.sli.plugins.file_audit.management import validate_result
from sli_agent.envelope import verify_packet


def check(directory):
    vectors = json.loads((ROOT / "agent-dotnet/tests/vectors/file-audit-scenarios.json").read_text("utf-8"))
    count = 0
    for scenario in vectors:
        exported = json.loads((directory / f"file-audit-{scenario['name']}.json").read_text("utf-8"))
        assert exported["config"] == scenario["normalized"]
        key = load_der_public_key(base64.b64decode(exported["public_key_spki_b64"]))
        previous = {"strategy": "bookmark", "token": ""}
        generation = exported["host_id"]
        assert len(exported["packets"]) == len(scenario["steps"])
        for sequence, packet in enumerate(exported["packets"], 1):
            env = verify_packet(packet, key)
            assert env["sequence"] == sequence
            assert env["cursor_before"] == (previous if generation == env["generation"] else {"strategy": "bookmark", "token": ""})
            packet_rows({"host_id": exported["host_id"]}, {"module_id": "sli.file-audit", "enabled": True, "config": exported["config"]}, env, packet["payload"])
            previous = env["cursor_after"]
            generation = env["generation"]
            count += 1
    inventories = 0
    for name, actions in (("check", ("check",)), ("apply", ("apply",)), ("restore", ("apply", "restore"))):
        for action in actions:
            value = json.loads((directory / f"file-inventory-{name}-{action}.json").read_text("utf-8"))
            validate_result(value["report"], {"request": value["request"]})
            inventories += 1
    print(f"Python accepted {count} signed .NET file-audit packets and {inventories} inventory reports")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    check(parser.parse_args().directory)


if __name__ == "__main__":
    main()

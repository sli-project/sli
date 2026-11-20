#!/usr/bin/env python3
"""Admit signed synthetic .NET NPS/Accounting packets with the unchanged Python server."""
from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives.serialization import load_der_public_key

from server.sli.agents.nps_ingest import nps_rows
from sli_agent.envelope import verify_packet


def check(directory):
    vectors = json.loads((ROOT / "agent-dotnet/tests/vectors/nps-scenarios.json").read_text("utf-8"))
    count = 0
    for scenario in vectors:
        exported = json.loads((directory / f"{scenario['name']}.json").read_text("utf-8"))
        assert exported["module_id"] == scenario["module_id"]
        assert exported["host_id"] == scenario["host_id"]
        key = load_der_public_key(base64.b64decode(exported["public_key_spki_b64"]))
        steps = [step for step in scenario["steps"] if "error" not in step]
        assert len(exported["samples"]) == len(steps)
        previous = {"strategy": "bookmark" if scenario["module_id"] == "sli.vpn-nps" else "file_offset", "token": ""}
        for sequence, (sample, expected) in enumerate(zip(exported["samples"], steps, strict=True), 1):
            assert sample["config"] == expected["config"]
            value = sample["packet"]
            env = verify_packet(value, key)
            assert env["sequence"] == sequence
            assert env["cursor_before"] == previous
            identity = {"host_id": exported["host_id"], "assigned_modules": [
                {"module_id": exported["module_id"], "enabled": True, "config": sample["config"]}]}
            nps_rows(identity, env, value["payload"])
            previous = env["cursor_after"]
            count += 1
    print(f"Python accepted {count} signed .NET NPS/Accounting packets, signatures and cursors")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    check(parser.parse_args().directory)


if __name__ == "__main__":
    main()

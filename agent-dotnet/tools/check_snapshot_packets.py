#!/usr/bin/env python3
"""Verify .NET snapshot exports using the Python signature and snapshot validators, without AD or a database."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives.serialization import (
    load_der_public_key,
)

from sli_agent.envelope import canonical, verify_packet
from sli_agent.snapshot_stream import policy, validate_chunk


def check(directory):
    vectors = json.loads((ROOT / "agent-dotnet/tests/vectors/snapshot-scenarios.json").read_text("utf-8"))
    packets_checked = 0
    for scenario in vectors:
        export = json.loads((directory / f"snapshot-{scenario['name']}.json").read_text("utf-8"))
        key = load_der_public_key(base64.b64decode(export["public_key_spki_b64"]))
        cfg = policy(scenario["module_id"], export["config"])
        assert cfg == scenario["config"]
        previous = {"strategy": "snapshot", "token": ""}
        fragments = {}
        assert len(export["packets"]) == len(scenario["samples"])
        for index, packet in enumerate(export["packets"]):
            envelope = verify_packet(packet, key)
            assert envelope["sequence"] == index + 1
            assert envelope["cursor_before"] == previous
            fragment = validate_chunk(envelope, packet["payload"], cfg)
            assert canonical(packet["payload"]).decode("ascii") == scenario["samples"][index]["payload_canonical"]
            previous = envelope["cursor_after"]
            fragments.setdefault(packet["payload"]["family"], bytearray()).extend(fragment)
            packets_checked += 1
        for family, raw in fragments.items():
            assert raw.decode("ascii") == scenario["families"][family]["data_canonical"]
            packet = next(p for p in export["packets"] if p["payload"]["family"] == family)
            assert hashlib.sha256(raw).hexdigest() == packet["payload"]["family_sha256"]
    print(f"Python accepted {packets_checked} .NET snapshot packets in {len(vectors)} scenarios")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    check(parser.parse_args().directory)


if __name__ == "__main__":
    main()

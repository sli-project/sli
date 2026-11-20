"""Read PowerShell snapshot output and its exact-byte SHA-256 sidecar."""
from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
from typing import Any

from sli_collect.packets import make_packet


def snapshot_packet(bundle: dict[str, Any], *, source: str, channel: str) -> dict[str, Any]:
    sections = bundle.get("sections") or []
    return make_packet(
        source=source, channel=channel, generation=bundle["run_id"],
        cursor={"run_id": bundle["run_id"]},
        records=[{"format": "snapshot_json", "record_id": None, "payload": bundle}],
        continuity={"status": "complete" if sections and all(
            section.get("status") == "complete" for section in sections) else "not_proven"},
    )


def collect_snapshot_packet(path: Path, *, source: str | None = None, channel: str) -> dict[str, Any]:
    if path.stat().st_size > 25 * 1024 * 1024:
        raise ValueError("snapshot_packet_size_limit")
    with path.open("rb") as stream:
        raw = stream.read(25 * 1024 * 1024 + 1)
    if len(raw) > 25 * 1024 * 1024:
        raise ValueError("snapshot_packet_size_limit")
    sidecar = path.with_name(path.name + ".sha256").read_text(encoding="ascii").strip().split()
    if not sidecar or sidecar[0].lower() != sha256(raw).hexdigest():
        raise ValueError("snapshot_packet_digest_mismatch")
    bundle = json.loads(raw.decode("utf-8-sig"))
    return snapshot_packet(bundle, source=source or bundle["domain"]["sid"], channel=channel)

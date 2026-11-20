# SPDX-License-Identifier: Apache-2.0
"""Durable single-writer spool. Limits pause capture, never evict evidence."""
from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

from sli_agent.envelope import canonical, make_packet, timestamp, validate_envelope
from sli_agent.protection import atomic_write, directory_lock, secure_directory, sync_directory


class SpoolFull(ValueError):
    pass


class Spool:
    def __init__(self, root: Path, *, max_bytes: int, max_age_seconds: int):
        if max_bytes <= 0 or max_age_seconds <= 0:
            raise ValueError("agent_spool_limits_invalid")
        self.root = Path(root)
        self.max_bytes = max_bytes
        self.max_age_seconds = max_age_seconds
        secure_directory(self.root)
        with directory_lock(self.root):
            self._recover()

    def _save_state(self, state):
        atomic_write(self.root / "checkpoints.json", canonical(state))

    def _entries(self):
        try:
            entries = [(path, json.loads(path.read_bytes())) for path in sorted(self.root.glob("*.packet"))]
            for path, value in entries:
                envelope = validate_envelope(value["envelope"])
                if path.stem != envelope["packet_id"]:
                    raise ValueError()
            return sorted(entries, key=lambda item: (item[1]["envelope"]["module_id"], item[1]["envelope"]["sequence"]))
        except (OSError, ValueError, KeyError, TypeError):
            raise ValueError("agent_spool_corrupt") from None

    def _recover(self):
        path = self.root / "checkpoints.json"
        try:
            state = json.loads(path.read_bytes()) if path.exists() else {}
            if not isinstance(state, dict):
                raise ValueError()
            changed = False
            for entry_path, value in self._entries():
                envelope = value["envelope"]
                module = state.setdefault(envelope["module_id"], {"committed": 0, "captured": None})
                if envelope["sequence"] <= module["committed"]:
                    # Crash after checkpoint fsync but before unlink: the durable
                    # exact receipt already authorized deletion.
                    entry_path.unlink()
                    sync_directory(self.root)
                    continue
                if not module["captured"] or envelope["sequence"] > module["captured"]["sequence"]:
                    module["captured"] = envelope
                    changed = True
            if changed:
                self._save_state(state)
            self.state = state
        except (ValueError, KeyError, TypeError):
            raise ValueError("agent_spool_corrupt") from None

    def captured(self, module_id):
        with directory_lock(self.root):
            self._recover()
            return deepcopy(self.state.get(module_id, {}).get("captured"))

    def pending(self, *, now=None):
        # Old entries remain uploadable; age limits prevent *new* capture only.
        with directory_lock(self.root):
            self._recover()
            return [value for _, value in self._entries()]

    def capture(self, key, *, agent_id, sample, now=None):
        now = now or datetime.now(timezone.utc)
        with directory_lock(self.root):
            self._recover()
            # Interrupted atomic writes were never captured packets. Remove
            # those temporary files under the writer lock before new capture.
            for temporary in self.root.glob(".*.tmp"):
                temporary.unlink()
            state = deepcopy(self.state)
            module = state.setdefault(sample.module_id, {"committed": 0, "captured": None})
            previous = module["captured"]
            if previous:
                if previous["agent_id"] != agent_id:
                    raise ValueError("agent_spool_identity_mismatch")
                if (previous["source_instance_id"] != sample.source_instance_id or
                        previous["channel"] != sample.channel):
                    raise ValueError("agent_capture_stream_changed")
                if (previous["generation"] == sample.generation and
                        previous["cursor_after"] != sample.cursor_before):
                    raise ValueError("agent_capture_cursor_mismatch")
            sequence = previous["sequence"] + 1 if previous else 1
            value = make_packet(key, agent_id=agent_id, sequence=sequence, sample=sample, now=now)
            entries = self._entries()
            if any(body["envelope"]["module_id"] != "sli.windows.ad-dc-history" and
                   (now - timestamp(body["envelope"]["observed_at_utc"])).total_seconds() > self.max_age_seconds
                   for _, body in entries):
                raise SpoolFull("agent_spool_age_limit")
            raw = canonical(value)
            if sum(path.stat().st_size for path, _ in entries) + len(raw) > self.max_bytes:
                raise SpoolFull("agent_spool_size_limit")
            path = self.root / (value["envelope"]["packet_id"] + ".packet")
            atomic_write(path, raw)
            module["captured"] = value["envelope"]
            self._save_state(state)  # sink before captured cursor
            self.state = state
            return value

    def acknowledge(self, value, receipt):
        envelope = value["envelope"]
        if (not isinstance(receipt, dict) or receipt.get("contract_id") != "sli.agent-receipt.v1"
                or receipt.get("status") not in ("committed", "duplicate")
                or receipt.get("packet_id") != envelope["packet_id"]
                or receipt.get("payload_sha256") != envelope["payload_sha256"]
                or receipt.get("committed_cursor") != envelope["cursor_after"]
                or not isinstance(receipt.get("evidence_ref"), str) or not receipt["evidence_ref"]
                or not isinstance(receipt.get("committed_at_utc"), str) or receipt.get("error_code") is not None):
            return False
        try:
            timestamp(receipt["committed_at_utc"])
        except ValueError:
            return False
        with directory_lock(self.root):
            self._recover()
            entries = [(path, body) for path, body in self._entries()
                       if body["envelope"]["module_id"] == envelope["module_id"]]
            if not entries or entries[0][1] != value:
                return False
            state = deepcopy(self.state)
            module = state[envelope["module_id"]]
            if envelope["sequence"] != module["committed"] + 1:
                return False
            module["committed"] = envelope["sequence"]
            module["committed_cursor"] = envelope["cursor_after"]
            self._save_state(state)  # delivery checkpoint before evidence deletion
            self.state = state
            entries[0][0].unlink()
            sync_directory(self.root)
            return True

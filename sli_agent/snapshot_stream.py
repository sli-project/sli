# SPDX-License-Identifier: Apache-2.0
"""Bounded, frozen snapshot cycles over the existing signed snapshot cursor."""
from __future__ import annotations

import base64
import hashlib
import json
import re
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sli_agent.envelope import canonical, timestamp
from sli_agent.modules import Sample
from sli_agent.protection import atomic_write, secure_directory

FRAGMENT_BYTES = 32 * 1024
MODULE_FAMILIES = {
    "sli.ad-snapshot": ("ad_context_base", "ad_privileged_membership", "ad_vpn_membership",
                        "ad_domain_posture", "ad_domain_health", "computers_v6"),
    "sli.gpo-snapshot": ("ad_gpo_governance", "gpo_v2"),
}
CONTRACTS = {module: module + ".chunk.v1" for module in MODULE_FAMILIES}
SECRET_KEYS = frozenset({"password", "passwordhash", "unicodepwd", "dbcspwd", "ntpwdhistory",
    "lmpwdhistory", "supplementalcredentials", "msmcsadmpwd", "mslapsPassword".lower(),
    "mslapsencryptedpassword", "mslapsencryptedpasswordhistory", "msdsmanagedpassword",
    "mslapsencrypteddsrmpassword", "mslapsencrypteddsrmpasswordhistory", "mslapsdsrmpassword",
    "msdsmanagedpasswordid", "msdsmanagedpasswordpreviousid", "credential", "credentials",
    "apikey", "clientsecret", "signingkey", "passwordhashes", "pwdhash", "pwdhashes",
    "cpassword", "secret", "key", "privatekey", "token", "accesstoken", "refreshtoken",
    "rawxml", "rawsysvol", "script", "scriptcontent"})


def _require(condition, code="agent_snapshot_invalid"):
    if not condition:
        raise ValueError(code)


def policy(module, config):
    """Owner bindings, normalized identically on the agent and server."""
    code = "agent_snapshot_policy_invalid"
    _require(module in MODULE_FAMILIES and isinstance(config, dict), code)
    result = deepcopy(config)
    _require(not set(result) - {"source_instance_id", "domain_sid", "domain_dns", "scope",
        "families", "policy_revision", "schedule", "capture_seconds", "buffer_bytes",
        "max_objects", "max_bytes", "dc", "search_bases", "groups", "expensive_flags"}, code)
    try:
        _require(str(UUID(result["source_instance_id"])) == result["source_instance_id"], code)
        _require(re.fullmatch(r"S-1-5-21-\d+-\d+-\d+", result["domain_sid"]) is not None, code)
        _require(re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", result["domain_dns"]) is not None, code)
        _require(isinstance(result["scope"], str) and 0 < len(result["scope"]) <= 512, code)
        revision = result.setdefault("policy_revision", "1")
        _require(isinstance(revision, str) and revision.isdecimal() and 1 <= int(revision) <= 9007199254740991, code)
        families = result.setdefault("families", list(MODULE_FAMILIES[module]))
        _require(isinstance(families, list) and families and len(families) == len(set(families))
                 and all(f in MODULE_FAMILIES[module] for f in families), code)
        schedule = result.setdefault("schedule", {"timezone": "Asia/Novosibirsk", "hours": [6, 18]})
        _require(isinstance(schedule, dict) and set(schedule) == {"timezone", "hours"}, code)
        ZoneInfo(schedule["timezone"])
        hours = schedule["hours"]
        _require(isinstance(hours, list) and 1 <= len(hours) <= 24
                 and all(type(h) is int and 0 <= h <= 23 for h in hours)
                 and hours == sorted(set(hours)), code)
        for name, default, ceiling in (
            ("capture_seconds", 300, 3600), ("buffer_bytes", 128 * 1024**2, 128 * 1024**2),
            ("max_objects", 10000 if module == "sli.gpo-snapshot" else 50000,
             10000 if module == "sli.gpo-snapshot" else 50000),
            ("max_bytes", 64 * 1024**2 if module == "sli.gpo-snapshot" else 25 * 1024**2,
             64 * 1024**2 if module == "sli.gpo-snapshot" else 25 * 1024**2),
        ):
            number = result.setdefault(name, default)
            _require(type(number) is int and 1 <= number <= ceiling, code)
        for name in ("dc", "search_bases", "groups"):
            values = result.setdefault(name, [])
            _require(isinstance(values, list) and len(values) <= 64
                     and all(isinstance(v, str) and 0 < len(v) <= 512 for v in values), code)
        flags = result.setdefault("expensive_flags", {})
        _require(isinstance(flags, dict) and not set(flags) - {"exact_last_logon", "dns", "ad_site", "inventory"}
                 and all(type(v) is bool for v in flags.values()), code)
    except (KeyError, TypeError, ValueError, ZoneInfoNotFoundError):
        raise ValueError(code) from None
    return result


def object_budget(module, counts):
    # GPO evidence and governance describe the same population twice.
    return max(counts, default=0) if module == "sli.gpo-snapshot" else sum(counts)


def redact(value):
    """Defence in depth for normalized collector output, before any disk write."""
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            _require(isinstance(key, str))
            normalized = re.sub(r"[^a-z0-9]", "", key.lower())
            sensitive = normalized in SECRET_KEYS
            result[key] = {"redacted": True} if sensitive else redact(item)
        return result
    if isinstance(value, list):
        return [redact(item) for item in value]
    # Raw XML/SYSVOL/script blobs are not snapshot family contracts.
    _require(not isinstance(value, (bytes, bytearray)))
    if isinstance(value, str):
        _require(not value.lstrip().startswith("<"))
    return value


def due_slot(config, now):
    local = now.astimezone(ZoneInfo(config["schedule"]["timezone"]))
    slots = [local.replace(hour=h, minute=0, second=0, microsecond=0) - timedelta(days=d)
             for d in (0, 1) for h in config["schedule"]["hours"]]
    return max(slot for slot in slots if slot <= local).astimezone(timezone.utc).isoformat()


def cursor(payload):
    return {"strategy": "snapshot", "token": canonical({name: payload[name] for name in
        ("cycle_id", "family", "chunk_index", "chunk_count", "cycle_families")}).decode("ascii")}


def cursor_state(value):
    _require(isinstance(value, dict) and set(value) == {"strategy", "token"}
             and value["strategy"] == "snapshot" and isinstance(value["token"], str))
    if value["token"] == "":
        return None
    try:
        state = json.loads(value["token"])
        _require(set(state) == {"cycle_id", "family", "chunk_index", "chunk_count", "cycle_families"})
        _require(canonical(state).decode("ascii") == value["token"])
        _require(str(UUID(state["cycle_id"])) == state["cycle_id"])
        _require(isinstance(state["cycle_families"], list) and state["cycle_families"]
                 and len(state["cycle_families"]) <= 6
                 and all(isinstance(f, str) for f in state["cycle_families"])
                 and len(set(state["cycle_families"])) == len(state["cycle_families"])
                 and state["family"] in state["cycle_families"])
        _require(type(state["chunk_index"]) is int and type(state["chunk_count"]) is int
                 and 0 <= state["chunk_index"] < state["chunk_count"] <= 2048)
        return state
    except (ValueError, TypeError, KeyError):
        raise ValueError("agent_snapshot_cursor_invalid") from None


def validate_chunk(envelope, payload, config):
    """Validate the snapshot branch, never pass fragments to event importers."""
    fields = {"contract", "cycle_id", "family", "slot_start_utc", "chunk_index", "chunk_count",
              "total_objects", "total_bytes", "family_sha256", "records", "cycle_families",
              "domain_sid", "domain_dns", "scope"}
    _require(isinstance(payload, dict) and set(payload) == fields)
    module = envelope["module_id"]
    _require(payload["contract"] == CONTRACTS[module])
    for name in ("source_instance_id", "policy_revision"):
        _require(envelope[name] == config[name])
    for name in ("domain_sid", "domain_dns", "scope"):
        _require(payload[name] == config[name])
    _require(envelope["module_version"] == "1.0.0" and envelope["channel"] == "snapshot"
             and envelope["generation"] == config["source_instance_id"]
             and envelope["continuity_state"] == "complete" and envelope["filtered_count"] == 0
             and envelope["lost_count"] == 0)
    _require(payload["cycle_families"] == config["families"])
    state = cursor_state(cursor(payload))
    _require(envelope["cursor_after"] == cursor(payload))
    before = cursor_state(envelope["cursor_before"])
    if before is None or before["cycle_id"] != state["cycle_id"]:
        _require(state["family"] == config["families"][0] and state["chunk_index"] == 0)
        if before:
            _require(before["family"] == before["cycle_families"][-1]
                     and before["chunk_index"] == before["chunk_count"] - 1)
    else:
        _require(before["cycle_families"] == state["cycle_families"])
        if before["family"] == state["family"]:
            _require(state["chunk_count"] == before["chunk_count"]
                     and state["chunk_index"] == before["chunk_index"] + 1)
        else:
            _require(before["chunk_index"] == before["chunk_count"] - 1
                     and config["families"].index(state["family"]) == config["families"].index(before["family"]) + 1
                     and state["chunk_index"] == 0)
    slot = timestamp(payload["slot_start_utc"])
    local_slot = slot.astimezone(ZoneInfo(config["schedule"]["timezone"]))
    _require(slot.isoformat() == payload["slot_start_utc"] and local_slot.hour in config["schedule"]["hours"]
             and local_slot.minute == local_slot.second == local_slot.microsecond == 0
             and slot <= timestamp(envelope["observed_at_utc"]))
    limit = 64 * 1024**2 if payload["family"] == "computers_v6" else config["max_bytes"]
    for name, ceiling in (("total_bytes", limit), ("total_objects", config["max_objects"])):
        _require(type(payload[name]) is int and 0 <= payload[name] <= ceiling)
    _require(isinstance(payload["family_sha256"], str)
             and re.fullmatch(r"[0-9a-f]{64}", payload["family_sha256"]) is not None)
    _require(payload["chunk_count"] == max(1, (payload["total_bytes"] + FRAGMENT_BYTES - 1) // FRAGMENT_BYTES))
    _require(isinstance(payload["records"], list) and len(payload["records"]) == 1
             and isinstance(payload["records"][0], dict) and set(payload["records"][0]) == {"data_b64"})
    try:
        fragment = base64.b64decode(payload["records"][0]["data_b64"], validate=True)
    except (ValueError, TypeError):
        raise ValueError("agent_snapshot_fragment_invalid") from None
    expected = min(FRAGMENT_BYTES, payload["total_bytes"] - payload["chunk_index"] * FRAGMENT_BYTES)
    _require(len(fragment) == expected and base64.b64encode(fragment).decode("ascii") == payload["records"][0]["data_b64"])
    return fragment


class SnapshotModule:
    """Transport adapter; source acquisition is implemented in PR 2/3."""
    def __init__(self, module_id, config):
        self.module_id = module_id
        self.policy = policy(module_id, config)

    def capture(self, config, *, deadline, stop):
        raise ValueError("agent_snapshot_collector_unavailable")


class SnapshotStream:
    """One protected frozen capture per module, retained until spool owns it."""
    def __init__(self, root: Path, module_id):
        _require(module_id in MODULE_FAMILIES)
        self.root = Path(root) / module_id
        secure_directory(self.root)
        self.module_id = module_id
        self._cached = None
        self._stamp = None

    def read(self):
        path = self.root / "cycle.json"
        try:
            if not path.exists():
                self._cached = self._stamp = None
                return None
            stat = path.stat()
            _require(stat.st_size <= 128 * 1024**2, "agent_snapshot_state_invalid")
            stamp = (stat.st_mtime_ns, stat.st_size)
            if stamp != self._stamp:
                state = json.loads(path.read_bytes())
                _require(isinstance(state, dict) and type(state["ready"]) is bool)
                _require(set(state) == {"cycle_id", "slot_start_utc", "policy", "ready"}
                         | ({"families"} if state["ready"] else set()))
                _require(str(UUID(state["cycle_id"])) == state["cycle_id"])
                _require(policy(self.module_id, state["policy"]) == state["policy"])
                timestamp(state["slot_start_utc"])
                self._cached, self._stamp = state, stamp
            return self._cached
        except (ValueError, OSError, TypeError, KeyError, AttributeError):
            raise ValueError("agent_snapshot_state_invalid") from None

    def begin(self, config, *, now):
        state = self.read()
        if state is not None:
            return state
        config = policy(self.module_id, config)
        slot = due_slot(config, now)
        last = self.root / "last_slot.json"
        if last.exists() and json.loads(last.read_bytes())["slot"] >= slot:
            return None
        state = {"cycle_id": str(uuid4()), "slot_start_utc": slot, "policy": config, "ready": False}
        atomic_write(self.root / "cycle.json", canonical(state))
        return state

    def freeze(self, state, families):
        config = state["policy"]
        _require(isinstance(families, dict) and set(families) == set(config["families"]))
        encoded = {}
        bundle_bytes = 0
        object_counts = []
        for family in config["families"]:
            data, count = families[family]
            _require(isinstance(data, (dict, list)) and type(count) is int and count >= 0)
            _require(count <= config["max_objects"], "agent_snapshot_size_limit")
            if self.module_id == "sli.gpo-snapshot":
                from sli_agent.gpo_privacy import mask_gpo
                raw = canonical(mask_gpo(data))
            else:
                raw = canonical(redact(data))
            limit = 64 * 1024**2 if family == "computers_v6" else config["max_bytes"]
            _require(len(raw) <= limit, "agent_snapshot_size_limit")
            bundle_bytes += 0 if family == "computers_v6" else len(raw)
            object_counts.append(count)
            encoded[family] = {"data_b64": base64.b64encode(raw).decode("ascii"),
                               "total_objects": count, "total_bytes": len(raw),
                               "family_sha256": hashlib.sha256(raw).hexdigest()}
        _require(bundle_bytes <= config["max_bytes"] and object_budget(self.module_id, object_counts) <= config["max_objects"], "agent_snapshot_size_limit")
        frozen = {**state, "ready": True, "families": encoded}
        raw = canonical(frozen)
        _require(len(raw) <= config["buffer_bytes"], "agent_snapshot_buffer_limit")
        existing = self.read()
        _require(existing is not None and existing["cycle_id"] == state["cycle_id"], "agent_snapshot_cycle_conflict")
        if existing["ready"]:
            _require(canonical(existing) == raw, "agent_snapshot_cycle_conflict")
            return
        atomic_write(self.root / "cycle.json", raw)

    def next_sample(self, captured):
        state = self.read()
        if not state or not state["ready"]:
            return None
        config = state["policy"]
        before = captured["cursor_after"] if captured else {"strategy": "snapshot", "token": ""}
        previous = cursor_state(before)
        family, index = config["families"][0], 0
        if previous and previous["cycle_id"] == state["cycle_id"]:
            family, index = previous["family"], previous["chunk_index"] + 1
            if index == previous["chunk_count"]:
                next_family = config["families"].index(family) + 1
                if next_family == len(config["families"]):
                    # Last-slot checkpoint precedes deletion. Repeating after a
                    # crash is safe because the durable spool cursor owns data.
                    atomic_write(self.root / "last_slot.json", canonical({"slot": state["slot_start_utc"]}))
                    (self.root / "cycle.json").unlink()
                    return None
                family, index = config["families"][next_family], 0
        info = state["families"][family]
        size = info["total_bytes"]
        count = max(1, (size + FRAGMENT_BYTES - 1) // FRAGMENT_BYTES)
        start, end = index * FRAGMENT_BYTES, min((index + 1) * FRAGMENT_BYTES, size)
        # Decode only this fragment, rather than repeatedly decoding a 64 MiB
        # family on the heartbeat/delivery thread. Base64 groups cover 3 bytes.
        raw = base64.b64decode(info["data_b64"][start // 3 * 4:(end + 2) // 3 * 4], validate=True)
        fragment = raw[start % 3:start % 3 + end - start]
        payload = {"contract": CONTRACTS[self.module_id], "cycle_id": state["cycle_id"], "family": family,
            "slot_start_utc": state["slot_start_utc"], "chunk_index": index, "chunk_count": count,
            "cycle_families": config["families"], "domain_sid": config["domain_sid"],
            "domain_dns": config["domain_dns"], "scope": config["scope"],
            **{k: v for k, v in info.items() if k != "data_b64"},
            "records": [{"data_b64": base64.b64encode(fragment).decode("ascii")}]}
        return Sample(self.module_id, config["source_instance_id"], "snapshot", config["source_instance_id"],
            before, cursor(payload), payload, policy_revision=config["policy_revision"],
            continuity_state="complete", lost_count=0)

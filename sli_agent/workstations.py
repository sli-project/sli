# SPDX-License-Identifier: Apache-2.0
"""Bounded workstation capture; all progress belongs to the durable spool."""
from __future__ import annotations

import json
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
from fnmatch import fnmatchcase
from xml.etree import ElementTree as ET

from server.sli.storage.xml_safety import parse_bounded_xml
from sli_agent.envelope import canonical
from sli_agent.modules import Sample
from sli_agent.script_secrets import MASK_FAILED, SCRIPT_BYTES, bounded_utf8, mask_script_secrets
from sli_collect.eventlog import NS, parse_event_xml
from sli_collect.packets import make_packet

# Native identities aligned with stage 7A normalizers (PR #414). Never translate
# Operational event IDs into Security IDs or derive identity from host names.
CHANNEL_EVENTS = {
    "Security": ("Microsoft-Windows-Security-Auditing", frozenset({
        4624, 4625, 4634, 4647, 4688, 4697, 4698, 4699, 4700, 4701, 4702,
        1102, 4732, 4733, 4719, 6416})),
    "System": ("Service Control Manager", frozenset({7036, 7040, 7045})),
    "Microsoft-Windows-Windows Defender/Operational": (
        "Microsoft-Windows-Windows Defender", frozenset({5001, 5010, 5012})),
    # Stage 7A projects task changes from Security 4698-4702. Preserve these
    # additional native Operational observations for future server projections.
    "Microsoft-Windows-TaskScheduler/Operational": (
        "Microsoft-Windows-TaskScheduler", frozenset({106, 140, 141, 142})),
    "Microsoft-Windows-DriverFrameworks-UserMode/Operational": (
        "Microsoft-Windows-DriverFrameworks-UserMode", frozenset({2003, 2100, 2101})),
    "Microsoft-Windows-Kernel-PnP/Configuration": (
        "Microsoft-Windows-Kernel-PnP", frozenset({400, 410, 420})),
    "Microsoft-Windows-PowerShell/Operational": ("Microsoft-Windows-PowerShell", frozenset({4104})),
}
CHANNELS = tuple(CHANNEL_EVENTS)
FAMILY_EVENTS = {
    "logons": frozenset({4624, 4625, 4634, 4647}),
    "processes": frozenset({4688}),
    "usb": frozenset({6416, 2003, 2100, 2101, 400, 410, 420}),
    "local_admins": frozenset({4732, 4733}),
    "protection": frozenset({1102, 7036, 7040, 4104, 4697, 4698, 4699, 4700, 4701, 4702, 4719, 7045,
                             5001, 5010, 5012, 106, 140, 141, 142}),
}
# Leave room for the signed envelope (including both aggregate cursors), below
# the agent's 60 KiB wire limit. Oversized evidence pauses rather than vanishes.
MAX_PAYLOAD_BYTES = 44 * 1024
MODULE_VERSION = "1.1.0"
POWERSHELL_CHANNEL = "Microsoft-Windows-PowerShell/Operational"
SCRIPT_LIMIT = 10  # hard ceiling per durable rate window, including catch-up/restarts
PROTECTED_SERVICES = (
    "SLIAgentNet", "SLI Agent .NET", "SLIAgent", "SLI Agent", "WinDefend", "Sense", "VSS", "wbengine",
    "Microsoft Defender Antivirus Service", "Windows Defender Antivirus Service",
    "Microsoft Defender for Endpoint Service", "Windows Defender Advanced Threat Protection Service",
    "Volume Shadow Copy", "Block Level Backup Engine Service",
    "Служба антивирусной программы Microsoft Defender", "Служба антивирусной программы Защитник Windows",
    "Теневое копирование тома", "Служба модуля архивации на уровне блоков",
)


def bound_tamper_row(row, root):
    """Bound every copy (XML/properties), preserving a native-field truncation marker.

    XML is captured evidence after explicit lossy sanitization, not original XML.
    Reduce further when JSON escaping would otherwise exceed the wire budget.
    """
    if row["event_id"] not in (1102, 7036, 7040, 4104):
        return row
    ns = NS["e"]
    fields = root.findall(".//e:EventData/e:Data", NS)
    changed = False
    truncated = False
    masked_count = 0
    for item in fields:
        script = row["event_id"] == 4104 and item.get("Name") == "ScriptBlockText"
        limit = SCRIPT_BYTES if item.get("Name") == "ScriptBlockText" else 512
        value = item.text or ""
        if script:
            bounded, count, lossy = mask_script_secrets(value)
            masked_count += count
            if bounded.startswith(MASK_FAILED):
                parent = root.find("e:EventData", NS)
                marker = parent.find("e:Data[@Name='ScriptMaskingFailed']", NS)
                if marker is None:
                    marker = ET.SubElement(parent, f"{{{ns}}}Data", {"Name": "ScriptMaskingFailed"})
                marker.text = "true"
        else:
            bounded = bounded_utf8(value, limit)
            lossy = bounded != value
        if value != bounded:
            item.text = bounded
            changed = True
        if lossy:
            truncated = True
            if item.get("Name") == "ScriptBlockText":
                marker = root.find("e:EventData/e:Data[@Name='ScriptBlockTextTruncated']", NS)
                if marker is None:
                    marker = ET.SubElement(root.find("e:EventData", NS), f"{{{ns}}}Data",
                                           {"Name": "ScriptBlockTextTruncated"})
                marker.text = "true"
    if row["event_id"] == 4104:
        row["secrets_masked"] = masked_count
        parent = root.find("e:EventData", NS)
        if parent is not None:
            marker = parent.find("e:Data[@Name='SecretsMasked']", NS)
            if marker is None and masked_count:
                marker = ET.SubElement(parent, f"{{{ns}}}Data", {"Name": "SecretsMasked"})
            # Native input cannot claim a trusted masking count.
            if marker is not None:
                marker.text = str(masked_count)
                changed = True
    if truncated:
        parent = root.find("e:EventData", NS)
        marker = root.find("e:EventData/e:Data[@Name='CollectionFieldsTruncated']", NS)
        if marker is None:
            marker = ET.SubElement(parent, f"{{{ns}}}Data", {"Name": "CollectionFieldsTruncated"})
        marker.text = "true"
    if not changed and len(canonical(row)) <= MAX_PAYLOAD_BYTES - 8192:
        return row
    while True:
        raw = ET.tostring(root, encoding="unicode")
        result = parse_event_xml(raw, source_name=row["computer_name"],
                                 connect_address=row["connect_address"], channel=row["channel"])
        if row["event_id"] == 4104:
            result["secrets_masked"] = masked_count
        if len(canonical(result)) <= MAX_PAYLOAD_BYTES - 8192:
            return result
        script = root.find("e:EventData/e:Data[@Name='ScriptBlockText']", NS)
        if script is None or not script.text:
            raise ValueError("agent_workstations_event_size_limit")
        marker = root.find("e:EventData/e:Data[@Name='ScriptBlockTextTruncated']", NS)
        if marker is None:
            marker = ET.SubElement(root.find("e:EventData", NS), f"{{{ns}}}Data",
                                   {"Name": "ScriptBlockTextTruncated"})
        marker.text = "true"
        script.text = bounded_utf8(script.text, len(script.text.encode("utf-8")) // 2)


DEFENDER_CHANNEL = "Microsoft-Windows-Windows Defender/Operational"
PROTECTION_COMPONENTS = (
    "antivirus_enabled", "real_time_protection_enabled", "behavior_monitor_enabled",
    "ioav_protection_enabled", "nis_enabled", "tamper_protected",
)


def validate_protection_state(value):
    if (not isinstance(value, dict) or set(value) != {"state", "components"}
            or value["state"] not in ("available", "unavailable")
            or not isinstance(value["components"], dict)
            or set(value["components"]) != set(PROTECTION_COMPONENTS)
            or any(v is not None and type(v) is not bool for v in value["components"].values())
            or value["state"] == "unavailable" and any(v is not None for v in value["components"].values())):
        raise ValueError("workstation_protection_state_invalid")
    return value


def read_protection_state():
    """Read only Defender flags; never serialize native diagnostics or identities."""
    import subprocess

    unavailable = {"state": "unavailable", "components": dict.fromkeys(PROTECTION_COMPONENTS)}
    command = "$ErrorActionPreference='Stop'; $s=Get-MpComputerStatus; [ordered]@{"
    properties = ("AntivirusEnabled", "RealTimeProtectionEnabled", "BehaviorMonitorEnabled",
                  "IoavProtectionEnabled", "NISEnabled", "IsTamperProtected")
    command += ";".join(f"{key}=$s.{native}" for key, native in zip(PROTECTION_COMPONENTS, properties))
    command += "} | ConvertTo-Json -Compress"
    try:
        completed = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True, text=True, timeout=5, check=False, creationflags=0x08000000)
        if completed.returncode or len(completed.stdout) > 4096:
            return unavailable
        return validate_protection_state({"state": "available", "components": json.loads(completed.stdout)})
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return unavailable


def read_local(channel, cursor, limit):
    from sli_collect.bookmarked_eventlog import read_local as read_bookmarked

    return read_bookmarked(channel, cursor, limit, error_code="agent_workstations_read_failed",
                           recover_missing_bookmark=True)


def _policy(value):
    try:
        allowed = {"policy_revision", "allow_event_ids", "deny_event_ids", "allow_process_paths",
                   "deny_process_paths", "rate_limits", "rate_window_seconds", "batch_size",
                   "channel_generations", "families", "family_filters", "protected_services"}
        if not isinstance(value, dict) or set(value) - allowed:
            raise ValueError()
        policy = {"policy_revision": "1", "allow_event_ids": None, "deny_event_ids": [],
                  "allow_process_paths": [], "deny_process_paths": [], "rate_limits": {},
                  "rate_window_seconds": 60, "batch_size": 32, "channel_generations": {}, **deepcopy(value)}
        services = policy.get("protected_services", [])
        if not isinstance(services, list) or len(services) > 64 or any(
                not isinstance(s, str) or not s.strip() or len(s) > 256 for s in services):
            raise ValueError()
        policy["protected_services"] = services
        families = policy.get("families", {})
        if (not isinstance(families, dict) or set(families) - set(FAMILY_EVENTS)
                or any(type(enabled) is not bool for enabled in families.values())):
            raise ValueError()
        policy["families"] = {**dict.fromkeys(FAMILY_EVENTS, True), **families}
        filters = policy.get("family_filters", {})
        if not isinstance(filters, dict) or set(filters) - set(FAMILY_EVENTS):
            raise ValueError()
        policy["family_filters"] = {}
        for family, settings in filters.items():
            keys = {"allow_event_ids", "deny_event_ids"}
            if family == "processes":
                keys |= {"allow_process_paths", "deny_process_paths"}
            if not isinstance(settings, dict) or set(settings) - keys:
                raise ValueError()
            validated = _policy(settings)
            for key in ("allow_event_ids", "deny_event_ids"):
                if validated[key] is not None and set(validated[key]) - FAMILY_EVENTS[family]:
                    raise ValueError()
            policy["family_filters"][family] = {key: validated[key] for key in keys}
        revision = policy["policy_revision"]
        if not isinstance(revision, str) or not revision.strip() or len(revision) > 128:
            raise ValueError()
        for name in ("allow_event_ids", "deny_event_ids"):
            ids = policy[name]
            if ids is None and name == "allow_event_ids":
                continue
            if not isinstance(ids, list) or len(ids) > 128 or any(
                    type(n) is not int or not 0 <= n <= 65535 for n in ids):
                raise ValueError()
        for name in ("allow_process_paths", "deny_process_paths"):
            patterns = policy[name]
            if not isinstance(patterns, list) or len(patterns) > 64 or any(
                    not isinstance(p, str) or not p.strip() or len(p) > 512 for p in patterns):
                raise ValueError()
            policy[name] = [p.replace("\\", "/").casefold() for p in patterns]
        rates = policy["rate_limits"]
        if not isinstance(rates, dict) or len(rates) > 32:
            raise ValueError()
        known_ids = set().union(*(spec[1] for spec in CHANNEL_EVENTS.values()))
        for key, limit in rates.items():
            if (not isinstance(key, str) or not key.isascii() or not key.isdecimal()
                    or str(int(key)) != key or int(key) not in known_ids
                    or type(limit) is not int or not 0 <= limit <= 1000000):
                raise ValueError()
        rates["4104"] = min(rates.get("4104", SCRIPT_LIMIT), SCRIPT_LIMIT)
        for name, maximum in (("batch_size", 128), ("rate_window_seconds", 86400)):
            n = policy[name]
            if type(n) is not int or not 1 <= n <= maximum:
                raise ValueError()
        generations = policy["channel_generations"]
        if not isinstance(generations, dict) or any(
                channel not in CHANNELS or not isinstance(g, str) or not g.strip() or len(g) > 128
                for channel, g in generations.items()):
            raise ValueError()
        return policy
    except (ValueError, TypeError):
        raise ValueError("agent_workstations_config_invalid") from None


class WorkstationsModule:
    module_id = "sli.workstations"

    def __init__(self, host_id, config=None, *, reader=None, protection_reader=None):
        self.host_id = host_id
        self.channels = CHANNELS
        self.policy = _policy({} if config is None else config)
        self.reader = reader or read_local
        self.protection_reader = protection_reader or read_protection_state
        self.protection_observation = None
        self.catch_up_channel = None

    def enabled_channels(self):
        enabled_ids = set().union(*(ids for family, ids in FAMILY_EVENTS.items() if self.policy["families"][family]))
        return tuple(channel for channel in self.channels if CHANNEL_EVENTS[channel][1] & enabled_ids)

    def _state(self, captured):
        if captured is None:
            return {"next": 0, "channels": {}, "rate": {"window": None, "counts": {}}}
        try:
            cursor = captured["cursor_after"]
            if captured["generation"] != self.host_id or cursor["strategy"] != "bookmark":
                raise ValueError()
            state = json.loads(cursor["token"])
            if (set(state) != {"next", "channels", "rate"} or type(state["next"]) is not int
                    or not 0 <= state["next"] < len(self.channels) or not isinstance(state["channels"], dict)
                    or set(state["channels"]) - set(self.channels)):
                raise ValueError()
            for progress in state["channels"].values():
                if (set(progress) != {"record_id", "bookmark", "generation"}
                        or (progress["record_id"] is not None and
                            (type(progress["record_id"]) is not int or progress["record_id"] < 0))
                        or not isinstance(progress["bookmark"], str)
                        or not isinstance(progress["generation"], str)):
                    raise ValueError()
            rate = state["rate"]
            if (set(rate) != {"window", "counts"} or
                    (rate["window"] is not None and type(rate["window"]) is not int)
                    or not isinstance(rate["counts"], dict) or len(rate["counts"]) > 32
                    or any(not isinstance(k, str) or not k.isdecimal() or type(v) is not int or v < 0
                           for k, v in rate["counts"].items())):
                raise ValueError()
            return state
        except (ValueError, KeyError, TypeError, AttributeError):
            raise ValueError("agent_workstations_cursor_invalid") from None

    def _allowed(self, row, data):
        event_id = row["event_id"]
        provider, event_ids = CHANNEL_EVENTS[row["channel"]]
        if event_id == 1102:
            provider = "Microsoft-Windows-Eventlog"
        if str(row["provider_name"]).casefold() != provider.casefold() or event_id not in event_ids:
            return False
        family = next(family for family, ids in FAMILY_EVENTS.items() if event_id in ids)
        if not self.policy["families"][family]:
            return False
        policies = (self.policy, self.policy["family_filters"].get(family, {}))
        for policy in policies:
            allow = policy.get("allow_event_ids")
            if (allow is not None and event_id not in allow) or event_id in policy.get("deny_event_ids", []):
                return False
        if event_id in (4732, 4733) and data.get("TargetSid") != "S-1-5-32-544":
            return False
        if event_id in (7036, 7040):
            names = {s.strip().casefold() for s in (*PROTECTED_SERVICES, *self.policy["protected_services"])}
            service = data.get("ServiceName") or (data.get("param4") if event_id == 7040 else None) or data.get("param1")
            if str(service or "").strip().casefold() not in names:
                return False
        if event_id == 4688:
            path = (data.get("NewProcessName") or "").replace("\\", "/").casefold()
            for policy in policies:
                allow = policy.get("allow_process_paths", [])
                deny = policy.get("deny_process_paths", [])
                if (allow and not any(fnmatchcase(path, p) for p in allow)) or any(fnmatchcase(path, p) for p in deny):
                    return False
        return True

    @staticmethod
    def _cursor(state):
        token = canonical(state).decode("ascii")
        if len(token) > 4096:
            raise ValueError("agent_workstations_cursor_size_limit")
        return {"strategy": "bookmark", "token": token}

    def collect(self, captured=None, *, now=None, channel=None):
        now = now or datetime.now(timezone.utc)
        state = self._state(captured)
        before = deepcopy(captured["cursor_after"]) if captured else {"strategy": "bookmark", "token": ""}
        enabled = self.enabled_channels()
        self.catch_up_channel = None
        if not enabled:
            return None
        index = next((state["next"] + offset) % len(self.channels) for offset in range(len(self.channels))
                     if self.channels[(state["next"] + offset) % len(self.channels)] in enabled)
        if channel is not None:
            if channel not in enabled:
                raise ValueError("agent_workstations_channel_invalid")
            index = self.channels.index(channel)
        channel = self.channels[index]
        generation = self.policy["channel_generations"].get(channel, self.host_id)
        progress = state["channels"].get(channel, {"record_id": None, "bookmark": "", "generation": generation})
        reset = progress["generation"] != generation
        if reset:
            progress = {"record_id": None, "bookmark": "", "generation": generation}
        after_id = progress["record_id"]
        rate = state["rate"]
        window = int(now.timestamp()) // self.policy["rate_window_seconds"]
        # A backwards clock cannot grant additional quota in the same window.
        if rate["window"] is None or window > rate["window"]:
            rate.update(window=window, counts={})
        rates = self.policy["rate_limits"]
        rate["counts"] = {k: v for k, v in rate["counts"].items() if k in rates}
        records, dropped = [], Counter()
        filtered = 0
        read_error = None
        self.read_observation = None
        try:
            rows = self.reader(channel, deepcopy(progress), self.policy["batch_size"])
        except (OSError, RuntimeError) as exc:
            # A missing/inaccessible channel must not starve other channels.
            # Publish an explicit unknown gap and retry its unchanged bookmark
            # next round; never infer zero loss from an unsuccessful read.
            rows = []
            read_error = "agent_workstations_read_failed"
            from sli_collect.eventlog_diagnostics import EventLogReadError, diagnostic
            details = (exc.diagnostic if isinstance(exc, EventLogReadError)
                       else diagnostic(exc, channel, progress, "collect"))
            self.read_observation = {"channel": channel, "observed_at_utc": now.isoformat(),
                "error": details}
        if self.read_observation is None:
            self.read_observation = {"channel": channel, "observed_at_utc": now.isoformat(),
                "error": None}
        if len(rows) > self.policy["batch_size"]:
            raise ValueError("agent_workstations_range_invalid")
        from sli_collect.bookmarked_eventlog import BookmarkRecoveryBatch
        bookmark_recovered = isinstance(rows, BookmarkRecoveryBatch)
        previous_id = after_id
        payload_full = False
        for raw, bookmark in rows:
            row = parse_event_xml(raw, source_name=self.host_id, connect_address="localhost", channel=channel)
            record_id = row["record_id"]
            if (type(record_id) is not int or record_id < 0
                    or previous_id is not None and record_id <= previous_id
                    or not isinstance(bookmark, str) or not bookmark):
                raise ValueError("agent_workstations_range_invalid")
            previous_id = record_id
            root = parse_bounded_xml(raw)
            native_channel = root.find("e:System/e:Channel", NS)
            if native_channel is None or native_channel.text != channel:
                raise ValueError("agent_workstations_channel_invalid")
            data = {}
            for item in root.findall(".//e:EventData/e:Data", NS):
                name = item.get("Name")
                if name:
                    if name in data:
                        raise ValueError("agent_workstations_duplicate_event_field")
                    data[name] = item.text
            allowed = self._allowed(row, data)
            key = str(row["event_id"])
            limited = allowed and key in rates and rate["counts"].get(key, 0) >= rates[key]
            if allowed and not limited:
                row = bound_tamper_row(row, root)
                record = {"format": "event_xml", "record_id": record_id, "payload": row}
                # Budget each admitted row before consuming its quota/cursor.
                if len(canonical(records + [record])) > MAX_PAYLOAD_BYTES - 4096:
                    if not records:
                        raise ValueError("agent_workstations_event_size_limit")
                    payload_full = True
                    break
                records.append(record)
                if key in rates:
                    rate["counts"][key] = rate["counts"].get(key, 0) + 1
            elif limited:
                dropped[key] += 1
            else:
                filtered += 1
            progress = {"record_id": record_id, "bookmark": bookmark, "generation": generation}
        state["channels"][channel] = progress
        state["next"] = (index + 1) % len(self.channels)
        if not read_error and (payload_full or len(rows) == self.policy["batch_size"]):
            self.catch_up_channel = channel
        lost = sum(dropped.values())
        protection = {}
        if channel == DEFENDER_CHANNEL and self.policy["families"]["protection"]:
            # All catch-up packets in this tick have the same observation time.
            # Freeze one measurement so they cannot conflict during replay.
            if self.protection_observation is None or self.protection_observation[0] != now:
                self.protection_observation = (now, deepcopy(validate_protection_state(self.protection_reader())))
            protection = {"protection_state": self.protection_observation[1]}
        payload = make_packet(source=self.host_id, channel=channel, generation=generation,
            cursor={"after_record_id": after_id, "last_record_id": progress["record_id"]},
            records=records, continuity={"status": "not_proven"}, observed_at=now,
            context={"workstations": {"policy_revision": self.policy["policy_revision"],
                "filtered_count": filtered, "dropped_count": lost, "dropped_by_event_id": dict(dropped),
                "rate_window_seconds": self.policy["rate_window_seconds"], "channel_reset": reset,
                "read_error": read_error,
                **protection,
                **({"bookmark_recovered": True} if bookmark_recovered else {})}})
        if len(canonical(payload)) > MAX_PAYLOAD_BYTES:
            raise ValueError("agent_workstations_event_size_limit")
        # One sequence owner multiplexes channels. The collection header keeps
        # the real native channel; the envelope's stream identity stays stable.
        return Sample(self.module_id, self.host_id, "workstations", self.host_id, before,
            self._cursor(state), payload, module_version=MODULE_VERSION, policy_revision=self.policy["policy_revision"],
            continuity_state="gap" if lost or reset or read_error or bookmark_recovered else "filtered" if filtered else "not_proven",
            filtered_count=filtered, lost_count=None if read_error or reset or bookmark_recovered else lost)

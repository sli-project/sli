# SPDX-License-Identifier: Apache-2.0
"""Pack-filtered DC capture with one durable sequence owner for three channels."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from functools import lru_cache
import json
from pathlib import Path

from sli_agent.envelope import canonical, timestamp
from sli_agent.modules import Sample
from sli_collect.bookmarked_eventlog import BookmarkRecoveryBatch, read_local as read_bookmarked
from sli_collect.eventlog import NS, parse_event_xml
from sli_collect.packets import make_packet
from server.sli.storage.xml_safety import parse_bounded_xml

CHANNELS = ("Security", "System", "Directory Service")
PACK_ID = "sli.windows.ad-dc"
HISTORY_ID = "sli.windows.ad-dc-history"
MAX_PAYLOAD_BYTES = 44 * 1024


@lru_cache(maxsize=1)
def event_identities():
    # Only bundled data, never a policy-supplied path or executable module.
    root = Path(__file__).resolve().parents[1] / "config"
    pack = json.loads((root / "source_packs/dc.json").read_text("utf-8"))
    if pack["pack_id"] != PACK_ID or not set(CHANNELS).issubset(pack["channels"]):
        raise ValueError("agent_ad_dc_pack_invalid")
    catalog = (root / pack["event_catalog"]).resolve()
    if not catalog.is_relative_to(root.resolve()):
        raise ValueError("agent_ad_dc_pack_invalid")
    entries = json.loads(catalog.read_text("utf-8"))["entries"]
    return frozenset((entry["channel"], entry["provider_name"].casefold(), entry["event_id"])
                     for entry in entries if entry["channel"] in CHANNELS)


def read_local(channel, cursor, limit):
    selector = None
    if channel == "Security":
        # Query a small superset of the bundled catalog before rendering XML.
        # File-audit traffic must not consume every bounded DC read. Exact
        # provider/ID admission still happens in collect(), including with fakes.
        groups = []
        for event in sorted({item[2] for item in event_identities() if item[0] == channel}):
            if groups and event - groups[-1][-1] <= 16:
                groups[-1].append(event)
            else:
                groups.append([event])
        terms = [f"EventID={group[0]}" if len(group) == 1 else
                 f"(EventID >= {group[0]} and EventID <= {group[-1]})" for group in groups]
        if cursor["bookmark"] and cursor["record_id"] is not None:
            # A pre-upgrade bookmark may point at a filtered-out event. Keep
            # that one anchor queryable for strict native seek and validation.
            terms.append(f"EventRecordID={cursor['record_id']}")
        selector = " or ".join(terms)
    return read_bookmarked(channel, cursor, limit, error_code="agent_ad_dc_read_failed",
                           recover_missing_bookmark=True, system_filter=selector)


def cursor_state(cursor):
    try:
        if cursor["strategy"] != "bookmark":
            raise ValueError()
        if not cursor["token"]:
            return {"next": 0, "channels": {}}
        state = json.loads(cursor["token"])
        if (set(state) != {"next", "channels"} or type(state["next"]) is not int
                or not 0 <= state["next"] < len(CHANNELS) or not isinstance(state["channels"], dict)
                or set(state["channels"]) - set(CHANNELS)):
            raise ValueError()
        for progress in state["channels"].values():
            if (set(progress) - {"record_id", "bookmark", "generation", "since_utc", "before_utc", "complete"}
                    or not {"record_id", "bookmark", "generation"}.issubset(progress)
                    or (progress["record_id"] is not None and
                        (type(progress["record_id"]) is not int or progress["record_id"] <= 0))
                    or not isinstance(progress["bookmark"], str) or len(progress["bookmark"]) > 2048
                    or bool(progress["bookmark"]) != (progress["record_id"] is not None)
                    or not isinstance(progress["generation"], str) or not progress["generation"]
                    or len(progress["generation"]) > 128):
                raise ValueError()
            for key in ("since_utc", "before_utc"):
                if key in progress:
                    timestamp(progress[key])
            if "complete" in progress and (type(progress["complete"]) is not bool or "before_utc" not in progress):
                raise ValueError()
        return state
    except (ValueError, KeyError, TypeError, AttributeError):
        raise ValueError("agent_ad_dc_cursor_invalid") from None


class ADDCModule:
    module_id = PACK_ID
    low_priority = False

    def __init__(self, host_id, config=None, *, reader=None):
        try:
            config = {} if config is None else config
            if not isinstance(config, dict) or set(config) - {
                    "source_name", "connect_address", "policy_revision", "batch_size", "channel_generations",
                    "channels", "allow_event_ids", "initial_read_hours"}:
                raise ValueError()
            self.config = {"policy_revision": "1", "batch_size": 32, "channel_generations": {},
                           "initial_read_hours": 24, **deepcopy(config)}
            depth = self.config["initial_read_hours"]
            if depth != "all" and (type(depth) is not int or not 0 <= depth <= 876000):
                raise ValueError()
            channels = self.config.get("channels", {})
            if (not isinstance(channels, dict) or set(channels) - set(CHANNELS)
                    or any(type(enabled) is not bool for enabled in channels.values())):
                raise ValueError()
            self.config["channels"] = {**dict.fromkeys(CHANNELS, True), **channels}
            allow = self.config.get("allow_event_ids")
            known = {item[2] for item in event_identities()}
            if allow is not None and (not isinstance(allow, list) or len(allow) > 512 or any(
                    type(n) is not int or n not in known for n in allow)):
                raise ValueError()
            self.config["allow_event_ids"] = allow
            for key in ("source_name", "connect_address", "policy_revision"):
                value = self.config[key]
                if not isinstance(value, str) or not value.strip() or len(value) > 128:
                    raise ValueError()
            if type(self.config["batch_size"]) is not int or not 1 <= self.config["batch_size"] <= 128:
                raise ValueError()
            generations = self.config["channel_generations"]
            if not isinstance(generations, dict) or any(
                    channel not in CHANNELS or not isinstance(g, str) or not g.strip() or len(g) > 128
                    for channel, g in generations.items()):
                raise ValueError()
        except (ValueError, KeyError, TypeError):
            raise ValueError("agent_ad_dc_config_invalid") from None
        self.host_id = host_id
        self.reader = reader or read_local
        self.identities = event_identities()

    def collect(self, captured=None, *, now=None, channel=None):
        now = now or datetime.now(timezone.utc)
        before = deepcopy(captured["cursor_after"]) if captured else {"strategy": "bookmark", "token": ""}
        if captured and captured["generation"] != self.host_id:
            raise ValueError("agent_ad_dc_cursor_invalid")
        state = cursor_state(before)
        enabled = active_channels(state, self.config, self.host_id, history=self.low_priority)
        self.catch_up_channel = None
        if not enabled:
            return None
        index = next((state["next"] + offset) % len(CHANNELS) for offset in range(len(CHANNELS))
                     if CHANNELS[(state["next"] + offset) % len(CHANNELS)] in enabled)
        if channel is not None:
            if channel not in enabled:
                raise ValueError("agent_ad_dc_channel_invalid")
            index = CHANNELS.index(channel)
        channel = CHANNELS[index]
        generation = self.config["channel_generations"].get(channel, self.host_id)
        progress = state["channels"].get(channel, {"record_id": None, "bookmark": "", "generation": generation})
        reset = progress["generation"] != generation
        if reset:
            progress = {"record_id": None, "bookmark": "", "generation": generation}
        if self.low_priority:
            progress = {"before_utc": self.config["history_before_utc"], **progress}
        elif (channel not in state["channels"] or reset) and self.config["initial_read_hours"] != "all":
            progress = {**progress, "since_utc": (now - timedelta(hours=self.config["initial_read_hours"])).isoformat()}
        after_id = progress["record_id"]
        read_error = None
        try:
            rows = self.reader(channel, deepcopy(progress), self.config["batch_size"])
        except (OSError, RuntimeError):
            rows = []
            read_error = "agent_ad_dc_read_failed"
        if len(rows) > self.config["batch_size"]:
            raise ValueError("agent_ad_dc_range_invalid")
        bookmark_recovered = isinstance(rows, BookmarkRecoveryBatch)
        records = []
        filtered = 0
        payload_full = False
        previous = after_id
        for raw, bookmark in rows:
            row = parse_event_xml(raw, source_name=self.config["source_name"],
                                  connect_address=self.config["connect_address"], channel=channel)
            record_id = row["record_id"]
            if (type(record_id) is not int or record_id <= 0 or previous is not None and record_id <= previous
                    or not isinstance(bookmark, str) or not bookmark or len(bookmark) > 2048):
                raise ValueError("agent_ad_dc_range_invalid")
            previous = record_id
            native = parse_bounded_xml(raw).find("e:System/e:Channel", NS)
            if native is None or native.text != channel:
                raise ValueError("agent_ad_dc_channel_invalid")
            identity = (channel, str(row["provider_name"]).casefold(), row["event_id"])
            allow = self.config["allow_event_ids"]
            if identity in self.identities and (allow is None or row["event_id"] in allow):
                record = {"format": "event_xml", "record_id": record_id, "payload": row}
                if len(canonical(records + [record])) > MAX_PAYLOAD_BYTES - 4096:
                    if not records:
                        raise ValueError("agent_ad_dc_event_size_limit")
                    payload_full = True
                    break
                records.append(record)
            else:
                filtered += 1
            progress = {**progress, "record_id": record_id, "bookmark": bookmark, "generation": generation}
        if self.low_priority and not rows and read_error is None:
            progress = {**progress, "complete": True}
        state["channels"][channel] = progress
        state["next"] = (index + 1) % len(CHANNELS)
        if not self.low_priority and not read_error and (payload_full or len(rows) == self.config["batch_size"]):
            self.catch_up_channel = channel
        after = {"strategy": "bookmark", "token": canonical(state).decode("ascii")}
        if len(after["token"]) > 4096:
            raise ValueError("agent_ad_dc_cursor_size_limit")
        payload = make_packet(source=self.config["source_name"], channel=channel, generation=generation,
            cursor={"after_record_id": after_id, "last_record_id": progress["record_id"]}, records=records,
            continuity={"status": "not_proven"}, observed_at=now,
            context={"ad_dc": {"pack_id": PACK_ID, "policy_revision": self.config["policy_revision"],
                "filtered_count": filtered, "channel_reset": reset, "read_error": read_error,
                **({"bookmark_recovered": True} if bookmark_recovered else {}),
                "channels": self.config["channels"], "channel_generations": self.config["channel_generations"]}})
        if len(canonical(payload)) > MAX_PAYLOAD_BYTES:
            raise ValueError("agent_ad_dc_event_size_limit")
        return Sample(self.module_id, self.host_id, "ad-dc", self.host_id, before, after, payload,
            policy_revision=self.config["policy_revision"],
            continuity_state="gap" if reset or read_error or bookmark_recovered else "filtered" if filtered else "not_proven",
            filtered_count=filtered, lost_count=None if reset or read_error or bookmark_recovered else 0)


def active_channels(state, config, host_id, *, history=False):
    return [channel for channel in CHANNELS if config["channels"][channel] and not (
        history and state["channels"].get(channel, {}).get("complete") is True
        and state["channels"][channel]["generation"] == config["channel_generations"].get(channel, host_id))]


class DCHistoryModule(ADDCModule):
    """Explicit bounded history stream; its spool sequence never owns live cursors."""
    module_id = HISTORY_ID
    low_priority = True

    def __init__(self, host_id, config=None, *, reader=None):
        config = deepcopy(config) if isinstance(config, dict) else {}
        try:
            before = config.pop("history_before_utc")
            timestamp(before)
            if config.get("initial_read_hours", "all") != "all":
                raise ValueError()
            super().__init__(host_id, {**config, "initial_read_hours": "all"}, reader=reader)
            self.config["history_before_utc"] = before
            self.config["batch_size"] = min(self.config["batch_size"], 4)
        except (ValueError, KeyError, TypeError):
            raise ValueError("agent_ad_dc_config_invalid") from None

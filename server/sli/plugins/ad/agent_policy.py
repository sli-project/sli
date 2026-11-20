"""AD/DC policy construction and signed native-event attestation."""
from __future__ import annotations

from xml.etree.ElementTree import ParseError

from server.sli.sources.collection_packet_import import event_rows_from_packet
from sli_agent.envelope import timestamp


def build_ad_policy(host_id, settings):
    from sli_agent.ad_dc import ADDCModule, DCHistoryModule

    factory = DCHistoryModule if "history_before_utc" in settings else ADDCModule
    return factory(host_id, settings).config


def dc_event_rows(envelope, payload, binding, policy=None):
    from sli_agent.ad_dc import CHANNELS, HISTORY_ID, PACK_ID, active_channels, cursor_state, event_identities
    from sli_collect.eventlog import NS, parse_event_xml
    from server.sli.storage.xml_safety import parse_bounded_xml

    rows = event_rows_from_packet(payload)
    try:
        before = cursor_state(envelope["cursor_before"])
        after = cursor_state(envelope["cursor_after"])
        context = payload["context"]["ad_dc"]
        history = envelope["module_id"] == HISTORY_ID
        settings = policy or {"channels": context.get("channels", dict.fromkeys(CHANNELS, True)),
                              "channel_generations": context.get("channel_generations", {})}
        enabled = active_channels(before, settings, envelope["source_instance_id"], history=history)
        if not enabled:
            raise ValueError()
        index = next((before["next"] + offset) % len(CHANNELS) for offset in range(len(CHANNELS))
                     if CHANNELS[(before["next"] + offset) % len(CHANNELS)] in enabled)
        header = payload["header"]
        # Live catch-up can continue the last channel before rotating. Its
        # signed cursor still owns progress; history keeps strict rotation.
        repeat_index = (before["next"] - 1) % len(CHANNELS)
        repeat_channel = CHANNELS[repeat_index]
        if (not history and header["channel"] == repeat_channel and repeat_channel in enabled
                and repeat_channel in before["channels"]):
            index = repeat_index
        channel = CHANNELS[index]
        progress = after["channels"][channel]
        previous = before["channels"].get(channel)
        reset = previous is not None and previous["generation"] != header["generation"]
        start = previous["record_id"] if previous and not reset else None
        last = progress["record_id"]
        others = {k: v for k, v in after["channels"].items() if k != channel}
        old_others = {k: v for k, v in before["channels"].items() if k != channel}
        filtered = envelope["filtered_count"]
        failed = context["read_error"] is not None
        recovered = context.get("bookmark_recovered", False)
        bounds = {key: progress[key] for key in ("since_utc", "before_utc") if key in progress}
        old_bounds = {key: previous[key] for key in ("since_utc", "before_utc") if previous and key in previous} if not reset else {}
        if (history and ("since_utc" in bounds or "before_utc" not in bounds)
                or not history and ("before_utc" in bounds or "complete" in progress)
                or old_bounds and bounds != old_bounds
                or not old_bounds and previous and not reset and bounds
                or progress.get("complete") is not None and (not history or rows or filtered or failed)):
            raise ValueError()
        if policy is not None:
            if (context.get("channels", policy["channels"]) != policy["channels"]
                    or context.get("channel_generations", policy["channel_generations"]) != policy["channel_generations"]):
                raise ValueError()
            if history and bounds["before_utc"] != policy["history_before_utc"]:
                raise ValueError()
            if not old_bounds and "since_utc" in bounds:
                from datetime import timedelta
                depth = policy["initial_read_hours"]
                if depth == "all" or timestamp(bounds["since_utc"]) != timestamp(header["observed_at_utc"]) - timedelta(hours=depth):
                    raise ValueError()
        expected_state = "gap" if reset or failed or recovered else "filtered" if filtered else "not_proven"
        ids = [row["record_id"] for row in rows]
        if (envelope["channel"] != "ad-dc" or envelope["generation"] != envelope["source_instance_id"]
                or header["source"] != binding["source_name"] or header["channel"] != channel
                or progress["generation"] != header["generation"]
                or header["cursor"] != {"after_record_id": start, "last_record_id": last}
                or after["next"] != (index + 1) % len(CHANNELS) or others != old_others
                or context["pack_id"] != PACK_ID or context["policy_revision"] != envelope["policy_revision"]
                or context["filtered_count"] != filtered or type(context["channel_reset"]) is not bool
                or context["channel_reset"] != reset
                or context["read_error"] not in (None, "agent_ad_dc_read_failed")
                or type(recovered) is not bool
                or recovered and (reset or failed or previous is None or start is None or not previous["bookmark"])
                or envelope["lost_count"] != (None if reset or failed or recovered else 0)
                or envelope["continuity_state"] != expected_state or payload["continuity"]["status"] != "not_proven"
                or any(type(n) is not int or n <= 0 for n in ids) or ids != sorted(set(ids))
                or any(start is not None and n <= start for n in ids)
                or any(last is None or n > last for n in ids)
                or last is not None and start is not None and last < start
                or not filtered and not failed and last != (ids[-1] if ids else start)
                or filtered and (last is None or start is not None and last <= start)
                or failed and (rows or filtered or last != start)
                or failed and previous and not reset and progress != {**previous, **bounds}):
            raise ValueError()
        if policy is not None and (header["generation"] != policy["channel_generations"].get(channel, envelope["source_instance_id"])
                or len(rows) + filtered > policy["batch_size"] or any(
                policy["allow_event_ids"] is not None and row["event_id"] not in policy["allow_event_ids"] for row in rows)):
            raise ValueError()
        identities = event_identities()
        for row in rows:
            if policy is not None and row["connect_address"] != policy["connect_address"]:
                raise ValueError()
            if (channel, str(row.get("provider_name")).casefold(), row.get("event_id")) not in identities:
                raise ValueError()
            # Reparse signed evidence: metadata cannot redirect native XML.
            native = parse_event_xml(row["xml"], source_name=header["source"],
                                     connect_address=row["connect_address"], channel=channel)
            native_channel = parse_bounded_xml(row["xml"]).find("e:System/e:Channel", NS)
            if native != row or native_channel is None or native_channel.text != channel:
                raise ValueError()
            event_time = timestamp(row["time_created"])
            if ("since_utc" in bounds and start is None and event_time < timestamp(bounds["since_utc"])
                    or "before_utc" in bounds and event_time >= timestamp(bounds["before_utc"])):
                raise ValueError()
    except (ValueError, KeyError, TypeError, AttributeError, ParseError):
        raise ValueError("agent_collection_cursor_invalid") from None
    return rows


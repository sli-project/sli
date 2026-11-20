# SPDX-License-Identifier: Apache-2.0
"""Allowlisted native evidence and lexical scope checks shared with admission."""
import ntpath
from xml.etree import ElementTree as ET

from server.sli.storage.xml_safety import parse_bounded_xml
from sli_agent.file_audit_policy import CONTEXT_EVENT_IDS, EVENT_IDS, OPTIONAL_EVENT_IDS, PROVIDER, local_path, path_in_root
from sli_collect.eventlog import NS, parse_event_xml

FIELDS = frozenset({"SubjectUserSid", "SubjectLogonId", "TargetUserSid", "TargetLogonId", "LogonType",
    "ObjectName", "ObjectType", "HandleId", "ProcessId", "ProcessName", "AccessMask", "AccessList",
    "AccessReason", "ShareName", "ShareLocalPath", "RelativeTargetName", "IpAddress", "IpPort",
    "OldSd", "NewSd", "OldSdValue", "NewSdValue", "ObjectServer", "PrivilegeList"})


def native_event(raw, host):
    root = parse_bounded_xml(raw)
    if root.tag != f"{{{NS['e']}}}Event":
        raise ValueError("file_audit_event_invalid")
    channel = root.find("e:System/e:Channel", NS)
    if channel is None or channel.text != "Security":
        raise ValueError("file_audit_channel_invalid")
    data = {}
    for item in root.findall("e:EventData/e:Data", NS):
        name = item.get("Name")
        if name in data:
            raise ValueError("file_audit_duplicate_field")
        data[name] = item.text or ""
    return parse_event_xml(raw, source_name=host, connect_address="localhost", channel="Security"), data


def masked_event(raw, config=None):
    root = parse_bounded_xml(raw)
    root.attrib.clear()
    allowed_fields = FIELDS
    if config is not None:
        row, data = native_event(raw, "mask")
        scopes, _ = scopes_for(row, data, config)
        if not scopes:
            allowed_fields = frozenset({"SubjectUserSid", "SubjectLogonId", "TargetUserSid", "TargetLogonId",
                                       "LogonType", "HandleId", "ProcessId", "AccessMask", "IpAddress", "IpPort"})
    # Keep only System and the reviewed EventData fields. Rendering/messages,
    # arbitrary UserData and credentials have no place in file evidence.
    for node in list(root):
        if node.tag not in (f"{{{NS['e']}}}System", f"{{{NS['e']}}}EventData"):
            root.remove(node)
    system_fields = {"Provider": {"Name", "Guid"}, "EventID": {"Qualifiers"}, "Version": set(),
        "Level": set(), "Task": set(), "Opcode": set(), "Keywords": set(), "EventRecordID": set(),
        "TimeCreated": {"SystemTime"}, "Channel": set(), "Computer": set(), "Security": {"UserID"}}
    for system in root.findall("e:System", NS):
        for item in list(system):
            name = item.tag.removeprefix(f"{{{NS['e']}}}")
            if name not in system_fields:
                system.remove(item)
                continue
            for attribute in list(item.attrib):
                if attribute not in system_fields[name]:
                    del item.attrib[attribute]
            for child in list(item):
                item.remove(child)
    for node in root.findall("e:EventData", NS):
        for item in list(node):
            if item.tag != f"{{{NS['e']}}}Data" or item.get("Name") not in allowed_fields:
                node.remove(item)
            else:
                for attribute in list(item.attrib):
                    if attribute != "Name":
                        del item.attrib[attribute]
                for child in list(item):
                    item.remove(child)
    return ET.tostring(root, encoding="unicode")


def fields_are_masked(raw, config):
    def shape(node):
        return node.tag, sorted(node.attrib.items()), node.text, [shape(child) for child in node]
    return shape(parse_bounded_xml(raw)) == shape(parse_bounded_xml(masked_event(raw, config)))


def outcome(row):
    try:
        flags = int(row.get("keywords") or "0", 0)
    except (ValueError, TypeError):
        return "unknown"
    success, failure = bool(flags & 0x20000000000000), bool(flags & 0x10000000000000)
    return "success" if success and not failure else "failure" if failure and not success else "unknown"


def number(value, maximum=0xffffffffffffffff):
    try:
        result = int(value, 0)
        return result if 0 <= result <= maximum else None
    except (ValueError, TypeError):
        return None


def scopes_for(row, data, config):
    event = row["event_id"]
    if row["provider_name"] != ("Microsoft-Windows-Eventlog" if event == 1102 else PROVIDER):
        return [], None
    if event not in (*EVENT_IDS, *(OPTIONAL_EVENT_IDS if config["optional_events"] else ()), *CONTEXT_EVENT_IDS):
        return [], None
    if event in CONTEXT_EVENT_IDS or event == 4660:
        return [], None  # bounded technical evidence; never invent a path
    share = data.get("ShareName", "").rsplit("\\", 1)[-1]
    path = data.get("ObjectName") or data.get("ShareLocalPath")
    if path and path.startswith("\\??\\"):
        path = path[4:]
    try:
        if path:
            path = local_path(path)
            if event == 5145:
                relative = data.get("RelativeTargetName", "")
                if ntpath.isabs(relative) or ntpath.splitdrive(relative)[0]:
                    return [], None
                path = local_path(ntpath.join(path, relative))
        scopes = [root for root in config["roots"]
                  if (not share or share.casefold() == root["share_name"].casefold())
                  and (path and path_in_root(path, root["path"]) or
                       not path and share and event in (5142, 5143, 5144))]
    except ValueError:
        return [], None
    return scopes, path


def admitted_event(row, data, config):
    scopes, path = scopes_for(row, data, config)
    event = row["event_id"]
    provider = "Microsoft-Windows-Eventlog" if event == 1102 else PROVIDER
    if row["provider_name"] != provider:
        return False, scopes, path
    if event not in (*EVENT_IDS, *(OPTIONAL_EVENT_IDS if config["optional_events"] else ()), *CONTEXT_EVENT_IDS):
        return False, scopes, path
    if config.get("source_kind") == "workstation" and event not in CONTEXT_EVENT_IDS:
        sid, name = data.get("SubjectUserSid", ""), data.get("SubjectUserName", "")
        if (not sid or sid in {"S-1-0-0", "S-1-5-7", "S-1-5-18", "S-1-5-19", "S-1-5-20"}
                or sid.startswith(("S-1-5-80-", "S-1-5-82-", "S-1-5-90-", "S-1-5-96-"))
                or name.endswith("$") or sid in config["service_account_exclusions"]):
            return False, scopes, path
    if event in CONTEXT_EVENT_IDS:
        return event != 4624 or data.get("LogonType") == "3", scopes, path
    if event == 4660:
        return True, scopes, path
    if not scopes and event in (4656, 4659, 4663, 4658) and number(data.get("HandleId")):
        # Out-of-scope handle reuse is necessary negative evidence. Send only
        # SID/logon/PID/handle/mask; never send its path or ACL.
        return True, [], None
    if not scopes:
        return False, scopes, path
    # Success checks/reads are profile-sensitive; handle-bearing observations
    # remain as technical context so filtering cannot break a deletion chain.
    if event == 5145 and outcome(row) != "failure" and not any(r["important"] for r in scopes):
        return False, scopes, path
    return True, scopes, path

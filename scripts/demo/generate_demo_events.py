#!/usr/bin/env python3
"""Offline deterministic generator of synthetic Windows Security and System events.

Writes raw batch folders in exactly the layout the collector
(`scripts/collect/collect_windows_events.py`) produces and the importer
(`scripts/import/import_event_jsonl_to_postgres.py`) reads:

    <out>/<DC>-<YYYYmmdd-HHMMSS>/Security.jsonl
    <out>/<DC>-<YYYYmmdd-HHMMSS>/System.jsonl
    <out>/<DC>-<YYYYmmdd-HHMMSS>/collection-summary.json

The script never touches a database, a domain controller or the network.
Only reserved identifiers are used: domain example.test, RFC 5737 addresses
and synthetic SIDs.  The same arguments always give byte-identical output.
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parents[2]

DOMAIN_FQDN = "example.test"
DOMAIN_NETBIOS = "EXAMPLE"
DOMAIN_DN = "DC=example,DC=test"
SID_PREFIX = "S-1-5-21-100000000-200000000-300000000"
DC_NAMES = ("DC01", "DC02")
CHANNEL = "Security"
PROVIDER = "Microsoft-Windows-Security-Auditing"
PROVIDER_GUID = "{54849625-5478-4994-A5BA-3E3B0328C30D}"
EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
DEFAULT_END = "2026-01-15T00:00:00Z"
FIRST_RECORD_ID = {"DC01": 100000, "DC02": 500000}
ATTACKER_IP = "203.0.113.77"
NPS_NAS_IP = "192.0.2.5"
MAX_USERS = 400
KEYWORDS_SUCCESS = "0x8020000000000000"
KEYWORDS_FAILURE = "0x8010000000000000"

# System channel (plan 9.4): a small set of event ids the windows_ad_dc catalog knows.
SYSTEM_CHANNEL = "System"
SYSTEM_PROCESS_ID = 780
SYSTEM_FIRST_RECORD_ID = {"DC01": 20000, "DC02": 30000}
KEYWORDS_CLASSIC = "0x8080000000000000"
SCM_PROVIDER = "Service Control Manager"
SCM_GUID = "{555908d1-a6d7-4695-8e1e-26931d2012f4}"
TIME_PROVIDER = "Microsoft-Windows-Time-Service"
NETLOGON_PROVIDER = "NETLOGON"
EVENTLOG_PROVIDER = "EventLog"
# event id -> (provider, provider guid or None, level, task, version)
SYSTEM_EVENT_META: dict[int, tuple[str, str | None, int, int, int]] = {
    7036: (SCM_PROVIDER, SCM_GUID, 4, 0, 0),
    7040: (SCM_PROVIDER, SCM_GUID, 4, 0, 0),
    7045: (SCM_PROVIDER, SCM_GUID, 4, 0, 0),
    6013: (EVENTLOG_PROVIDER, None, 4, 0, 0),
    142: (TIME_PROVIDER, "{06edcfeb-0fd0-4e53-acca-a6f8bbf81bcb}", 3, 0, 0),
    5805: (NETLOGON_PROVIDER, None, 2, 0, 0),
}

# event id -> (task, version)
EVENT_META: dict[int, tuple[int, int]] = {
    4624: (12544, 2), 4625: (12546, 0), 4634: (12545, 0), 4672: (12548, 0),
    4719: (13568, 0), 4720: (13824, 0), 4722: (13824, 0), 4723: (13824, 0),
    4724: (13824, 0), 4726: (13824, 0), 4728: (13826, 0), 4729: (13826, 0),
    4732: (13826, 0), 4733: (13826, 0), 4740: (13824, 0), 4756: (13826, 0),
    4767: (13824, 0), 6272: (12552, 1), 6273: (12552, 1),
}
FAILURE_EVENT_IDS = frozenset({4625, 6273})


def _channel_of(event: dict[str, Any]) -> str:
    return event.get("channel", CHANNEL)


def _event_meta(event: dict[str, Any]) -> dict[str, Any]:
    """Provider/task/version/keywords/level of one logical event (Security or System)."""
    event_id = event["event_id"]
    if _channel_of(event) == SYSTEM_CHANNEL:
        provider, guid, level, task, version = SYSTEM_EVENT_META[event_id]
        return {"provider": provider, "guid": guid, "level": level, "task": task,
                "version": version, "keywords": KEYWORDS_CLASSIC, "process_id": SYSTEM_PROCESS_ID,
                "user_id": "S-1-5-18" if provider == SCM_PROVIDER else None}
    task, version = EVENT_META[event_id]
    return {"provider": PROVIDER, "guid": PROVIDER_GUID, "level": 0, "task": task,
            "version": version, "process_id": 672, "user_id": None,
            "keywords": KEYWORDS_FAILURE if event_id in FAILURE_EVENT_IDS else KEYWORDS_SUCCESS}


def _sid(rid: int) -> str:
    return f"{SID_PREFIX}-{rid}"


def _utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond:06d}0Z"


def _iso_short(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def resolve_out_dir(out: str | Path) -> Path:
    """Resolve --out and refuse anything inside the repository data/ tree."""
    resolved = Path(out).resolve()
    data_dir = (ROOT / "data").resolve()
    if resolved == data_dir or data_dir in resolved.parents:
        raise ValueError("out_dir_inside_data_refused")
    return resolved


class _World:
    def __init__(self, users: int) -> None:
        pool = [f"192.0.2.{n}" for n in range(10, 251)] + [f"198.51.100.{n}" for n in range(10, 251)]
        self.users = []
        for index in range(users):
            number = index + 1
            self.users.append({
                "name": f"user{number:03d}",
                "sid": _sid(1100 + index),
                "host": f"WS{number:03d}",
                "ip": pool[index % len(pool)],
            })
        self.admins = [
            {"name": "adm001", "sid": _sid(1001), "host": "WS900", "ip": "192.0.2.200"},
            {"name": "adm002", "sid": _sid(1002), "host": "WS901", "ip": "192.0.2.201"},
        ]
        self.next_rid = 2000
        self.logon_seq = 0

    def logon_id(self) -> str:
        self.logon_seq += 1
        return f"0x{0x100000 + self.logon_seq * 0x37:x}"


def _subject(actor: dict[str, str], logon_id: str) -> dict[str, str]:
    return {
        "SubjectUserSid": actor["sid"], "SubjectUserName": actor["name"],
        "SubjectDomainName": DOMAIN_NETBIOS, "SubjectLogonId": logon_id,
    }


def _system_subject(dc: str) -> dict[str, str]:
    return {
        "SubjectUserSid": "S-1-5-18", "SubjectUserName": f"{dc}$",
        "SubjectDomainName": DOMAIN_NETBIOS, "SubjectLogonId": "0x3e7",
    }


def generate_events(*, days: int, seed: int, users: int, end: datetime) -> list[dict[str, Any]]:
    """Return unsorted logical events: time, dc, event_id, data (ordered dict)."""
    rng = random.Random(seed)
    world = _World(users)
    start = end - timedelta(days=days)
    events: list[dict[str, Any]] = []

    def emit(when: datetime, dc: str, event_id: int, data: dict[str, str]) -> None:
        if start <= when < end:
            events.append({"time": when, "dc": dc, "event_id": event_id, "data": data})

    def at(day: datetime, hour: float, jitter_minutes: float = 0.0) -> datetime:
        seconds = hour * 3600 + rng.uniform(-jitter_minutes, jitter_minutes) * 60
        return day + timedelta(seconds=seconds, microseconds=rng.randrange(1_000_000))

    def pick_dc() -> str:
        return DC_NAMES[rng.randrange(len(DC_NAMES))]

    def kerberos_logon(who: dict[str, str], when: datetime, dc: str, privileged: bool) -> None:
        lid = world.logon_id()
        emit(when, dc, 4624, {
            **_system_subject(dc),
            "TargetUserSid": who["sid"], "TargetUserName": who["name"],
            "TargetDomainName": DOMAIN_NETBIOS, "TargetLogonId": lid, "LogonType": "3",
            "LogonProcessName": "Kerberos", "AuthenticationPackageName": "Kerberos",
            "WorkstationName": who["host"], "LogonGuid": "{00000000-0000-0000-0000-000000000000}",
            "TransmittedServices": "-", "LmPackageName": "-", "KeyLength": "0",
            "ProcessId": "0x0", "ProcessName": "-", "IpAddress": who["ip"],
            "IpPort": str(49152 + rng.randrange(16000)), "ImpersonationLevel": "%%1833",
            "RestrictedAdminMode": "-", "TargetOutboundUserName": "-",
            "TargetOutboundDomainName": "-", "VirtualAccount": "%%1843",
            "TargetLinkedLogonId": "0x0", "ElevatedToken": "%%1842",
        })
        if privileged:
            emit(when + timedelta(microseconds=200), dc, 4672, {
                "SubjectUserSid": who["sid"], "SubjectUserName": who["name"],
                "SubjectDomainName": DOMAIN_NETBIOS, "SubjectLogonId": lid,
                "PrivilegeList": "SeSecurityPrivilege\n\t\t\tSeBackupPrivilege\n\t\t\tSeRestorePrivilege",
            })
        off = when.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(
            hours=17, minutes=rng.uniform(-30, 90), microseconds=rng.randrange(1_000_000))
        emit(off, dc, 4634, {
            "TargetUserSid": who["sid"], "TargetUserName": who["name"],
            "TargetDomainName": DOMAIN_NETBIOS, "TargetLogonId": lid, "LogonType": "3",
        })

    def failed_logon(name: str, sid: str, ip: str, host: str, when: datetime, dc: str,
                     sub_status: str = "0xc000006a", status: str = "0xc000006d") -> None:
        emit(when, dc, 4625, {
            "SubjectUserSid": "S-1-0-0", "SubjectUserName": "-", "SubjectDomainName": "-",
            "SubjectLogonId": "0x0", "TargetUserSid": sid, "TargetUserName": name,
            "TargetDomainName": DOMAIN_NETBIOS, "Status": status, "FailureReason": "%%2313",
            "SubStatus": sub_status, "LogonType": "3", "LogonProcessName": "NtLmSsp",
            "AuthenticationPackageName": "NTLM", "WorkstationName": host,
            "TransmittedServices": "-", "LmPackageName": "-", "KeyLength": "0",
            "ProcessId": "0x0", "ProcessName": "-", "IpAddress": ip,
            "IpPort": str(49152 + rng.randrange(16000)),
        })

    def account_event(event_id: int, when: datetime, dc: str, actor: dict[str, str],
                      target_name: str, target_sid: str) -> None:
        emit(when, dc, event_id, {
            "TargetUserName": target_name, "TargetDomainName": DOMAIN_NETBIOS,
            "TargetSid": target_sid, **_subject(actor, world.logon_id()),
        })

    def group_event(event_id: int, when: datetime, dc: str, actor: dict[str, str],
                    member: str, member_sid: str, group: str, group_sid: str, domain: str) -> None:
        emit(when, dc, event_id, {
            "MemberName": f"CN={member},OU=Users,{DOMAIN_DN}", "MemberSid": member_sid,
            "TargetUserName": group, "TargetDomainName": domain, "TargetSid": group_sid,
            **_subject(actor, world.logon_id()), "PrivilegeList": "-",
        })

    admin = world.admins[0]
    first_day = start.replace(hour=0, minute=0, second=0, microsecond=0)
    span = end - first_day
    day_count = span.days + (1 if span % timedelta(days=1) else 0)
    brute_index = days // 2
    created: dict[str, str] | None = None
    sequence = 0
    workday_index = 0

    for index in range(day_count):
        day = first_day + timedelta(days=index)
        workday = day.weekday() < 5

        if workday:
            for who in world.admins:
                kerberos_logon(who, at(day, 7.75, 20), pick_dc(), True)
            for who in world.users:
                if rng.random() < 0.06:
                    failed_logon(who["name"], who["sid"], who["ip"], who["host"],
                                 at(day, 7.6, 25), pick_dc())
                if rng.random() < 0.95:
                    kerberos_logon(who, at(day, 8.0, 35), pick_dc(), False)
            for n in range(rng.randint(1, 3)):
                failed_logon(f"admin{n}", "S-1-0-0", f"203.0.113.{rng.randint(100, 200)}", "-",
                             at(day, 13.0, 300), pick_dc(), status="0xc000006d",
                             sub_status="0xc0000064")
            for who in world.users[: min(8, len(world.users))]:
                sequence += 1
                session = f"{0x5A000000 + sequence:08X}"
                nps_base = {
                    "SubjectUserSid": who["sid"], "SubjectUserName": who["name"],
                    "SubjectDomainName": DOMAIN_NETBIOS,
                    "FullyQualifiedSubjectUserName": f"{DOMAIN_NETBIOS}\\{who['name']}",
                    "CalledStationID": "vpn.example.test",
                    "CallingStationID": f"203.0.113.{10 + (index * 7 + sequence) % 90}",
                    "NASIPv4Address": NPS_NAS_IP, "NASIdentifier": "VPN-GW01",
                    "NASPortType": "Virtual", "ClientName": "VPN-GW01",
                    "ClientIPAddress": NPS_NAS_IP, "ProxyPolicyName": "Use Windows authentication",
                    "NetworkPolicyName": "VPN Users", "AuthenticationProvider": "Windows",
                    "AuthenticationServer": f"{DC_NAMES[1]}.{DOMAIN_FQDN}",
                    "AuthenticationType": "MS-CHAPv2", "EAPType": "-",
                    "AccountSessionIdentifier": session,
                }
                if rng.random() < 0.12:
                    emit(at(day, 8.5, 60), DC_NAMES[1], 6273, {
                        **nps_base, "ReasonCode": "16",
                        "Reason": "Authentication failed due to a user credentials mismatch.",
                    })
                else:
                    emit(at(day, 8.5, 60), DC_NAMES[1], 6272,
                         {**nps_base, "ReasonCode": "0", "Reason": "-"})

        if index == brute_index and len(world.users) >= 3:
            victim = world.users[2]
            when = day + timedelta(hours=2, minutes=13, microseconds=rng.randrange(1_000_000))
            for attempt in range(60):
                when = when + timedelta(seconds=rng.uniform(2.0, 6.0))
                locked = attempt >= 10
                failed_logon(victim["name"], victim["sid"], ATTACKER_IP, "-", when, DC_NAMES[0],
                             sub_status="0xc0000234" if locked else "0xc000006a",
                             status="0xc0000234" if locked else "0xc000006d")
                if attempt == 9:
                    emit(when + timedelta(milliseconds=400), DC_NAMES[0], 4740, {
                        "TargetUserName": victim["name"], "TargetDomainName": "WS-UNKNOWN",
                        "TargetSid": victim["sid"], **_system_subject(DC_NAMES[0]),
                    })
            account_event(4767, at(day, 9.1, 10), DC_NAMES[0], admin, victim["name"], victim["sid"])

        if workday:
            step = workday_index % 4
            workday_index += 1
            if step == 0:
                who = world.users[rng.randrange(len(world.users))]
                account_event(4723, at(day, 10.0, 60), DC_NAMES[0], who, who["name"], who["sid"])
            elif step == 1:
                world.next_rid += 1
                created = {"name": f"demo{world.next_rid:04d}", "sid": _sid(world.next_rid)}
                t = at(day, 10.0, 30)
                account_event(4720, t, DC_NAMES[0], admin, created["name"], created["sid"])
                account_event(4722, t + timedelta(seconds=2), DC_NAMES[0], admin,
                              created["name"], created["sid"])
                account_event(4724, t + timedelta(seconds=4), DC_NAMES[0], admin,
                              created["name"], created["sid"])
                group_event(4728, t + timedelta(seconds=6), DC_NAMES[0], admin, created["name"],
                            created["sid"], "Staff", _sid(1500), DOMAIN_NETBIOS)
            elif step == 2:
                for who in rng.sample(world.users, min(3, len(world.users))):
                    account_event(4723, at(day, 11.0, 90), pick_dc(), who, who["name"], who["sid"])
                if created is not None:
                    t = at(day, 14.0, 30)
                    group_event(4732, t, DC_NAMES[0], admin, created["name"], created["sid"],
                                "Remote Desktop Users", "S-1-5-32-555", "Builtin")
                    group_event(4756, t + timedelta(seconds=5), DC_NAMES[0], admin, created["name"],
                                created["sid"], "Ops-Universal", _sid(1501), DOMAIN_NETBIOS)
            else:
                if created is not None:
                    t = at(day, 15.0, 30)
                    group_event(4733, t, DC_NAMES[0], admin, created["name"], created["sid"],
                                "Remote Desktop Users", "S-1-5-32-555", "Builtin")
                    group_event(4729, t + timedelta(seconds=3), DC_NAMES[0], admin, created["name"],
                                created["sid"], "Staff", _sid(1500), DOMAIN_NETBIOS)
                    account_event(4726, t + timedelta(seconds=8), DC_NAMES[0], admin,
                                  created["name"], created["sid"])
                    created = None
                emit(at(day, 16.0, 20), DC_NAMES[0], 4719, {
                    **_subject(admin, world.logon_id()), "CategoryId": "%%8274",
                    "SubcategoryId": "%%12807",
                    "SubcategoryGuid": "{0CCE9215-69AE-11D9-BED3-505054503030}",
                    "AuditPolicyChanges": "%%8448, %%8450",
                })
    return events


def build_xml(event: dict[str, Any], *, record_id: int, computer: str, process_id: int) -> str:
    event_id = event["event_id"]
    meta = _event_meta(event)
    data = "".join(
        f'<Data Name="{name}">{escape(str(value))}</Data>' for name, value in event["data"].items()
    )
    guid = f' Guid="{meta["guid"]}"' if meta["guid"] else ""
    security = f' UserID="{meta["user_id"]}"' if meta["user_id"] else ""
    return (
        f'<Event xmlns="{EVENT_NS}"><System>'
        f'<Provider Name="{meta["provider"]}"{guid}/>'
        f'<EventID>{event_id}</EventID><Version>{meta["version"]}</Version><Level>{meta["level"]}</Level>'
        f'<Task>{meta["task"]}</Task><Opcode>0</Opcode><Keywords>{meta["keywords"]}</Keywords>'
        f'<TimeCreated SystemTime="{_iso(event["time"])}"/>'
        f"<EventRecordID>{record_id}</EventRecordID>"
        f'<Correlation/><Execution ProcessID="{process_id}" ThreadID="{process_id + 40}"/>'
        f"<Channel>{_channel_of(event)}</Channel><Computer>{computer}</Computer>"
        f"<Security{security}/></System>"
        f"<EventData>{data}</EventData></Event>"
    )


def build_row(event: dict[str, Any], *, record_id: int, source_name: str) -> dict[str, Any]:
    """One collector row: same keys as collect_windows_events.parse_event_xml."""
    meta = _event_meta(event)
    xml = build_xml(event, record_id=record_id, computer=source_name, process_id=meta["process_id"])
    return {
        "computer_name": source_name, "connect_address": source_name, "channel": _channel_of(event),
        "provider_name": meta["provider"], "event_id": event["event_id"], "version": meta["version"],
        "level": meta["level"], "task": meta["task"], "opcode": 0, "keywords": meta["keywords"],
        "record_id": record_id, "time_created": _iso(event["time"]), "machine_name": source_name,
        "user_id": meta["user_id"], "message": None,
        "properties": [str(v) for v in event["data"].values()], "xml": xml,
    }


def generate_system_events(*, days: int, seed: int, end: datetime) -> list[dict[str, Any]]:
    """Small deterministic System-channel set per DC; own RNG so Security output is unchanged."""
    rng = random.Random(f"system-channel:{seed}")
    start = end - timedelta(days=days)
    events: list[dict[str, Any]] = []

    def emit(when: datetime, dc: str, event_id: int, data: dict[str, str]) -> None:
        if start <= when < end:
            events.append({"time": when, "dc": dc, "event_id": event_id, "data": data,
                           "channel": SYSTEM_CHANNEL})

    def at(day: datetime, hour: float, jitter_minutes: float = 0.0) -> datetime:
        seconds = hour * 3600 + rng.uniform(-jitter_minutes, jitter_minutes) * 60
        return day + timedelta(seconds=seconds, microseconds=rng.randrange(1_000_000))

    def state(dc: str, when: datetime, service: str, new_state: str) -> None:
        emit(when, dc, 7036, {"param1": service, "param2": new_state})

    first_day = start.replace(hour=0, minute=0, second=0, microsecond=0)
    span = end - first_day
    day_count = span.days + (1 if span % timedelta(days=1) else 0)
    for index in range(day_count):
        day = first_day + timedelta(days=index)
        for number, dc in enumerate(DC_NAMES):
            uptime = (index + 1) * 86400 + rng.randrange(3600)
            emit(at(day, 12.0, 5), dc, 6013, {
                "param1": str(uptime),
            })
            # Daily update-style service churn.
            t = at(day, 3.0 + number * 0.5, 20)
            state(dc, t, "Windows Modules Installer", "running")
            state(dc, t + timedelta(minutes=rng.uniform(2, 9)), "Windows Modules Installer", "stopped")
        if index % 3 == 0:
            emit(at(day, 6.0, 30), DC_NAMES[1], 142, {
                "param1": f"{DC_NAMES[0].lower()}.{DOMAIN_FQDN}", "param2": "0x80072746",
            })
    # One-off events at deterministic positions of the window.
    change_day = first_day + timedelta(days=min(day_count - 1, days // 2))
    for number, dc in enumerate(DC_NAMES):
        t = at(change_day, 9.0 + number, 15)
        state(dc, t, "Print Spooler", "stopped")
        emit(t + timedelta(seconds=3), dc, 7040, {
            "param1": "Print Spooler", "param2": "auto start", "param3": "disabled",
            "param4": "Spooler",
        })
    install_day = first_day + timedelta(days=min(day_count - 1, days // 4))
    emit(at(install_day, 10.5, 10), DC_NAMES[0], 7045, {
        "ServiceName": "Demo Inventory Agent",
        "ImagePath": "C:\\Program Files\\DemoAgent\\agent.exe",
        "ServiceType": "user mode service", "ServiceStartType": "auto start",
        "AccountName": "LocalSystem",
    })
    netlogon_day = first_day + timedelta(days=min(day_count - 1, (3 * days) // 4))
    emit(at(netlogon_day, 14.0, 20), DC_NAMES[1], 5805, {
        "param1": "WS003", "param2": "0xc0000022", "param3": "WS003$",
    })
    return events


def _write_channel(batch_dir: Path, channel: str, events: list[dict[str, Any]], *, source_name: str,
                   first_record_id: int, rng: random.Random, dc: str, start: datetime,
                   end: datetime) -> tuple[dict[str, Any], int, dict[int, int]]:
    """Write one channel jsonl; return its collection-summary entry, row count, per-id counts."""
    record_id = first_record_id
    after = record_id - 1
    last_record = after
    previous: datetime | None = None
    lines: list[str] = []
    counts: dict[int, int] = {}
    for event in events:
        if previous is not None and event["time"] <= previous:
            event["time"] = previous + timedelta(microseconds=1)
        previous = event["time"]
        row = build_row(event, record_id=record_id, source_name=source_name)
        lines.append(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
        counts[event["event_id"]] = counts.get(event["event_id"], 0) + 1
        last_record = record_id
        record_id += rng.randint(1, 3)
    payload = "".join(lines).encode("utf-8")
    (batch_dir / f"{channel}.jsonl").write_bytes(payload)
    generation = f"demo-{dc.lower()}-generation-1" if channel == CHANNEL else (
        f"demo-{dc.lower()}-{channel.lower()}-generation-1")
    finished = _iso_short(end)
    entry = {
        "channel": channel, "start_time_utc": _iso_short(start), "end_time_utc": None,
        "event_ids": [], "after_record_id": after, "max_events": 0, "timeout_seconds": 0,
        "file": f"{channel}.jsonl", "status": "completed", "count": len(lines),
        "error": None, "started_at": finished, "finished_at": finished,
        "duration_seconds": 0.0, "cursor_strategy": "record_id",
        "requested_cursor_strategy": "record_id", "cursor_fallback_reason": None,
        "cursor_probe_error": None, "effective_after_record_id": after,
        "saved_channel_generation_identity": generation,
        "channel_generation_identity": generation,
        "channel_generation_identity_after_read": generation,
        "cursor_post_probe_error": None,
        "channel_oldest_record_id_before_read": after + 1,
        "channel_latest_record_id_before_read": last_record,
        "latest_available_record_id": last_record if lines else None,
        "batch_max_record_id": last_record if lines else None,
        "collector_backend": "python", "bytes_written": len(payload),
        "continuity": {
            "contract": "sli.source-capture-continuity.v1", "status": "complete",
            "after_record_id": after, "latest_record_id": last_record,
            "channel_generation_identity": generation,
            "channel_generation_identity_after_read": generation,
            "generation_stable_during_read": True, "oldest_record_id": after + 1,
            "truncated": False, "selector_event_ids": sorted(counts),
            "query_exhausted": True,
        },
    }
    return entry, len(lines), counts


def write_batches(out_dir: Path, events: list[dict[str, Any]], *, start: datetime,
                  end: datetime, days: int,
                  system_events: list[dict[str, Any]] | None = None) -> dict[str, dict[str, Any]]:
    """Split by DC, assign increasing record ids/timestamps and write the batches."""
    rng = random.Random(f"record-gaps:{start.isoformat()}")
    system_rng = random.Random(f"system-record-gaps:{start.isoformat()}")
    order = sorted(range(len(events)), key=lambda i: (events[i]["time"], i))
    system_events = system_events or []
    system_order = sorted(range(len(system_events)), key=lambda i: (system_events[i]["time"], i))
    result: dict[str, dict[str, Any]] = {}
    stamp = end.strftime("%Y%m%d-%H%M%S")
    for dc in DC_NAMES:
        source_name = f"{dc}.{DOMAIN_FQDN}"
        batch_dir = out_dir / f"{dc}-{stamp}"
        batch_dir.mkdir(parents=True, exist_ok=True)
        channels: list[dict[str, Any]] = []
        entry, count, counts = _write_channel(
            batch_dir, CHANNEL, [events[i] for i in order if events[i]["dc"] == dc],
            source_name=source_name, first_record_id=FIRST_RECORD_ID[dc], rng=rng, dc=dc,
            start=start, end=end)
        channels.append(entry)
        result[dc] = {"dir": str(batch_dir), "events": count, "by_event_id": dict(sorted(counts.items()))}
        if system_events:
            entry, count, counts = _write_channel(
                batch_dir, SYSTEM_CHANNEL,
                [system_events[i] for i in system_order if system_events[i]["dc"] == dc],
                source_name=source_name, first_record_id=SYSTEM_FIRST_RECORD_ID[dc],
                rng=system_rng, dc=dc, start=start, end=end)
            channels.append(entry)
            result[dc]["system_events"] = count
            result[dc]["system_by_event_id"] = dict(sorted(counts.items()))
        finished = _iso_short(end)
        summary = {
            "computer_name": source_name, "connect_address": source_name,
            "started_at": finished, "start_time_utc": _iso_short(start),
            "end_time_utc": None, "event_ids": [], "collection_mode": "python_eventlog",
            "requested_collection_mode": "python", "collector_backend": "python",
            "collect_message": False, "hours": days * 24, "max_events_per_channel": 0,
            "channel_timeout_seconds": 0, "synthetic_demo": True,
            "channels": channels,
            "finished_at": finished,
        }
        (batch_dir / "collection-summary.json").write_bytes(
            (json.dumps(summary, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        )
    return result


def generate(out: str | Path, *, days: int = 7, seed: int = 1, users: int = 25,
             end: str = DEFAULT_END) -> dict[str, dict[str, Any]]:
    out_dir = resolve_out_dir(out)
    if days < 1 or days > 366:
        raise ValueError("days_out_of_range")
    if users < 3 or users > MAX_USERS:
        raise ValueError(f"users_out_of_range_3_{MAX_USERS}")
    end_dt = _utc(end)
    start_dt = end_dt - timedelta(days=days)
    events = generate_events(days=days, seed=seed, users=users, end=end_dt)
    system_events = generate_system_events(days=days, seed=seed, end=end_dt)
    out_dir.mkdir(parents=True, exist_ok=True)
    return write_batches(out_dir, events, start=start_dt, end=end_dt, days=days,
                         system_events=system_events)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True, help="Output directory (not inside data/).")
    parser.add_argument("--days", type=int, default=7)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--users", type=int, default=25)
    parser.add_argument("--end", default=DEFAULT_END, help="ISO UTC end of the window.")
    args = parser.parse_args(argv)
    try:
        result = generate(args.out, days=args.days, seed=args.seed, users=args.users, end=args.end)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

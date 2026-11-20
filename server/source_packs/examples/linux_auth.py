from __future__ import annotations

"""Reference source pack: Linux ``auth.log`` (sshd and sudo).

Uses only the manifest v2 contract (ADR 0012): three required handlers, every
other handler comes from the defaults of ``load_normalizer_entry``. The parser
is deliberately strict: a line it does not understand is skipped, never guessed.
"""

import re
import sys
from collections.abc import Mapping
from datetime import datetime, timezone, tzinfo
from typing import Any
from zoneinfo import ZoneInfo

from server.source_packs.contracts import EventEntitySemantics

STREAM = "linux:auth"
SSHD_ACCEPTED = 100
SSHD_FAILED = 101
SUDO_COMMAND = 110
SESSION_OPENED = 120
SESSION_CLOSED = 121
EVENT_IDS = (SSHD_ACCEPTED, SSHD_FAILED, SUDO_COMMAND, SESSION_OPENED, SESSION_CLOSED)

_MONTHS = {
    name: number
    for number, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
        1,
    )
}
_LINE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) (?P<hms>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>[A-Za-z0-9._-]{1,253}) (?P<program>[A-Za-z0-9_.-]{1,64})"
    r"(?:\[(?P<pid>\d{1,10})\])?: (?P<msg>.*)$"
)
_SSHD_ACCEPTED = re.compile(
    r"^Accepted (?P<method>password|publickey) for (?P<user>\S{1,64}) "
    r"from (?P<ip>[0-9a-fA-F:.]{2,45}) port \d{1,5}"
)
_SSHD_FAILED = re.compile(
    r"^Failed (?P<method>password|publickey) for (?:invalid user )?(?P<user>\S{1,64}) "
    r"from (?P<ip>[0-9a-fA-F:.]{2,45}) port \d{1,5}"
)
_SUDO = re.compile(r"^\s*(?P<user>\S{1,64}) : (?:.*?; )?COMMAND=(?P<command>.+)$")
_SESSION = re.compile(
    r"^pam_unix\(sshd:session\): session (?P<state>opened|closed) for user (?P<user>[^\s(]{1,64})"
)
_COMMAND_LIMIT = 512


def _zone(value: tzinfo | str | None) -> tzinfo:
    if value is None:
        return timezone.utc
    if isinstance(value, tzinfo):
        return value
    return timezone.utc if value.upper() == "UTC" else ZoneInfo(value)


def parse_line(line: str, year: int, timezone_: tzinfo | str | None = None) -> dict[str, Any] | None:
    """Turns one raw syslog line into an event dict, or ``None`` if not understood.

    ``time`` is timezone-aware UTC: syslog carries neither year nor zone, so the
    caller (the collector knows the file and the host) supplies both.
    """
    match = _LINE.match(str(line or "").rstrip("\r\n"))
    if not match or match["mon"] not in _MONTHS:
        return None
    program, message = match["program"], match["msg"]
    event: dict[str, Any] = {
        "event_id": 0,
        "host": match["host"],
        "program": program,
        "pid": match["pid"],
        "user": None,
        "source_ip": None,
        "auth_method": None,
        "command": None,
    }
    if program == "sshd" and (found := _SSHD_ACCEPTED.match(message)):
        event.update(event_id=SSHD_ACCEPTED, user=found["user"], source_ip=found["ip"], auth_method=found["method"])
    elif program == "sshd" and (found := _SSHD_FAILED.match(message)):
        event.update(event_id=SSHD_FAILED, user=found["user"], source_ip=found["ip"], auth_method=found["method"])
    elif program == "sudo" and (found := _SUDO.match(message)):
        event.update(event_id=SUDO_COMMAND, user=found["user"], command=found["command"].strip()[:_COMMAND_LIMIT])
    elif program == "sshd" and (found := _SESSION.match(message)):
        event.update(
            event_id=SESSION_OPENED if found["state"] == "opened" else SESSION_CLOSED,
            user=found["user"],
        )
    else:
        return None
    hour, minute, second = (int(part) for part in match["hms"].split(":"))
    try:
        naive = datetime(year, _MONTHS[match["mon"]], int(match["day"]), hour, minute, second, tzinfo=_zone(timezone_))
    except ValueError:
        return None
    event["time"] = naive.astimezone(timezone.utc)
    return event


def _event_id(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def event_facts(*, row: Mapping[str, Any], event_data: Mapping[str, Any] | None = None) -> dict[str, Any]:
    data = event_data if event_data is not None else row
    event_id = _event_id(row.get("event_id"))
    if event_id not in EVENT_IDS:
        return {}
    return {
        "process_name": data.get("program"),
        "process_id": data.get("pid"),
        "target_server_name": data.get("host"),
        "service_name": None,
        "task_name": None,
        "task_action": None,
        "task_author": None,
        "run_as": None,
        "logon_type": data.get("auth_method"),
        "result_code": {SSHD_ACCEPTED: "success", SSHD_FAILED: "failure"}.get(event_id),
        "object_name": data.get("command"),
        "share_name": None,
        "message_sample": None,
    }


def entity_semantics(*, channel: str | None, event_id: Any) -> EventEntitySemantics:
    return EventEntitySemantics()


def event_label(event_id: Any, lang: str) -> str | None:
    labels = {
        SSHD_ACCEPTED: {"ru": "sshd: вход принят", "en": "sshd: login accepted"},
        SSHD_FAILED: {"ru": "sshd: вход отклонён", "en": "sshd: login failed"},
        SUDO_COMMAND: {"ru": "sudo: выполнена команда", "en": "sudo: command run"},
        SESSION_OPENED: {"ru": "Сессия открыта", "en": "Session opened"},
        SESSION_CLOSED: {"ru": "Сессия закрыта", "en": "Session closed"},
    }.get(_event_id(event_id))
    if labels is None:
        return None
    return labels.get(str(lang or "ru").casefold()) or labels["ru"]


#: The namespace named by the manifest ``normalizer_entry``: this module itself.
normalizer_namespace = sys.modules[__name__]


def auth_log_collector(*, path: str, year: int, timezone: str | None = None):
    """Manifest ``collector`` entry (kind ``file``): reads one explicit auth.log.

    Syslog lines carry no year or zone, so the operator's request supplies both;
    lines the parser does not understand are skipped, never guessed.
    """
    from pathlib import Path

    from server.source_packs.collector_contract import FileLineCollector

    return FileLineCollector(path=Path(path), parse=lambda line: parse_line(line, year, timezone))

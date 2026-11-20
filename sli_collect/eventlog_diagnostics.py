"""Allowlisted native read diagnostics: never exception text or event/bookmark XML."""
import re
from copy import deepcopy
from datetime import datetime

CHANNELS = frozenset({"Security", "System", "Directory Service",
    "Microsoft-Windows-Windows Defender/Operational", "Microsoft-Windows-TaskScheduler/Operational",
    "Microsoft-Windows-DriverFrameworks-UserMode/Operational", "Microsoft-Windows-Kernel-PnP/Configuration"})
STAGES = frozenset({"query", "bookmark", "seek", "anchor", "read", "render", "collect"})
FIELDS = {"exception_class", "winerror", "hresult", "channel", "record_id", "bookmark_present", "stage"}


def _number(value, lower, upper):
    return type(value) is int and lower <= value <= upper


def diagnostic(exc, channel, cursor, stage):
    name = type(exc).__name__
    winerror, hresult = getattr(exc, "winerror", None), getattr(exc, "hresult", None)
    return {"exception_class": name if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", name) else "Exception",
            "winerror": winerror if _number(winerror, 0, 2**32 - 1) else None,
            "hresult": hresult if _number(hresult, -(2**31), 2**32 - 1) else None,
            "channel": channel, "record_id": cursor["record_id"],
            "bookmark_present": bool(cursor["bookmark"]), "stage": stage}


class EventLogReadError(RuntimeError):
    def __init__(self, code, details):
        super().__init__(code)
        self.diagnostic = details


def validate_diagnostic(value):
    if (not isinstance(value, dict) or set(value) != FIELDS
            or not isinstance(value["exception_class"], str)
            or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", value["exception_class"])
            or value["channel"] not in CHANNELS or value["stage"] not in STAGES
            or type(value["bookmark_present"]) is not bool
            or value["record_id"] is not None and not _number(value["record_id"], 0, 2**63 - 1)
            or value["winerror"] is not None and not _number(value["winerror"], 0, 2**32 - 1)
            or value["hresult"] is not None and not _number(value["hresult"], -(2**31), 2**32 - 1)):
        raise ValueError("eventlog_diagnostics_invalid")
    return deepcopy(value)


def validate_observations(values):
    try:
        if not isinstance(values, list) or len(values) > len(CHANNELS):
            raise ValueError()
        channels = set()
        for item in values:
            if (not isinstance(item, dict) or set(item) != {"channel", "observed_at_utc", "policy_revision", "error"}
                    or item["channel"] not in CHANNELS or item["channel"] in channels
                    or not _number(item["policy_revision"], 1, 9007199254740991)
                    or not isinstance(item["observed_at_utc"], str) or len(item["observed_at_utc"]) > 40
                    or datetime.fromisoformat(item["observed_at_utc"]).utcoffset() is None):
                raise ValueError()
            channels.add(item["channel"])
            if item["error"] is not None and validate_diagnostic(item["error"])["channel"] != item["channel"]:
                raise ValueError()
        return deepcopy(values)
    except (ValueError, TypeError, KeyError):
        raise ValueError("eventlog_diagnostics_invalid") from None

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,}[0-9a-fA-F]{1,4}\b")
SID_RE = re.compile(r"\bS-1-5(?:-\d+){2,}\b", re.I)
UNC_PATH_RE = re.compile(r"(?:\\\\[\w.$-]+\\[^\s\"']+|[A-Za-z]:\\[^\s\"']+)")
DOMAIN_USER_RE = re.compile(r"\b[A-Za-z0-9_.-]+\\[A-Za-z0-9_.-]+\b")
FQDN_RE = re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

PATTERNS = {
    "ipv4": IPV4_RE,
    "ipv6": IPV6_RE,
    "sid": SID_RE,
    "path_or_unc": UNC_PATH_RE,
    "domain_user": DOMAIN_USER_RE,
    "fqdn": FQDN_RE,
    "email": EMAIL_RE,
}

ALLOWLIST_PREFIXES = ("account_", "host_", "ip_", "domain_", "sid_", "path_", "logon_")


def _iter_text_values(payload: Any, path: str = "$"):
    if isinstance(payload, str):
        yield path, payload
        return
    if isinstance(payload, dict):
        for key, value in payload.items():
            yield from _iter_text_values(value, f"{path}.{key}")
        return
    if isinstance(payload, (list, tuple)):
        for index, value in enumerate(payload):
            yield from _iter_text_values(value, f"{path}[{index}]")


def check_redaction_leaks(payload: Any, *, redaction_level: str = "strict") -> dict[str, Any]:
    """Inspect actual leaf strings instead of serialized JSON escapes.

    Walking request values prevents false positives across escaped newlines while
    keeping each final-request finding attributable to a concrete field.
    """
    findings: list[dict[str, Any]] = []
    for path, text in _iter_text_values(payload):
        for name, pattern in PATTERNS.items():
            for match in pattern.finditer(text):
                value = match.group(0)
                if _is_allowed_token(value):
                    continue
                findings.append({"type": name, "value": value[:160], "position": match.start(), "path": path})
                if len(findings) >= 100:
                    break
            if len(findings) >= 100:
                break
        if len(findings) >= 100:
            break
    blocked = redaction_level == "strict" and bool(findings)
    warn = redaction_level == "balanced" and bool(findings)
    return {"status": "blocked" if blocked else "warning" if warn else "ok", "redaction_level": redaction_level, "blocked": blocked, "warnings": warn, "leaks_found": len(findings), "items": findings}


def load_and_check(path: Path, *, redaction_level: str = "strict") -> dict[str, Any]:
    raw = path.read_text(encoding="utf-8")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        data = raw
    return check_redaction_leaks(data, redaction_level=redaction_level)


def _is_allowed_token(value: str) -> bool:
    lower = value.lower()
    if re.fullmatch(r"\d{2}:\d{2}:\d{2}", value):
        return True
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}t\d{2}:\d{2}:\d{2}z?", lower):
        return True
    return any(lower.startswith(prefix) for prefix in ALLOWLIST_PREFIXES)

"""Shared fail-closed Stage 8 process identity bounds.

All text limits are UTF-8 byte limits so archive normalization, semantic
assembly, persistence code, and PostgreSQL constraints enforce one contract.
"""
from __future__ import annotations

from typing import Any, Mapping

WINDOWS_PID_MIN = 1
WINDOWS_PID_MAX = 4_294_967_295
PROCESS_TEXT_BYTE_LIMITS: Mapping[str, int] = {
    "process_name": 512,
    "process_command_line": 4096,
    "process_user_sid": 512,
    "process_user_name": 512,
    "process_user_domain": 512,
    "process_logon_id": 128,
}


def bounded_process_text(value: Any, field: str) -> str | None:
    """Return stripped text only when it satisfies the named UTF-8 bound."""
    if field not in PROCESS_TEXT_BYTE_LIMITS:
        raise KeyError(f"unknown process bounded field: {field}")
    text = str(value or "").strip()
    if not text or len(text.encode("utf-8")) > PROCESS_TEXT_BYTE_LIMITS[field]:
        return None
    return text


def bounded_process_text_state(value: Any, field: str) -> str:
    text = str(value or "").strip()
    if not text or text == "-":
        return "unknown_missing"
    return "exact" if bounded_process_text(text, field) is not None else "unknown_over_limit"


def windows_process_id(value: Any) -> str | None:
    """Canonicalize a decimal/0x Windows PID inside the unsigned 32-bit range."""
    raw = str(value or "").strip()
    if not raw or raw == "-" or len(raw.encode("utf-8")) > 128:
        return None
    try:
        parsed = int(raw, 16 if raw.casefold().startswith("0x") else 10)
    except (TypeError, ValueError):
        return None
    if not WINDOWS_PID_MIN <= parsed <= WINDOWS_PID_MAX:
        return None
    return str(parsed)


def process_episode_fields_valid(facts: Mapping[str, Any]) -> bool:
    for field in PROCESS_TEXT_BYTE_LIMITS:
        value = facts.get(field)
        if value is not None and bounded_process_text(value, field) is None:
            return False
    for field in ("process_id", "process_parent_id", "native_process_id"):
        value = facts.get(field)
        if value is not None and windows_process_id(value) is None:
            return False
    return True

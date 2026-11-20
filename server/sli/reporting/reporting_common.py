from __future__ import annotations

"""Common helpers and utilities for SLI reporting modules.

Consolidates shared parsing, normalization, CSV formatting, and database
connection boilerplate across reporting endpoints while preserving backwards
compatibility.
"""

import html
import json
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import Any

from server.sli.core.time_format import parse_event_time


def parse_utc(value: Any) -> datetime | None:
    """Parse a datetime or string value and return an aware UTC datetime."""
    if isinstance(value, datetime):
        parsed = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    return parse_event_time(value)


def format_iso(value: Any) -> str:
    """Format a timestamp into standard ISO 8601 UTC representation (ending with 'Z')."""
    parsed = parse_utc(value)
    if parsed is not None:
        return parsed.isoformat().replace("+00:00", "Z")
    return "" if value is None else str(value)


def clean_text(value: Any) -> str | None:
    """Strip whitespace and return None for empty or None values."""
    return str(value).strip() or None if value is not None else None


def clean_sid(value: Any) -> str | None:
    """Clean a SID string, treating '-' and whitespace as None."""
    candidate = clean_text(value)
    return None if candidate == "-" else candidate


def sanitize_public(value: Any) -> Any:
    """Normalize raw bytes (e.g. hashes/GUIDs) to hex strings for JSON/public payloads."""
    return value.hex() if isinstance(value, bytes) else value


def build_domain_resource_groups(domain_id: int) -> list[list[dict[str, Any]]]:
    """Build the standard domain-scoped access control resource group specification."""
    return [[{"kind": "domain", "id": int(domain_id)}]]


def format_csv_cell(value: Any) -> str:
    """Format and escape a CSV cell to protect against spreadsheet formula injection."""
    if value is None:
        return ""
    if isinstance(value, (Mapping, list, tuple)):
        clean = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    else:
        clean = str(value)
    return "'" + clean if clean.lstrip().startswith(("=", "+", "-", "@")) else clean


def format_spreadsheet_cell(value: Any) -> str:
    """Format a cell for Russian Excel CSV export, escaping leading formula triggers."""
    text = str(value or "")
    candidate = text.lstrip(" \t\r\n")
    if text.startswith(("\t", "\r", "\n")) or candidate.startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def clean_int_list(values: list[int | str]) -> list[int]:
    """Parse and sanitize a list of comma- or semicolon-delimited integer strings."""
    output: list[int] = []
    for raw in values:
        for part in str(raw or "").replace(";", ",").split(","):
            part = part.strip()
            if not part:
                continue
            try:
                output.append(int(part))
            except ValueError:
                continue
    return output


def get_runtime_connection():
    """Obtain a runtime database connection from the canonical PostgreSQL pipeline."""
    from server.sli.core.postgres_runtime_pipeline import connect

    return connect()


def format_html_escape(value: Any) -> str:
    """Escape text for HTML presentation, substituting empty values with an em-dash."""
    return html.escape("—" if value is None or value == "" else str(value))


def format_html_pill(name: str, value: Any, cls: str = "") -> str:
    """Render a standard status pill badge span element."""
    class_attr = f"pill {cls}".strip()
    return f'<span class="{format_html_escape(class_attr)}"><strong>{format_html_escape(name)}:</strong> {format_html_escape(value)}</span>'

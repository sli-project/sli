"""Validated service-account hygiene exceptions; attribution is server-owned."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any

SETTING_KEY = "ad.service_account_exceptions"
ERROR = "ad_service_account_exceptions_invalid"
_SID = re.compile(r"S-1-5-21-\d+-\d+-\d+-\d+", re.IGNORECASE)


def entries(value: str) -> list[dict[str, Any]]:
    try:
        raw = json.loads(value)
        if not isinstance(raw, list) or len(raw) > 1000:
            raise ValueError(ERROR)
        result = {}
        for item in raw:
            entry = {"sid": item} if isinstance(item, str) else item
            if not isinstance(entry, dict) or set(entry) - {"sid", "excluded_by", "excluded_at"}:
                raise ValueError(ERROR)
            sid = entry.get("sid")
            if not isinstance(sid, str) or not _SID.fullmatch(sid.strip()):
                raise ValueError(ERROR)
            sid = sid.strip().upper()
            if sid in result:
                raise ValueError(ERROR)
            result[sid] = {**entry, "sid": sid}
        return [result[sid] for sid in sorted(result)]
    except (ValueError, TypeError) as exc:
        raise ValueError(ERROR) from exc


def setting_value(value: str) -> str:
    return json.dumps(entries(value), ensure_ascii=False, separators=(",", ":"))


def attributed(value: str, previous: str, *, actor: str) -> str:
    """Retained SIDs keep their original attribution; clients cannot forge it."""
    existing = {entry["sid"]: entry for entry in entries(previous)}
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    result = []
    for entry in entries(value):
        prior = existing.get(entry["sid"]) or {}
        result.append({"sid": entry["sid"],
                       "excluded_by": prior.get("excluded_by") or actor,
                       "excluded_at": prior.get("excluded_at") or now})
    return json.dumps(result, ensure_ascii=False, separators=(",", ":"))


def configured() -> dict[str, dict[str, Any]]:
    from server.sli.core.platform_settings import get_setting

    return {entry["sid"]: entry for entry in entries(get_setting(SETTING_KEY))}

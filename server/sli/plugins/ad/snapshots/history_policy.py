"""Validated policy for compact AD/GPO snapshot changes."""
from __future__ import annotations

SETTING_KEY = "ad.snapshot_history_days"
DEFAULT_DAYS = "365"
ENVIRONMENT = "SLI_AD_SNAPSHOT_HISTORY_DAYS"


def history_days(value: str) -> str:
    text = str(value).strip()
    if not text.isascii() or not text.isdecimal() or not 7 <= int(text) <= 3650:
        raise ValueError("ad_snapshot_history_days_must_be_7_to_3650")
    return str(int(text))

"""Workstation-specific retention policy in the core settings mechanism."""

SETTING_KEY = "workstations.evidence_retention_days"
DEFAULT_DAYS = "90"


def retention_days(value: str) -> str:
    text = str(value).strip()
    if not text.isascii() or not text.isdigit() or not 1 <= int(text) <= 3650:
        raise ValueError("workstation_retention_days_invalid")
    return str(int(text))

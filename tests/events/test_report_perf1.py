from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest


def _row(row_id: int, record_id: int, ts: str) -> dict:
    return {
        "id": row_id,
        "server": "DC1",
        "channel": "Security",
        "provider_name": "Microsoft-Windows-Security-Auditing",
        "event_id": 4624,
        "event_record_id": record_id,
        "time_created_utc": ts,
        "time_created_local": ts,
        "subject_user_name": "alice",
        "subject_domain_name": "EXAMPLE",
        "target_user_name": "alice",
        "target_domain_name": "EXAMPLE",
        "ip_address": "",
        "workstation_name": "WS01",
        "logon_id": "0x1",
        "message_text": "sample",
        "event_data_json": "{}",
    }


def test_schema_declares_reverse_event_link_index() -> None:
    assert "idx_event_links_target on event_links(target_event_id)" in Path("config/postgres_schema.sql").read_text(encoding="utf-8")

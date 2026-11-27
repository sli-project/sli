from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest



def test_migration_126_registers_exact_catalog_access_and_revokes_public() -> None:
    forward = Path("config/postgres_migrations/126_what_where_when_report.sql").read_text(encoding="utf-8")
    rollback = Path("config/postgres_migrations/126_what_where_when_report.rollback.sql").read_text(encoding="utf-8")
    folded = forward.casefold()
    assert "ad.authentication.computer-logons" in forward
    assert "ad.computer-logons" in forward
    assert "'что где когда'" in forward
    assert "'/what-where-when-report'" in forward
    assert "field.computer_logon_observation" in forward
    assert "computer_logon_observation" in forward
    assert "security_analyst" in forward and "project_operations" in forward
    assert "revoke all on what_where_when_observations from public" in folded
    assert "revoke all on what_where_when_projection_state from public" in folded
    assert "delete from access_report_assignments where report_key='ad.computer-logons'" in rollback
    assert "delete from report_registry_v4 where report_key='ad.computer-logons'" in rollback


def _inventory() -> dict:
    return {
        "state": "available",
        "partial": False,
        "items": [
            {"entity_id": 2, "object_guid": "22222222-2222-4222-8222-222222222222", "display_name": "WS-B", "dns_host_name": "ws-b.example.test"},
            {"entity_id": 1, "object_guid": "11111111-1111-4111-8111-111111111111", "display_name": "WS-A", "dns_host_name": "ws-a.example.test"},
        ],
    }

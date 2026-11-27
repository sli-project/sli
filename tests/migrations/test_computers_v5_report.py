from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[2]
OBSERVED = datetime(2026, 8, 29, 0, 0, tzinfo=timezone.utc)


def _rows(sql: str, *_args, **_kwargs):
    if "computers_v5_coverage" in sql:
        return [{
            "domain_id": 1,
            "domain_name": "example.test",
            "run_status": "completed",
            "section_status": "complete",
            "record_count": 3,
            "observed_at_utc": OBSERVED,
            "run_id": "00000000-0000-0000-0000-000000000029",
        }]
    if "computers_v5_semantic" in sql:
        return [{
            "finding_id": 77,
            "entity_id": 10,
            "display_name": "WS-INACTIVE",
            "title": "Подозрительная последовательность входов",
            "status": "open",
            "summary": "Наблюдалась опубликованная цепочка событий.",
            "why_it_matters": "Требует проверки контекста администратором.",
            "recommended_action": "Открыть доказательства и проверить события.",
            "last_seen_utc": OBSERVED,
        }]
    if "computers_v5_snapshot" in sql:
        return []
    return [
        {
            "entity_id": 10,
            "domain_id": 1,
            "display_name": "WS-INACTIVE",
            "natural_key": "WS-INACTIVE$",
            "observed_at_utc": OBSERVED,
            "attributes": {
                "object_class": "computer",
                "enabled": True,
                "last_logon_utc": "2026-05-01T00:00:00Z",
                "operating_system": "Windows 11 Pro",
                "operating_system_version": "10.0 (26100)",
                "ip_addresses": ["10.42.8.15"],
                "distinguished_name": "CN=WS-INACTIVE,OU=Workstations,DC=example,DC=test",
                "attribute_states": {
                    "enabled": {"state": "present", "source_attribute": "Enabled"},
                    "last_logon_utc": {"state": "present", "source_attribute": "LastLogonDate"},
                    "operating_system": {"state": "present", "source_attribute": "OperatingSystem"},
                },
            },
        },
        {
            "entity_id": 11,
            "domain_id": 1,
            "display_name": "WS-DISABLED-NO-ACTIVITY",
            "natural_key": "WS-DISABLED-NO-ACTIVITY$",
            "observed_at_utc": OBSERVED,
            "attributes": {
                "object_class": "computer",
                "enabled": False,
                "operating_system": "Windows 10 Pro",
                "operating_system_version": "10.0 (19045)",
                "distinguished_name": "CN=WS-DISABLED-NO-ACTIVITY,OU=Disabled,DC=example,DC=test",
                "attribute_states": {
                    "enabled": {"state": "present", "source_attribute": "Enabled"},
                    "last_logon_utc": {"state": "absent_in_source", "source_attribute": "LastLogonDate"},
                    "operating_system": {"state": "present", "source_attribute": "OperatingSystem"},
                },
            },
        },
        {
            "entity_id": 12,
            "domain_id": 1,
            "display_name": "UNKNOWN-AD-STATE",
            "natural_key": "UNKNOWN-AD-STATE$",
            "observed_at_utc": OBSERVED,
            "attributes": {
                "object_class": "computer",
                "distinguished_name": "CN=UNKNOWN-AD-STATE,CN=Computers,DC=example,DC=test",
                "attribute_states": {
                    "enabled": {"state": "absent_in_source", "source_attribute": "Enabled"},
                    "operating_system": {"state": "absent_in_source", "source_attribute": "OperatingSystem"},
                },
            },
        },
    ]


def test_migration_108_registers_v5_and_retires_v2_v4_without_touching_v1() -> None:
    migration = (ROOT / "config/postgres_migrations/108_computers_report_v5.sql").read_text(encoding="utf-8")
    normalized = "".join(migration.split()).casefold()

    assert "'ad.assets.computers.v5',1" in normalized
    assert "'ad.computers.v5',1,'компьютерыv5'" in normalized
    assert "'target_path','/computers-v5-report'" in normalized
    assert "report_keyin('ad.computers.v2','ad.computers.v4')" in normalized
    assert "status='retired'" in normalized
    assert "deletefromaccess_package_reportswherereport_keyin('ad.computers.v2','ad.computers.v4')" in normalized
    assert "report_key='ad.computers'" not in normalized
    assert "version=106" not in normalized and "version=107" not in normalized
    assert "insertintoschema_migrations(version,name)values(108,'computers_report_v5')" in normalized

    rollback = (ROOT / "config/postgres_migrations/108_computers_report_v5.rollback.sql").read_text(encoding="utf-8").casefold()
    assert "report_key='ad.computers.v5'" in rollback
    assert "version=108" in rollback

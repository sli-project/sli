from __future__ import annotations

import io
from http import HTTPStatus
from types import SimpleNamespace

import pytest



def _events_access(*, capabilities: list[str] | None = None, actions: list[str] | None = None) -> dict[str, object]:
    allowed_actions = actions or ["view"]
    return {
        "capabilities": capabilities or [],
        "reports": [{
            "report_key": "events.test", "version": 1, "allowed": True,
            "allowed_actions": allowed_actions,
            "grants": [{
                "scope": {"kind": "channel", "values": ["Security"]},
                "field_categories": ["security", "technical", "raw_evidence"],
                "allowed_actions": allowed_actions,
            }],
        }],
    }


def _privileged_access(field_categories: list[str]) -> dict[str, object]:
    return {
        "capabilities": [],
        "reports": [{
            "report_key": "events.test", "version": 1, "allowed": True,
            "allowed_actions": ["view"],
            "grants": [{
                "scope": {"kind": "domain", "ids": [7]},
                "field_categories": field_categories,
                "allowed_actions": ["view"],
            }],
        }],
    }


def _security_queue_access() -> dict[str, object]:
    return {
        "capabilities": [],
        "reports": [{
            "report_key": "events.test",
            "version": 1,
            "allowed": True,
            "allowed_actions": ["view"],
            "grants": [{
                "scope": {"kind": "all"},
                "field_categories": ["security"],
                "allowed_actions": ["view"],
            }],
        }],
    }


def test_privileged_state_migration_updates_both_column_authorities() -> None:
    from pathlib import Path
    forward = Path(
        "config/postgres_migrations/056_privileged_account_state_fields.sql"
    ).read_text(encoding="utf-8")
    rollback = Path(
        "config/postgres_migrations/056_privileged_account_state_fields.rollback.sql"
    ).read_text(encoding="utf-8")
    for key in (
        "enabled", "is_inactive", "password_never_expires", "locked_out",
        "last_logon_utc",
    ):
        assert key in forward
        assert key in rollback
    assert "update report_datasets_v4" in forward
    assert "update report_registry_v4" in forward
    assert "version=55" in forward
    assert "delete from schema_migrations" in rollback

"""Migration 149 and the finding <-> investigation link (fakes, no database)."""

from __future__ import annotations

import re
from http import HTTPStatus
from pathlib import Path
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parents[2]
FORWARD = ROOT / "config/postgres_migrations/149_investigation_finding_links.sql"
ROLLBACK = ROOT / "config/postgres_migrations/149_investigation_finding_links.rollback.sql"


def _statements(path: Path) -> str:
    return " ".join(line for line in path.read_text(encoding="utf-8").splitlines() if not line.lstrip().startswith("--"))


def test_migration_text_contract() -> None:
    sql = _statements(FORWARD)
    assert "requires exact migration 148 vpn_session_reader_domains_grant" in sql
    assert "pg_advisory_xact_lock" in sql
    assert "investigation_id bigint not null references public.investigations(id) on delete restrict" in sql
    assert "finding_id bigint not null references public.findings(id) on delete restrict" in sql
    assert "primary key (investigation_id, finding_id)" in sql
    assert "unique (finding_id)" in sql
    assert re.findall(r"grant\s+[^;]+;", sql) == [
        "grant select, insert on public.investigation_finding_links to adlog_user;"
    ]
    assert "values (149, 'investigation_finding_links')" in sql


def test_rollback_only_when_latest() -> None:
    sql = _statements(ROLLBACK)
    assert "version > 149" in sql
    assert "drop table if exists public.investigation_finding_links;" in sql
    assert "delete from schema_migrations where version = 149;" in sql


# --- HTTP handlers --------------------------------------------------------


class Handler:
    def __init__(self, body: dict[str, Any], *, capabilities: tuple[str, ...] = ("investigations.manage",)) -> None:
        self.body = body
        self.sent: list[tuple[dict[str, Any], HTTPStatus]] = []
        self._principal = {"username": "analyst"}
        self.storage_route_authorization = None
        self._capabilities = list(capabilities)

    def _access_decision(self) -> dict[str, Any]:
        return {
            "capabilities": self._capabilities,
            "reports": [{"report_key": "investigations.workspace", "allowed": True, "allowed_actions": ["start_case", "view"]}],
        }

    def _read_json_body(self) -> dict[str, Any]:
        return self.body

    def _send_json(self, payload: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        self.sent.append((payload, status))


def _case(case_id: int = 10) -> dict[str, Any]:
    return {
        "id": case_id, "public_id": None, "title": "Проблема #7", "status": "new", "owner": "analyst",
        "created_by": "analyst", "created_at": "2026-10-02T10:00:00Z", "updated_at": "2026-10-02T10:00:00Z",
        "events": [], "evidence_refs": [], "evidence_refs_state": "available", "notes": [], "audit": [],
    }

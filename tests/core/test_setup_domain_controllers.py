"""«Первичная настройка»: domain controller targets in the database."""

from __future__ import annotations

import importlib.util
import json
from http import HTTPStatus
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]


class _Cursor:
    """Records SQL; answers selects from in-memory domains and targets."""

    def __init__(self, store: dict) -> None:
        self.store = store
        self._rows: list[dict] = []

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def execute(self, sql, params=()):
        text = " ".join(sql.split())
        self.store["log"].append((text, params))
        self._rows = []
        if text.startswith("select id from domains where lower(fqdn)"):
            domain_id = self.store["domains"].get(params[0])
            self._rows = [{"id": domain_id}] if domain_id else []
        elif text.startswith("select id, lower(fqdn) as fqdn from domains"):
            self._rows = [{"id": i, "fqdn": f} for f, i in self.store["domains"].items()]
        elif text.startswith("select lower(hostname) as key from domain_controller_targets"):
            self._rows = [{"key": key} for key in self.store["targets"]]
        elif text.startswith("select hostname, enabled from domain_controller_targets"):
            row = self.store["targets"].get(params[0])
            self._rows = [{"hostname": row["hostname"], "enabled": row["enabled"]}] if row else []
        elif text.startswith("insert into domain_controller_targets"):
            hostname, address, domain_id, *rest = params
            ip = rest[0] if len(rest) == 3 else None
            self.store["targets"][hostname.lower()] = {
                "hostname": hostname, "connect_address": address, "domain_id": domain_id,
                "owner_confirmed_ip": ip, "enabled": True, "sql": text,
            }
        elif text.startswith("update domain_controller_targets"):
            self.store["targets"][params[2]]["enabled"] = params[0]

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return self._rows


class _Connection:
    def __init__(self, store: dict) -> None:
        self.store = store

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def cursor(self):
        return _Cursor(self.store)

    def commit(self):
        self.store["log"].append(("commit", ()))


@pytest.fixture
def store(monkeypatch: pytest.MonkeyPatch) -> dict:
    data = {"domains": {"corp.example.test": 7, "example.test": 3}, "targets": {}, "log": []}
    monkeypatch.setattr("server.sli.core.postgres_runtime_pipeline.connect", lambda: _Connection(data))
    return data


FILE_TARGETS = [
    {"hostname": "DC1", "connect_address": "dc1.corp.example.test", "owner_confirmed_ip": "198.51.100.23"},
    {"hostname": "DC2", "connect_address": "dc2.other.test"},
]




class _Handler:
    client_address = ("127.0.0.1", 0)
    _principal = {"id": 1, "username": "admin", "type": "session"}

    def __init__(self, *, allowed=True, capable=True, body=None) -> None:
        self.allowed, self.capable, self.body, self.sent, self.calls = allowed, capable, body or {}, [], []

    def _authorize_mutation(self, *, required_role):
        self.calls.append(("role", required_role))
        return self.allowed

    def _require_capability(self, capability):
        self.calls.append(("capability", capability))
        return self.capable

    def _read_json_body(self):
        return self.body

    def _send_json(self, payload, status=HTTPStatus.OK):
        self.sent.append((payload, status))


def test_migration_147_is_additive_reads_no_files_and_has_a_rollback() -> None:
    sql = (ROOT / "config/postgres_migrations/147_domain_controller_targets.sql").read_text(encoding="utf-8")
    code = " ".join(line for line in sql.splitlines() if not line.lstrip().startswith("--"))
    assert "requires exact migration 146 platform_settings" in code
    assert "references public.domains(id) on delete restrict" in code
    assert "grant select, insert, update on public.domain_controller_targets to adlog_user;" in code
    assert "values (147, 'domain_controller_targets')" in code
    assert "pg_read_file" not in code and "copy " not in code.lower()
    rollback = (ROOT / "config/postgres_migrations/147_domain_controller_targets.rollback.sql").read_text(encoding="utf-8")
    assert "drop table if exists public.domain_controller_targets;" in rollback
    assert "delete from schema_migrations where version = 147;" in rollback

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]




class _MigrationCursor:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, sql, _params=None):
        self.events.append("ddl" if "create table" in str(sql).casefold() else "query")


class _MigrationConnection:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    def __enter__(self):
        self.events.append("transaction_enter")
        return self

    def __exit__(self, exc_type, *_args):
        self.events.append("rollback" if exc_type else "commit")
        return False

    def cursor(self):
        return _MigrationCursor(self.events)


def test_migration_121_sql_leaves_transaction_ownership_to_controller() -> None:
    for name in ("121_ad_snapshot_manifest_foundation.sql", "121_ad_snapshot_manifest_foundation.rollback.sql"):
        statements = (ROOT / "config/postgres_migrations" / name).read_text(encoding="utf-8").casefold().splitlines()
        assert not any(line.strip() in {"begin;", "commit;"} for line in statements)

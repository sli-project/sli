from __future__ import annotations

from server.sli.storage import storage_v2_worker_connection as module


class Cursor:
    def __init__(self, calls: list[object]) -> None:
        self.calls = calls

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, sql: str) -> None:
        self.calls.append(sql)

    def fetchone(self):
        return {"role": "adlog_storage_worker"}


class Connection:
    def __init__(self, calls: list[object]) -> None:
        self.calls = calls

    def cursor(self):
        return Cursor(self.calls)

    def commit(self) -> None:
        self.calls.append("commit")


def test_worker_connection_activates_and_verifies_least_privilege_role(monkeypatch) -> None:
    calls: list[object] = []
    conn = Connection(calls)
    monkeypatch.setenv("ADLOG_STORAGE_V2_WORKER_DSN", "postgresql://worker.invalid/db")
    monkeypatch.setattr(module.psycopg, "connect", lambda *args, **kwargs: conn)

    result = module.connect_storage_v2_worker()

    assert result is conn
    assert calls == [
        "set role adlog_storage_worker",
        "select current_user as role",
        "commit",
    ]

from __future__ import annotations

from server.sli.ops.postgres_session_lock import session_advisory_lock


class _Cursor:
    def __init__(self, conn: "_Connection") -> None:
        self.conn = conn
        self.last_sql = ""

    def __enter__(self) -> "_Cursor":
        return self

    def __exit__(self, *_args) -> None:
        return None

    def execute(self, sql: str, params: tuple[str]) -> None:
        assert self.conn.autocommit is True
        self.last_sql = sql
        self.conn.queries.append((sql, params))

    def fetchone(self) -> dict[str, bool]:
        return {"acquired": True}


class _Connection:
    def __init__(self) -> None:
        self.autocommit = False
        self.commits = 0
        self.closed = False
        self.queries: list[tuple[str, tuple[str]]] = []

    def commit(self) -> None:
        self.commits += 1

    def cursor(self) -> _Cursor:
        return _Cursor(self)

    def close(self) -> None:
        self.closed = True


def test_session_advisory_lock_uses_dedicated_autocommit_connection() -> None:
    conn = _Connection()
    prepared: list[bool] = []

    with session_advisory_lock(
        lambda: conn,
        "worker-lock",
        prepare=lambda current: prepared.append(current.autocommit),
    ) as acquired:
        assert acquired is True
        assert conn.commits == 1
        assert conn.closed is False

    assert prepared == [True]
    assert conn.closed is True
    assert "pg_try_advisory_lock" in conn.queries[0][0]
    assert "pg_advisory_unlock" in conn.queries[-1][0]

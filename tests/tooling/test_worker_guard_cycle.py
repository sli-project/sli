"""Guard-cycle batching: one process inventory scan and one DB connection
for the whole cycle, regardless of how many workers are being checked - not
one PowerShell subprocess and one DB connection per worker.
"""
from __future__ import annotations


class _FakeCursor:
    def __init__(self, heartbeat_rows):
        self.heartbeat_rows = heartbeat_rows
        self.execute_calls: list[str] = []
        self._last_query = ""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, query, params=None):
        self.execute_calls.append(query)
        self._last_query = query

    def fetchone(self):
        if "runtime_collection_blocks" in self._last_query:
            return None
        return None

    def fetchall(self):
        if "runtime_worker_heartbeats" in self._last_query:
            return self.heartbeat_rows
        return []


class _FakeConnection:
    def __init__(self, cursor):
        self._cursor = cursor

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def cursor(self):
        return self._cursor


def test_one_process_inventory_and_one_db_connection_regardless_of_worker_count(
    monkeypatch,
) -> None:
    from scripts.maintenance import worker_guard

    synthetic_names = {f"synthetic_worker_{i}": f"synthetic_worker_{i}.py" for i in range(12)}
    monkeypatch.setattr(worker_guard, "WORKER_SCRIPTS", synthetic_names)
    monkeypatch.setattr(worker_guard, "PLUGIN_WORKERS", {})
    monkeypatch.setattr(
        worker_guard, "load_config",
        lambda: type("Cfg", (), {"postgres_dsn": "postgresql://example"})(),
    )

    inventory_calls = {"count": 0}

    def fake_inventory():
        inventory_calls["count"] += 1
        return [], None

    connect_calls = {"count": 0}
    cursor = _FakeCursor(heartbeat_rows=[])

    def fake_connect(dsn):
        connect_calls["count"] += 1
        return _FakeConnection(cursor)

    results = worker_guard.evaluate_cycle(
        list(synthetic_names),
        process_inventory=fake_inventory,
        connect=fake_connect,
    )

    assert inventory_calls["count"] == 1
    assert connect_calls["count"] == 1
    # Exactly one execute for the statement_timeout/read-only setup pair plus
    # one batched heartbeat select - not one query per worker.
    heartbeat_selects = [q for q in cursor.execute_calls if "runtime_worker_heartbeats" in q]
    assert len(heartbeat_selects) == 1
    assert len(results) == len(synthetic_names)


def test_cycle_result_covers_every_requested_worker() -> None:
    from scripts.maintenance import worker_guard

    def fake_inventory():
        return [], None

    cursor = _FakeCursor(heartbeat_rows=[])

    def fake_connect(dsn):
        return _FakeConnection(cursor)

    results = worker_guard.evaluate_cycle(
        ["collection", "entity_state"],
        process_inventory=fake_inventory,
        connect=fake_connect,
    )

    assert set(results) == {"collection", "entity_state"}
    for payload in results.values():
        assert "decision" in payload
        assert "code" in payload
        assert "os_pids_running_script" in payload

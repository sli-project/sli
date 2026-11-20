from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from server.sli.core import database
from server.sli.core import postgres_runtime_pipeline as pg
from server.sli.reporting import read_timeout as timeout


@pytest.mark.parametrize("value,expected", [("12000", 12000), ("invalid", 8000), ("0", 8000), ("-1", 8000)])
def test_configurable_budget_with_sane_default(monkeypatch, value, expected):
    monkeypatch.setenv("ADLOG_REPORT_READ_TIMEOUT_MS", value)
    assert timeout.read_timeout_ms() == expected


def test_nested_readers_share_deadline_and_timeout_before_next_query(monkeypatch):
    tick = [100.0]
    monkeypatch.setattr(timeout, "monotonic", lambda: tick[0])
    monkeypatch.setenv("ADLOG_REPORT_READ_TIMEOUT_MS", "8000")
    bounded = Mock(return_value=[{"count": 1}])
    monkeypatch.setattr(database, "query_rows_bounded", bounded)
    with timeout.report_read_budget():
        tick[0] += 3
        with timeout.report_read_budget():
            assert database.query_rows("select 1") == [{"count": 1}]
            assert bounded.call_args.kwargs["statement_timeout_ms"] == 5000
        tick[0] += 6
        with pytest.raises(database.QueryTimeoutError):
            database.query_rows("select 1")
    assert timeout.remaining_read_ms() is None
    bounded.assert_called_once()


def test_connection_policy_uses_shared_budget_without_changing_worker_policy(monkeypatch):
    monkeypatch.setattr(pg, "load_config", lambda: SimpleNamespace(
        postgres_statement_timeout_ms=900000, postgres_connect_timeout_seconds=15, postgres_lock_timeout_ms=1000))
    monkeypatch.setenv("ADLOG_REPORT_READ_TIMEOUT_MS", "8000")
    assert pg.connection_policy()["statement_timeout_ms"] == 900000
    with timeout.report_read_budget():
        policy = pg.connection_policy()
        assert 0 < policy["statement_timeout_ms"] <= 8000
        assert policy["connect_timeout_seconds"] <= 8
    assert pg.connection_policy()["statement_timeout_ms"] == 900000


def test_direct_cursor_connections_are_cancelled_and_watchdogs_cleaned_up(monkeypatch):
    timers = []

    def timer(seconds, callback):
        instance = Mock(callback=callback, seconds=seconds)
        timers.append(instance)
        return instance

    monkeypatch.setattr(timeout, "Timer", timer)
    connection = Mock()
    with timeout.report_read_budget():
        timeout.watch_read_connection(connection)
        assert 0 < timers[0].seconds <= 8
        timers[0].start.assert_called_once()
        timers[0].callback()
        connection.cancel.assert_called_once()
    timers[0].cancel.assert_called_once()


def test_bounded_reader_caps_explicit_long_timeout_with_fake_connection(monkeypatch):
    cursor = Mock()
    cursor.__enter__ = Mock(return_value=cursor)
    cursor.__exit__ = Mock(return_value=False)
    cursor.fetchall.return_value = []
    connection = Mock()
    connection.__enter__ = Mock(return_value=connection)
    connection.__exit__ = Mock(return_value=False)
    connection.cursor.return_value = cursor
    monkeypatch.setattr(pg, "connect", lambda: connection)
    monkeypatch.setattr(database, "_require_runtime_db", lambda: None)
    monkeypatch.setenv("ADLOG_REPORT_READ_TIMEOUT_MS", "1000")
    timer = Mock()
    monkeypatch.setattr(database.threading, "Timer", Mock(return_value=timer))
    with timeout.report_read_budget():
        database.query_rows_bounded("select 1", statement_timeout_ms=50000)
    statement = cursor.execute.call_args_list[0].args[0]
    assert 0 < int(statement.rsplit("=", 1)[-1]) <= 1000
    assert database.threading.Timer.call_args.args[0] <= 1
    timer.cancel.assert_called_once()


@pytest.mark.parametrize("path", [
    "/api/v1/reports/synthetic.report/data",
    "/api/v2/reports/synthetic.report/data",
    "/reports/synthetic-report",
    "/api/v1/home/summary",
])
def test_http_report_timeout_is_structured_and_clears_context(path):
    from server.api.http_server import RequestHandler

    handler = object.__new__(RequestHandler)
    handler.path = path
    handler._admit_request = lambda: True
    handler._send_json = Mock()
    handler.server = SimpleNamespace(request_slots=SimpleNamespace(release=Mock()))

    def read():
        assert timeout.remaining_read_ms() is not None
        raise database.QueryTimeoutError("Synthetic timeout", timeout_ms=8000)

    handler._do_GET = read
    handler.do_GET()
    handler._send_json.assert_called_once_with({"error": "report_read_timeout", "state": "unavailable"}, 503)
    assert timeout.remaining_read_ms() is None
    handler.server.request_slots.release.assert_called_once()


def test_runtime_connection_registers_watchdog_and_closes_on_expired_budget(monkeypatch):
    import psycopg

    connection = Mock()
    monkeypatch.setattr(psycopg, "connect", Mock(return_value=connection))
    monkeypatch.setattr(pg, "_dsn", lambda: "synthetic-dsn")
    monkeypatch.setattr(pg, "connection_policy", lambda: {
        "connect_timeout_seconds": 1, "statement_timeout_ms": 1000, "lock_timeout_ms": 100,
        "application_name": "synthetic-read",
    })
    watch = Mock(side_effect=database.QueryTimeoutError("Synthetic timeout", timeout_ms=1000))
    monkeypatch.setattr(timeout, "watch_read_connection", watch)
    with pytest.raises(database.QueryTimeoutError):
        pg.connect()
    watch.assert_called_once_with(connection)
    connection.close.assert_called_once()

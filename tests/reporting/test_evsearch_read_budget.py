from unittest.mock import Mock

import pytest

from server.sli.core.database import QueryTimeoutError
from server.sli.reporting import read_timeout as budget


@pytest.mark.parametrize('configured,cap,expected', [('20000', 8000, 8000), ('1000', 8000, 1000)])
def test_cap_never_expands_configured_budget(monkeypatch, configured, cap, expected):
    monkeypatch.setenv('ADLOG_REPORT_READ_TIMEOUT_MS', configured)
    monkeypatch.setattr(budget, 'monotonic', lambda: 100.0)
    with budget.report_read_budget(timeout_ms=cap):
        assert budget.remaining_read_ms() == expected
    assert budget.remaining_read_ms() is None


def test_nested_caps_preserve_outer_deadline_and_exception_cleanup(monkeypatch):
    tick = [100.0]
    monkeypatch.setenv('ADLOG_REPORT_READ_TIMEOUT_MS', '20000')
    monkeypatch.setattr(budget, 'monotonic', lambda: tick[0])
    with budget.report_read_budget(timeout_ms=8000):
        tick[0] += 3
        with budget.report_read_budget(timeout_ms=18000):
            assert budget.remaining_read_ms() == 5000
        with pytest.raises(QueryTimeoutError):
            with budget.report_read_budget(timeout_ms=1000):
                tick[0] += 2
                budget.remaining_read_ms()
        assert budget.remaining_read_ms() == 3000
    assert budget.remaining_read_ms() is None


def test_capped_direct_connections_remain_cancellable(monkeypatch):
    timers = []
    def timer(seconds, callback):
        obj = Mock(seconds=seconds, callback=callback)
        timers.append(obj)
        return obj
    monkeypatch.setenv('ADLOG_REPORT_READ_TIMEOUT_MS', '20000')
    monkeypatch.setattr(budget, 'Timer', timer)
    connection = Mock()
    with budget.report_read_budget(timeout_ms=8000):
        budget.watch_read_connection(connection)
        assert 0 < timers[0].seconds <= 8
        timers[0].callback()
        connection.cancel.assert_called_once()
    timers[0].cancel.assert_called_once()


@pytest.mark.parametrize('cap', [0, -1, True, '8000'])
def test_invalid_caps_do_not_change_context(cap):
    with pytest.raises(ValueError):
        with budget.report_read_budget(timeout_ms=cap):
            pass
    assert budget.remaining_read_ms() is None

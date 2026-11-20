from unittest.mock import Mock

import pytest

from server.sli.core.database import QueryTimeoutError
from server.sli.reporting import read_timeout
from server.sli.storage import permanent_fact_history as history


def test_history_queries_share_report_budget(monkeypatch):
    tick = [100.0]
    monkeypatch.setattr(read_timeout, 'monotonic', lambda: tick[0])
    monkeypatch.setenv('ADLOG_REPORT_READ_TIMEOUT_MS', '1000')
    query = Mock(return_value=b'')
    monkeypatch.setattr(history, '_http_query', query)
    with read_timeout.report_read_budget():
        tick[0] += .25
        assert history._rows(8123, 'SELECT 1') == []
        assert 0 < query.call_args.kwargs['timeout'] <= .75
        assert 0 < float(query.call_args.kwargs['params']['max_execution_time']) <= .75
        tick[0] += 1
        with pytest.raises(QueryTimeoutError):
            history._rows(8123, 'SELECT 2')
    assert query.call_count == 1


def test_history_worker_retains_existing_timeout(monkeypatch):
    query = Mock(return_value=b'')
    monkeypatch.setattr(history, '_http_query', query)
    history._rows(8123, 'SELECT 1')
    assert query.call_args.kwargs['timeout'] == 65
    assert query.call_args.kwargs['params']['max_execution_time'] == '60'


def test_history_transport_timeout_keeps_typed_reason(monkeypatch):
    monkeypatch.setattr(history, '_history_auth', lambda: ('synthetic', 'synthetic'))
    monkeypatch.setattr(history, '_transport_query', Mock(side_effect=TimeoutError('private diagnostic')))
    with read_timeout.report_read_budget(), pytest.raises(QueryTimeoutError):
        history._rows(8123, 'SELECT 1')


def test_http_trickling_body_stops_at_shared_deadline():
    import socket
    from threading import Thread
    from time import monotonic, sleep
    from server.sli.storage.storage_lifecycle_io import _http_query

    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    def serve():
        with listener:
            client, _ = listener.accept()
            with client:
                client.recv(65536)
                client.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 30\r\n\r\n')
                for _ in range(30):
                    try:
                        client.sendall(b'x')
                    except OSError:
                        break
                    sleep(.03)
    thread = Thread(target=serve, daemon=True)
    thread.start()
    started = monotonic()
    try:
        with pytest.raises(TimeoutError):
            _http_query(listener.getsockname()[1], 'SELECT 1', host='127.0.0.1',
                        timeout=2, deadline=started + .15)
        assert monotonic() - started < .75
    finally:
        thread.join(2)


def test_expired_deadline_never_opens_http_connection(monkeypatch):
    from server.sli.storage import storage_lifecycle_io as transport
    connection = Mock()
    monkeypatch.setattr(transport.http.client, 'HTTPConnection', connection)
    monkeypatch.setattr(transport, 'monotonic', lambda: 100.0)
    with pytest.raises(TimeoutError):
        transport._http_query(8123, 'SELECT 1', host='127.0.0.1', deadline=99.0)
    connection.assert_not_called()


def test_address_attempts_do_not_restart_report_budget(monkeypatch):
    from server.sli.storage import storage_lifecycle_io as transport
    tick = [100.0]
    monkeypatch.setattr(transport, 'monotonic', lambda: tick[0])
    addresses = [(2, 1, 6, '', ('127.0.0.1', 8123))] * 2
    monkeypatch.setattr(transport.socket, 'getaddrinfo', lambda *args: addresses)
    first = Mock()
    def refused(*args):
        tick[0] = 102.0
        raise ConnectionRefusedError()
    first.connect.side_effect = refused
    factory = Mock(return_value=first)
    monkeypatch.setattr(transport.socket, 'socket', factory)
    with pytest.raises(TimeoutError):
        transport._connect_before_deadline(('127.0.0.1', 8123), 65, deadline=101.0)
    assert first.connect.call_count == 1
    assert first.settimeout.call_args.args[0] <= 1.0
    assert first.close.called

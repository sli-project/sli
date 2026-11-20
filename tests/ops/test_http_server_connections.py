from __future__ import annotations

import http.client
import json
import socket
import ssl
import sys
import threading
from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from server.api import http_server
from server.sli.core import app_config
from server.sli.core.app_config import AdLogConfig
from server.sli.ops.shutdown import http_shutdown


@pytest.mark.parametrize('dual_stack', [False, True])
def test_wildcard_listener_accepts_loopback_and_normalizes_proxy_peer(monkeypatch, dual_stack):
    if sys.platform == 'win32':
        pytest.skip('Wildcard listener test opens a firewall prompt on Windows; Linux CI covers it')
    if dual_stack and not socket.has_dualstack_ipv6():
        pytest.skip('Dual-stack IPv6 unavailable on this host')
    monkeypatch.setattr(socket, 'has_dualstack_ipv6', lambda: dual_stack)
    config = AdLogConfig(reports_dir='', log_dir='')
    server = http_server.ProtectedHTTPServer(('0.0.0.0', 0), http_server.RequestHandler, config=config)
    try:
        for host in (['127.0.0.1', '::1'] if dual_stack else ['127.0.0.1']):
            with socket.create_connection((host, server.server_port), timeout=2):
                request, peer = server.get_request()
                request.close()
                assert peer[0] == host
    finally:
        server.server_close()


@pytest.mark.parametrize("payload", [b"", b"GET / HTTP/1.0\r\nHost: incomplete", b"GET /"])
@pytest.mark.parametrize("tls", [False, True])
def test_sigterm_wakes_idle_and_partial_header_connections(server, payload, tls):
    import signal

    wrapped = []
    if tls:
        server.server.adlog_tls_context = _fake_tls_context(lambda _: None, wrapped)
    request, peer = socket.socketpair()
    with request, peer, http_shutdown(server.server):
        serving = threading.Thread(target=server.server.serve_forever, kwargs={"poll_interval": 0.01})
        serving.start()
        try:
            server.server.process_request(request, ("192.0.2.1", 1234))
            if payload:
                peer.sendall(payload)
            assert server.started.wait(2)
            signal.raise_signal(signal.SIGTERM)
            serving.join(timeout=2)
            assert not serving.is_alive()
            for worker in server.workers:
                worker.join(timeout=2)
                assert not worker.is_alive()
            assert not server.server.connections
            _assert_slot_available(server.server)
        finally:
            peer.close()
            server.server.shutdown()
            serving.join(timeout=2)


def test_sigterm_wakes_pending_tls_handshake(server):
    import signal

    entered = threading.Event()

    def handshake(request):
        entered.set()
        assert request.recv(1) == b""

    server.server.adlog_tls_context = _fake_tls_context(handshake, [])
    request, peer = socket.socketpair()
    with request, peer, http_shutdown(server.server):
        serving = threading.Thread(target=server.server.serve_forever, kwargs={"poll_interval": 0.01})
        serving.start()
        try:
            server.server.process_request(request, ("192.0.2.1", 1234))
            assert entered.wait(2)
            signal.raise_signal(signal.SIGTERM)
            serving.join(timeout=2)
            for worker in server.workers:
                worker.join(timeout=2)
                assert not worker.is_alive()
            assert not serving.is_alive()
            assert not server.server.connections
        finally:
            peer.close()
            server.server.shutdown()
            serving.join(timeout=2)


def test_update_http_shutdown_waits_for_accepted_import_to_commit(server, monkeypatch):
    import signal

    started, committed, release, closed = (threading.Event() for _ in range(4))

    def import_packet(handler):
        started.set()
        assert release.wait(2)
        committed.set()
        handler._send_json({"ok": True})

    monkeypatch.setattr(http_server.RequestHandler, "_do_POST", import_packet)
    request, peer = socket.socketpair()
    with request, peer, http_shutdown(server.server):
        serving = threading.Thread(target=server.server.serve_forever, kwargs={"poll_interval": 0.01})
        serving.start()
        closer = None
        try:
            server.server.process_request(request, ("192.0.2.1", 1234))
            peer.sendall(b"POST /api/v1/agent/packets HTTP/1.0\r\nContent-Length: 0\r\n\r\n")
            assert started.wait(2)
            signal.raise_signal(signal.SIGTERM)
            serving.join(timeout=2)
            assert not serving.is_alive() and not committed.is_set()

            def close():
                server.server.server_close()
                closed.set()

            closer = threading.Thread(target=close)
            closer.start()
            assert not closed.wait(0.02)  # The accepted import still owns its thread.
            release.set()
            assert b"200 OK" in _response(peer)
            assert closed.wait(2) and committed.is_set()
        finally:
            release.set()
            server.server.shutdown()
            serving.join(timeout=2)
            if closer is not None:
                closer.join(timeout=2)


@pytest.mark.parametrize("end", ["revoked", "limit", "idle", "rejected", "other_route", "duplicate", "updating"])
def test_packet_keepalive_is_bounded_and_authenticates_every_packet(server, monkeypatch, end):
    from server.api.routes import agent_packets
    from server.sli.agents.ca import AgentError

    authenticated = []
    received = []
    finished = threading.Event()
    original_finished = server.server.request_finished
    def request_finished(request):
        original_finished(request)
        finished.set()
    monkeypatch.setattr(server.server, 'request_finished', request_finished)
    monkeypatch.setattr(http_server, "AGENT_PACKET_KEEPALIVE_SECONDS", 0.05 if end == "idle" else 5, raising=False)
    monkeypatch.setattr(http_server, "AGENT_PACKET_KEEPALIVE_REQUESTS", 2, raising=False)
    monkeypatch.setattr(agent_packets, "_peer", lambda _: b"fixture-peer")
    cursor = object()
    connection = SimpleNamespace(cursor=lambda: nullcontext(cursor), commit=lambda: None)
    monkeypatch.setattr(agent_packets, "connect", lambda: nullcontext(connection))
    def authenticate(cur, der):
        assert cur is cursor and der == b"fixture-peer"
        authenticated.append(True)
        if end == "revoked" and len(authenticated) == 2:
            raise AgentError("fixture_revoked", 401)
        return {}, object()
    monkeypatch.setattr(agent_packets, "_authenticate", authenticate)
    def receive(*args, **kwargs):
        received.append(kwargs["value"])
        status = "duplicate" if end == "duplicate" else "rejected" if end == "rejected" and len(received) == 2 else "committed"
        return {"contract_id": "sli.agent-receipt.v1", "status": status}
    monkeypatch.setattr(agent_packets, "receive_packet", receive)
    monkeypatch.setattr(http_server.RequestHandler, "_do_POST",
                        lambda handler: agent_packets.try_handle_post(handler, "/api/v1/agent/packets"))
    request, peer = socket.socketpair()
    with request, peer:
        client = http.client.HTTPConnection("fixture.invalid", timeout=1)
        client.sock = peer
        server.server.process_request(request, ("192.0.2.1", 1234))
        client.request("POST", "/api/v1/agent/packets", b'{}',
                       {"Content-Type": "application/json", "Connection": "keep-alive"})
        response = client.getresponse()
        assert response.status == 200 and not response.will_close
        assert json.loads(response.read())["status"] == ("duplicate" if end == "duplicate" else "committed")
        # Reading the ACK can precede the worker's finally block. Change the
        # stopping flag only after that block, otherwise it wakes the reader
        # before this test's second request and legitimately closes the socket.
        assert finished.wait(timeout=1)
        if end != "idle":
            headers = {"Content-Type": "application/json", "Connection": "keep-alive"}
            if end == "updating":
                server.server.sli_stopping = True
                # Admission must reject before reading even an incomplete body.
                headers["Content-Length"] = "2"
            # GET and update rejection answer before reading a body. A second
            # send would race the deliberate close, so leave that body unsent.
            client.request("GET" if end == "other_route" else "POST",
                           "/api/health/live" if end == "other_route" else "/api/v1/agent/packets",
                           None if end in ("other_route", "updating") else b'{}', headers)
            response = client.getresponse()
            assert response.status == (401 if end == "revoked" else 503 if end == "updating" else 200)
            assert response.will_close
            body = response.read()
            if end == "other_route":
                assert json.loads(body) == {"ok": True}
            elif end == "updating":
                assert b"service_updating" in body
        server.workers[0].join(timeout=1)
        assert not server.workers[0].is_alive()
        client.close()
    assert len(authenticated) == (1 if end in ("idle", "other_route", "updating") else 2)
    assert len(received) == (2 if end in ("limit", "rejected", "duplicate") else 1)
    _assert_slot_available(server.server)


class FakeTLSSocket:
    def __init__(self, request, handshake):
        self.request = request
        self.handshake = handshake
        self.timeouts = []
        self.closed = False
        self.shutdowns = []

    def __getattr__(self, name):
        return getattr(self.request, name)

    def settimeout(self, timeout):
        self.timeouts.append(timeout)
        self.request.settimeout(timeout)

    def do_handshake(self):
        self.handshake(self)

    def close(self):
        self.closed = True
        self.request.close()

    def shutdown(self, how):
        self.shutdowns.append(how)
        self.request.shutdown(how)


@pytest.fixture
def server(monkeypatch):
    config = AdLogConfig(
        reports_dir="", log_dir="",
        http_max_connections=1, tls_handshake_timeout_seconds=30,
    )
    server = http_server.ProtectedHTTPServer(("127.0.0.1", 0), http_server.RequestHandler, config=config)
    events = []
    workers = []
    started = threading.Event()
    original_worker = server.process_request_thread

    def worker(request, client_address):
        workers.append(threading.current_thread())
        started.set()
        original_worker(request, client_address)

    monkeypatch.setattr(server, "process_request_thread", worker)
    monkeypatch.setattr(http_server, "log_event", lambda *args, **kwargs: events.append((args, kwargs)))
    monkeypatch.setattr(
        http_server.RequestHandler, "_do_GET",
        lambda handler: handler._send_json({"ok": True}),
    )
    yield SimpleNamespace(server=server, events=events, workers=workers, started=started)
    server.server_close()
    for thread in workers:
        thread.join(timeout=1)
        assert not thread.is_alive()


def _assert_slot_available(server):
    assert server.connection_slots.acquire(blocking=False)
    server.connection_slots.release()


def _response(peer):
    peer.settimeout(1)
    chunks = []
    while chunk := peer.recv(4096):
        chunks.append(chunk)
    return b"".join(chunks)


def _fake_tls_context(handshake, wrapped):
    def wrap_socket(request, *, server_side, do_handshake_on_connect):
        assert server_side is True
        assert do_handshake_on_connect is False
        tls_request = FakeTLSSocket(request, handshake)
        wrapped.append(tls_request)
        return tls_request

    return SimpleNamespace(wrap_socket=wrap_socket)


def test_stalled_tls_handshake_exits_worker_and_releases_connection(server):
    server.server.adlog_tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Exercise the actual SSL timeout without waiting for the production 30s.
    server.server.tls_handshake_timeout_seconds = 0.05
    request, peer = socket.socketpair()
    with request, peer:
        server.server.process_request(request, ("192.0.2.1", 1234))
        assert server.started.wait(timeout=1)
        server.workers[0].join(timeout=1)
        assert not server.workers[0].is_alive()
        assert _response(peer) == b""

    assert server.events == [(
        ("api", "tls_handshake_timeout", "TLS connection closed: handshake timeout exceeded."), {},
    )]
    _assert_slot_available(server.server)
    assert server.server.request_slots.acquire(blocking=False)
    server.server.request_slots.release()


def test_connection_limit_rejects_before_starting_another_worker(server):
    entered = threading.Event()
    release = threading.Event()
    wrapped = []

    def handshake(tls_request):
        assert tls_request.gettimeout() == 30
        entered.set()
        assert release.wait(timeout=2)

    server.server.adlog_tls_context = _fake_tls_context(handshake, wrapped)
    request, peer = socket.socketpair()
    rejected, rejected_peer = socket.socketpair()
    with request, peer, rejected, rejected_peer:
        peer.sendall(b"GET /api/health/live HTTP/1.0\r\n\r\n")
        server.server.process_request(request, ("192.0.2.1", 1234))
        try:
            assert entered.wait(timeout=1)
            assert not server.server.connection_slots.acquire(blocking=False)
            server.server.process_request(rejected, ("192.0.2.2", 1235))
            assert _response(rejected_peer) == b""
            assert len(server.workers) == 1
            assert server.events == [(
                ("api", "http_connection_limit_exceeded", "HTTP connection rejected: connection limit reached."), {},
            )]
        finally:
            release.set()
        assert b"200 OK" in _response(peer)
        server.workers[0].join(timeout=1)

    assert wrapped[0].closed
    _assert_slot_available(server.server)
    # The released slot must admit the next ordinary request.
    server.server.adlog_tls_context = None
    request, peer = socket.socketpair()
    with request, peer:
        peer.sendall(b"GET /api/health/live HTTP/1.0\r\n\r\n")
        server.server.process_request(request, ("192.0.2.3", 1236))
        assert b"200 OK" in _response(peer)
    assert len(server.workers) == 2


def test_browser_spare_handshake_does_not_block_another_request(server):
    server.server.connection_slots = threading.BoundedSemaphore(2)
    entered = threading.Event()
    release = threading.Event()
    wrapped = []
    spare, spare_peer = socket.socketpair()
    active, active_peer = socket.socketpair()

    def handshake(tls_request):
        assert tls_request.gettimeout() == 30
        if tls_request.request is spare:
            entered.set()
            assert release.wait(timeout=2)

    server.server.adlog_tls_context = _fake_tls_context(handshake, wrapped)
    with spare, spare_peer, active, active_peer:
        server.server.process_request(spare, ("192.0.2.1", 1234))
        try:
            assert entered.wait(timeout=1)
            active_peer.sendall(b"GET /api/health/live HTTP/1.0\r\n\r\n")
            server.server.process_request(active, ("192.0.2.2", 1235))
            assert b"200 OK" in _response(active_peer)
            assert not release.is_set()
            spare_peer.sendall(b"GET /api/health/live HTTP/1.0\r\n\r\n")
        finally:
            release.set()
        assert b"200 OK" in _response(spare_peer)
        for worker in server.workers:
            worker.join(timeout=1)
            assert not worker.is_alive()

    assert len(wrapped) == 2
    assert all(sock.timeouts[:2] == [30, None] and sock.timeouts[-1] is None
               and sock.closed for sock in wrapped)
    assert len(server.events) == 2
    assert all(args[1] == "http_access" and fields["status"] == "200" for args, fields in server.events)
    _assert_slot_available(server.server)


def test_browser_spare_after_handshake_is_bounded(server, monkeypatch):
    ready = threading.Event()
    wrapped = []
    monkeypatch.setattr(http_server.RequestHandler, "header_timeout_seconds", 0.05)
    original_setup = http_server.RequestHandler.setup

    def setup(handler):
        original_setup(handler)
        ready.set()

    monkeypatch.setattr(http_server.RequestHandler, "setup", setup)
    server.server.adlog_tls_context = _fake_tls_context(lambda _request: None, wrapped)
    request, peer = socket.socketpair()
    rejected, rejected_peer = socket.socketpair()
    with request, peer, rejected, rejected_peer:
        server.server.process_request(request, ("192.0.2.1", 1234))
        try:
            assert ready.wait(timeout=1)
            assert wrapped[0].timeouts[:2] == [30, None]
            assert server.workers[0].is_alive()
            assert not server.server.connection_slots.acquire(blocking=False)
            server.server.process_request(rejected, ("192.0.2.2", 1235))
            assert _response(rejected_peer) == b""
            assert len(server.workers) == 1
        finally:
            server.workers[0].join(timeout=1)
        assert not server.workers[0].is_alive()
        assert _response(peer) == b""
        assert not server.server.connections

    assert wrapped[0].closed
    _assert_slot_available(server.server)


@pytest.mark.parametrize("tls", [False, True])
@pytest.mark.parametrize("previous_timeout", [None, 2])
def test_ordinary_request_works_and_handshake_timeout_is_not_http_timeout(server, tls, previous_timeout):
    wrapped = []

    def handshake(tls_request):
        assert threading.current_thread() is not threading.main_thread()
        assert tls_request.gettimeout() == 30

    if tls:
        server.server.adlog_tls_context = _fake_tls_context(handshake, wrapped)
    request, peer = socket.socketpair()
    with request, peer:
        request.settimeout(previous_timeout)
        peer.sendall(b"GET /api/health/live HTTP/1.0\r\n\r\n")
        server.server.process_request(request, ("192.0.2.1", 1234))
        response = _response(peer)
        assert b"200 OK" in response
        assert b'"ok": true' in response
        server.workers[0].join(timeout=1)

    if tls:
        assert wrapped[0].timeouts[:2] == [30, previous_timeout]
        assert wrapped[0].timeouts[-1] == previous_timeout
        assert wrapped[0].closed
    _assert_slot_available(server.server)


def test_worker_start_failure_releases_connection_slot(server, monkeypatch):
    def fail_start(*_args):
        raise RuntimeError("worker start failed")

    monkeypatch.setattr(http_server.ThreadingHTTPServer, "process_request", fail_start)
    request, peer = socket.socketpair()
    with request, peer, pytest.raises(RuntimeError, match="worker start failed"):
        server.server.process_request(request, ("192.0.2.1", 1234))
    _assert_slot_available(server.server)


def test_tls_protocol_failure_closes_socket_and_releases_slot(server):
    wrapped = []

    def handshake(_tls_request):
        raise ssl.SSLError("invalid protocol")

    server.server.adlog_tls_context = _fake_tls_context(handshake, wrapped)
    request, peer = socket.socketpair()
    with request, peer:
        server.server.process_request(request, ("192.0.2.1", 1234))
        assert server.started.wait(timeout=1)
        server.workers[0].join(timeout=1)
        assert _response(peer) == b""
    assert wrapped[0].closed
    assert server.events == []
    _assert_slot_available(server.server)


def test_handler_failure_closes_tls_socket_and_releases_slot(server, monkeypatch):
    wrapped = []
    errors = []

    def fail_handler(*_args):
        raise RuntimeError("handler failed")

    server.server.adlog_tls_context = _fake_tls_context(lambda _request: None, wrapped)
    monkeypatch.setattr(server.server, "RequestHandlerClass", fail_handler)
    monkeypatch.setattr(server.server, "handle_error", lambda *_args: errors.append(True))
    request, peer = socket.socketpair()
    with request, peer:
        server.server.process_request(request, ("192.0.2.1", 1234))
        assert server.started.wait(timeout=1)
        server.workers[0].join(timeout=1)
        assert _response(peer) == b""
    assert errors == [True]
    assert wrapped[0].closed
    _assert_slot_available(server.server)


def test_tls_response_shuts_down_live_socket_before_close(server):
    wrapped = []
    server.server.adlog_tls_context = _fake_tls_context(lambda _: None, wrapped)
    request, peer = socket.socketpair()
    with request, peer:
        peer.sendall(b'GET /api/health/live HTTP/1.0\r\n\r\n')
        server.server.process_request(request, ('192.0.2.1', 1234))
        response = _response(peer)
        server.workers[0].join(timeout=1)
        assert b'200 OK' in response and response.endswith(b'\n}')
    assert wrapped[0].closed
    assert wrapped[0].shutdowns == [socket.SHUT_WR]


@pytest.mark.parametrize(
    ("env_connections", "env_timeout", "expected_connections", "expected_timeout"),
    [(None, None, 3, 20), ("2", "25", 2, 25), ("-1", "5", 1, 15), ("999", "99", 256, 30),
     ("invalid", "invalid", 3, 20)],
)
def test_http_connection_config_and_env_safe_bounds(
    monkeypatch, env_connections, env_timeout, expected_connections, expected_timeout,
):
    monkeypatch.setattr(app_config, "_read_simple_yaml", lambda _path: {
        "http": {"max_connections": 3, "tls_handshake_timeout_seconds": 20},
    })
    for name, value in (
        ("ADLOG_HTTP_MAX_CONNECTIONS", env_connections),
        ("ADLOG_TLS_HANDSHAKE_TIMEOUT_SECONDS", env_timeout),
    ):
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)
    config = app_config.load_config()
    assert config.http_max_connections == expected_connections
    assert config.tls_handshake_timeout_seconds == expected_timeout


def test_http_connection_config_defaults_leave_room_for_browser_spares(monkeypatch):
    monkeypatch.setattr(app_config, "_read_simple_yaml", lambda _path: {})
    monkeypatch.delenv("ADLOG_HTTP_MAX_CONNECTIONS", raising=False)
    monkeypatch.delenv("ADLOG_TLS_HANDSHAKE_TIMEOUT_SECONDS", raising=False)
    config = app_config.load_config()
    assert config.http_max_connections == 64
    assert config.tls_handshake_timeout_seconds == 30


@pytest.mark.parametrize("incomplete,code,status", [
    (False, b"request_body_timeout", b"408"), (True, b"request_body_incomplete", b"400")])
def test_stalled_agent_body_releases_slots_without_opening_database(server, monkeypatch, incomplete, code, status):
    from server.api.routes import agent_packets

    database_calls = []
    monkeypatch.setattr(http_server, "JSON_BODY_TIMEOUT_SECONDS", 0.05)
    monkeypatch.setattr(agent_packets, "_peer", lambda _handler: b"fixture-peer")
    def connect():
        database_calls.append(True)
        raise AssertionError("body must complete before opening database")
    monkeypatch.setattr(agent_packets, "connect", connect)
    monkeypatch.setattr(http_server.RequestHandler, "_do_POST",
        lambda handler: agent_packets.try_handle_post(handler, "/api/v1/agent/packets"))
    request, peer = socket.socketpair()
    with request, peer:
        peer.sendall(b"POST /api/v1/agent/packets HTTP/1.0\r\nContent-Type: application/json\r\n"
                     b"Content-Length: 10\r\n\r\n{")
        if incomplete:
            peer.shutdown(socket.SHUT_WR)
        server.server.process_request(request, ("192.0.2.1", 1234))
        assert server.started.wait(timeout=1)
        server.workers[0].join(timeout=1)
        assert not server.workers[0].is_alive()
        response = _response(peer)
        assert status in response.split(b"\r\n", 1)[0] and code in response
    assert database_calls == []
    _assert_slot_available(server.server)
    assert server.server.request_slots.acquire(blocking=False)
    server.server.request_slots.release()


def test_body_trickle_cannot_restart_total_deadline(monkeypatch):
    from server.api.errors import RequestInputError

    elapsed = [0.0]
    timeouts = []
    monkeypatch.setattr(http_server.time, "monotonic", lambda: elapsed[0])
    monkeypatch.setattr(http_server, "JSON_BODY_TIMEOUT_SECONDS", 1)
    class Stream:
        def read1(self, _length):
            elapsed[0] += 0.6
            return b" "
    handler = http_server.RequestHandler.__new__(http_server.RequestHandler)
    handler.headers = {"Content-Length": "10", "Content-Type": "application/json"}
    handler.connection = SimpleNamespace(gettimeout=lambda: None, settimeout=timeouts.append)
    handler.rfile = Stream()
    with pytest.raises(RequestInputError, match="request_body_timeout") as exc:
        handler._read_json_body()
    assert exc.value.status == 408 and handler.close_connection
    assert timeouts == [1.0, 0.4, None]


def test_oversized_body_is_rejected_before_reading_or_opening_database(monkeypatch):
    from server.api.errors import RequestInputError
    from server.api.routes import agent_packets

    handler = http_server.RequestHandler.__new__(http_server.RequestHandler)
    handler.headers = {"Content-Length": str(http_server.MAX_JSON_REQUEST_BYTES + 1)}
    monkeypatch.setattr(agent_packets, "_peer", lambda _handler: b"fixture-peer")
    monkeypatch.setattr(agent_packets, "connect", lambda: pytest.fail("database must not be reached"))
    with pytest.raises(RequestInputError, match="request_body_too_large"):
        agent_packets.try_handle_post(handler, "/api/v1/agent/packets")
    assert handler.close_connection


@pytest.mark.parametrize("headers,reason", [
    ({"Content-Length": "-1"}, "invalid_content_length"),
    ({"Content-Length": "invalid"}, "invalid_content_length"),
    ({"Transfer-Encoding": "chunked"}, "unsupported_transfer_encoding"),
    ({"Content-Length": "2", "Content-Type": "text/plain"}, "json_content_type_required")])
def test_unread_invalid_body_closes_connection(headers, reason):
    from server.api.errors import RequestInputError

    handler = http_server.RequestHandler.__new__(http_server.RequestHandler)
    handler.headers = headers
    with pytest.raises(RequestInputError, match=reason):
        handler._read_json_body()
    assert handler.close_connection


def test_complete_json_body_restores_socket_timeout():
    import io

    timeouts = []
    handler = http_server.RequestHandler.__new__(http_server.RequestHandler)
    handler.headers = {"Content-Length": "11", "Content-Type": "application/json"}
    handler.connection = SimpleNamespace(gettimeout=lambda: 2, settimeout=timeouts.append)
    handler.rfile = io.BytesIO(b'{"ok":true}')
    assert handler._read_json_body() == {"ok": True}
    assert timeouts == [2, 2]


@pytest.mark.parametrize("payload", [b"", b"GET / HTTP/1.0\r\nHost: incomplete", b"GET /"])
@pytest.mark.parametrize("tls", [False, True])
def test_header_deadline_releases_connection_once(server, monkeypatch, payload, tls):
    monkeypatch.setattr(http_server.RequestHandler, "header_timeout_seconds", 0.05)
    if tls:
        server.server.adlog_tls_context = _fake_tls_context(lambda _: None, [])
    request, peer = socket.socketpair()
    with request, peer:
        if payload:
            peer.sendall(payload)
        server.server.process_request(request, ("192.0.2.1", 1234))
        assert server.started.wait(1)
        server.workers[0].join(timeout=1)
        assert not server.workers[0].is_alive()
        assert _response(peer) == b""
        assert not server.server.connections
    assert server.server.connection_slots.acquire(blocking=False)
    assert not server.server.connection_slots.acquire(blocking=False)
    server.server.connection_slots.release()

"""No listener, service, database or third-party packages are needed."""
import io
import socket
import unittest
from http.server import BaseHTTPRequestHandler
from types import SimpleNamespace
from unittest.mock import patch

from server.api.http_header_deadline import HeaderDeadlineMixin


class FakeSocket:
    def __init__(self, chunks, clock):
        self.chunks = iter(chunks)
        self.clock = clock
        self.timeout = None
        self.timeouts = []
        self.output = bytearray()
        self.reads = 0
        self.pending = b""

    def gettimeout(self):
        return self.timeout

    def settimeout(self, value):
        self.timeout = value
        self.timeouts.append(value)

    def makefile(self, mode, buffering=-1):
        return io.BufferedReader(RawSocket(self)) if buffering != 0 else RawSocket(self)

    def sendall(self, data):
        self.output.extend(data)


class RawSocket(io.RawIOBase):
    def __init__(self, sock):
        self.sock = sock

    def readable(self):
        return True

    def readinto(self, target):
        self.sock.reads += 1
        if self.sock.pending:
            delay, chunk = 0, self.sock.pending
        else:
            delay, chunk = next(self.sock.chunks, (100, b""))
        if self.sock.timeout is not None and delay > self.sock.timeout:
            self.sock.clock[0] += self.sock.timeout
            raise TimeoutError("silent socket")
        self.sock.clock[0] += delay
        count = min(len(target), len(chunk))
        target[:count] = chunk[:count]
        self.sock.pending = chunk[count:]
        return count


class Handler(HeaderDeadlineMixin, BaseHTTPRequestHandler):
    header_timeout_seconds = 1

    def log_message(self, *_args):
        pass

    def do_GET(self):
        self.server.seen.append((self.path, self.connection.gettimeout()))
        self.send_response(200)
        self.end_headers()

    def do_POST(self):
        self.server.seen.append(self.rfile.read(int(self.headers["Content-Length"])))
        self.send_response(200)
        self.end_headers()


class HeaderDeadlineTests(unittest.TestCase):
    def run_request(self, chunks, timeout=None, handler=Handler):
        clock = [0.0]
        sock = FakeSocket(chunks, clock)
        sock.timeout = timeout
        server = SimpleNamespace(seen=[])
        with patch("server.api.http_header_deadline.time.monotonic", lambda: clock[0]):
            handler(sock, ("192.0.2.1", 1234), server)
        self.assertEqual(sock.timeout, timeout)
        return sock, server, clock[0]

    def test_silent_initial_line_is_bounded(self):
        sock, server, elapsed = self.run_request([])
        self.assertEqual(elapsed, 1)
        self.assertEqual(server.seen, [])
        self.assertEqual(sock.output, b"")

    def test_partial_header_is_bounded(self):
        _, server, elapsed = self.run_request([(0, b"GET / HTTP/1.0\r\nHost: partial")])
        self.assertEqual(elapsed, 1)
        self.assertEqual(server.seen, [])

    def test_trickle_cannot_restart_total_budget(self):
        sock, server, elapsed = self.run_request([(0.2, bytes([c])) for c in b"GET / HTTP/1.0\r\n\r\n"])
        self.assertAlmostEqual(elapsed, 1)
        self.assertLessEqual(sock.reads, 6)
        self.assertEqual(server.seen, [])

    def test_valid_request_before_deadline_restores_timeout(self):
        sock, server, _ = self.run_request([(0.6, b"GET / HTTP/1.0\r\n\r\n")], timeout=2)
        self.assertEqual(server.seen, [("/", 2)])
        self.assertIn(b"200 OK", sock.output)

    def test_body_has_no_header_deadline(self):
        sock, server, elapsed = self.run_request([
            (0.6, b"POST / HTTP/1.0\r\nContent-Length: 2\r\n\r\n"), (2, b"{}")])
        self.assertEqual(server.seen, [b"{}"])
        self.assertGreater(elapsed, 1)
        self.assertIn(b"200 OK", sock.output)

    def test_shorter_existing_keepalive_timeout_is_respected(self):
        _, _, elapsed = self.run_request([], timeout=0.25)
        self.assertEqual(elapsed, 0.25)

    def test_malformed_request_restores_timeout(self):
        sock, server, _ = self.run_request([(0, b"BROKEN\r\n")])
        self.assertIn(b"400", sock.output)
        self.assertEqual(server.seen, [])

    def test_oversized_header_keeps_stdlib_limit(self):
        sock, server, _ = self.run_request([(0, b"GET / HTTP/1.0\r\n")] +
            [(0, b"X" * 8192)] * 9)
        self.assertIn(b"431", sock.output)
        self.assertEqual(server.seen, [])

    def test_buffered_body_bytes_are_preserved(self):
        _, server, _ = self.run_request([(0, b"POST / HTTP/1.0\r\nContent-Length: 2\r\n\r\n{}")])
        self.assertEqual(server.seen, [b"{}"])

    def test_eof_and_overlong_request_line_restore_timeout(self):
        for chunks, status in [([(0, b"")], None), ([(0, b"X" * 8192)] * 9, b"414")]:
            sock, server, _ = self.run_request(chunks, timeout=2)
            self.assertEqual(server.seen, [])
            if status:
                self.assertIn(status, sock.output)

    def test_each_persistent_request_gets_a_new_budget(self):
        class PersistentHandler(Handler):
            protocol_version = "HTTP/1.1"

        sock, server, elapsed = self.run_request([
            (0.6, b"GET /one HTTP/1.1\r\n\r\n"),
            (0.6, b"GET /two HTTP/1.1\r\nConnection: close\r\n\r\n"),
        ], handler=PersistentHandler)
        self.assertEqual(server.seen, [("/one", None), ("/two", None)])
        self.assertGreater(elapsed, 1)
        self.assertEqual(sock.output.count(b"200 OK"), 2)

    def test_explicit_and_unbuffered_rbufsize_are_preserved(self):
        for buffer_size in (0, 17):
            class SizedHandler(Handler):
                rbufsize = buffer_size

            _, server, _ = self.run_request([
                (0, b"POST / HTTP/1.0\r\nContent-Length: 2\r\n\r\n{}"),
            ], handler=SizedHandler)
            self.assertEqual(server.seen, [b"{}"])
            self.assertEqual(SizedHandler.rbufsize, buffer_size)

    def test_read_error_restores_timeout(self):
        with patch.object(RawSocket, "readinto", side_effect=OSError("read failed")):
            clock = [0.0]
            sock = FakeSocket([], clock)
            sock.timeout = 2
            with self.assertRaises(OSError):
                Handler(sock, ("192.0.2.1", 1234), SimpleNamespace(seen=[]))
            self.assertEqual(sock.timeout, 2)

    def test_socketpair_real_buffered_reader_silent_deadline(self):
        class ShortHandler(Handler):
            header_timeout_seconds = 0.02

        request, peer = socket.socketpair()
        with request, peer:
            server = SimpleNamespace(seen=[])
            ShortHandler(request, ("192.0.2.1", 1234), server)
            self.assertEqual(server.seen, [])
            self.assertIsNone(request.gettimeout())
            # Handler closes its stream, not the transport owned by the server.
            self.assertGreaterEqual(request.fileno(), 0)

    def test_socketpair_real_buffer_preserves_prefetched_body(self):
        request, peer = socket.socketpair()
        with request, peer:
            request.settimeout(0.1)
            peer.sendall(b"POST / HTTP/1.0\r\nContent-Length: 2\r\n\r\n{}")
            server = SimpleNamespace(seen=[])
            Handler(request, ("192.0.2.1", 1234), server)
            self.assertEqual(server.seen, [b"{}"])
            self.assertEqual(request.gettimeout(), 0.1)


if __name__ == "__main__":
    unittest.main()

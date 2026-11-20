from __future__ import annotations

import ipaddress
from email.message import Message
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from socketserver import TCPServer
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from server.api import http_server, proxy
from server.api.routes import auth as routes_auth


TRUSTED = (ipaddress.ip_network("192.0.2.0/24"), ipaddress.ip_network("2001:db8::/64"))
HEADERS = {
    "Host": "backend.example.test:8080",
    "X-Forwarded-For": "198.51.100.23",
    "X-Forwarded-Proto": "https",
    "X-Forwarded-Host": "public.example.test",
}


@pytest.fixture(autouse=True)
def isolated_auth(monkeypatch):
    monkeypatch.setenv("ADLOG_AUTH_REQUIRED", "1")
    monkeypatch.delenv("ADLOG_AUTH_ALLOW_INSECURE_HTTP", raising=False)
    monkeypatch.delenv("ADLOG_AUTH_COOKIE_SECURE", raising=False)


def _handler(*, peer="192.0.2.2", tls=False, trusted=TRUSTED, headers=None):
    handler = object.__new__(http_server.RequestHandler)
    # Parsing tests bypass setup and the socket reader; model its teardown.
    handler._header_reader = Mock(spec=["disarm"])
    handler.server = SimpleNamespace(adlog_tls_enabled=tls, adlog_trusted_proxies=trusted)
    handler.client_address = (peer, 1234)
    handler.headers = dict(HEADERS if headers is None else headers)
    handler.responses = []
    handler._send_json = lambda payload, status=HTTPStatus.OK, **kwargs: handler.responses.append((payload, status))
    handler.cookies = []
    handler._send_json_with_cookie = lambda payload, cookie: handler.cookies.append(cookie)
    handler._require_access = lambda role: True
    return handler


@pytest.mark.parametrize("trusted", [(), TRUSTED])
def test_headers_from_untrusted_peer_are_ignored(trusted):
    handler = _handler(peer="203.0.113.9", trusted=trusted)
    assert handler._external_request() == proxy.RequestContext("203.0.113.9", "http", HEADERS["Host"])
    assert not handler._secure_transport()


@pytest.mark.parametrize("peer", ["192.0.2.2", "2001:db8::2"])
def test_trusted_proxy_headers_are_honoured(peer):
    handler = _handler(peer=peer)
    assert handler._external_request() == proxy.RequestContext("198.51.100.23", "https", "public.example.test")
    assert handler._secure_transport()


@pytest.mark.parametrize("peer", ["192.0.2.2", "::ffff:192.0.2.2", "2001:db8::2"])
@pytest.mark.parametrize("header", ["X-Forwarded-For", "X-Real-IP"])
def test_accepted_socket_peer_preserves_proxy_trust(monkeypatch, peer, header):
    # Exercise dual-stack normalization without binding a wildcard/IPv6 socket.
    request = object()
    monkeypatch.setattr(TCPServer, "get_request", lambda _: (request, (peer, 1234)))
    accepted, address = http_server.ProtectedHTTPServer.get_request(object.__new__(http_server.ProtectedHTTPServer))
    assert accepted is request
    assert address[0] == ("192.0.2.2" if peer.startswith("::ffff:") else peer)
    headers = {name: value for name, value in HEADERS.items() if name != "X-Forwarded-For"}
    headers[header] = "198.51.100.23"
    handler = _handler(peer=address[0], headers=headers)
    assert handler._external_request() == proxy.RequestContext("198.51.100.23", "https", "public.example.test")
    assert handler._secure_transport()


def test_mapped_untrusted_socket_peer_cannot_supply_forwarded_address(monkeypatch):
    monkeypatch.setattr(TCPServer, "get_request", lambda _: (object(), ("::ffff:203.0.113.9", 1234)))
    _, address = http_server.ProtectedHTTPServer.get_request(object.__new__(http_server.ProtectedHTTPServer))
    handler = _handler(peer=address[0], headers={**HEADERS, "X-Real-IP": "198.51.100.23"})
    assert handler._external_request() == proxy.RequestContext("203.0.113.9", "http", HEADERS["Host"])


def test_client_ip_stops_at_first_untrusted_hop():
    handler = _handler(headers={**HEADERS, "X-Forwarded-For": "203.0.113.99, 198.51.100.23, 192.0.2.3"})
    assert handler._external_request().client_ip == "198.51.100.23"


@pytest.mark.parametrize("forwarded_for", ["unknown", "198.51.100.23,", "_hidden", "198.51.100.23:80"])
def test_invalid_forwarded_address_does_not_replace_peer(forwarded_for):
    handler = _handler(headers={**HEADERS, "X-Forwarded-For": forwarded_for})
    assert handler._external_request().client_ip == "192.0.2.2"


def test_forwarded_ipv6_client():
    handler = _handler(headers={**HEADERS, "X-Forwarded-For": "2001:db8:1::23"})
    assert handler._external_request().client_ip == "2001:db8:1::23"


@pytest.mark.parametrize("host", ["evil.example.test/path", "user@evil.example.test", "evil.example.test,public.example.test", "evil.example.test:bad", "evil.example.test:99999", "evil.example.test#fragment"])
def test_invalid_forwarded_host_is_ignored(host):
    handler = _handler(headers={**HEADERS, "X-Forwarded-Host": host})
    assert handler._external_request().host == HEADERS["Host"]


@pytest.mark.parametrize("proto", ["https,http", "ftp", "https://"])
def test_invalid_forwarded_proto_is_ignored(proto):
    handler = _handler(headers={**HEADERS, "X-Forwarded-Proto": proto})
    assert not handler._secure_transport()


def test_duplicate_proxy_headers_are_ignored():
    headers = Message()
    headers["Host"] = HEADERS["Host"]
    for name, value in HEADERS.items():
        if name.startswith("X-"):
            headers[name] = value
            headers[name] = value
    handler = _handler()
    handler.headers = headers
    assert handler._external_request() == proxy.RequestContext("192.0.2.2", "http", HEADERS["Host"])


def test_forwarded_header_is_not_an_alternate_trust_path():
    handler = _handler(headers={"Host": HEADERS["Host"], "Forwarded": 'for=198.51.100.23;proto=https;host="public.example.test"'})
    assert not handler._secure_transport()
    assert handler._external_request().host == HEADERS["Host"]


def test_parse_request_preserves_socket_peer_across_requests(monkeypatch):
    handler = _handler()
    pending = [HEADERS, {**HEADERS, "X-Forwarded-For": "203.0.113.7", "X-Forwarded-Proto": "http"}]

    def parse(self):
        self.headers = pending.pop(0)
        return True

    monkeypatch.setattr(BaseHTTPRequestHandler, "parse_request", parse)
    assert handler.parse_request()
    assert handler.client_address == ("198.51.100.23", 1234)
    assert handler._secure_transport()
    assert handler.parse_request()
    assert handler.client_address == ("203.0.113.7", 1234)
    assert not handler._secure_transport()
    assert handler._peer_address == ("192.0.2.2", 1234)
    assert handler._header_reader.disarm.call_count == 2


@pytest.mark.parametrize(("peer", "tls", "proto", "hsts"), [
    ("203.0.113.9", False, "https", False),
    ("192.0.2.2", False, "https", True),
    ("192.0.2.2", False, "http", False),
    ("203.0.113.9", True, "http", True),
    ("192.0.2.2", True, "http", False),
])
def test_hsts_and_cookie_flags_use_effective_tls(monkeypatch, peer, tls, proto, hsts):
    handler = _handler(peer=peer, tls=tls, headers={**HEADERS, "X-Forwarded-Proto": proto})
    emitted = {}
    handler.send_header = lambda name, value: emitted.update({name: value})
    monkeypatch.setattr(BaseHTTPRequestHandler, "end_headers", lambda self: None)
    handler.end_headers()
    assert ("Strict-Transport-Security" in emitted) == hsts
    routes_auth._send_login_success(handler, {"id": 1, "role": "viewer"}, "synthetic-session")
    cookie = handler.cookies[-1]
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie and "Path=/" in cookie
    assert ("; Secure" in cookie) == hsts
    monkeypatch.setattr(routes_auth, "revoke_session", lambda token: None)
    routes_auth._handle_logout(handler)
    assert "Max-Age=0" in handler.cookies[-1]
    assert ("; Secure" in handler.cookies[-1]) == hsts


@pytest.mark.parametrize(("origin", "accepted"), [
    ("https://public.example.test", True),
    ("https://PUBLIC.example.test:443", True),
    ("http://public.example.test", False),
    ("https://public.example.test:8443", False),
    ("https://backend.example.test:8080", False),
    ("https://evil.example.test", False),
    ("null", False),
    ("", False),
    ("https://public.example.test/path", False),
    ("https://public.example.test\n", False),
])
def test_origin_check_uses_external_scheme_and_host(origin, accepted):
    handler = _handler(headers={**HEADERS, "Origin": origin})
    assert handler._authorize_mutation() == accepted
    if not accepted:
        assert handler.responses == [({"error": "cross_origin_request_rejected"}, HTTPStatus.FORBIDDEN)]


def test_spoofed_forwarded_host_cannot_authorize_untrusted_origin():
    handler = _handler(peer="203.0.113.9", headers={**HEADERS, "Origin": "https://public.example.test"})
    assert not handler._authorize_mutation()


def test_untrusted_peer_can_use_direct_origin():
    handler = _handler(peer="203.0.113.9", headers={**HEADERS, "Origin": "http://backend.example.test:8080"})
    assert handler._authorize_mutation()


def test_ipv6_authority_and_port_behind_proxy():
    handler = _handler(headers={**HEADERS, "X-Forwarded-Host": "[2001:db8::10]:8443", "Origin": "https://[2001:db8::10]:8443"})
    assert handler._authorize_mutation()


def test_origin_without_host_is_rejected():
    handler = _handler(headers={"Origin": "https://public.example.test"})
    assert not handler._authorize_mutation()


def test_duplicate_origins_are_rejected():
    handler = _handler()
    headers = Message()
    for name, value in HEADERS.items():
        headers[name] = value
    headers["Origin"] = "https://public.example.test"
    headers["Origin"] = "https://evil.example.test"
    handler.headers = headers
    assert not handler._authorize_mutation()


@pytest.mark.parametrize("action", [routes_auth._handle_login, routes_auth._handle_logout])
def test_login_and_logout_reject_cross_origin_before_side_effects(monkeypatch, action):
    handler = _handler(headers={**HEADERS, "Origin": "https://evil.example.test"})
    handler._read_json_body = lambda: pytest.fail("must not read credentials")
    monkeypatch.setattr(routes_auth, "revoke_session", lambda token: pytest.fail("must not revoke a session"))
    action(handler)
    assert handler.responses == [({"error": "cross_origin_request_rejected"}, HTTPStatus.FORBIDDEN)]
    assert handler.cookies == []


def test_login_behind_proxy_uses_client_ip_for_limiter_and_audit(monkeypatch):
    handler = _handler(headers={**HEADERS, "Origin": "https://public.example.test"})
    monkeypatch.setattr(BaseHTTPRequestHandler, "parse_request", lambda self: setattr(self, "headers", {**HEADERS, "Origin": "https://public.example.test"}) or True)
    handler.parse_request()
    handler._header_reader.disarm.assert_called_once_with()
    addresses = []
    handler.server.login_allowed = lambda address: addresses.append(address) or (True, 0)
    handler._read_json_body = lambda: {"username": "synthetic-user", "password": "synthetic-password", "remember": True}
    monkeypatch.setattr(routes_auth, "authenticate_password", lambda username, password: {"id": 1, "role": "viewer"})
    monkeypatch.setattr(routes_auth, "record_auth_audit", lambda **kwargs: addresses.append(kwargs["remote_address"]))
    monkeypatch.setattr(routes_auth, "issue_session", lambda principal, remember: "synthetic-session")
    routes_auth._handle_login(handler)
    assert addresses == ["198.51.100.23"] * 2
    assert "Max-Age=1209600" in handler.cookies[0] and "; Secure" in handler.cookies[0]
    assert handler.responses == []


def test_untrusted_https_spoof_cannot_enable_login():
    handler = _handler(peer="203.0.113.9")
    routes_auth._handle_login(handler)
    assert handler.responses == [({"error": "secure_transport_required"}, HTTPStatus.FORBIDDEN)]


def test_cookie_override_does_not_enable_hsts_or_https_login(monkeypatch):
    handler = _handler(peer="203.0.113.9")
    monkeypatch.setenv("ADLOG_AUTH_COOKIE_SECURE", "1")
    routes_auth._send_login_success(handler, {"id": 1}, "synthetic-session")
    assert "; Secure" in handler.cookies[0]
    emitted = {}
    handler.send_header = lambda name, value: emitted.update({name: value})
    monkeypatch.setattr(BaseHTTPRequestHandler, "end_headers", lambda self: None)
    handler.end_headers()
    assert "Strict-Transport-Security" not in emitted
    routes_auth._handle_login(handler)
    assert handler.responses == [({"error": "secure_transport_required"}, HTTPStatus.FORBIDDEN)]


@pytest.mark.parametrize("peer", ["192.0.2.2", "203.0.113.9"])
def test_login_redirect_stays_relative_to_external_origin(monkeypatch, peer):
    handler = _handler(peer=peer)
    handler.path = "/app/operations"
    locations = []
    handler.send_response = lambda status: None
    handler.send_header = lambda name, value: locations.append(value) if name == "Location" else None
    handler.end_headers = lambda: None
    monkeypatch.setattr(http_server, "principal_from_headers", lambda headers: None)
    handler._do_GET()
    assert locations == ["/login?next=%2Fapp%2Foperations"]


@pytest.mark.parametrize("cidrs", ["invalid", "192.0.2.0/33", "192.0.2.2/24", "192.0.2.0/24,"])
def test_invalid_proxy_cidrs_fail_closed_without_echoing_configuration(monkeypatch, cidrs):
    monkeypatch.setenv("ADLOG_TRUSTED_PROXIES", cidrs)
    with pytest.raises(RuntimeError) as error:
        proxy.load_trusted_proxies()
    assert str(error.value) == "ADLOG_TRUSTED_PROXIES must contain valid CIDRs or IP addresses"


def test_proxy_trust_is_empty_by_default(monkeypatch):
    monkeypatch.delenv("ADLOG_TRUSTED_PROXIES", raising=False)
    assert proxy.load_trusted_proxies() == ()


@pytest.mark.parametrize("method,path", [
    ("GET", "/api/auth/me"), ("GET", "/api/health/live"), ("GET", "/api/findings"),
    ("POST", "/api/auth/login"), ("POST", "/api/auth/logout"), ("POST", "/api/findings/1/status"),
])
@pytest.mark.parametrize("peer,headers", [
    ("203.0.113.9", HEADERS),
    ("127.0.0.1", HEADERS),
    ("192.0.2.2", {**HEADERS, "X-Forwarded-Proto": "http"}),
    ("192.0.2.2", {"Host": HEADERS["Host"]}),
])
def test_proxy_mode_rejects_insecure_api_before_auth_or_dispatch(monkeypatch, method, path, peer, headers):
    handler = _handler(peer=peer, headers={**headers, "Authorization": "Bearer synthetic-key"})
    handler.path = path
    monkeypatch.setenv("ADLOG_AUTH_ALLOW_INSECURE_HTTP", "1")
    monkeypatch.setattr(http_server, "principal_from_headers", lambda *_: pytest.fail("credentials were read"))
    monkeypatch.setattr(http_server.ROUTE_REGISTRY, "dispatch_post", lambda *_: pytest.fail("mutation was dispatched"))
    handler._read_json_body = lambda: pytest.fail("body was read")
    getattr(handler, f"_do_{method}")()
    assert handler.responses == [({"error": "secure_transport_required"}, HTTPStatus.FORBIDDEN)]


@pytest.mark.parametrize("peer,tls,trusted", [
    ("192.0.2.2", False, TRUSTED), ("203.0.113.9", True, TRUSTED),
    ("127.0.0.1", False, ()),
])
@pytest.mark.parametrize("method", ["GET", "POST"])
def test_secure_proxy_tls_and_non_proxy_loopback_api_reach_dispatch(monkeypatch, peer, tls, trusted, method):
    handler = _handler(peer=peer, tls=tls, trusted=trusted)
    handler.path = "/api/synthetic"
    calls = []
    monkeypatch.setattr(http_server, "principal_from_headers", lambda *_: {"role": "viewer"})
    monkeypatch.setattr(http_server, "route_capability", lambda *_: "fixture.view")
    handler._require_capability = lambda *_: True
    monkeypatch.setattr(http_server.ROUTE_REGISTRY, f"dispatch_{method.lower()}", lambda *_: calls.append(method) or True)
    getattr(handler, f"_do_{method}")()
    assert calls == [method]
    assert handler.responses == []

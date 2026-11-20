"""Candidate requests never enter authentication, imports or packet ACK handlers."""
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from server.api.http_server import BaseHTTPRequestHandler, RequestHandler


@pytest.mark.parametrize('method,path,allowed', [
    ('GET', '/api/health/ready', True), ('GET', '/api/health/live', True),
    ('POST', '/api/health/ready', False), ('GET', '/api/health/ready?extra=1', False),
    ('POST', '/api/auth/login', False), ('POST', '/api/agents/packets', False),
    ('GET', '/app', False), ('PUT', '/api/settings', False),
])
def test_candidate_fence_precedes_every_route(monkeypatch, method, path, allowed):
    monkeypatch.setenv('SLI_NATIVE_UPGRADE_TESTING', '1')
    monkeypatch.setattr(BaseHTTPRequestHandler, 'parse_request', lambda self: True)
    errors = []
    handler = object.__new__(RequestHandler)
    # No socket setup in these route-fence tests; retain reader teardown.
    handler._header_reader = Mock(spec=["disarm"])
    handler.client_address = ('127.0.0.1', 1)
    handler.command, handler.path = method, path
    handler.server = SimpleNamespace()
    handler.send_error = lambda *args: errors.append(args)
    handler._external_request = lambda: SimpleNamespace(client_ip='127.0.0.1')
    assert handler.parse_request() is allowed
    handler._header_reader.disarm.assert_called_once_with()
    assert errors == ([] if allowed else [(503, 'service_updating')])


def test_normal_runtime_keeps_existing_request_admission(monkeypatch):
    monkeypatch.delenv('SLI_NATIVE_UPGRADE_TESTING', raising=False)
    monkeypatch.setattr(BaseHTTPRequestHandler, 'parse_request', lambda self: True)
    handler = object.__new__(RequestHandler)
    # No socket setup in these route-fence tests; retain reader teardown.
    handler._header_reader = Mock(spec=["disarm"])
    handler.client_address = ('127.0.0.1', 1)
    handler.command, handler.path = 'POST', '/api/agents/packets'
    handler.server = SimpleNamespace()
    handler._external_request = lambda: SimpleNamespace(client_ip='127.0.0.1')
    assert handler.parse_request()
    handler._header_reader.disarm.assert_called_once_with()

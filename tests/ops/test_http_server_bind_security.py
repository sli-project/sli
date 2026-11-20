from __future__ import annotations

import logging

import pytest

from server.api import http_server
from server.api.proxy import load_trusted_proxies
from server.sli.access.auth import auth_required


@pytest.fixture(autouse=True)
def isolated_security_environment(monkeypatch):
    for name in (
        "ADLOG_AUTH_REQUIRED", "ADLOG_ALLOW_UNAUTHENTICATED", "ADLOG_TRUSTED_PROXIES",
        "ADLOG_TLS_CERT_PATH", "ADLOG_TLS_KEY_PATH", "ADLOG_TLS_CERT_FILE", "ADLOG_TLS_KEY_FILE",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize(
    "host",
    ["127.0.0.1", "127.42.3.9", "::1", "[::1]", "::1%1", "localhost", "LOCALHOST."],
)
def test_loopback_bind_allows_explicit_diagnostic_opt_out_without_tls(host: str) -> None:
    http_server._validate_server_bind_security(
        host,
        authentication_required=False,
        tls_configured=False,
        allow_unauthenticated=True,
    )


@pytest.mark.parametrize("host", ["", "0.0.0.0", "::", "[::]", "192.0.2.10", "server.example.test"])
def test_external_or_wildcard_bind_requires_tls_or_trusted_proxy(host: str) -> None:
    with pytest.raises(RuntimeError, match="non-loopback server bind requires"):
        http_server._validate_server_bind_security(
            host,
            authentication_required=True,
            tls_configured=False,
        )


@pytest.mark.parametrize("host", ["127.0.0.1", "0.0.0.0", "::"])
@pytest.mark.parametrize("tls_configured", [True, False])
def test_disabling_authentication_requires_explicit_opt_out(host, tls_configured):
    with pytest.raises(RuntimeError, match="ADLOG_ALLOW_UNAUTHENTICATED=1"):
        http_server._validate_server_bind_security(
            host, authentication_required=False, tls_configured=tls_configured,
        )


@pytest.mark.parametrize("value", [None, "", "1", "true", "yes", "on"])
def test_authentication_is_required_by_default(monkeypatch, value):
    if value is not None:
        monkeypatch.setenv("ADLOG_AUTH_REQUIRED", value)
    assert auth_required()


def test_unknown_auth_setting_fails_closed(monkeypatch):
    monkeypatch.setenv("ADLOG_AUTH_REQUIRED", "typo")
    with pytest.raises(RuntimeError, match="invalid ADLOG_AUTH_REQUIRED"):
        auth_required()


def test_external_proxy_bind_allows_tls_termination(monkeypatch):
    monkeypatch.setenv("ADLOG_TRUSTED_PROXIES", "192.0.2.0/24,2001:db8::/64")
    http_server._validate_server_bind_security(
        "0.0.0.0", authentication_required=True, tls_configured=False,
        trusted_proxies=load_trusted_proxies(),
    )


def test_explicit_opt_out_allows_external_tls_bind():
    http_server._validate_server_bind_security(
        "0.0.0.0", authentication_required=False, tls_configured=True,
        allow_unauthenticated=True,
    )


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.0.2.10", "server.example.test"])
def test_secure_external_bind_is_preserved(host: str) -> None:
    http_server._validate_server_bind_security(
        host,
        authentication_required=True,
        tls_configured=True,
    )


def test_run_server_rejects_insecure_external_bind_before_runtime_work(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ADLOG_AUTH_REQUIRED", raising=False)
    monkeypatch.delenv("ADLOG_TLS_CERT_PATH", raising=False)
    monkeypatch.delenv("ADLOG_TLS_KEY_PATH", raising=False)

    touched: list[str] = []
    monkeypatch.setattr(http_server, "load_config", lambda: touched.append("database") or None)
    monkeypatch.setattr(http_server, "start_scheduler", lambda **_kwargs: touched.append("scheduler"))
    monkeypatch.setattr(
        http_server,
        "ProtectedHTTPServer",
        lambda *_args, **_kwargs: touched.append("listener"),
    )

    with pytest.raises(RuntimeError, match="non-loopback server bind requires"):
        http_server.run_server("0.0.0.0", 8080)

    assert touched == []


def test_tls_pair_is_validated_before_runtime_work(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ADLOG_AUTH_REQUIRED", "1")
    monkeypatch.setenv("ADLOG_TLS_CERT_PATH", "missing-cert.pem")
    monkeypatch.delenv("ADLOG_TLS_KEY_PATH", raising=False)
    monkeypatch.setattr(
        http_server,
        "load_config",
        lambda: pytest.fail("database bootstrap must not run before TLS validation"),
    )

    with pytest.raises(RuntimeError, match="must be set together"):
        http_server.run_server("0.0.0.0", 8080)


@pytest.mark.parametrize("host", ["127.0.0.1", "0.0.0.0"])
def test_startup_rejects_auth_disabled_without_opt_out_before_runtime(monkeypatch, host):
    monkeypatch.setenv("ADLOG_AUTH_REQUIRED", "0")
    monkeypatch.setattr(http_server, "load_config", lambda: pytest.fail("runtime must not start"))
    with pytest.raises(RuntimeError, match="ADLOG_ALLOW_UNAUTHENTICATED=1"):
        http_server.run_server(host, 8080)


def test_opt_out_is_logged_before_runtime_starts(monkeypatch):
    monkeypatch.setenv("ADLOG_AUTH_REQUIRED", "0")
    monkeypatch.setenv("ADLOG_ALLOW_UNAUTHENTICATED", "1")
    monkeypatch.setattr(http_server, "resolve_storage_route", lambda **kwargs: None)
    events = []
    monkeypatch.setattr(http_server, "log_event", lambda *args, **kwargs: events.append((args, kwargs)))

    def runtime_reached():
        raise RuntimeError("runtime_reached")

    monkeypatch.setattr(http_server, "load_config", runtime_reached)
    with pytest.raises(RuntimeError, match="runtime_reached"):
        http_server.run_server("127.0.0.1", 8080)
    assert events == [((
        "api", "authentication_disabled_opt_out",
        "WARNING: authentication explicitly disabled; unauthenticated access is enabled.",
    ), {"level": logging.WARNING})]


def test_opt_out_flag_alone_keeps_authentication_enabled(monkeypatch):
    monkeypatch.setenv("ADLOG_ALLOW_UNAUTHENTICATED", "1")
    assert auth_required()


def test_invalid_proxy_configuration_rejected_before_runtime(monkeypatch):
    monkeypatch.setenv("ADLOG_TRUSTED_PROXIES", "invalid")
    monkeypatch.setattr(http_server, "load_config", lambda: pytest.fail("runtime must not start"))
    with pytest.raises(RuntimeError, match="ADLOG_TRUSTED_PROXIES must contain valid"):
        http_server.run_server("127.0.0.1", 8080)

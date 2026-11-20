from __future__ import annotations

import json
import logging
import os
import hmac
import ipaddress
import re
import secrets
import socket
import ssl
import sys
import threading
import time
from collections import OrderedDict
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

from server.sli.reporting.dashboard_snapshot import warm_dashboard_snapshot_async
from server.sli.ops.logging_config import log_event, log_internal_error
from server.sli.storage.runtime_storage import StorageRouteConsumer, resolve_storage_route
from server.sli.core.app_config import AdLogConfig, load_config, require_postgres_runtime
from server.sli.access.auth import (
    allows,
    auth_opt_out,
    auth_required,
    ensure_auth_schema,
    principal_from_headers,
)
from server.sli.access.access_control_v4 import (
    capability_decision,
    effective_access,
    route_capability,
)
from server.sli.core.database import QueryTimeoutError
from server.sli.ops.system_health import warm_system_health_storage_async

from server.sli.reporting.ui_route_parity import react_route_for_legacy
from server.sli.sources.post_collection_pipeline import recover_stale_post_collection_jobs, cleanup_post_collection_jobs
from server.jobs.collector import (
    get_scheduler_runtime_status,
    external_post_collection_worker_enabled, inprocess_post_collection_opt_in_enabled,
    inprocess_scheduler_opt_in_enabled,
    resume_persisted_post_collection_jobs, start_scheduler,
)
from server.api.http_header_deadline import HeaderDeadlineMixin
from server.api.net_utils import is_loopback_bind_host
from server.api.proxy import Network, RequestContext, load_trusted_proxies, origin_matches, request_context
from server.api.errors import RequestInputError
from server.sli.core.messages import response_messages
from server.sli.core.report_domain import NOT_CONFIGURED_CODE, ReportDomainNotConfiguredError
from server.api.routes import health as routes_health
from server.api.routes import static as routes_static
from server.api.routes import plugin_ui as routes_plugin_ui
from server.api.routes import auth as routes_auth
from server.api.routes import access as routes_access
from server.api.routes import reports as routes_reports
from server.api.routes import reports_v2 as routes_reports_v2
from server.api.routes import events as routes_events
from server.api.routes import entities as routes_entities
from server.api.routes import objects as routes_objects
from server.api.routes import workspace as routes_workspace
from server.api.routes import investigations as routes_investigations
from server.api.routes import findings as routes_findings
from server.api.routes import operations as routes_operations
from server.api.routes import runtime as routes_runtime
from server.api.routes import diagnostics as routes_diagnostics
from server.api.routes import semantic as routes_semantic
from server.api.routes import ai as routes_ai
from server.api.routes import security_monitor as routes_security_monitor
from server.api.routes import legacy_reports as routes_legacy_reports
from server.api.routes import settings as routes_settings
from server.api.routes import notification_channels as routes_notification_channels
from server.api.routes import notification_outbox as routes_notification_outbox
from server.api.routes import decoys as routes_decoys
from server.api.routes import watch_entries as routes_watch
from server.api.routes import setup as routes_setup
from server.api.routes import agents as routes_agents
from server.api.routes import agent_packets as routes_agent_packets
from server.api.route_registry import RouteRegistry

# Модули маршрутов (ADR 0014, план 4.3). Порядок здесь не влияет на выбор
# обработчика: реестр выбирает самое точное совпадение по таблицам ROUTES.
ROUTE_MODULES = (
    routes_static, routes_plugin_ui, routes_health, routes_auth, routes_access, routes_reports_v2,
    routes_reports, routes_workspace, routes_events, routes_entities, routes_objects,
    routes_investigations, routes_findings, routes_operations, routes_runtime,
    routes_diagnostics, routes_semantic, routes_ai, routes_security_monitor,
    routes_legacy_reports, routes_settings, routes_notification_channels, routes_notification_outbox,
    routes_setup, routes_agent_packets, routes_agents, routes_decoys, routes_watch,
)
def create_app() -> RouteRegistry:
    """Create the HTTP dispatch application without sockets or database work."""
    return RouteRegistry(ROUTE_MODULES)


ROUTE_REGISTRY = create_app()


# 5,000 clients × three dynamic buckets, with headroom. No active key is
# evicted to make room: new identities receive the existing 429/60s retry.
MAX_RATE_CLIENT_BUCKETS = 16_384
RATE_STALE_CLEANUP_BATCH = 64

MAX_JSON_REQUEST_BYTES = 64 * 1024
JSON_BODY_TIMEOUT_SECONDS = 15
AGENT_PACKET_KEEPALIVE_SECONDS = 5
AGENT_PACKET_KEEPALIVE_REQUESTS = 16


_is_loopback_bind_host = is_loopback_bind_host


def _validate_server_bind_security(
    host: str,
    *,
    authentication_required: bool,
    tls_configured: bool,
    allow_unauthenticated: bool = False,
    trusted_proxies: tuple[Network, ...] = (),
) -> None:
    """Fail closed before runtime work when an external bind is insecure."""
    if not authentication_required and not allow_unauthenticated:
        raise RuntimeError(
            "disabling authentication requires ADLOG_AUTH_REQUIRED=0 and ADLOG_ALLOW_UNAUTHENTICATED=1"
        )
    if _is_loopback_bind_host(host):
        return
    if not tls_configured and not trusted_proxies:
        raise RuntimeError(
            "non-loopback server bind requires configured TLS or ADLOG_TRUSTED_PROXIES"
        )


def _load_server_tls_context() -> ssl.SSLContext | None:
    """Validate TLS configuration and load its context before runtime starts."""
    cert_path = _tls_file_path("ADLOG_TLS_CERT")
    key_path = _tls_file_path("ADLOG_TLS_KEY")
    if bool(cert_path) != bool(key_path):
        raise RuntimeError("ADLOG_TLS_CERT_PATH and ADLOG_TLS_KEY_PATH must be set together")
    if not cert_path:
        return None
    cert_file = Path(cert_path)
    key_file = Path(key_path)
    if not cert_file.is_file() or not key_file.is_file():
        raise RuntimeError("configured TLS certificate or key file was not found")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
    agent_ca_file = os.environ.get("SLI_AGENT_MTLS_CA_FILE", "").strip()
    if agent_ca_file:
        context.load_verify_locations(cafile=agent_ca_file)
        # UI/login and enrollment share the listener; only agent routes require
        # a certificate. OpenSSL still rejects any invalid presented certificate.
        context.verify_mode = ssl.CERT_OPTIONAL
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def _tls_file_path(name: str) -> str:
    """TLS libraries consume mounted files directly, never PEM environment values."""
    path = os.environ.get(f"{name}_PATH", "").strip()
    if f"{name}_FILE" not in os.environ:
        return path
    if path:
        raise RuntimeError("TLS path and file settings are mutually exclusive")
    filename = os.environ[f"{name}_FILE"].strip()
    if not filename:
        raise RuntimeError("configured TLS file is empty")
    return filename


def _request_rate_bucket(method: str, path: str) -> str | None:
    """Separate UI delivery from bounded dynamic request classes.

    A React page load legitimately fetches many local assets. Counting those
    files against the same per-client window as API calls can lock a person out
    of the login screen after an ordinary refresh. Concurrency still bounds
    every request; only dynamic routes consume a rate bucket.
    """
    normalized_method = str(method or "").upper()
    normalized_path = str(path or "")
    if normalized_method == "GET":
        if normalized_path in {
            "/",
            "/login",
            "/app",
            "/app/",
            "/app.css",
            "/app.js",
            "/admin.js",
            "/api/health",
            "/api/health/live",
            "/api/health/ready",
        }:
            return None
        if normalized_path.startswith("/app/") or routes_static._login_static_asset(normalized_path) is not None:
            return None
    if normalized_method == "POST" and normalized_path == "/api/auth/login":
        # All password attempts have a dedicated, stricter limiter.
        return None
    if normalized_path.startswith("/api/"):
        return "api"
    if normalized_path.startswith("/reports/"):
        return "reports"
    return "other"


# This map is enforced on the server.  Dashboard focus buttons may tailor a
# view, but they must never be the only barrier between a person and a report.
IT_ONLY_PATHS = {
    "/api/runtime/status", "/api/sources", "/api/domain-controllers", "/api/collector/health",
    "/api/system/health", "/api/storage/health", "/api/storage/lifecycle", "/api/db/status",
    "/api/diagnostics/overview",
    "/api/jobs", "/api/autocollection/status", "/api/logs/tail", "/reports/collector-health.html",
    "/reports/autocollection.html", "/reports/storage-health.html", "/reports/system-health.html",
    "/reports/db-status.html",
    "/reports/diagnostics.html",
    "/api/v1/operations/overview",
    "/api/v1/operations/plugins",
    "/api/v1/operations/administrative-activity",
    "/api/v1/source-packs",
    "/api/v1/source-adapters",
}


def _required_read_role(path: str) -> str:
    if path == "/admin" or path.startswith("/api/auth/users") or path.startswith("/api/auth/api-keys"):
        return "admin"
    if path in IT_ONLY_PATHS or path.startswith("/api/jobs/"):
        return "operator"
    return "viewer"


def _safe_request_path(value: str) -> str:
    """Return only the route component for logs and diagnostics."""
    return urlparse(str(value or "")).path


class ProtectedHTTPServer(ThreadingHTTPServer):
    """Bounded connection and request admission for a small monitoring service."""

    daemon_threads = True

    def __init__(
        self, address: tuple[str, int], handler: type[BaseHTTPRequestHandler],
        *, config: AdLogConfig | None = None,
    ) -> None:
        cfg = config or load_config()
        self.adlog_trusted_proxies = load_trusted_proxies()
        # IPv4 wildcard bind becomes one dual-stack listener where the OS allows it.
        self._dual_stack = (ipaddress.ip_address(address[0]) == ipaddress.IPv4Address(0)
                            and socket.has_dualstack_ipv6())
        if self._dual_stack:
            self.address_family = socket.AF_INET6
            address = ('::', address[1])
        elif ':' in address[0]:
            self.address_family = socket.AF_INET6
        super().__init__(address, handler)
        self.connection_slots = threading.BoundedSemaphore(cfg.http_max_connections)
        self.connection_lock = threading.Lock()
        self.connections: dict[socket.socket, bool] = {}
        self.tls_handshake_timeout_seconds = cfg.tls_handshake_timeout_seconds
        max_concurrent = max(4, min(int(os.environ.get("ADLOG_HTTP_MAX_CONCURRENT_REQUESTS", "32")), 128))
        self.request_slots = threading.BoundedSemaphore(max_concurrent)
        self.rate_per_minute = max(60, min(int(os.environ.get("ADLOG_HTTP_RATE_PER_MINUTE", "600")), 5000))
        self.rate_lock = threading.Lock()
        self.client_request_times: OrderedDict[tuple[str, str], list[float]] = OrderedDict()
        # A browser can legitimately refresh a page often. Keep login admission separate from
        # the general request limiter so an attacker cannot turn it into a
        # cheap denial of service against the whole UI.
        self.login_lock = threading.Lock()
        self.login_failure_window_seconds = max(60, min(int(os.environ.get("ADLOG_LOGIN_FAILURE_WINDOW_SECONDS", "900")), 3600))
        self.max_login_failures = max(3, min(int(os.environ.get("ADLOG_MAX_LOGIN_FAILURES", "8")), 30))
        self.login_attempts: dict[str, list[float]] = {}

    def server_bind(self):
        if self._dual_stack:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()

    def get_request(self):
        request, address = super().get_request()
        # Preserve IPv4 proxy trust, rate limits and audit identity on a
        # dual-stack listener; the socket peer must remain the trust anchor.
        peer = ipaddress.ip_address(address[0])
        if isinstance(peer, ipaddress.IPv6Address) and peer.ipv4_mapped:
            address = (str(peer.ipv4_mapped), address[1])
        return request, address

    def handle_error(self, request, client_address):
        # socketserver's default prints exception text, request peer and a
        # traceback, which can contain credentials. systemd captures stderr.
        error = sys.exc_info()[1]
        kind = type(error).__name__
        trace = error.__traceback__ if error is not None else None
        frames = []
        while trace is not None:
            frames.append(f'{trace.tb_frame.f_code.co_name}:{trace.tb_lineno}')
            trace = trace.tb_next
        location = ' > '.join(frames[-16:])
        log_event('api', 'http_request_failed', 'HTTP request/response failed.', level=logging.ERROR,
                  error_type=kind, failure_frames=location)
        print(f'http_request_failed: {kind} [{location}]', file=sys.stderr, flush=True)

    def admit_client(self, client: str, bucket: str) -> bool:
        key = (str(client), str(bucket))
        with self.rate_lock:
            # Sample under the lock so accepted timestamps and insertion order
            # agree even when request threads contend. One entry per key, no
            # growing expiration queue; cleanup examines at most 64 keys.
            now = time.monotonic()
            for _ in range(RATE_STALE_CLEANUP_BATCH):
                if not self.client_request_times:
                    break
                oldest = next(iter(self.client_request_times))
                if self.client_request_times[oldest][-1] > now - 60:
                    break
                self.client_request_times.popitem(last=False)
            if key not in self.client_request_times and len(self.client_request_times) >= MAX_RATE_CLIENT_BUCKETS:
                return False
            recent = [value for value in self.client_request_times.get(key, []) if value > now - 60]
            if len(recent) >= self.rate_per_minute:
                self.client_request_times[key] = recent
                return False
            recent.append(now)
            self.client_request_times[key] = recent
            self.client_request_times.move_to_end(key)
            return True

    def login_allowed(self, client: str) -> tuple[bool, int]:
        """Atomically reserve an attempt before password verification starts."""
        now = time.monotonic()
        with self.login_lock:
            for key, attempts in list(self.login_attempts.items()):
                recent = [value for value in attempts if value > now - self.login_failure_window_seconds]
                if recent:
                    self.login_attempts[key] = recent
                else:
                    del self.login_attempts[key]
            recent = self.login_attempts.get(client, [])
            if len(recent) >= self.max_login_failures:
                retry_after = max(1, int(self.login_failure_window_seconds - (now - recent[0])))
                return False, retry_after
            recent.append(now)
            self.login_attempts[client] = recent
            return True, 0

    def process_request(self, request, client_address):
        # Admission must precede ThreadingMixIn's worker creation, including
        # connections that have not sent any TLS or HTTP bytes yet.
        if not self.connection_slots.acquire(blocking=False):
            self.shutdown_request(request)
            log_event("api", "http_connection_limit_exceeded", "HTTP connection rejected: connection limit reached.")
            return
        try:
            with self.connection_lock:
                self.connections[request] = False
                if getattr(self, "sli_stopping", False):
                    self._wake_reader(request)
            super().process_request(request, client_address)
        except BaseException:
            with self.connection_lock:
                self.connections.pop(request, None)
            self.connection_slots.release()
            raise

    @staticmethod
    def _wake_reader(request):
        try:
            request.shutdown(socket.SHUT_RD)
        except OSError:
            pass

    def begin_shutdown(self):
        """Wake idle/header readers; admitted requests retain their transaction."""
        with self.connection_lock:
            self.sli_stopping = True
            for request, active in self.connections.items():
                if not active:
                    self._wake_reader(request)

    def admit_request(self, request):
        with self.connection_lock:
            if getattr(self, "sli_stopping", False):
                return False
            self.connections[request] = True
            return True

    def request_finished(self, request):
        with self.connection_lock:
            if request in self.connections:
                self.connections[request] = False
                if getattr(self, "sli_stopping", False):
                    self._wake_reader(request)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self.connection_lock:
                self.connections.pop(request, None)
            self.connection_slots.release()

    def finish_request(self, request, client_address):
        """Complete the TLS handshake inside the worker thread.

        ``get_request`` runs on the single accept loop, so performing the
        handshake there serialised every connection behind it.  The page is
        served over HTTP/1.0, meaning one connection — and one handshake — per
        asset, about a dozen per page load.  A browser opens spare connections
        it may never use; each of those stalled the accept loop until it gave
        up, so a quick second refresh left later assets unanswered and the page
        rendered black.  The plain HTTP copy never showed this because it has no
        handshake to serialise.

        Handshaking here costs a worker thread instead of the listener, so a
        client that connects and stays silent can no longer keep other clients
        from being accepted.  Connection admission bounds these workers, and
        a configurable 15–30 second handshake timeout (30 by default) gives
        browser spare connections more time than the former five second limit.
        Restore the socket's prior timeout before handling HTTP; this deadline
        applies only to the handshake. HTTP request lines and headers have a
        separate bounded grace period, including browser idle time afterwards.
        """
        context = getattr(self, "adlog_tls_context", None)
        if context is None:
            super().finish_request(request, client_address)
            return
        try:
            tls_request = context.wrap_socket(request, server_side=True, do_handshake_on_connect=False)
        except (ssl.SSLError, OSError):
            return
        try:
            with self.connection_lock:
                self.connections.pop(request, None)
                self.connections[tls_request] = False
                if getattr(self, "sli_stopping", False):
                    self._wake_reader(tls_request)
            previous_timeout = tls_request.gettimeout()
            try:
                tls_request.settimeout(self.tls_handshake_timeout_seconds)
                tls_request.do_handshake()
            except TimeoutError:
                log_event("api", "tls_handshake_timeout", "TLS connection closed: handshake timeout exceeded.")
                return
            except (ssl.SSLError, OSError):
                # A speaker of the wrong protocol is not an error worth logging
                # per connection; drop it and leave the listener untouched.
                return
            tls_request.settimeout(previous_timeout)
            super().finish_request(tls_request, client_address)
        finally:
            with self.connection_lock:
                self.connections.pop(tls_request, None)
            # wrap_socket detached the original request. socketserver will
            # later shut down that dead socket, so finish the live transport
            # here: SHUT_WR before close preserves queued response bytes.
            self.shutdown_request(tls_request)


class RequestHandler(HeaderDeadlineMixin, BaseHTTPRequestHandler):
    server_version = "ADLogReports/0.1"

    def handle_one_request(self):
        try:
            super().handle_one_request()
        finally:
            finished = getattr(self.server, "request_finished", None)
            if finished is not None:
                finished(self.connection)

    def parse_request(self) -> bool:
        # Persistence is negotiated again only after a committed packet ACK.
        # All other routes/errors retain the existing HTTP/1.0 close behavior.
        self.protocol_version = "HTTP/1.0"
        self._response_started = False
        # Keep the socket peer across requests: a forwarded client address must
        # never become the trust anchor for a subsequent keep-alive request.
        self._peer_address = getattr(self, "_peer_address", self.client_address)
        self.client_address = self._peer_address
        self._request_context = None
        self.headers = {}
        if not super().parse_request():
            return False
        # Candidate acceptance exposes health only. No login, import or ACK may
        # cross the fence before the package coordinator commits the release.
        if os.environ.get("SLI_NATIVE_UPGRADE_TESTING") == "1" and not (
            self.command == "GET" and self.path in {"/api/health/live", "/api/health/ready"}
        ):
            self.close_connection = True
            self.send_error(HTTPStatus.SERVICE_UNAVAILABLE, "service_updating")
            return False
        admit = getattr(self.server, "admit_request", None)
        admitted = admit(self.connection) if admit is not None else not getattr(self.server, "sli_stopping", False)
        if not admitted:
            self.close_connection = True
            self.send_error(HTTPStatus.SERVICE_UNAVAILABLE, "service_updating")
            return False
        context = self._external_request()
        # Domain audit and rate limit handlers already use client_address.
        self.client_address = (context.client_ip, self._peer_address[1])
        return True

    def _external_request(self) -> RequestContext:
        context = getattr(self, "_request_context", None)
        if context is None:
            peer = getattr(self, "_peer_address", getattr(self, "client_address", ("", 0)))[0]
            context = request_context(
                peer, getattr(self, "headers", {}),
                tls=bool(getattr(self.server, "adlog_tls_enabled", False)),
                trusted_proxies=getattr(self.server, "adlog_trusted_proxies", ()),
            )
            self._request_context = context
        return context

    @property
    def storage_route_authorization(self):
        """Expose the server-owned sealed route capability to domain handlers."""
        return getattr(self.server, "storage_route_authorization", None)

    def end_headers(self) -> None:
        # Security policy is emitted centrally so it covers generated reports,
        # API responses and static assets alike. HTML responses receive a
        # per-response nonce before headers are emitted. React still requires
        # bounded style attributes, but executable inline script and arbitrary
        # inline style blocks are not permitted.
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        # Reports describe a live operational state. A browser's back/forward
        # cache must not make an old report look like the current collection.
        # Static routes (routes/static.py) may override this for the SPA shell
        # and build assets via `_cache_control_override`; everything else,
        # including JSON/API responses, keeps no-store.
        override = getattr(self, "_cache_control_override", None)
        if override:
            self.send_header("Cache-Control", str(override))
        else:
            self.send_header("Cache-Control", "no-store, max-age=0")
        nonce = str(getattr(self, "_csp_nonce", "") or "")
        nonce_source = f" 'nonce-{nonce}'" if nonce else ""
        self.send_header(
            "Content-Security-Policy",
            f"default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; "
            f"img-src 'self' data:; style-src 'self'{nonce_source}; style-src-attr 'unsafe-inline'; "
            f"script-src 'self'{nonce_source}; script-src-attr 'none'",
        )
        if self._secure_transport():
            self.send_header("Strict-Transport-Security", "max-age=15552000; includeSubDomains")
        # Once a write may have reached the wire, a fallback HTTP response
        # would corrupt this response's Content-Length and status.
        self._response_started = True
        super().end_headers()

    def log_error(self, format: str, *args: object) -> None:
        # BaseHTTPRequestHandler contains socket timeouts here. Do not log
        # its interpolated text (which can include untrusted request data).
        self.server.handle_error(self.connection, self.client_address)

    def log_message(self, format: str, *args: object) -> None:
        # Do not persist login names, search text or other query values in the
        # technical access log.  Route, method and status are enough for ops.
        message = format % args
        parts = message.split()
        method = parts[0] if parts else "UNKNOWN"
        route = urlparse(parts[1]).path if len(parts) > 1 else ""
        status = parts[-2] if len(parts) >= 2 else ""
        log_event("api", "http_access", "HTTP request completed.", method=method, route=route, status=status)

    def do_GET(self) -> None:
        if not self._admit_request():
            return
        try:
            from contextlib import nullcontext

            from server.sli.reporting.read_timeout import report_read_budget

            path = urlparse(self.path).path
            report_read = path.startswith(("/api/v2/reports", "/api/v1/reports/", "/reports/")) or path == "/api/v1/home/summary"
            with report_read_budget() if report_read else nullcontext():
                self._do_GET()
        except RequestInputError as exc:
            self._send_json({"error": exc.code}, exc.status)
        except ReportDomainNotConfiguredError:
            self._send_report_domain_not_configured()
        except QueryTimeoutError:
            self._send_json({"error": "report_read_timeout", "state": "unavailable"}, HTTPStatus.SERVICE_UNAVAILABLE)
        except Exception as exc:
            if getattr(self, '_response_started', False):
                raise
            if getattr(exc, "sqlstate", None) == "57014":
                self._send_json({"error": "report_read_timeout", "state": "unavailable"}, HTTPStatus.SERVICE_UNAVAILABLE)
                return
            error_id = log_internal_error(
                "api", "request_failed", "GET request failed.",
                exc=exc, path=_safe_request_path(self.path),
            )
            self._send_json(
                {"error": "internal_server_error", "internal_error_id": error_id},
                HTTPStatus.INTERNAL_SERVER_ERROR,
            )
        finally:
            self.server.request_slots.release()

    def _do_GET(self) -> None:
        self._effective_access_cache = None
        parsed = urlparse(self.path)
        path = parsed.path
        # An empty collection scope is part of Sigma's exact source identity.
        # Preserve blanks only on this contract; other routes keep their parser.
        query = parse_qs(parsed.query, keep_blank_values=path == "/api/v1/semantic/sigma-rules")
        if not self._require_secure_api_transport(path):
            return
        if routes_health.try_handle_liveness_get(self, path):
            return
        if routes_auth.try_handle_account_get(self, path):
            return
        if routes_static.try_handle_login_get(self, path):
            return
        # This module owns both the explicit owner check and the independent
        # TLS peer authentication. User sessions cannot authenticate an agent.
        if routes_agents.try_handle_get(self, path, query):
            return
        if auth_required():
            if path not in {"/app.css", "/app.js", "/admin.js"}:
                principal = principal_from_headers(self.headers)
                if not principal:
                    if path.startswith("/api/"):
                        self._send_json({"error": "authentication_required"}, HTTPStatus.UNAUTHORIZED)
                    else:
                        # Browser navigation after an expired session belongs
                        # on the sign-in screen, not on a raw API error page.
                        self.send_response(HTTPStatus.FOUND)
                        self.send_header("Location", "/login?" + urlencode({"next": self.path}))
                        self.end_headers()
                    return
                required_role = _required_read_role(path)
                if not allows(principal, required_role):
                    if path.startswith("/api/"):
                        self._send_json({"error": "insufficient_permissions"}, HTTPStatus.FORBIDDEN)
                    else:
                        self.send_response(HTTPStatus.FOUND)
                        self.send_header("Location", "/")
                        self.end_headers()
                    return
                self._principal = principal
        capability = route_capability(path)
        resource_aware_investigation = routes_investigations.is_resource_aware(path)
        resource_aware_object = routes_objects.is_resource_aware(path)
        resource_aware_report = routes_reports.is_resource_aware(path) or routes_reports_v2.is_resource_aware(path) or routes_findings.is_resource_aware(path) or routes_decoys.is_resource_aware(path) or routes_watch.is_resource_aware(path)
        resource_aware_semantic = routes_semantic.is_resource_aware(path, query)
        if capability and not resource_aware_investigation and not resource_aware_object and not resource_aware_report and not resource_aware_semantic and not self._require_capability(capability):
            return
        if path.startswith("/api/") and capability is None:
            self._send_json({"error": "route_policy_unclassified"}, HTTPStatus.FORBIDDEN)
            return
        parity_target = react_route_for_legacy(path, query)
        if parity_target is not None:
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", parity_target)
            self.end_headers()
            return
        if ROUTE_REGISTRY.dispatch_get(self, path, query):
            return
        self._send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        if not self._admit_request():
            return
        try:
            self._do_POST()
        except RequestInputError as exc:
            self._send_json({"error": exc.code}, exc.status)
        except ReportDomainNotConfiguredError:
            self._send_report_domain_not_configured()
        except Exception as exc:
            if getattr(self, '_response_started', False):
                raise
            error_id = log_internal_error(
                "api", "request_failed", "POST request failed.",
                # Auth/DB failures may contain submitted credentials.
                exc=RuntimeError(type(exc).__name__), path=_safe_request_path(self.path),
            )
            self._send_json(
                {"error": "internal_server_error", "internal_error_id": error_id},
                HTTPStatus.INTERNAL_SERVER_ERROR,
            )
        finally:
            self.server.request_slots.release()

    def _send_report_domain_not_configured(self) -> None:
        """Honest installation state instead of a 500: the report domain is unset."""
        self._send_json(
            {
                "error": NOT_CONFIGURED_CODE,
                "message": "Домен отчётов не задан. Укажите его в разделе «Настройки платформы».",
            },
            HTTPStatus.SERVICE_UNAVAILABLE,
        )

    def do_PUT(self) -> None:
        if not self._admit_request():
            return
        try:
            self._do_PUT()
        except RequestInputError as exc:
            self._send_json({"error": exc.code}, exc.status)
        except Exception as exc:
            if getattr(self, '_response_started', False):
                raise
            error_id = log_internal_error(
                "api", "request_failed", "PUT request failed.",
                # Database errors can include stored or submitted values.
                exc=RuntimeError(type(exc).__name__), path=_safe_request_path(self.path),
            )
            self._send_json(
                {"error": "internal_server_error", "internal_error_id": error_id},
                HTTPStatus.INTERNAL_SERVER_ERROR,
            )
        finally:
            self.server.request_slots.release()

    def _do_PUT(self) -> None:
        self._effective_access_cache = None
        path = urlparse(self.path).path
        if not self._require_secure_api_transport(path):
            return
        if ROUTE_REGISTRY.dispatch_put(self, path):
            return
        if not self._authorize_mutation():
            return
        self._send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)

    def _admit_request(self) -> bool:
        if not self.server.request_slots.acquire(blocking=False):
            self._send_json({"error": "server_busy"}, HTTPStatus.TOO_MANY_REQUESTS)
            return False
        path = urlparse(self.path).path
        bucket = _request_rate_bucket(self.command, path)
        if bucket is not None and not self.server.admit_client(self.client_address[0], bucket):
            self.server.request_slots.release()
            self._send_json(
                {"error": "rate_limit_exceeded"},
                HTTPStatus.TOO_MANY_REQUESTS,
                headers={"Retry-After": "60"},
            )
            return False
        return True

    def _do_POST(self) -> None:
        self._effective_access_cache = None
        path = urlparse(self.path).path
        if not self._require_secure_api_transport(path):
            return
        if ROUTE_REGISTRY.dispatch_post(self, path):
            return
        if not self._authorize_mutation():
            return
        self._send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)

    @staticmethod
    def _public_principal(principal: dict) -> dict:
        return {key: principal[key] for key in ("type", "id", "username", "label", "role") if key in principal}

    def _require_access(self, required_role: str) -> bool:
        principal = principal_from_headers(self.headers)
        if not principal:
            self._send_json({"error": "authentication_required"}, HTTPStatus.UNAUTHORIZED)
            return False
        if not allows(principal, required_role):
            self._send_json({"error": "insufficient_permissions"}, HTTPStatus.FORBIDDEN)
            return False
        self._principal = principal
        return True

    def _require_capability(self, capability: str, *, resource: dict[str, Any] | None = None) -> bool:
        principal = getattr(self, "_principal", None)
        if auth_required() and principal is None:
            principal = principal_from_headers(self.headers)
            if not principal:
                self._send_json({"error": "authentication_required"}, HTTPStatus.UNAUTHORIZED)
                return False
            self._principal = principal
        decision = capability_decision(self._access_decision(), capability, resource=resource)
        if not decision["allowed"]:
            self._send_json({
                "error": str(decision["reason"]),
                "required_capability": capability,
            }, HTTPStatus.FORBIDDEN)
            return False
        return True

    def _access_decision(self) -> dict[str, Any]:
        cached = getattr(self, "_effective_access_cache", None)
        if cached is None:
            from server.sli.access.auth import session_token_from_cookie
            from server.sli.access.session_access_cache import session_access

            cached = session_access(
                getattr(self, "_principal", None),
                session_token_from_cookie(getattr(self, "headers", {}).get("Cookie")),
                effective_access,
            )
            self._effective_access_cache = cached
        return cached

    def _audit_actor(self) -> tuple[str, int | None]:
        principal = getattr(self, "_principal", {})
        actor_id = principal.get("id")
        return str(principal.get("type") or "session"), int(actor_id) if actor_id is not None else None

    def _send_json_with_cookie(self, payload: dict, cookie: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload, ensure_ascii=False, indent=2, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _secure_transport(self) -> bool:
        return self._external_request().scheme == "https"

    def _require_secure_api_transport(self, path: str) -> bool:
        """Proxy deployments require HTTPS before any API authentication/read."""
        if path.startswith("/api/") and getattr(getattr(self, "server", None), "adlog_trusted_proxies", ()) and not self._secure_transport():
            self._send_json({"error": "secure_transport_required"}, HTTPStatus.FORBIDDEN)
            return False
        from server.sli.access.report_api_key import (
            exact_event_allowed,
            request_allowed,
        )

        headers = getattr(self, "headers", {})
        has_key = str(headers.get("Authorization", "")).lower().startswith("bearer ") or headers.get("X-ADLog-API-Key")
        if has_key:
            principal = principal_from_headers(headers)
            if not request_allowed(principal, self.command, path):
                self._send_json({"error": "report_key_route_denied"}, HTTPStatus.FORBIDDEN)
                return False
            if not exact_event_allowed(principal, path):
                self._send_json({"error": "event_not_found"}, HTTPStatus.NOT_FOUND)
                return False
            if principal and principal.get("report_subject_id") is not None:
                self._principal = principal
        return True

    def _check_request_origin(self) -> bool:
        origin = self.headers.get("Origin")
        get_all = getattr(self.headers, "get_all", None)
        duplicate = get_all is not None and len(get_all("Origin", [])) > 1
        if duplicate or (origin is not None and not origin_matches(origin, self._external_request())):
            self._send_json({"error": "cross_origin_request_rejected"}, HTTPStatus.FORBIDDEN)
            return False
        return True

    def _authorize_mutation(self, *, required_role: str = "operator") -> bool:
        """Protect state-changing API calls without restricting report viewing.

        A same-origin browser request is required when an Origin header is
        present.  Operators can additionally set ADLOG_OPERATOR_TOKEN; then
        every changing request must provide it in X-ADLog-Operator-Token.
        The token is never logged or returned.
        """
        if not self._check_request_origin():
            return False

        if auth_required():
            return self._require_access(required_role)

        expected_token = os.environ.get("ADLOG_OPERATOR_TOKEN", "").strip()
        if expected_token:
            supplied_token = self.headers.get("X-ADLog-Operator-Token", "")
            if not hmac.compare_digest(supplied_token, expected_token):
                self._send_json({"error": "operator_token_required"}, HTTPStatus.UNAUTHORIZED)
                return False
        return True

    def _read_json_body(self, *, max_bytes: int = MAX_JSON_REQUEST_BYTES) -> dict:
        if self.headers.get("Transfer-Encoding"):
            self.close_connection = True
            raise RequestInputError("unsupported_transfer_encoding")
        raw_length = self.headers.get("Content-Length") or "0"
        try:
            length = int(raw_length)
        except ValueError as exc:
            self.close_connection = True
            raise RequestInputError("invalid_content_length") from exc
        if length < 0:
            self.close_connection = True
            raise RequestInputError("invalid_content_length")
        if length == 0:
            return {}
        if length > max_bytes:
            self.close_connection = True
            raise RequestInputError("request_body_too_large", HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
        content_type = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            self.close_connection = True
            raise RequestInputError("json_content_type_required", HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
        deadline = time.monotonic() + JSON_BODY_TIMEOUT_SECONDS
        previous_timeout = self.connection.gettimeout()
        raw = bytearray()
        try:
            while len(raw) < length:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError()
                self.connection.settimeout(min(remaining, previous_timeout) if previous_timeout is not None else remaining)
                # read1 performs at most one socket read, so a trickle cannot
                # restart the total body deadline inside a buffered read().
                chunk = self.rfile.read1(length - len(raw))
                if time.monotonic() >= deadline:
                    raise TimeoutError()
                if not chunk:
                    self.close_connection = True
                    raise RequestInputError("request_body_incomplete")
                raw.extend(chunk)
        except TimeoutError:
            self.close_connection = True
            raise RequestInputError("request_body_timeout", HTTPStatus.REQUEST_TIMEOUT) from None
        finally:
            self.connection.settimeout(previous_timeout)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RequestInputError("invalid_json") from exc
        if not isinstance(payload, dict):
            raise RequestInputError("json_object_required")
        return payload

    def _send_json(self, payload: dict, status: HTTPStatus = HTTPStatus.OK, *, headers: dict[str, str] | None = None) -> None:
        path = urlparse(self.path).path
        payload = response_messages(payload, self.headers.get("Accept-Language"), request_path=path,
                                      login=path == "/api/auth/login", report=path.startswith("/api/v2/reports/"),
                                      investigation=path == "/api/v1/investigation-cases" or path == "/api/v1/investigations" or path.startswith("/api/v1/investigations/"))
        body = json.dumps(payload, ensure_ascii=False, indent=2, default=str).encode("utf-8")
        lengths = self.headers.get_all("Content-Length", []) if hasattr(self.headers, "get_all") else []
        if (path == "/api/v1/agent/packets" and self.command == "POST"
                and not getattr(self.server, "sli_stopping", False)
                and status == HTTPStatus.OK and payload.get("contract_id") == "sli.agent-receipt.v1"
                and payload.get("status") in ("committed", "duplicate")
                and self.request_version == "HTTP/1.1"
                and self.headers.get("Connection", "").lower() == "keep-alive"
                and len(lengths) == 1 and not self.headers.get("Transfer-Encoding")):
            count = getattr(self, "_packet_requests", 0) + 1
            self._packet_requests = count
            if count < AGENT_PACKET_KEEPALIVE_REQUESTS:
                self.protocol_version = "HTTP/1.1"
                self.close_connection = False
                self.connection.settimeout(AGENT_PACKET_KEEPALIVE_SECONDS)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


    def _send_html(self, html_text: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        nonce = secrets.token_urlsafe(24)
        self._csp_nonce = nonce
        secured_html = re.sub(
            r"<(script|style)(?![^>]*\bnonce=)(?=[\s>])",
            lambda match: f'<{match.group(1)} nonce="{nonce}"',
            html_text,
            flags=re.IGNORECASE,
        )
        body = secured_html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path: Path, content_type: str) -> None:
        if not path.is_file():
            self._send_json({"error": "file_not_found"}, HTTPStatus.NOT_FOUND)
            return
        body = path.read_bytes()
        if content_type.lower().startswith("text/html"):
            try:
                self._send_html(body.decode("utf-8"))
            except UnicodeDecodeError:
                self._send_json({"error": "invalid_html_encoding"}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run_server(
    host: str,
    port: int,
    *,
    storage_route_authorization: object | None = None,
) -> None:
    tls_context = _load_server_tls_context()
    trusted_proxies = load_trusted_proxies()
    authentication_required = auth_required()
    _validate_server_bind_security(
        host,
        authentication_required=authentication_required,
        tls_configured=tls_context is not None,
        allow_unauthenticated=auth_opt_out(),
        trusted_proxies=trusted_proxies,
    )
    if not authentication_required:
        log_event(
            "api", "authentication_disabled_opt_out",
            "WARNING: authentication explicitly disabled; unauthenticated access is enabled.",
            level=logging.WARNING,
        )
    # Reject an invalid or V1 rollback authority before schema or durable-job work.
    resolve_storage_route(
        authorization=storage_route_authorization,
        consumer=StorageRouteConsumer.FINDINGS,
    )
    cfg = require_postgres_runtime(load_config())
    restore_smoke_mode = os.environ.get("ADLOG_RESTORE_SMOKE_MODE", "0").strip().lower() in {"1", "true", "yes", "on"}
    log_event(
        "database",
        "bootstrap_skipped",
        "SQLite schema bootstrap skipped for PostgreSQL runtime.",
        backend=cfg.db_backend,
    )
    if (cfg.db_backend or "postgres").strip().lower() == "postgres" and not restore_smoke_mode:
        from server.sli.core.postgres_runtime_pipeline import ensure_cursor_audit_schema_pg
        from server.sli.semantic.findings_pg_pipeline import ensure_findings_pg_schema
        from server.sli.storage.storage_lifecycle import ensure_storage_lifecycle_schema

        ensure_cursor_audit_schema_pg()
        ensure_auth_schema()
        findings_state = (
            ensure_findings_pg_schema(bootstrap_to_current=True)
            if storage_route_authorization is None
            else ensure_findings_pg_schema(
                bootstrap_to_current=True,
                authorization=storage_route_authorization,
            )
        )
        storage_schema = ensure_storage_lifecycle_schema()
        recovery = recover_stale_post_collection_jobs()
        # scripts/runtime/post_collection_worker.py is the sole designated
        # production owner of post-collection; resuming persisted jobs
        # in-process on startup is the same rollback/diagnostic path as the
        # in-process executor itself, so it needs the same explicit opt-in
        # instead of running whenever the external worker happens to be off.
        if external_post_collection_worker_enabled():
            resumed = {"claimed": 0, "resumed": 0, "reason": "external_post_collection_worker"}
        elif not inprocess_post_collection_opt_in_enabled():
            resumed = {"claimed": 0, "resumed": 0, "reason": "inprocess_post_collection_not_opted_in"}
        else:
            resume_limit = max(1, int(os.environ.get("ADLOG_POST_COLLECTION_RESUME_LIMIT", "1")))
            resumed = (
                resume_persisted_post_collection_jobs(limit=resume_limit)
                if storage_route_authorization is None
                else resume_persisted_post_collection_jobs(
                    limit=resume_limit,
                    authorization=storage_route_authorization,
                )
            )
        cleaned = cleanup_post_collection_jobs()
        log_event(
            "collector", "post_collection_recovery",
            "Post-collection persisted state checked on startup.",
            recovery=recovery, resumed=resumed, cleaned=cleaned,
            findings_watermark=findings_state.get("last_event_id"),
            storage_snapshot_count=storage_schema.get("snapshot_count"),
            web_sessions_preserved=True,
        )
    elif restore_smoke_mode:
        log_event(
            "database",
            "restore_smoke_startup",
            "Restore smoke mode: startup recovery and schema-changing helpers are skipped.",
            backend=cfg.db_backend,
        )
    log_event("api", "server_starting", "HTTP server starting.", path=f"http://{host}:{port}")
    interval_seconds = int(os.environ.get("ADLOG_COLLECTOR_INTERVAL_SECONDS", os.environ.get("ADLOG_COLLECTION_INTERVAL_SECONDS", "600")))
    # The in-process scheduler is a rollback/diagnostic path, not a normal part
    # of server startup: collection_worker.py is the sole designated production
    # owner of collection.  Normal boot never calls start_scheduler() at all;
    # only an explicit opt-in does.
    if inprocess_scheduler_opt_in_enabled():
        scheduler_status = start_scheduler(interval_seconds=interval_seconds)
    else:
        scheduler_status = get_scheduler_runtime_status()
    server = ProtectedHTTPServer((host, port), RequestHandler, config=cfg)
    server.storage_route_authorization = storage_route_authorization
    if tls_context is not None:
        server.adlog_tls_context = tls_context
        server.adlog_tls_enabled = True
    else:
        server.adlog_tls_enabled = False
    if not restore_smoke_mode:
        warm_dashboard_snapshot_async()
    warm_system_health_storage_async()
    scheme = "https" if server.adlog_tls_enabled else "http"
    print(f"AD log reports server: {scheme}://{host}:{port}")
    print("Collector mode: real read-only")
    if scheduler_status.get("scheduler_enabled"):
        print(f"Schedule: every {interval_seconds} seconds; continuous recovery may run immediate cycles while backlog exists")
    else:
        print(f"Schedule: disabled ({scheduler_status.get('disabled_reason')})")
    from server.sli.ops.shutdown import http_shutdown

    with http_shutdown(server):
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("Stopping server...")
        finally:
            server.server_close()
            log_event("api", "server_stopped", "HTTP server stopped.")

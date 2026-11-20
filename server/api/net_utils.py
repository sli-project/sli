"""Tiny shared HTTP-adjacent utilities with no dependency on RequestHandler.

Exists so that both `server.api.http_server` (server startup / bind
security) and a domain module in `server.api.routes` (which must not import
`server.api.http_server`, to avoid a domain_routes -> http_server ->
domain_routes cycle) can use the same predicate without duplicating it.
"""
from __future__ import annotations

import ipaddress


def is_loopback_bind_host(host: str) -> bool:
    """Return whether *host* can only expose the service on loopback."""
    candidate = str(host or "").strip().lower()
    if candidate in {"localhost", "localhost."}:
        return True
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    # Scoped IPv6 loopback addresses are still local.  Avoid DNS resolution:
    # an arbitrary hostname must be treated as externally reachable.
    candidate = candidate.split("%", 1)[0]
    try:
        return ipaddress.ip_address(candidate).is_loopback
    except ValueError:
        return False

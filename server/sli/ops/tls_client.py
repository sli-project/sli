"""TLS policy for local operator HTTP clients."""
from __future__ import annotations

import ipaddress
import ssl
from urllib.parse import urlparse


def _is_loopback_host(hostname: str | None) -> bool:
    host = str(hostname or "").strip().casefold()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def tls_context_for_url(url: str, *, insecure: bool = False) -> ssl.SSLContext | None:
    """Use normal certificate verification unless loopback bypass is explicit."""
    parsed = urlparse(url)
    if parsed.scheme.casefold() != "https":
        if insecure:
            raise ValueError("insecure_tls_requires_https_loopback_url")
        return None
    if not insecure:
        return None
    if not _is_loopback_host(parsed.hostname):
        raise ValueError("insecure_tls_is_limited_to_loopback")
    return ssl._create_unverified_context()

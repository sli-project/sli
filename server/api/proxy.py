"""Resolve request metadata only from explicitly trusted proxy peers.

The edge proxy must overwrite X-Forwarded-Host and X-Forwarded-Proto. For
X-Forwarded-For, walk from the socket peer towards the client and stop at the
first untrusted hop; attacker-supplied prefixes cannot select the client IP.
"""
from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from typing import Mapping
from urllib.parse import urlsplit

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def load_trusted_proxies() -> tuple[Network, ...]:
    value = os.environ.get("ADLOG_TRUSTED_PROXIES", "").strip()
    if not value:
        return ()
    try:
        return tuple(ipaddress.ip_network(item.strip(), strict=True) for item in value.split(","))
    except ValueError:
        # Configuration values may contain private addresses: never echo them.
        raise RuntimeError("ADLOG_TRUSTED_PROXIES must contain valid CIDRs or IP addresses") from None


def _trusted(address: str, networks: tuple[Network, ...]) -> bool:
    try:
        candidate = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(candidate in network for network in networks)


def _single_header(headers: Mapping[str, str], name: str) -> str:
    get_all = getattr(headers, "get_all", None)
    if get_all is not None and len(get_all(name, [])) > 1:
        return ""
    return str(headers.get(name) or "").strip()


def canonical_origin(scheme: str, host: str) -> str:
    """Validate an HTTP authority and normalize its default port for CSRF."""
    if scheme not in {"http", "https"} or not re.fullmatch(r"[A-Za-z0-9.\-_:\[\]]+", host):
        return ""
    try:
        parsed = urlsplit(f"{scheme}://{host}")
        hostname = parsed.hostname
        port = parsed.port
        if not hostname or parsed.username is not None or parsed.password is not None:
            return ""
        if ":" in hostname:
            ipaddress.IPv6Address(hostname)
            hostname = f"[{hostname}]"
        elif not re.fullmatch(r"[A-Za-z0-9_\-]+(?:\.[A-Za-z0-9_\-]+)*\.?", hostname):
            return ""
        if port is not None and port != (443 if scheme == "https" else 80):
            hostname += f":{port}"
        return f"{scheme}://{hostname.lower()}"
    except ValueError:
        return ""


@dataclass(frozen=True)
class RequestContext:
    client_ip: str
    scheme: str
    host: str

    @property
    def origin(self) -> str:
        return canonical_origin(self.scheme, self.host)


def request_context(
    peer: str, headers: Mapping[str, str], *, tls: bool, trusted_proxies: tuple[Network, ...],
) -> RequestContext:
    scheme = "https" if tls else "http"
    host = _single_header(headers, "Host")
    client = peer
    if _trusted(peer, trusted_proxies):
        forwarded_proto = _single_header(headers, "X-Forwarded-Proto").lower()
        if forwarded_proto in {"http", "https"}:
            scheme = forwarded_proto
        forwarded_host = _single_header(headers, "X-Forwarded-Host")
        if canonical_origin(scheme, forwarded_host):
            host = forwarded_host
        forwarded_for = _single_header(headers, "X-Forwarded-For")
        if forwarded_for and len(forwarded_for) <= 4096:
            hops = forwarded_for.split(",")
            try:
                addresses = [str(ipaddress.ip_address(hop.strip())) for hop in hops] if len(hops) <= 32 else []
            except ValueError:
                addresses = []
            for address in reversed(addresses):
                if not _trusted(client, trusted_proxies):
                    break
                client = address
        elif "X-Forwarded-For" not in headers:
            # XFF, including malformed/duplicate XFF, takes precedence. The
            # trusted edge must overwrite X-Real-IP when using this fallback.
            real_ip = _single_header(headers, "X-Real-IP")
            try:
                client = str(ipaddress.ip_address(real_ip))
            except ValueError:
                pass
    return RequestContext(client, scheme, host)


def origin_matches(origin: str, context: RequestContext) -> bool:
    if re.search(r"\s", origin):
        return False
    try:
        parsed = urlsplit(origin)
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            return False
        normalized = canonical_origin(parsed.scheme, parsed.netloc)
        return bool(normalized) and normalized == context.origin
    except ValueError:
        return False

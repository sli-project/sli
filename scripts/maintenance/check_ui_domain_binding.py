"""Reject installation-specific DNS/IP literals in UI and API sources.

Reserved example namespaces are fixtures, not installation defaults. External
service/documentation hosts and non-DNS language identifiers are listed exactly;
neither a public suffix nor a whole source file is exempted. Diagnostics contain
only paths, line numbers and categories, never matched installation data.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
SOURCE_SUFFIXES = {".py", ".ts", ".tsx", ".js", ".jsx", ".json", ".css", ".html", ".cs"}
# Include private DNS suffixes as well as the public suffixes used in literals.
DNS = re.compile(
    r"(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+"
    r"(?:local|lan|internal|corp|home|ru|su|com|net|org|io|dev|biz|xyz|"
    r"cloud|uk|de|fr|us|cn|edu|example|test|invalid)(?![\w.-])",
    re.IGNORECASE,
)
URL = re.compile(r"https?://[^\s\"'<>`{}$&]+", re.IGNORECASE)
# Configuration literals and email addresses may use any DNS suffix.
HOST_VALUE = re.compile(
    r"\b(?:domain|default_?domain|report_?domain|domain_?fqdn|fqdn|host(?:name)?|connect_address|source_endpoint)"
    r"[\"']?\s*[:=]\s*[\"'](?P<host>[a-z0-9-]+(?:\.[a-z0-9-]+)+)\.?[\"']",
    re.IGNORECASE,
)
EMAIL_HOST = re.compile(r"[\w.+-]+@(?P<host>[a-z0-9-]+(?:\.[a-z0-9-]+)+)", re.IGNORECASE)
IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
FIXTURE_ROOTS = {"example", "example.com", "example.net", "example.org", "test", "invalid"}
PUBLIC_HOSTS = {
    "api.openai.com", "api.telegram.org", "learn.microsoft.com",
    "schemas.microsoft.com", "manifests.microsoft.com", "www.w3.org", "raw.githubusercontent.com",
}
NON_HOST_IDENTIFIERS = {
    "frontend/src/i18n/ru.ts": {"shell.profile.language.ru", "login.language.ru"},
    "frontend/src/i18n/en.ts": {"shell.profile.language.ru", "login.language.ru"},
    "server-dotnet/src/Sli.Server/Legacy/report-template.html": {"dictionary.ru"},
}
DOCUMENTATION_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
))


def allowed_host(host: str) -> bool:
    host = host.lower().rstrip(".")
    if host in PUBLIC_HOSTS or host in {"localhost", "*"}:
        return True
    if any(host == root or host.endswith("." + root) for root in FIXTURE_ROOTS):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_loopback or address.is_unspecified or any(address in network for network in DOCUMENTATION_NETWORKS)


def findings(path: str, source: str) -> list[str]:
    result = []
    for number, line in enumerate(source.splitlines(), 1):
        if path.endswith(".cs") and re.fullmatch(r"\s*(?:global )?using (?:static )?[\w.]+(?:\s*=\s*[\w.]+)?;\s*", line):
            continue
        if path.endswith(".cs"):
            line = re.sub(r'(?<=ReadObjectIdentifier\(\) != ")\d+(?:\.\d+)+(?![.\d])(?=")', "", line)
            line = re.sub(r"\bTimeZoneInfo\.Local\b", "", line)
        hosts = {match.group() for match in DNS.finditer(line)}
        hosts.update(match.group() for match in IPV4.finditer(line))
        hosts.update(match["host"] for match in HOST_VALUE.finditer(line))
        hosts.update(match["host"] for match in EMAIL_HOST.finditer(line))
        # URLs catch arbitrary public suffixes, not just the DNS suffixes above.
        for match in URL.finditer(line):
            if match.group() in {"http://[", "https://HOST[:PORT]."}:
                continue  # IPv6 prefix and CLI usage placeholders.
            try:
                hosts.add(urlsplit(match.group().replace(r"\.", ".")).hostname or "")
            except ValueError:
                result.append(f"{path}:{number}:invalid_host")
        identifiers = NON_HOST_IDENTIFIERS.get(path, set())
        if path.endswith(".cs"):
            identifiers = identifiers | {"ASP.NET", "SS.US"}
        if any(host not in identifiers and not allowed_host(host) for host in hosts):
            result.append(f"{path}:{number}:embedded_host")
    return result


def scan(root: Path) -> list[str]:
    result = []
    for base in ("frontend/src", "server-dotnet/src"):
        for path in sorted((root / base).rglob("*")):
            if {"bin", "obj", "node_modules", "__pycache__"}.intersection(path.relative_to(root / base).parts):
                continue
            if path.suffix not in SOURCE_SUFFIXES or not path.is_file():
                continue
            result.extend(findings(path.relative_to(root).as_posix(), path.read_text(encoding="utf-8")))
    return result


if __name__ == "__main__":
    violations = scan(ROOT)
    print("\n".join(violations) if violations else "UI-DOMAIN-BINDING: passed")
    raise SystemExit(bool(violations))

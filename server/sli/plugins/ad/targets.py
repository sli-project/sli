from __future__ import annotations

from collections.abc import Callable
import ipaddress
import json
import os
import re
import socket
import subprocess
import threading
import time

from server.sli.core import database
from server.sli.core.database import get_sources
from server.sli.core.paths import CONFIG_DIR


class DomainControllerConfigurationError(RuntimeError):
    """Raised when a configured DC endpoint could bypass its DNS authority."""


_DB_CACHE_SECONDS = 10.0
_db_lock = threading.Lock()
_db_cache: tuple[float, list[dict] | None] | None = None


def _query_target_rows() -> list[dict]:
    return database.query_rows(
        "select hostname, connect_address, host(owner_confirmed_ip) as owner_confirmed_ip, enabled "
        "from domain_controller_targets order by lower(hostname)"
    )


def clear_database_target_cache() -> None:
    global _db_cache
    with _db_lock:
        _db_cache = None


def _load_database_rows() -> list[dict] | None:
    """All stored targets (enabled or not), or None if the table is unreadable.

    Cached for a few seconds because the collector resolves every server. An
    unmigrated table, a process without a database or an outage fall back to
    the file instead of failing collection.
    """
    global _db_cache
    now = time.monotonic()
    with _db_lock:
        if _db_cache is not None and _db_cache[0] > now:
            return _db_cache[1]
    try:
        rows: list[dict] | None = [dict(row) for row in _query_target_rows()]
    except Exception:  # noqa: BLE001 - table absent or database unavailable
        rows = None
    with _db_lock:
        _db_cache = (now + _DB_CACHE_SECONDS, rows)
    return rows


def domain_controller_target_source() -> str:
    """``db`` once targets are stored in the database, else ``file`` or ``none``."""
    if _load_database_rows():
        return "db"
    return "file" if (CONFIG_DIR / "domain_controllers.json").is_file() else "none"


def stored_enabled_targets() -> list[dict] | None:
    """Enabled stored targets, or None while the table is empty or unreadable."""
    stored = _load_database_rows()
    if not stored:
        return None
    return [row for row in stored if row.get("enabled")]


def read_file_targets() -> list[dict[str, str]]:
    """Targets of config/domain_controllers.json (for the one-shot import)."""
    return _targets_from_config_file()


def get_configured_domain_controller_targets() -> list[dict[str, str]]:
    """Return logical DC names with FQDN connection addresses.

    Source order (owner decision 2026-10-02): enabled rows of the
    ``domain_controller_targets`` table once it holds any row (disabling every
    row means no targets, not a fallback); otherwise, during the transition,
    config/domain_controllers.json, for example
    ``{"domain_controllers": [{"hostname": "DC1", "connect_address": "dc1.example.test", "owner_confirmed_ip": "198.51.100.23"}]}``.

    The logical ``hostname`` is kept for DB/report naming; ``connect_address`` is
    the authoritative remote Event Log FQDN. Literal IP endpoints are rejected
    so an old address cannot bypass DNS. ``owner_confirmed_ip`` is optional
    DNS-readback evidence, never a connection endpoint.
    """
    _reject_environment_endpoint_overrides()
    targets: list[dict[str, str]] = []
    seen: set[str] = set()

    stored = stored_enabled_targets()
    for item in _targets_from_config_file() if stored is None else stored:
        _append_target(
            targets,
            seen,
            item["hostname"],
            item["connect_address"],
            item.get("owner_confirmed_ip") or "",
        )

    return targets


def _append_target(
    targets: list[dict[str, str]],
    seen: set[str],
    hostname: str,
    connect_address: str,
    owner_confirmed_ip: str = "",
) -> None:
    hostname = _clean_hostname(hostname)
    connect_address = _clean_connect_address(connect_address or hostname)
    if hostname and hostname.lower() not in seen:
        target = {"hostname": hostname, "connect_address": connect_address or hostname}
        if owner_confirmed_ip:
            target["owner_confirmed_ip"] = _clean_owner_confirmed_ip(owner_confirmed_ip)
        targets.append(target)
        seen.add(hostname.lower())


def _targets_from_config_file() -> list[dict[str, str]]:
    path = CONFIG_DIR / "domain_controllers.json"
    if not path.is_file():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return []

    targets: list[dict[str, str]] = []
    for item in payload.get("domain_controllers") or []:
        if isinstance(item, str):
            hostname = _clean_hostname(item)
            connect_address = hostname
            owner_confirmed_ip = ""
        elif isinstance(item, dict):
            hostname = _clean_hostname(str(item.get("hostname") or item.get("name") or ""))
            connect_address = _clean_connect_address(
                item.get("connect_address")
                or item.get("address")
                or item.get("ip")
                or hostname
            )
            owner_confirmed_ip = str(item.get("owner_confirmed_ip") or "")
        else:
            continue
        if hostname:
            target = {"hostname": hostname, "connect_address": connect_address or hostname}
            if owner_confirmed_ip:
                target["owner_confirmed_ip"] = _clean_owner_confirmed_ip(owner_confirmed_ip)
            targets.append(target)
    return targets


def resolve_domain_controller_connect_address(hostname: str) -> str:
    requested = _clean_hostname(hostname)
    targets = get_configured_domain_controller_targets()
    for target in targets:
        if target["hostname"].lower() == requested.lower():
            _verify_target_dns_readback(target)
            return target["connect_address"]
    if domain_controller_target_source() != "none":
        raise DomainControllerConfigurationError(
            f"DC server {hostname!r} is not configured in the endpoint contract"
        )
    return hostname


def verify_configured_domain_controller_dns_readback(
    *,
    resolver: Callable[[str], tuple[str, list[str], list[str]]] = socket.gethostbyname_ex,
) -> list[dict[str, str]]:
    """Fail closed when a configured FQDN no longer resolves to its attested IP."""
    targets = get_configured_domain_controller_targets()
    for target in targets:
        _verify_target_dns_readback(target, resolver=resolver)
    return targets


def _verify_target_dns_readback(
    target: dict[str, str],
    *,
    resolver: Callable[[str], tuple[str, list[str], list[str]]] = socket.gethostbyname_ex,
) -> None:
    expected_ip = target.get("owner_confirmed_ip")
    if not expected_ip:
        return
    connect_address = target["connect_address"]
    try:
        _name, _aliases, addresses = resolver(connect_address)
    except OSError as exc:
        raise DomainControllerConfigurationError(
            f"DNS readback failed for configured DC endpoint {connect_address}"
        ) from exc
    resolved = {_clean_owner_confirmed_ip(address) for address in addresses}
    if expected_ip not in resolved:
        raise DomainControllerConfigurationError(
            f"DNS readback mismatch for configured DC endpoint {connect_address}"
        )


def discover_domain_controllers() -> list[str]:
    configured = _discover_from_config()
    if configured:
        return configured

    if domain_controller_target_source() != "none":
        return []

    configured = _discover_from_env()
    if configured:
        return configured

    discovered = _discover_with_directory_services()
    if discovered:
        return discovered

    for domain in _domain_candidates():
        discovered = _discover_with_nltest(domain)
        if discovered:
            return discovered

    from_db = [item["hostname"] for item in get_sources() if item.get("role") == "domain_controller"]
    if from_db:
        return sorted(set(from_db))

    logon_server = (os.environ.get("LOGONSERVER") or "").lstrip("\\")
    if logon_server:
        return [logon_server]

    return []


def _discover_from_env() -> list[str]:
    raw = os.environ.get("ADLOG_DOMAIN_CONTROLLERS") or ""
    names = [item.strip().lstrip("\\") for item in re.split(r"[,; ]+", raw) if item.strip()]
    return _clean_names(names)


def _discover_from_config() -> list[str]:
    return _clean_names([item["hostname"] for item in get_configured_domain_controller_targets()])


def _domain_candidates() -> list[str]:
    candidates = [
        os.environ.get("ADLOG_DOMAIN"),
        os.environ.get("USERDNSDOMAIN"),
        os.environ.get("USERDOMAIN"),
    ]
    output = []
    for item in candidates:
        if item and item not in output:
            output.append(item)
    return output


def _discover_with_directory_services() -> list[str]:
    command = [
        "powershell",
        "-NoProfile",
        "-Command",
        "[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers | ForEach-Object { $_.Name }",
    ]
    try:
        result = subprocess.run(
            command,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []

    if result.returncode != 0:
        return []

    return _clean_names(result.stdout.splitlines())


def _discover_with_nltest(domain: str) -> list[str]:
    try:
        result = subprocess.run(
            ["nltest", f"/dclist:{domain}"],
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []

    if result.returncode != 0:
        return []

    names = []
    for line in result.stdout.splitlines():
        match = re.search(r"\\\\([A-Za-z0-9_.-]+)", line)
        if match:
            names.append(match.group(1).split(".", 1)[0])
    return _clean_names(names)


def _clean_names(names: list[str]) -> list[str]:
    cleaned = []
    for name in names:
        value = _clean_hostname(name)
        if not value:
            continue
        if value and value not in cleaned:
            cleaned.append(value)
    return sorted(cleaned)



def _clean_connect_address(address: str) -> str:
    value = str(address or "").strip().strip().lstrip("\\")
    value = value.rstrip(".")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise DomainControllerConfigurationError(
            "DC connect_address must be an FQDN, not an IP literal"
        )
    labels = value.split(".")
    if (
        len(labels) < 2
        or any(
            not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in labels
        )
    ):
        raise DomainControllerConfigurationError(
            "DC connect_address must be an FQDN"
        )
    return value


def _reject_environment_endpoint_overrides() -> None:
    if (
        os.environ.get("ADLOG_DC_CONNECT_MAP", "").strip()
        or os.environ.get("ADLOG_DOMAIN_CONTROLLER_CONNECT_MAP", "").strip()
    ):
        raise DomainControllerConfigurationError(
            "Environment DC endpoint override is not permitted"
        )


def _clean_owner_confirmed_ip(address: str) -> str:
    value = str(address or "").strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise DomainControllerConfigurationError(
            "owner_confirmed_ip must be an IP literal"
        ) from exc

def _clean_hostname(name: str) -> str:
    value = str(name or "").strip().strip(".").lstrip("\\")
    if not value:
        return ""
    return value.split(".", 1)[0]


def configured_server_names(*, config_dir, stored) -> list[str]:
    if stored is not None:
        names: list[str] = []
        for row in stored:
            value = str(row.get("hostname") or "").strip().lstrip("\\").split(".", 1)[0]
            if value and value not in names:
                names.append(value)
        return names
    path = config_dir / "domain_controllers.json"
    if not path.is_file():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return []
    names = []
    for item in payload.get("domain_controllers") or []:
        value = item if isinstance(item, str) else item.get("hostname", "")
        value = str(value).strip().lstrip("\\").split(".", 1)[0]
        if value and value not in names:
            names.append(value)
    return names


def configured_source_addresses(*, config_dir, stored) -> dict[str, list[str]]:
    """Return owner-confirmed DNS readback IPs, never connection endpoints."""
    if stored is not None:
        items: list = list(stored)
    else:
        path = config_dir / "domain_controllers.json"
        if not path.is_file():
            return {}
        try:
            payload = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            return {}
        items = list(payload.get("domain_controllers") or [])
    result: dict[str, list[str]] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        hostname = str(item.get("hostname") or "").strip().lstrip("\\").rstrip(".")
        address = str(item.get("owner_confirmed_ip") or "").strip()
        try:
            normalized = str(ipaddress.ip_address(address))
        except ValueError:
            continue
        if hostname:
            result.setdefault(hostname.casefold(), []).append(normalized)
    return result


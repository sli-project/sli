"""Domain controller collection targets as a setup item («Первичная настройка»).

Owner decision 2026-10-02: the targets that lived only in
``config/domain_controllers.json`` are stored in ``domain_controller_targets``
(migration 147) and added, disabled and enabled by an administrator. The
resolution order used by collection is in
``server.sli.sources.dc_discovery.get_configured_domain_controller_targets``:
enabled database rows once the table holds any row, otherwise the file.

Rows are never deleted, only disabled. ``owner_confirmed_ip`` is carried over
from the file by the one-shot import and is never accepted from or shown to the
interface beyond a "DNS readback on" flag. Adding the first row while targets
still come from the file copies those file targets first (same transaction), so
the new row does not silently replace them.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from server.sli.core import database
from server.sli.core.platform_settings import _dns_name
from server.sli.plugins.ad import targets as dc_discovery

LOCK_SQL = "select pg_advisory_xact_lock(hashtext('ad_log_setup_domain_controllers'))"
IMPORT_ACTOR = "maintenance:import-from-file"
IMPORT_CONFIRMATION = "IMPORT-DOMAIN-CONTROLLERS"


class DomainControllerConflictError(Exception):
    """The domain controller is already registered (HTTP 409)."""


class DomainControllerNotFoundError(LookupError):
    """No such domain or domain controller (HTTP 404)."""


def _fetchone(cur) -> dict[str, Any] | None:
    row = cur.fetchone()
    return dict(row) if row else None


def _fetchall(cur) -> list[dict[str, Any]]:
    return [dict(row) for row in cur.fetchall()]


def list_targets() -> dict[str, Any]:
    """Stored targets, or the file's targets until the table has rows."""
    try:
        rows = database.query_rows(
            """
            select t.hostname, t.connect_address, d.fqdn as domain, t.enabled,
                   (t.owner_confirmed_ip is not null) as dns_readback
            from domain_controller_targets t
            left join domains d on d.id = t.domain_id
            order by lower(t.hostname)
            """
        )
    except Exception:  # noqa: BLE001 - table not migrated yet or database unavailable
        rows = []
    if rows:
        return {"source": "db", "items": [
            {
                "hostname": str(row["hostname"]), "connect_address": str(row["connect_address"]),
                "domain": row.get("domain"), "enabled": bool(row["enabled"]),
                "source": "db", "dns_readback": bool(row.get("dns_readback")),
            }
            for row in rows
        ]}
    file_items = [
        {
            "hostname": target["hostname"], "connect_address": target["connect_address"],
            "domain": None, "enabled": True, "source": "file",
            "dns_readback": bool(target.get("owner_confirmed_ip")),
        }
        for target in dc_discovery.read_file_targets()
    ]
    return {"source": "file" if file_items else "none", "items": file_items}


def _infer_domain_id(connect_address: str, domains: dict[str, int]) -> int | None:
    """Longest registered domain the FQDN belongs to, else None."""
    address = connect_address.lower()
    matches = [(len(fqdn), domain_id) for fqdn, domain_id in domains.items() if address.endswith("." + fqdn)]
    return max(matches)[1] if matches else None


def _insert_file_targets(cur, actor: str, targets: list[dict[str, str]], taken: set[str]) -> tuple[int, int]:
    """Insert file targets whose hostname is not stored yet; returns (inserted, with_domain)."""
    cur.execute("select id, lower(fqdn) as fqdn from domains")
    domains = {str(row["fqdn"]): int(row["id"]) for row in _fetchall(cur)}
    inserted = matched = 0
    for target in targets:
        key = target["hostname"].lower()
        if key in taken:
            continue
        domain_id = _infer_domain_id(target["connect_address"], domains)
        cur.execute(
            """
            insert into domain_controller_targets(
                hostname, connect_address, domain_id, owner_confirmed_ip, enabled,
                source, created_by, updated_by)
            values (%s, %s, %s, %s, true, 'file_import', %s, %s)
            """,
            (target["hostname"], target["connect_address"], domain_id,
             target.get("owner_confirmed_ip") or None, actor, actor),
        )
        taken.add(key)
        inserted += 1
        matched += domain_id is not None
    return inserted, matched


def _actor(value: str) -> str:
    name = str(value or "").strip()[:256]
    if not name:
        raise ValueError("actor_required")
    return name


def add_target(
    hostname_fqdn: str,
    domain_fqdn: str,
    *,
    actor: str,
    audit: Callable[[Any, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Register a controller (FQDN) under a registered domain, audited in one transaction."""
    actor_name = _actor(actor)
    try:
        address = dc_discovery._clean_connect_address(hostname_fqdn)
    except dc_discovery.DomainControllerConfigurationError as exc:
        raise ValueError("connect_address_must_be_fqdn") from exc
    address = _dns_name(address)
    hostname = dc_discovery._clean_hostname(address)
    domain = _dns_name(domain_fqdn)
    try:
        file_targets = dc_discovery.read_file_targets() if dc_discovery.domain_controller_target_source() == "file" else []
    except dc_discovery.DomainControllerConfigurationError as exc:
        raise ValueError("domain_controllers_file_invalid") from exc
    from server.sli.core.postgres_runtime_pipeline import connect

    with connect() as conn, conn.cursor() as cur:
        cur.execute(LOCK_SQL)
        cur.execute("select id from domains where lower(fqdn) = %s", (domain,))
        domain_row = _fetchone(cur)
        if domain_row is None:
            raise DomainControllerNotFoundError("domain_not_found")
        cur.execute("select lower(hostname) as key from domain_controller_targets")
        taken = {str(row["key"]) for row in _fetchall(cur)}
        imported = 0
        if not taken and file_targets:
            imported, _matched = _insert_file_targets(cur, actor_name, file_targets, taken)
        if hostname.lower() in taken:
            raise DomainControllerConflictError("domain_controller_already_exists")
        cur.execute(
            """
            insert into domain_controller_targets(
                hostname, connect_address, domain_id, enabled, source, created_by, updated_by)
            values (%s, %s, %s, true, 'interface', %s, %s)
            """,
            (hostname, address, domain_row["id"], actor_name, actor_name),
        )
        result = {
            "hostname": hostname, "connect_address": address, "domain": domain, "enabled": True,
            "source": "db", "dns_readback": False,
        }
        if audit is not None:
            audit(cur, {**result, "imported_from_file": imported})
        conn.commit()
    dc_discovery.clear_database_target_cache()
    return result


def set_enabled(
    hostname: str,
    enabled: Any,
    *,
    actor: str,
    audit: Callable[[Any, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Enable or disable a stored controller; collection stops using it when disabled."""
    if not isinstance(enabled, bool):
        raise ValueError("enabled_must_be_boolean")
    actor_name = _actor(actor)
    key = dc_discovery._clean_hostname(hostname).lower()
    if not key:
        raise ValueError("hostname_required")
    from server.sli.core.postgres_runtime_pipeline import connect

    with connect() as conn, conn.cursor() as cur:
        cur.execute(LOCK_SQL)
        cur.execute(
            "select hostname, enabled from domain_controller_targets where lower(hostname) = %s", (key,),
        )
        current = _fetchone(cur)
        if current is None:
            raise DomainControllerNotFoundError("domain_controller_not_found")
        cur.execute(
            "update domain_controller_targets set enabled = %s, updated_by = %s, updated_at = now() "
            "where lower(hostname) = %s",
            (enabled, actor_name, key),
        )
        result = {"hostname": str(current["hostname"]), "enabled": enabled, "previous_enabled": bool(current["enabled"])}
        if audit is not None:
            audit(cur, result)
        conn.commit()
    dc_discovery.clear_database_target_cache()
    return result


def import_from_file(*, apply: bool = False, actor: str = IMPORT_ACTOR) -> dict[str, int | str]:
    """One-shot copy of config/domain_controllers.json into the table; counts only.

    Idempotent: hostnames already stored are skipped. Without ``apply`` nothing
    is written. The domain is taken from the registered domain the controller's
    FQDN belongs to; targets without a match are stored without a domain.
    """
    targets = dc_discovery.read_file_targets()
    from server.sli.core.postgres_runtime_pipeline import connect

    with connect() as conn, conn.cursor() as cur:
        cur.execute(LOCK_SQL)
        cur.execute("select lower(hostname) as key from domain_controller_targets")
        taken = {str(row["key"]) for row in _fetchall(cur)}
        pending = {target["hostname"].lower(): target for target in targets if target["hostname"].lower() not in taken}
        result: dict[str, int | str] = {
            "mode": "apply" if apply else "plan",
            "file_targets": len({target["hostname"].lower() for target in targets}),
            "already_present": len({target["hostname"].lower() for target in targets} & taken),
            "to_import": len(pending),
        }
        if apply:
            inserted, matched = _insert_file_targets(cur, _actor(actor), list(pending.values()), taken)
            conn.commit()
            result.update(imported=inserted, with_domain=matched, without_domain=inserted - matched)
            dc_discovery.clear_database_target_cache()
    return result

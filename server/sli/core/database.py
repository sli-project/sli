from __future__ import annotations

import ipaddress
import re
import threading

from server.sli.core.app_config import load_config
from server.sli.core.paths import CONFIG_DIR
from server.sli.storage.runtime_storage import (
    StorageRouteConsumer,
    resolve_storage_route,
)


def active_backend() -> str:
    try:
        backend = (load_config().db_backend or "postgres").strip().lower()
    except Exception:  # noqa: BLE001 -- unreadable runtime selection must fail closed
        # Runtime database selection must fail closed to PostgreSQL.
        return "postgres"
    if backend != "postgres":
        raise RuntimeError(f"Unsupported database backend: {backend} (PostgreSQL is the only runtime)")
    return backend




def _active_backend() -> str:
    # Compatibility alias for older internal imports/tests.
    return active_backend()


def is_postgres_runtime_db() -> bool:
    return active_backend() == "postgres"


def _pg_sql(sql: str) -> str:
    # Project read queries use DB-API '?' positional placeholders. psycopg uses %s.
    # Escape every literal percent sign *before* creating psycopg placeholders.
    # The previous negative-lookahead approach misread SQL literals such as
    # LIKE '%service%' and LIKE '%schema admins%' as additional %s bind markers.
    # That defect was invisible in SQLite tests and caused PostgreSQL HTTP 500s.
    converted = re.sub(
        r"json_extract\(\s*([A-Za-z_][A-Za-z0-9_\.]*)\s*,\s*'\$\.([A-Za-z0-9_]+)'\s*\)",
        r"(\1::jsonb ->> '\2')",
        sql,
    )
    converted = re.sub(
        r"group_concat\(\s*distinct\s+(.+?)\s*\)",
        r"string_agg(distinct (\1)::text, ',')",
        converted,
        flags=re.IGNORECASE,
    )
    converted = converted.replace("%", "%%")
    converted = converted.replace("?", "%s")
    return converted


def _require_runtime_db() -> None:
    if not is_postgres_runtime_db():
        raise RuntimeError("Only the PostgreSQL runtime database is supported")


def query_rows(sql: str, params: tuple = ()) -> list[dict]:
    from server.sli.reporting.read_timeout import remaining_read_ms

    remaining = remaining_read_ms()
    if remaining is not None:
        return query_rows_bounded(sql, params, statement_timeout_ms=remaining, wall_timeout_ms=remaining)
    _require_runtime_db()
    from server.sli.core.postgres_runtime_pipeline import connect

    with connect() as conn, conn.cursor() as cur:
        cur.execute(_pg_sql(sql), params)
        return [dict(row) for row in cur.fetchall()]


class QueryTimeoutError(RuntimeError):
    """Raised after a bounded read query is cancelled and its connection is released."""

    def __init__(self, message: str, *, timeout_ms: int, cancelled: bool = True) -> None:
        super().__init__(message)
        self.timeout_ms = int(timeout_ms)
        self.cancelled = bool(cancelled)


def query_rows_bounded(
    sql: str,
    params: tuple = (),
    *,
    statement_timeout_ms: int = 8000,
    wall_timeout_ms: int | None = None,
    lock_timeout_ms: int = 1000,
    jit: bool = True,
) -> list[dict]:
    """Execute a read query with database and wall-clock cancellation.

    PostgreSQL receives a page-specific ``statement_timeout`` and a watchdog calls
    ``Connection.cancel()`` if the driver remains blocked beyond the wall budget.
    Context managers then close the cursor/connection, so a timed-out HTTP request
    does not leave a live worker or backend query behind.
    ``jit=False`` avoids compilation for short indexed reads; SET LOCAL stays
    inside this bounded transaction and preserves the connection default.
    """
    from server.sli.reporting.read_timeout import remaining_read_ms

    remaining = remaining_read_ms()
    statement_timeout_ms = max(100, int(statement_timeout_ms))
    wall_timeout_ms = max(statement_timeout_ms + 250, int(wall_timeout_ms or statement_timeout_ms + 1000))
    if remaining is not None:
        statement_timeout_ms = min(statement_timeout_ms, remaining)
        wall_timeout_ms = min(wall_timeout_ms, remaining)
    lock_timeout_ms = max(50, min(int(lock_timeout_ms), statement_timeout_ms))

    _require_runtime_db()
    from server.sli.core.postgres_runtime_pipeline import connect

    with connect() as conn:
        cancelled = threading.Event()
        finished = threading.Event()

        def _cancel() -> None:
            if finished.is_set():
                return
            cancelled.set()
            try:
                conn.cancel()
            except Exception:  # noqa: BLE001 -- cancellation must preserve the original read failure
                # The context manager still owns and closes the connection.
                return

        timer = threading.Timer(wall_timeout_ms / 1000.0, _cancel)
        timer.daemon = True
        try:
            with conn.cursor() as cur:
                cur.execute(f"set local statement_timeout = {statement_timeout_ms}")
                cur.execute(f"set local lock_timeout = {lock_timeout_ms}")
                if not jit:
                    cur.execute("set local jit = off")
                timer.start()
                try:
                    cur.execute(_pg_sql(sql), params)
                    return [dict(row) for row in cur.fetchall()]
                except Exception as exc:
                    sqlstate = getattr(exc, "sqlstate", None)
                    if cancelled.is_set() or sqlstate == "57014":
                        raise QueryTimeoutError(
                            f"PostgreSQL read query cancelled after {statement_timeout_ms} ms",
                            timeout_ms=statement_timeout_ms,
                            cancelled=True,
                        ) from exc
                    raise
        finally:
            finished.set()
            timer.cancel()


def get_entity_summary(*, authorization: object | None = None) -> dict:
    _v2_summary_route_selected(authorization, StorageRouteConsumer.EVENT_ENTITIES)
    return _get_entity_summary_v2()


def _get_entity_summary_v2() -> dict:
    total_entities = query_rows("select count(*) as count from entities_v2")
    total_links = query_rows("select count(*) as count from event_entity_links_v2")
    by_type = query_rows(
        """
        select entity_type.value as entity_type, count(*) as count
        from entities_v2 entity
        join storage_v2_entity_type entity_type on entity_type.id=entity.entity_type_id
        group by entity_type.value
        order by count(*) desc, entity_type.value
        """,
    )
    by_role = query_rows(
        """
        select role.value as link_role, count(*) as count
        from event_entity_links_v2 link
        join storage_v2_role role on role.id=link.role_id
        group by role.value
        order by count(*) desc, role.value
        """,
    )
    return {
        "total_entities": total_entities[0]["count"] if total_entities else 0,
        "total_event_entity_links": total_links[0]["count"] if total_links else 0,
        "by_type": by_type,
        "by_role": by_role,
    }


def get_event_summary(*, authorization: object | None = None) -> dict:
    _v2_summary_route_selected(authorization, StorageRouteConsumer.EVENTS)
    return _get_event_summary_v2(authorization=authorization)


def _get_event_summary_v2(*, authorization: object | None) -> dict:
    total_rows = query_rows("select count(*) as count from events_v2_core")
    by_channel = query_rows(
        """
        select channel.value as channel, count(*) as count
        from events_v2_core event
        join storage_v2_channel channel on channel.id=event.channel_id
        group by channel.value
        order by count(*) desc
        """,
    )
    top_event_ids = query_rows(
        """
        select event.event_id, channel.value as channel, count(*) as count
        from events_v2_core event
        join storage_v2_channel channel on channel.id=event.channel_id
        group by event.event_id, channel.value
        order by count(*) desc
        limit 20
        """,
    )
    by_server_channel = query_rows(
        """
        select server.hostname, channel.value as channel, count(event.id) as count
        from events_v2_core event
        join servers server on server.id=event.server_id
        join storage_v2_channel channel on channel.id=event.channel_id
        group by server.hostname, channel.value
        order by server.hostname, channel.value
        """,
    )
    by_server_rows = query_rows(
        """
        select distinct
            server.hostname, server.fqdn, server.role, server.is_active,
            domain.fqdn as domain_fqdn, site.name as site_name,
            count(event.id) as count
        from servers server
        join domains domain on domain.id=server.domain_id
        left join sites site on site.id=server.site_id
        left join events_v2_core event on event.server_id=server.id
        group by server.id, server.hostname, server.fqdn, server.role,
                 server.is_active, domain.fqdn, site.name
        order by server.hostname
        """,
    )
    return {
        "total_events": total_rows[0]["count"] if total_rows else 0,
        "by_channel": by_channel,
        "top_event_ids": top_event_ids,
        "by_server": _merge_configured_servers(by_server_rows),
        "by_server_channel": by_server_channel,
        "security_24h_summary": _security_24h_summary(
            authorization=authorization,
        ),
    }


def _v2_summary_route_selected(
    authorization: object | None, consumer: str,
) -> bool:
    """Storage V2 is the only route (plan 6.5); reject bad authority or non-PostgreSQL."""
    resolve_storage_route(authorization=authorization, consumer=consumer)
    if not is_postgres_runtime_db():
        raise RuntimeError("storage_v2_summary_requires_postgres")
    return True


def _security_24h_summary(
     *, authorization: object | None = None,
) -> dict:
    # Imported lazily to keep database.py independent from report rendering.
    try:
        from server.sli.events.security_events_monitor import (
            get_security_events_24h_summary,
        )

        return get_security_events_24h_summary(
            authorization=authorization,
        )
    except Exception:  # noqa: BLE001 -- preserve the existing optional summary fallback
        return {"important_total": 0}


def _merge_configured_servers(rows: list[dict]) -> list[dict]:
    by_name = {row["hostname"]: dict(row) for row in rows}
    for hostname in _configured_domain_controllers():
        by_name.setdefault(
            hostname,
            {
                "hostname": hostname,
                "fqdn": None,
                "role": "domain_controller",
                "is_active": 1,
                "domain_fqdn": None,
                "site_name": None,
                "count": 0,
            },
        )
    return [by_name[name] for name in sorted(by_name)]


def _stored_domain_controller_targets() -> list[dict] | None:
    """Enabled targets stored in the database (owner decision 2026-10-02), else None."""
    from server.sli.plugins.registry import plugin_hook

    hook = plugin_hook("sli.ad", "stored_enabled_targets")
    return hook() if hook else None


def _configured_domain_controllers() -> list[str]:
    from server.sli.plugins.registry import plugin_hook

    hook = plugin_hook("sli.ad", "configured_server_names")
    return hook(config_dir=CONFIG_DIR, stored=_stored_domain_controller_targets()) if hook else []


def _configured_source_addresses() -> dict[str, list[str]]:
    """Return owner-confirmed DNS readback IPs, never connection endpoints."""
    from server.sli.plugins.registry import plugin_hook

    hook = plugin_hook("sli.ad", "configured_source_addresses")
    return hook(config_dir=CONFIG_DIR, stored=_stored_domain_controller_targets()) if hook else {}


def get_sources() -> list[dict]:
    rows = query_rows(
        """
        select
            s.hostname,
            s.fqdn,
            s.role,
            s.is_active,
            s.os_name,
            s.os_version,
            d.fqdn as domain_fqdn,
            d.netbios_name,
            si.name as site_name
        from servers s
        join domains d on d.id = s.domain_id
        left join sites si on si.id = s.site_id
        order by s.hostname
        """,
    )
    if rows:
        rows = _enrich_sources_from_current_ad_context(rows)
    configured_addresses = _configured_source_addresses()
    if rows:
        return [
            _finalize_source_inventory(
                row,
                addresses,
            )
            for row, addresses in zip(
                rows, _attribute_configured_source_addresses(rows, configured_addresses)
            )
        ]
    return []


def _attribute_configured_source_addresses(
    rows: list[dict], configured: dict[str, list[str]],
) -> list[list[str]]:
    """Attribute each configured identity to exactly one registered source.

    An explicit FQDN takes precedence over a domain-derived name. Unqualified
    configuration remains compatible only while its short alias has one owner.
    Connection endpoints are not inventory identity evidence.
    """
    qualified: dict[str, list[int]] = {}
    short: dict[str, list[int]] = {}
    for index, row in enumerate(rows):
        hostname = _inventory_name(row.get("hostname"))
        fqdn = _inventory_name(row.get("fqdn"))
        domain = _inventory_name(row.get("domain_fqdn"))
        if not fqdn:
            fqdn = hostname if "." in hostname else (
                f"{hostname}.{domain}" if hostname and domain else ""
            )
        if fqdn:
            qualified.setdefault(fqdn, []).append(index)
        if hostname:
            short.setdefault(hostname.split(".", 1)[0], []).append(index)
    result: list[list[str]] = [[] for _ in rows]
    for name, addresses in configured.items():
        key = _inventory_name(name)
        owners = (qualified if "." in key else short).get(key, [])
        if len(owners) == 1:
            result[owners[0]].extend(addresses)
    return result


def _enrich_sources_from_current_ad_context(
    rows: list[dict]) -> list[dict]:
    """Project current computer inventory into registered source cards.

    The 30-minute AD Context contour already observes computer DNS names and
    operating-system attributes.  Reusing that current version avoids a second
    remote inventory worker and keeps ``servers`` as the registration source,
    while the UI adapter exposes fresher read-only inventory when available.
    """
    hostnames = sorted({
        key
        for row in rows
        for key in _source_inventory_keys(row)
    })
    if not hostnames:
        return [dict(row) for row in rows]
    inventory_limit = min(200, max(4, len(rows) * 3))
    try:
        inventory = query_rows_bounded(
            """
            select
                domain.fqdn as domain_fqdn,
                lower(coalesce(version.attributes_json->'attributes'->>'display_name','')) as display_key,
                lower(trim(trailing '$' from coalesce(version.attributes_json->'attributes'->>'sam_account_name',''))) as sam_key,
                lower(split_part(coalesce(version.attributes_json->'attributes'->>'dns_host_name',''),'.',1)) as dns_key,
                version.attributes_json->'attributes'->>'dns_host_name' as fqdn,
                version.attributes_json->'attributes'->>'operating_system' as os_name,
                version.attributes_json->'attributes'->>'operating_system_version' as os_version,
                version.attributes_json->'attributes'->'ip_addresses' as ip_addresses,
                version.attributes_json->'attributes'->'logical_disks' as logical_disks,
                version.attributes_json->'attributes'->>'technical_inventory_status' as technical_inventory_status,
                version.attributes_json->'attributes'->>'technical_inventory_observed_at_utc' as technical_inventory_observed_at_utc,
                version.last_observed_at_utc
            from ad_context_entity_versions version
            join ad_context_runs run on run.run_id = version.source_run_id
            join domains domain on domain.id = run.domain_id
            where version.valid_to_utc is null
              and version.source_section='directory_accounts'
              and lower(coalesce(version.attributes_json->'identity'->>'kind',''))='ad_computer'
              and (
                    lower(coalesce(version.attributes_json->'attributes'->>'display_name','')) = any(?)
                 or lower(trim(trailing '$' from coalesce(version.attributes_json->'attributes'->>'sam_account_name',''))) = any(?)
                 or lower(split_part(coalesce(version.attributes_json->'attributes'->>'dns_host_name',''),'.',1)) = any(?)
                 or lower(rtrim(coalesce(version.attributes_json->'attributes'->>'dns_host_name',''),'.')) = any(?)
              )
            order by version.last_observed_at_utc desc
            limit ?
            """,
            (hostnames, hostnames, hostnames, hostnames, inventory_limit + 1),
            statement_timeout_ms=3000,
            wall_timeout_ms=4000,
        )
    except Exception:  # noqa: BLE001 -- optional enrichment must not prevent inventory reads
        # AD Context is an optional enrichment source. Registration remains
        # usable and honest if its current read model is not available yet.
        return [dict(row) for row in rows]

    # A truncated population cannot establish uniqueness, even if the first
    # row looks like an exact match. Keep registration-only inventory instead.
    if len(inventory) > inventory_limit:
        return [dict(row) for row in rows]
    enriched: list[dict] = []
    for raw in rows:
        row = dict(raw)
        current = _match_source_inventory(raw, rows, inventory)
        if current:
            row["fqdn"] = row.get("fqdn") or current.get("fqdn")
            row["os_name"] = row.get("os_name") or current.get("os_name")
            row["os_version"] = row.get("os_version") or current.get("os_version")
            row["ip_addresses"] = list(current.get("ip_addresses") or [])
            row["logical_disks"] = list(current.get("logical_disks") or [])
            row["technical_inventory_status"] = current.get("technical_inventory_status")
            row["technical_inventory_observed_at_utc"] = current.get(
                "technical_inventory_observed_at_utc"
            )
            row["inventory_observed_at_utc"] = current.get("last_observed_at_utc")
            row["inventory_source"] = "ad_context"
        enriched.append(row)
    return enriched


def _inventory_name(value: object) -> str:
    return str(value or "").strip().casefold().rstrip(".")


def _source_inventory_keys(row: dict) -> set[str]:
    hostname = _inventory_name(row.get("hostname"))
    fqdn = _inventory_name(row.get("fqdn"))
    domain = _inventory_name(row.get("domain_fqdn"))
    keys = {hostname, fqdn, hostname.split(".", 1)[0]}
    if hostname and domain and "." not in hostname:
        keys.add(f"{hostname}.{domain}")
    return keys - {""}


def _match_source_inventory(
    source: dict, sources: list[dict], inventory: list[dict],
) -> dict | None:
    """Prefer qualified identity; a short alias must be unique on both sides."""
    keys = _source_inventory_keys(source)
    if not keys:
        return None
    domain = _inventory_name(source.get("domain_fqdn"))
    hostname = _inventory_name(source.get("hostname"))
    fqdn = _inventory_name(source.get("fqdn"))
    if not fqdn and "." in hostname:
        fqdn = hostname
    explicit_fqdn = fqdn
    if not fqdn and hostname and domain:
        fqdn = f"{hostname}.{domain}"
    candidates = []
    for item in inventory:
        aliases = {
            _inventory_name(item.get(key))
            for key in ("display_key", "sam_key", "dns_key", "fqdn")
        } - {""}
        if keys & aliases:
            candidates.append(item)

    def compatible(item: dict) -> bool:
        item_domain = _inventory_name(item.get("domain_fqdn"))
        item_fqdn = _inventory_name(item.get("fqdn"))
        return not (
            (domain and item_domain and domain != item_domain)
            or (explicit_fqdn and item_fqdn and explicit_fqdn != item_fqdn)
        )

    exact = [item for item in candidates if compatible(item) and fqdn
             and _inventory_name(item.get("fqdn")) == fqdn]
    if exact:
        return exact[0] if len(exact) == 1 else None
    same_domain = [item for item in candidates if compatible(item) and domain
                   and _inventory_name(item.get("domain_fqdn")) == domain]
    if same_domain:
        return same_domain[0] if len(same_domain) == 1 else None
    if len(candidates) != 1 or not compatible(candidates[0]):
        return None
    candidate_fqdn = _inventory_name(candidates[0].get("fqdn"))
    if fqdn and candidate_fqdn and fqdn != candidate_fqdn:
        return None
    # Domain-less observations may not be shared between registered sources
    # with colliding aliases. Never infer ownership from observation recency.
    owners = [row for row in sources if keys & _source_inventory_keys(row)]
    return candidates[0] if len(owners) == 1 else None


def _finalize_source_inventory(row: dict, configured_addresses: list[str]) -> dict:
    result = dict(row)
    addresses: list[str] = []
    for raw in [*configured_addresses, *list(result.get("ip_addresses") or [])]:
        try:
            value = str(ipaddress.ip_address(str(raw)))
        except ValueError:
            continue
        if value not in addresses:
            addresses.append(value)
    disks: list[dict] = []
    for raw in list(result.get("logical_disks") or [])[:64]:
        parts = str(raw).split("|")
        if len(parts) != 3 or not re.fullmatch(r"[A-Za-z]:", parts[0]):
            continue
        try:
            total_bytes = int(parts[1])
            free_bytes = int(parts[2])
        except ValueError:
            continue
        if total_bytes <= 0 or free_bytes < 0 or free_bytes > total_bytes:
            continue
        disks.append({
            "name": parts[0].upper(),
            "total_bytes": total_bytes,
            "free_bytes": free_bytes,
            "free_percent": round(free_bytes * 100 / total_bytes, 1),
        })
    technical_status = str(result.get("technical_inventory_status") or "").strip()
    if technical_status == "complete":
        disk_state = "warning" if any(
            float(item["free_percent"]) < 15 for item in disks
        ) else "ok"
    elif technical_status in {"failed", "timeout"}:
        disk_state = technical_status
    else:
        disk_state = "not_collected"
    result["ip_addresses"] = addresses
    result["disks"] = disks
    result["disk_state"] = disk_state
    return result

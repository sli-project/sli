"""AD domains as a setup item («Первичная настройка», owner decision 2026-10-02).

Domains live in ``domains`` (grouped by ``forests``). The same rows are created
by the event import and the existing-database bootstrap with the same
semantics: the forest is found or created by name, the domain by
``(forest_id, fqdn)``. Here the DNS name is also unique on its own, case
insensitively, because reports and AD Context pick a domain by FQDN.

Domains are never deleted: events, servers and report snapshots reference them
(``ON DELETE RESTRICT``). Archiving is explicit report-selection metadata; it does not stop collection
or change access grants. Existing domains can also change their NetBIOS name. ``domain_sid`` is filled by the AD
Context import and is not editable here. Which domain reports use is decided
by the ``reports.domain_fqdn`` setting, not by the number of rows.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from server.sli.core import database
from server.sli.core.platform_settings import _dns_name

_NETBIOS = re.compile(r"[A-Z0-9](?:[A-Z0-9-]{0,13}[A-Z0-9])?\Z")


class DomainConflictError(Exception):
    """The domain or NetBIOS name is already registered (HTTP 409)."""


class DomainNotFoundError(LookupError):
    """No such domain (HTTP 404)."""


def _netbios(value: str | None) -> str | None:
    text = str(value or "").strip().upper()
    if not text:
        return None
    if len(text) > 15 or not _NETBIOS.match(text):
        raise ValueError("netbios_must_be_up_to_15_letters_digits_hyphen")
    return text


def list_domains() -> list[dict[str, Any]]:
    rows = database.query_rows(
        """
        select d.fqdn, d.netbios_name, d.is_archived, f.name as forest,
               (select max(observed_at_utc) from ad_context_runs where domain_id = d.id) as observed_at_utc,
               (select count(*) from servers s where s.domain_id = d.id) as server_count
        from domains d join forests f on f.id = d.forest_id
        order by d.fqdn
        """
    )
    return [
        {
            "fqdn": str(row["fqdn"]), "netbios_name": row.get("netbios_name"),
            "forest": str(row["forest"]), "server_count": int(row.get("server_count") or 0),
            "is_archived": bool(row.get("is_archived", False)),
            "observed_at_utc": str(row["observed_at_utc"]) if row.get("observed_at_utc") else None,
        }
        for row in rows
    ]


def _one(cur) -> dict[str, Any] | None:
    row = cur.fetchone()
    return dict(row) if row else None


def add_domain(
    fqdn: str,
    netbios_name: str | None = None,
    forest: str | None = None,
    *,
    audit: Callable[[Any, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Register a domain in one transaction together with its audit record."""
    domain = _dns_name(fqdn)
    forest_name = _dns_name(forest) if str(forest or "").strip() else domain
    netbios = _netbios(netbios_name)
    from server.sli.core.postgres_runtime_pipeline import connect

    with connect() as conn, conn.cursor() as cur:
        cur.execute("select pg_advisory_xact_lock(hashtext('ad_log_setup_domains'))")
        cur.execute("select 1 as found from domains where lower(fqdn) = %s", (domain,))
        if _one(cur):
            raise DomainConflictError("domain_already_exists")
        if netbios:
            cur.execute("select 1 as found from domains where upper(netbios_name) = %s", (netbios,))
            if _one(cur):
                raise DomainConflictError("netbios_already_exists")
        cur.execute(
            """
            insert into forests(name) values (%s)
            on conflict(name) do update set name = excluded.name
            returning id
            """,
            (forest_name,),
        )
        forest_row = _one(cur)
        if forest_row is None:
            raise RuntimeError("forest_insert_failed")
        cur.execute(
            "insert into domains(forest_id, fqdn, netbios_name) values (%s, %s, %s) returning id",
            (forest_row["id"], domain, netbios),
        )
        result = {"fqdn": domain, "netbios_name": netbios, "forest": forest_name, "server_count": 0}
        if audit is not None:
            audit(cur, {**result, "previous_netbios_name": None})
        conn.commit()
    return result


def update_netbios(
    fqdn: str,
    netbios_name: str | None,
    *,
    audit: Callable[[Any, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Change the NetBIOS name of a registered domain (empty clears it)."""
    domain = _dns_name(fqdn)
    netbios = _netbios(netbios_name)
    from server.sli.core.postgres_runtime_pipeline import connect

    with connect() as conn, conn.cursor() as cur:
        cur.execute("select pg_advisory_xact_lock(hashtext('ad_log_setup_domains'))")
        cur.execute("select netbios_name from domains where lower(fqdn) = %s", (domain,))
        current = _one(cur)
        if current is None:
            raise DomainNotFoundError("domain_not_found")
        if netbios:
            cur.execute(
                "select 1 as found from domains where upper(netbios_name) = %s and lower(fqdn) <> %s",
                (netbios, domain),
            )
            if _one(cur):
                raise DomainConflictError("netbios_already_exists")
        cur.execute("update domains set netbios_name = %s where lower(fqdn) = %s", (netbios, domain))
        result = {"fqdn": domain, "netbios_name": netbios, "previous_netbios_name": current.get("netbios_name")}
        if audit is not None:
            audit(cur, result)
        conn.commit()
    return result


def update_archive(
    fqdn: str,
    is_archived: bool,
    *,
    audit: Callable[[Any, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Change report eligibility, not collection, retention or access grants."""
    domain = _dns_name(fqdn)
    if not isinstance(is_archived, bool):
        raise ValueError("domain_archive_must_be_boolean")
    from server.sli.core.postgres_runtime_pipeline import connect

    with connect() as conn, conn.cursor() as cur:
        cur.execute("select pg_advisory_xact_lock(hashtext('ad_log_setup_domains'))")
        cur.execute("select is_archived from domains where lower(fqdn) = %s for update", (domain,))
        current = _one(cur)
        if current is None:
            raise DomainNotFoundError("domain_not_found")
        cur.execute("update domains set is_archived = %s where lower(fqdn) = %s", (is_archived, domain))
        result = {"fqdn": domain, "is_archived": is_archived, "previous_is_archived": current["is_archived"]}
        if audit is not None:
            audit(cur, result)
        conn.commit()
    return result

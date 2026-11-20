"""Domain selection narrows existing report grants; it never issues new rights."""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime

from server.sli.core.database import query_rows_bounded
from server.sli.reporting.v2.access import resolve_access_scope


def parse_domain_id(query):
    """Only an absent parameter means all accessible domains."""
    if "domain_id" not in query:
        return None
    values = query["domain_id"]
    if (not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], str)
            or not re.fullmatch(r"[1-9][0-9]{0,18}", values[0]) or int(values[0]) > 2**63 - 1):
        raise ValueError("domain_scope_invalid")
    return int(values[0])


@dataclass(frozen=True)
class DomainSelection:
    domain_id: int | None
    domains: tuple[dict, ...]

    @property
    def domain_ids(self):
        return [domain["id"] for domain in self.domains]

    def to_json(self):
        return {"mode": "domain" if self.domain_id is not None else "accessible",
                "domain_id": self.domain_id, "domain_ids": self.domain_ids,
                "state": "available" if self.domains else "no_domains"}


def _permitted_ids(access):
    from server.sli.reporting.v2.registry import registered_reports

    ids = set()
    for definition in registered_reports():
        if definition.access.scope != "domain":
            continue
        try:
            domains = resolve_access_scope(access, definition.access).domain_ids()
        except PermissionError:
            # A source/entity restriction cannot be widened to its whole domain.
            continue
        if domains is None:
            return None
        ids.update(domains)
    return sorted(ids)


def _domain_rows(ids):
    if ids == []:
        return []
    # Both metadata and freshness are filtered in SQL, before aggregation. The
    # small collector cursor table avoids a scan over event history. Join by
    # registered FQDN, or by a short hostname only when it is unambiguous.
    return query_rows_bounded("""
        select d.id, d.fqdn as display_name, d.is_archived,
               m.slot_start_utc as snapshot_at_utc, m.created_at as published_at_utc,
               m.coverage_state as snapshot_state,
               observed.observed_at_utc, current_observation.observed_at_utc as default_observed_at_utc,
               events.event_at_utc,
               events.last_successful_collection_utc
        from domains d
        left join lateral (
            select manifest_id, slot_start_utc, created_at, coverage_state
            from ad_snapshot_manifests where domain_id=d.id
            order by slot_start_utc desc, manifest_id desc limit 1
        ) m on true
        left join lateral (
            select min(observed_at_utc) as observed_at_utc
            from ad_snapshot_manifest_sources where manifest_id=m.manifest_id
        ) observed on true
        left join lateral (
            select max(run.observed_at_utc) as observed_at_utc
            from ad_context_runs run
            where run.domain_id=d.id and run.status='completed'
        ) current_observation on true
        left join lateral (
            select max(c.last_event_time_utc) as event_at_utc,
                   max(c.last_successful_collection_utc) as last_successful_collection_utc
            from servers s join collection_channel_state c
              on lower(c.server_hostname)=lower(s.fqdn)
              or (lower(c.server_hostname)=lower(s.hostname) and not exists (
                  select 1 from servers other
                  where lower(other.hostname)=lower(s.hostname) and other.id<>s.id
              ))
            where s.domain_id=d.id
        ) events on true
        where (?::bigint[] is null or d.id=any(?::bigint[]))
        order by d.fqdn, d.id
    """, (ids, ids))


def resolve_domain_selection(access, query):
    if "workspace.view" not in access.get("capabilities", []):
        raise PermissionError("workspace_view_required")
    selected = parse_domain_id(query)
    permitted = _permitted_ids(access)
    if selected is not None and permitted is not None and selected not in permitted:
        raise PermissionError("domain_scope_denied")
    rows = _domain_rows([selected] if selected is not None else permitted)
    if selected is not None and not rows:
        raise PermissionError("domain_scope_denied")
    return _selection(selected, rows)


def resolve_report_domain_selection(access, rule, query, action="view"):
    """Resolve the shared selector against this report/action, never the workspace union."""
    selected = parse_domain_id(query)
    if "domain" in query:
        legacy = parse_domain_id({"domain_id": query["domain"]})
        if selected is not None and selected != legacy:
            raise ValueError("domain_scope_invalid")
        selected = legacy
    permitted = resolve_access_scope(access, rule, action).domain_ids()
    if selected is not None and permitted is not None and selected not in permitted:
        raise PermissionError("domain_scope_denied")
    rows = _domain_rows([selected] if selected is not None else permitted)
    if selected is not None and not rows:
        raise PermissionError("domain_scope_denied")
    if selected is None and rule.report_key in {"ad.users.v2", "ad.computers.v6", "ad.state"}:
        rows = [row for row in rows if not row.get("is_archived", False)]
    return _selection(selected, rows)


def _selection(selected, rows):
    domains = []
    for row in rows:
        freshness = {key: value.isoformat() if isinstance(value, datetime) else value
                     for key, value in row.items() if key not in {"id", "display_name", "is_archived"}}
        domains.append({"id": int(row["id"]), "display_name": row["display_name"], "is_archived": bool(row.get("is_archived", False)), "freshness": freshness})
    return DomainSelection(selected, tuple(domains))

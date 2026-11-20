"""WS read/decision authority. Callers supply effective access, never request grants."""

from collections.abc import Mapping

from server.sli.access.scope import scope_from_grant
from server.sli.plugins.workstations.reports import FIELDS, REPORTS
from server.sli.plugins.workstations.scope import RESOURCES, scope_predicate
from server.sli.reporting.v2.access import report_grant

REPORT_KEY = "workstations.overview"
CAPABILITIES = {
    action: f"workstations.{action}"
    for action in ("read", "review", "exception.station", "exception.account", "exception.ou", "decision.manage")
}


def _grants(access, key):
    report = report_grant(access, key)
    if not report or "view" not in (report.get("allowed_actions") or []):
        return []
    return [grant for grant in report.get("grants") or []
            if "view" in (grant.get("allowed_actions") or [])
            and FIELDS.issubset(set(grant.get("field_categories") or []))]


def _exists(raw, *, inventory=False):
    predicate, params, _ = scope_predicate(raw)
    source = "station_resources r where r.station_id=s.station_id" if inventory else "resources r where r.agent_key=a.agent_key"
    return "exists(select 1 from " + source + " and (" + predicate + "))", params


def _union(scopes, *, inventory=False):
    predicates, params = [], []
    for raw in scopes:
        try:
            predicate, values = _exists(raw, inventory=inventory)
        except (TypeError, ValueError):
            continue
        predicates.append(predicate)
        params.extend(values)
    return "(" + " OR ".join(predicates) + ")" if predicates else "FALSE", params


def _capability(access, action, *, legacy=False, inventory=False):
    """Allow/deny EXISTS are independent: an AD deny also blocks the device row."""
    key = CAPABILITIES[action]
    if access.get("platform_owner"):
        return "TRUE", []
    policies = [item for item in access.get("capability_policies") or [] if item.get("capability_key") == key]
    denies = [item for item in policies if item.get("effect") == "deny"]
    if any(not item.get("valid") for item in denies):
        return "FALSE", []
    # Invalid denies must fail closed even if a malformed snapshot marks them valid.
    try:
        for item in denies:
            scope_predicate(item.get("scope"))
    except (TypeError, ValueError):
        return "FALSE", []
    denied, deny_params = _union((item.get("scope") for item in denies), inventory=inventory)
    if legacy or key in (access.get("capabilities") or []):
        allowed, allow_params = "TRUE", []
    else:
        allowed, allow_params = _union((item.get("scope") for item in policies
                                       if item.get("effect") == "allow" and item.get("valid")), inventory=inventory)
    return f"({allowed} AND NOT {denied})", [*allow_params, *deny_params]


def station_predicate(access, *, family=None, action="read", inventory=False):
    """SQL admission precedes rows, paging and counts. Legacy grants stay per family."""
    if action not in CAPABILITIES or family is not None and family not in REPORTS:
        raise PermissionError("workstation_access_denied")
    keys = [REPORTS[family][0]] if family else [key for key, _ in REPORTS.values()]
    legacy, legacy_params = _union((grant.get("scope") for key in keys for grant in _grants(access, key)), inventory=inventory)
    current, current_params = _union((grant.get("scope") for grant in _grants(access, REPORT_KEY)), inventory=inventory)
    legacy_read, legacy_read_params = _capability(access, "read", legacy=True, inventory=inventory)
    current_read, current_read_params = _capability(access, "read", inventory=inventory)
    predicate = f"(({legacy} AND {legacy_read}) OR ({current} AND {current_read}))"
    params = [*legacy_params, *legacy_read_params, *current_params, *current_read_params]
    if legacy == current == "FALSE":
        raise PermissionError("workstation_access_denied")
    if action != "read":
        permitted, values = _capability(access, action, inventory=inventory)
        predicate = f"({predicate} AND {permitted})"
        params.extend(values)
    return predicate, params


def require_stations(cur, access, agent_keys, *, family, action="read"):
    """Authorize the complete concrete selection; never silently trim mutations."""
    if action not in {"read", "review", "exception.station", "decision.manage"}:
        raise PermissionError("workstation_access_denied")
    scope_predicate({"kind": "agent", "ids": agent_keys})
    predicate, params = station_predicate(access, family=family, action=action)
    cur.execute("set local statement_timeout = '5000ms'")
    cur.execute(RESOURCES + " select a.agent_key from registered a where " + predicate
                + " and a.agent_key=ANY(%s)", (*params, agent_keys))
    if {row["agent_key"] for row in cur.fetchall()} != set(agent_keys):
        raise PermissionError("workstation_access_denied")


def _covers(raw, target):
    # Validate even all grants/targets before attempting coverage.
    scope_predicate(raw)
    scope_predicate(target)
    if raw.get("kind") == "all" or raw.get("mode") == "all":
        return True
    if target.get("kind") == "ou":
        if raw.get("kind") == "ou":
            return raw["domain_id"] == target["domain_id"] and set(target["values"]) <= set(raw["values"])
        # Domain-wide authority includes its OUs; entity/agent authority does not.
        return scope_from_grant(raw).covers(scope_from_grant({"kind": "domain", "ids": [target["domain_id"]]}))
    if raw.get("kind") == "agent" and target.get("kind") == "agent":
        return set(target["ids"]) <= set(raw["ids"])
    if raw.get("kind") in {"agent", "ou"} or target.get("kind") == "agent":
        return False
    return scope_from_grant(raw).covers(scope_from_grant(target))


def _may_overlap(raw, target):
    if raw.get("kind") == target.get("kind") == "agent":
        return bool(set(raw["ids"]) & set(target["ids"]))
    if raw.get("kind") == target.get("kind") == "ou":
        return raw["domain_id"] == target["domain_id"] and bool(set(raw["values"]) & set(target["values"]))
    if raw.get("kind") == "agent" or target.get("kind") == "agent":
        # Membership can change. A wide exception must not outlive an unchecked deny.
        return True
    # OU membership can change within its bound domain, never across domains.
    if raw.get("kind") == "ou":
        raw = {"kind": "domain", "ids": [raw["domain_id"]]}
    if target.get("kind") == "ou":
        target = {"kind": "domain", "ids": [target["domain_id"]]}
    return scope_from_grant(raw).intersect(scope_from_grant(target)).mode != "none"


def _capability_covers(access, action, target, *, legacy=False):
    if access.get("platform_owner"):
        return True
    key = CAPABILITIES[action]
    policies = [item for item in access.get("capability_policies") or [] if item.get("capability_key") == key]
    for item in policies:
        if item.get("effect") == "deny":
            try:
                scope_predicate(item.get("scope"))
                if not item.get("valid") or _may_overlap(item.get("scope"), target):
                    return False
            except (TypeError, ValueError, AttributeError):
                return False
    if legacy or key in (access.get("capabilities") or []):
        return True
    for item in policies:
        if item.get("effect") == "allow" and item.get("valid"):
            try:
                if _covers(item.get("scope"), target):
                    return True
            except (TypeError, ValueError):
                continue
    return False


def require_decision_scope(access, target, *, family, action):
    """Check dynamic account/OU coverage, not just today's enumerated stations.

    Target is a server-resolved scope (OU refs include the domain). Descendant
    expansion, subject validation and finding revisions belong to decision preview.
    """
    if action not in {"exception.account", "exception.ou", "decision.manage"} or family not in REPORTS:
        raise PermissionError("workstation_access_denied")
    if not isinstance(target, Mapping):
        raise PermissionError("workstation_access_denied")
    if action == "exception.ou" and target.get("kind") != "ou":
        raise PermissionError("workstation_access_denied")
    try:
        scope_predicate(target)
        if not _capability_covers(access, action, target):
            raise PermissionError("workstation_access_denied")
        for key in (REPORT_KEY, REPORTS[family][0]):
            if not _capability_covers(access, "read", target, legacy=key != REPORT_KEY):
                continue
            for grant in _grants(access, key):
                try:
                    if _covers(grant.get("scope"), target):
                        return
                except (TypeError, ValueError):
                    continue
    except (TypeError, ValueError):
        pass
    raise PermissionError("workstation_access_denied")

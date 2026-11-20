"""Read-only AD review API over saved agent snapshot projections and exact events.

Counts are unique within each check. Missing inputs and comparison baselines
remain unknown; a snapshot difference never supplies an event actor.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from server.sli.access import auth
from server.sli.core import ad_service_exceptions
from server.sli.core.database import query_rows_bounded
from server.sli.core.messages import message
from server.sli.plugins.ad.reports import report_additions, review_catalog, users_security
from server.sli.plugins.ad.reports.computers_reporting import evaluate_operating_system_support
from server.sli.plugins.ad.reports.computer_security import OS_SUPPORT_POLICY_VERSION, computer_posture
from server.sli.plugins.ad.reports.users_v2_views import _dt, best_activity
from server.sli.plugins.ad.directory_projection import _standard_admin_group
from server.sli.reporting.v2.definition import result

TABLES = {"users": ("users_report_v2_snapshots", "users_v2", "snapshot_id", "scope_json", "users"),
          "computers": ("computers_v6_source_snapshots", "computers_v6", "snapshot_uuid", "source_options_json", "objects")}
EVENT_IDS = [4624, 4720, 4722, 4723, 4724, 4725, 4728, 4732, 4738, 4741, 4742, 4756, 5136]
SCAN_LIMIT = 10000
EVENT_LOOKBACK_DAYS = 7
COMPLETE = {"complete", "completed", "available", "empty", "ok"}


def previous_login(principal):
    """Older installations without homeimpl2 have no personal baseline yet."""
    reader = getattr(auth, "previous_login", None)
    return reader(principal) if reader else None


def _time(value):
    return value.astimezone(timezone.utc) if isinstance(value, datetime) and value.tzinfo else _dt(value)


def _payload(row):
    raw = row.get("payload_json") or {}
    return dict(raw) if isinstance(raw, dict) else json.loads(raw)


def _population_complete(snapshot):
    """Optional attributes do not determine directory population coverage."""
    return bool(snapshot and snapshot.get("population_complete", snapshot.get("state") in COMPLETE))


def _payload_population_complete(kind, payload, state):
    metadata = payload.get("metadata") or {}
    coverage = metadata.get("coverage") or {}
    if coverage.get("truncated") or (metadata.get("limits") or {}).get("input_truncated"):
        return False
    if state in COMPLETE:
        return True
    # A partial source can still attest every directory object. Exact logon,
    # OS, DNS and other optional sections retain their own unknown values.
    source_name = "directory" if kind == "users" else "ad"
    count_key = "user_count" if kind == "users" else "object_count"
    collection = TABLES[kind][-1]
    return (state == "partial" and metadata.get(count_key) == len(payload.get(collection) or [])
            and any(source.get("name") == source_name and source.get("status") == "observed"
                    for source in metadata.get("sources") or []))


def load_snapshots(kind, domain_ids, since):
    """Read exact published sources, including a missing family in the latest slot.

    Computers use the agent source, not the old independently saved report.
    A missing family must never silently select an older complete slot.
    """
    table, family, identifier, scope, collection = TABLES[kind]
    extra_roles = """
                union all
                select 'previous_predecessor',s.* from (
                    select * from slots order by slot_start_utc desc offset 2 limit 1) s
                union all
                select 'baseline_predecessor',s.* from baseline
                cross join lateral (select * from slots s where s.slot_start_utc<baseline.slot_start_utc
                    order by s.slot_start_utc desc limit 1) s
    """ if kind == "users" else ""
    domains = query_rows_bounded(
        "select id,fqdn from domains where (?::bigint[] is null or id=any(?::bigint[])) order by id",
        (domain_ids, domain_ids), statement_timeout_ms=5000) if domain_ids != [] else []
    bundles = []
    for domain in domains:
        rows = query_rows_bounded(
            f"""/* ad_review_snapshots */
            with slots as (
                select * from ad_snapshot_manifests where domain_id=?
                and slot_start_utc>=now()-interval '365 days'
            ), latest as (
                select * from slots order by slot_start_utc desc limit 1
            ), baseline as (
                select * from slots where slot_start_utc<=?::timestamptz and assembled_at_utc<=?::timestamptz
                order by slot_start_utc desc limit 1
            ), selected as (
                select 'current' as role,latest.* from latest
                union all
                select 'previous' as role,prior.* from latest
                cross join lateral (select s.* from slots s
                    where s.slot_start_utc<latest.slot_start_utc
                    order by s.slot_start_utc desc limit 1) prior
                union all
                select 'baseline' as role,baseline.* from baseline
                {extra_roles}
            ) select selected.role,source.source_state,source.observed_at_utc as source_observed_at_utc,
                     source.contract_id,snap.{scope} as scope,snap.payload_json
              from selected left join ad_snapshot_manifest_sources source
                on source.manifest_id=selected.manifest_id and source.family=?
              left join {table} snap on snap.domain_id=selected.domain_id
                and snap.{identifier}::text=source.source_id and snap.payload_sha256=source.payload_sha256""",
            (domain["id"], since, since, family), statement_timeout_ms=5000)
        bundle = {"domain_id": int(domain["id"]), "domain_name": domain["fqdn"]}
        current_row = next((row for row in rows if row["role"] == "current"), {})
        for row in rows:
            if not row.get("payload_json") or (row["role"] != "current" and (
                row.get("scope") != current_row.get("scope") or row.get("contract_id") != current_row.get("contract_id")
            )):
                continue
            payload = _payload(row)
            bundle[row["role"]] = {
                "objects": [_computer(obj, row.get("source_observed_at_utc")) for obj in payload.get(collection) or []] if kind == "computers" else payload.get(collection) or [],
                "state": row["source_state"],
                "population_complete": _payload_population_complete(kind, payload, row["source_state"]),
                "observed_at": row.get("source_observed_at_utc"),
            }
        bundles.append(bundle)
    return bundles


def _computer(raw, observed_at=None):
    """Project only non-secret daily source attributes needed by the checks."""
    obj = {target: raw.get(source) for source, target in (
        ("objectGuid", "object_guid"), ("sid", "object_sid"), ("name", "display_name"),
        ("enabled", "enabled"), ("lastLogonTimestamp", "last_logon_utc"),
        ("passwordLastSet", "password_last_set_utc"), ("whenCreated", "created_utc"),
        ("osName", "operating_system"), ("osVersion", "operating_system_version"),
        ("deviceType", "computer_type"), ("ou", "ou_path"))}
    computer_posture(obj, {target: raw.get(source) for source, target in (
        ("userAccountControl", "user_account_control"), ("trustedForDelegation", "trusted_for_delegation"),
        ("allowedToDelegateTo", "allowed_to_delegate_to"), ("resourceBasedDelegationPresent", "resource_based_delegation_present"),
        ("lapsPasswordExpiration", "laps_password_expiration_utc"),
        ("legacyLapsPasswordExpiration", "legacy_laps_password_expiration_utc"))}, _time(raw.get("collectedAt") or observed_at), _time)
    obj["dns_ip"] = report_additions.dns_observation({
        "ip_addresses": [*(raw.get("ipv4s") or []), *(raw.get("ipv6s") or [])],
        "evidence": {"network_sources": {"dns_addresses": (raw.get("sources") or {}).get("dns")}}})
    return obj


def load_events(domain_ids, start, end, include_logons=True):
    """No raw XML or name matching: correlate only a SID inside its domain."""
    if domain_ids == [] or not start or not end:
        return [], False
    sql = """/* ad_review_events */ with source_page as (
               select e.* from events_v2_core e where e.domain_id=any(?) and e.event_id=any(?)
                 and e.time_created_utc>=? and e.time_created_utc<=?
               order by e.time_created_utc desc,e.id desc limit ?
           ) select e.id,e.domain_id,e.event_id,e.time_created_utc,
               e.target_user_sid,e.subject_user_sid,e.subject_user_name,actor_domain.value as subject_domain_name,
               f.logon_type,f.membership_member_sid,n.facts_json
           from source_page e left join event_facts_v2 f on f.event_id=e.id
           left join storage_v2_domain_name actor_domain on actor_domain.id=e.subject_domain_id
           left join lateral (select facts_json from normalized_events n where n.source_event_id=e.id
               order by n.semantic_contract_version desc,n.normalized_at desc,n.normalized_event_id desc limit 1) n on true
           order by e.time_created_utc desc,e.id desc"""
    rows, truncated = [], False
    # A busy authentication source must not displace all change evidence.
    for codes in ([code for code in EVENT_IDS if code != 4624], [4624]):
        if codes == [4624] and not include_logons:
            continue
        batch = query_rows_bounded(sql, (domain_ids, codes, start, end, SCAN_LIMIT + 1), statement_timeout_ms=10000)
        truncated |= len(batch) > SCAN_LIMIT
        rows.extend(batch[:SCAN_LIMIT])
    # Event collection coverage is not established by an empty scan.
    return rows, truncated


def _identity(obj, kind):
    names = ("objectGuid", "sid", "entityId", "id") if kind == "users" else ("object_guid", "object_sid", "entity_id")
    return next((str(obj[key]).casefold() for key in names if obj.get(key)), None)


def _age(value, at):
    stamp = _time(value)
    return (at - stamp).total_seconds() / 86400 if at and stamp and stamp <= at else None


def _and(*values):
    return False if False in values else None if None in values else True


def _over(value, limit):
    return value > limit if value is not None else None


def _privileged(obj):
    if users_security.privileged(obj):
        return True
    membership = obj.get("memberships") or {}
    return False if membership.get("status") in {"observed", "complete"} else None


def _object_events(obj, kind, events):
    sid = obj.get("sid") if kind == "users" else obj.get("object_sid")
    guid = obj.get("objectGuid") if kind == "users" else obj.get("object_guid")
    if isinstance(events, dict):
        related = [*events.get(("sid", str(sid or "").casefold()), []),
                   *events.get(("guid", str(guid or "").strip("{}").casefold()), [])]
        return list({event["id"]: event for event in related}.values())
    return [event for event in events if (
        sid and str(event.get("membership_member_sid") or event.get("target_user_sid") or "").casefold() == str(sid).casefold()
    ) or (guid and event["event_id"] == 5136 and str((event.get("facts_json") or {}).get("object") or "").strip("{}").casefold() == str(guid).strip("{}").casefold())]


def _event_index(events):
    indexed = {}
    for event in events:
        sid = event.get("membership_member_sid") or (event.get("facts_json") or {}).get("relation_member_sid") or event.get("target_user_sid")
        if sid:
            indexed.setdefault(("sid", str(sid).casefold()), []).append(event)
        guid = (event.get("facts_json") or {}).get("object") if event["event_id"] == 5136 else None
        if guid:
            indexed.setdefault(("guid", str(guid).strip("{}").casefold()), []).append(event)
    return indexed


def evaluate(kind, obj, at, previous, previous_complete, events):
    """Three-valued check results, including event observations with their limits."""
    related = _object_events(obj, kind, events)
    enabled = obj.get("enabled")
    if kind == "computers":
        activity = _age(obj.get("last_logon_utc"), at)
        password = _age(obj.get("password_last_set_utc"), at)
        support = evaluate_operating_system_support(obj.get("operating_system"), obj.get("operating_system_version"))
        end = _time(str(support.get("support_end_date")) + "T00:00:00Z")
        unsupported = at.date() > end.date() if at and end else None
        laps = obj.get("laps") or {}
        laps_state = laps.get("state") or obj.get("laps_state")
        delegation = obj.get("delegation") or {}
        created_age = _age(obj.get("created_utc"), at)
        return {
            "no_sli_agent": True if (obj.get("sli_agent") or {}).get("state") == "absent" else
                            False if (obj.get("sli_agent") or {}).get("state") in {"installed", "silent"} else None,
            "unconstrained_delegation": delegation.get("unconstrained", obj.get("trusted_for_delegation")),
            "unsupported_os": unsupported,
            "new_computer": created_age < 1 if created_age is not None else None,
            # Missing/denied LAPS metadata does not prove LAPS is absent.
            "laps": True if laps_state in {"expired", "absent"} else False if laps_state == "metadata_present" else None,
            "rbcd": delegation.get("resource_based", obj.get("resource_based_delegation_present")),
            "inactive_enabled": _and(enabled, _over(activity, 90)),
            "old_machine_password": _over(password, 60),
        }
    spn_known = isinstance(obj.get("servicePrincipalNames"), list)
    obj = users_security.facts(obj)
    privilege = _privileged(obj)
    activity = best_activity(obj)
    inactive = _over(_age(activity.get("value") if activity else None, at), 90)
    password = _over(_age(obj.get("passwordLastSet"), at), 365)
    old_privilege = _privileged(previous) if previous else False if previous_complete else None
    new_privilege = _and(privilege, None if old_privilege is None else not old_privilege)
    lifecycle = sorted((event for event in related if event["event_id"] in {4722, 4725}),
                       key=lambda event: (_time(event["time_created_utc"]), event["id"]))
    disabled_at = _time(lifecycle[-1]["time_created_utc"]) if lifecycle and lifecycle[-1]["event_id"] == 4725 else None
    disabled_logon = any(event["event_id"] == 4624 and disabled_at and _time(event["time_created_utc"]) > disabled_at for event in related)
    interactive = any(event["event_id"] == 4624 and str(event.get("logon_type")) in {"2", "10"} for event in related)
    service = obj.get("serviceAccountType")
    return {
        "disabled_logon": False if enabled is True else True if disabled_logon and enabled is False else None,
        "new_privileged": new_privilege,
        "reversible_password": obj.get("allowReversiblePasswordEncryption"),
        "inactive_privileged": _and(privilege, True if enabled is False or inactive is True else None if enabled is None or inactive is None else False),
        "spn_privileged": _and(privilege, bool(obj.get("servicePrincipalNames")) if spn_known else None),
        "privileged_password_never_expires": _and(privilege, obj.get("passwordNeverExpires")),
        "locked_out": obj.get("lockedOut"),
        "service_interactive_logon": True if service and interactive else
                                     False if not service and spn_known and isinstance(obj.get("objectClasses"), list) else None,
        "kerberos_no_preauth": obj.get("doesNotRequirePreAuth"),
        "inactive_enabled": _and(enabled, inactive), "old_password": password,
        "password_never_expires": obj.get("passwordNeverExpires"),
    }


def _assess(kind, snapshot, predecessor=None, events=(), exceptions=None):
    if not snapshot:
        return None
    at = _time(snapshot.get("observed_at"))
    before = {_identity(obj, kind): obj for obj in (predecessor or {}).get("objects") or []}
    rows = {}
    indexed = events if isinstance(events, dict) else _event_index(events)
    for obj in snapshot.get("objects") or []:
        key = _identity(obj, kind)
        if key:
            checks = evaluate(kind, obj, at, before.get(key),
                              _population_complete(predecessor), _object_events(obj, kind, indexed))
            if kind == "users" and users_security.exception(users_security.facts(obj), exceptions or {}):
                checks.update(old_password=False, inactive_enabled=False)
            rows[key] = (obj, {name: value if isinstance(value, bool) else None for name, value in checks.items()})
    return rows


def _matches_search(obj, search):
    return not search or str(search).casefold() in " ".join(str(obj.get(field) or "") for field in (
        "samAccountName", "displayName", "ou", "display_name")).casefold()


def summarize(kind, bundles, since=None, events=(), events_truncated=False, now=None, exceptions=None, object_check=None, search=None):
    """Aggregate domains without adding overlapping objects across checks."""
    now = now or datetime.now(timezone.utc)
    catalog = review_catalog.CATALOG[kind]
    matches = {key: {} for key, _ in catalog}
    old_matches = {key: set() for key, _ in catalog}
    baseline_matches = {key: set() for key, _ in catalog}
    unknown = {key: set() for key, _ in catalog}
    old_known = {key: True for key, _ in catalog}
    baseline_known = {key: bool(since) for key, _ in catalog}
    unassessed, population, domains = set(), set(), []
    for bundle in bundles:
        domain_id = bundle["domain_id"]
        current, previous, baseline = (bundle.get(role) for role in ("current", "previous", "baseline"))
        at = _time((current or {}).get("observed_at"))
        complete = _population_complete(current)
        domain_events = [event for event in events if event.get("domain_id") == domain_id and _time(event.get("time_created_utc")) and _time(event["time_created_utc"]) <= now]
        indexed_events = _event_index(domain_events)
        assessed = _assess(kind, current, previous, indexed_events, exceptions)
        old = _assess(kind, previous, bundle.get("previous_predecessor"), events=[event for event in domain_events if _time(previous.get("observed_at")) and _time(event["time_created_utc"]) <= _time(previous["observed_at"])] if previous else [], exceptions=exceptions)
        base = _assess(kind, baseline, bundle.get("baseline_predecessor"), events=[event for event in domain_events if _time(baseline.get("observed_at")) and _time(event["time_created_utc"]) <= _time(baseline["observed_at"])] if baseline else [], exceptions=exceptions)
        domains.append({"domain_id": domain_id, "domain_name": bundle["domain_name"],
                        "state": "complete" if complete else (current or {}).get("state", "not_collected"),
                        "snapshot_state": (current or {}).get("state", "not_collected"),
                        "observed_at_utc": at.isoformat() if at else None})
        for key, _ in catalog:
            old_known[key] &= bool(complete and _population_complete(previous) and old is not None)
            baseline_known[key] &= bool(complete and _population_complete(baseline) and base is not None)
            for target, source, known in ((old_matches, old, old_known), (baseline_matches, base, baseline_known)):
                for identity, (obj, checks) in (source or {}).items():
                    if not _matches_search(obj, search):
                        continue
                    if checks[key] is None:
                        known[key] = False
                    elif checks[key] is True:
                        target[key].add((domain_id, identity))
        for identity, (obj, checks) in (assessed or {}).items():
            if not _matches_search(obj, search):
                continue
            object_key = (domain_id, identity)
            population.add(object_key)
            for key, value in checks.items():
                if value is None:
                    unknown[key].add(object_key)
                    unassessed.add(object_key)
                elif value is True:
                    related = _object_events(obj, kind, indexed_events)
                    matches[key][object_key] = {
                        "entity_id": obj.get("entityId") if kind == "users" else obj.get("entity_id"),
                        "name": (obj.get("samAccountName") or obj.get("displayName")) if kind == "users" else obj.get("display_name"),
                        "domain_id": domain_id, "domain_name": bundle["domain_name"],
                        "observed_at_utc": at.isoformat() if at else None,
                        "computer_type": obj.get("computer_type") if kind == "computers" else None,
                        # Only actual change events can supply an actor.
                        "change": _change(related, kind, key, obj),
                    }
                    if kind == "computers":
                        # Card previews use the same safe daily facts as checks.
                        matches[key][object_key].update({field: obj.get(field) for field in (
                            "operating_system", "last_logon_utc", "ou_path", "laps_state", "enabled", "dns_ip", "sli_agent")})
                    else:
                        activity = best_activity(obj)
                        matches[key][object_key].update({"enabled": obj.get("enabled"), "sam": obj.get("samAccountName"),
                            "activity_at": activity.get("value") if activity else None, "ou": obj.get("ou"),
                            "password_last_set": obj.get("passwordLastSet"), "membership_paths": (obj.get("memberships") or {}).get("paths")})
    rows = []
    missing = not bundles or any(not bundle.get("current") for bundle in bundles)
    for key, severity in catalog:
        identities = set(matches[key])
        uncertain = bool(unknown[key]) or missing
        complete = not missing and all(_population_complete(bundle.get("current")) for bundle in bundles)
        # Count the assessed portion even when another object's input is absent.
        # Unknown objects and incomplete populations remain explicit lower bounds.
        assessed_count = len(population - unknown[key])
        total = len(identities) if assessed_count or identities or (complete and not uncertain) else None
        new = len(identities - baseline_matches[key]) if baseline_known[key] and not uncertain else None
        prior = len(old_matches[key]) if old_known[key] and not uncertain else None
        delta = len(identities) - prior if prior is not None else None
        status = ("no_comparison" if total is not None else "not_evaluated") if delta is None else "new" if delta > 0 else "decreased" if delta < 0 else "unchanged"
        envelope = message(review_catalog.PREFIX + "status." + status, {"count": abs(delta or 0)})
        objects = [matches[key][identity] for identity in sorted(identities)]
        rows.append({"id": f"{kind}:{key}", "key": key, "severity": severity,
                     "section": "hygiene" if severity == "low" else "review",
                     **review_catalog.presentation(kind, key), "total": total,
                     "new_count": new, "previous_total": prior, "delta": delta,
                     "status": status, "status_text": envelope["text"],
                     "not_evaluated_count": len(unknown[key]) if not missing else None,
                     "assessed_count": assessed_count,
                     "is_lower_bound": not complete or uncertain,
                     "objects": objects if key == object_check else objects[:3], "remaining_objects": max(0, len(objects) - 3),
                     "last_seen_utc": max((obj["observed_at_utc"] for obj in objects if obj["observed_at_utc"]), default=None),
                     "change": next((obj["change"] for obj in sorted(objects, key=lambda obj: (obj["change"] or {}).get("at_utc", ""), reverse=True) if obj["change"]), None)})
        rows[-1]["presentation_messages"]["status_text"] = envelope
        for field, code in (("severity_text", "severity." + severity),
                            ("section_text", "hygiene" if severity == "low" else "tab")):
            localized = message(review_catalog.PREFIX + code)
            rows[-1][field] = localized["text"]
            rows[-1]["presentation_messages"][field] = localized
    order = {"high": 0, "medium": 1, "low": 2}
    rows.sort(key=lambda row: (order[row["severity"]], -(row["new_count"] or 0), -(row["total"] or 0), row["id"]))
    affected = set().union(*(set(value) for value in matches.values()))
    fresh = all(_time(domain["observed_at_utc"]) and now - _time(domain["observed_at_utc"]) <= timedelta(days=1) for domain in domains)
    state = "not_collected" if not any(bundle.get("current") for bundle in bundles) else "partial" if missing or unassessed or events_truncated or any(not _population_complete(bundle.get("current")) for bundle in bundles) else "ok"
    if state == "ok" and not fresh:
        state = "stale"
    not_evaluated_count = len(unassessed) if not missing else None
    footer = message(review_catalog.PREFIX + ("not_evaluated_line" if not_evaluated_count is not None else "status.not_evaluated"),
                     {"count": not_evaluated_count} if not_evaluated_count is not None else {})
    return {"state": state, "items": rows, "coverage": {
        "contract_id": "sli.ad-review-checks.v1", "domains": domains,
        "population": len(population) if not missing else None,
        "affected_objects": len(affected) if affected or not missing else None,
        "not_evaluated_count": not_evaluated_count,
        "footer_rows": [{"id": "not_evaluated", "total": not_evaluated_count, "label": footer["text"],
                         "presentation_messages": {"label": footer}}],
        "previous_login_at": since, "events_truncated": events_truncated,
        "event_coverage": "unconfirmed", "freshness_threshold_seconds": 86400,
        "os_support_policy_version": OS_SUPPORT_POLICY_VERSION,
        "new_computer_window_days": 1, "counts_are_unique_per_check": True,
    }}


def _change(events, kind, key, obj):
    allowed = {"new_computer": {4741},
               "old_password": {4723, 4724}, "disabled_logon": {4725},
               "inactive_privileged": {4725}, "new_privileged": {4728, 4732, 4756}}
    attributes = {"unconstrained_delegation": {"useraccountcontrol"},
                  "old_machine_password": {"pwdlastset"},
                  "rbcd": {"msds-allowedtoactonbehalfofotheridentity"},
                  "reversible_password": {"useraccountcontrol"},
                  "kerberos_no_preauth": {"useraccountcontrol"},
                  "password_never_expires": {"useraccountcontrol"},
                  "privileged_password_never_expires": {"useraccountcontrol"},
                  "spn_privileged": {"serviceprincipalname"}}
    events = [event for event in events if event["event_id"] in allowed.get(key, set()) or (
        event["event_id"] == 5136 and str((event.get("facts_json") or {}).get("attribute") or "").casefold() in attributes.get(key, set()))]
    if key == "new_privileged":
        # Adding this user to an unrelated group cannot identify the author of
        # a privilege grant. Standard groups use the same policy as projection.
        known_sids = {str(group.get("sid") or "").casefold() for group in (obj.get("memberships") or {}).get("effective") or [] if group.get("watchGroup")}
        events = [event for event in events if _standard_admin_group({}, {"object_sid": event.get("target_user_sid")}) or
                  str(event.get("target_user_sid") or "").casefold() in known_sids - {""}]
    if not events:
        return None
    event = max(events, key=lambda item: (_time(item["time_created_utc"]), item["id"]))
    name, domain = event.get("subject_user_name"), event.get("subject_domain_name")
    return {"event_db_id": event["id"], "event_id": event["event_id"],
            "at_utc": _time(event["time_created_utc"]).isoformat(),
            "actor": f"{domain}\\{name}" if domain and name else name or None}


def query(report, context, kind):
    fields = review_catalog.COMPUTER_FIELDS if kind == "computers" else review_catalog.FIELDS
    if context.field_access and not context.field_access(fields):
        return result(report, state="denied")
    check = context.params.get("check") if kind == "users" else None
    if check and check not in dict(review_catalog.CATALOG[kind]):
        raise ValueError("report_check_invalid")
    try:
        offset = int(context.cursor or 0)
        if offset < 0:
            raise ValueError
    except ValueError as exc:
        raise ValueError("report_cursor_invalid") from exc
    try:
        since = previous_login(context.principal)
        bundles = load_snapshots(kind, context.domain_ids, since)
        if kind == "computers":
            agents = report_additions.agent_index(report_additions.load_agents(context.domain_ids))
            for bundle in bundles:
                for role in ("current", "previous", "baseline"):
                    snapshot = bundle.get(role) or {}
                    for obj in snapshot.get("objects") or []:
                        obj["sli_agent"] = report_additions.agent_status(
                            obj, bundle["domain_id"], agents,
                            at=(snapshot.get("observed_at") or "") if role != "current" else None)
        times = [_time(bundle["current"].get("observed_at")) for bundle in bundles if bundle.get("current")]
        times = [stamp for stamp in times if stamp]
        end = datetime.now(timezone.utc) if times else None
        start = end - timedelta(days=EVENT_LOOKBACK_DAYS) if end else None
        ids = [bundle["domain_id"] for bundle in bundles]
        # Computer checks need change actors, never the DC's authentication flood.
        try:
            events, truncated = load_events(ids, start, end, kind == "users")
            event_state = "unconfirmed"
        except Exception:  # Event evidence is optional; keep snapshot checks usable.
            events, truncated, event_state = [], False, "unavailable"
        exceptions = ad_service_exceptions.configured() if kind == "users" else {}
        data = summarize(kind, bundles, since, events, truncated, exceptions=exceptions, object_check=check,
                         search=context.params.get("q") if kind == "users" else None)
        data["coverage"]["event_coverage"] = event_state
        data["coverage"]["event_lookback_days"] = EVENT_LOOKBACK_DAYS
        data["coverage"]["event_window"] = {"from_utc": start.isoformat() if start else None,
                                             "to_utc": end.isoformat() if end else None}
    except Exception:  # Never expose a database error containing source identities.
        return result(report, state="error", coverage={"reason": "ad_review_unavailable"})
    if check:
        selected = next(row for row in data["items"] if row["key"] == check)
        objects = selected["objects"]
        page = objects[offset:offset + context.limit]
        more = offset + len(page) < len(objects)
        return result(report, state=data["state"], items=page, filtered_count=len(objects),
                      has_more=more, next_cursor=str(offset + len(page)) if more else None,
                      collections={"checks": page}, coverage={**data["coverage"], "check": check,
                          "is_lower_bound": selected["is_lower_bound"], "assessed_total": selected["total"]})
    footer_title = message(review_catalog.PREFIX + "not_evaluated")
    footer = {"id": kind + ":not_evaluated", "section": "not_evaluated", "title": footer_title["text"],
              "total": data["coverage"]["not_evaluated_count"], "new_count": None,
              "objects": [], "presentation_messages": {"title": footer_title}}
    # A named view has its own field projection. In particular, a check title
    # must not inherit the HR category of the inventory's job-title column.
    return result(report, state=data["state"], items=data["items"], filtered_count=len(data["items"]),
                  collections={"checks": [*data["items"], footer]},
                  coverage=data["coverage"], metrics=[
                      {"key": "not_evaluated", "label": message(review_catalog.PREFIX + "not_evaluated")["text"],
                       "value": data["coverage"]["not_evaluated_count"]}])

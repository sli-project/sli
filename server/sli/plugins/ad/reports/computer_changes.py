"""Bounded computer differences from the same published agent slots as checks."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from server.sli.plugins.ad.reports import review_catalog, review_checks
from server.sli.reporting.v2.definition import result


def compare(bundle):
    """A snapshot difference is an observation, never a deletion or actor claim."""
    current, previous = bundle.get("current"), bundle.get("previous")
    if not current or not previous:
        return []
    observed = review_checks._time(current.get("observed_at"))
    before = {obj["object_guid"]: obj for obj in previous.get("objects") or [] if obj.get("object_guid")}
    after = {obj["object_guid"]: obj for obj in current.get("objects") or [] if obj.get("object_guid")}
    rows = []
    for guid in sorted(before.keys() | after.keys()):
        old, new = before.get(guid), after.get(guid)
        obj = new or old
        changes = []
        if not old or not new:
            changes.append(("new_object" if new else "missing_current", "presence", bool(old), bool(new)))
        else:
            for field, kind in (("enabled", "enabled_changed"), ("ou_path", "ou_changed"),
                                ("operating_system", "os_changed"), ("computer_type", "classification_changed"),
                                ("laps_password_expiration_utc", "laps_changed")):
                left, right = old.get(field), new.get(field)
                if left is not None and right is not None and left != right:
                    changes.append((kind, field, left, right))
            for field in ("unconstrained", "constrained", "resource_based"):
                left, right = (old.get("delegation") or {}).get(field), (new.get("delegation") or {}).get(field)
                if isinstance(left, bool) and isinstance(right, bool) and left != right:
                    changes.append(("delegation_changed", field, left, right))
        for kind, field, left, right in changes:
            rows.append({**obj, "row_id": f"{bundle['domain_id']}:{guid}:{kind}:{field}",
                         "domain_id": bundle["domain_id"], "domain_name": bundle["domain_name"],
                         "change_type": kind, "field": field, "before": left, "after": right,
                         "observed_at_utc": observed.isoformat() if observed else None, "actor": None,
                         "account_state": "enabled" if obj.get("enabled") is True else "disabled" if obj.get("enabled") is False else "unknown"})
    return rows


def query(report, context):
    if context.field_access and not context.field_access(review_catalog.COMPUTER_FIELDS):
        return result(report, state="denied")
    try:
        bundles = review_checks.load_snapshots("computers", context.domain_ids, None)
    except Exception:
        return result(report, state="error", coverage={"reason": "computer_changes_unavailable"})
    rows, domains, missing = [], [], []
    partial = False
    for bundle in bundles:
        current, previous = bundle.get("current"), bundle.get("previous")
        current_at = review_checks._time((current or {}).get("observed_at"))
        previous_at = review_checks._time((previous or {}).get("observed_at"))
        domains.append({"domain_id": bundle["domain_id"], "domain_name": bundle["domain_name"],
                        "state": (current or {}).get("state", "not_collected"),
                        "observed_at_utc": current_at.isoformat() if current_at else None})
        if not current or not previous or not current_at or not previous_at or current_at <= previous_at:
            missing.append(bundle["domain_name"])
            continue
        partial |= current.get("state") not in review_checks.COMPLETE or previous.get("state") not in review_checks.COMPLETE
        rows.extend(compare(bundle))
    needle = str(context.params.get("q") or "").strip().casefold()
    rows = [row for row in rows if not needle or needle in " ".join(str(row.get(key) or "") for key in (
        "display_name", "domain_name", "computer_type", "operating_system", "ou_path")).casefold()]
    rows.sort(key=lambda row: (str(row["observed_at_utc"] or ""), row["row_id"]), reverse=True)
    total = len(rows)
    if context.cursor:
        position = next((index for index, row in enumerate(rows) if row["row_id"] == context.cursor), None)
        if position is None:
            raise ValueError("computer_changes_cursor_invalid")
        rows = rows[position + 1:]
    page = rows[:context.limit]
    more = len(rows) > context.limit
    stamps = [review_checks._time(domain["observed_at_utc"]) for domain in domains]
    stale = any(stamp and datetime.now(timezone.utc) - stamp > timedelta(days=1) for stamp in stamps)
    state = "not_collected" if not bundles or len(missing) == len(bundles) else "partial" if partial or missing else "stale" if stale else "ok" if total else "empty"
    return result(report, state=state, items=page, collections={"changes": page}, filtered_count=None if state == "not_collected" else total,
                  has_more=more, next_cursor=page[-1]["row_id"] if more else None,
                  coverage={"domains": domains, "comparison_missing_domains": missing,
                            "freshness_threshold_seconds": 86400, "history_mode": "latest_compatible_agent_pair"})

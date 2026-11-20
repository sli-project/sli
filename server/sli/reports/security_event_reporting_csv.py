"""Split out of ``server.sli.reports.security_event_reporting`` (plan 7.2b).

Module-level names of ``security_event_reporting`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import server.sli.reports.security_event_reporting as _src


def render_security_events_csv(report: _src.Mapping[str, _src.Any]) -> str:
    """Render exactly the supplied filtered page; this function has no I/O."""

    output = _src.io.StringIO(newline="")
    writer = _src.csv.writer(output, lineterminator="\n")
    items = list(report.get("items") or [])
    has_more = bool(report.get("has_more"))
    incomplete = (
        has_more
        or str(report.get("state") or "") != "available"
        or any(str((item.get("evidence") or {}).get("state") or "") != "complete" for item in items)
    )
    coverage = report.get("category_coverage")
    coverage_text = _src.json.dumps(coverage, ensure_ascii=False, sort_keys=True, separators=(",", ":")) if isinstance(coverage, _src.Mapping) else "{}"
    writer.writerow([
        f"# has_more={str(has_more).lower()}",
        f"incomplete={str(incomplete).lower()}",
        f"# category_coverage={coverage_text}",
    ])
    writer.writerow([
        "event_db_id", "event_id", "event_family", "time_created_utc",
        "actor_sid", "actor_name", "affected_account_sid", "affected_account_name",
        "member_sid", "member_name", "group_sid", "group_name", "source_host",
        "caller_computer", "change_state", "change_kind", "change_observed_value",
        "outcome_state", "outcome_value", "outcome_result_code", "evidence_state",
        "has_more", "incomplete",
    ])
    for item in items:
        actor = dict(item.get("actor") or {})
        account = dict(item.get("affected_account") or {})
        member = dict(item.get("member") or {})
        group = dict(item.get("group") or {})
        host = dict(item.get("source_host") or {})
        caller = dict(item.get("caller_computer") or {})
        change = dict(item.get("change") or {})
        outcome = dict(item.get("outcome") or {})
        evidence = dict(item.get("evidence") or {})
        writer.writerow([_src._csv_cell(value) for value in [
            item.get("event_db_id"), item.get("event_id"), item.get("event_family"), item.get("time_created_utc"),
            actor.get("sid"), actor.get("name"), account.get("sid"), account.get("name"),
            member.get("sid"), member.get("name"), group.get("sid"), group.get("name"), host.get("hostname"),
            caller.get("hostname"), change.get("state"), change.get("kind"), change.get("observed_value"),
            outcome.get("state"), outcome.get("value"), outcome.get("result_code"), evidence.get("state"),
            str(has_more).lower(), str(incomplete).lower(),
        ]])
    return output.getvalue()

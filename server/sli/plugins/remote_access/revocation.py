"""Accounting continuation reader for the shared revocation report."""
from datetime import datetime
from typing import Any
from psycopg import errors
from server.sli.reports.account_revocation_reporting import MAX_SOURCE_ROWS


def _read_sessions(cur: Any, *, domain_id: int, start: datetime, end: datetime,
                   sids: list[str]) -> tuple[list[dict[str, Any]], str, bool]:
    if not sids:
        return [], "not_checked", False
    cur.execute("savepoint revocation_accounting")
    try:
        cur.execute("select to_regclass('radius_vpn_session_rows_v1') as relation")
        if not cur.fetchone()["relation"]:
            return [], "unavailable", False
        # The alias key (domain, type, normalized SID) is unique and indexed.
        # The session view resolves entity_id through the indexed exact principal.
        cur.execute(
            """select session.*,alias.normalized_value as target_user_sid
                 from ad_context_entity_aliases alias
                 join radius_vpn_session_rows_v1 session on session.entity_id=alias.entity_id
                  and session.domain_id=alias.domain_id
                where alias.domain_id=%s and alias.alias_type='object_sid'
                  and alias.normalized_value=any(%s)
                  and session.started_at_utc<%s and session.last_observed_at_utc>%s
                  and (session.stopped_at_utc is null or session.stopped_at_utc>%s)
                order by session.last_observed_at_utc desc,session.session_row_id limit %s""",
            [domain_id, sids, end, start, start, MAX_SOURCE_ROWS + 1],
        )
        rows = [dict(row) for row in cur.fetchall()]
        return rows[:MAX_SOURCE_ROWS], "available" if rows else "empty_unverified", len(rows) > MAX_SOURCE_ROWS
    except (errors.UndefinedTable, errors.UndefinedColumn, errors.InsufficientPrivilege):
        cur.execute("rollback to savepoint revocation_accounting")
        return [], "unavailable", False
    finally:
        cur.execute("release savepoint revocation_accounting")



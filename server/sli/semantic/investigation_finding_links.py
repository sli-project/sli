"""Link between a problem (finding) and an investigation case (migration 149).

A finding belongs to at most one case. Creating a case from a finding and
attaching a finding to an existing case both copy the finding's evidence
events into the case and write an ``investigation_audit`` row
``finding_linked``, all in one transaction.
"""
from __future__ import annotations

from typing import Any, Sequence
from uuid import UUID, uuid4

from server.sli.core.postgres_runtime_pipeline import connect
from server.sli.semantic.investigation_cases import (
    InvestigationCaseError,
    _case_row,
    _lock_event_evidence_writes,
)

_TITLE_LIMIT = 300
_EVENT_LIMIT = 200
_LOCK_NAMESPACE = 149


def _finding_row(cur: Any, finding_id: int) -> dict[str, Any]:
    if int(finding_id) <= 0:
        raise InvestigationCaseError("invalid_finding_id", "Finding ID must be positive")
    cur.execute(
        "select id, rule_code, title, status from findings where id=%s",
        (int(finding_id),),
    )
    row = cur.fetchone()
    if not row:
        raise InvestigationCaseError("finding_not_found", f"Finding {finding_id} was not found")
    return dict(row)


def _finding_event_ids(cur: Any, finding_id: int) -> list[int]:
    """Evidence events of one finding that still exist in the active event store."""
    cur.execute(
        """select distinct fe.event_id
           from finding_evidence fe
           join events_v2_core core on core.id=fe.event_id
           where fe.finding_id=%s
           order by fe.event_id desc
           limit %s""",
        (int(finding_id), _EVENT_LIMIT),
    )
    return [int(item["event_id"]) for item in cur.fetchall()]


def finding_event_ids(finding_id: int) -> list[int]:
    """Event IDs a finding would copy into a case (used for the scope check)."""
    with connect() as conn:
        with conn.cursor() as cur:
            _finding_row(cur, int(finding_id))
            return _finding_event_ids(cur, int(finding_id))


def _lock_finding(cur: Any, finding_id: int) -> None:
    cur.execute("select pg_advisory_xact_lock(%s, %s)", (_LOCK_NAMESPACE, int(finding_id)))


def _raise_if_linked(cur: Any, finding_id: int) -> None:
    cur.execute(
        "select investigation_id from investigation_finding_links where finding_id=%s",
        (int(finding_id),),
    )
    row = cur.fetchone()
    if row:
        case_id = int(row["investigation_id"])
        raise InvestigationCaseError(
            "finding_already_linked",
            f"Finding is already linked to investigation {case_id}",
            {"investigation_id": case_id},
        )


def _attach(cur: Any, *, case_id: int, finding_id: int, actor: str) -> None:
    _lock_event_evidence_writes(cur)
    cur.execute(
        """insert into investigation_finding_links(investigation_id, finding_id, linked_by)
           values (%s, %s, %s)""",
        (case_id, int(finding_id), actor),
    )
    copied = 0
    for event_db_id in _finding_event_ids(cur, int(finding_id)):
        cur.execute(
            """insert into investigation_events(investigation_id, event_db_id, relation_status, added_by)
               values (%s, %s, 'confirmed', %s)
               on conflict(investigation_id, event_db_id) do nothing
               returning event_db_id""",
            (case_id, event_db_id, actor),
        )
        if cur.fetchone():
            copied += 1
    cur.execute("update investigations set updated_at=now() where id=%s", (case_id,))
    cur.execute(
        """insert into investigation_audit(investigation_id, action, actor, payload)
           values (%s, 'finding_linked', %s,
                   jsonb_build_object('finding_id', %s::bigint, 'events_copied', %s::int))""",
        (case_id, actor, int(finding_id), copied),
    )


def create_case_from_finding(*, finding_id: int, actor: str) -> dict[str, Any]:
    """Create a case (owner = actor) from a finding and link them."""
    with connect() as conn:
        with conn.cursor() as cur:
            _lock_finding(cur, int(finding_id))
            finding = _finding_row(cur, int(finding_id))
            _raise_if_linked(cur, int(finding_id))
            label = str(finding.get("title") or "").strip() or str(finding.get("rule_code") or "").strip() or "Проблема"
            title = f"Проблема #{int(finding['id'])}: {label}"[:_TITLE_LIMIT]
            cur.execute(
                """insert into investigations(public_id, title, owner, created_by)
                   values (%s, %s, %s, %s) returning id""",
                (str(uuid4()), title, actor, actor),
            )
            case_id = int(cur.fetchone()["id"])
            cur.execute(
                "insert into investigation_audit(investigation_id, action, actor) values (%s, 'created', %s)",
                (case_id, actor),
            )
            _attach(cur, case_id=case_id, finding_id=int(finding_id), actor=actor)
            return _case_row(cur, case_id)


def link_finding_to_case(
    *, investigation_id: int | str | UUID, finding_id: int, actor: str,
) -> dict[str, Any]:
    """Attach a finding to an existing case that is not closed."""
    with connect() as conn:
        with conn.cursor() as cur:
            _lock_finding(cur, int(finding_id))
            _finding_row(cur, int(finding_id))
            case = _case_row(cur, investigation_id)
            if case.get("status") == "closed":
                raise InvestigationCaseError(
                    "investigation_case_closed", "A closed investigation cannot receive findings"
                )
            _raise_if_linked(cur, int(finding_id))
            _attach(cur, case_id=int(case["id"]), finding_id=int(finding_id), actor=actor)
            return _case_row(cur, int(case["id"]))


def linked_cases_for_findings(finding_ids: Sequence[int]) -> dict[int, dict[str, Any]]:
    """Case each finding is linked to: ``{finding_id: {id, public_id, status}}``."""
    ids = sorted({int(item) for item in finding_ids if int(item) > 0})
    if not ids:
        return {}
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """select link.finding_id, inv.id, inv.public_id, inv.status
                   from investigation_finding_links link
                   join investigations inv on inv.id=link.investigation_id
                   where link.finding_id=any(%s)""",
                (ids,),
            )
            return {
                int(row["finding_id"]): {
                    "id": int(row["id"]),
                    "public_id": str(row["public_id"]) if row.get("public_id") else None,
                    "status": row.get("status"),
                }
                for row in cur.fetchall()
            }

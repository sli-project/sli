"""PostgreSQL-backed investigation cases.

The module deliberately contains no runtime DDL.  Deploy migration 015 before
enabling these routes in a production environment.
"""
from __future__ import annotations

import re
from typing import Any, Sequence
from uuid import UUID, uuid4

from server.sli.core.postgres_runtime_pipeline import connect
from server.sli.storage.runtime_storage import StorageRouteConsumer, resolve_storage_route


VALID_STATUSES = frozenset({"new", "active", "review", "confirmed", "closed"})
STATUS_TRANSITIONS = {
    "new": frozenset({"active", "closed"}),
    "active": frozenset({"review", "confirmed", "closed"}),
    "review": frozenset({"active", "confirmed", "closed"}),
    "confirmed": frozenset({"active", "closed"}),
    "closed": frozenset({"active"}),
}
VPN_ACCOUNTING_EVIDENCE_KIND = "vpn_accounting_session"
_VPN_SESSION_ROW_ID = re.compile(r"radius-session-row:[0-9a-f]{64}", re.IGNORECASE)


class InvestigationCaseError(Exception):
    """Expected investigation-domain failure.

    This must not inherit from ``ValueError``: the HTTP mutation handlers use
    ``ValueError`` exclusively for malformed numeric identifiers.  Inheriting
    from it caused valid domain errors (including an event missing from the
    active store) to be reported incorrectly as ``invalid_event_db_id``.
    """

    def __init__(self, code: str, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.details = dict(details or {})


def _event_route(authorization: object | None) -> str:
    """Storage V2 is the only event store (plan 6.5): migration 097 dropped
    ``events``, so the former V1/dual lookups failed on every installation."""
    resolve_storage_route(
        authorization=authorization,
        consumer=StorageRouteConsumer.INVESTIGATIONS,
    )
    return "v2"


def _event_exists(
    cur: Any, event_db_id: int, *, authorization: object | None = None,
) -> bool:
    """Validate an evidence ID against the Storage V2 event store."""
    _event_route(authorization)
    cur.execute(
        "select exists(select 1 from events_v2_core where id=%s) as present",
        (int(event_db_id),),
    )
    return bool((cur.fetchone() or {}).get("present"))


def _event_exists_for_route(
    cur: Any, event_db_id: int, authorization: object | None,
) -> bool:
    if authorization is None:
        return _event_exists(cur, event_db_id)
    return _event_exists(cur, event_db_id, authorization=authorization)


def _case_identity(value: int | str | UUID) -> tuple[str, int | str]:
    if isinstance(value, int) or str(value).isdigit():
        numeric = int(value)
        if numeric <= 0:
            raise InvestigationCaseError("invalid_investigation_id", "Investigation ID must be positive")
        return "id", numeric
    try:
        return "public_id", str(UUID(str(value)))
    except (TypeError, ValueError, AttributeError) as exc:
        raise InvestigationCaseError("invalid_investigation_id", "Investigation ID is invalid") from exc


def _resource_group(row: dict[str, Any]) -> list[dict[str, Any]]:
    resources: list[dict[str, Any]] = []
    if row.get("server_id") is not None:
        resources.append({"kind": "server", "id": int(row["server_id"])})
    if row.get("domain_id") is not None:
        resources.append({"kind": "domain", "id": int(row["domain_id"])})
    if row.get("channel"):
        resources.append({"kind": "channel", "value": str(row["channel"])})
    return resources


def _resource_groups_for_case_ids(
    cur: Any,
    case_ids: Sequence[int],
    *,
    authorization: object | None = None,
) -> dict[int, list[list[dict[str, Any]]]]:
    ids = sorted({int(item) for item in case_ids if int(item) > 0})
    result = {case_id: [] for case_id in ids}
    if not ids:
        return result
    _event_route(authorization)
    source_sql = """
        select core.server_id, server.domain_id, channel.value as channel
        from events_v2_core core
        join servers server on server.id=core.server_id
        join storage_v2_channel channel on channel.id=core.channel_id
        where core.id=linked.event_db_id
    """
    cur.execute(
        f"""
        select linked.investigation_id, linked.event_db_id,
               source.server_id, source.domain_id, source.channel
        from investigation_events linked
        left join lateral (
            {source_sql}
        ) source on true
        where linked.investigation_id=any(%s)
        order by linked.investigation_id,linked.event_db_id
        """,
        (ids,),
    )
    seen: set[tuple[int, int]] = set()
    for stored in cur.fetchall():
        row = dict(stored)
        case_id = int(row["investigation_id"])
        event_db_id = int(row["event_db_id"])
        identity = (case_id, event_db_id)
        if identity in seen:
            continue
        seen.add(identity)
        result.setdefault(case_id, []).append(_resource_group(row))
    cur.execute(
        """select investigation_id,source_domain_id
           from investigation_evidence_refs
           where investigation_id=any(%s)
           order by investigation_id,source_domain_id,reference_id""",
        (ids,),
    )
    seen_typed: set[tuple[int, int]] = set()
    for stored in cur.fetchall():
        row = dict(stored)
        case_id = int(row["investigation_id"])
        domain_id = int(row["source_domain_id"])
        identity = (case_id, domain_id)
        if identity in seen_typed:
            continue
        seen_typed.add(identity)
        result.setdefault(case_id, []).append([{"kind": "domain", "id": domain_id}])
    return result


def case_resource_groups(
    investigation_id: int | str | UUID, *, authorization: object | None = None,
) -> list[list[dict[str, Any]]]:
    """Resolve protected dimensions from exact evidence already linked to a case."""
    identity_column, identity_value = _case_identity(investigation_id)
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(f"select id from investigations where {identity_column}=%s", (identity_value,))
            row = cur.fetchone()
            if not row:
                raise InvestigationCaseError("not_found", f"Investigation {identity_value} was not found")
            case_id = int(row["id"])
            return _resource_groups_for_case_ids(
                cur, [case_id], authorization=authorization,
            ).get(case_id, [])


def case_resource_groups_batch(
    case_ids: Sequence[int], *, authorization: object | None = None,
) -> dict[int, list[list[dict[str, Any]]]]:
    """Resolve resource groups for a bounded list without leaking them to the UI."""
    with connect() as conn:
        with conn.cursor() as cur:
            return _resource_groups_for_case_ids(
                cur, case_ids, authorization=authorization,
            )


def event_resource_group(
    event_db_id: int, *, authorization: object | None = None,
) -> list[dict[str, Any]]:
    """Resolve one exact event into equivalent server/domain/channel dimensions."""
    event_id = int(event_db_id)
    if event_id <= 0:
        raise InvestigationCaseError("event_not_found", f"Event {event_id} was not found")
    with connect() as conn:
        with conn.cursor() as cur:
            _event_route(authorization)
            query = """
                select core.server_id,server.domain_id,channel.value as channel
                from events_v2_core core
                join servers server on server.id=core.server_id
                join storage_v2_channel channel on channel.id=core.channel_id
                where core.id=%s
            """
            params = (event_id,)
            cur.execute(query, params)
            row = cur.fetchone()
    if not row:
        raise InvestigationCaseError("event_not_found", f"Event {event_id} was not found")
    resources = _resource_group(dict(row))
    if not resources:
        raise InvestigationCaseError("unavailable", "Event resource context is unavailable")
    return resources


def _case_row(cur: Any, investigation_id: int | str | UUID, *, include_links: bool = True) -> dict[str, Any]:
    identity_column, identity_value = _case_identity(investigation_id)
    cur.execute(
        f"""select id, public_id, title, status, owner, created_by, created_at, updated_at, closed_at
           from investigations where {identity_column}=%s""",
        (identity_value,),
    )
    row = cur.fetchone()
    if not row:
        raise InvestigationCaseError("not_found", f"Investigation {identity_value} was not found")
    result = dict(row)
    case_id = int(result["id"])
    if include_links:
        cur.execute(
            """select event_db_id, relation_status, added_by, added_at
               from investigation_events where investigation_id=%s order by added_at desc limit 500""",
            (case_id,),
        )
        result["events"] = [dict(item) for item in cur.fetchall()]
        cur.execute(
            """select evidence_kind,source_domain_id,reference_id,relation_status,added_by,added_at
               from investigation_evidence_refs where investigation_id=%s
               order by added_at desc,evidence_kind,reference_id limit 500""",
            (case_id,),
        )
        result["evidence_refs"] = [dict(item) for item in cur.fetchall()]
    cur.execute(
        """select id, body, created_by, created_at from investigation_notes
           where investigation_id=%s order by created_at desc limit 100""",
        (case_id,),
    )
    result["notes"] = [dict(item) for item in cur.fetchall()]
    return result


def _lock_event_evidence_writes(cur: Any) -> None:
    """Fence event validation and insertion against hot-retention deletion.

    Acquire before reading event existence, in the same transaction as the
    case link. Retention uses SHARE NOWAIT before locking event rows, so an
    active case writer makes retention fail closed instead of deadlocking.
    """
    # A finding-copy transaction may already have read metadata. Refuse a
    # snapshot that can remain older than a retention commit after this fence.
    cur.execute("show transaction_isolation")
    if (cur.fetchone() or {}).get("transaction_isolation") != "read committed":
        raise InvestigationCaseError(
            "evidence_write_requires_read_committed",
            "Investigation evidence writes require READ COMMITTED isolation",
        )
    cur.execute("lock table investigation_events in row exclusive mode")


def create_case(
    *,
    title: str,
    actor: str,
    owner: str | None = None,
    event_db_id: int | None = None,
    authorization: object | None = None,
) -> dict[str, Any]:
    clean_title = str(title or "").strip()[:300]
    if not clean_title:
        raise InvestigationCaseError("invalid_title", "Investigation title is required")
    with connect() as conn:
        with conn.cursor() as cur:
            if event_db_id is not None:
                _lock_event_evidence_writes(cur)
                if not _event_exists_for_route(cur, int(event_db_id), authorization):
                    raise InvestigationCaseError("event_not_found", f"Event {event_db_id} was not found")
            public_id = str(uuid4())
            cur.execute(
                """insert into investigations(public_id, title, owner, created_by) values (%s, %s, %s, %s)
                   returning id""",
                (public_id, clean_title, str(owner or "").strip()[:200] or None, actor),
            )
            investigation_id = int(cur.fetchone()["id"])
            cur.execute(
                "insert into investigation_audit(investigation_id, action, actor) values (%s, 'created', %s)",
                (investigation_id, actor),
            )
            if event_db_id is not None:
                cur.execute(
                    """insert into investigation_events(investigation_id, event_db_id, relation_status, added_by)
                       values (%s, %s, 'confirmed', %s)""",
                    (investigation_id, int(event_db_id), actor),
                )
                cur.execute(
                    """insert into investigation_audit(investigation_id, action, actor, payload)
                       values (%s, 'event_linked', %s, jsonb_build_object('event_db_id', %s, 'relation_status', 'confirmed'))""",
                    (investigation_id, actor, int(event_db_id)),
                )
            return _case_row(cur, investigation_id)


def get_case(investigation_id: int | str | UUID) -> dict[str, Any]:
    with connect() as conn:
        with conn.cursor() as cur:
            result = _case_row(cur, investigation_id)
            cur.execute(
                """select id, action, actor, payload, created_at from investigation_audit
                   where investigation_id=%s order by created_at desc,id desc limit 200""",
                (int(result["id"]),),
            )
            result["audit"] = [dict(item) for item in cur.fetchall()]
            return result


def list_cases(*, limit: int = 50) -> list[dict[str, Any]]:
    safe_limit = max(1, min(int(limit), 100))
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """select id, public_id, title, status, owner, created_by, created_at, updated_at, closed_at
                   from investigations order by updated_at desc limit %s""",
                (safe_limit,),
            )
            return [dict(row) for row in cur.fetchall()]


def add_event(
    *,
    investigation_id: int | str | UUID,
    event_db_id: int,
    actor: str,
    relation_status: str = "confirmed",
    authorization: object | None = None,
) -> dict[str, Any]:
    state = str(relation_status or "confirmed").lower()
    if state not in {"confirmed", "excluded"}:
        raise InvestigationCaseError("invalid_relation_status", "Relation status must be confirmed or excluded")
    with connect() as conn:
        with conn.cursor() as cur:
            _lock_event_evidence_writes(cur)
            case_id = int(_case_row(cur, investigation_id)["id"])
            if not _event_exists_for_route(cur, int(event_db_id), authorization):
                raise InvestigationCaseError("event_not_found", f"Event {event_db_id} was not found")
            cur.execute(
                """insert into investigation_events(investigation_id, event_db_id, relation_status, added_by)
                   values (%s, %s, %s, %s)
                   on conflict(investigation_id, event_db_id) do nothing
                   returning event_db_id, relation_status, added_by, added_at""",
                (case_id, int(event_db_id), state, actor),
            )
            inserted = cur.fetchone()
            if not inserted:
                cur.execute(
                    """select event_db_id, relation_status, added_by, added_at
                       from investigation_events where investigation_id=%s and event_db_id=%s""",
                    (case_id, int(event_db_id)),
                )
                existing = dict(cur.fetchone() or {})
                if existing.get("relation_status") != state:
                    raise InvestigationCaseError(
                        "conflict", "Evidence already exists with a different relation status"
                    )
                return {**existing, "idempotent_replay": True}
            item = dict(inserted)
            cur.execute("update investigations set updated_at=now() where id=%s", (case_id,))
            cur.execute(
                """insert into investigation_audit(investigation_id, action, actor, payload)
                   values (%s, 'event_linked', %s, jsonb_build_object('event_db_id', %s, 'relation_status', %s::text))""",
                (case_id, actor, int(event_db_id), state),
            )
            return item


def _vpn_session_exists(cur: Any, *, source_domain_id: int, session_row_id: str) -> bool:
    from server.sli.plugins.registry import plugin_hook

    hook = plugin_hook("sli.remote-access", "session_exists")
    return bool(hook and hook(cur, source_domain_id=source_domain_id, session_row_id=session_row_id))


def add_evidence_ref(
    *,
    investigation_id: int | str | UUID,
    evidence_kind: str,
    source_domain_id: int,
    reference_id: str,
    actor: str,
    relation_status: str = "confirmed",
) -> dict[str, Any]:
    kind = str(evidence_kind or "").strip()
    domain_id = int(source_domain_id)
    reference = str(reference_id or "").strip()
    state = str(relation_status or "confirmed").strip().lower()
    if kind != VPN_ACCOUNTING_EVIDENCE_KIND:
        raise InvestigationCaseError("invalid_evidence_kind", "Unsupported evidence kind")
    if domain_id <= 0 or not _VPN_SESSION_ROW_ID.fullmatch(reference):
        raise InvestigationCaseError("invalid_evidence_ref", "Accounting evidence reference is invalid")
    if state not in {"confirmed", "excluded"}:
        raise InvestigationCaseError("invalid_relation_status", "Relation status must be confirmed or excluded")
    with connect() as conn:
        with conn.cursor() as cur:
            case_id = int(_case_row(cur, investigation_id)["id"])
            if not _vpn_session_exists(
                cur, source_domain_id=domain_id, session_row_id=reference,
            ):
                raise InvestigationCaseError("not_found", "Investigation evidence was not found")
            cur.execute(
                """insert into investigation_evidence_refs(
                       investigation_id,evidence_kind,source_domain_id,reference_id,
                       relation_status,added_by
                   ) values (%s,%s,%s,%s,%s,%s)
                   on conflict(investigation_id,evidence_kind,source_domain_id,reference_id)
                   do nothing
                   returning evidence_kind,source_domain_id,reference_id,
                             relation_status,added_by,added_at""",
                (case_id, kind, domain_id, reference, state, actor),
            )
            inserted = cur.fetchone()
            if not inserted:
                cur.execute(
                    """select evidence_kind,source_domain_id,reference_id,
                              relation_status,added_by,added_at
                       from investigation_evidence_refs
                       where investigation_id=%s and evidence_kind=%s
                         and source_domain_id=%s and reference_id=%s""",
                    (case_id, kind, domain_id, reference),
                )
                existing = dict(cur.fetchone() or {})
                if existing.get("relation_status") != state:
                    raise InvestigationCaseError(
                        "conflict", "Evidence already exists with a different relation status"
                    )
                return {**existing, "idempotent_replay": True}
            item = dict(inserted)
            cur.execute("update investigations set updated_at=now() where id=%s", (case_id,))
            cur.execute(
                """insert into investigation_audit(investigation_id,action,actor,payload)
                   values (%s,'evidence_ref_linked',%s,
                     jsonb_build_object(
                       'evidence_kind',%s::text,'source_domain_id',%s,
                       'reference_id',%s::text,'relation_status',%s::text
                     ))""",
                (case_id, actor, kind, domain_id, reference, state),
            )
            return item


def remove_event(*, investigation_id: int | str | UUID, event_db_id: int, actor: str) -> dict[str, Any]:
    with connect() as conn:
        with conn.cursor() as cur:
            case_id = int(_case_row(cur, investigation_id)["id"])
            cur.execute(
                """delete from investigation_events
                   where investigation_id=%s and event_db_id=%s
                   returning event_db_id""",
                (case_id, int(event_db_id)),
            )
            removed = cur.fetchone()
            if not removed:
                raise InvestigationCaseError("not_found", "Investigation evidence was not found")
            cur.execute("update investigations set updated_at=now() where id=%s", (case_id,))
            cur.execute(
                """insert into investigation_audit(investigation_id, action, actor, payload)
                   values (%s, 'event_unlinked', %s, jsonb_build_object('event_db_id', %s))""",
                (case_id, actor, int(event_db_id)),
            )
            return {"event_db_id": int(removed["event_db_id"]), "removed": True}


def assign_owner(*, investigation_id: int | str | UUID, owner: str | None, actor: str) -> dict[str, Any]:
    clean_owner = str(owner or "").strip()[:200] or None
    with connect() as conn:
        with conn.cursor() as cur:
            current = _case_row(cur, investigation_id)
            case_id = int(current["id"])
            if current.get("owner") == clean_owner:
                return {**current, "idempotent_replay": True}
            cur.execute(
                "update investigations set owner=%s, updated_at=now() where id=%s",
                (clean_owner, case_id),
            )
            cur.execute(
                """insert into investigation_audit(investigation_id, action, actor, payload)
                   values (%s, 'owner_changed', %s, jsonb_build_object('old_owner', %s::text, 'new_owner', %s::text))""",
                (case_id, actor, current.get("owner"), clean_owner),
            )
            return _case_row(cur, case_id)


def add_note(*, investigation_id: int | str | UUID, body: str, actor: str) -> dict[str, Any]:
    clean_body = str(body or "").strip()[:4000]
    if not clean_body:
        raise InvestigationCaseError("invalid_note", "Note text is required")
    with connect() as conn:
        with conn.cursor() as cur:
            case_id = int(_case_row(cur, investigation_id)["id"])
            cur.execute(
                """insert into investigation_notes(investigation_id, body, created_by)
                   values (%s, %s, %s) returning id, body, created_by, created_at""",
                (case_id, clean_body, actor),
            )
            item = dict(cur.fetchone())
            cur.execute("update investigations set updated_at=now() where id=%s", (case_id,))
            cur.execute(
                "insert into investigation_audit(investigation_id, action, actor) values (%s, 'note_added', %s)",
                (case_id, actor),
            )
            return item


def update_case_status(*, investigation_id: int | str | UUID, status: str, actor: str) -> dict[str, Any]:
    target = str(status or "").strip().lower()
    if target not in VALID_STATUSES:
        raise InvestigationCaseError("invalid_status", "Unsupported investigation status")
    with connect() as conn:
        with conn.cursor() as cur:
            current = _case_row(cur, investigation_id)
            case_id = int(current["id"])
            if current["status"] == target:
                return {**current, "idempotent_replay": True}
            if target not in STATUS_TRANSITIONS.get(str(current["status"]), frozenset()):
                raise InvestigationCaseError(
                    "conflict", f"Transition {current['status']} -> {target} is not allowed"
                )
            cur.execute(
                """update investigations
                   set status=%s, updated_at=now(),
                       closed_at=case when %s = 'closed' then now() else null end
                   where id=%s""",
                (target, target, case_id),
            )
            cur.execute(
                """insert into investigation_audit(investigation_id, action, actor, payload)
                   values (%s, 'status_changed', %s, jsonb_build_object('old_status', %s::text, 'new_status', %s::text))""",
                (case_id, actor, current["status"], target),
            )
            return _case_row(cur, case_id)


# Page order is immutable evidence identity, not mutable metadata/event time.
# Every response has its own snapshot; cursors are not cross-request snapshots.
CASE_EVIDENCE_PAGE_SIZE = 100


def _positive_evidence_id(value: Any) -> int | None:
    if value is None:
        return None
    if type(value) is int:
        if 0 < value < 2**63:
            return value
    elif isinstance(value, str) and 1 <= len(value) <= 19 and re.fullmatch(r"[0-9]+", value):
        try:
            numeric = int(value)
        except ValueError as exc:
            raise InvestigationCaseError("invalid_cursor", "Invalid evidence cursor or anchor") from exc
        if 0 < numeric < 2**63:
            return numeric
    raise InvestigationCaseError("invalid_cursor", "Invalid evidence cursor or anchor")


def _event_evidence_page(cur: Any, case_id: int, *, after: Any, anchor: Any) -> dict[str, Any]:
    after_id = _positive_evidence_id(after)
    anchor_id = _positive_evidence_id(anchor)
    cur.execute("select count(*) as total from investigation_events where investigation_id=%s", (case_id,))
    total = int(cur.fetchone()["total"])
    predicate = " and event_db_id < %s" if after_id is not None else ""
    params = (case_id, after_id, CASE_EVIDENCE_PAGE_SIZE + 1) if after_id is not None else (case_id, CASE_EVIDENCE_PAGE_SIZE + 1)
    cur.execute(
        "select event_db_id,relation_status,added_by,added_at from investigation_events "
        f"where investigation_id=%s{predicate} order by event_db_id desc limit %s", params,
    )
    rows = [dict(row) for row in cur.fetchall()]
    page = rows[:CASE_EVIDENCE_PAGE_SIZE]
    anchored = None
    if anchor_id is not None:
        cur.execute(
            "select event_db_id,relation_status,added_by,added_at from investigation_events "
            "where investigation_id=%s and event_db_id=%s", (case_id, anchor_id),
        )
        row = cur.fetchone()
        anchored = dict(row) if row else None
    return {"events": page, "events_total": total,
            "events_next_cursor": page[-1]["event_db_id"] if len(rows) > CASE_EVIDENCE_PAGE_SIZE else None,
            "anchor_event": anchored}


def _typed_evidence_page(cur: Any, case_id: int, *, after: str | None, allowed: Any) -> dict[str, Any]:
    import base64
    import json

    key = None
    if after is not None:
        try:
            if not after or len(after) > 1024:
                raise ValueError("length")
            key = json.loads(base64.b64decode(after.encode("ascii"), altchars=b"-_", validate=True))
            if (not isinstance(key, list) or len(key) != 3 or key[0] != VPN_ACCOUNTING_EVIDENCE_KIND
                    or type(key[1]) is not int or not 0 < key[1] < 2**63
                    or not isinstance(key[2], str) or len(key[2]) > 200):
                raise ValueError("shape")
        except (ValueError, TypeError, UnicodeError) as exc:
            raise InvestigationCaseError("invalid_cursor", "Invalid reference cursor") from exc
    cur.execute("select distinct source_domain_id from investigation_evidence_refs where investigation_id=%s", (case_id,))
    domains = [int(row["source_domain_id"]) for row in cur.fetchall()]
    visible_domains = [domain for domain in domains if allowed(domain)]
    result: dict[str, Any] = {"evidence_refs": [], "evidence_refs_total": 0, "evidence_refs_next_cursor": None,
                              "evidence_refs_state": "partially_authorized" if len(visible_domains) != len(domains) else "available"}
    if not visible_domains:
        return result
    cur.execute("select count(*) as total from investigation_evidence_refs where investigation_id=%s and source_domain_id=any(%s)", (case_id, visible_domains))
    result["evidence_refs_total"] = int(cur.fetchone()["total"])
    predicate = " and (evidence_kind,source_domain_id,reference_id) > (%s,%s,%s)" if key else ""
    params = (case_id, visible_domains, *(key or []), CASE_EVIDENCE_PAGE_SIZE + 1)
    cur.execute(
        "select evidence_kind,source_domain_id,reference_id,relation_status,added_by,added_at "
        "from investigation_evidence_refs where investigation_id=%s and source_domain_id=any(%s)"
        f"{predicate} order by evidence_kind,source_domain_id,reference_id limit %s", params,
    )
    rows = [dict(row) for row in cur.fetchall()]
    result["evidence_refs"] = rows[:CASE_EVIDENCE_PAGE_SIZE]
    if len(rows) > CASE_EVIDENCE_PAGE_SIZE:
        last = result["evidence_refs"][-1]
        result["evidence_refs_next_cursor"] = base64.urlsafe_b64encode(json.dumps(
            [last["evidence_kind"], last["source_domain_id"], last["reference_id"]], separators=(",", ":"),
        ).encode()).decode()
    return result


def get_case_evidence_page(
    investigation_id: int | str | UUID, *, case_allowed: Any, reference_allowed: Any,
    event_after: Any = None, reference_after: str | None = None, anchor_event_id: Any = None,
    authorization: object | None = None,
) -> dict[str, Any]:
    """Bounded read with exact whole-case authorization in the same snapshot.

    Resource resolution remains O(case size), deliberately: sampling it would
    weaken authorization. A shared eight-second SQL budget fails closed.
    """
    import time

    import psycopg

    from server.sli.core.database import QueryTimeoutError
    from server.sli.reporting.read_timeout import report_read_budget

    deadline = time.monotonic() + 8

    class BudgetCursor:
        def __init__(self, cursor: Any):
            self.cursor = cursor

        def execute(self, sql: str, params: Any = ()) -> None:
            remaining = int((deadline - time.monotonic()) * 1000)
            if remaining <= 0:
                raise InvestigationCaseError("unavailable", "Case evidence read budget exceeded")
            self.cursor.execute("select set_config('statement_timeout', %s, true)", (str(remaining),))
            self.cursor.execute(sql, params)

        def fetchone(self):
            return self.cursor.fetchone()

        def fetchall(self):
            return self.cursor.fetchall()

    try:
        with report_read_budget(), connect() as conn, conn.cursor() as raw_cur:
            raw_cur.execute("set transaction isolation level repeatable read, read only")
            cur = BudgetCursor(raw_cur)
            identity_column, identity_value = _case_identity(investigation_id)
            cur.execute(f"select id from investigations where {identity_column}=%s", (identity_value,))
            row = cur.fetchone()
            if not row:
                raise InvestigationCaseError("not_found", "Investigation was not found")
            case_id = int(row["id"])
            groups = _resource_groups_for_case_ids(cur, [case_id], authorization=authorization).get(case_id, [])
            if not case_allowed(groups):
                raise InvestigationCaseError("not_found", "Investigation was not found")
            result = _case_row(cur, case_id, include_links=False)
            cur.execute(
                """select id, action, actor, payload, created_at from investigation_audit
                   where investigation_id=%s order by created_at desc,id desc limit 200""",
                (case_id,),
            )
            result["audit"] = [dict(item) for item in cur.fetchall()]
            result.update(_event_evidence_page(cur, case_id, after=event_after, anchor=anchor_event_id))
            result.update(_typed_evidence_page(cur, case_id, after=reference_after, allowed=reference_allowed))
            result["evidence_page_size"] = CASE_EVIDENCE_PAGE_SIZE
            if time.monotonic() >= deadline:
                raise InvestigationCaseError("unavailable", "Case evidence read budget exceeded")
            return result
    except (psycopg.Error, QueryTimeoutError) as exc:
        raise InvestigationCaseError("unavailable", "Case evidence is temporarily unavailable") from exc

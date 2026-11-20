"""Bounded, audited replay of quarantined normalization jobs.

Run with ``python -m server.sli.semantic.semantic_quarantine_replay --help``.
The original outbox record is immutable; the audit is the resolution receipt.
"""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime
from hashlib import sha256
import json
import re
from typing import Any

from server.sli.semantic.semantic_processing import (
    ASSEMBLER_VERSION, SEMANTIC_CONTRACT_VERSION, apply_identity_role_overrides,
    assemble_canonical_actions, normalize_semantic_source_payload,
)
from server.sli.semantic.semantic_processing_repository import (
    PROCESSOR_ID, PROCESSOR_VERSION, load_identity_role_overrides,
    load_semantic_source_event, lock_semantic_source, persist_canonical_actions,
    persist_normalized_event, semantic_source_identity,
)

AUDIT_ACTION = "semantic_quarantine_resolution"
CLOSE_REASONS = ("source_unavailable", "canonical_conflict", "superseded", "unsupported_failure")
FINGERPRINT_FIELDS = (
    "job_id", "source_event_id", "job_kind", "status", "semantic_contract_version",
    "processor_id", "processor_version", "attempt_count", "max_attempts",
    "updated_at", "last_error_code", "last_error_detail", "payload_json",
    "source_identity_json",
)


def _digest(value: Any) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def _fingerprint(row: dict[str, Any]) -> str:
    return _digest({key: row.get(key) for key in FINGERPRINT_FIELDS})


@dataclass(frozen=True)
class Selection:
    reasons: tuple[str, ...]
    source_id_min: int | None = None
    source_id_max: int | None = None
    since: datetime | None = None
    until: datetime | None = None
    limit: int = 100
    close_reason: str | None = None
    dispatch: bool = False

    def __post_init__(self):
        if not self.reasons or any(re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,127}", r) is None for r in self.reasons):
            raise ValueError("invalid_reason")
        if not 1 <= self.limit <= 1000:
            raise ValueError("invalid_limit")
        if any(v is not None and v <= 0 for v in (self.source_id_min, self.source_id_max)):
            raise ValueError("invalid_source_range")
        if self.source_id_min is not None and self.source_id_max is not None and self.source_id_min > self.source_id_max:
            raise ValueError("invalid_source_range")
        if any(v is not None and v.utcoffset() is None for v in (self.since, self.until)):
            raise ValueError("timezone_required")
        if self.since is not None and self.until is not None and self.since >= self.until:
            raise ValueError("invalid_time_range")
        if self.close_reason is not None and self.close_reason not in CLOSE_REASONS:
            raise ValueError("invalid_close_reason")


def _select(cur: Any, selection: Selection) -> list[dict[str, Any]]:
    filters = ["status='quarantined'", "last_error_code=any(%s)"]
    params: list[Any] = [list(selection.reasons)]
    for column, operator, value in (
        ("source_event_id", ">=", selection.source_id_min),
        ("source_event_id", "<=", selection.source_id_max),
        ("updated_at", ">=", selection.since),
        ("updated_at", "<", selection.until),
    ):
        if value is not None:
            filters.append(f"{column} {operator} %s")
            params.append(value)
    params.append(selection.limit + 1)
    cur.execute(
        "select * from semantic_processing_outbox where " + " and ".join(filters)
        + " order by source_event_id,job_id limit %s", tuple(params),
    )
    rows = [dict(row) for row in cur.fetchall()]
    if len(rows) > selection.limit:
        raise ValueError("selection_limit_exceeded")
    return rows


def _resolved(cur: Any, rows: list[dict[str, Any]], *, dispatch: bool) -> set[str]:
    if not rows:
        return set()
    fingerprints = {str(row["job_id"]): _fingerprint(row) for row in rows}
    cur.execute(
        """select target,details from semantic_control_audit
           where action=%s and target=any(%s)
             and (details->>'outcome'='closed' or
                  (details->>'outcome'='replayed'
                   and details->>'processor_version'=%s
                   and details->>'assembler_version'=%s))""",
        (AUDIT_ACTION, list(fingerprints), PROCESSOR_VERSION, ASSEMBLER_VERSION),
    )
    resolved = set()
    for receipt in cur.fetchall():
        details = receipt["details"]
        if isinstance(details, str):
            details = json.loads(details)
        target = str(receipt["target"])
        if (details.get("original_fingerprint") == fingerprints.get(target)
            and (details.get("outcome") == "closed" or not dispatch or details.get("dispatch") is True)):
            resolved.add(target)
    return resolved


def _retry_reason(row: dict[str, Any]) -> str | None:
    if (row.get("job_kind") != "normalize_event"
        or row.get("processor_id") != PROCESSOR_ID
        or row.get("semantic_contract_version") != SEMANTIC_CONTRACT_VERSION):
        return None
    try:
        identity = semantic_source_identity(row.get("source_identity_json") or {})
        if identity["id"] != row["source_event_id"]:
            return None
    except (ValueError, TypeError, RuntimeError):
        return None
    detail = str(row.get("last_error_detail") or "")
    if row.get("last_error_code") == "QueryCanceled" and detail.strip() in {
        "canceling statement due to statement timeout",
        "cancelling statement due to statement timeout",
    }:
        return "retry_statement_timeout"
    if row.get("last_error_code") == "UniqueViolation" and re.search(r"['\"]canonical_actions_pkey['\"]", detail):
        return "fixed_canonical_identity"
    missing = f"published archive block not found for event {row['source_event_id']}"
    if row.get("last_error_code") == "KeyError" and detail in {missing, repr(missing), "'sli.windows.ad-dc'", '"sli.windows.ad-dc"'}:
        return "fixed_source_lookup"
    return None


def _replay(cur: Any, row: dict[str, Any], *, archive: Any, dispatch: bool) -> int:
    source = load_semantic_source_event(
        cur, source_event_id=int(row["source_event_id"]), archive=archive,
        source_identity=row["source_identity_json"],
    )
    if source is None:
        raise LookupError("source_unavailable")
    normalized = normalize_semantic_source_payload(source)
    normalized = apply_identity_role_overrides(normalized, load_identity_role_overrides(cur, event=normalized))
    normalized_id = persist_normalized_event(cur, event=normalized, source_identity=row["source_identity_json"])
    action_ids = persist_canonical_actions(cur, actions=assemble_canonical_actions((normalized,)))
    if dispatch:
        from server.sli.semantic.semantic_dispatch_repository import enqueue_dispatch_jobs
        enqueue_dispatch_jobs(cur, normalized_event_id=normalized_id)
    return len(action_ids)


def _failure_reason(exc: Exception) -> str:
    from server.sli.storage.storage_v2_archive import ArchiveIntegrityError

    if isinstance(exc, ArchiveIntegrityError):
        return "source_integrity_failed"
    if isinstance(exc, LookupError):
        return "source_unavailable"
    if isinstance(exc, RuntimeError) and str(exc).startswith("canonical action "):
        return "canonical_conflict"
    return "replay_failed"


def _record(cur: Any, row: dict[str, Any], *, outcome: str, reason: str, plan_digest: str,
            dispatch: bool, actions: int = 0) -> None:
    # Never store exception text or the immutable source identity in the audit.
    details = {
        "job_id": str(row["job_id"]), "source_event_id": int(row["source_event_id"]),
        "outcome": outcome, "reason": reason, "plan_digest": plan_digest,
        "original_fingerprint": _fingerprint(row), "processor_version": PROCESSOR_VERSION,
        "assembler_version": ASSEMBLER_VERSION, "actions": actions, "dispatch": dispatch,
    }
    cur.execute(
        """insert into semantic_control_audit(action,target,actor,details)
           values(%s,%s,session_user,%s::jsonb)""",
        (AUDIT_ACTION, str(row["job_id"]), json.dumps(details, sort_keys=True)),
    )


def run(conn: Any, selection: Selection, *, archive: Any = None, apply: bool = False, plan_digest: str = "") -> dict[str, Any]:
    """Preview without source I/O; apply each resolution in its own transaction."""
    with conn.transaction(), conn.cursor() as cur:
        cur.execute("set transaction read only")
        rows = _select(cur, selection)
        resolved = _resolved(cur, rows, dispatch=selection.dispatch)
    digest = _digest({
        "selection": asdict(selection), "rows": [_fingerprint(row) for row in rows],
        "processor_version": PROCESSOR_VERSION, "assembler_version": ASSEMBLER_VERSION,
    })
    counts = Counter(selected=len(rows), retryable=0, blocked=0, already_resolved=0,
                     replayed=0, closed=0, failed=0, changed=0, actions=0)
    decisions: Counter[str] = Counter()
    failures: Counter[str] = Counter()
    if apply and plan_digest != digest:
        raise ValueError("plan_changed")
    for row in rows:
        job_id = str(row["job_id"])
        reason = selection.close_reason or _retry_reason(row)
        if job_id in resolved:
            counts["already_resolved"] += 1
            continue
        if reason is None:
            counts["blocked"] += 1
            decisions["unsupported_failure"] += 1
            continue
        decisions[reason] += 1
        if not apply:
            counts["closed" if selection.close_reason else "retryable"] += 1
            continue
        with conn.transaction(), conn.cursor() as cur:
            lock_semantic_source(cur, source_event_id=int(row["source_event_id"]))
            cur.execute("select * from semantic_processing_outbox where job_id=%s for update", (job_id,))
            current = dict(cur.fetchone() or {})
            if _fingerprint(current) != _fingerprint(row):
                counts["changed"] += 1
                continue
            if job_id in _resolved(cur, [row], dispatch=selection.dispatch):
                counts["already_resolved"] += 1
                continue
            if selection.close_reason:
                _record(cur, row, outcome="closed", reason=reason, plan_digest=digest, dispatch=selection.dispatch)
                counts["closed"] += 1
                continue
            try:
                # A failed job rolls back normalization, canonical writes and
                # dispatch together. Its safe failure receipt remains durable.
                with conn.transaction():
                    actions = _replay(cur, row, archive=archive, dispatch=selection.dispatch)
                    _record(cur, row, outcome="replayed", reason=reason, plan_digest=digest,
                            dispatch=selection.dispatch, actions=actions)
            except Exception as exc:
                failure_reason = _failure_reason(exc)
                _record(cur, row, outcome="failed", reason=failure_reason, plan_digest=digest, dispatch=selection.dispatch)
                counts["failed"] += 1
                failures[failure_reason] += 1
            else:
                counts["replayed"] += 1
                counts["actions"] += actions
    return {"mode": "apply" if apply else "dry_run", "plan_digest": digest,
            "decisions": dict(decisions), "failures": dict(failures), **counts}


def _connect():
    import psycopg
    from psycopg.rows import dict_row
    from server.sli.core.secret_files import postgres_secret_parts

    parts = postgres_secret_parts("ADLOG_SEMANTIC_REPLAY_DSN")
    if not parts:
        raise ValueError("replay_dsn_required")
    parts.update(autocommit=True, row_factory=dict_row, connect_timeout=5,
                 application_name="sli_semantic_quarantine_replay",
                 options="-c statement_timeout=30000 -c lock_timeout=5000")
    return psycopg.connect(**parts)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="Default; count only, with no source hydration or writes.")
    mode.add_argument("--apply", action="store_true")
    parser.add_argument("--reason", action="append", required=True, help="Exact last_error_code; repeat to select multiple reasons.")
    parser.add_argument("--source-id-min", type=int, help="Inclusive source_event_id lower bound.")
    parser.add_argument("--source-id-max", type=int, help="Inclusive source_event_id upper bound.")
    parser.add_argument("--since", type=datetime.fromisoformat, help="Inclusive quarantine updated_at, with timezone.")
    parser.add_argument("--until", type=datetime.fromisoformat, help="Exclusive quarantine updated_at, with timezone.")
    parser.add_argument("--limit", type=int, default=100, help="Maximum selected rows (1..1000); excess fails closed.")
    parser.add_argument("--plan-digest", default="", help="Exact digest returned by the identical dry-run selection.")
    parser.add_argument("--close-reason", choices=CLOSE_REASONS, help="Explicitly close in audit instead of replaying.")
    parser.add_argument("--dispatch", action="store_true", help="Also enqueue current correlation rules, idempotently.")
    args = parser.parse_args(argv)
    if args.apply and re.fullmatch(r"[0-9a-f]{64}", args.plan_digest) is None:
        parser.error("--apply requires --plan-digest from dry-run")
    try:
        selection = Selection(tuple(sorted(set(args.reason))), args.source_id_min, args.source_id_max,
                              args.since, args.until, args.limit, args.close_reason, args.dispatch)
        with _connect() as conn:
            archive = None
            if args.apply and not args.close_reason:
                from server.sli.storage.storage_v2_archive import ArchiveReader
                from server.sli.storage.storage_v2_repository import PostgresArchiveManifestStore
                archive = ArchiveReader(PostgresArchiveManifestStore(_connect))
            result = run(conn, selection, archive=archive, apply=args.apply, plan_digest=args.plan_digest)
        print(json.dumps(result, sort_keys=True))
        return 1 if result["failed"] or result["changed"] or result["blocked"] else 0
    except Exception as exc:
        # DSNs, database errors and source contents must not reach stdout/stderr.
        safe_errors = {
            "invalid_reason", "invalid_limit", "invalid_source_range", "timezone_required",
            "invalid_time_range", "invalid_close_reason", "selection_limit_exceeded",
            "plan_changed", "replay_dsn_required",
        }
        reason = str(exc) if type(exc) is ValueError and str(exc) in safe_errors else "semantic_quarantine_replay_failed"
        print(json.dumps({"status": "error", "reason": reason}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

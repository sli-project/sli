"""Split out of ``server.sli.core.postgres_runtime_pipeline`` (plan 7.2b).

Module-level names of ``postgres_runtime_pipeline`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import server.sli.core.postgres_runtime_pipeline as _src


def begin_raw_batch_lifecycle_pg(
    *, batch_identity: str, manifest_hash: str, server: str, raw_path: str,
    trace_id: str, expected_channels: int,
) -> dict[str, _src.Any]:
    """Create the durable owner row before import; hash conflicts fail closed."""
    with _src.connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                insert into raw_batch_lifecycle(
                    batch_identity, manifest_hash, server, raw_path, trace_id,
                    expected_channels, import_outcome, cursor_outcome, cleanup_outcome
                ) values (%s,%s,%s,%s,%s,%s,'unknown','unknown','retained')
                on conflict(batch_identity) do update set
                    trace_id=excluded.trace_id,
                    expected_channels=excluded.expected_channels,
                    updated_at=now()
                where raw_batch_lifecycle.manifest_hash=excluded.manifest_hash
                  and raw_batch_lifecycle.raw_path=excluded.raw_path
                  and raw_batch_lifecycle.server=excluded.server
                returning *
                """,
                (batch_identity, manifest_hash, server, raw_path, trace_id, expected_channels),
            )
            row = cur.fetchone()
            if not row:
                raise RuntimeError("raw_batch_identity_manifest_mismatch")
            return dict(row)


def raw_batch_cursor_outcome(
    *, summary: _src.Mapping[str, _src.Any], audit_rows: list[_src.Mapping[str, _src.Any]],
) -> tuple[str, int]:
    """Classify same-run per-channel cursor evidence without optimistic gaps."""
    channels = summary.get("channels") or []
    expected = {
        str(item.get("channel") or "")
        for item in channels
        if str(item.get("channel") or "")
    }
    if not expected or any(
        str(item.get("status") or "unknown") != "completed"
        for item in channels
        if str(item.get("channel") or "")
    ):
        return "not_committed", 0
    committed = {
        str(row.get("channel") or "")
        for row in audit_rows
        if str(row.get("decision") or "") in {"committed", "no_change"}
    }
    matched = len(expected & committed)
    return ("committed" if committed == expected else "not_committed", matched)


def record_raw_batch_cursor_outcome_pg(
    *, batch_identity: str, manifest_hash: str, server: str, trace_id: str,
    summary: _src.Mapping[str, _src.Any],
) -> dict[str, _src.Any]:
    """Persist cursor outcome only from exact trace/server audit readback."""
    with _src.connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select channel, decision
                from collector_cursor_audit
                where trace_id=%s and server=%s
                """,
                (trace_id, server),
            )
            audit_rows = [dict(row) for row in cur.fetchall()]
            outcome, committed_channels = _src.raw_batch_cursor_outcome(
                summary=summary, audit_rows=audit_rows,
            )
            cur.execute(
                """
                update raw_batch_lifecycle
                set cursor_outcome=%s, committed_channels=%s,
                    cursor_recorded_at=now(), updated_at=now()
                where batch_identity=%s and manifest_hash=%s
                  and server=%s and trace_id=%s and import_outcome='succeeded'
                returning *
                """,
                (outcome, committed_channels, batch_identity, manifest_hash, server, trace_id),
            )
            row = cur.fetchone()
            if not row or row.get("cursor_outcome") != outcome:
                raise RuntimeError("raw_batch_cursor_outcome_readback_failed")
            return dict(row)


def record_raw_batch_import_outcome_pg(
    *, batch_identity: str, manifest_hash: str, outcome: str,
    error: str | None = None,
) -> dict[str, _src.Any]:
    if outcome not in {"succeeded", "failed"}:
        raise ValueError("invalid raw batch import outcome")
    with _src.connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                update raw_batch_lifecycle
                set import_outcome=%s, import_error=%s,
                    import_recorded_at=now(), updated_at=now()
                where batch_identity=%s and manifest_hash=%s
                returning *
                """,
                (outcome, error, batch_identity, manifest_hash),
            )
            row = cur.fetchone()
            if not row or row.get("import_outcome") != outcome:
                raise RuntimeError("raw_batch_import_outcome_readback_failed")
            return dict(row)


def authorize_raw_batch_cleanup_pg(*, batch_identity: str, manifest_hash: str) -> bool:
    """Durably authorize deletion only after exact-manifest import+cursor proof."""
    with _src.connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                update raw_batch_lifecycle
                set cleanup_outcome='delete_authorized', cleanup_error=null,
                    cleanup_recorded_at=now(), updated_at=now()
                where batch_identity=%s and manifest_hash=%s
                  and import_outcome='succeeded' and cursor_outcome='committed'
                  and expected_channels > 0
                  and committed_channels=expected_channels
                returning batch_identity, manifest_hash, import_outcome,
                          cursor_outcome, cleanup_outcome
                """,
                (batch_identity, manifest_hash),
            )
            row = cur.fetchone()
            return bool(
                row
                and row.get("batch_identity") == batch_identity
                and row.get("manifest_hash") == manifest_hash
                and row.get("import_outcome") == "succeeded"
                and row.get("cursor_outcome") == "committed"
                and row.get("cleanup_outcome") == "delete_authorized"
            )


def record_raw_batch_cleanup_outcome_pg(
    *, batch_identity: str, manifest_hash: str, outcome: str,
    error: str | None = None,
) -> dict[str, _src.Any]:
    if outcome not in {"deleted", "delete_failed"}:
        raise ValueError("invalid raw batch cleanup outcome")
    with _src.connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                update raw_batch_lifecycle
                set cleanup_outcome=%s, cleanup_error=%s,
                    cleanup_recorded_at=now(), updated_at=now()
                where batch_identity=%s and manifest_hash=%s
                  and cleanup_outcome='delete_authorized'
                returning *
                """,
                (outcome, error, batch_identity, manifest_hash),
            )
            row = cur.fetchone()
            if not row or row.get("cleanup_outcome") != outcome:
                raise RuntimeError("raw_batch_cleanup_outcome_readback_failed")
            return dict(row)

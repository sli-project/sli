"""Split out of ``server.sli.semantic.semantic_investigation_backfill`` (plan 7.2b).

Module-level names of ``semantic_investigation_backfill`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import server.sli.semantic.semantic_investigation_backfill as _src


def investigation_quarantine_recovery_candidates(
    cur: _src.Any,
    *,
    frozen_normalized_at: str | _src.datetime,
    high_watermark_source_event_id: int,
    job_ids: _src.Sequence[str] | None = None,
    for_update: bool = False,
) -> tuple[dict[str, _src.Any], ...]:
    """Select only the accepted ACL-failure jobs inside one frozen backfill range."""
    boundary = _src._recovery_boundary(frozen_normalized_at)
    high = int(high_watermark_source_event_id)
    if high < 0:
        raise ValueError("investigation recovery high watermark is invalid")
    selected_job_ids = _src._exact_job_ids(job_ids)
    identities = _src.investigation_rule_identity_tuples()
    exact_rules = " or ".join(
        "(rule.rule_id=%s and rule.rule_version=%s and rule.definition_sha256=%s)"
        for _identity in identities
    )
    parameters: list[_src.Any] = [
        _src.QUARANTINE_RECOVERY_ERROR_CODE,
        _src.QUARANTINE_RECOVERY_DETAIL_PATTERN,
        boundary,
        high,
    ]
    for rule_id, rule_version, definition_sha256 in identities:
        parameters.extend((rule_id, rule_version, definition_sha256))
    job_filter = ""
    if selected_job_ids is not None:
        job_filter = "and job.job_id=any(%s::uuid[])"
        parameters.append(selected_job_ids)
    parameters.append(_src.QUARANTINE_RECOVERY_MAX + 1)
    lock_clause = "for update of job" if for_update else ""
    cur.execute(
        f"""
        select job.job_id::text as job_id,
               job.normalized_event_id::text as normalized_event_id,
               normalized.source_event_id,normalized.normalized_at,
               rule.rule_id,rule.rule_version,
               encode(rule.definition_sha256,'hex') as definition_sha256,
               job.dispatch_status,job.attempt_count,job.max_attempts,
               job.last_error_code,job.last_error_detail
        from semantic_correlation_dispatch_jobs job
        join normalized_events normalized
          on normalized.normalized_event_id=job.normalized_event_id
        join semantic_correlation_rules rule
          on rule.rule_id=job.rule_id and rule.rule_version=job.rule_version
        where job.dispatch_status='quarantined'
          and job.attempt_count>=job.max_attempts
          and job.completed_at is null
          and job.last_error_code=%s
          and job.last_error_detail ilike %s
          and normalized.normalized_at<=%s
          and normalized.source_event_id<=%s
          and rule.lifecycle_status='shadow'
          and ({exact_rules})
          {job_filter}
        order by job.job_id
        limit %s
        {lock_clause}
        """,
        tuple(parameters),
    )
    rows = tuple(dict(row) for row in (cur.fetchall() or ()))
    if len(rows) > _src.QUARANTINE_RECOVERY_MAX:
        raise RuntimeError("investigation recovery candidate set exceeds bound")
    expected = {
        (rule_id, int(rule_version), definition_sha256.hex())
        for rule_id, rule_version, definition_sha256 in identities
    }
    seen: set[str] = set()
    for row in rows:
        try:
            job_id = str(_src.UUID(str(row["job_id"])))
            normalized_at = _src._recovery_boundary(row["normalized_at"])
            source_event_id = int(row["source_event_id"])
            attempt_count = int(row["attempt_count"])
            max_attempts = int(row["max_attempts"])
            identity = (
                str(row["rule_id"]),
                int(row["rule_version"]),
                _src._definition_hex(row["definition_sha256"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeError("investigation recovery candidate is invalid") from exc
        if (
            job_id in seen
            or identity not in expected
            or normalized_at > boundary
            or source_event_id > high
            or str(row.get("dispatch_status") or "") != "quarantined"
            or attempt_count < max_attempts
            or str(row.get("last_error_code") or "")
            != _src.QUARANTINE_RECOVERY_ERROR_CODE
            or "semantic_correlation_rules"
            not in str(row.get("last_error_detail") or "").casefold()
        ):
            raise RuntimeError("investigation recovery candidate is invalid")
        seen.add(job_id)
    return rows


def investigation_quarantine_recovery_digest(
    candidates: _src.Sequence[_src.Mapping[str, _src.Any]],
    *,
    database_identity: _src.Mapping[str, str],
    frozen_normalized_at: str | _src.datetime,
    high_watermark_source_event_id: int,
) -> str:
    """Bind an operator-visible plan to one database, range and exact job state."""
    boundary = _src._recovery_boundary(frozen_normalized_at).isoformat()
    identity = {
        name: str(database_identity.get(name) or "")
        for name in ("host", "database", "role")
    }
    if not all(identity.values()):
        raise ValueError("investigation recovery database identity is invalid")
    jobs = []
    for row in candidates:
        detail = str(row.get("last_error_detail") or "")
        jobs.append({
            "job_id": str(_src.UUID(str(row["job_id"]))),
            "normalized_event_id": str(_src.UUID(str(row["normalized_event_id"]))),
            "source_event_id": int(row["source_event_id"]),
            "normalized_at": _src._recovery_boundary(row["normalized_at"]).isoformat(),
            "rule_id": str(row["rule_id"]),
            "rule_version": int(row["rule_version"]),
            "definition_sha256": _src._definition_hex(row["definition_sha256"]),
            "dispatch_status": str(row["dispatch_status"]),
            "attempt_count": int(row["attempt_count"]),
            "max_attempts": int(row["max_attempts"]),
            "last_error_code": str(row["last_error_code"]),
            "last_error_detail_sha256": _src.sha256(detail.encode("utf-8")).hexdigest(),
        })
    payload = {
        "contract": "semantic_investigation_acl_quarantine_recovery_v1",
        "database_identity": identity,
        "frozen_normalized_at": boundary,
        "high_watermark_source_event_id": int(high_watermark_source_event_id),
        "jobs": sorted(jobs, key=lambda item: item["job_id"]),
    }
    encoded = _src.json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _src.sha256(encoded).hexdigest()


def recover_investigation_quarantined_dispatch_jobs(
    cur: _src.Any,
    *,
    expected_digest: str,
    database_identity: _src.Mapping[str, str],
    frozen_normalized_at: str | _src.datetime,
    high_watermark_source_event_id: int,
) -> tuple[str, ...]:
    """Grant exactly one retry to a plan-bound terminal ACL-failure set."""
    digest = str(expected_digest or "").casefold()
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise ValueError("investigation recovery digest is invalid")
    candidates = _src.investigation_quarantine_recovery_candidates(
        cur,
        frozen_normalized_at=frozen_normalized_at,
        high_watermark_source_event_id=high_watermark_source_event_id,
        for_update=True,
    )
    observed = _src.investigation_quarantine_recovery_digest(
        candidates,
        database_identity=database_identity,
        frozen_normalized_at=frozen_normalized_at,
        high_watermark_source_event_id=high_watermark_source_event_id,
    )
    if observed != digest:
        raise RuntimeError("investigation recovery candidate set changed")
    job_ids = tuple(str(row["job_id"]) for row in candidates)
    if not job_ids:
        return ()
    cur.execute(
        """
        update semantic_correlation_dispatch_jobs
        set dispatch_status='failed',attempt_count=max_attempts-1,
            available_at=now(),lease_token=null,lease_until=null,
            heartbeat_at=null,completed_at=null,updated_at=now()
        where job_id=any(%s::uuid[])
          and dispatch_status='quarantined'
          and attempt_count>=max_attempts
          and last_error_code=%s
          and last_error_detail ilike %s
        returning job_id::text as job_id
        """,
        (
            list(job_ids),
            _src.QUARANTINE_RECOVERY_ERROR_CODE,
            _src.QUARANTINE_RECOVERY_DETAIL_PATTERN,
        ),
    )
    recovered = tuple(sorted(str(dict(row)["job_id"]) for row in (cur.fetchall() or ())))
    if recovered != tuple(sorted(job_ids)):
        raise RuntimeError("investigation recovery update set changed")
    return recovered

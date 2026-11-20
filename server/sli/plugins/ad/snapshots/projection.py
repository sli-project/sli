from __future__ import annotations

"""Exact-manifest compatibility projections with immutable durable outputs."""

from collections.abc import Callable, Mapping
import hashlib
import json
from typing import Any
from uuid import UUID

from server.sli.plugins.ad.snapshots.manifest import BASE_FAMILIES, snapshot_composition

PROJECTION_ALLOWLIST: dict[str, int] = {
    "ad.users.v2": 1,
    "ad.computers.v6": 1,
    "ad.gpo.v2": 1,
    "ad.state": 1,
}
_PROJECTION_FAMILY = {
    "ad.users.v2": "users_v2",
    "ad.computers.v6": "computers_v6",
    "ad.gpo.v2": "gpo_v2",
    "ad.state": "ad_context_base",
}


class ProjectionConflictError(ValueError):
    """An immutable manifest, output, or completed receipt disagrees on replay."""


class ProjectionOutputMissingError(ProjectionConflictError):
    """A completed receipt has no immutable output to exact-read."""


def canonical_output_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_output_json(value).encode("utf-8")).hexdigest()


def _canonical_output_json(value: Any) -> str:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str
    )


def _canonical_manifest_id(value: Any) -> str:
    try:
        return str(UUID(str(value)))
    except (TypeError, ValueError, AttributeError) as exc:
        raise ValueError("manifest_id must be a UUID") from exc


def _sha256_hex(value: Any, *, field: str) -> str:
    text = str(value).casefold()
    if len(text) != 64:
        raise ValueError(f"{field} must be sha256 hex")
    try:
        digest = bytes.fromhex(text)
    except ValueError as exc:
        raise ValueError(f"{field} must be sha256 hex") from exc
    if len(digest) != 32:
        raise ValueError(f"{field} must be sha256 hex")
    return text


def _projection_pair(projection_key: Any, projection_version: Any) -> tuple[str, int]:
    key = str(projection_key)
    version = int(projection_version)
    if key not in PROJECTION_ALLOWLIST or version != PROJECTION_ALLOWLIST[key]:
        raise ValueError("projection key/version is not allowlisted")
    return key, version


def _output_identity(manifest_id: Any, projection_key: Any, projection_version: Any) -> str:
    manifest_text = _canonical_manifest_id(manifest_id)
    key, version = _projection_pair(projection_key, projection_version)
    return f"{manifest_text}:{key}:v{version}"


def create_projection_receipts(
    manifest_id: str,
    *,
    manifest_state: str,
    manifest_sha256: str | None = None,
    existing: Mapping[tuple[str, int], Mapping[str, Any]] | None = None,
) -> tuple[dict[str, Any], ...]:
    """Return four bounded receipt intents only for committed manifests."""
    if manifest_state != "committed":
        return ()
    canonical_manifest_id = _canonical_manifest_id(manifest_id)
    rows: list[dict[str, Any]] = []
    for projection_key, version in PROJECTION_ALLOWLIST.items():
        prior = (existing or {}).get((projection_key, version))
        if prior is not None and (
            _canonical_manifest_id(prior.get("manifest_id")) != canonical_manifest_id
            or (
                manifest_sha256 is not None
                and prior.get("input_sha256") not in (None, manifest_sha256)
            )
        ):
            raise ProjectionConflictError("conflicting projection receipt replay")
        rows.append(
            {
                "manifest_id": canonical_manifest_id,
                "projection_key": projection_key,
                "projection_version": version,
                "status": "pending",
            }
        )
    return tuple(rows)


def insert_projection_receipts(cur: Any, *, manifest_id: str) -> None:
    for receipt in create_projection_receipts(manifest_id, manifest_state="committed"):
        cur.execute(
            """
            insert into ad_snapshot_projection_receipts(
              manifest_id,projection_key,projection_version,status
            ) values(%s,%s,%s,'pending')
            on conflict(manifest_id,projection_key,projection_version) do nothing
            """,
            (
                receipt["manifest_id"], receipt["projection_key"],
                receipt["projection_version"],
            ),
        )


def claim_projection_receipts(
    conn: Any,
    *,
    worker_id: str,
    limit: int = 4,
    lease_seconds: int = 300,
    max_attempts: int = 4,
    manifest_id: str | None = None,
    projection_keys: tuple[str, ...] | None = None,
) -> list[dict[str, Any]]:
    canonical_manifest_id = (
        _canonical_manifest_id(manifest_id) if manifest_id is not None else None
    )
    if (
        not worker_id
        or not 1 <= limit <= 16
        or not 1 <= lease_seconds <= 3600
        or not 1 <= max_attempts <= 16
    ):
        raise ValueError("invalid bounded projection claim")
    if projection_keys is not None and (
        not projection_keys or any(key not in PROJECTION_ALLOWLIST for key in projection_keys)
    ):
        raise ValueError("projection key is not allowlisted")
    with conn.cursor() as cur:
        cur.execute(
            """
            with candidates as (
              select manifest_id,projection_key,projection_version
              from ad_snapshot_projection_receipts receipt
              where attempt_count < %s
                and (%s::uuid is null or receipt.manifest_id=%s::uuid)
                and (%s::text[] is null or receipt.projection_key=any(%s::text[]))
                and (
                  status in ('pending','failed')
                  or (status='running' and lease_expires_at <= now())
                )
              order by created_at,manifest_id,projection_key
              for update skip locked
              limit %s
            )
            update ad_snapshot_projection_receipts receipt
               set status='running',attempt_count=attempt_count+1,
                   lease_owner=%s,
                   lease_expires_at=now()+make_interval(secs => %s),
                   updated_at=now(),last_error=null
              from candidates
             where receipt.manifest_id=candidates.manifest_id
               and receipt.projection_key=candidates.projection_key
               and receipt.projection_version=candidates.projection_version
            returning receipt.*
            """,
            (
                max_attempts,
                canonical_manifest_id,
                canonical_manifest_id,
                list(projection_keys) if projection_keys is not None else None,
                list(projection_keys) if projection_keys is not None else None,
                limit,
                worker_id,
                lease_seconds,
            ),
        )
        return [dict(row) for row in cur.fetchall()]


def _read_projection_output(
    conn: Any,
    *,
    manifest_id: str,
    projection_key: str,
    projection_version: int,
) -> dict[str, Any] | None:
    with conn.cursor() as cur:
        cur.execute(
            """
            select manifest_id::text as manifest_id,projection_key,projection_version,
                   encode(input_sha256,'hex') as input_sha256,
                   encode(output_sha256,'hex') as output_sha256,
                   output_identity,payload_json
              from ad_snapshot_projection_outputs
             where manifest_id=%s::uuid and projection_key=%s and projection_version=%s
            """,
            (manifest_id, projection_key, projection_version),
        )
        row = cur.fetchone()
    return dict(row) if row else None


def _verify_projection_output_readback(
    conn: Any,
    *,
    manifest_id: Any,
    projection_key: Any,
    projection_version: Any,
    input_sha256: Any,
    output_sha256: Any,
    output_identity: Any,
) -> dict[str, str]:
    canonical_manifest_id = _canonical_manifest_id(manifest_id)
    key, version = _projection_pair(projection_key, projection_version)
    expected_input = _sha256_hex(input_sha256, field="projection input hash")
    expected_output = _sha256_hex(output_sha256, field="projection output hash")
    expected_identity = _output_identity(canonical_manifest_id, key, version)
    if str(output_identity) != expected_identity:
        raise ProjectionConflictError("projection output identity is not manifest-bound")

    readback = _read_projection_output(
        conn,
        manifest_id=canonical_manifest_id,
        projection_key=key,
        projection_version=version,
    )
    if readback is None:
        raise ProjectionOutputMissingError("projection output readback missing")

    payload = readback.get("payload_json")
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise ProjectionConflictError("projection output readback payload is not JSON") from exc
    try:
        actual = {
            "manifest_id": _canonical_manifest_id(readback.get("manifest_id")),
            "projection_key": str(readback.get("projection_key")),
            "projection_version": int(readback.get("projection_version")),
            "input_sha256": _sha256_hex(
                readback.get("input_sha256"), field="readback input hash"
            ),
            "output_sha256": _sha256_hex(
                readback.get("output_sha256"), field="readback output hash"
            ),
            "output_identity": str(readback.get("output_identity")),
        }
    except (TypeError, ValueError) as exc:
        raise ProjectionConflictError("projection output readback mismatch") from exc
    expected = {
        "manifest_id": canonical_manifest_id,
        "projection_key": key,
        "projection_version": version,
        "input_sha256": expected_input,
        "output_sha256": expected_output,
        "output_identity": expected_identity,
    }
    if actual != expected or canonical_output_sha256(payload) != expected_output:
        raise ProjectionConflictError("projection output readback mismatch")
    return {
        "input_sha256": expected_input,
        "output_sha256": expected_output,
        "output_identity": expected_identity,
    }


def record_projection_result(
    conn: Any, *, claim: Mapping[str, Any], result: Mapping[str, Any]
) -> None:
    """Complete a claim only after re-reading its immutable durable output."""
    manifest_id = _canonical_manifest_id(claim["manifest_id"])
    projection_key, projection_version = _projection_pair(
        claim["projection_key"], claim["projection_version"]
    )
    lease_owner = str(claim["lease_owner"])
    if not lease_owner:
        raise ValueError("projection claim lease owner is required")
    identity = (manifest_id, projection_key, projection_version, lease_owner)
    if result.get("error"):
        with conn.cursor() as cur:
            cur.execute(
                """update ad_snapshot_projection_receipts
                      set status='failed',lease_owner=null,lease_expires_at=null,
                          last_error=%s,updated_at=now()
                    where manifest_id=%s::uuid and projection_key=%s
                      and projection_version=%s and lease_owner=%s and status='running'""",
                (str(result["error"])[:2000], *identity),
            )
        return

    durable = _verify_projection_output_readback(
        conn,
        manifest_id=manifest_id,
        projection_key=projection_key,
        projection_version=projection_version,
        input_sha256=result.get("input_sha256"),
        output_sha256=result.get("output_sha256"),
        output_identity=result.get("output_identity"),
    )
    with conn.cursor() as cur:
        cur.execute(
            """update ad_snapshot_projection_receipts
                  set status='completed',lease_owner=null,lease_expires_at=null,
                      input_sha256=decode(%s,'hex'),output_sha256=decode(%s,'hex'),
                      output_identity=%s,last_error=null,updated_at=now()
                where manifest_id=%s::uuid and projection_key=%s
                  and projection_version=%s and lease_owner=%s and status='running'""",
            (
                durable["input_sha256"],
                durable["output_sha256"],
                durable["output_identity"],
                *identity,
            ),
        )


def persist_projection_output(
    conn: Any,
    *,
    manifest_id: str,
    projection_key: str,
    projection_version: int,
    input_sha256: str,
    output: Any,
) -> dict[str, str]:
    """Insert-once an output, then exact-read every immutable identity/hash field."""
    canonical_manifest_id = _canonical_manifest_id(manifest_id)
    key, version = _projection_pair(projection_key, projection_version)
    canonical_input = _sha256_hex(input_sha256, field="projection input hash")
    payload_json = _canonical_output_json(output)
    canonical_output = canonical_output_sha256(output)
    output_identity = _output_identity(canonical_manifest_id, key, version)
    with conn.cursor() as cur:
        cur.execute(
            """
            insert into ad_snapshot_projection_outputs(
              manifest_id,projection_key,projection_version,input_sha256,
              output_sha256,output_identity,payload_json
            ) values(%s::uuid,%s,%s,%s,%s,%s,%s::jsonb)
            on conflict(manifest_id,projection_key,projection_version) do nothing
            """,
            (
                canonical_manifest_id,
                key,
                version,
                bytes.fromhex(canonical_input),
                bytes.fromhex(canonical_output),
                output_identity,
                payload_json,
            ),
        )
    return _verify_projection_output_readback(
        conn,
        manifest_id=canonical_manifest_id,
        projection_key=key,
        projection_version=version,
        input_sha256=canonical_input,
        output_sha256=canonical_output,
        output_identity=output_identity,
    )


def read_projection_receipts(conn: Any, *, manifest_id: str) -> list[dict[str, Any]]:
    canonical_manifest_id = _canonical_manifest_id(manifest_id)
    with conn.cursor() as cur:
        cur.execute(
            """
            select manifest_id::text as manifest_id,projection_key,projection_version,status,
                   attempt_count,lease_owner,lease_expires_at,
                   encode(input_sha256,'hex') as input_sha256,
                   encode(output_sha256,'hex') as output_sha256,
                   output_identity,last_error,created_at,updated_at
              from ad_snapshot_projection_receipts
             where manifest_id=%s::uuid
             order by projection_key,projection_version
            """,
            (canonical_manifest_id,),
        )
        return [dict(row) for row in cur.fetchall()]


def ensure_projection_receipts(conn: Any, *, manifest_id: str) -> list[dict[str, Any]]:
    """Idempotently ensure and exact-read the four receipts for one manifest."""
    canonical_manifest_id = _canonical_manifest_id(manifest_id)
    with conn.cursor() as cur:
        insert_projection_receipts(cur, manifest_id=canonical_manifest_id)
    rows = read_projection_receipts(conn, manifest_id=canonical_manifest_id)
    expected_pairs = set(PROJECTION_ALLOWLIST.items())
    actual_pairs: set[tuple[str, int]] = set()
    for row in rows:
        row_manifest_id = _canonical_manifest_id(row.get("manifest_id"))
        pair = _projection_pair(row.get("projection_key"), row.get("projection_version"))
        if row_manifest_id != canonical_manifest_id or pair in actual_pairs:
            raise ProjectionConflictError("projection receipt exact-read mismatch")
        actual_pairs.add(pair)
    if actual_pairs != expected_pairs:
        raise ProjectionConflictError("projection receipt set is not exact")
    return rows


def _mark_completed_receipt_retryable_failed(
    conn: Any,
    *,
    manifest_id: str,
    projection_key: str,
    projection_version: int,
    error: str,
) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """update ad_snapshot_projection_receipts
                  set status='failed',lease_owner=null,lease_expires_at=null,
                      last_error=%s,updated_at=now()
                where manifest_id=%s::uuid and projection_key=%s
                  and projection_version=%s and status='completed'""",
            (error[:2000], manifest_id, projection_key, projection_version),
        )


def revalidate_completed_projection_receipt(
    conn: Any, *, receipt: Mapping[str, Any]
) -> dict[str, Any]:
    """Verify completed receipt/output truth; only a missing output becomes retryable."""
    manifest_id = _canonical_manifest_id(receipt.get("manifest_id"))
    projection_key, projection_version = _projection_pair(
        receipt.get("projection_key"), receipt.get("projection_version")
    )
    if str(receipt.get("status")) != "completed":
        raise ValueError("only completed projection receipts can be revalidated")
    try:
        durable = _verify_projection_output_readback(
            conn,
            manifest_id=manifest_id,
            projection_key=projection_key,
            projection_version=projection_version,
            input_sha256=receipt.get("input_sha256"),
            output_sha256=receipt.get("output_sha256"),
            output_identity=receipt.get("output_identity"),
        )
    except ProjectionOutputMissingError as exc:
        _mark_completed_receipt_retryable_failed(
            conn,
            manifest_id=manifest_id,
            projection_key=projection_key,
            projection_version=projection_version,
            error=str(exc),
        )
        return {
            "status": "failed",
            "readback": "missing_output",
            "retryable": True,
            "error": f"{type(exc).__name__}:{exc}",
        }
    return {"status": "completed", "readback": "verified", **durable}


def project_exact_manifest(
    manifest: Mapping[str, Any],
    *,
    load_exact: Callable[[str, str, str], Any],
    projection_keys: tuple[str, ...] | None = None,
) -> dict[str, dict[str, Any]]:
    """Project each allowlisted key independently from declared exact sources."""
    return {
        projection_key: result
        for projection_key, (result, _output) in _project_exact_manifest_payloads(
            manifest, load_exact=load_exact, projection_keys=projection_keys
        ).items()
    }


def complete_projection_claim(
    conn: Any,
    *,
    claim: Mapping[str, Any],
    manifest: Mapping[str, Any],
    load_exact: Callable[[str, str, str], Any],
    persist_output: Callable[..., Mapping[str, str]] = persist_projection_output,
) -> dict[str, Any]:
    """Load exact source, project deterministically, persist/readback, then complete."""
    try:
        claim_manifest_id = _canonical_manifest_id(claim["manifest_id"])
        manifest_id = _canonical_manifest_id(manifest.get("manifest_id"))
        projection_key, projection_version = _projection_pair(
            claim["projection_key"], claim["projection_version"]
        )
    except (TypeError, ValueError) as exc:
        result = {"error": f"ProjectionConflictError:{exc}"}
        record_projection_result(conn, claim=claim, result=result)
        return result
    if claim_manifest_id != manifest_id:
        result = {"error": "ProjectionConflictError:claim_manifest_mismatch"}
        record_projection_result(conn, claim=claim, result=result)
        return result

    result, output = _project_exact_manifest_payloads(
        manifest, load_exact=load_exact, projection_keys=(projection_key,)
    )[projection_key]
    if result.get("error"):
        record_projection_result(conn, claim=claim, result=result)
        return result
    try:
        persisted = dict(
            persist_output(
                conn,
                manifest_id=manifest_id,
                projection_key=projection_key,
                projection_version=projection_version,
                input_sha256=str(result["input_sha256"]),
                output=output,
            )
        )
        if persisted != result:
            raise ProjectionConflictError("projection output identity mismatch")
        record_projection_result(conn, claim=claim, result=persisted)
    except ProjectionConflictError:
        raise
    except Exception as exc:
        failure = {"error": f"{type(exc).__name__}:{exc}"}
        record_projection_result(conn, claim=claim, result=failure)
        return failure
    return persisted


def run_exact_manifest_projection_cycle(
    conn: Any,
    *,
    manifest_id: str,
    worker_id: str,
    load_manifest: Callable[[Any, str], Mapping[str, Any]] | None = None,
    load_exact: Callable[[str, str, str], Any] | None = None,
    ensure_receipts: Callable[..., list[dict[str, Any]]] = ensure_projection_receipts,
    revalidate_completed: Callable[..., Mapping[str, Any]] = revalidate_completed_projection_receipt,
    claim_receipts: Callable[..., list[dict[str, Any]]] = claim_projection_receipts,
    complete_claim: Callable[..., Mapping[str, Any]] = complete_projection_claim,
    persist_output: Callable[..., Mapping[str, str]] = persist_projection_output,
    projection_keys: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """Revalidate then drain only one exact manifest; it never reacquires sources."""
    canonical_manifest_id = _canonical_manifest_id(manifest_id)
    if not worker_id:
        raise ValueError("worker_id is required")
    selected = tuple(PROJECTION_ALLOWLIST) if projection_keys is None else projection_keys
    if not selected or len(set(selected)) != len(selected) or any(
        key not in PROJECTION_ALLOWLIST for key in selected
    ):
        raise ValueError("projection key is not allowlisted")
    if load_manifest is None or load_exact is None:
        from server.sli.plugins.ad.context.repository import (
            load_exact_projection_source,
            load_projection_manifest,
        )
        if load_manifest is None:
            load_manifest = load_projection_manifest
        if load_exact is None:
            load_exact = lambda family, source_id, payload_sha256: load_exact_projection_source(
                conn,
                family=family,
                source_id=source_id,
                payload_sha256=payload_sha256,
            )

    manifest = dict(load_manifest(conn, canonical_manifest_id))
    if _canonical_manifest_id(manifest.get("manifest_id")) != canonical_manifest_id:
        raise ProjectionConflictError("exact manifest readback mismatch")
    composition = snapshot_composition(manifest)
    raw_members = manifest.get("members") or []
    families = set(raw_members) if isinstance(raw_members, Mapping) else {
        row["family"] for row in raw_members
    }
    if (projection_keys is None and BASE_FAMILIES <= families
            and "gpo" not in composition["parts"]):
        selected = tuple(key for key in selected if key != "ad.gpo.v2")

    receipts = ensure_receipts(conn, manifest_id=canonical_manifest_id)
    by_key: dict[str, dict[str, Any]] = {}
    expected_pairs = {(key, PROJECTION_ALLOWLIST[key]) for key in selected}
    for raw_receipt in receipts:
        receipt = dict(raw_receipt)
        if _canonical_manifest_id(receipt.get("manifest_id")) != canonical_manifest_id:
            raise ProjectionConflictError("projection receipt escaped exact manifest scope")
        projection_key, projection_version = _projection_pair(
            receipt.get("projection_key"), receipt.get("projection_version"))
        if projection_key not in selected:
            continue
        if (projection_key, projection_version) not in expected_pairs or projection_key in by_key:
            raise ProjectionConflictError("projection receipt set is not exact")
        by_key[projection_key] = receipt
    if set((key, PROJECTION_ALLOWLIST[key]) for key in by_key) != expected_pairs:
        raise ProjectionConflictError("projection receipt set is not exact")

    projection_results: dict[str, dict[str, Any]] = {
        key: {"status": str(receipt.get("status")), "readback": "not_required"}
        for key, receipt in by_key.items()
    }
    for projection_key in selected:
        receipt = by_key[projection_key]
        if str(receipt.get("status")) != "completed":
            continue
        try:
            projection_results[projection_key] = dict(
                revalidate_completed(conn, receipt=receipt)
            )
        except ProjectionConflictError as exc:
            projection_results[projection_key] = {
                "status": "blocked",
                "readback": "mismatch",
                "error": f"{type(exc).__name__}:{exc}",
            }

    claim_options = {"projection_keys": selected} if (
        projection_keys is not None or selected != tuple(PROJECTION_ALLOWLIST)
    ) else {}
    claims = claim_receipts(
        conn, worker_id=worker_id, manifest_id=canonical_manifest_id, **claim_options
    )
    claimed_keys: set[str] = set()
    for claim in claims:
        if _canonical_manifest_id(claim.get("manifest_id")) != canonical_manifest_id:
            raise ProjectionConflictError("claim escaped exact manifest scope")
        projection_key, projection_version = _projection_pair(
            claim.get("projection_key"), claim.get("projection_version"))
        if projection_key not in selected:
            raise ProjectionConflictError("claim escaped plugin ownership")
        if projection_key in claimed_keys:
            raise ProjectionConflictError("duplicate projection receipt claim")
        claimed_keys.add(projection_key)
        completed = dict(
            complete_claim(
                conn,
                claim=claim,
                manifest=manifest,
                load_exact=load_exact,
                persist_output=persist_output,
            )
        )
        if completed.get("error"):
            projection_results[projection_key] = {
                "status": "failed",
                "readback": "not_completed",
                **completed,
            }
        else:
            projection_results[projection_key] = {
                "status": "completed",
                "readback": "inserted_and_verified",
                **completed,
            }

    statuses = {str(row.get("status")) for row in projection_results.values()}
    cycle_status = (
        "failed"
        if any(row.get("error") for row in projection_results.values())
        else "completed"
        if statuses == {"completed"}
        else "pending"
    )
    return {
        "manifest_id": canonical_manifest_id,
        "status": cycle_status,
        "claimed_count": len(claims),
        "projection_results": projection_results,
        "composition": composition,
    }


def _project_exact_manifest_payloads(
    manifest: Mapping[str, Any],
    *,
    load_exact: Callable[[str, str, str], Any],
    projection_keys: tuple[str, ...] | None = None,
) -> dict[str, tuple[dict[str, Any], Any]]:
    canonical_manifest_id = _canonical_manifest_id(manifest.get("manifest_id"))
    canonical_manifest_hash = _sha256_hex(
        manifest.get("manifest_sha256"), field="manifest hash"
    )
    raw_members = manifest.get("members") or {}
    members = (
        {str(row["family"]): row for row in raw_members}
        if not isinstance(raw_members, Mapping)
        else dict(raw_members)
    )
    result: dict[str, tuple[dict[str, Any], Any]] = {}
    composition = snapshot_composition(dict(manifest))
    selected = projection_keys or tuple(PROJECTION_ALLOWLIST)
    if any(key not in PROJECTION_ALLOWLIST for key in selected):
        raise ValueError("projection key is not allowlisted")
    for projection_key in selected:
        version = PROJECTION_ALLOWLIST[projection_key]
        family = _PROJECTION_FAMILY[projection_key]
        member = members.get(family)
        if not isinstance(member, Mapping):
            result[projection_key] = ({"error": f"missing_exact_source:{family}"}, None)
            continue
        try:
            source_id = str(member["source_id"])
            if not source_id:
                raise ValueError("source_id is required")
            source_hash = _sha256_hex(
                member["payload_sha256"], field="source payload hash"
            )
            input_hash = canonical_output_sha256(
                {
                    "manifest_id": canonical_manifest_id,
                    "manifest_sha256": canonical_manifest_hash,
                    "projection_key": projection_key,
                    "projection_version": version,
                    "family": family,
                    "source_id": source_id,
                    "payload_sha256": source_hash,
                }
            )
            exact_input = load_exact(family, source_id, source_hash)
            output = _pure_project(projection_key, exact_input)
            # Preserve historical full-composition v1 output hashes. Base-only
            # snapshots are new and carry their composition in existing JSON.
            if (projection_key == "ad.state" and BASE_FAMILIES <= set(members)
                    and "gpo" not in composition["parts"]):
                output = {**output, "composition": composition}
            result[projection_key] = (
                {
                    "input_sha256": input_hash,
                    "output_sha256": canonical_output_sha256(output),
                    "output_identity": _output_identity(
                        canonical_manifest_id, projection_key, version
                    ),
                },
                output,
            )
        except Exception as exc:
            result[projection_key] = ({"error": f"{type(exc).__name__}:{exc}"}, None)
    return result


def _pure_project(projection_key: str, exact_input: Any) -> Any:
    if projection_key == "ad.users.v2":
        from server.sli.reports.users_v2_reporting import project_users_v2_exact

        return project_users_v2_exact(exact_input)
    if projection_key == "ad.computers.v6":
        from server.sli.reports.computers_v6_reporting import project_computers_v6_exact

        return project_computers_v6_exact(exact_input)
    if projection_key == "ad.gpo.v2":
        from server.sli.plugins.gpo.snapshot_projection import project_gpo_v2_exact

        return project_gpo_v2_exact(exact_input)
    return json.loads(json.dumps(exact_input, ensure_ascii=False, default=str))

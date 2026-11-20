"""Append-only analyst labels for already persisted semantic scenarios."""
from __future__ import annotations

from hashlib import sha256
import json
from typing import Any, Mapping
from uuid import UUID, uuid4

from server.sli.core.postgres_runtime_pipeline import connect


REVIEW_VERDICTS = frozenset({
    "confirmed_security", "false_positive", "benign_expected", "insufficient_evidence",
})
REVIEW_CONFIDENCE = frozenset({"high", "medium", "low"})
REVIEWER_ROLES = frozenset({"viewer", "operator", "admin"})
MINIMUM_DECISIVE_SAMPLE = 10


def _uuid(value: str | UUID, field: str) -> str:
    try:
        return str(UUID(str(value)))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid_{field}") from exc


def _snapshot_sha256(row: Mapping[str, Any]) -> bytes:
    keys = (
        "scenario_id", "scenario_kind", "result_class", "scenario_status",
        "partition_key", "strict_keys_json", "first_seen_utc", "last_seen_utc",
        "risk_class", "display_score", "hard_critical", "confidence",
        "confidence_score", "coverage_status", "step_count", "evidence_count",
        "contribution_count", "updated_at",
    )
    payload = {key: row.get(key) for key in keys}
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return sha256(encoded.encode("utf-8")).digest()


def create_scenario_review(
    *,
    scenario_id: str | UUID,
    verdict: str,
    review_confidence: str,
    rationale: str,
    reviewed_by: str,
    reviewer_role: str,
    review_request_id: str | UUID | None = None,
) -> dict[str, Any]:
    """Append one review or return the exact idempotent request replay."""
    clean_scenario_id = _uuid(scenario_id, "scenario_id")
    clean_request_id = _uuid(review_request_id or uuid4(), "review_request_id")
    clean_verdict = str(verdict or "").strip().lower()
    clean_confidence = str(review_confidence or "").strip().lower()
    clean_rationale = str(rationale or "").strip()
    clean_actor = str(reviewed_by or "").strip()
    clean_role = str(reviewer_role or "").strip().lower()
    if clean_verdict not in REVIEW_VERDICTS:
        raise ValueError("invalid_review_verdict")
    if clean_confidence not in REVIEW_CONFIDENCE:
        raise ValueError("invalid_review_confidence")
    if not 5 <= len(clean_rationale) <= 2000:
        raise ValueError("review_rationale_length")
    if not 1 <= len(clean_actor) <= 160:
        raise ValueError("reviewed_by_required")
    if clean_role not in REVIEWER_ROLES:
        raise ValueError("invalid_reviewer_role")

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("select pg_advisory_xact_lock(hashtextextended(%s,0))", (clean_scenario_id,))
            cur.execute(
                """
                select review_id,review_request_id,scenario_id,supersedes_review_id,
                       verdict,review_confidence,rationale,encode(scenario_snapshot_sha256,'hex') as scenario_snapshot_sha256,
                       reviewed_by,reviewer_role,reviewed_at
                from semantic_scenario_reviews where review_request_id=%s
                """,
                (clean_request_id,),
            )
            replay = cur.fetchone()
            if replay:
                item = _review_item(replay)
                expected = (clean_scenario_id, clean_verdict, clean_confidence, clean_rationale, clean_actor, clean_role)
                actual = (item["scenario_id"], item["verdict"], item["review_confidence"], item["rationale"], item["reviewed_by"], item["reviewer_role"])
                if actual != expected:
                    raise ValueError("review_request_id_conflict")
                return {**item, "replayed": True}

            cur.execute(
                """
                select scenario_id,scenario_kind,result_class,scenario_status,
                       partition_key,strict_keys_json,first_seen_utc,last_seen_utc,
                       risk_class,display_score,hard_critical,confidence,
                       confidence_score,coverage_status,step_count,evidence_count,
                       contribution_count,updated_at
                from semantic_security_scenarios where scenario_id=%s
                for key share
                """,
                (clean_scenario_id,),
            )
            scenario = cur.fetchone()
            if not scenario:
                raise LookupError("semantic_scenario_not_found")
            cur.execute(
                """
                select review_id from semantic_scenario_reviews
                where scenario_id=%s order by reviewed_at desc,review_id desc limit 1
                """,
                (clean_scenario_id,),
            )
            previous = cur.fetchone()
            review_id = str(uuid4())
            cur.execute(
                """
                insert into semantic_scenario_reviews(
                    review_id,review_request_id,scenario_id,supersedes_review_id,
                    verdict,review_confidence,rationale,scenario_snapshot_sha256,
                    reviewed_by,reviewer_role
                ) values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                returning review_id,review_request_id,scenario_id,supersedes_review_id,
                          verdict,review_confidence,rationale,
                          encode(scenario_snapshot_sha256,'hex') as scenario_snapshot_sha256,
                          reviewed_by,reviewer_role,reviewed_at
                """,
                (
                    review_id, clean_request_id, clean_scenario_id,
                    previous["review_id"] if previous else None,
                    clean_verdict, clean_confidence, clean_rationale,
                    _snapshot_sha256(scenario), clean_actor, clean_role,
                ),
            )
            return {**_review_item(cur.fetchone()), "replayed": False}


def _review_item(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "review_id": str(row["review_id"]),
        "review_request_id": str(row["review_request_id"]),
        "scenario_id": str(row["scenario_id"]),
        "supersedes_review_id": str(row["supersedes_review_id"]) if row.get("supersedes_review_id") else None,
        "verdict": str(row["verdict"]),
        "review_confidence": str(row["review_confidence"]),
        "rationale": str(row["rationale"]),
        "scenario_snapshot_sha256": str(row["scenario_snapshot_sha256"]),
        "reviewed_by": str(row["reviewed_by"]),
        "reviewer_role": str(row["reviewer_role"]),
        "reviewed_at": row["reviewed_at"],
    }


def summarize_review_labels(
    rows: list[Mapping[str, Any]], *, schema_ready: bool, minimum_sample: int = MINIMUM_DECISIVE_SAMPLE,
) -> dict[str, Any]:
    """Return an honest FP measurement from latest append-only labels only."""
    by_verdict = {str(row["verdict"]): int(row.get("item_count") or 0) for row in rows}
    reviewed = sum(by_verdict.values())
    confirmed = by_verdict.get("confirmed_security", 0)
    false_positive = by_verdict.get("false_positive", 0)
    decisive = confirmed + false_positive
    rate = round((false_positive / decisive) * 100, 2) if decisive else None
    if not schema_ready:
        state, reason = "not_measurable", "analyst_review_schema_unavailable"
    elif decisive == 0:
        state, reason = "not_measurable", "decisive_analyst_labels_not_available"
    elif decisive < minimum_sample:
        state, reason = "insufficient_sample", f"minimum_{minimum_sample}_decisive_labels_required"
    else:
        state, reason = "measured", "decisive_analyst_sample_available"
    return {
        "state": state,
        "reason": reason,
        "reviewed_scenarios": reviewed,
        "decisive_labels": decisive,
        "false_positive_labels": false_positive,
        "rate_percent": rate,
        "minimum_decisive_sample": minimum_sample,
        "by_verdict": by_verdict,
    }

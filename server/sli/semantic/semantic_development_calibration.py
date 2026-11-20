"""Development-only calibration evidence kept separate from analyst reviews.

The fixture contour proves calculation and presentation contracts while the
product is still being built.  It must never be interpreted as measured
production accuracy or written to ``semantic_scenario_reviews``.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from hashlib import sha256
import json
from typing import Any

from server.sli.semantic.semantic_reviews import MINIMUM_DECISIVE_SAMPLE, summarize_review_labels


EVIDENCE_CLASS = "development_fixture"


def evaluate_development_fixture(
    verdicts: Sequence[str], *, minimum_sample: int = MINIMUM_DECISIVE_SAMPLE
) -> dict[str, Any]:
    """Evaluate a bounded synthetic label set without touching runtime state."""
    allowed = {"confirmed_security", "false_positive", "benign_expected", "insufficient_evidence"}
    normalized = [str(value or "").strip().lower() for value in verdicts]
    if not 1 <= len(normalized) <= 100:
        raise ValueError("development calibration requires 1..100 fixture labels")
    unsupported = sorted(set(normalized) - allowed)
    if unsupported:
        raise ValueError(f"unsupported development fixture verdicts: {', '.join(unsupported)}")
    counts = {value: normalized.count(value) for value in sorted(set(normalized))}
    summary = summarize_review_labels(
        [{"verdict": verdict, "item_count": count} for verdict, count in counts.items()],
        schema_ready=True,
        minimum_sample=minimum_sample,
    )
    fingerprint = sha256(
        json.dumps(normalized, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        **summary,
        "reason": (
            "development_decisive_fixture_available"
            if summary["state"] == "measured"
            else f"development_fixture_{summary['reason']}"
        ),
        "evidence_class": EVIDENCE_CLASS,
        "fixture_fingerprint_sha256": fingerprint,
        "writes_runtime_data": False,
        "counts_as_analyst_sample": False,
        "production_accuracy_claim": False,
        "development_contract_ready": summary["state"] == "measured",
    }


def assert_development_only(payload: Mapping[str, Any]) -> None:
    """Fail closed if a caller tries to relabel fixture evidence as production."""
    if payload.get("evidence_class") != EVIDENCE_CLASS:
        raise ValueError("development calibration evidence class mismatch")
    if payload.get("counts_as_analyst_sample") is not False:
        raise ValueError("development fixture cannot count as an analyst sample")
    if payload.get("production_accuracy_claim") is not False:
        raise ValueError("development fixture cannot claim production accuracy")

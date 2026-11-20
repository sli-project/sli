"""Bounded pre-projection aggregate payload, never a recipient-ready digest.

The trusted producer may see candidates before applying the saved actors' ACL.
This validator establishes shape/bounds only. It does not establish provenance,
schedule binding, report parity or authorization. A fixed leased DB accessor
must establish provenance; existing Python ACL must select the final projection.
The fixed RPC consumer must establish that provenance before using this data.
"""

from copy import deepcopy
import json

MAX_ROOTS = 1000
MAX_BYTES = 262144
MAX_COUNT = 2**63 - 1
QUALITIES = frozenset({"ok", "empty", "partial", "stale", "not_collected", "denied", "error", "processing"})
COUNT_QUALITIES = frozenset({"ok", "empty", "partial", "stale"})


def _count(value):
    return type(value) is int and 0 <= value <= MAX_COUNT


def _summary(value):
    return (isinstance(value, dict) and set(value) == {"total", "has_more"}
            and _count(value["total"]) and type(value["has_more"]) is bool
            and value["has_more"] == (value["total"] > 50))


def validate(payload):
    """Reject extra data and return a detached bounded aggregate candidate.

    This provisional contract deliberately has no ``new`` count: its exact
    report-period meaning still needs characterization before being added.
    """
    try:
        if not isinstance(payload, dict):
            raise ValueError
        expected = {"report_key", "quality", "counts", "roots"}
        if payload.get("report_key") == "file-audit.mass-operations":
            expected.add("root_limit")
        if set(payload) != expected:
            raise ValueError
        if len(json.dumps(payload, allow_nan=False).encode("utf-8")) > MAX_BYTES:
            raise ValueError
        key, quality = payload["report_key"], payload["quality"]
        if key not in ("security.problems", "file-audit.mass-operations") or quality not in QUALITIES:
            raise ValueError
        if not isinstance(payload["counts"], dict):
            raise ValueError
        roots = payload["roots"]
        if not isinstance(roots, list) or len(roots) > MAX_ROOTS:
            raise ValueError
        if key == "security.problems":
            if roots:
                raise ValueError
            counts = payload["counts"]
            if quality in COUNT_QUALITIES:
                if set(counts) != {"individual", "cohorts"} or not all(_summary(v) for v in counts.values()):
                    raise ValueError
            elif counts:
                raise ValueError
        else:
            if type(payload["root_limit"]) is not bool or payload["root_limit"] and (roots or quality != "partial"):
                raise ValueError
            if payload["counts"] or roots and quality not in COUNT_QUALITIES:
                raise ValueError
            seen = set()
            dimensions = ("agent_id", "source_instance_id", "collection_scope_id")
            for root in roots:
                if (not isinstance(root, dict) or set(root) != {*dimensions, "source_kind"}
                        or root["source_kind"] not in {"server", "workstation"}):
                    raise ValueError
                values = tuple(root[k] for k in dimensions)
                if any(not isinstance(v, str) or v.strip() != v or not 1 <= len(v) <= 256 for v in values):
                    raise ValueError
                if values in seen:
                    raise ValueError
                seen.add(values)
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
        raise ValueError("invalid_report_candidate") from None
    return deepcopy(payload)

"""Shared NPS QW document contract, without detector, reader or worker imports.

Both the source adapter and core admission validate the same rule pin and
bounded context. Importing this contract never loads the NPS evaluator.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256

from server.sli.storage.evidence_ref import EvidenceScope

RULE_ID = "qw.nps-denials"
MAX_EVENTS = 10000
DIMENSIONS = frozenset({"account", "nas_identifier", "network_policy", "reason_code", "client_ip"})
QUALITIES = frozenset({"good", "partial", "stale", "not_collected", "truncated"})


def digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def utc(value):
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("nps_threshold_time_invalid") from None
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("nps_threshold_time_invalid")
    return value.astimezone(timezone.utc)


@dataclass(frozen=True, repr=False, kw_only=True)
class ThresholdRule:
    scope: EvidenceScope
    policy_revision: int = 1
    dimension: str = "account"
    threshold: int = 20
    window_seconds: int = 300
    surge_factor: int = 3
    evaluation_mode: str = "shadow"

    def __post_init__(self):
        if (not isinstance(self.scope, EvidenceScope)
                or self.scope.plugin_id not in {"sli.windows.ad-dc", "sli.vpn-nps"}
                or self.scope.collection_scope_id
                or self.dimension not in DIMENSIONS
                or self.evaluation_mode not in {"test", "shadow", "enabled"}
                or any(type(value) is not int or not low <= value <= high for value, low, high in (
                    (self.policy_revision, 1, 2**31 - 1), (self.threshold, 1, MAX_EVENTS),
                    (self.window_seconds, 60, 3600), (self.surge_factor, 2, 100)))):
            raise ValueError("nps_threshold_rule_invalid")

    @property
    def rule_sha256(self):
        return digest({"contract": "sli.nps-threshold.v1", "dimension": self.dimension,
                       "threshold": self.threshold, "window_seconds": self.window_seconds,
                       "surge_factor": self.surge_factor})

    @property
    def checkpoint_key(self):
        return digest({"scope": asdict(self.scope), "rule": self.rule_sha256,
                       "revision": self.policy_revision, "mode": self.evaluation_mode})


def validate_context(context):
    """Only bounded numeric diagnostics and fixed codes enter the QW document."""
    keys = {"count", "previous_count", "threshold", "window_seconds", "surge_factor", "dimension",
            "comparison", "current_quality", "previous_quality", "from_utc", "to_utc", "identity_state"}
    if (not isinstance(context, dict) or set(context) != keys
            or any(type(context[key]) is not int or not 0 <= context[key] <= MAX_EVENTS
                   for key in ("count", "previous_count", "threshold", "window_seconds", "surge_factor"))
            or not 1 <= context["threshold"] <= context["count"]
            or not 60 <= context["window_seconds"] <= 3600 or not 2 <= context["surge_factor"] <= 100
            or context["dimension"] not in DIMENSIONS
            or context["comparison"] not in {"threshold", "surge", "new_activity"}
            or context["current_quality"] not in QUALITIES or context["previous_quality"] not in QUALITIES
            or context["identity_state"] not in {"unknown", "observed"}
            or utc(context["to_utc"]) - utc(context["from_utc"]) != timedelta(seconds=context["window_seconds"])):
        raise ValueError("nps_threshold_context_invalid")
    if context["comparison"] == "surge" and not (
            context["current_quality"] == context["previous_quality"] == "good"
            and context["previous_count"] > 0
            and context["count"] >= context["surge_factor"] * context["previous_count"]):
        raise ValueError("nps_threshold_context_invalid")

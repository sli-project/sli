"""WS overview DTOs, independent of storage, evaluation and request access.

Counts are already scoped by the caller. Missing evidence cannot become zero;
partial counts describe lower bounds, and denied responses contain no findings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from collections.abc import Mapping
from typing import Literal

from .check_catalog import BY_ID, CATALOG, REASON_KEYS

Scalar = str | int | bool | None
OverviewState = Literal["data", "partial", "empty", "denied"]
QualityStatus = Literal["complete", "partial", "stale", "unavailable", "not_collected", "denied"]
CountRelation = Literal["exact", "at_least", "unknown"]


@dataclass(frozen=True)
class Reason:
    code: str
    params: Mapping[str, Scalar] = field(default_factory=dict)

    def __post_init__(self):
        if (self.code not in REASON_KEYS or not isinstance(self.params, Mapping)
                or any(not isinstance(key, str) or type(value) not in (str, int, bool, type(None))
                       for key, value in self.params.items())):
            raise ValueError("reason_invalid")
        object.__setattr__(self, "params", MappingProxyType(dict(self.params)))

    def to_dict(self) -> dict:
        return {"code": self.code, "message_key": REASON_KEYS[self.code], "params": dict(self.params)}


@dataclass(frozen=True)
class Quality:
    status: QualityStatus
    reasons: tuple[Reason, ...] = ()

    def __post_init__(self):
        if (self.status not in ("complete", "partial", "stale", "unavailable", "not_collected", "denied")
                or any(not isinstance(reason, Reason) for reason in self.reasons)):
            raise ValueError("quality_invalid")
        object.__setattr__(self, "reasons", tuple(self.reasons))
        if self.status == "denied" and any(reason.code != "scope_denied" or reason.params
                                           for reason in self.reasons):
            raise ValueError("quality_invalid")

    def to_dict(self) -> dict:
        return {"status": self.status, "reasons": [reason.to_dict() for reason in self.reasons]}


@dataclass(frozen=True)
class Count:
    value: int | None
    relation: CountRelation

    def __post_init__(self):
        if (self.relation not in ("exact", "at_least", "unknown")
                or (self.relation == "unknown" and self.value is not None)
                or (self.relation != "unknown" and (type(self.value) is not int or self.value < 0))):
            raise ValueError("count_invalid")

    def to_dict(self) -> dict:
        return {"value": self.value, "relation": self.relation}


@dataclass(frozen=True)
class CheckCounts:
    stations: Count
    new_since_previous_login: Count

    def __post_init__(self):
        if (self.stations.relation == "exact" and self.new_since_previous_login.value is not None
                and self.new_since_previous_login.value > self.stations.value):
            raise ValueError("check_counts_invalid")

    def to_dict(self) -> dict:
        return {"stations": self.stations.to_dict(),
                "new_since_previous_login": self.new_since_previous_login.to_dict()}


@dataclass(frozen=True)
class CheckResult:
    check_id: str
    quality: Quality
    counts: CheckCounts
    reasons: tuple[Reason, ...] = ()

    def __post_init__(self):
        if self.check_id not in BY_ID:
            raise ValueError("check_id_invalid")
        object.__setattr__(self, "reasons", tuple(self.reasons))
        relations = {self.counts.stations.relation, self.counts.new_since_previous_login.relation}
        allowed = {"complete": {"exact", "unknown"}, "partial": {"at_least", "unknown"}}
        if (not relations <= allowed.get(self.quality.status, {"unknown"})
                or (self.quality.status == "complete" and self.counts.stations.relation != "exact")):
            raise ValueError("check_counts_quality_invalid")
        if (any(not isinstance(reason, Reason) or reason.code != BY_ID[self.check_id].reason_code
                for reason in self.reasons)
                or (self.quality.status == "denied" and self.reasons)):
            raise ValueError("check_reasons_invalid")

    def to_dict(self) -> dict:
        return {**BY_ID[self.check_id].to_dict(), "quality": self.quality.to_dict(),
                "counts": self.counts.to_dict(), "reasons": [reason.to_dict() for reason in self.reasons]}


@dataclass(frozen=True)
class ChecksOverview:
    state: OverviewState
    quality: Quality
    checks: tuple[CheckResult, ...]

    def __post_init__(self):
        object.__setattr__(self, "checks", tuple(self.checks))
        if [row.check_id for row in self.checks] != [rule.check_id for rule in CATALOG]:
            raise ValueError("overview_checks_invalid")
        statuses = {row.quality.status for row in self.checks}
        counts = [row.counts.stations.value for row in self.checks]
        if self.state in ("data", "empty"):
            valid = self.quality.status == "complete" and statuses == {"complete"}
            valid = valid and ((all(value == 0 for value in counts)) if self.state == "empty"
                               else any(value is not None and value > 0 for value in counts))
        elif self.state == "denied":
            valid = self.quality.status == "denied" and statuses == {"denied"}
        elif self.state == "partial":
            valid = self.quality.status == "partial" and statuses != {"complete"} and statuses != {"denied"}
        else:
            valid = False
        if not valid:
            raise ValueError("overview_state_invalid")

    def to_dict(self) -> dict:
        return {"contract_id": "sli.workstation-checks.v1", "state": self.state,
                "quality": self.quality.to_dict(), "checks": [row.to_dict() for row in self.checks]}

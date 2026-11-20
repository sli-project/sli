"""Versioned WS review catalogue. Registration does not evaluate any rule."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Severity = Literal["high", "medium", "low"]
StationType = Literal["workstation", "server", "unknown"]
PREFIX = "workstations."


@dataclass(frozen=True)
class CheckDefinition:
    check_id: str
    order: int
    severity: Severity
    reason_code: str
    rule_version: int = 1

    def severity_for(self, station_type: StationType) -> Severity:
        # C09 remains one check, including its server-specific escalation.
        return "medium" if self.check_id == "C09" and station_type == "server" else self.severity

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "rule_version": self.rule_version,
            "order": self.order,
            "severity": self.severity,
            "reason_code": self.reason_code,
            **{f"{field}_key": f"{PREFIX}checks.{self.check_id}.{field}"
               for field in ("title", "why", "action", "remediation")},
        }


CATALOG = (
    CheckDefinition("C01", 1, "high", "protection_disabled"),
    CheckDefinition("C02", 2, "high", "local_admin_added"),
    CheckDefinition("C03", 3, "high", "password_failures"),
    CheckDefinition("C04", 4, "medium", "suspicious_process_path"),
    CheckDefinition("C05", 5, "medium", "service_or_task_changed"),
    CheckDefinition("C06", 6, "medium", "removable_media_first_seen"),
    CheckDefinition("C07", 7, "medium", "logon_outside_policy"),
    CheckDefinition("C08", 8, "medium", "server_silent"),
    CheckDefinition("C09", 9, "low", "protection_stale"),
    CheckDefinition("C10", 10, "low", "workstation_silent"),
)
BY_ID = {rule.check_id: rule for rule in CATALOG}
REASON_KEYS = {
    code: f"{PREFIX}reasons.{code}"
    for code in (
        *(rule.reason_code for rule in CATALOG),
        "source_missing", "coverage_incomplete", "baseline_unknown", "scope_denied",
        "data_stale", "not_collected", "local_admin_baseline_unknown", "local_admin_removed",
        "protection_enabled", "device_history_incomplete",
        "logon_policy_not_configured", "logon_type_unknown",
        "service_installed", "task_created", "task_deleted", "task_enabled", "task_disabled", "task_updated",
        "service_task_baseline_unknown",
    )
}

from __future__ import annotations

"""Authorization contract for one visible VPN report with two data branches.

The existing ``vpn.audit`` assignment authorizes only the AD membership
branch.  RADIUS lifecycle data additionally requires the independent
``vpn.sessions.view`` capability; absence or denial is returned explicitly and
must never be rendered as an empty data set.
"""

from dataclasses import dataclass
from typing import Any, Mapping

from server.sli.access.access_control_v4 import (
    capability_decision,
    capability_decision_for_resource_groups,
    report_action_decision,
)


COMPOSITION_CONTRACT_ID = "sli.vpn-report-composition.v1"
REPORT_KEY = "vpn.audit"
DIRECTORY_DATASET = "ad.accounts.vpn"
SESSION_RESOURCE_GROUP = "vpn.sessions"
SESSION_VIEW_CAPABILITY = "vpn.sessions.view"
SESSION_EVIDENCE_CAPABILITY = "vpn.session.evidence.read"


@dataclass(frozen=True)
class VpnReportBranchDecision:
    branch: str
    state: str
    reason: str
    dataset_or_resource_group: str
    required_capability: str | None

    @property
    def allowed(self) -> bool:
        return self.state == "available"


@dataclass(frozen=True)
class VpnReportCompositionDecision:
    contract_id: str
    report_key: str
    report_allowed: bool
    directory: VpnReportBranchDecision
    sessions: VpnReportBranchDecision
    session_evidence: VpnReportBranchDecision


def vpn_report_composition_decision(
    access: Mapping[str, Any],
    *,
    source_domain_id: int | None = None,
    action: str = "view",
) -> VpnReportCompositionDecision:
    """Evaluate every branch independently from server-built access."""

    clean_action = str(action or "").strip().lower()
    if clean_action not in {"view", "export"}:
        raise ValueError("vpn_report_action_invalid")
    domain_id = int(source_domain_id or 0)
    resource_groups = (
        [[{"kind": "domain", "id": domain_id}]]
        if domain_id > 0
        else []
    )
    report_decision = report_action_decision(
        access,
        REPORT_KEY,
        clean_action,
        resource_groups=resource_groups,
    )
    report_allowed = bool(report_decision["allowed"])
    directory_export_allowed = (
        clean_action != "export"
        or capability_decision(access, "reports.export")["allowed"]
    )
    if report_allowed and directory_export_allowed:
        directory = VpnReportBranchDecision(
            branch="directory_membership",
            state="available",
            reason=str(report_decision["reason"]),
            dataset_or_resource_group=DIRECTORY_DATASET,
            required_capability=None,
        )
    else:
        directory = VpnReportBranchDecision(
            branch="directory_membership",
            state="not_authorized",
            reason=(
                "reports_export_required"
                if report_allowed and not directory_export_allowed
                else str(report_decision["reason"])
            ),
            dataset_or_resource_group=DIRECTORY_DATASET,
            required_capability=None,
        )

    sessions = _capability_branch(
        access,
        report_allowed=report_allowed,
        branch="sessions",
        capability=SESSION_VIEW_CAPABILITY,
        action=clean_action,
        resource_groups=resource_groups,
    )
    evidence = _capability_branch(
        access,
        report_allowed=report_allowed,
        branch="session_evidence",
        capability=SESSION_EVIDENCE_CAPABILITY,
        action=clean_action,
        resource_groups=resource_groups,
    )
    return VpnReportCompositionDecision(
        contract_id=COMPOSITION_CONTRACT_ID,
        report_key=REPORT_KEY,
        report_allowed=report_allowed,
        directory=directory,
        sessions=sessions,
        session_evidence=evidence,
    )


def _capability_branch(
    access: Mapping[str, Any],
    *,
    report_allowed: bool,
    branch: str,
    capability: str,
    action: str,
    resource_groups: list[list[dict[str, Any]]],
) -> VpnReportBranchDecision:
    if not report_allowed:
        return VpnReportBranchDecision(
            branch=branch,
            state="not_authorized",
            reason="vpn_report_scope_required",
            dataset_or_resource_group=SESSION_RESOURCE_GROUP,
            required_capability=capability,
        )
    if action == "export":
        decision = capability_decision(access, "reports.export")
        if not decision["allowed"]:
            return VpnReportBranchDecision(
                branch=branch,
                state="not_authorized",
                reason="reports_export_required",
                dataset_or_resource_group=SESSION_RESOURCE_GROUP,
                required_capability="reports.export",
            )
    decision = capability_decision_for_resource_groups(
        access,
        capability,
        resource_groups=resource_groups,
    )
    return VpnReportBranchDecision(
        branch=branch,
        state=(
            "available" if decision["allowed"] else "not_authorized"
        ),
        reason=str(decision["reason"]),
        dataset_or_resource_group=SESSION_RESOURCE_GROUP,
        required_capability=capability,
    )

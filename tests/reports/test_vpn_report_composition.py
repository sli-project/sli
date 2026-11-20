from __future__ import annotations

from server.sli.reports.vpn_report_composition import (
    COMPOSITION_CONTRACT_ID,
    vpn_report_composition_decision,
)


def _access(
    *,
    capabilities: list[str] | None = None,
    report_actions: list[str] | None = None,
    policies: list[dict] | None = None,
    owner: bool = False,
) -> dict:
    return {
        "platform_owner": owner,
        "capabilities": list(capabilities or []),
        "capability_policies": list(policies or []),
        "reports": [
            {
                "report_key": "vpn.audit",
                "allowed": report_actions is not None,
                "allowed_actions": list(report_actions or []),
                "grants": ([{
                    "allowed_actions": list(report_actions or []),
                    "scope": {"kind": "domain", "ids": [7]},
                }] if report_actions is not None else []),
            }
        ],
    }


def test_existing_vpn_assignment_does_not_grant_sessions() -> None:
    decision = vpn_report_composition_decision(
        _access(report_actions=["view"]),
        source_domain_id=7,
    )

    assert decision.contract_id == COMPOSITION_CONTRACT_ID
    assert decision.directory.allowed is True
    assert decision.sessions.allowed is False
    assert decision.sessions.state == "not_authorized"
    assert decision.sessions.reason == "insufficient_capability"


def test_session_branch_requires_both_report_and_capability() -> None:
    with_capability = _access(
        capabilities=["vpn.sessions.view"],
        report_actions=["view"],
    )
    assert vpn_report_composition_decision(
        with_capability,
        source_domain_id=7,
    ).sessions.allowed is True

    no_report = _access(
        capabilities=["vpn.sessions.view"],
        report_actions=None,
    )
    decision = vpn_report_composition_decision(
        no_report,
        source_domain_id=7,
    )
    assert decision.sessions.allowed is False
    assert decision.sessions.reason == "vpn_report_scope_required"


def test_evidence_requires_stronger_separate_capability() -> None:
    decision = vpn_report_composition_decision(
        _access(
            capabilities=["vpn.sessions.view"],
            report_actions=["view"],
        ),
        source_domain_id=7,
    )
    assert decision.sessions.allowed is True
    assert decision.session_evidence.allowed is False

    allowed = vpn_report_composition_decision(
        _access(
            capabilities=[
                "vpn.sessions.view",
                "vpn.session.evidence.read",
            ],
            report_actions=["view"],
        ),
        source_domain_id=7,
    )
    assert allowed.session_evidence.allowed is True


def test_explicit_deny_wins_for_session_branch() -> None:
    access = _access(
        capabilities=["vpn.sessions.view"],
        report_actions=["view"],
        policies=[{
            "capability_key": "vpn.sessions.view",
            "effect": "deny",
            "scope": {"kind": "all"},
            "valid": True,
        }],
    )
    decision = vpn_report_composition_decision(
        access,
        source_domain_id=7,
    )
    assert decision.directory.allowed is True
    assert decision.sessions.allowed is False
    assert decision.sessions.reason == "explicit_deny"


def test_export_does_not_inherit_from_view_capability() -> None:
    access = _access(
        capabilities=["vpn.sessions.view"],
        report_actions=["view", "export"],
    )
    decision = vpn_report_composition_decision(
        access,
        source_domain_id=7,
        action="export",
    )
    assert decision.directory.allowed is False
    assert decision.directory.reason == "reports_export_required"
    assert decision.sessions.allowed is False
    assert decision.sessions.reason == "reports_export_required"


def test_platform_owner_still_needs_the_report_entry() -> None:
    decision = vpn_report_composition_decision(
        _access(
            owner=True,
            report_actions=["view"],
        ),
        source_domain_id=7,
    )
    assert decision.sessions.allowed is True
    assert decision.session_evidence.allowed is True


def test_report_and_capability_must_cover_exact_domain() -> None:
    access = _access(
        capabilities=[],
        report_actions=["view"],
        policies=[{
            "capability_key": "vpn.sessions.view",
            "effect": "allow",
            "scope": {"kind": "domain", "ids": [7]},
            "valid": True,
        }],
    )
    allowed = vpn_report_composition_decision(
        access,
        source_domain_id=7,
    )
    denied = vpn_report_composition_decision(
        access,
        source_domain_id=8,
    )
    assert allowed.sessions.allowed is True
    assert denied.directory.allowed is False
    assert denied.sessions.allowed is False

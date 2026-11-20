"""Deterministic SLI v4 parity actors, unavailable outside an explicit test flag."""
from __future__ import annotations

from datetime import date
from typing import Any, Mapping

_PACKAGES = {
    "sec-operators": {"label": "ИБ · операторы", "capabilities": {"entity.view", "entity.basic", "problem.view", "problem.act", "case.create", "finding.summary"}, "fields": {"identity.basic"}, "scopes": {"host5.example.invalid"}, "reports": {"security-queue"}},
    "sec-analysts": {"label": "ИБ · аналитики", "capabilities": {"entity.view", "entity.basic", "entity.groups", "entity.privileges", "entity.activity", "entity.states", "entity.technical", "event.view", "evidence.view", "evidence.raw", "finding.view", "case.view", "case.manage", "case.create"}, "fields": {"identity.basic", "technical.raw"}, "scopes": {"host5.example.invalid"}, "reports": {"security-events", "investigations"}},
    "ad-auditors": {"label": "AD · аудит и сопровождение", "capabilities": {"entity.view", "entity.basic", "entity.groups", "entity.privileges", "entity.states", "task.create", "report.export"}, "fields": {"identity.basic", "pii.contact", "pii.hr", "ad.attributes"}, "scopes": {"host5.example.invalid", "OU=Users_KHV"}, "reports": {"ad-summary", "gpo-review"}},
    "project-ops": {"label": "Проект · эксплуатация", "capabilities": {"project.ops.view", "project.events.view", "report.export"}, "fields": {"platform.technical"}, "scopes": {"platform"}, "reports": {"project-readiness", "technical-events"}},
    "access-admins": {"label": "Администраторы доступа", "capabilities": {"access.manage", "access.audit", "report.publish", "report.design"}, "fields": {"access.metadata"}, "scopes": {"all-subjects"}, "reports": set()},
}

_ACTORS = {
    "alex": {"packages": ["sec-operators", "ad-auditors"], "direct_reports": [{"report": "privileged-accounts", "valid_until": "2026-12-31", "source": "Распоряжение ИБ-128"}]},
    "marina": {"packages": ["sec-operators"], "direct_reports": []},
    "dmitry": {"packages": ["sec-analysts", "ad-auditors"], "direct_reports": [{"report": "privileged-accounts", "valid_until": "2026-09-30", "source": "Проект аттестации PAM-26"}]},
    "admin": {"packages": ["project-ops", "access-admins"], "direct_reports": []},
}


def evaluate_fixture_actor(payload: Mapping[str, Any]) -> dict[str, Any]:
    actor = str(payload.get("actor") or "")
    fixture = str(payload.get("fixture") or "")
    if fixture != "sli-universal-prototype-v4" or actor not in _ACTORS:
        raise ValueError("invalid_sli_v4_fixture_actor")
    definition = _ACTORS[actor]
    capabilities: set[str] = set()
    fields: set[str] = set()
    scopes: set[str] = set()
    grants: list[dict[str, Any]] = []
    for package_key in definition["packages"]:
        package = _PACKAGES[package_key]
        capabilities.update(package["capabilities"])
        fields.update(package["fields"])
        scopes.update(package["scopes"])
        grants.extend({"report": report, "source_type": "group", "source": package["label"], "valid_until": None} for report in package["reports"])
    for direct in definition["direct_reports"]:
        valid_until = str(direct["valid_until"])
        if date.fromisoformat(valid_until) >= date.today():
            grants.append({**direct, "source_type": "direct"})
    reports = {str(item["report"]) for item in grants}
    report_decisions = [{
        "report": report,
        "allowed": True,
        "scope": sorted(scopes),
        "fields": sorted(fields),
        "actions": ["view", *( ["export"] if "report.export" in capabilities else [] )],
        "trace": [item for item in grants if item["report"] == report],
    } for report in sorted(reports)]
    return {
        "actor": actor,
        "fixture": fixture,
        "packages": [{"key": key, "name": _PACKAGES[key]["label"]} for key in definition["packages"]],
        "capabilities": sorted(capabilities),
        "fields": sorted(fields),
        "scopes": sorted(scopes),
        "reports": sorted(reports),
        "report_decisions": report_decisions,
        "direct_reports": [str(item["report"]) for item in definition["direct_reports"]],
        "explicit_denies": [],
        "server_evaluated": True,
    }

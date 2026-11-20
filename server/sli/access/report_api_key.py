"""Expiring report-only API keys backed by isolated direct access assignments."""
from __future__ import annotations

import argparse
import json
import re
import secrets
import sys
from datetime import datetime, timedelta, timezone

from server.sli.access import auth

REPORTS = ("events.explorer", "ad.state", "ad.gpo.v2", "security.queue", "security.events.chains", "ad.users.v2", "ad.computers.v6", "vpn.audit")
WORKSTATION_REPORTS = tuple('workstations.' + family for family in ('logons', 'processes', 'usb', 'protection'))
FILE_REPORTS = tuple('file-audit.' + tab for tab in ('overview', 'actions', 'mass-operations',
    'permission-changes', 'access-denials', 'out-of-hours', 'permissions', 'audit-state'))
ROUTES = re.compile(r"^/api/v2/reports/(?:events\.journal|ad\.infrastructure|ad\.gpo\.v2|ad\.users\.v2|ad\.computers\.v6|security\.events\.chains|security\.problems|workstations\.(?:logons|processes|usb|protection)|file-audit\.(?:overview|actions|mass-operations|permission-changes|access-denials|out-of-hours|permissions|audit-state))(?:/data|/rows/[A-Za-z0-9_.:-]{1,128}/detail)?$|^/api/v2/reports/vpn\.(?:accounts|connections)/data$|^/api/v1/events/[0-9]+$")


def request_allowed(principal, method, path):
    if not principal or principal.get("report_subject_id") is None:
        return True
    return method == "GET" and ROUTES.fullmatch(path) is not None


def exact_event_allowed(principal, path):
    """Check event attribution before the legacy exact reader touches evidence."""
    if not principal or principal.get("report_subject_id") is None or not path.startswith('/api/v1/events/'):
        return True
    match = re.fullmatch(r'/api/v1/events/([1-9][0-9]{0,18})', path)
    if not match or int(match[1]) > 2**63 - 1:
        return False
    with auth._connect() as conn, conn.cursor() as cur:
        cur.execute('select domain_id from events_v2_core where id=%s', (int(match[1]),))
        row = cur.fetchone()
    if not row or row['domain_id'] is None:
        return False
    from server.sli.access.access_control_v4 import (
        effective_access,
        report_action_decision,
    )

    return report_action_decision(effective_access(principal), 'events.explorer', 'view',
        resource_groups=[[{'kind': 'domain', 'id': int(row['domain_id'])}]],
        required_field_categories=['raw_evidence', 'technical', 'security'])['allowed']


def validate_expiry(expires_at, *, now=None):
    now = now or datetime.now(timezone.utc)
    if (not isinstance(expires_at, datetime) or expires_at.tzinfo is None
            or not now < expires_at <= now + timedelta(days=7)):
        raise ValueError("report_key_expiry_must_be_within_seven_days")
    return expires_at


def file_scope(cur, domain_id, agent_ids):
    """Resolve selected file servers against their owner-provisioned DC binding."""
    from server.sli.agents.ca import uuid_text
    ids = sorted({uuid_text(value) for value in agent_ids})
    if not ids or len(ids) > 100:
        raise ValueError('report_key_file_agents_invalid')
    cur.execute("""select distinct a.id::text as agent_id,a.host_id::text as source_instance_id
        from sli_agents a join sli_agent_module_bindings b on b.agent_id=a.id
        join servers s on lower(s.hostname)=lower(b.source_name)
        where a.id=any(%s::uuid[]) and a.status='active' and s.domain_id=%s
            and b.module_id='sli.windows.ad-dc' and s.is_active
            and exists(select 1 from jsonb_array_elements(a.assigned_modules) m
                where m->>'module_id'='sli.file-audit' and m->>'enabled'='true')""", (ids, domain_id))
    rows = cur.fetchall()
    if {r['agent_id'] for r in rows} != set(ids):
        raise ValueError('report_key_file_agent_domain_mismatch')
    return {'mode': 'restricted', 'clauses': [{'plugin_ids': ['sli.file-audit'],
        'source_instance_ids': sorted({r['source_instance_id'] for r in rows})}]}


def workstation_scope(cur, agent_ids):
    """Explicit server-registered stations; no inference from a DC domain."""
    from server.sli.agents.ca import uuid_text

    ids = sorted({uuid_text(value) for value in agent_ids})
    if not ids or len(ids) > 100:
        raise ValueError('report_key_workstation_agents_invalid')
    cur.execute("""select a.id::text as agent_id,a.host_id::text as source_instance_id
        from sli_agents a where a.id=any(%s::uuid[]) and a.status='active'
        and exists(select 1 from jsonb_array_elements(a.assigned_modules) m
            where m->>'module_id'='sli.workstations' and m->>'enabled'='true')""", (ids,))
    rows = cur.fetchall()
    if {r['agent_id'] for r in rows} != set(ids):
        raise ValueError('report_key_workstation_agent_not_assigned')
    return {'mode': 'restricted', 'clauses': [{'plugin_ids': ['sli.workstations'],
        'source_instance_ids': sorted({r['source_instance_id'] for r in rows})}]}


def issue_report_key(*, label, domain_id, hours=24, file_agent_ids=(), workstation_agent_ids=(),
                     workstations_only=False):
    """Assign view-only grants first; publish the secret only after audited commit."""
    if type(domain_id) is not int or domain_id < 1 or type(hours) is not int or not 1 <= hours <= 168:
        raise ValueError("report_key_parameters_invalid")
    if type(workstations_only) is not bool or workstations_only and (not workstation_agent_ids or file_agent_ids):
        raise ValueError("report_key_parameters_invalid")
    expiry = validate_expiry(datetime.now(timezone.utc) + timedelta(hours=hours))
    label = str(label).strip()
    if not label or len(label) > 120:
        raise ValueError("api_key_label_required")
    with auth._connect() as conn, conn.cursor() as cur:
        cur.execute("select id from domains where id=%s", (domain_id,))
        if not cur.fetchone():
            raise ValueError("report_key_domain_not_found")
        core_reports = () if workstations_only else REPORTS
        reports = (*core_reports, *(FILE_REPORTS if file_agent_ids else ()),
                   *(WORKSTATION_REPORTS if workstation_agent_ids else ()))
        scopes = {key: {'kind': 'domain', 'ids': [domain_id]} for key in core_reports}
        if file_agent_ids:
            scope = file_scope(cur, domain_id, file_agent_ids)
            scopes.update(dict.fromkeys(FILE_REPORTS, scope))
        if workstation_agent_ids:
            scope = workstation_scope(cur, workstation_agent_ids)
            scopes.update(dict.fromkeys(WORKSTATION_REPORTS, scope))
        cur.execute("select report_key,definition_json from report_registry_v4 where report_key=any(%s) and status='published'", (list(reports),))
        definitions = {r["report_key"]: r["definition_json"] for r in cur.fetchall()}
        if set(definitions) != set(reports):
            raise ValueError("report_key_reports_not_published")
    subject = auth.create_user(username="report-key-" + secrets.token_hex(12),
                               password=secrets.token_urlsafe(48), role="viewer", actor_type="local_operator",
                               is_service=True)
    try:
        return _issue_for_subject(subject, definitions, label, domain_id, expiry, scopes=scopes)
    except Exception:  # revoke the isolated subject on partial setup
        auth.update_user(user_id=subject["id"], is_active=False, actor_type="local_operator")
        raise


def _issue_for_subject(subject, definitions, label, domain_id, expiry, *, scopes=None):
    from server.sli.access.access_control_v4 import (
        create_report_assignment,
        record_access_audit_with_cursor,
    )

    actor = {"type": "local_operator", "id": None}
    reason = "Expiring read-only report verification"
    scope = {"kind": "domain", "ids": [domain_id]}
    # Required report capabilities are global so the report framework can open
    # the declaration. Data is restricted by atomic domain report grants.
    required = set().union(*(set(d.get("required_capabilities", [])) for d in definitions.values())) | {"evidence.exact"}
    if any(key in FILE_REPORTS for key in definitions):
        required.add('file-audit.view')
    fields = set().union(*(set(d.get("field_categories", [])) for d in definitions.values()))
    caps = required | {"field." + f for f in fields} | {"evidence.exact"}
    # vpn.audit covers membership only; connection tabs independently require
    # session viewing in the selected domain, never session evidence or export.
    if "vpn.audit" in definitions:
        caps.add("vpn.sessions.view")
    with auth._connect() as conn, conn.cursor() as cur:
        cur.execute("select id,capability_key from access_capabilities where capability_key=any(%s)", (sorted(caps),))
        found = {r["capability_key"]: r["id"] for r in cur.fetchall()}
        if set(found) != caps:
            raise ValueError("report_key_capabilities_missing")
        for key, cap_id in found.items():
            cap_scope = {"kind": "all"} if key in required and key != "vpn.sessions.view" else scope
            cur.execute("""insert into access_capability_assignments(subject_type,subject_id,capability_id,effect,
                scope_json,valid_until,source_type,business_reason,created_by)
                values('user',%s,%s,'allow',%s::jsonb,%s,'temporary',%s,null)""",
                (subject["id"], cap_id, json.dumps(cap_scope), expiry, reason))
        record_access_audit_with_cursor(cursor=cur, actor=actor, action="report_key_capabilities_created",
            subject_type="user", subject_id=subject["id"], target_type="ad_domain", target_key=str(domain_id),
            reason=reason, details={"capabilities": sorted(caps), "valid_until": expiry.isoformat()})
    for key, definition in definitions.items():
        create_report_assignment({"subject_type": "user", "subject_id": subject["id"], "report_key": key,
            "scope": (scopes or {}).get(key, scope), "field_categories": definition.get("field_categories", []), "allowed_actions": ["view"],
            "source_type": "temporary", "valid_until": expiry.isoformat(), "business_reason": reason}, actor=actor)
    token = "adl_" + secrets.token_urlsafe(32)
    with auth._connect() as conn, conn.cursor() as cur:
        cur.execute("""insert into auth_api_keys(key_prefix,key_hash,label,role,expires_at,report_subject_id)
            values(%s,%s,%s,'viewer',%s,%s) returning id""",
            (token[:12], auth._digest(token), label, expiry, subject["id"]))
        key_id = cur.fetchone()["id"]
        auth._audit(cur, actor_type="local_operator", actor_id=None, action=f"api_key_issued:{key_id}:{token[:12]}")
        record_access_audit_with_cursor(cursor=cur, actor=actor, action="report_api_key_issued",
            subject_type="user", subject_id=subject["id"], target_type="api_key", target_key=str(key_id),
            reason=reason, details={"domain_id": domain_id, "reports": sorted(definitions), "valid_until": expiry.isoformat()})
    return {"id": key_id, "expires_at": expiry.isoformat(), "domain_id": domain_id}, token


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--label", required=True)
    parser.add_argument("--domain-id", required=True, type=int)
    parser.add_argument("--hours", type=int, default=24)
    parser.add_argument("--file-agent-id", action='append', default=[])
    parser.add_argument("--workstation-agent-id", action='append', default=[])
    parser.add_argument("--workstations-only", action='store_true')
    args = parser.parse_args()
    # stdout is a secret channel: pipe directly to a protected destination.
    if sys.stdout.isatty():
        parser.exit(1, "report_key_requires_protected_output_pipe\n")
    try:
        item, secret = issue_report_key(label=args.label, domain_id=args.domain_id, hours=args.hours,
                                       file_agent_ids=args.file_agent_id, workstation_agent_ids=args.workstation_agent_id,
                                       workstations_only=args.workstations_only)
    except Exception:  # noqa: BLE001 - secret-safe CLI boundary
        parser.exit(1, "report_key_issue_failed\n")
    print(json.dumps(item), file=sys.stderr)
    sys.stdout.write(secret)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

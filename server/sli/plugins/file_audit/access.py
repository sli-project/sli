"""File evidence uses the core scope decision, with independent audit authority."""
from collections.abc import Mapping

from server.sli.access.access_control_v4 import capability_decision
from server.sli.plugins.file_audit.contracts import CAPABILITIES, PLUGIN_ID


def validate_scope_targets(cur, clause):
    """File sources are agent bindings; they need no fabricated AD entity."""
    if (clause.plugin_ids != (PLUGIN_ID,) or not clause.source_instance_ids
            or clause.entity_ids or clause.collection_scope_ids):
        return False
    cur.execute("""select id::text as device_id,host_id::text as source_instance_id from sli_agents
        where status='active' and host_id::text=any(%s)
            and exists(select 1 from jsonb_array_elements(assigned_modules) m
                where m->>'module_id'='sli.file-audit' and m->>'enabled'='true')""", (list(clause.source_instance_ids),))
    rows = cur.fetchall()
    if ({r['source_instance_id'] for r in rows} != set(clause.source_instance_ids)
            or clause.device_ids and {r['device_id'] for r in rows} != set(clause.device_ids)):
        raise ValueError('report_scope_target_not_found')
    return True


def require_access(access, *, action, agent_id, source_instance_id, collection_scope_id, principal=None):
    if not isinstance(action, str) or action not in CAPABILITIES or not isinstance(access, Mapping):
        raise PermissionError("file_audit_action_invalid")
    if any(not isinstance(value, str) or not value.strip() or len(value) > 256
           for value in (agent_id, source_instance_id, collection_scope_id)):
        raise PermissionError("file_audit_resource_required")
    if action == "manage_audit" and not (
            isinstance(principal, Mapping) and type(principal.get("id")) is int and principal["id"] > 0
            and principal.get("type") in ("session", "api_key")
            and (principal.get("role") == "admin"
                 or principal.get("type") == "session" and access.get("platform_owner") is True)):
        raise PermissionError("file_audit_admin_required")
    resource = {"plugin_id": PLUGIN_ID, "device_id": agent_id,
                "source_instance_id": source_instance_id, "collection_scope_id": collection_scope_id}
    decision = capability_decision(access, CAPABILITIES[action], resource=resource)
    if not decision["allowed"]:
        raise PermissionError("file_audit_access_denied")
    return decision

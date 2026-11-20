"""Validated caller for the exact bundled plugin runtime transition."""
from __future__ import annotations

import re
from typing import Any, Callable, Mapping
from uuid import UUID


PLAN_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
ACTIONS = frozenset({"enable", "drain", "disable"})
ACTOR_KINDS = frozenset({"session", "api_key", "windows", "system", "local_operator"})


class PluginRuntimeActivationError(ValueError):
    pass


def execute_plugin_runtime_transition(
    *,
    plan: Mapping[str, Any],
    confirmation: str,
    operation_uid: str,
    actor_kind: str,
    actor_key: str,
    actor_capabilities: set[str] | frozenset[str],
    connection_factory: Callable[[], Any],
) -> dict[str, Any]:
    if "plugins.manage" not in actor_capabilities:
        raise PermissionError("plugins_manage_required")
    action = str(plan.get("requested_action") or "")
    digest = str(plan.get("plan_sha256") or "")
    revision = plan.get("expected_revision")
    expected_confirmation = (
        f"PLUGIN-{action.upper()}-SLI-REMOTE-ACCESS-R{revision}-"
        f"{digest[:12].upper()}"
    )
    if (
        action not in ACTIONS
        or plan.get("plugin_id") != "sli.remote-access"
        or not isinstance(revision, int)
        or isinstance(revision, bool)
        or not PLAN_SHA_RE.fullmatch(digest)
        or confirmation != expected_confirmation
        or plan.get("preserve_immutable_evidence") is not True
        or plan.get("production_read_path_cutover") is not False
        or plan.get("destructive_purge") is not False
    ):
        raise PluginRuntimeActivationError("plugin_runtime_transition_plan_invalid")
    try:
        clean_uid = str(UUID(str(operation_uid)))
    except (TypeError, ValueError, AttributeError) as exc:
        raise PluginRuntimeActivationError("plugin_runtime_operation_uid_invalid") from exc
    clean_kind = str(actor_kind or "").strip()
    clean_key = str(actor_key or "").strip()
    if clean_kind not in ACTOR_KINDS or not clean_key or len(clean_key) > 200:
        raise PluginRuntimeActivationError("plugin_runtime_actor_invalid")
    with connection_factory() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select operation_id,committed_revision,desired_activation,
                   component_runtime,queue_state
            from execute_plugin_runtime_transition_v1(
              %s::uuid,%s,%s::bigint,%s,%s,%s,%s
            )
            """,
            (clean_uid, action, revision, digest, confirmation, clean_kind, clean_key),
        )
        row = dict(cur.fetchone() or {})
    if int(row.get("operation_id") or 0) < 1 or int(row.get("committed_revision") or 0) != revision + 1:
        raise PluginRuntimeActivationError("plugin_runtime_transition_result_invalid")
    return {
        "status": "succeeded",
        "plugin_id": "sli.remote-access",
        "requested_action": action,
        "operation_uid": clean_uid,
        "operation_id": int(row["operation_id"]),
        "committed_revision": int(row["committed_revision"]),
        "desired_activation": row.get("desired_activation"),
        "component_runtime": row.get("component_runtime"),
        "queue_state": row.get("queue_state"),
        "source_contacted": False,
        "process_started_or_stopped": False,
        "production_read_path_cutover": False,
    }

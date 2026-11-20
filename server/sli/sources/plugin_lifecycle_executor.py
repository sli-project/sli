"""Bounded bundled-install DB executor; no API, process, source, or runtime control."""
from __future__ import annotations

import re
from typing import Any, Callable, Mapping
from uuid import UUID

from server.sli.sources.plugin_lifecycle import PluginLifecycleError


PLAN_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
ACTOR_KINDS = frozenset({"session", "api_key", "windows", "system", "local_operator"})
EXPECTED_EFFECTS = {"package_lifecycle": "registered"}


def execute_bundled_plugin_install(
    *,
    plan: Mapping[str, Any],
    confirmation: str,
    operation_uid: str,
    actor_kind: str,
    actor_key: str,
    actor_capabilities: set[str] | frozenset[str],
    connection_factory: Callable[[], Any],
) -> dict[str, Any]:
    """Commit one exact install transition through migration 074."""
    if "plugins.manage" not in actor_capabilities:
        raise PermissionError("plugins_manage_required")
    if confirmation != plan.get("confirmation"):
        raise PluginLifecycleError("plugin_lifecycle_confirmation_invalid")
    if (
        plan.get("requested_action") != "install"
        or plan.get("plugin_id") != "sli.remote-access"
        or plan.get("effects") != EXPECTED_EFFECTS
        or plan.get("preconditions_met") is not True
        or plan.get("preserve_immutable_evidence") is not True
        or plan.get("production_read_path_cutover") is not False
        or plan.get("destructive_purge") is not False
    ):
        raise PluginLifecycleError("plugin_bundled_install_plan_invalid")
    plan_sha256 = str(plan.get("plan_sha256") or "")
    if not PLAN_SHA_RE.fullmatch(plan_sha256):
        raise PluginLifecycleError("plugin_bundled_install_plan_hash_invalid")
    expected_revision = plan.get("expected_revision")
    if not isinstance(expected_revision, int) or isinstance(expected_revision, bool):
        raise PluginLifecycleError("plugin_bundled_install_revision_invalid")
    try:
        clean_operation_uid = str(UUID(str(operation_uid)))
    except (TypeError, ValueError, AttributeError) as exc:
        raise PluginLifecycleError("plugin_bundled_install_operation_uid_invalid") from exc
    clean_actor_kind = str(actor_kind or "").strip()
    clean_actor_key = str(actor_key or "").strip()
    if (
        clean_actor_kind not in ACTOR_KINDS
        or not clean_actor_key
        or len(clean_actor_key) > 200
    ):
        raise PluginLifecycleError("plugin_bundled_install_actor_invalid")

    with connection_factory() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select operation_id,committed_revision,package_lifecycle,
                   desired_activation
            from execute_bundled_plugin_install_v1(
                %s::uuid,%s,%s::bigint,%s,%s,%s,%s
            )
            """,
            (
                clean_operation_uid,
                "sli.remote-access",
                expected_revision,
                plan_sha256,
                confirmation,
                clean_actor_kind,
                clean_actor_key,
            ),
        )
        row = dict(cur.fetchone() or {})
    if (
        int(row.get("operation_id") or 0) < 1
        or int(row.get("committed_revision") or 0) != expected_revision + 1
        or row.get("package_lifecycle") != "registered"
        or row.get("desired_activation") != "disabled"
    ):
        raise PluginLifecycleError("plugin_bundled_install_result_invalid")
    return {
        "status": "registered",
        "plugin_id": "sli.remote-access",
        "operation_uid": clean_operation_uid,
        "operation_id": int(row["operation_id"]),
        "committed_revision": int(row["committed_revision"]),
        "package_lifecycle": "registered",
        "desired_activation": "disabled",
        "process_started_or_stopped": False,
        "source_contacted": False,
        "runtime_enabled": False,
        "autostart_enabled": False,
        "production_read_path_cutover": False,
    }

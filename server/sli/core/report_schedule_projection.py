"""Project bounded candidates using the existing Python report/file policy."""

from server.sli.plugins.file_audit.access import require_access


def project(definition, snapshot, candidate, *, authority_factory=None, check=None,
            dependency_definition=None, scope_resolver=None):
    """Select owner population, then withhold counts unless every actor qualifies.

    Inputs must come from the fixed lease-bound accessors. ``authority_factory``
    lets dependency-free tests load the real class from source; the production
    path uses ReportAccess. It never accepts caller authority flags. SQL later
    reconstructs staged counts from this finite selection descriptor.
    """
    if authority_factory is None:
        from server.sli.reporting.v2.access import ReportAccess
        authority_factory = ReportAccess
    check = check or (lambda: None)
    check()
    key = candidate["report_key"]
    if definition.key != key or key not in {"security.problems", "file-audit.mass-operations"}:
        raise ValueError("invalid_report_candidate")
    owner = snapshot["actors"][snapshot["owner_user_id"]]
    descriptor = {"variant": None, "root_indexes": [], "qw_root_indexes": [],
                  "include_count": False, "owner_state": "denied"}

    def authority(access, action):
        if action == "export" and key.startswith("file-audit.") and (
                "file-audit.export" not in set(access.get("capabilities") or [])):
            raise PermissionError("notification_recipient_denied")
        policy = authority_factory(definition, access, action)
        if policy.scope is None or policy.scope.mode != "all":
            raise PermissionError("notification_recipient_denied")
        return policy

    try:
        owner_policy = authority(owner, "view")
    except (ValueError, PermissionError):
        return {"quality": "denied", "item_count": None, "truncated": False, "selection": descriptor}
    descriptor["owner_state"] = "readable"
    quality = candidate["quality"]
    if quality not in {"ok", "empty", "partial", "stale"}:
        return {"quality": quality, "item_count": None, "truncated": False, "selection": descriptor}
    roots = candidate["roots"]
    if key == "security.problems":
        variant = "cohorts" if owner_policy.fields_allowed(frozenset({"identity_basic"})) else "individual"
        descriptor["variant"] = variant
        count = candidate["counts"][variant]["total"]
        truncated = candidate["counts"][variant]["has_more"]
    else:
        if candidate.get("root_limit"):
            return {"quality": "partial", "item_count": None, "truncated": False, "selection": descriptor}
        for index, root in enumerate(roots):
            check()
            try:
                require_access(owner, action="view", **{k: root[k] for k in (
                    "agent_id", "source_instance_id", "collection_scope_id")})
            except PermissionError:
                continue
            descriptor["root_indexes"].append(index)
        if not descriptor["root_indexes"]:
            return {"quality": "not_collected", "item_count": None, "truncated": False, "selection": descriptor}
        # No event/detail reader runs before root admission. The fixed SQL
        # publication computes the exact combined page/count only after this
        # trusted projection, and discards all rows internally.
        count = None
        truncated = False
        quality = "partial"
        dependency = snapshot.get("dependencies", {}).get("security.queue")
        if dependency is not None:
            if dependency_definition is None:
                from server.sli.reporting.v2.registry import get_report
                dependency_definition = get_report("security.problems")
            if scope_resolver is None:
                from server.sli.reporting.v2.access import resolve_access_scope
                scope_resolver = resolve_access_scope
            try:
                queue_scope = scope_resolver(dependency, dependency_definition.access)
            except PermissionError:
                queue_scope = None
            if queue_scope is not None:
                for index in descriptor["root_indexes"]:
                    check()
                    root = roots[index]
                    if queue_scope.allows(plugin_id="sli.file-audit", device_id=root["agent_id"],
                            source_instance_id=root["source_instance_id"], collection_scope_id=root["collection_scope_id"]):
                        descriptor["qw_root_indexes"].append(index)
    can_count = True
    users = {snapshot["owner_user_id"], *(row["recipient_user_id"] for row in snapshot["bindings"])}
    for user in users:
        check()
        access = snapshot["actors"][user]
        try:
            authority(access, "view")
            authority(access, "export")
            if key.startswith("file-audit."):
                for index in descriptor["root_indexes"]:
                    check()
                    resource = {k: roots[index][k] for k in ("agent_id", "source_instance_id", "collection_scope_id")}
                    require_access(access, action="view", **resource)
                    require_access(access, action="export", **resource)
        except (ValueError, PermissionError):
            can_count = False
    if truncated and quality in {"ok", "empty"}:
        quality = "partial"
    descriptor["include_count"] = can_count
    return {"quality": quality, "item_count": count if can_count else None,
            "truncated": truncated, "selection": descriptor}

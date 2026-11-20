"""Evidence-backed file rules; no collection, audit writes or report UI."""
from collections import defaultdict, deque
from datetime import timedelta
import ntpath

from server.sli.core.working_time import outside, validate
from server.sli.plugins.file_audit.acl import WRITE_MASK, access_mask, parse_dacl, token_for
from sli_agent.envelope import digest, timestamp
from sli_agent.file_audit_policy import path_in_root

RULE_VERSION = 1
SNAPSHOT_MAX_AGE = timedelta(days=1)


def _finding(code, binding, subject, at, *, actions=(), snapshots=(), details=None, state="observed"):
    action_ids = sorted({item["action_id"] for item in actions})
    snapshot_ids = sorted({item["snapshot_id"] for item in snapshots})
    details = details or {}
    identity = [code, RULE_VERSION, binding, subject, action_ids, snapshot_ids, details]
    return {"result_id": digest(identity), "rule_code": code, "rule_version": RULE_VERSION,
            "agent_id": binding[0], "source_instance_id": binding[1], "collection_scope_id": binding[2],
            "subject_sid": subject, "observed_at": at, "conclusion_state": state,
            "action_ids": action_ids, "snapshot_ids": snapshot_ids, "details": details}


def _inventory(action, snapshots):
    instant = timestamp(action["observed_at"])
    binding = tuple(action[key] for key in ("agent_id", "source_instance_id", "collection_scope_id"))
    candidates = [row for row in snapshots if tuple(row[key] for key in
        ("agent_id", "source_instance_id", "collection_scope_id")) == binding
        and instant - SNAPSHOT_MAX_AGE <= timestamp(row["observed_at_utc"]) <= instant]
    # Do not let a partial scan replace an earlier full inventory. An exact
    # object on a partial page may still provide positive type evidence.
    for snapshot in sorted(candidates, key=lambda row: (row["completeness"] == "complete",
            timestamp(row["observed_at_utc"]), row["snapshot_id"]), reverse=True):
        rows = [row for row in snapshot["objects"] if ntpath.normcase(row["path"]) == ntpath.normcase(action["path"])]
        kinds = {row["object_type"] for row in rows}
        if len(kinds) == 1:
            return next(iter(kinds)), snapshot
    return "unknown", None


def activity_findings(actions, *, config, agent_id, source_instance_id, snapshots=(), working_time=None):
    if working_time is not None:
        working_time = validate(working_time)
    roots = {root["collection_scope_id"]: root for root in config["roots"]}
    eligible = {}
    for item in actions:
        scope, operation = item["collection_scope_id"], item["operation"]
        if (item["agent_id"] != agent_id or item["source_instance_id"] != source_instance_id
                or scope not in roots or not item.get("subject_sid")
                or item["subject_sid"] in config["service_account_exclusions"]
                or item["outcome"] != "success" or operation not in ("read", "write", "delete")
                or not item.get("evidence") or not item.get("path")
                or item["correlation_state"] in ("ambiguous", "not_attempted")
                or operation == "delete" and item["correlation_state"] != "complete"
                or operation == "read" and not roots[scope]["important"]):
            continue
        if not path_in_root(item["path"], roots[scope]["path"]):
            continue
        kind, snapshot = item["object_type"], None
        if kind == "unknown":
            kind, snapshot = _inventory(item, snapshots)
        if kind != "file":
            continue
        previous = eligible.get(item["action_id"])
        if previous is not None and previous[0] != item:
            raise ValueError("file_audit_action_replay_conflict")
        eligible[item["action_id"]] = item, snapshot
    groups, result = defaultdict(list), []
    for item, snapshot in sorted(eligible.values(), key=lambda row: (timestamp(row[0]["observed_at"]), row[0]["action_id"])):
        binding = (agent_id, source_instance_id, item["collection_scope_id"])
        groups[(*binding, item["subject_sid"], item["operation"])].append((item, snapshot))
        if working_time is not None:
            forbidden, local = outside(item["observed_at"], item["subject_sid"], working_time)
            if forbidden:
                result.append(_finding("file-audit.out-of-hours", binding, item["subject_sid"], item["observed_at"],
                    actions=[item], snapshots=[snapshot] if snapshot else (), details={
                        "local_time": local, "calendar": working_time, "operation": item["operation"]}))
    seconds, threshold = config["mass_operation_seconds"], config["mass_operation_files"]
    for key, rows in sorted(groups.items()):
        window, selected, episodes = deque(), None, []
        for item, snapshot in rows:
            cutoff = timestamp(item["observed_at"]) - timedelta(seconds=seconds)
            while window and timestamp(window[0][0]["observed_at"]) < cutoff:
                window.popleft()
            window.append((item, snapshot))
            paths = {ntpath.normcase(row["path"]) for row, _ in window}
            if len(paths) >= threshold:
                # One current window per burst/actor/scope/operation in this bounded
                # evaluation, including every native witness of each file.
                selected = list(window), len(paths)
            elif selected:
                episodes.append(selected)
                selected = None
        if selected:
            episodes.append(selected)
        for selected in episodes:
            window, count = selected
            result.append(_finding(f"file-audit.mass-{key[-1]}", key[:3], key[3], window[-1][0]["observed_at"],
                actions=[row for row, _ in window], snapshots=[snap for _, snap in window if snap], details={
                    "distinct_files": count, "threshold": threshold, "window_seconds": seconds,
                    "window_start": window[0][0]["observed_at"], "window_end": window[-1][0]["observed_at"]}))
    return sorted(result, key=lambda row: row["result_id"])


def permission_findings(snapshot, *, config, principals=None):
    principals = principals or {}
    root = next((root for root in config["roots"] if root["collection_scope_id"] == snapshot["collection_scope_id"]), None)
    if root is None or ntpath.normcase(snapshot["share"]["path"]) != ntpath.normcase(root["path"]):
        raise ValueError("file_audit_snapshot_scope_invalid")
    binding = tuple(snapshot[key] for key in ("agent_id", "source_instance_id", "collection_scope_id"))
    share_aces, share_known = parse_dacl(snapshot["share"]["dacl"])
    share_known = share_known and snapshot["share"]["complete"]
    result = []
    objects = [("ntfs", row) for row in snapshot["objects"]]
    if config.get("source_kind") != "workstation":
        objects.append(("smb", {"path": root["path"], "dacl": snapshot["share"]["dacl"]}))
    for layer, obj in objects:
        if not path_in_root(obj["path"], root["path"]):
            raise ValueError("file_audit_snapshot_scope_invalid")
        aces, known = parse_dacl(obj["dacl"])
        if not known:
            result.append(_finding("file-audit.acl-review", binding, None, snapshot["observed_at_utc"],
                snapshots=[snapshot], state="requires_review", details={"path": obj["path"], "layer": layer,
                    "reason": "unsupported_descriptor"}))
            continue
        for sid in sorted({ace.sid for ace in aces if ace.kind == "A" and not ace.inherit_only}):
            if sid in config["service_account_exclusions"]:
                continue
            principal = principals.get(sid, {})
            token, complete = token_for(sid, principal, snapshot["local_groups"])
            mask = access_mask(aces, {sid, "S-1-1-0"})
            if not mask:
                continue
            if not principal and sid.startswith("S-1-5-21-"):
                result.append(_finding("file-audit.acl-review", binding, sid, snapshot["observed_at_utc"],
                    snapshots=[snapshot], state="requires_review", details={"path": obj["path"], "layer": layer,
                        "reason": "principal_not_observed"}))
            broad = sid == "S-1-1-0" or principal.get("kind") == "group" and principal.get("domain_users") is True
            direct = principal.get("kind") == "user" and any(ace.sid == sid and ace.kind == "A"
                                                             and not ace.inherited and not ace.inherit_only for ace in aces)
            codes = (["file-audit.broad-write"] if broad and mask & WRITE_MASK else [])
            if direct:
                codes.append("file-audit.direct-user-rights")
            if principal.get("kind") == "user" and principal.get("enabled") is False:
                codes.append("file-audit.disabled-account-rights")
            effective = None
            if layer == "ntfs" and complete and share_known:
                effective = access_mask(aces, token) & access_mask(share_aces, token)
            for code in codes:
                result.append(_finding(code, binding, sid, snapshot["observed_at_utc"], snapshots=[snapshot], details={
                    "path": obj["path"], "layer": layer, "ntfs_mask": mask if layer == "ntfs" else None,
                    "share_mask": mask if layer == "smb" else None, "effective_smb_mask": effective,
                    "effective_smb_state": "dacl_model" if effective is not None else "requires_review",
                    "limitations": ["privileges_and_conditional_aces_not_evaluated"],
                    "coverage_state": snapshot["completeness"], "membership_complete": complete,
                    "snapshot_sha256": snapshot["snapshot_sha256"], "principal": principal}))
    return sorted(result, key=lambda row: row["result_id"])

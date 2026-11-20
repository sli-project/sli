"""Read-only ATT&CK projection of registered revisions and bounded TEST history.

Offline publishers retain aggregate counters, never event payloads or samples.
An empty match store is not telemetry evidence. Source ACLs and application
capabilities are both required; neither query parameters nor STIX grant access.
"""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import re

from server.sli.access.access_control_v4 import capability_decision_for_resource_groups
from server.sli.reporting.reporting_common import get_runtime_connection
from server.sli.sigma.history_job import HistoryCounts, HistoryResult
from server.sli.sigma.registry import RegistryScope, read_revision
from server.sli.storage.evidence_ref import EvidenceScope

CONTRACT = "sli.sigma.attack-coverage.v1"
MAX_ROWS = 5000
CAPABILITIES = ("semantic.review", "events.view", "field.security")
_SHA = re.compile(r"[a-f0-9]{64}")
_TECHNIQUE = re.compile(r"T[0-9]{4}(?:\.[0-9]{3})?")


class CoverageUnavailable(RuntimeError):
    """Fixed diagnostics; storage errors and imported content stay private."""


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def import_attack_catalog(cur, raw: bytes, *, release: str, expected_sha256: str, source_uri: str):
    """Import a hash-pinned official Enterprise STIX bundle, entirely offline.

    A digest verifies the supplied bytes, not publisher authenticity. The
    installation's offline delivery process is responsible for that trust.
    Only IDs, tactics, versions and retirement flags enter the reporting store.
    """
    try:
        if (not isinstance(raw, bytes) or not 0 < len(raw) <= 64 * 1024 * 1024
                or not isinstance(release, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", release)
                or not isinstance(expected_sha256, str) or not _SHA.fullmatch(expected_sha256)
                or sha256(raw).hexdigest() != expected_sha256
                or not re.fullmatch(
                    r"https://raw\.githubusercontent\.com/mitre-attack/attack-stix-data/"
                    r"[a-f0-9]{40}/enterprise-attack/enterprise-attack\.json", source_uri)):
            raise ValueError
        bundle = json.loads(raw)
        if bundle["type"] != "bundle" or not isinstance(bundle["objects"], list):
            raise ValueError
        techniques = {}
        for item in bundle["objects"]:
            if item.get("type") != "attack-pattern" or "enterprise-attack" not in item.get("x_mitre_domains", []):
                continue
            ids = [ref["external_id"] for ref in item.get("external_references", [])
                   if ref.get("source_name") == "mitre-attack" and _TECHNIQUE.fullmatch(ref.get("external_id", ""))]
            if len(ids) != 1 or ids[0] in techniques:
                raise ValueError
            if (not isinstance(item.get("id"), str)
                    or not re.fullmatch(r"attack-pattern--[a-f0-9-]{36}", item["id"])
                    or not isinstance(item.get("modified"), str)
                    or datetime.fromisoformat(item["modified"].replace("Z", "+00:00")).utcoffset() is None
                    or any(type(item.get(key, False)) is not bool for key in ("revoked", "x_mitre_deprecated"))
                    or item.get("x_mitre_version") is not None and (
                        not isinstance(item["x_mitre_version"], str) or not 0 < len(item["x_mitre_version"]) <= 80)):
                raise ValueError
            tactics = sorted({phase["phase_name"] for phase in item.get("kill_chain_phases", [])
                              if phase.get("kill_chain_name") == "mitre-attack"})
            if any(not re.fullmatch(r"[a-z][a-z-]{0,79}", tactic) for tactic in tactics):
                raise ValueError
            techniques[ids[0]] = {"stix_id": item["id"], "modified": item["modified"],
                                  "object_version": item.get("x_mitre_version"), "tactics": tactics,
                                  "revoked": item.get("revoked", False),
                                  "deprecated": item.get("x_mitre_deprecated", False)}
        if not techniques or len(techniques) > 5000:
            raise ValueError
        document = {"release": release, "source_uri": source_uri, "techniques": techniques}
        if len(_json(document).encode()) > 4 * 1024 * 1024:
            raise ValueError
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise ValueError("sigma_attack_catalog_invalid") from None
    cur.execute("""
        insert into sli_sigma.attack_catalogs(stix_sha256,document_json)
        values(%s,%s::jsonb) on conflict(stix_sha256) do nothing
    """, (expected_sha256, _json(document)))
    cur.execute("select document_json from sli_sigma.attack_catalogs where stix_sha256=%s", (expected_sha256,))
    if dict(cur.fetchone() or {}).get("document_json") != document:
        raise CoverageUnavailable("sigma_attack_catalog_conflict")
    return expected_sha256


def record_history_coverage(cur, result: HistoryResult, *, scope: EvidenceScope, resources: list[dict]):
    """Publish aggregate history checkpoints in the caller's transaction.

    ``resources`` comes from the authorized source adapter (server/domain/
    channel and plugin/source dimensions), never an HTTP body. Registration
    is append-only and an existing scope cannot be rebound to other resources.
    No fixture success, audit continuity, live matches or admission is inferred.
    """
    if (not isinstance(result, HistoryResult) or not isinstance(scope, EvidenceScope)
            or not isinstance(resources, list) or not 1 <= len(resources) <= 16
            or any(not isinstance(resource, dict) or set(resource) - {
                "server_id", "domain_id", "channel", "plugin_id", "source_instance_id", "collection_scope_id"}
                   or not resource for resource in resources)
            or result.status not in ("completed", "partial", "cancelled", "failed")
            or result.checkpoint.request_sha256 != result.request.key):
        raise ValueError("sigma_attack_history_invalid")
    # Always include the exact generic source, alongside native ACL dimensions.
    resources = [dict(resource) for resource in resources]
    for resource in resources:
        if (resource.get("plugin_id", scope.plugin_id) != scope.plugin_id
                or resource.get("source_instance_id", scope.source_instance_id) != scope.source_instance_id
                or resource.get("collection_scope_id", scope.collection_scope_id) != scope.collection_scope_id
                or any(type(resource[key]) is not int or resource[key] <= 0
                       for key in ("server_id", "domain_id") if key in resource)
                or ("channel" in resource and (not isinstance(resource["channel"], str)
                                               or not 0 < len(resource["channel"]) <= 256))):
            raise ValueError("sigma_attack_history_invalid")
        resource.update(plugin_id=scope.plugin_id, source_instance_id=scope.source_instance_id,
                        collection_scope_id=scope.collection_scope_id)
    parts = result.request.partitions
    selected = [(index, part) for index, part in enumerate(parts)
                if (part.scope.installation_id, part.scope.source_instance_id, part.scope.source_generation)
                == (scope.installation_id, scope.source_instance_id, scope.source_generation)]
    kinds = {"core_event": "sli.windows.ad-dc", "core_history": "sli.windows.ad-dc",
             "workstation_observation": "sli.workstations", "workstation_history": "sli.workstations",
             "file_audit": "sli.file-audit"}
    if not selected or any(kinds[part.storage_kind] != scope.plugin_id for _, part in selected):
        raise ValueError("sigma_attack_history_invalid")
    if ((scope.plugin_id == "sli.file-audit") != bool(scope.collection_scope_id)
            or not 0 <= result.checkpoint.partition_index <= len(parts)
            or result.status == "completed" and result.checkpoint.partition_index != len(parts)):
        raise ValueError("sigma_attack_history_invalid")
    counts = {(row.partition_key, row.rule_id): row for row in result.checkpoint.counts}
    if len(counts) != len(result.checkpoint.counts):
        raise ValueError("sigma_attack_history_invalid")
    for index, part in selected:
        for rule in result.request.rules:
            row = counts.get((part.key, rule.rule_id))
            if row is None:
                if index < result.checkpoint.partition_index:
                    raise ValueError("sigma_attack_history_invalid")
                continue
            numbers = (row.scanned, row.evaluable, row.matched, row.suppressed, row.unknown, row.skipped)
            if (any(type(value) is not int or value < 0 for value in numbers)
                    or row.scanned != row.evaluable + row.unknown + row.skipped
                    or row.matched + row.suppressed > row.evaluable):
                raise ValueError("sigma_attack_history_invalid")
    scope_params = tuple(asdict(scope).values())
    cur.execute("""
        insert into sli_sigma.attack_source_scopes(
            installation_id,plugin_id,source_instance_id,source_generation,collection_scope_id,resources)
        values(%s,%s,%s,%s,%s,%s::jsonb) on conflict do nothing
    """, (*scope_params, _json(resources)))
    cur.execute("""
        select resources from sli_sigma.attack_source_scopes
        where installation_id=%s and plugin_id=%s and source_instance_id=%s
          and source_generation=%s and collection_scope_id=%s
    """, scope_params)
    if dict(cur.fetchone() or {}).get("resources") != resources:
        raise CoverageUnavailable("sigma_attack_source_conflict")
    registry_scope = RegistryScope(scope.installation_id, scope.plugin_id, scope.source_instance_id)
    for rule in result.request.rules:
        revision = read_revision(cur, registry_scope, rule.rule_id, rule.source_sha256)
        if (not revision or revision["raw_sha256"] != rule.source_sha256
                or revision["upstream_commit"] != rule.upstream_commit):
            raise CoverageUnavailable("sigma_attack_revision_unavailable")
        for index, part in selected:
            count = counts.get((part.key, rule.rule_id), HistoryCounts(part.key, rule.rule_id))
            complete = index < result.checkpoint.partition_index
            document = {"version": CONTRACT, "request_sha256": result.request.key,
                        "partition_key": part.key, "snapshot_sha256": sha256(part.snapshot.encode()).hexdigest(),
                        "high_watermark": part.high_watermark, "manifest_sha256": result.request.manifest_sha256,
                        "plan_sha256": rule.plan_sha256, "compiler_version": rule.compiler_version,
                        "mapping_version": rule.mapping_version, "overlay_sha256": None,
                        "required_fields": list(rule.required_fields), "logsource": rule.logsource,
                        "mode": "test", "status": result.status, "partition_complete": complete,
                        "counts": asdict(count), "fixture_validation": "not_checked",
                        "telemetry_continuity": "unknown"}
            cur.execute("""
                insert into sli_sigma.attack_history_coverage(
                    installation_id,plugin_id,source_instance_id,source_generation,collection_scope_id,
                    rule_id,raw_sha256,time_from,time_to,document_json)
                values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb) on conflict do nothing
            """, (*scope_params, rule.rule_id, rule.source_sha256, part.start, part.end, _json(document)))


def _window(since, until):
    try:
        start, end = (datetime.fromisoformat(value.replace("Z", "+00:00")) for value in (since, until))
        if (start.utcoffset() is None or end.utcoffset() is None
                or not timedelta(0) < end - start <= timedelta(days=31)):
            raise ValueError
        return start.astimezone(timezone.utc), end.astimezone(timezone.utc)
    except (ValueError, TypeError, AttributeError):
        raise ValueError("sigma_attack_filter_invalid") from None


def _read_source(cur, scope):
    params = tuple(asdict(scope).values())
    cur.execute("""
        select resources from sli_sigma.attack_source_scopes
        where installation_id=%s and plugin_id=%s and source_instance_id=%s
          and source_generation=%s and collection_scope_id=%s
    """, params)
    return dict(cur.fetchone() or {})


def _authorized(access, resources):
    if not resources:
        return False
    if access.get("platform_owner"):
        return True
    groups = []
    for resource in resources:
        group = [resource]
        for kind in ("server", "domain"):
            if resource.get(f"{kind}_id") is not None:
                group.append({"kind": kind, "id": resource[f"{kind}_id"]})
        if resource.get("channel"):
            group.append({"kind": "channel", "value": resource["channel"]})
        groups.append(group)
    # Aggregate sources without a native dimension cannot prove that a deny
    # on that dimension is irrelevant. Keep such sources unavailable.
    dimensions = {"server": "server_id", "domain": "domain_id", "channel": "channel"}
    for policy in access.get("capability_policies", []):
        if policy.get("effect") != "deny" or policy.get("capability_key") not in CAPABILITIES:
            continue
        denied_scope = policy.get("scope") or {}
        dimension = dimensions.get(denied_scope.get("kind"))
        if dimension and any(not resource.get(dimension) for resource in resources):
            return False
        if any(clause.get("device_ids") or clause.get("entity_ids") for clause in denied_scope.get("clauses", [])):
            return False
    return all(capability_decision_for_resource_groups(
        access, capability, resource_groups=groups)["allowed"]
        for capability in CAPABILITIES)


def get_attack_coverage(access, *, scope: EvidenceScope, since: str, until: str, catalog_sha256: str):
    """Aggregate one exact source/generation and a half-open occurrence window.

    The denominator is visible registered revisions, not all ATT&CK attacks.
    Subtechniques never roll up into parent coverage. Partial-window history
    cannot be apportioned and is excluded with an explicit incomplete state.
    """
    start, end = _window(since, until)
    if not isinstance(scope, EvidenceScope) or not isinstance(catalog_sha256, str) or not _SHA.fullmatch(catalog_sha256):
        raise ValueError("sigma_attack_filter_invalid")
    base = {"api_version": "v1", "contract": CONTRACT, "read_only": True,
            "scope": asdict(scope), "since": start.isoformat(), "until": end.isoformat(),
            "window_basis": "occurrence_time", "denominator": "visible_registered_rule_revisions",
            "catalog_sha256": catalog_sha256, "items": [], "unmapped": [], "rules": []}
    # Coarse preflight avoids any DB read when the module itself is unavailable.
    available = set(access.get("capabilities") or []) | set(access.get("resource_bound_capabilities") or [])
    available |= {row.get("capability_key") for row in access.get("capability_policies", [])
                  if row.get("effect") == "allow" and row.get("valid")}
    if not access.get("platform_owner") and not set(CAPABILITIES) <= available:
        return base | {"state": "unavailable", "reason": "source_unavailable_or_denied"}
    try:
        with get_runtime_connection() as connection, connection.cursor() as cur:
            cur.execute("set transaction isolation level repeatable read, read only")
            source = _read_source(cur, scope)
            if not _authorized(access, source.get("resources")):
                return base | {"state": "unavailable", "reason": "source_unavailable_or_denied"}
            cur.execute("select document_json from sli_sigma.attack_catalogs where stix_sha256=%s", (catalog_sha256,))
            catalog = dict(cur.fetchone() or {}).get("document_json")
            if not catalog:
                return base | {"state": "unavailable", "reason": "catalog_unavailable"}
            cur.execute("""
                select rule_id,raw_sha256,canonical_sha256,upstream_commit,status,tags
                from sli_sigma.sigma_rule_revisions
                where installation_id=%s and plugin_id=%s and source_instance_id=%s
                order by rule_id,raw_sha256 limit %s
            """, (scope.installation_id, scope.plugin_id, scope.source_instance_id, MAX_ROWS + 1))
            revisions = [dict(row) for row in cur.fetchall()]
            cur.execute("""
                select rule_id,raw_sha256,time_from,time_to,document_json,created_at,coverage_sha256
                from sli_sigma.attack_history_coverage
                where installation_id=%s and plugin_id=%s and source_instance_id=%s
                  and source_generation=%s and collection_scope_id=%s
                  and time_from < %s and time_to > %s
                order by created_at desc,coverage_sha256 desc limit %s
            """, (*tuple(asdict(scope).values()), end, start, MAX_ROWS + 1))
            observations = [dict(row) for row in cur.fetchall()]
            cur.execute("select * from sli_sigma.read_attack_live_matches(%s,%s,%s,%s,%s,%s,%s)",
                        (*tuple(asdict(scope).values()), start, end))
            matches = [dict(row) for row in cur.fetchall()]
            if max(len(revisions), len(observations), len(matches)) > MAX_ROWS:
                return base | {"state": "unavailable", "reason": "projection_limit"}
            return _aggregate(base, catalog, revisions, observations, matches, start, end)
    except Exception:
        # No fallback to an owner connection, missing schema is not zero data.
        return base | {"state": "unavailable", "reason": "projection_unavailable"}


def _aggregate(base, catalog, revisions, observations, matches, start, end):
    by_rule = {}
    for row in observations:
        by_rule.setdefault((str(row["rule_id"]), row["raw_sha256"]), []).append(row)
    cells, unmapped, rules = {}, [], []
    for revision in revisions:
        key = (str(revision["rule_id"]), revision["raw_sha256"])
        executions = _executions(by_rule.get(key, []), start, end)
        inputs = [row for row in matches if (row["rule_id"], row["rule_sha256"]) == key]
        for row in inputs:
            for name in ("first_occurred_at", "last_occurred_at"):
                row[name] = row[name].isoformat()
        rule = {"rule_id": key[0], "raw_sha256": key[1],
                "canonical_sha256": revision["canonical_sha256"], "upstream_commit": revision["upstream_commit"],
                "upstream_status": revision["status"], "upstream_tags": revision["tags"],
                "executions": executions, "compiled": bool(executions or inputs),
                "compile_state": "supported" if executions or inputs else (
                    "unsupported" if revision["status"] == "unsupported" else "not_checked"),
                "fixture_validation": "not_checked", "telemetry_continuity": "unknown",
                "detection_inputs": inputs, "eligible_detection_matches": sum(row["matches"] for row in inputs),
                "match_basis": "eligible_atomic_detection_inputs", "current_admission": "not_measured",
                "lifecycle": "test" if executions else "not_checked"}
        rules.append(rule)
        tags = sorted(set(tag for tag in revision["tags"] if isinstance(tag, str) and tag.startswith("attack.")))
        mapped = set()
        tactics = {tactic for technique in catalog["techniques"].values() for tactic in technique["tactics"]}
        rule["upstream_tactics"] = []
        for tag in tags:
            technique = tag.removeprefix("attack.").upper()
            tactic = tag.removeprefix("attack.").replace("_", "-")
            if tactic in tactics:
                rule["upstream_tactics"].append(tactic)
                continue
            if not _TECHNIQUE.fullmatch(technique) or technique not in catalog["techniques"]:
                unmapped.append({"rule_id": key[0], "raw_sha256": key[1], "tag": tag,
                                 "reason": "not_a_catalog_technique"})
                continue
            mapped.add(technique)
        if not tags:
            unmapped.append({"rule_id": key[0], "raw_sha256": key[1], "tag": None, "reason": "missing_attack_tag"})
        elif not mapped and len(rule["upstream_tactics"]) == len(tags):
            unmapped.append({"rule_id": key[0], "raw_sha256": key[1], "tag": None, "reason": "missing_technique_tag"})
        for technique in sorted(mapped):
            cell = cells.setdefault(technique, {"technique_id": technique, **catalog["techniques"][technique],
                                               "mapping_provenance": "upstream_tag_exact", "rules": []})
            cell["rules"].append({"rule_id": key[0], "raw_sha256": key[1]})
    for cell in cells.values():
        refs = {(ref["rule_id"], ref["raw_sha256"]) for ref in cell["rules"]}
        members = [rule for rule in rules if (rule["rule_id"], rule["raw_sha256"]) in refs]
        cell["counts"] = {"library": len(members), "compiled": sum(rule["compiled"] for rule in members),
                          "fixture_verified": 0, "telemetry_verified": 0,
                          "shadow": None, "enabled": None,
                          "eligible_detection_matches": sum(rule["eligible_detection_matches"] for rule in members)}
        cell["history_states"] = {state: sum(any(execution["state"] == state for execution in rule["executions"])
                                             for rule in members)
                                  for state in ("no_data", "no_matches", "matched", "degraded", "not_evaluable", "incomplete")}
    return base | {"state": "available", "reason": None,
                   "catalog": {key: value for key, value in catalog.items() if key != "techniques"},
                   "items": [cells[key] for key in sorted(cells)], "unmapped": unmapped, "rules": rules}


def _executions(rows, start, end):
    groups = {}
    for row in rows:
        doc = row["document_json"]
        pin = tuple(doc[key] for key in ("manifest_sha256", "plan_sha256", "compiler_version", "mapping_version", "overlay_sha256"))
        groups.setdefault(pin, []).append(row)
    output = []
    for pin, candidates in sorted(groups.items(), key=lambda item: _json(item[0])):
        selected, excluded, intervals = [], False, []
        # Newest publication replaces earlier checkpoints/replays of the same
        # source interval. Overlaps never double-count events or rule matches.
        for row in sorted(candidates, key=lambda row: (row["created_at"], row["coverage_sha256"]), reverse=True):
            left, right = row["time_from"], row["time_to"]
            if not start <= left < right <= end:
                excluded = True
                continue
            if any(left < old_right and old_left < right for old_left, old_right in intervals):
                if (left, right) not in intervals:
                    excluded = True
                continue
            intervals.append((left, right))
            selected.append(row)
        counts = {key: sum(row["document_json"]["counts"][key] for row in selected)
                  for key in ("scanned", "evaluable", "matched", "suppressed", "unknown", "skipped")}
        ordered = sorted(intervals)
        covered = bool(ordered) and ordered[0][0] == start and ordered[-1][1] == end and all(
            previous[1] == following[0] for previous, following in zip(ordered, ordered[1:]))
        complete = (covered and not excluded and all(row["document_json"]["partition_complete"]
                    and row["document_json"]["status"] == "completed" for row in selected))
        if not complete:
            state = "incomplete"
        elif not counts["scanned"]:
            state = "no_data"
        elif counts["unknown"] or counts["skipped"] or not counts["evaluable"]:
            state = "not_evaluable" if not counts["evaluable"] else "degraded"
        else:
            state = "matched" if counts["matched"] else "no_matches"
        output.append({**dict(zip(("manifest_sha256", "plan_sha256", "compiler_version", "mapping_version", "overlay_sha256"), pin)),
                       "mode": "test", "state": state, "complete": complete, "counts": counts,
                       "required_fields": sorted({field for row in selected for field in
                                                   row["document_json"].get("required_fields", [])}),
                       "logsources": sorted({row["document_json"]["logsource"] for row in selected
                                             if "logsource" in row["document_json"]}),
                       "evaluable_percent": 100 * counts["evaluable"] / counts["scanned"] if counts["scanned"] else None,
                       "matches_per_1000_evaluable": 1000 * counts["matched"] / counts["evaluable"] if counts["evaluable"] else None,
                       "evaluation_intervals": [{"since": left.isoformat(), "until": right.isoformat()} for left, right in ordered],
                       "observed_intervals": [{"first_occurred_at": row["document_json"]["counts"]["first_occurred_at"],
                                               "last_occurred_at": row["document_json"]["counts"]["last_occurred_at"]}
                                              for row in selected if row["document_json"]["counts"]["scanned"]
                                              and row["document_json"]["counts"]["first_occurred_at"] is not None],
                       "quality": [{"since": row["time_from"].isoformat(), "until": row["time_to"].isoformat(),
                                    "status": row["document_json"]["status"],
                                    "reasons": row["document_json"]["counts"]["reasons"],
                                    "unknown_fields": row["document_json"]["counts"]["unknown_fields"],
                                    "first_occurred_at": row["document_json"]["counts"]["first_occurred_at"],
                                    "last_occurred_at": row["document_json"]["counts"]["last_occurred_at"],
                                    "published_at": row["created_at"].isoformat(),
                                    "request_sha256": row["document_json"]["request_sha256"],
                                    "snapshot_sha256": row["document_json"]["snapshot_sha256"],
                                    "high_watermark": row["document_json"]["high_watermark"],
                                    "coverage_sha256": row["coverage_sha256"]} for row in selected]})
    return output

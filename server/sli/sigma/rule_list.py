"""Read-only registered revisions with exact, owner-visible policy bindings.

Uses metadata columns and the bounded exact-revision label reader. Policy
titles never masquerade as retained revision metadata.
"""
from dataclasses import asdict
from datetime import timedelta
import json

from server.sli.reporting.reporting_common import get_runtime_connection
from server.sli.sigma.attack_coverage import CAPABILITIES, MAX_ROWS, _authorized, _executions, _read_source
from server.sli.sigma.lifecycle import execution_pin_sha256
from server.sli.storage.evidence_ref import EvidenceScope

CONTRACT = "sli.sigma.rules.v1"
MAX_SOURCES = 200


def _policies(cur, scope, revisions):
    cur.execute("""
        select p.policy_id,p.policy_version,p.lifecycle_status,
               p.definition_json->>'title' as policy_title,
               p.definition_json->'source_selector' as selector,
               coalesce(a.enabled,false) as admitted,
               semantic_policy_mode_v160(p.policy_id,p.policy_version,p.lifecycle_status) as effective_mode
        from semantic_risk_policies p
        left join semantic_policy_admission a using(policy_id,policy_version)
        where p.source_kind='detection_match'
          and p.definition_json#>'{source_selector,execution,scope}'=%s::jsonb
        order by p.policy_id,p.policy_version limit %s
    """, (json.dumps(asdict(scope), sort_keys=True), MAX_ROWS + 1))
    candidates = [dict(row) for row in cur.fetchall()]
    if len(candidates) > MAX_ROWS:
        raise ValueError("projection_limit")
    keys = {(str(row["rule_id"]), row["raw_sha256"]) for row in revisions}
    output = {}
    for row in candidates:
        selector = row.pop("selector")
        try:
            pin = selector["execution"]
            execution_pin_sha256(pin, rule_id=selector["rule_id"])
            key = (selector["rule_id"], pin["rule_sha256"])
            if pin["scope"] != asdict(scope) or key not in keys:
                continue
        except (ValueError, KeyError, TypeError):
            continue
        output.setdefault(key, []).append(row | {"execution": pin})
    return output


def get_sigma_rules(access, *, scope: EvidenceScope | None = None):
    """Discover authorized scopes or read one scope's latest retained window.

    Historical bounds are explicit and never silently replaced by today's
    date. No TEST, lifecycle, compilation or plugin flag implies admission.
    """
    if scope is not None and not isinstance(scope, EvidenceScope):
        raise ValueError("sigma_rule_filter_invalid")
    base = {"api_version": "v1", "contract": CONTRACT, "read_only": True,
            "state": "available", "reason": None, "sources": [], "rules": [],
            "scope": asdict(scope) if scope else None, "since": None, "until": None,
            "window_basis": "latest_retained_test_history", "metadata_state": "unavailable"}

    def unavailable(reason):
        return base | {"state": "unavailable", "reason": reason}

    available = set(access.get("capabilities") or []) | set(access.get("resource_bound_capabilities") or [])
    available |= {row.get("capability_key") for row in access.get("capability_policies", [])
                  if row.get("effect") == "allow" and row.get("valid")}
    if not access.get("platform_owner") and not set(CAPABILITIES) <= available:
        return unavailable("source_unavailable_or_denied")
    try:
        with get_runtime_connection() as connection, connection.cursor() as cur:
            cur.execute("set transaction isolation level repeatable read, read only")
            if scope is None:
                cur.execute("""select installation_id,plugin_id,source_instance_id,source_generation,
                    collection_scope_id,resources from sli_sigma.attack_source_scopes
                    order by installation_id,plugin_id,source_instance_id,source_generation,collection_scope_id
                    limit 201""")
                sources = [dict(row) for row in cur.fetchall()]
                if len(sources) > MAX_SOURCES:
                    return unavailable("projection_limit")
                visible = [{key: str(row[key]) for key in EvidenceScope.__dataclass_fields__}
                           for row in sources if _authorized(access, row["resources"])]
                return base | {"sources": visible} if visible else unavailable("source_unavailable_or_denied")
            if not _authorized(access, _read_source(cur, scope).get("resources")):
                return unavailable("source_unavailable_or_denied")
            cur.execute("""select r.rule_id,r.raw_sha256,r.canonical_sha256,r.upstream_commit,r.status,r.tags,
                       labels.title,labels.description,labels.rule_id is not null as labels_available
                from sli_sigma.sigma_rule_revisions r
                left join lateral sli_sigma.read_rule_labels(
                    r.installation_id,r.plugin_id,r.source_instance_id,r.rule_id,r.raw_sha256) labels on true
                where r.installation_id=%s and r.plugin_id=%s and r.source_instance_id=%s
                order by r.rule_id,r.raw_sha256 limit %s""",
                (scope.installation_id, scope.plugin_id, scope.source_instance_id, MAX_ROWS + 1))
            revisions = [dict(row) for row in cur.fetchall()]
            cur.execute("""select rule_id,raw_sha256,time_from,time_to,document_json,created_at,coverage_sha256
                from sli_sigma.attack_history_coverage
                where installation_id=%s and plugin_id=%s and source_instance_id=%s
                  and source_generation=%s and collection_scope_id=%s
                order by created_at desc,coverage_sha256 desc limit %s""",
                (*asdict(scope).values(), MAX_ROWS + 1))
            observations = [dict(row) for row in cur.fetchall()]
            if max(len(revisions), len(observations)) > MAX_ROWS:
                return unavailable("projection_limit")
            matches = []
            start = end = None
            if observations:
                end = max(row["time_to"] for row in observations)
                start = max(min(row["time_from"] for row in observations), end - timedelta(days=31))
                cur.execute("select * from sli_sigma.read_attack_live_matches(%s,%s,%s,%s,%s,%s,%s)",
                            (*asdict(scope).values(), start, end))
                matches = [dict(row) for row in cur.fetchall()]
                if len(matches) > MAX_ROWS:
                    return unavailable("projection_limit")
            policies = _policies(cur, scope, revisions) if access.get("platform_owner") else {}
            rules = []
            for revision in revisions:
                key = (str(revision["rule_id"]), revision["raw_sha256"])
                history = [row for row in observations if (str(row["rule_id"]), row["raw_sha256"]) == key
                           and row["time_from"] < end and row["time_to"] > start] if start else []
                inputs = [row for row in matches if (str(row["rule_id"]), row["rule_sha256"]) == key]
                runtime = {mode: sum(row["matches"] for row in inputs if row["evaluation_mode"] == mode)
                           if start else None for mode in ("enabled", "shadow", "test")}
                labels_available = revision.pop("labels_available", False)
                rules.append({**revision, "rule_id": key[0], "title": revision.get("title"), "description": revision.get("description"),
                    "metadata_state": "available" if labels_available else "unavailable", "executions": _executions(history, start, end) if start else [],
                    "admission": {"state": "available" if access.get("platform_owner") else "unavailable",
                                  "reason": None if access.get("platform_owner") else "owner_required",
                                  "policies": policies.get(key, [])},
                    "runtime": {"state": "measured" if start else "unmeasured",
                                "basis": "eligible_atomic_detection_inputs", **runtime}})
            return base | {"rules": rules, "metadata_state": "available" if all(row["metadata_state"] == "available" for row in rules) else "unavailable",
                           "since": start.isoformat() if start else None,
                           "until": end.isoformat() if end else None}
    except ValueError as exc:
        return unavailable("projection_limit" if str(exc) == "projection_limit" else "projection_unavailable")
    except Exception:
        # Preserve RLS and least privilege. Missing bindings/schema are not zero.
        return unavailable("projection_unavailable")

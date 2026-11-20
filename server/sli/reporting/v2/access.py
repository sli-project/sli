"""One report-grant check for every report (replaces the copied ``_*_domain_scope`` helpers)."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
import json
from typing import Any

from server.sli.access.scope import AccessScope, ScopeClause, legacy_domain_ids, scope_from_grant
from server.sli.access.access_control_v4 import capability_decision
from server.sli.reporting.v2.definition import AccessRequirement, AccessRule, Detail, ReportDefinition, ResultState, result


def report_grant(access: Mapping[str, Any], report_key: str) -> Mapping[str, Any] | None:
    return next(
        (item for item in access.get("reports") or [] if item.get("report_key") == report_key and item.get("allowed")),
        None,
    )


def resolve_access_scope(access: Mapping[str, Any], rule: AccessRule | AccessRequirement, action: str = "view") -> AccessScope:
    """Issue an explicit scope from server grants, keeping each grant atomic."""
    required_role = getattr(rule, "required_role", None)
    if required_role and (access.get("subject") or {}).get("coarse_role") != required_role:
        raise PermissionError("report_access_denied")
    report = report_grant(access, rule.report_key)
    if not report or action not in set(report.get("allowed_actions") or []):
        raise PermissionError("report_access_denied")
    if not getattr(rule, "required_capabilities", frozenset()).issubset(set(access.get("capabilities") or [])):
        raise PermissionError("report_access_denied")
    if getattr(rule, "global_scope_only", False) and any(
        not capability_decision(access, key)["allowed"] for key in rule.required_capabilities
    ):
        raise PermissionError("report_access_denied")
    revision = str(access.get("policy_revision") or sha256(json.dumps(
        {"report": report, "capabilities": access.get("capabilities", [])}, sort_keys=True, default=str,
    ).encode()).hexdigest())
    decision_id = str(access.get("decision_id") or sha256(json.dumps(
        {"principal": access.get("subject", {}), "revision": revision, "action": action}, sort_keys=True, default=str,
    ).encode()).hexdigest())
    scopes = []
    eligible = False
    for grant in report.get("grants") or []:
        if action not in set(grant.get("allowed_actions") or []):
            continue
        if not rule.required_fields.issubset(set(grant.get("field_categories") or [])):
            continue
        eligible = True
        try:
            scopes.append(scope_from_grant(dict(grant.get("scope") or {}), decision_id=decision_id, policy_revision=revision))
        except (TypeError, ValueError):
            # Invalid/unsupported grants never become an unrestricted query.
            continue
    if not eligible:
        raise PermissionError("report_field_categories_not_allowed")
    if any(scope.mode == "all" for scope in scopes):
        return AccessScope("all", decision_id=decision_id, policy_revision=revision)
    if getattr(rule, "global_scope_only", False):
        raise PermissionError("report_scope_not_executable")
    clauses = tuple(clause for scope in scopes for clause in scope.clauses)
    # Preserve the legacy union of independent domain assignments, including
    # category grants covering different subsets of the same query domains.
    domains = {value for clause in clauses if not any((clause.plugin_ids, clause.source_instance_ids, clause.device_ids, clause.entity_ids))
               for value in clause.collection_scope_ids}
    others = tuple(clause for clause in clauses if any((clause.plugin_ids, clause.source_instance_ids, clause.device_ids, clause.entity_ids)))
    clauses = others + ((ScopeClause(collection_scope_ids=tuple(sorted(domains))),) if domains else ())
    if not clauses:
        raise PermissionError("report_scope_not_executable")
    try:
        return AccessScope("restricted", clauses, decision_id, revision)
    except ValueError as exc:
        raise PermissionError("report_scope_not_executable") from exc


def resolve_domain_scope(access: Mapping[str, Any], rule: AccessRule, action: str = "view") -> list[int] | None:
    """AD compatibility adapter; None follows only an explicit all grant."""
    return legacy_domain_ids(resolve_access_scope(access, rule, action))


class ReportAccess:
    """Project a report over categories authorised for its entire query scope.

    Every check resolves core + dependencies within individual grants. A field
    granted in only part of the query scope stays hidden; categories and scopes
    from different grants are never multiplied together.
    """

    def __init__(self, definition: ReportDefinition, access: Mapping[str, Any], action: str = "view"):
        self.definition = definition
        self.access = access
        self.action = action
        if definition.access.scope == "delegated" and not definition.access.accepts_generic_scope:
            report = report_grant(access, definition.access.report_key)
            if any("mode" in (grant.get("scope") or {}) for grant in (report or {}).get("grants") or []):
                # These readers still delegate to legacy engines; a persisted
                # generic grant must not be interpreted as an absent filter.
                raise PermissionError("report_scope_not_executable")
        self.scope = resolve_access_scope(access, definition.access, action) if definition.access.scope != "delegated" else None
        self.domain_ids = legacy_domain_ids(self.scope) if definition.access.scope == "domain" else None
        self._checks: dict[frozenset[str], bool] = {}

    def fields_allowed(self, fields: frozenset[str]) -> bool:
        if not fields:
            return True
        if fields not in self._checks:
            rule = replace(self.definition.access, required_fields=self.definition.access.required_fields | fields)
            try:
                scope = resolve_access_scope(self.access, rule, self.action)
                target = self.scope or AccessScope("all")
                self._checks[fields] = scope.covers(target)
            except PermissionError:
                self._checks[fields] = False
        return self._checks[fields]

    def rule_decision(self, rule: AccessRule | None) -> dict[str, Any]:
        if rule is None:
            return {"allowed": True}
        # A same-report tab must satisfy its core and tab categories atomically.
        if rule.report_key == self.definition.access.report_key:
            rule = replace(rule, required_fields=rule.required_fields | self.definition.access.required_fields)
        try:
            scope = resolve_access_scope(self.access, rule, self.action)
            if not scope.covers(self.scope or AccessScope("all")):
                raise PermissionError("report_scope_not_executable")
        except PermissionError as exc:
            fields = rule.required_fields
            if rule.report_key == self.definition.access.report_key:
                fields -= self.definition.access.required_fields
            return {"allowed": False, "reason": str(exc), "hidden_categories": sorted(fields) if str(exc) == "report_field_categories_not_allowed" else []}
        return {"allowed": True}

    @property
    def summary(self) -> dict[str, Any]:
        definition = self.definition
        dependencies = [item.field_categories for item in (*definition.columns, *definition.params)]
        dependencies += list(definition.metric_categories.values()) + list(definition.row_categories.values()) + list(definition.series_categories.values())
        dependencies += [column.field_categories for view in definition.views for column in view.columns]
        if isinstance(definition.detail, Detail):
            dependencies += [column.field_categories for column in definition.detail.columns]
        hidden = {category for fields in dependencies if not self.fields_allowed(fields) for category in fields
                  if not self.fields_allowed(frozenset({category}))}
        # Joint dependencies may fail even when each category is available on
        # its own: those categories still cannot be combined across grants.
        if not hidden:
            hidden = set().union(*(fields for fields in dependencies if not self.fields_allowed(fields)))
        return {"allowed": True, "hidden_categories": sorted(hidden), "reason": "report_field_categories_not_allowed" if hidden else None}

    def declaration(self) -> dict[str, Any]:
        definition = self.definition
        payload = definition.to_json()
        payload["access"] = self.summary
        payload["columns"] = [column.to_json() for column in definition.columns if self.fields_allowed(column.field_categories)]
        payload["params"] = [param.to_json() for param in definition.params if self.fields_allowed(param.field_categories)]
        visible_params = {param["key"] for param in payload["params"]}
        payload["presets"] = [preset for preset in payload["presets"] if set(preset["params"]) <= visible_params]
        for view, item in zip(definition.views, payload["views"], strict=True):
            item["access"] = self.rule_decision(view.access)
            if "columns" in item:
                item["columns"] = [col.to_json() for col in view.columns if self.fields_allowed(col.field_categories)]
        if isinstance(definition.detail, Detail):
            payload["detail"]["access"] = self.rule_decision(definition.detail.access)
            payload["detail"]["columns"] = [col.to_json() for col in definition.detail.columns if self.fields_allowed(col.field_categories)]
        return payload

    def validate_request(self, query: Mapping[str, Any], paging: Mapping[str, Any], *, detail: bool = False) -> None:
        definition = self.definition
        for param in definition.params:
            if query.get(param.key) and not self.fields_allowed(param.field_categories):
                raise PermissionError("report_field_categories_not_allowed")
        for column in definition.columns:
            if paging.get("sort") == column.key and not self.fields_allowed(column.field_categories):
                raise PermissionError("report_field_categories_not_allowed")
        tab = paging.get("tab") or (definition.views[0].key if definition.views else None)
        view = next((view for view in definition.views if view.key == tab), None)
        rules = [view.access] if view else []
        if detail and isinstance(definition.detail, Detail):
            rules.append(definition.detail.access)
        for rule in rules:
            decision = self.rule_decision(rule)
            if not decision["allowed"]:
                raise PermissionError(decision["reason"])

    def restrict_request(self, params: Mapping[str, Any]) -> AccessScope:
        """Intersect declared request dimensions with the issued grant scope."""
        scope = self.scope or AccessScope()
        dimensions = {}
        for key, dimension in (("plugin_id", "plugin_ids"), ("source_instance_id", "source_instance_ids"),
                               ("device_id", "device_ids"), ("entity_id", "entity_ids")):
            if key == "entity_id" and self.definition.access.scope == "domain":
                # Legacy domain readers enforce entity membership as a population
                # filter; entity clauses cannot pass through the domain adapter.
                continue
            value = params.get(key)
            if value is not None:
                dimensions[dimension] = tuple(value) if isinstance(value, list) else (value,)
        if params.get("domain") is not None:
            dimensions["collection_scope_ids"] = (f"ad-domain:{params['domain']}",)
        if dimensions:
            scope = scope.intersect(AccessScope("restricted", (ScopeClause(**dimensions),)))
            if scope.mode == "none" and self.definition.access.scope != "delegated":
                raise PermissionError("report_scope_not_executable")
        return scope

    def _rows(self, rows, columns, *, main: bool = False):
        denied = {col.path or col.key for col in columns if not self.fields_allowed(col.field_categories)}
        if main:
            denied.update(path for path, fields in self.definition.row_categories.items() if not self.fields_allowed(fields))
        projected = deepcopy(list(rows or []))
        for row in projected:
            for path in denied:
                self._remove(row, path)
        return projected

    @staticmethod
    def _remove(row, path: str) -> None:
        head, _, tail = path.partition(".")
        if isinstance(row, list):
            for item in row:
                ReportAccess._remove(item, path)
        elif isinstance(row, dict):
            if tail:
                ReportAccess._remove(row.get(head), tail)
            else:
                row.pop(head, None)

    def result(self, data: Mapping[str, Any], *, detail: bool = False) -> dict[str, Any]:
        definition = self.definition
        payload = deepcopy(dict(data))
        try:
            payload["state"] = ResultState(payload.get("state")).value
        except (TypeError, ValueError):
            payload = result(definition, state="error", coverage={"reason": "report_state_unknown"})
        payload["access"] = self.summary
        if payload.get("state") == "denied":
            reason = payload.get("reason")
            if reason not in {"report_access_denied", "report_field_categories_not_allowed", "report_scope_not_executable"}:
                reason = "report_access_denied"
            payload.update(reason=reason, items=[], metrics=[], series={}, collections={}, filter_options={}, coverage={}, limitations=[], window={},
                           filtered_count=None, has_more=False, next_cursor=None)
            payload["state_details"] = {"reason": reason, "missing_sources": [], "missing_domains": [],
                                        "observed_at_utc": None, "stale_since_utc": None}
            payload["access"] = {**payload["access"], "allowed": False, "reason": reason}
            return payload
        columns = definition.detail.columns if detail and isinstance(definition.detail, Detail) else definition.columns
        if not detail:
            columns += tuple(column for view in definition.views if view.source == "items" for column in view.columns)
        if "items" in payload:
            payload["items"] = self._rows(payload["items"], columns, main=not detail)
        if not detail and isinstance(definition.detail, Detail) and definition.detail.inline:
            drill = definition.detail
            for row in payload.get("items", []):
                if not self.rule_decision(drill.access)["allowed"]:
                    self._remove(row, drill.inline)
                else:
                    nested = row
                    parts = drill.inline.split(".")
                    for part in parts[:-1]:
                        nested = nested.get(part, {}) if isinstance(nested, dict) else {}
                    if isinstance(nested, dict) and parts[-1] in nested:
                        nested[parts[-1]] = self._rows(nested[parts[-1]], drill.columns)
        visible_params = {p.key for p in definition.params if self.fields_allowed(p.field_categories)}
        visible_options = {p.options_from or p.key for p in definition.params if p.key in visible_params}
        payload["filter_options"] = {key: values for key, values in payload.get("filter_options", {}).items() if key in visible_options}
        payload["metrics"] = [metric for metric in payload.get("metrics", [])
                              if self.fields_allowed(definition.metric_categories.get(metric.get("key"), frozenset()))
                              and set(metric.get("filter") or {}) <= visible_params]
        payload["series"] = {key: value for key, value in payload.get("series", {}).items()
                             if self.fields_allowed(definition.series_categories.get(key, frozenset()))}
        if "collections" in payload:
            collections = {}
            for view in definition.views:
                if view.source in payload["collections"] and self.rule_decision(view.access)["allowed"]:
                    collections[view.source] = self._rows(payload["collections"][view.source], view.columns)
            payload["collections"] = collections
        return payload

    def csv(self, body: str) -> str:
        """Filter legacy exporter output as well as the UI declaration."""
        import csv
        import io

        columns = self.definition.columns
        if all(self.fields_allowed(col.field_categories) for col in columns):
            return body
        rows = csv.reader(io.StringIO(body))
        header = next(rows, [])
        # Exporters using field categories must follow the declared column
        # order. Labels alone are ambiguous and could expose a hidden column.
        if header != [col.label for col in columns]:
            raise PermissionError("report_field_categories_not_allowed")
        indices = [index for index, col in enumerate(columns) if self.fields_allowed(col.field_categories)]
        output = io.StringIO(newline="")
        writer = csv.writer(output)
        writer.writerow([header[index] for index in indices])
        for row in rows:
            writer.writerow([row[index] for index in indices])
        return output.getvalue()

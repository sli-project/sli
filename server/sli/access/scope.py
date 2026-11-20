"""Server-issued, source-neutral scopes and the legacy collection adapter."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, fields, replace
from typing import Any, Literal

DIMENSIONS = ("plugin_ids", "source_instance_ids", "device_ids", "entity_ids", "collection_scope_ids")


@dataclass(frozen=True)
class ScopeClause:
    plugin_ids: tuple[str, ...] = ()
    source_instance_ids: tuple[str, ...] = ()
    device_ids: tuple[str, ...] = ()
    entity_ids: tuple[int, ...] = ()
    collection_scope_ids: tuple[str, ...] = ()

    def __post_init__(self):
        for name in DIMENSIONS:
            values = getattr(self, name)
            if not isinstance(values, tuple) or len(values) > 100:
                raise ValueError("invalid_scope_dimension")
            if name == "entity_ids":
                valid = all(type(value) is int and value > 0 for value in values)
            else:
                valid = all(isinstance(value, str) and value.strip() == value and 0 < len(value) <= 256 for value in values)
            if not valid or len(set(values)) != len(values):
                raise ValueError("invalid_scope_dimension")
        if not any(getattr(self, name) for name in DIMENSIONS):
            raise ValueError("empty_scope_clause")

    def covers(self, other: ScopeClause) -> bool:
        return all(not getattr(self, name) or (bool(getattr(other, name)) and set(getattr(other, name)) <= set(getattr(self, name))) for name in DIMENSIONS)


@dataclass(frozen=True)
class AccessScope:
    mode: Literal["none", "restricted", "all"] = "none"
    clauses: tuple[ScopeClause, ...] = ()
    decision_id: str = "unissued"
    policy_revision: str = "unissued"

    def __post_init__(self):
        if not isinstance(self.mode, str) or self.mode not in {"none", "restricted", "all"} or not isinstance(self.clauses, tuple):
            raise ValueError("invalid_access_scope")
        if (self.mode == "restricted") != bool(self.clauses) or len(self.clauses) > 100:
            raise ValueError("invalid_access_scope")
        if not all(isinstance(clause, ScopeClause) for clause in self.clauses):
            raise ValueError("invalid_access_scope")
        if any(not isinstance(value, str) or not value.strip() or len(value) > 256 for value in (self.decision_id, self.policy_revision)):
            raise ValueError("invalid_scope_decision")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> AccessScope:
        if not isinstance(value, Mapping) or set(value) - {item.name for item in fields(cls)}:
            raise ValueError("invalid_access_scope")
        raw = value.get("clauses", [])
        if not isinstance(raw, list) or len(raw) > 100:
            raise ValueError("invalid_access_scope")
        clauses = []
        for item in raw:
            if not isinstance(item, Mapping) or set(item) - set(DIMENSIONS):
                raise ValueError("invalid_scope_clause")
            if any(not isinstance(values, list) for values in item.values()):
                raise ValueError("invalid_scope_dimension")
            clauses.append(ScopeClause(**{name: tuple(values) for name, values in item.items()}))
        return cls(value.get("mode", "none"), tuple(clauses), value.get("decision_id", "unissued"), value.get("policy_revision", "unissued"))

    def to_dict(self) -> dict[str, Any]:
        return {"mode": self.mode, "clauses": [{name: list(getattr(clause, name)) for name in DIMENSIONS} for clause in self.clauses],
                "decision_id": self.decision_id, "policy_revision": self.policy_revision}

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def allows(self, *, plugin_id=None, source_instance_id=None, device_id=None, entity_id=None, collection_scope_id=None, domain_id=None) -> bool:
        if self.mode != "restricted":
            return self.mode == "all"
        collection_scope_id = collection_scope_id or (f"ad-domain:{domain_id}" if domain_id is not None else None)
        values = (plugin_id, source_instance_id, device_id, entity_id, collection_scope_id)
        return any(all(not getattr(clause, name) or value in getattr(clause, name) for name, value in zip(DIMENSIONS, values, strict=True)) for clause in self.clauses)

    def covers(self, other: AccessScope) -> bool:
        if other.mode == "none" or self.mode == "all":
            return True
        if self.mode == "none" or other.mode == "all":
            return False
        return all(any(clause.covers(wanted) for clause in self.clauses) for wanted in other.clauses)

    def intersect(self, other: AccessScope) -> AccessScope:
        if self.mode == "none" or other.mode == "none":
            return AccessScope(decision_id=self.decision_id, policy_revision=self.policy_revision)
        if other.mode == "all":
            return self
        if self.mode == "all":
            return AccessScope(other.mode, other.clauses, self.decision_id, self.policy_revision)
        clauses = []
        for left in self.clauses:
            for right in other.clauses:
                dimensions = {}
                for name in DIMENSIONS:
                    a, b = getattr(left, name), getattr(right, name)
                    values = tuple(value for value in a if value in b) if a and b else a or b
                    if a and b and not values:
                        break
                    dimensions[name] = values
                else:
                    clause = ScopeClause(**dimensions)
                    if clause not in clauses:
                        clauses.append(clause)
        return AccessScope("restricted" if clauses else "none", tuple(clauses), self.decision_id, self.policy_revision)

    def domain_ids(self) -> list[int] | None:
        """Only a pure domain scope is executable by a legacy domain reader."""
        if self.mode == "all":
            return None
        if self.mode == "none":
            return []
        ids = set()
        for clause in self.clauses:
            if any(getattr(clause, name) for name in DIMENSIONS[:-1]) or not clause.collection_scope_ids:
                raise PermissionError("report_scope_not_executable")
            for value in clause.collection_scope_ids:
                if not re.fullmatch(r"ad-domain:[1-9][0-9]*", value):
                    raise PermissionError("report_scope_not_executable")
                ids.add(int(value.split(":", 1)[1]))
        return sorted(ids)

    def sql_predicate(self, columns: Mapping[str, str]) -> tuple[str, list[Any]]:
        """Apply BEFORE aggregation/paging; columns must be supplied by the reader."""
        if any(not re.fullmatch(r"[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*)?", column) for column in columns.values()):
            raise ValueError("invalid_scope_column")
        if self.mode != "restricted":
            return ("TRUE" if self.mode == "all" else "FALSE"), []
        clauses, params = [], []
        for clause in self.clauses:
            predicates = []
            for name in DIMENSIONS:
                values = getattr(clause, name)
                if values:
                    if name not in columns:
                        raise PermissionError("report_scope_not_executable")
                    predicates.append(f"{columns[name]} = ANY(%s)")
                    params.append(list(values))
            clauses.append("(" + " AND ".join(predicates) + ")")
        return "(" + " OR ".join(clauses) + ")", params

    def sql_filter(self, columns: Mapping[str, str]) -> tuple[str, list[Any]]:
        return self.sql_predicate(columns)


def scope_from_grant(value: Mapping[str, Any], *, decision_id: str = "unissued", policy_revision: str = "unissued") -> AccessScope:
    """Issue provenance separately from persisted grant data."""
    return replace(_grant_scope(value), decision_id=decision_id, policy_revision=policy_revision)


def _grant_scope(value: Mapping[str, Any]) -> AccessScope:
    """Adapt persisted domain grants without changing their assignments."""
    if "mode" in value:
        return AccessScope.from_dict(value)
    kind = value.get("kind")
    if kind == "all" and set(value) == {"kind"}:
        return AccessScope("all")
    if kind in {"domain", "server", "channel"}:
        key = "values" if kind == "channel" else "ids"
        raw = value.get(key)
        if set(value) != {"kind", key} or not isinstance(raw, list) or not raw or len(raw) > 100:
            raise ValueError("invalid_legacy_scope")
        if kind != "channel" and any(type(item) is not int or item <= 0 for item in raw):
            raise ValueError("invalid_legacy_scope")
        if kind == "channel" and any(not isinstance(item, str) or not item.strip() for item in raw):
            raise ValueError("invalid_legacy_scope")
        # Singleton clauses preserve union coverage for old domain assignments.
        dimension = "device_ids" if kind == "server" else "collection_scope_ids"
        prefix = "ad-domain" if kind == "domain" else kind
        return AccessScope("restricted", tuple(ScopeClause(**{dimension: (f"{prefix}:{item}",)}) for item in sorted(set(raw))))
    if value:
        raise ValueError("invalid_legacy_scope")
    return AccessScope()


def legacy_domain_ids(scope: AccessScope) -> list[int] | None:
    ids = scope.domain_ids()
    if ids == []:
        raise PermissionError("report_scope_not_executable")
    return ids

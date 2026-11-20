from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from server.sli.plugins.ad.context.contracts import record_content_sha256, validate_bundle


@dataclass
class Version:
    content_hash: str
    valid_from_utc: str
    valid_to_utc: str | None
    last_observed_at_utc: str
    payload: dict[str, Any]


@dataclass
class ContextProjection:
    """Deterministic local projection used by contract tests and dry runs."""

    entity_versions: dict[str, list[Version]] = field(default_factory=dict)
    relation_versions: dict[str, list[Version]] = field(default_factory=dict)
    applied_runs: dict[str, str] = field(default_factory=dict)
    latest_observed_at_utc: str | None = None

    def apply(self, bundle: dict[str, Any]) -> dict[str, int]:
        normalized = validate_bundle(bundle)
        run_id = normalized["run_id"]
        bundle_hash = normalized["bundle_sha256"]
        existing = self.applied_runs.get(run_id)
        if existing:
            if existing != bundle_hash:
                raise ValueError("run_id replay has a different bundle hash")
            return {"entities_changed": 0, "relations_changed": 0, "relations_closed": 0, "replayed": 1}
        if self.latest_observed_at_utc and normalized["observed_at_utc"] < self.latest_observed_at_utc:
            raise ValueError("out-of-order AD Context bundle is not allowed")
        entities = {item["record_key"]: item for item in normalized["records"] if item["record_type"] == "entity"}
        entity_changes = sum(self._observe(self.entity_versions, key, value) for key, value in entities.items())
        relation_records = [item for item in normalized["records"] if item["record_type"] == "relation"]
        for relation in relation_records:
            if relation["source_record_key"] not in entities or relation["target_record_key"] not in entities:
                raise ValueError("relation endpoints must be present in the same first-slice bundle")
        relation_changes = sum(
            self._observe(self.relation_versions, item["record_key"], item) for item in relation_records
        )
        closed = 0
        declared_sections = {item["name"]: item for item in normalized["sections"]}
        for section_name, scope_key in (
            ("privileged_membership", "privileged_group_sids"),
            ("vpn_membership", "vpn_group_sids"),
        ):
            section = declared_sections.get(section_name)
            authoritative = bool(section and section["status"] == "complete" and normalized["mode"] in {"full", "reconcile"})
            if not authoritative:
                continue
            section_relations = [item for item in relation_records if item["section"] == section_name]
            seen = {item["record_key"] for item in section_relations}
            scoped_group_sids = {value.casefold() for value in normalized["scope"].get(scope_key, [])}
            scoped_targets = {
                item["record_key"] for item in entities.values()
                if str(item["identity"].get("object_sid") or "").casefold() in scoped_group_sids
            } | {item["target_record_key"] for item in section_relations}
            for key, versions in self.relation_versions.items():
                current = versions[-1]
                if (
                    key not in seen
                    and current.valid_to_utc is None
                    and current.payload["section"] == section_name
                    and current.payload["target_record_key"] in scoped_targets
                ):
                    current.valid_to_utc = normalized["observed_at_utc"]
                    closed += 1
        self.applied_runs[run_id] = bundle_hash
        self.latest_observed_at_utc = normalized["observed_at_utc"]
        return {
            "entities_changed": entity_changes,
            "relations_changed": relation_changes,
            "relations_closed": closed,
            "replayed": 0,
        }

    @staticmethod
    def _observe(store: dict[str, list[Version]], key: str, payload: dict[str, Any]) -> int:
        observed_at = payload["observed_at_utc"]
        content_hash = record_content_sha256(payload)
        versions = store.setdefault(key, [])
        if versions and versions[-1].valid_to_utc is None and versions[-1].content_hash == content_hash:
            versions[-1].last_observed_at_utc = observed_at
            return 0
        if versions and versions[-1].valid_to_utc is None:
            versions[-1].valid_to_utc = observed_at
        versions.append(
            Version(
                content_hash=content_hash,
                valid_from_utc=observed_at,
                valid_to_utc=None,
                last_observed_at_utc=observed_at,
                payload=payload,
            )
        )
        return 1

"""Dormant PostgreSQL registry adapter; no admission, connections or commits.

Importers supply already verified raw/canonical rules and attribution. The
database computes content hashes, enforces immutable keys and authorizes the
session login against an administrator-provisioned exact scope. A scope object
is a query boundary, never a replacement for that database authorization.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID


class RegistryError(RuntimeError):
    """Fixed diagnostics only; database errors may contain imported values."""


@dataclass(frozen=True, repr=False)
class RegistryScope:
    installation_id: str
    plugin_id: str
    source_instance_id: str

    def __post_init__(self):
        try:
            valid = str(UUID(self.installation_id)) == self.installation_id
        except (ValueError, TypeError, AttributeError):
            valid = False
        if (not valid or not isinstance(self.plugin_id, str) or not 1 <= len(self.plugin_id) <= 128
                or not isinstance(self.source_instance_id, str) or not 1 <= len(self.source_instance_id) <= 256):
            raise RegistryError("sigma_registry_scope_invalid")

    @property
    def params(self):
        return (self.installation_id, self.plugin_id, self.source_instance_id)


def _json(value):
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False, separators=(",", ":"))
    except (TypeError, ValueError, RecursionError):
        raise RegistryError("sigma_registry_document_invalid") from None


def _query(cursor, sql, params):
    try:
        cursor.execute(sql, params)
        return cursor.fetchone()
    except Exception:
        # Preserve the caller's failed transaction; never reconnect as an owner
        # or retry outside the scope. The caller owns rollback on failure.
        raise RegistryError("sigma_registry_query_failed") from None


def register_revision(cursor, scope: RegistryScope, *, raw_yaml: bytes, canonical_rule: dict,
                      upstream_commit: str, status: str, level: str, tags: list[str],
                      author: str, license_id: str, source_uri: str, requirements: dict):
    """Atomically insert a revision and requirements; duplicate keys are errors.

    A failed statement rolls back both inserts. Existing revisions are never
    updated, even if only attribution or requirements differ. Returned hashes
    use the database's JSONB canonicalization, independent of compiler versions.
    """
    try:
        if not isinstance(raw_yaml, bytes) or not 0 < len(raw_yaml) <= 1048576:
            raise ValueError
        raw_text = raw_yaml.decode("utf-8")
        if not isinstance(canonical_rule, dict) or not isinstance(requirements, dict):
            raise ValueError
        rule_id = str(UUID(canonical_rule["id"]))
        if rule_id != canonical_rule["id"]:
            raise ValueError
    except (UnicodeError, ValueError, TypeError, KeyError, AttributeError):
        raise RegistryError("sigma_registry_document_invalid") from None
    return _query(cursor, """
        with revision as (
            insert into sli_sigma.sigma_rule_revisions
                (installation_id,plugin_id,source_instance_id,rule_id,raw_yaml,canonical_rule,
                 upstream_commit,status,level,tags,author,license,source_uri)
            values (%s,%s,%s,%s,%s,%s::jsonb,%s,%s,%s,%s::jsonb,%s,%s,%s)
            returning installation_id,plugin_id,source_instance_id,rule_id,raw_sha256,canonical_sha256
        ), requirements as (
            insert into sli_sigma.sigma_source_requirements
                (installation_id,plugin_id,source_instance_id,rule_id,raw_sha256,requirements)
            select installation_id,plugin_id,source_instance_id,rule_id,raw_sha256,%s::jsonb from revision
            returning requirements_sha256
        )
        select revision.raw_sha256,revision.canonical_sha256,requirements.requirements_sha256
        from revision cross join requirements
    """, (*scope.params, rule_id, raw_text, _json(canonical_rule), upstream_commit,
          status, level, _json(tags), author, license_id, source_uri, _json(requirements)))


def register_overlay(cursor, scope: RegistryScope, *, overlay_id: str, version: int,
                     rule_id: str, base_raw_sha256: str, base_canonical_sha256: str,
                     mapping_version: str, predicate: dict, reason: str, expires_at: datetime):
    """Append a version pinned to an existing revision in the same exact scope.

    Storage does not apply a predicate or activate an exception. Incompatible
    bases are never silently rebound to another revision.
    """
    if (type(version) is not int or version < 1 or not isinstance(predicate, dict)
            or not isinstance(expires_at, datetime) or expires_at.utcoffset() is None):
        raise RegistryError("sigma_registry_overlay_invalid")
    return _query(cursor, """
        insert into sli_sigma.sigma_rule_overlays
            (installation_id,plugin_id,source_instance_id,overlay_id,version,rule_id,
             base_raw_sha256,base_canonical_sha256,mapping_version,predicate,reason,expires_at)
        values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s)
        returning overlay_sha256
    """, (*scope.params, overlay_id, version, rule_id, base_raw_sha256, base_canonical_sha256,
          mapping_version, _json(predicate), reason, expires_at.astimezone(timezone.utc)))


def read_revision(cursor, scope: RegistryScope, rule_id: str, raw_sha256: str):
    """Read the retained revision, attribution and requirements, or return None."""
    return _query(cursor, """
        select r.*,q.requirements,q.requirements_sha256
        from sli_sigma.sigma_rule_revisions r
        join sli_sigma.sigma_source_requirements q
          using (installation_id,plugin_id,source_instance_id,rule_id,raw_sha256)
        where r.installation_id=%s and r.plugin_id=%s and r.source_instance_id=%s
          and r.rule_id=%s and r.raw_sha256=%s
    """, (*scope.params, rule_id, raw_sha256))


def read_overlay(cursor, scope: RegistryScope, overlay_id: str, version: int):
    """Read an exact historical version, including expired overlays."""
    return _query(cursor, """
        select * from sli_sigma.sigma_rule_overlays
        where installation_id=%s and plugin_id=%s and source_instance_id=%s
          and overlay_id=%s and version=%s
    """, (*scope.params, overlay_id, version))

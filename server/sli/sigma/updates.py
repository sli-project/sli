"""Offline Sigma candidates and rollback pins, without runtime admission.

The caller supplies a scope-authorized mapping-row cursor and owns the registry
transaction. Package verification precedes every insert. Persist the returned
manifest only after committing that transaction; failures require rollback.
Manifests reference retained registry rows, never rewrite history/results or
touch source cursors. Their hashes are evaluation namespaces, not signatures.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import date, datetime
from pathlib import Path
from uuid import UUID

import yaml

from server.sli.sigma import registry
from server.sli.sigma.compiler import COMPILER_VERSION, _BoundedLoader, compile_rule
from server.sli.sigma.windows_mapping import MAPPING_VERSION

MANIFEST_VERSION = "sli.sigma.manifest.v1"
MAX_MANIFEST_BYTES = 1024 * 1024
_EDITORIAL = frozenset({"title", "description", "author", "date", "modified", "references",
                        "tags", "falsepositives", "level", "license"})


class UpdateError(ValueError):
    """Fixed diagnostics; imported rules and database errors may be private."""


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _hash(value):
    return hashlib.sha256(_json(value).encode()).hexdigest()


def _sha(value):
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) is not None


def _uuid(value):
    return isinstance(value, str) and str(UUID(value)) == value


@dataclass(frozen=True, repr=False)
class OverlayPin:
    overlay_id: str
    version: int
    sha256: str
    compiler_version: str = COMPILER_VERSION

    def __post_init__(self):
        try:
            valid = (_uuid(self.overlay_id) and type(self.version) is int and self.version > 0 and _sha(self.sha256)
                     and isinstance(self.compiler_version, str) and 1 <= len(self.compiler_version) <= 128)
        except ValueError:
            valid = False
        if not valid:
            raise UpdateError("sigma_update_overlay_pin_invalid")


@dataclass(frozen=True, repr=False)
class RulePin:
    rule_id: str
    raw_sha256: str
    canonical_sha256: str
    requirements_sha256: str
    upstream_commit: str
    overlays: tuple[OverlayPin, ...] = ()

    def __post_init__(self):
        try:
            valid = (_uuid(self.rule_id) and all(_sha(v) for v in (
                self.raw_sha256, self.canonical_sha256, self.requirements_sha256))
                and isinstance(self.upstream_commit, str)
                and re.fullmatch(r"[a-f0-9]{40}", self.upstream_commit)
                and type(self.overlays) is tuple and len(self.overlays) <= 32
                and all(isinstance(v, OverlayPin) for v in self.overlays)
                and len({v.overlay_id for v in self.overlays}) == len(self.overlays))
        except ValueError:
            valid = False
        if not valid:
            raise UpdateError("sigma_update_rule_pin_invalid")


@dataclass(frozen=True, repr=False)
class Manifest:
    scope: registry.RegistryScope
    rules: tuple[RulePin, ...]
    retired: tuple[RulePin, ...] = ()
    compiler_version: str = COMPILER_VERSION
    mapping_version: str = MAPPING_VERSION
    package_sha256: str | None = None
    upstream_commit: str | None = None

    def __post_init__(self):
        if (not isinstance(self.scope, registry.RegistryScope)
                or type(self.rules) is not tuple or type(self.retired) is not tuple
                or len(self.rules) > 25 or len(self.retired) > 256
                or any(not isinstance(pin, RulePin) for pin in self.rules + self.retired)
                or len({pin.rule_id for pin in self.rules + self.retired}) != len(self.rules + self.retired)
                or any(not isinstance(v, str) or not 1 <= len(v) <= 128
                       for v in (self.compiler_version, self.mapping_version))
                or ((self.package_sha256 is None) != (self.upstream_commit is None))
                or (self.package_sha256 is not None and (
                    not _sha(self.package_sha256) or not isinstance(self.upstream_commit, str)
                    or not re.fullmatch(r"[a-f0-9]{40}", self.upstream_commit)))):
            raise UpdateError("sigma_update_manifest_invalid")
        # Stable serialization regardless of package delivery order.
        for name in ("rules", "retired"):
            pins = tuple(sorted(getattr(self, name), key=lambda p: p.rule_id))
            if any(tuple(sorted(p.overlays, key=lambda o: o.overlay_id)) != p.overlays for p in pins):
                raise UpdateError("sigma_update_overlay_order_invalid")
            object.__setattr__(self, name, pins)

    def document(self):
        return {"version": MANIFEST_VERSION, **asdict(self)}

    @property
    def sha256(self):
        return _hash(self.document())


@dataclass(frozen=True)
class Change:
    rule_id: str
    kind: str
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True, repr=False)
class UpdatePlan:
    candidate: Manifest
    rollback: Manifest
    changes: tuple[Change, ...]

    @property
    def blocked(self):
        return any(change.reasons for change in self.changes)

    def candidate_manifest(self):
        if self.blocked:
            raise UpdateError("sigma_update_candidate_blocked")
        return self.candidate

    def document(self):
        return {"version": "sli.sigma.update.v1", "blocked": self.blocked,
                "candidate_sha256": self.candidate.sha256, "candidate": self.candidate.document(),
                "rollback_sha256": self.rollback.sha256, "rollback": self.rollback.document(),
                "changes": [asdict(change) for change in self.changes]}


def _revision(cursor, scope, pin):
    row = registry.read_revision(cursor, scope, pin.rule_id, pin.raw_sha256)
    if (not isinstance(row, dict) or not _same_scope(row, scope)
            or str(row.get("rule_id")) != pin.rule_id or row.get("raw_sha256") != pin.raw_sha256
            or row.get("canonical_sha256") != pin.canonical_sha256
            or row.get("requirements_sha256") != pin.requirements_sha256
            or row.get("upstream_commit") != pin.upstream_commit
            or not isinstance(row.get("canonical_rule"), dict) or not isinstance(row.get("requirements"), dict)):
        raise UpdateError("sigma_update_revision_unavailable")
    return row


def _same_scope(row, scope):
    return tuple(str(row.get(name)) for name in ("installation_id", "plugin_id", "source_instance_id")) == scope.params


def _meaning(row):
    return {key: value for key, value in row["canonical_rule"].items() if key not in _EDITORIAL}


def _overlay_conflicts(cursor, scope, pin, revision, mapping_version, compiler_version):
    reasons = set()
    for overlay in pin.overlays:
        row = registry.read_overlay(cursor, scope, overlay.overlay_id, overlay.version)
        if (not isinstance(row, dict) or not _same_scope(row, scope)
                or str(row.get("rule_id")) != pin.rule_id or str(row.get("overlay_id")) != overlay.overlay_id
                or row.get("version") != overlay.version or row.get("overlay_sha256") != overlay.sha256):
            raise UpdateError("sigma_update_overlay_unavailable")
        # A compatible update keeps the original immutable overlay, including
        # predicate/reason/expiry. Its original base remains independently readable.
        base = registry.read_revision(cursor, scope, pin.rule_id, row["base_raw_sha256"])
        if (not isinstance(base, dict) or not _same_scope(base, scope)
                or str(base.get("rule_id")) != pin.rule_id or base.get("raw_sha256") != row["base_raw_sha256"]
                or base.get("canonical_sha256") != row["base_canonical_sha256"]):
            raise UpdateError("sigma_update_overlay_base_unavailable")
        if row["mapping_version"] != mapping_version:
            reasons.add("overlay_mapping_changed")
        if overlay.compiler_version != compiler_version:
            reasons.add("overlay_compiler_changed")
        if _json(_meaning(base)) != _json(_meaning(revision)):
            reasons.add("overlay_base_changed")
        if _json(base["requirements"]) != _json(revision["requirements"]):
            reasons.add("overlay_requirements_changed")
        fields = revision["requirements"].get("required_fields", [])
        if any(term["field"] not in fields for term in row["predicate"]["all_of"]):
            reasons.add("overlay_field_unavailable")
    return tuple(sorted(reasons))


def validate_manifest(cursor, scope: registry.RegistryScope, manifest: Manifest):
    """Resolve all historical pins in the exact scope, including retired rules."""
    if manifest.scope != scope:
        raise UpdateError("sigma_update_scope_mismatch")
    for pin in manifest.rules + manifest.retired:
        row = _revision(cursor, scope, pin)
        conflicts = _overlay_conflicts(cursor, scope, pin, row, manifest.mapping_version, manifest.compiler_version)
        if pin in manifest.rules and (conflicts or row.get("status") in ("deprecated", "unsupported")):
            raise UpdateError("sigma_update_manifest_incompatible")
    return manifest


def prepare_update(cursor, scope: registry.RegistryScope, previous: Manifest,
                   revisions: tuple[RulePin, ...], *, compiler_version=COMPILER_VERSION,
                   mapping_version=MAPPING_VERSION, package_sha256=None, upstream_commit=None) -> UpdatePlan:
    """Three-way comparison of registered bases/overlays; SELECT-only planning.

    A blocked candidate is diagnostic data only. The complete previous manifest
    remains the rollback target; no current manifest or results are mutated.
    """
    validate_manifest(cursor, scope, previous)
    # Incoming revisions cannot supply or silently replace local exceptions.
    if type(revisions) is not tuple or any(not isinstance(p, RulePin) or p.overlays for p in revisions):
        raise UpdateError("sigma_update_package_pins_invalid")
    Manifest(scope, revisions, compiler_version=compiler_version, mapping_version=mapping_version)
    old = {p.rule_id: p for p in previous.rules + previous.retired}
    incoming = {p.rule_id: p for p in revisions}
    changes, pins = [], []
    for rule_id, new in sorted(incoming.items()):
        row = _revision(cursor, scope, new)
        prior = old.get(rule_id)
        pin = RulePin(new.rule_id, new.raw_sha256, new.canonical_sha256, new.requirements_sha256,
                      new.upstream_commit, prior.overlays if prior else ())
        reasons = set(_overlay_conflicts(cursor, scope, pin, row, mapping_version, compiler_version))
        if row.get("status") in ("deprecated", "unsupported"):
            reasons.add("rule_not_supported")
        kind = "added" if prior is None else ("unchanged" if prior == pin else "changed")
        if prior in previous.retired:
            kind = "restored"
        changes.append(Change(rule_id, kind, tuple(sorted(reasons))))
        pins.append(pin)
    retired = tuple(p for p in previous.rules + previous.retired if p.rule_id not in incoming)
    changes.extend(Change(p.rule_id, "retired") for p in previous.rules if p.rule_id not in incoming)
    candidate = Manifest(scope, tuple(pins), retired, compiler_version, mapping_version,
                         package_sha256, upstream_commit)
    return UpdatePlan(candidate, previous, tuple(sorted(changes, key=lambda c: c.rule_id)))


def rollback_manifest(cursor, scope: registry.RegistryScope, target: Manifest) -> Manifest:
    """Return the exact retained rule/mapping/overlay triple, without a replay."""
    return validate_manifest(cursor, scope, target)


def _dates(value):
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    if isinstance(value, dict):
        return {key: _dates(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_dates(item) for item in value]
    return value


def prepare_offline_update(cursor, scope: registry.RegistryScope, previous: Manifest,
                           archive: Path, config: Path) -> UpdatePlan:
    """Verify a reviewed offline lock/package, append revisions, prepare TEST pins.

    The lock/config is operator-trusted input, never extracted from the archive.
    There is no network, package execution, connection, commit or admission here.
    The unchanged stage-01 verifier limits each reviewed selection to 25 rules.
    """
    from scripts.dev.verify_sigma_package import load_config, verify_package

    try:
        lock, _ = load_config(config)
        verified = verify_package(archive, config)
        documents = []
        for rule in verified:
            plan = compile_rule(rule.raw_yaml, source_uri=rule.source_uri,
                                upstream_commit=rule.upstream_commit, license_id=rule.license)
            document = _dates(yaml.load(rule.raw_yaml, Loader=_BoundedLoader))
            documents.append((rule, document, {"logsource": plan.logsource,
                                              "required_fields": list(plan.required_fields)}))
    except Exception:
        raise UpdateError("sigma_update_package_invalid") from None
    validate_manifest(cursor, scope, previous)
    pins = []
    for rule, document, requirements in documents:
        raw_hash = hashlib.sha256(rule.raw_yaml).hexdigest()
        row = registry.read_revision(cursor, scope, rule.id, raw_hash)
        if row is None:
            hashes = registry.register_revision(
                cursor, scope, raw_yaml=rule.raw_yaml, canonical_rule=document,
                upstream_commit=rule.upstream_commit, status=document.get("status", "test"),
                level=document.get("level", "informational"), tags=document.get("tags", []),
                author=rule.author, license_id=rule.license, source_uri=rule.source_uri,
                requirements=requirements)
            if not isinstance(hashes, dict) or hashes.get("raw_sha256") != raw_hash:
                raise UpdateError("sigma_update_import_failed")
            canonical_hash, requirements_hash = hashes["canonical_sha256"], hashes["requirements_sha256"]
            commit = rule.upstream_commit
        else:
            # Identical bytes can occur in several upstream commits. The registry
            # retains first-import attribution; never overwrite it on reimport.
            if (not _same_scope(row, scope) or str(row.get("rule_id")) != rule.id
                    or row.get("raw_sha256") != raw_hash or row.get("canonical_rule") != document
                    or row.get("requirements") != requirements):
                raise UpdateError("sigma_update_existing_revision_mismatch")
            canonical_hash, requirements_hash = row["canonical_sha256"], row["requirements_sha256"]
            commit = row["upstream_commit"]
        pins.append(RulePin(rule.id, raw_hash, canonical_hash, requirements_hash, commit))
    return prepare_update(cursor, scope, previous, tuple(pins),
                          package_sha256=lock["upstream"]["archive"]["sha256"],
                          upstream_commit=lock["upstream"]["commit"])


def read_manifest(path: Path, expected_sha256: str) -> Manifest:
    """Read a separately pinned local manifest; hashes are integrity, not trust."""
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_MANIFEST_BYTES + 1)
        document = json.loads(raw)
        if len(raw) > MAX_MANIFEST_BYTES or document.pop("version") != MANIFEST_VERSION:
            raise ValueError
        scope = registry.RegistryScope(**document.pop("scope"))
        for key in ("rules", "retired"):
            document[key] = tuple(RulePin(**{**pin, "overlays": tuple(OverlayPin(**o) for o in pin["overlays"])})
                                  for pin in document[key])
        result = Manifest(scope=scope, **document)
        if not _sha(expected_sha256) or result.sha256 != expected_sha256:
            raise ValueError
        return result
    except Exception:
        raise UpdateError("sigma_update_manifest_invalid") from None

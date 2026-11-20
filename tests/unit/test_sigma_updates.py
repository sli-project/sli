"""Offline update contracts with synthetic packages and a scope-bound fake DB."""
from __future__ import annotations

import copy
import hashlib
import json
import shutil
from dataclasses import FrozenInstanceError, asdict, replace
from datetime import datetime, timezone
from uuid import UUID
from zipfile import ZipFile

import pytest
import yaml

from scripts.dev import verify_sigma_package as packages
from server.sli.sigma import registry, updates

SCOPE = registry.RegistryScope(str(UUID(int=1)), "synthetic.plugin", "synthetic-source")
RULE = str(UUID(int=2))
OVERLAY = str(UUID(int=3))


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def json_hash(document):
    # Simulates storage-returned hashes, not PostgreSQL JSONB canonicalization.
    return digest(json.dumps(document, sort_keys=True).encode())


class Cursor:
    def __init__(self):
        self.revisions = {}
        self.overlays = {}
        self.calls = []
        self.row = None
        self.denied = False

    def execute(self, sql, params):
        self.calls.append((sql, params))
        if self.denied:
            raise RuntimeError("synthetic private database diagnostic")
        if "with revision as" in sql:
            (installation, plugin, source, rule_id, raw, canonical, commit, status,
             level, tags, author, license_id, uri, requirements) = params
            row = dict(installation_id=installation, plugin_id=plugin, source_instance_id=source,
                       rule_id=rule_id, raw_yaml=raw, canonical_rule=json.loads(canonical),
                       requirements=json.loads(requirements), upstream_commit=commit, status=status,
                       level=level, tags=json.loads(tags), author=author, license=license_id, source_uri=uri)
            row.update(raw_sha256=digest(raw.encode()), canonical_sha256=json_hash(row["canonical_rule"]),
                       requirements_sha256=json_hash(row["requirements"]))
            key = (*params[:3], rule_id, row["raw_sha256"])
            assert key not in self.revisions, "Immutable revisions cannot be replaced"
            self.revisions[key] = row
            self.row = {key: row[key] for key in ("raw_sha256", "canonical_sha256", "requirements_sha256")}
        elif "from sli_sigma.sigma_rule_revisions" in sql:
            self.row = copy.deepcopy(self.revisions.get(params))
        elif "from sli_sigma.sigma_rule_overlays" in sql:
            self.row = copy.deepcopy(self.overlays.get(params))
        else:
            raise AssertionError("Unexpected SQL: no runtime or production writer allowed")

    def fetchone(self):
        return self.row

    @property
    def writes(self):
        return [call for call in self.calls if "insert into" in call[0]]


def document(rule_id=RULE, **extra):
    return dict(id=rule_id, title="Synthetic rule", author="Fixture Team", status="test", level="low",
                logsource={"product": "windows", "service": "security"},
                detection={"selection": {"EventID": 1}, "condition": "selection"}, **extra)


def add_revision(cursor, doc=None, *, requirements=None, commit="a" * 40):
    doc = doc or document()
    hashes = registry.register_revision(
        cursor, SCOPE, raw_yaml=yaml.safe_dump(doc).encode(), canonical_rule=doc,
        upstream_commit=commit, status=doc["status"], level=doc["level"], tags=[],
        author="Fixture Team", license_id="DRL-1.1", source_uri="urn:synthetic:sigma",
        requirements=requirements or {"logsource": "security", "required_fields": ["EventID"]})
    return updates.RulePin(doc["id"], hashes["raw_sha256"], hashes["canonical_sha256"],
                           hashes["requirements_sha256"], commit)


def add_overlay(cursor, pin):
    row = dict(**asdict(SCOPE), overlay_id=OVERLAY, version=1, rule_id=pin.rule_id,
               base_raw_sha256=pin.raw_sha256, base_canonical_sha256=pin.canonical_sha256,
               mapping_version=updates.MAPPING_VERSION,
               predicate={"version": "sli.sigma.overlay.v1", "all_of": [{"field": "EventID", "equals": 1}]},
               reason="Synthetic narrow exception", expires_at="2100-01-01T00:00:00Z")
    row["overlay_sha256"] = json_hash(row)
    row["expires_at"] = datetime(2100, 1, 1, tzinfo=timezone.utc)
    cursor.overlays[(*SCOPE.params, OVERLAY, 1)] = row
    return replace(pin, overlays=(updates.OverlayPin(OVERLAY, 1, row["overlay_sha256"]),))


@pytest.fixture
def previous():
    cursor = Cursor()
    pin = add_overlay(cursor, add_revision(cursor))
    manifest = updates.Manifest(SCOPE, (pin,))
    cursor.calls.clear()
    return cursor, manifest


def test_compatible_update_preserves_exact_exception_and_all_historical_rows(previous):
    cursor, old = previous
    before = copy.deepcopy((cursor.revisions, cursor.overlays, old.document()))
    doc = document()
    doc["title"] = "Synthetic revised title"
    new = add_revision(cursor, doc, commit="b" * 40)
    cursor.calls.clear()
    plan = updates.prepare_update(cursor, SCOPE, old, (new,))
    candidate = plan.candidate_manifest()
    assert not plan.blocked and plan.changes == (updates.Change(RULE, "changed"),)
    assert candidate.rules[0].overlays == old.rules[0].overlays
    assert candidate.sha256 != old.sha256
    assert updates.validate_manifest(cursor, SCOPE, candidate) == candidate
    assert updates.rollback_manifest(cursor, SCOPE, plan.rollback) is old
    assert (cursor.overlays, old.document()) == before[1:]
    for key, row in before[0].items():
        assert cursor.revisions[key] == row
    assert not cursor.writes


@pytest.mark.parametrize("change,reason", [
    ("detection", "overlay_base_changed"), ("logsource", "overlay_base_changed"),
    ("unknown_semantics", "overlay_base_changed"), ("requirements", "overlay_requirements_changed"),
    ("field", "overlay_field_unavailable"), ("mapping", "overlay_mapping_changed"),
    ("compiler", "overlay_compiler_changed"),
])
def test_three_way_conflict_blocks_candidate_and_keeps_rollback(previous, change, reason):
    cursor, old = previous
    doc = document()
    requirements = {"logsource": "security", "required_fields": ["EventID"]}
    options = {}
    if change == "detection":
        doc["detection"]["selection"]["EventID"] = 2
    elif change == "logsource":
        doc["logsource"]["service"] = "system"
    elif change == "unknown_semantics":
        doc["future_semantics"] = "synthetic"
    elif change == "requirements":
        doc["title"] = "Synthetic requirements revision"
        requirements["audit_required"] = True
    elif change == "field":
        doc["title"] = "Synthetic fields revision"
        requirements["required_fields"] = ["Status"]
    elif change == "mapping":
        options["mapping_version"] = "synthetic.mapping.v2"
    else:
        options["compiler_version"] = "synthetic.compiler.v2"
    new = add_revision(cursor, doc, requirements=requirements, commit="b" * 40) if change not in (
        "mapping", "compiler") else replace(old.rules[0], overlays=())
    plan = updates.prepare_update(cursor, SCOPE, old, (new,), **options)
    assert plan.blocked and reason in plan.changes[0].reasons
    assert plan.candidate.rules[0].overlays == old.rules[0].overlays
    with pytest.raises(updates.UpdateError, match="^sigma_update_candidate_blocked$"):
        plan.candidate_manifest()
    with pytest.raises(updates.UpdateError, match="^sigma_update_manifest_incompatible$"):
        updates.validate_manifest(cursor, SCOPE, plan.candidate)
    assert updates.rollback_manifest(cursor, SCOPE, plan.rollback).sha256 == old.sha256
    assert plan.document()["blocked"] is True


def test_removed_rule_and_old_result_remain_explainable_and_readdition_keeps_overlay(previous):
    cursor, old = previous
    result = {"manifest_sha256": old.sha256, "rule": asdict(old.rules[0]), "matched": 1}
    before = copy.deepcopy(result)
    plan = updates.prepare_update(cursor, SCOPE, old, ())
    retired = plan.candidate_manifest()
    assert retired.rules == () and retired.retired == old.rules
    assert plan.changes == (updates.Change(RULE, "retired"),)
    assert updates.validate_manifest(cursor, SCOPE, retired) == retired
    row = registry.read_revision(cursor, SCOPE, RULE, old.rules[0].raw_sha256)
    assert row["author"] == "Fixture Team" and row["license"] == "DRL-1.1"
    assert row["source_uri"] == "urn:synthetic:sigma"
    restored = updates.prepare_update(cursor, SCOPE, retired, (replace(old.rules[0], overlays=()),))
    assert restored.candidate_manifest().rules == old.rules
    assert restored.changes == (updates.Change(RULE, "restored"),)
    assert result == before and not cursor.writes


def test_manifest_hash_is_deterministic_and_round_trips_exact_rollback(previous, tmp_path):
    cursor, old = previous
    other = add_revision(cursor, document(str(UUID(int=4))))
    first = updates.prepare_update(cursor, SCOPE, old, (other, replace(old.rules[0], overlays=())))
    second = updates.prepare_update(cursor, SCOPE, old, (replace(old.rules[0], overlays=()), other))
    assert first.document() == second.document()
    path = tmp_path / "rollback.json"
    path.write_text(json.dumps(first.document()["rollback"]), encoding="utf-8")
    loaded = updates.read_manifest(path, first.rollback.sha256)
    assert updates.rollback_manifest(cursor, SCOPE, loaded).document() == old.document()
    with pytest.raises(FrozenInstanceError):
        loaded.mapping_version = "synthetic.mapping.v2"
    assert SCOPE.source_instance_id not in repr(loaded)


@pytest.mark.parametrize("change", ["hash", "version", "scope", "overlay", "oversize", "json"])
def test_invalid_saved_manifest_is_rejected(previous, tmp_path, change):
    _, old = previous
    doc = old.document()
    expected = old.sha256
    if change == "hash":
        expected = "f" * 64
    elif change == "version":
        doc["version"] = "unsupported"
    elif change == "scope":
        doc["scope"]["source_instance_id"] = "another-source"
    elif change == "overlay":
        doc["rules"][0]["overlays"][0]["version"] = True
    raw = json.dumps(doc)
    if change == "oversize":
        raw += " " * updates.MAX_MANIFEST_BYTES
    elif change == "json":
        raw = "{"
    path = tmp_path / "manifest.json"
    path.write_text(raw, encoding="utf-8")
    with pytest.raises(updates.UpdateError, match="^sigma_update_manifest_invalid$"):
        updates.read_manifest(path, expected)


def test_cross_scope_never_queries_registry(previous):
    cursor, old = previous
    foreign = replace(SCOPE, source_instance_id="another-source")
    for action in (lambda: updates.prepare_update(cursor, foreign, old, ()),
                   lambda: updates.rollback_manifest(cursor, foreign, old)):
        with pytest.raises(updates.UpdateError, match="^sigma_update_scope_mismatch$"):
            action()
    assert cursor.calls == []


@pytest.mark.parametrize("missing", ["revision", "overlay", "base"])
def test_missing_historical_references_fail_closed(previous, missing):
    cursor, old = previous
    if missing == "overlay":
        cursor.overlays.clear()
    elif missing == "base":
        row = next(iter(cursor.overlays.values()))
        row["base_raw_sha256"] = "f" * 64
    else:
        cursor.revisions.clear()
    with pytest.raises(updates.UpdateError, match="^sigma_update_.*unavailable$"):
        updates.rollback_manifest(cursor, SCOPE, old)
    assert not cursor.writes


def test_permission_denial_stays_sanitized_and_never_retries(previous):
    cursor, old = previous
    cursor.denied = True
    with pytest.raises(registry.RegistryError, match="^sigma_registry_query_failed$") as error:
        updates.prepare_update(cursor, SCOPE, old, ())
    assert len(cursor.calls) == 1 and error.value.__suppress_context__
    assert "private" not in str(error.value) and not cursor.writes


def test_imported_pins_cannot_replace_local_overlay_or_duplicate_uuid(previous):
    cursor, old = previous
    with pytest.raises(updates.UpdateError, match="^sigma_update_package_pins_invalid$"):
        updates.prepare_update(cursor, SCOPE, old, old.rules)
    pin = replace(old.rules[0], overlays=())
    with pytest.raises(updates.UpdateError, match="^sigma_update_manifest_invalid$"):
        updates.prepare_update(cursor, SCOPE, old, (pin, pin))


@pytest.mark.parametrize("status", ["deprecated", "unsupported"])
def test_upstream_retirement_status_blocks_candidate_and_keeps_old_revision(previous, status):
    cursor, old = previous
    doc = document()
    doc["status"] = status
    new = add_revision(cursor, doc)
    plan = updates.prepare_update(cursor, SCOPE, old, (new,))
    assert plan.blocked and "rule_not_supported" in plan.changes[0].reasons
    assert updates.rollback_manifest(cursor, SCOPE, old) == old
    with pytest.raises(updates.UpdateError, match="^sigma_update_manifest_incompatible$"):
        updates.validate_manifest(cursor, SCOPE, plan.candidate)


@pytest.fixture
def offline_package(tmp_path):
    pytest.importorskip("sigma.rule", reason="Requires isolated Sigma parser dependencies")
    config = tmp_path / "config"
    shutil.copytree(packages.CONFIG, config)
    lock, profile = packages.load_config(config)
    root = lock["upstream"]["archive"]["root"]
    members = {f"{root}/LICENSE": b"Synthetic license notice"}
    lock["upstream"]["license"]["sha256"] = digest(members[f"{root}/LICENSE"])
    for index, entry in enumerate(lock["rules"]):
        rule_id = str(UUID(int=index + 100))
        entry["id"] = profile["rules"][index]["id"] = rule_id
        members[f"{root}/{entry['path']}"] = yaml.safe_dump(document(rule_id)).encode()
    archive = tmp_path / "rules.zip"

    def save():
        commit = lock["upstream"]["commit"]
        profile["upstream_commit"] = commit
        for entry in lock["rules"]:
            entry["sha256"] = digest(members[f"{root}/{entry['path']}"])
            entry["source_uri"] = f"{lock['upstream']['repository']}/blob/{commit}/{entry['path']}"
        profile_raw = json.dumps(profile).encode()
        (config / lock["profile"]["path"]).write_bytes(profile_raw)
        lock["profile"]["sha256"] = digest(profile_raw)
        with ZipFile(archive, "w") as zipped:
            for name, raw in members.items():
                zipped.writestr(name, raw)
        lock["upstream"]["archive"]["sha256"] = digest(archive.read_bytes())
        (config / "lock.json").write_text(json.dumps(lock), encoding="utf-8")

    save()
    return archive, config, lock, profile, members, save


def test_verified_offline_update_imports_25_preserves_exception_retires_rule_and_rolls_back(offline_package, tmp_path):
    archive, config, lock, profile, members, save = offline_package
    cursor = Cursor()
    initial = updates.prepare_offline_update(cursor, SCOPE, updates.Manifest(SCOPE, ()), archive, config)
    old = initial.candidate_manifest()
    assert len(old.rules) == 25 and len(cursor.writes) == 25
    assert old.package_sha256 == digest(archive.read_bytes())
    assert old.upstream_commit == lock["upstream"]["commit"]
    old = replace(old, rules=(add_overlay(cursor, old.rules[0]), *old.rules[1:]))
    first = lock["rules"][0]
    name = f"{lock['upstream']['archive']['root']}/{first['path']}"
    members[name] = members[name].replace(b"Synthetic rule", b"Synthetic updated title")
    removed = old.rules[-1]
    new_id = str(UUID(int=200))
    lock["rules"][-1]["id"] = profile["rules"][-1]["id"] = new_id
    name = f"{lock['upstream']['archive']['root']}/{lock['rules'][-1]['path']}"
    members[name] = yaml.safe_dump(document(new_id)).encode()
    lock["upstream"]["commit"] = "b" * 40
    save()
    cursor.calls.clear()
    plan = updates.prepare_offline_update(cursor, SCOPE, old, archive, config)
    candidate = plan.candidate_manifest()
    assert len(cursor.writes) == 2 and len(candidate.rules) == 25
    assert candidate.rules[0].overlays == old.rules[0].overlays
    assert candidate.retired == (removed,)
    assert candidate.upstream_commit == "b" * 40
    assert candidate.package_sha256 == digest(archive.read_bytes())
    path = tmp_path / "rollback.json"
    path.write_text(json.dumps(plan.document()["rollback"]), encoding="utf-8")
    assert updates.rollback_manifest(cursor, SCOPE, updates.read_manifest(path, old.sha256)) == old
    assert registry.read_revision(cursor, SCOPE, removed.rule_id, removed.raw_sha256)["author"] == "Fixture Team"
    cursor.calls.clear()
    repeated = updates.prepare_offline_update(cursor, SCOPE, candidate, archive, config)
    assert repeated.candidate_manifest().sha256 == candidate.sha256
    assert not cursor.writes


@pytest.mark.parametrize("failure", ["hash", "compile"])
def test_package_or_compiler_failure_precedes_all_registry_access(offline_package, failure):
    archive, config, lock, _, members, save = offline_package
    if failure == "hash":
        archive.write_bytes(b"synthetic tampering")
    else:
        entry = lock["rules"][-1]
        name = f"{lock['upstream']['archive']['root']}/{entry['path']}"
        members[name] = members[name].replace(b"EventID: 1", b"UnsupportedField: 1")
        save()
    cursor = Cursor()
    with pytest.raises(updates.UpdateError, match="^sigma_update_package_invalid$") as error:
        updates.prepare_offline_update(cursor, SCOPE, updates.Manifest(SCOPE, ()), archive, config)
    assert not cursor.calls and error.value.__suppress_context__


def test_offline_semantic_update_blocks_existing_exception(offline_package):
    archive, config, lock, _, members, save = offline_package
    cursor = Cursor()
    old = updates.prepare_offline_update(cursor, SCOPE, updates.Manifest(SCOPE, ()), archive, config).candidate_manifest()
    old = replace(old, rules=(add_overlay(cursor, old.rules[0]), *old.rules[1:]))
    entry = lock["rules"][0]
    name = f"{lock['upstream']['archive']['root']}/{entry['path']}"
    members[name] = members[name].replace(b"EventID: 1", b"EventID: 2")
    save()
    plan = updates.prepare_offline_update(cursor, SCOPE, old, archive, config)
    assert plan.blocked and plan.changes[0].reasons == ("overlay_base_changed",)
    assert plan.rollback == old
    assert plan.candidate.rules[0].overlays == old.rules[0].overlays

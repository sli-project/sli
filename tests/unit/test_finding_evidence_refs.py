"""Native evidence and publication contracts, using fakes without a database."""
from dataclasses import replace

import pytest

from server.sli.semantic.finding_evidence import link_finding_evidence, validate_finding_evidence
from server.sli.semantic.semantic_findings import publish_enabled_scenario_finding
from server.sli.storage.evidence_ref import EvidenceRef, EvidenceRefError, EvidenceScope
from tests.semantic.test_decision_chain import PublicationCursor

INSTALLATION = "00000000-0000-0000-0000-000000000001"
KINDS = ("core_event", "workstation_observation", "file_audit_observation")


def reference(kind="core_event"):
    plugin = dict(zip(KINDS, ("sli.windows.ad-dc", "sli.workstations", "sli.file-audit")))[kind]
    scope = EvidenceScope(INSTALLATION, plugin, "fixture-source", "generation-1",
                          "fixture-root" if kind == "file_audit_observation" else "")
    return EvidenceRef(kind, "42" if kind == "core_event" else "a" * 64, "b" * 64, scope)


class NativeCursor(PublicationCursor):
    """A login's immutable native rows; SQL contracts are tested separately."""

    def __init__(self, refs=(), *, legacy=True):
        super().__init__()
        self.allowed = {ref.params for ref in refs}
        self.links = set()
        self.legacy = legacy
        self.core_ids = {1} if legacy else set()

    def execute(self, sql, params=()):
        normalized = " ".join(sql.split()).lower()
        if "public.resolve_finding_evidence_ref(" in normalized:
            self.calls.append((normalized, params))
            self.rows = [{"verified": params in self.allowed}]
        elif "public.link_finding_evidence_ref(" in normalized:
            self.calls.append((normalized, params))
            if params[1:] not in self.allowed:
                raise RuntimeError("private database diagnostic")
            added = params not in self.links
            self.links.add(params)
            if params[-3] == "core_event":
                event_id = int(params[-2])
                added = event_id not in self.core_ids
                self.core_ids.add(event_id)
            self.rows = [{"added": added}]
        elif normalized.startswith("select count(*)"):
            self.calls.append((normalized, params))
            plugins = sum(row[-3] != "core_event" for row in self.links)
            self.rows = [{"count": len(self.core_ids) + plugins,
                          "max_event_id": max(self.core_ids) if self.core_ids else None}]
        elif "insert into finding_evidence(" in normalized and not self.legacy:
            self.calls.append((normalized, params))
            self.rows = []
        else:
            super().execute(sql, params)


@pytest.mark.parametrize("kind", KINDS)
def test_native_types_preserve_exact_ids_scope_and_hash(kind):
    ref = reference(kind)
    cur = NativeCursor((ref,))
    assert validate_finding_evidence(cur, (ref,)) == (ref,)
    assert cur.calls[0][1] == ref.params
    assert link_finding_evidence(cur, finding_id=7, refs=(ref, ref)) == 1
    assert link_finding_evidence(cur, finding_id=7, refs=(ref,)) == 0
    assert len(cur.links) == 1
    assert next(iter(cur.links)) == (7, *ref.params)
    if kind != "core_event":
        assert ref.native_id == "a" * 64
        assert cur.core_ids == {1}


@pytest.mark.parametrize("overrides", [
    {"storage_kind": "workstation_history"}, {"storage_kind": "unknown"},
    {"storage_kind": []}, {"sha256": "B" * 64}, {"sha256": ""},
    {"native_id": 42}, {"native_id": "042"}, {"native_id": "-1"},
    {"native_id": str(2**63)}, {"native_id": "a" * 64},
])
def test_invalid_or_unsupported_native_identity_is_rejected(overrides):
    with pytest.raises(EvidenceRefError):
        replace(reference(), **overrides)


@pytest.mark.parametrize("overrides", [
    {"installation_id": "not-a-uuid"}, {"source_instance_id": ""},
    {"source_generation": " "}, {"collection_scope_id": None},
    {"source_generation": "g" * 513},
])
def test_invalid_scope_is_rejected(overrides):
    with pytest.raises(EvidenceRefError, match="evidence_scope_invalid"):
        replace(reference().scope, **overrides)


def test_type_cannot_be_relabelled_or_lose_fs_collection_root():
    with pytest.raises(EvidenceRefError, match="evidence_type_unsupported"):
        replace(reference("workstation_observation"), storage_kind="file_audit_observation")
    ref = reference("file_audit_observation")
    with pytest.raises(EvidenceRefError, match="evidence_reference_invalid"):
        replace(ref, scope=replace(ref.scope, collection_scope_id=""))


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("changed", ["hash", "id", "installation", "source", "generation", "root"])
def test_hash_identity_and_foreign_scope_fail_closed(kind, changed):
    original = reference(kind)
    if changed == "hash":
        ref = replace(original, sha256="c" * 64)
    elif changed == "id":
        ref = replace(original, native_id="43" if kind == "core_event" else "d" * 64)
    else:
        field, value = {
            "installation": ("installation_id", "00000000-0000-0000-0000-000000000002"),
            "source": ("source_instance_id", "other-source"),
            "generation": ("source_generation", "other-generation"),
            "root": ("collection_scope_id", "other-root") if kind == "file_audit_observation"
                    else ("plugin_id", "sli.other"),
        }[changed]
        scope = replace(original.scope, **{field: value})
        if field == "plugin_id":
            with pytest.raises(EvidenceRefError, match="evidence_type_unsupported"):
                replace(original, scope=scope)
            return
        ref = replace(original, scope=scope)
    cur = NativeCursor((original,))
    with pytest.raises(EvidenceRefError, match="evidence_unavailable_or_denied"):
        link_finding_evidence(cur, finding_id=7, refs=(ref,))
    assert not cur.links


def test_conflicting_hashes_are_rejected_before_any_query():
    ref = reference()
    cur = NativeCursor((ref,))
    with pytest.raises(EvidenceRefError, match="evidence_hash_conflict"):
        validate_finding_evidence(cur, (ref, replace(ref, sha256="c" * 64)))
    assert not cur.calls


@pytest.mark.parametrize("refs", [[], (object(),), (reference(),) * 257])
def test_complete_set_is_typed_and_bounded_before_reading(refs):
    cur = NativeCursor()
    with pytest.raises(EvidenceRefError, match="evidence_reference_invalid"):
        validate_finding_evidence(cur, refs)
    assert not cur.calls


@pytest.mark.parametrize("finding_id", [True, 0, -1, "7", 2**63])
def test_invalid_finding_identity_is_rejected_before_reading(finding_id):
    cur = NativeCursor((reference(),))
    with pytest.raises(EvidenceRefError, match="evidence_finding_invalid"):
        link_finding_evidence(cur, finding_id=finding_id, refs=(reference(),))
    assert not cur.calls


def test_database_diagnostics_are_never_exposed():
    class Unavailable:
        def execute(self, *args):
            raise RuntimeError("private database diagnostic")

    with pytest.raises(EvidenceRefError, match="^evidence_verification_failed$") as error:
        validate_finding_evidence(Unavailable(), (reference(),))
    assert error.value.__suppress_context__
    assert "fixture-source" not in repr(reference())
    assert "fixture-source" not in repr(reference().scope)


def test_access_revocation_after_preflight_blocks_link():
    ref = reference("workstation_observation")

    class Revoked(NativeCursor):
        def execute(self, sql, params=()):
            if "public.link_finding_evidence_ref(" in sql:
                self.allowed.clear()
            super().execute(sql, params)

    cur = Revoked((ref,))
    with pytest.raises(EvidenceRefError, match="^evidence_link_failed$"):
        link_finding_evidence(cur, finding_id=7, refs=(ref,))
    assert not cur.links


@pytest.mark.parametrize("refs", [(reference("workstation_observation"),), (object(),)])
def test_unsupported_or_unavailable_evidence_blocks_entire_publication_before_writes(refs):
    core = reference()
    cur = NativeCursor((core,))
    with pytest.raises(EvidenceRefError):
        publish_enabled_scenario_finding(cur, job_id="test-job", scenario_id="test-scenario",
                                        evidence_refs=(core, *refs))
    assert not any("insert into" in sql or "update findings" in sql for sql, _ in cur.calls)


@pytest.mark.parametrize("kind", KINDS)
def test_typed_only_publication_counts_native_evidence_and_preserves_core_max(kind):
    ref = reference(kind)
    cur = NativeCursor((ref,), legacy=False)
    result = publish_enabled_scenario_finding(cur, job_id="test-job", scenario_id="test-scenario",
                                            evidence_refs=(ref, ref))
    assert result["evidence_count"] == result["evidence_added"] == 1
    count_query = next(sql for sql, _ in cur.calls if sql.startswith("select count(*)"))
    assert "storage_kind<>'core_event'" in count_query
    update = next(params for sql, params in cur.calls if "update findings" in sql)
    assert update[-2] == (42 if kind == "core_event" else None)
    assert not any("insert into events" in sql for sql, _ in cur.calls)

    replay = publish_enabled_scenario_finding(cur, job_id="test-job", scenario_id="test-scenario")
    assert replay["evidence_count"] == 1  # Empty new input must not erase previous plugin counts.
    assert replay["evidence_added"] == 0


def test_mixed_sources_count_once_and_do_not_modify_manual_statuses():
    refs = tuple(reference(kind) for kind in KINDS)
    cur = NativeCursor(refs)
    result = publish_enabled_scenario_finding(cur, job_id="test-job", scenario_id="test-scenario",
                                            evidence_refs=refs)
    assert result["evidence_count"] == 4  # Existing core 1, native core 42, WS, FS.
    update = next(sql for sql, _ in cur.calls if "update findings" in sql)
    assert "status=" not in update and "status_reason=" not in update


def test_typed_evidence_does_not_bypass_admission():
    ref = reference("workstation_observation")
    cur = NativeCursor((ref,))
    cur.admitted = False
    with pytest.raises(RuntimeError, match="observed enabled result"):
        publish_enabled_scenario_finding(cur, job_id="test-job", scenario_id="test-scenario", evidence_refs=(ref,))
    assert len(cur.calls) == 1

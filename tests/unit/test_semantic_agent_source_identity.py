"""T063: semantic hydration keeps native identity and full-body verification."""
from copy import deepcopy

import pytest

from server.sli.semantic.semantic_processing import normalize_semantic_source_payload
from server.sli.semantic.semantic_processing_repository import (
    load_semantic_source_event,
)
from server.sli.storage.event_source_identity import (
    digest,
    event_identity_hash,
    legacy_event_hash,
)
from server.sli.storage.storage_v2_archive import ArchiveIntegrityError
from tests.semantic.test_semantic_agent_source import Cursor, MissingArchive, evidence


def source(version=2, *, nested=False):
    core, full = evidence()
    full["connect_address"] = "fixture-endpoint"
    row = deepcopy(full)
    if nested:
        row["xml"] = row["xml"].replace('<Data Name="TargetUserName">fixture-account</Data>', "")
        row["connect_address"] = "localhost"
    core["normalized_hash"] = bytes.fromhex((legacy_event_hash if version == 1 else event_identity_hash)(row))
    # Match to_jsonb(bytea) from the SECURITY DEFINER reader, not driver bytes.
    preferred = {"event_id": core["id"], "identity_version": 2,
                 "normalized_hash": "\\x" + core["normalized_hash"].hex(),
                 "canonical_hash": "\\x" + event_identity_hash(full),
                 "representation": full, "representation_sha256": "\\x" + digest(full)}
    return core, {"core": core, "event_row": row, "preferred": preferred}


def hydrate(core, value):
    return load_semantic_source_event(Cursor({"source": value}), source_event_id=core["id"],
                                      archive=MissingArchive(), source_identity=core)


@pytest.mark.parametrize("version,nested", [(2, False), (2, True), (1, True)])
def test_semantic_reader_uses_verified_full_representation_with_retained_hash(version, nested):
    core, value = source(version, nested=nested)
    result = hydrate(core, value)
    assert result["event_data_json"]["TargetUserName"] == "fixture-account"
    assert result["source_event_sha256"] == core["normalized_hash"]
    normalized = normalize_semantic_source_payload(result)
    assert normalized.semantic_type == "authentication.session.failed"
    assert normalized.facts["failure_status"] == "0xc000006a"


@pytest.mark.parametrize("mutation", ["body", "checksum", "canonical_hash", "normalized_hash", "version", "event_id"])
def test_semantic_reader_rejects_corrupt_preferred_representation(mutation):
    core, value = source()
    preferred = value["preferred"]
    if mutation == "body":
        preferred["representation"]["xml"] = preferred["representation"]["xml"].replace("fixture-account", "changed")
    elif mutation == "version":
        preferred["identity_version"] = 1
    elif mutation == "event_id":
        preferred["event_id"] += 1
    else:
        preferred[{"checksum": "representation_sha256"}.get(mutation, mutation)] = "\\x" + "00" * 32
    with pytest.raises(ArchiveIntegrityError):
        hydrate(core, value)


def test_semantic_reader_rejects_changed_shared_xml_even_when_native_hash_matches():
    core, value = source()
    value["event_row"]["xml"] = value["event_row"]["xml"].replace("0xc000006a", "0xc0000064")
    assert event_identity_hash(value["event_row"]) == core["normalized_hash"].hex()
    with pytest.raises(ArchiveIntegrityError, match="representation"):
        hydrate(core, value)


def test_semantic_reader_requires_full_body_evidence_for_v2():
    core, value = source()
    value.pop("preferred")
    with pytest.raises(ArchiveIntegrityError, match="hash mismatch"):
        hydrate(core, value)


def test_semantic_reader_preserves_job_hash_verification_with_preferred_source():
    core, value = source()
    identity = {**core, "normalized_hash": b"x" * 32}
    with pytest.raises(ArchiveIntegrityError, match="hash mismatch"):
        hydrate(identity, value)

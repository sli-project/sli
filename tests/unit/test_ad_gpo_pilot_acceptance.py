"""Stage 8 reporting and negative probes; synthetic files/fakes, no DB or AD."""
from copy import deepcopy
import json
import os

import pytest

from scripts.maintenance import ad_gpo_pilot_acceptance as subject


RUN = "10000000-0000-4000-8000-000000000001"
INSTALLATION = "20000000-0000-4000-8000-000000000001"
ARTIFACT = "30000000-0000-4000-8000-000000000001"
PRIVATE = "synthetic-private-marker-only"


def evidence():
    return subject.empty_evidence(run_id=RUN, source_revision="a" * 40, worktree_sha256="b" * 64, installation_id=INSTALLATION)


def observation(case, fact, *, kind="lab", outcome="passed"):
    return {"case_id": case, "fact_id": fact, "kind": kind, "outcome": outcome, "artifact_id": ARTIFACT}


def all_observations(kind="lab"):
    return [observation(case, fact, kind=kind) for case, facts in subject.CASES.items() for fact in facts]


def recorded_report(data, tmp_path):
    receipt = {key: data[key] for key in subject.CONTEXT_FIELDS}
    receipt["observations"] = [{key: value for key, value in item.items() if key != "artifact_id"}
                               for item in data["observations"]]
    (tmp_path / (ARTIFACT + ".json")).write_text(json.dumps(receipt))
    return subject.report(data, artifact_dir=tmp_path)


def test_empty_matrix_covers_all_design_rows_and_blocks_release():
    result = subject.report(evidence())
    assert result["release_gate"] == "blocked"
    assert [row["design_row"] for row in result["rows"]] == list(range(1, 18))
    assert all(row["status"] == "not_verified" for row in result["rows"])
    assert all(fact["code"] == "lab_evidence_missing" for row in result["rows"] for fact in row["facts"])
    assert result["memory_lsass_risk"] == "not_eliminated"


def test_full_unit_matrix_never_counts_as_installed_lab_acceptance(tmp_path):
    result = recorded_report({**evidence(), "observations": all_observations("unit")}, tmp_path)
    assert result["release_gate"] == "blocked"
    assert all(row["status"] == "not_verified" for row in result["rows"])
    assert all(fact["evidence"][0]["kind"] == "unit" for row in result["rows"] for fact in row["facts"])
    assert all(fact["evidence"][0]["artifact_status"] == "recorded" for row in result["rows"] for fact in row["facts"])


def test_complete_recorded_lab_matrix_is_only_eligible_for_review(tmp_path):
    result = recorded_report({**evidence(), "observations": all_observations()}, tmp_path)
    assert result["release_gate"] == "eligible_for_review"
    assert all(row["status"] == "verified" for row in result["rows"])
    assert "write_enabled" not in result


@pytest.mark.parametrize("fact", ["msi_complete", "service_running", "independent_key", "approved", "heartbeat"])
def test_configured_or_approved_never_implies_another_installation_fact(fact, tmp_path):
    observations = [item for item in all_observations() if (item["case_id"], item["fact_id"]) != ("installation", fact)]
    result = recorded_report({**evidence(), "observations": observations}, tmp_path)
    row = next(row for row in result["rows"] if row["case_id"] == "installation")
    assert result["release_gate"] == "blocked" and row["status"] == "not_verified"
    assert next(item for item in row["facts"] if item["fact_id"] == fact)["status"] == "not_verified"


@pytest.mark.parametrize("case,fact", [("execution_context", "sysvol_second"), ("secret_leaks", "spool"),
    ("backup_restore_rotation", "rotation_restart"), ("envelope", "restart")])
@pytest.mark.parametrize("kind", ["lab", "unit"])
def test_any_failure_blocks_even_with_a_complete_lab_matrix(case, fact, kind, tmp_path):
    observations = [item for item in all_observations() if (item["case_id"], item["fact_id"], item["kind"]) != (case, fact, kind)]
    observations.append(observation(case, fact, kind=kind, outcome="failed"))
    result = recorded_report({**evidence(), "observations": observations}, tmp_path)
    assert result["release_gate"] == "blocked"
    row = next(row for row in result["rows"] if row["case_id"] == case)
    assert row["status"] == "failed"


def test_single_dc_pilot_does_not_accept_multi_dc_even_with_all_observations(tmp_path):
    result = recorded_report({**evidence(), "dc_count": 2, "observations": all_observations()}, tmp_path)
    assert result["release_gate"] == "blocked" and result["scope_status"] == "unsupported_multi_dc"


def test_claims_without_existing_artifacts_do_not_establish_lab_facts(tmp_path):
    for directory in (None, tmp_path):
        result = subject.report({**evidence(), "observations": all_observations()}, artifact_dir=directory)
        assert result["release_gate"] == "blocked"
        assert all(row["status"] == "not_verified" for row in result["rows"])


def test_unconfirmed_installation_blocks_even_with_all_lab_attestations(tmp_path):
    result = recorded_report({**evidence(), "installation_id": None, "observations": all_observations()}, tmp_path)
    assert result["release_gate"] == "blocked" and result["context_status"] == "not_verified"
    assert all(row["status"] == "not_verified" for row in result["rows"])


def test_every_install_and_delete_phase_requires_separate_evidence():
    from sli_agent.gpo_deployment import DELETE_PHASES, PHASES
    assert {"phase_" + phase for phase in PHASES} <= set(subject.CASES["configured"])
    assert {"phase_" + phase for phase in DELETE_PHASES} <= set(subject.CASES["deletion"])


@pytest.mark.parametrize("field,value", [("run_id", ARTIFACT), ("installation_id", RUN),
    ("source_revision", "b" * 40), ("worktree_sha256", "c" * 64), ("schema_version", True), ("password", PRIVATE),
    ("observations", []), ("observations", [{"password": PRIVATE}])])
def test_receipt_must_match_run_installation_source_and_exact_safe_fact(tmp_path, field, value):
    data = {**evidence(), "observations": all_observations()}
    recorded_report(data, tmp_path)
    path = tmp_path / (ARTIFACT + ".json")
    receipt = json.loads(path.read_text())
    receipt[field] = value
    path.write_text(json.dumps(receipt))
    result = subject.report(data, artifact_dir=tmp_path)
    assert result["release_gate"] == "blocked" and PRIVATE not in json.dumps(result)
    assert all(row["status"] == "not_verified" for row in result["rows"])


def test_linked_receipt_does_not_count_as_evidence(tmp_path):
    data = {**evidence(), "observations": all_observations()}
    recorded_report(data, tmp_path)
    path = tmp_path / (ARTIFACT + ".json")
    original = tmp_path / "outside.json"
    path.rename(original)
    path.symlink_to(original)
    result = subject.report(data, artifact_dir=tmp_path)
    assert result["release_gate"] == "blocked"


def test_receipt_cannot_hide_a_failed_attempt_behind_a_passed_observation(tmp_path):
    data = {**evidence(), "observations": all_observations()}
    recorded_report(data, tmp_path)
    path = tmp_path / (ARTIFACT + ".json")
    receipt = json.loads(path.read_text())
    receipt["observations"].append({**receipt["observations"][0], "outcome": "failed"})
    path.write_text(json.dumps(receipt))
    result = subject.report(data, artifact_dir=tmp_path)
    assert result["release_gate"] == "blocked"
    assert all(row["status"] == "not_verified" for row in result["rows"])


@pytest.mark.parametrize("field,value", [("schema_version", True), ("run_id", PRIVATE),
    ("source_revision", PRIVATE), ("worktree_sha256", PRIVATE), ("installation_id", "0" * 32), ("dc_count", True),
    ("dc_count", 0), ("observations", {}), ("password", PRIVATE)])
def test_untrusted_context_has_fixed_error_without_values(field, value):
    with pytest.raises(subject.EvidenceError, match="^pilot_evidence_invalid$") as error:
        subject.report({**evidence(), field: value})
    assert PRIVATE not in str(error.value)


@pytest.mark.parametrize("field,value", [("case_id", []), ("fact_id", PRIVATE), ("kind", "e2e"),
    ("outcome", "not_found"), ("artifact_id", "../" + PRIVATE), ("raw_log", PRIVATE)])
def test_unknown_facts_raw_data_and_paths_are_rejected(field, value):
    item = observation("secret_leaks", "http")
    item[field] = value
    with pytest.raises(subject.EvidenceError, match="^pilot_evidence_invalid$"):
        subject.report({**evidence(), "observations": [item]})


def test_duplicate_observations_cannot_hide_an_earlier_failure():
    first = observation("secret_leaks", "http", outcome="failed")
    with pytest.raises(subject.EvidenceError):
        subject.report({**evidence(), "observations": [first, {**first, "outcome": "passed"}]})


def test_report_does_not_mutate_input():
    data = {**evidence(), "observations": all_observations()}
    before = deepcopy(data)
    subject.report(data)
    assert data == before


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16-le", "utf-16-be"])
@pytest.mark.parametrize("offset", [0, 65530, 131069])
def test_canary_detects_leak_across_chunks_without_disclosing_match(tmp_path, encoding, offset):
    marker = PRIVATE.encode(encoding)
    artifact = tmp_path / "renamed-temporary-key-or-spool"
    artifact.write_bytes(b"x" * offset + marker + b"tail")
    result = subject.scan_canary(artifact, marker)
    assert result == "failed" and PRIVATE not in result and str(artifact) not in result


def test_canary_absence_missing_and_linked_artifacts_are_distinct(tmp_path):
    artifact = tmp_path / "collected-log"
    marker = PRIVATE.encode()
    assert subject.scan_canary(artifact, marker) == "not_verified"
    artifact.write_bytes(b"redacted")
    assert subject.scan_canary(artifact, marker) == "passed"
    link = tmp_path / "link"
    link.symlink_to(artifact)
    assert subject.scan_canary(link, marker) == "not_verified"
    os.link(artifact, tmp_path / "hardlink")
    assert subject.scan_canary(artifact, marker) == "not_verified"
    assert subject.scan_canary(tmp_path, marker) == "not_verified"


def test_canary_never_blocks_on_fifo(tmp_path):
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    assert subject.scan_canary(fifo, PRIVATE.encode()) == "not_verified"


@pytest.mark.parametrize("marker", [b"", b"short", "not-bytes", b"x" * 4097])
def test_canary_requires_bounded_synthetic_marker(tmp_path, marker):
    with pytest.raises(subject.EvidenceError):
        subject.scan_canary(tmp_path, marker)


def test_cli_blocks_with_complete_matrix_of_explicit_not_verified(tmp_path, capsys):
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps(evidence()))
    assert subject.main(["--evidence", str(path)]) == 1
    result = json.loads(capsys.readouterr().out)
    assert len(result["rows"]) == 17 and result["release_gate"] == "blocked"


@pytest.mark.parametrize("contents", [PRIVATE, '{"password":"' + PRIVATE + '"}',
    '{"schema_version":1,"schema_version":2}', "x" * (subject.MAX_INPUT_BYTES + 1), "[" * 2000])
def test_cli_malformed_input_never_prints_parser_error_path_or_content(tmp_path, capsys, contents):
    path = tmp_path / PRIVATE
    path.write_text(contents)
    assert subject.main(["--evidence", str(path)]) == 1
    captured = capsys.readouterr()
    assert PRIVATE not in captured.out + captured.err and captured.err == ""
    assert json.loads(captured.out) == {"schema_version": 1, "release_gate": "blocked", "error_code": "pilot_evidence_invalid"}

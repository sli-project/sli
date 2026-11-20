"""Stage 8 evidence ledger for section 8 of GPO_DEPLOY_DESIGN.

This read-only tool aggregates recorded observations; it does not execute LAB
operations, authenticate their provenance or enable a runtime feature. A clean
unit run cannot establish installed acceptance. Only separately recorded LAB
observations cover LAB facts. Inputs contain opaque evidence IDs, never raw
logs, names, domains, passwords, envelopes or password/key fingerprints.
"""
from __future__ import annotations

import argparse
import json
import re
import stat
from pathlib import Path
from uuid import UUID


# Order and row numbers match the 17 rows of the design's LAB matrix. Facts are
# deliberately independent: configured, installed, approved and heartbeat are
# not interchangeable evidence.
CASES = {
    "credential_registry": ("two_same_domain", "foreign_domain_denied", "last_use_scoped", "write_only"),
    "credential_check": ("selected_bind", "wrong_password", "partial_rights", "read_only", "bounded_attempts"),
    "authorization": ("missing_credential", "missing_permission", "foreign_domain", "foreign_ou", "no_mutation"),
    "install_methods": ("gpo_account", "share_account", "manual_no_ad_password", "manual_not_installed", "safe_argv"),
    "preview": ("cancel_no_mutation", "expired_plan", "account_swap", "ineligible_account"),
    "execution_context": ("ldap_first", "sysvol_first", "ldap_second", "sysvol_second", "old_session_closed"),
    "configured": ("one_owned_gpo", "exact_links", "sid_filter", "signed_files", "no_sysvol_secret",
        "phase_create_disabled", "phase_filter", "phase_gpt", "phase_versions", "phase_links", "phase_readback", "phase_enable"),
    "installation": ("msi_complete", "service_running", "pending_no_collection", "independent_key", "approved", "heartbeat"),
    "scope": ("excluded_station", "spoofed_name_no_certificate"),
    "idempotency": ("same_guid", "fixed_ttl", "foreign_objects_preserved", "conflict_blocks"),
    "envelope": ("wrong_agent", "tamper", "replay", "ttl", "restart", "legacy_blocked"),
    "credential_lifecycle": ("replace_blocks_old", "delete_blocks_old", "permission_revoked", "certificate_revoked", "safe_boundary"),
    "recovery": ("access_denied", "lost_reply", "link_drift", "restart_no_replay", "compensation_remainder"),
    "database_theft": ("missing_kek", "corrupt_ciphertext", "row_aad", "domain_aad", "safe_error"),
    "backup_restore_rotation": ("archive_no_kek", "companion_no_kek", "temporary_copy_excluded", "restore_requires_reentry", "no_resumed_jobs", "rotation_restart", "active_records_preserved"),
    "secret_leaks": ("http", "proxy", "apm", "sql", "application", "msi_argv", "msi_log", "spool", "agent_state", "dumps"),
    "deletion": ("token_revoked", "token_expired", "owned_objects_deleted", "foreign_objects_preserved", "installed_agent_preserved", "selected_account",
        "phase_revoke", "phase_disable", "phase_unlink", "phase_delete_gpo", "phase_delete_gpt", "phase_absent"),
}
CONTEXT_FIELDS = ("schema_version", "run_id", "source_revision", "worktree_sha256", "installation_id")
INPUT_FIELDS = {*CONTEXT_FIELDS, "dc_count", "observations"}
OBSERVATION_FIELDS = {"case_id", "fact_id", "kind", "outcome", "artifact_id"}
MAX_INPUT_BYTES = 1024 * 1024


class EvidenceError(ValueError):
    def __init__(self):
        super().__init__("pilot_evidence_invalid")


def _uuid(value):
    try:
        return type(value) is str and str(UUID(value)) == value and UUID(value).int != 0
    except (ValueError, AttributeError):
        return False


def empty_evidence(*, run_id, source_revision, worktree_sha256, installation_id):
    return {"schema_version": 1, "run_id": run_id, "source_revision": source_revision,
            "worktree_sha256": worktree_sha256, "installation_id": installation_id, "dc_count": 1, "observations": []}


def _artifact_recorded(artifact_dir, item, evidence):
    """Check an on-disk sanitized receipt, bound to this run and source.

    Receipts are attestations from the acceptance operator, not trusted remote
    execution proofs. Their existence/binding is necessary for review; it never
    grants production execution permission.
    """
    if artifact_dir is None or evidence["installation_id"] is None and item["kind"] == "lab":
        return False
    try:
        import os

        path = Path(artifact_dir) / (item["artifact_id"] + ".json")
        if path.parent.is_symlink() or path.parent.resolve() != path.parent.absolute():
            return False
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_INPUT_BYTES:
                return False
            receipt = json.loads(stream.read(MAX_INPUT_BYTES + 1), object_pairs_hook=_unique_object)
        expected = {key: evidence[key] for key in CONTEXT_FIELDS}
        return (type(receipt) is dict and set(receipt) == {*expected, "observations"}
                and all(type(receipt[key]) is type(value) and receipt[key] == value for key, value in expected.items())
                and type(receipt["observations"]) is list
                and all(type(row) is dict and set(row) == OBSERVATION_FIELDS - {"artifact_id"}
                        and all(type(value) is str for value in row.values())
                        and row["case_id"] in CASES and row["fact_id"] in CASES[row["case_id"]]
                        and row["kind"] in {"lab", "unit"} and row["outcome"] in {"passed", "failed"}
                        for row in receipt["observations"])
                and len({(row["case_id"], row["fact_id"], row["kind"]) for row in receipt["observations"]})
                    == len(receipt["observations"])
                and {key: value for key, value in item.items() if key != "artifact_id"} in receipt["observations"])
    except (OSError, ValueError, TypeError, RecursionError):
        return False


def report(evidence, *, artifact_dir=None):
    """Reject unknown/free-text fields, and never turn unit evidence into LAB."""
    if (type(evidence) is not dict or set(evidence) != INPUT_FIELDS
            or type(evidence["schema_version"]) is not int or evidence["schema_version"] != 1
            or not _uuid(evidence["run_id"])
            or evidence["installation_id"] is not None and not _uuid(evidence["installation_id"])
            or type(evidence["source_revision"]) is not str
            or re.fullmatch(r"[0-9a-f]{40}", evidence["source_revision"]) is None
            or type(evidence["worktree_sha256"]) is not str
            or re.fullmatch(r"[0-9a-f]{64}", evidence["worktree_sha256"]) is None
            or type(evidence["dc_count"]) is not int or evidence["dc_count"] < 1
            or type(evidence["observations"]) is not list or len(evidence["observations"]) > 4096):
        raise EvidenceError()
    observations = {}
    for item in evidence["observations"]:
        if (type(item) is not dict or set(item) != OBSERVATION_FIELDS
                or any(type(item[key]) is not str for key in OBSERVATION_FIELDS)
                or item["case_id"] not in CASES or item["fact_id"] not in CASES[item["case_id"]]
                or item["kind"] not in {"unit", "lab"} or item["outcome"] not in {"passed", "failed"}
                or not _uuid(item["artifact_id"])):
            raise EvidenceError()
        key = (item["case_id"], item["fact_id"], item["kind"])
        # Conflicting retries cannot overwrite an earlier failure. A new run is
        # required after remediation, with its own opaque run/evidence IDs.
        if key in observations:
            raise EvidenceError()
        observations[key] = item
    rows = []
    for number, (case, facts) in enumerate(CASES.items(), 1):
        results = []
        for fact in facts:
            lab = observations.get((case, fact, "lab"))
            unit = observations.get((case, fact, "unit"))
            failed = any(item and item["outcome"] == "failed" for item in (lab, unit))
            recorded = {item["kind"]: _artifact_recorded(artifact_dir, item, evidence) for item in (unit, lab) if item}
            lab_recorded = recorded.get("lab", False)
            status = "failed" if failed else "verified" if lab_recorded else "not_verified"
            results.append({"fact_id": fact, "status": status,
                "code": "recorded_failure" if failed else "lab_evidence_recorded" if lab_recorded else "lab_evidence_missing",
                "evidence": [{**{key: item[key] for key in ("kind", "outcome", "artifact_id")},
                              "artifact_status": "recorded" if recorded[item["kind"]] else "not_verified"}
                             for item in (unit, lab) if item]})
        status = ("failed" if any(item["status"] == "failed" for item in results)
                  else "verified" if all(item["status"] == "verified" for item in results) else "not_verified")
        rows.append({"design_row": number, "case_id": case, "status": status, "facts": results})
    single_dc = evidence["dc_count"] == 1
    return {"schema_version": 1, "run_id": evidence["run_id"], "source_revision": evidence["source_revision"],
        "worktree_sha256": evidence["worktree_sha256"], "installation_id": evidence["installation_id"], "scope": "single_dc_pilot",
        "release_gate": "eligible_for_review" if single_dc and all(row["status"] == "verified" for row in rows) else "blocked",
        "scope_status": "single_dc_declared" if single_dc else "unsupported_multi_dc",
        "context_status": "recorded" if evidence["installation_id"] is not None else "not_verified",
        "memory_lsass_risk": "not_eliminated", "rows": rows}


def scan_canary(path: Path, marker: bytes) -> str:
    """Scan one collected artifact without returning its path or matching bytes.

    Missing, linked, special or unreadable artifacts are not evidence of absence.
    The caller supplies a synthetic marker in memory, never an AD password.
    This checks exact bytes only; callers must scan each relevant encoding and
    each channel separately. Absence does not prove absence in process memory.
    """
    if type(marker) is not bytes or not 16 <= len(marker) <= 4096:
        raise EvidenceError()
    try:
        import os

        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                return "not_verified"
            tail = b""
            while block := stream.read(65536):
                value = tail + block
                if marker in value:
                    return "failed"
                tail = value[-(len(marker) - 1):]
            after = os.fstat(stream.fileno())
            if (after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (info.st_size, info.st_mtime_ns, info.st_ctime_ns):
                return "not_verified"
    except OSError:
        return "not_verified"
    return "passed"


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError()
        result[key] = value
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, help="Directory of sanitized <artifact_id>.json receipts")
    args = parser.parse_args(argv)
    try:
        # Bound reads even for malformed input. Raw content and parser errors
        # must never reach the report or stderr.
        with args.evidence.open("rb") as stream:
            body = stream.read(MAX_INPUT_BYTES + 1)
        if len(body) > MAX_INPUT_BYTES:
            raise EvidenceError()
        result = report(json.loads(body, object_pairs_hook=_unique_object), artifact_dir=args.artifacts)
    except (OSError, ValueError, TypeError, RecursionError):
        result = {"schema_version": 1, "release_gate": "blocked", "error_code": "pilot_evidence_invalid"}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["release_gate"] == "eligible_for_review" else 1


if __name__ == "__main__":
    raise SystemExit(main())

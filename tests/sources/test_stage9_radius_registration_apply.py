from __future__ import annotations

from uuid import UUID
from pathlib import Path

import pytest

from scripts.maintenance import stage9_radius_registration_apply as registration
from scripts.maintenance.stage9_radius_registration_apply import (
    RadiusProductionRegistrationError,
    _trusted_windows_powershell,
    _validate_postgres_authority,
    validate_prerequisites,
)
from scripts.maintenance.stage9_radius_postgres_migrate import (
    FOUNDATION_TABLES,
    _hashes,
)
from server.source_packs.radius.collection_routes import load_radius_collection_routes


def test_fresh_prerequisites_are_isolated_from_historical_evidence(monkeypatch, tmp_path):
    monkeypatch.setattr(registration, "ROOT", tmp_path)
    fresh = tmp_path / "artifacts" / "restore"
    fresh.mkdir(parents=True)
    seen = []
    def read(path):
        seen.append(path)
        return {"readback_sha256": "same"}
    monkeypatch.setattr(registration, "_read_json", read)
    monkeypatch.setattr(registration, "_read_optional_json", read)
    sentinel = object()
    monkeypatch.setattr(registration, "validate_prerequisites", lambda *a: sentinel)
    monkeypatch.setattr(registration, "_live_acl_readback", lambda: {"readback_sha256": "same"})
    monkeypatch.setattr(registration, "_inspect_rows", lambda: {
        "migration_58": True, "source_count": 0, "cursor_count": 0, "subscription_count": 0})
    result, bootstrap = registration.plan(prerequisites_dir=fresh)
    assert bootstrap is sentinel and result["status"] == "ready"
    assert len(seen) == 5 and all(path.parent == fresh for path in seen)
    assert {path.name for path in seen} == {
        registration.POSTGRES_APPLY.name, registration.POSTGRES_ATTESTATION.name,
        registration.CURSOR_BOOTSTRAP.name, registration.ACL_READBACK.name}


def test_fresh_prerequisites_reject_outside_artifacts_before_read(monkeypatch, tmp_path):
    monkeypatch.setattr(registration, "ROOT", tmp_path)
    monkeypatch.setattr(registration, "_read_optional_json", lambda *a: pytest.fail("read before path admission"))
    with pytest.raises(registration.RadiusProductionRegistrationError, match="prerequisites_directory_invalid"):
        registration.plan(prerequisites_dir=tmp_path)


def test_configured_cursor_evidence_path_preserves_existing_installation(monkeypatch, tmp_path):
    configured = tmp_path / "cursor-evidence.json"
    monkeypatch.setenv("ADLOG_RADIUS_CURSOR_BOOTSTRAP_EVIDENCE_PATH", str(configured))
    seen = []

    def read(path):
        seen.append(path)
        return {"readback_sha256": "same"}

    monkeypatch.setattr(registration, "_read_json", read)
    monkeypatch.setattr(registration, "_read_optional_json", read)
    monkeypatch.setattr(registration, "validate_prerequisites", lambda *_args: object())
    monkeypatch.setattr(registration, "_live_acl_readback", lambda: {"readback_sha256": "same"})
    monkeypatch.setattr(registration, "_inspect_rows", lambda: {
        "migration_58": True, "source_count": 1, "cursor_count": 1, "subscription_count": 1,
    })

    result, _bootstrap = registration.plan()

    assert result["registration_already_exact_candidate"] is True
    assert configured in seen
    assert registration.CURSOR_BOOTSTRAP not in seen


def _postgres() -> dict:
    return {
        "status": "passed",
        "action": "apply",
        "migration": {"version": 58},
        "production_database_changed": True,
        "source_instance_created": False,
        "runtime_enabled": False,
    }


def _attestation() -> dict:
    return {
        "status": "passed",
        "action": "finalize_applied_readback",
        "evidence_kind": "production_current_state_attestation",
        "migration": {
            "version": 58,
            **_hashes(),
        },
        "postcondition": {
            "marker": True,
            "worker_role": True,
            "evidence_insert": True,
            "evidence_delete": False,
            "cursor_update": True,
            "tables": sorted(FOUNDATION_TABLES),
        },
        "production_migration_applied": True,
        "production_database_changed": False,
        "source_instance_created": False,
        "runtime_enabled": False,
        "radius_source_contacted": False,
    }


def _acl() -> dict:
    return {
        "status": "accepted",
        "classification": "protected_acl_exact",
        "contract_id": "sli.radius-acquisition-evidence-root.v2",
        "node_count": 4,
        "acl_entry_count": 12,
        "activation_enabled": False,
        "raw_path_persisted": False,
    }


def _cursor() -> dict:
    return {
        "status": "completed",
        "read_only": True,
        "cursor_updated": False,
        "source_instance_created": False,
        "worker_activated": False,
        "source_instance_id": load_radius_collection_routes()["source_instance_id"],
        "stream_id": "radius-accounting",
        "transport_binding": "windows-rpc-smb-readonly-tail-v1",
        "cursor_bootstrap": {
            "cursor_epoch": "00000000-0000-4000-8000-000000000043",
            "file_generation": "gen-8ba902d1827e23272db2644bb703a1e2",
            "byte_offset": 10134781,
            "last_record_sha256": "a" * 64,
        },
    }


def test_prerequisites_yield_exact_bootstrap_without_activation() -> None:
    bootstrap = validate_prerequisites(_postgres(), _cursor(), _acl())
    assert bootstrap.cursor_epoch == UUID(
        "00000000-0000-4000-8000-000000000043"
    )
    assert bootstrap.byte_offset == 10134781
    assert bootstrap.file_generation.startswith("gen-")


def test_registration_loads_dpapi_when_pg_values_lack_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name, value in {
        "ADLOG_PG_ADMIN_USER": "already-present",
        "ADLOG_PG_ADMIN_PASSWORD": "already-present",
        "ADLOG_PG_DSN": "already-present",
    }.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("ADLOG_COLLECTION_PRINCIPAL", raising=False)
    monkeypatch.delenv("ADLOG_COLLECTION_PRINCIPAL_SID", raising=False)
    calls: list[bool] = []

    def load() -> None:
        calls.append(True)
        monkeypatch.setenv("ADLOG_COLLECTION_PRINCIPAL", "configured")
        monkeypatch.setenv("ADLOG_COLLECTION_PRINCIPAL_SID", "S-1-5-21-1")

    monkeypatch.setattr(registration, "load_supervisor_environment", load)

    registration._load_environment()

    assert calls == [True]


def _safe_legacy_candidate() -> dict[str, object]:
    contract = registration.load_registration_contract()
    source_id, subscription_id = registration._legacy_identifiers(contract)
    stream = contract["stream"]
    return {
        "legacy_source_instance_id": source_id,
        "legacy_subscription_id": subscription_id,
        "cursor": (
            stream["stream_id"],
            stream["transport_binding"],
            UUID("00000000-0000-4000-8000-000000000058"),
            "gen-legacy-registration",
            28,
            "a" * 64,
            None,
            None,
            28,
        ),
        "cursor_revision": 28,
        "source_contract_matches": True,
        "subscription_contract_matches": True,
        "cursor_contract_matches": True,
        "source_disabled": True,
        "subscription_disabled": True,
        "runtime_state_rows": 0,
    }


def test_legacy_remediation_requires_exact_disabled_empty_state() -> None:
    candidate = _safe_legacy_candidate()

    assert registration._require_safe_legacy_remediation(candidate) == candidate


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        (
            "legacy_source_instance_id",
            "radius.unexpected.example.invalid",
            "legacy_remediation_source_identity_unexpected",
        ),
        (
            "legacy_subscription_id",
            "vpn-radius-session-observations-unexpected-v1",
            "legacy_remediation_subscription_identity_unexpected",
        ),
    ],
)
def test_legacy_remediation_refuses_noncanonical_legacy_identity(
    field: str, value: str, code: str,
) -> None:
    candidate = _safe_legacy_candidate()
    candidate[field] = value

    with pytest.raises(RadiusProductionRegistrationError, match=code):
        registration._require_safe_legacy_remediation(candidate)


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("runtime_state_rows", 1, "legacy_remediation_runtime_state_present"),
        ("source_contract_matches", False, "legacy_remediation_source_contract_mismatch"),
        ("subscription_contract_matches", False, "legacy_remediation_subscription_contract_mismatch"),
        ("cursor_contract_matches", False, "legacy_remediation_cursor_contract_mismatch"),
        ("source_disabled", False, "legacy_remediation_source_not_disabled"),
        ("subscription_disabled", False, "legacy_remediation_subscription_not_disabled"),
    ],
)
def test_legacy_remediation_refuses_any_unsafe_state(
    field: str, value: int | bool, code: str,
) -> None:
    candidate = _safe_legacy_candidate()
    candidate[field] = value

    with pytest.raises(RadiusProductionRegistrationError, match=code):
        registration._require_safe_legacy_remediation(candidate)


def test_registration_refuses_unaccepted_acl() -> None:
    acl = _acl()
    acl["classification"] = "broad_acl"
    with pytest.raises(
        RadiusProductionRegistrationError,
        match="protected_root_evidence_invalid",
    ):
        validate_prerequisites(_postgres(), _cursor(), acl)


def test_registration_refuses_cursor_that_was_already_updated() -> None:
    cursor = _cursor()
    cursor["cursor_updated"] = True
    with pytest.raises(
        RadiusProductionRegistrationError,
        match="cursor_bootstrap_evidence_invalid",
    ):
        validate_prerequisites(_postgres(), cursor, _acl())


def test_registration_refuses_historical_placeholder_bootstrap() -> None:
    cursor = _cursor()
    cursor["source_instance_id"] = "radius.radius01.example.invalid"
    with pytest.raises(
        RadiusProductionRegistrationError,
        match="cursor_bootstrap_evidence_invalid",
    ):
        validate_prerequisites(_postgres(), cursor, _acl())


def test_registration_accepts_current_058_attestation() -> None:
    validate_prerequisites(None, _cursor(), _acl(), _attestation())


def test_registration_refuses_missing_or_inconsistent_058_authority() -> None:
    with pytest.raises(
        RadiusProductionRegistrationError,
        match="production_058_evidence_invalid",
    ):
        _validate_postgres_authority(None, None)
    legacy = _postgres()
    legacy["migration"].update({"forward_sha256": "c" * 64, "rollback_sha256": "b" * 64})
    with pytest.raises(
        RadiusProductionRegistrationError,
        match="production_058_evidence_hash_mismatch",
    ):
        _validate_postgres_authority(legacy, _attestation())


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("migration", "forward_sha256"), "0" * 64),
        (("migration", "rollback_sha256"), "0" * 64),
        (("migration", "version"), 57),
    ],
)
def test_registration_refuses_tampered_current_058_attestation(
    path: tuple[str, str], replacement: str | int,
) -> None:
    attestation = _attestation()
    attestation[path[0]][path[1]] = replacement
    with pytest.raises(
        RadiusProductionRegistrationError,
        match="production_058_attestation_invalid",
    ):
        _validate_postgres_authority(None, attestation)


def test_registration_refuses_v1_acl_evidence() -> None:
    acl = _acl()
    acl["contract_id"] = "sli.radius-acquisition-evidence-root.v1"
    with pytest.raises(
        RadiusProductionRegistrationError,
        match="protected_root_evidence_invalid",
    ):
        validate_prerequisites(_postgres(), _cursor(), acl)


def test_trusted_powershell_does_not_depend_on_child_path(
    monkeypatch, tmp_path
) -> None:
    executable = (
        tmp_path
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    executable.parent.mkdir(parents=True)
    executable.touch()
    monkeypatch.setenv("SystemRoot", str(tmp_path))
    monkeypatch.setenv("PATH", "")
    assert _trusted_windows_powershell() == executable.resolve()


def test_current_registration_consumer_uses_v2_acl_and_058_attestation() -> None:
    from pathlib import Path

    source = Path(
        "scripts/maintenance/stage9_radius_registration_apply.py"
    ).read_text(encoding="utf-8").casefold()
    assert "invoke-sli-stage9radiusevidencerootv2.ps1" in source
    assert "radius-accounting-postgres58-production-attestation.json" in source
    assert "sli.radius-acquisition-evidence-root.v2" in source

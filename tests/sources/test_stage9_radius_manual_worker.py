from __future__ import annotations

import sys
from pathlib import Path

import pytest

from scripts.maintenance import stage9_radius_manual_worker as worker
from scripts.maintenance import stage9_radius_identity_owner_migrate as identity_migrate
from server.source_packs.radius.accounting_manual_control import (
    RadiusManualLease,
)


def _disposable() -> dict:
    return {
        "status": "passed",
        "production_database_changed": False,
        "radius_source_contacted": False,
        "runtime_enabled": False,
        "acceptance": {
            "success_final_state": "disabled",
            "failure_final_state": "disabled",
            "success_ephemeral_login_dropped": True,
            "failure_ephemeral_login_dropped": True,
            "cursor_unchanged": True,
        },
    }


def _identity() -> dict:
    return {
        "status": "passed",
        "action": "apply",
        "migration": {"version": 59},
        "production_database_changed": True,
        "runtime_enabled": False,
    }


def _identity_attestation() -> dict:
    return {
        "status": "passed",
        "action": "finalize_applied_readback",
        "evidence_kind": "production_current_state_attestation",
        "covers_migrations": [59, 60],
        "migrations": identity_migrate._attestation_migrations(),
        "postcondition": {
            "marker": True,
            "resolver_owner": "adlog_radius_identity_resolver",
            "resolver_owner_restricted_nologin": True,
            "domains_column_select": True,
            "aliases_column_select": True,
            "resolver_owner_schema_create": False,
            "worker_identity_select": False,
            "public_execute": False,
            "missing_identity_result": None,
        },
        "production_migration_applied": True,
        "production_database_changed": False,
        "radius_source_contacted": False,
        "runtime_enabled": False,
    }


def _registration() -> dict:
    return {
        "status": "passed",
        "action": "disabled_registration",
        "source_instance_id": worker._source_id(),
        "subscription_id": worker._subscription_id(),
        "desired_activation": "disabled",
        "cursor_revision": 0,
        "worker_activated": False,
        "runtime_enabled": False,
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


def test_manual_worker_prerequisites_accept_exact_chain() -> None:
    worker.validate_prerequisite_evidence(
        _disposable(),
        _identity(),
        _registration(),
        _acl(),
    )


@pytest.mark.parametrize("method", ["_plan_after_external_acl_preflight", "contract_self_check"])
def test_configured_registration_evidence_path_preserves_existing_installation(monkeypatch, tmp_path, method):
    configured = tmp_path / "registration-evidence.json"
    monkeypatch.setenv("ADLOG_RADIUS_REGISTRATION_APPLY_EVIDENCE_PATH", str(configured))
    seen = []

    def read(path):
        seen.append(path)
        return {}

    monkeypatch.setattr(worker, "_read_json", read)
    monkeypatch.setattr(worker, "_read_optional_json", read)
    monkeypatch.setattr(worker, "validate_prerequisite_evidence", lambda *_args: None)
    monkeypatch.setattr(worker, "_inspect_production", dict)
    monkeypatch.setattr(worker, "_expected_account", lambda: "")

    result = getattr(worker, method)()

    assert result["source_contacted"] is False
    assert configured in seen
    assert worker.REGISTRATION_APPLY not in seen


def test_manual_worker_loads_dpapi_when_pg_values_lack_identity(
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

    monkeypatch.setattr(worker, "load_supervisor_environment", load)

    worker._load_environment()

    assert calls == [True]


def test_manual_worker_prerequisites_refuse_failure_cleanup_gap() -> None:
    disposable = _disposable()
    disposable["acceptance"]["failure_final_state"] = "manual_enabled"
    with pytest.raises(
        worker.RadiusManualWorkerError,
        match="manual_disposable_acceptance_invalid",
    ):
        worker.validate_prerequisite_evidence(
            disposable,
            _identity(),
            _registration(),
            _acl(),
        )


def test_manual_worker_prerequisites_refuse_nonzero_registration_cursor() -> None:
    registration = _registration()
    registration["cursor_revision"] = 1
    with pytest.raises(
        worker.RadiusManualWorkerError,
        match="disabled_registration_evidence_invalid",
    ):
        worker.validate_prerequisite_evidence(
            _disposable(),
            _identity(),
            registration,
            _acl(),
        )


def test_manual_worker_accepts_current_060_attestation() -> None:
    worker.validate_prerequisite_evidence(
        _disposable(), None, _registration(), _acl(), _identity_attestation()
    )


def test_manual_worker_refuses_missing_identity_authority() -> None:
    with pytest.raises(
        worker.RadiusManualWorkerError,
        match="identity_resolver_evidence_invalid",
    ):
        worker.validate_prerequisite_evidence(
            _disposable(), None, _registration(), _acl()
        )


def test_manual_worker_refuses_legacy_059_hash_mismatch_with_attestation() -> None:
    legacy = _identity()
    legacy["migration"].update(
        {"forward_sha256": "0" * 64, "rollback_sha256": "1" * 64}
    )
    with pytest.raises(
        worker.RadiusManualWorkerError,
        match="identity_resolver_evidence_hash_mismatch",
    ):
        worker._validate_identity_authority(legacy, _identity_attestation())


@pytest.mark.parametrize(
    ("migration", "field", "replacement"),
    [
        ("59", "forward_sha256", "0" * 64),
        ("59", "rollback_sha256", "0" * 64),
        ("60", "forward_sha256", "0" * 64),
        ("60", "rollback_sha256", "0" * 64),
        ("59", "version", 58),
        ("60", "version", 61),
    ],
)
def test_manual_worker_refuses_tampered_current_identity_attestation(
    migration: str, field: str, replacement: str | int,
) -> None:
    attestation = _identity_attestation()
    attestation["migrations"][migration][field] = replacement
    with pytest.raises(
        worker.RadiusManualWorkerError,
        match="identity_resolver_attestation_invalid",
    ):
        worker.validate_prerequisite_evidence(
            _disposable(), None, _registration(), _acl(), attestation
        )


def test_manual_worker_refuses_v1_acl_evidence() -> None:
    acl = _acl()
    acl["contract_id"] = "sli.radius-acquisition-evidence-root.v1"
    with pytest.raises(
        worker.RadiusManualWorkerError,
        match="protected_root_evidence_invalid",
    ):
        worker.validate_prerequisite_evidence(
            _disposable(), _identity(), _registration(), acl
        )


def test_child_environment_contains_only_worker_database_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ADLOG_PG_ADMIN_PASSWORD", "admin-secret")
    monkeypatch.setenv("ADLOG_PG_DSN", "admin-dsn")
    monkeypatch.setenv("ADLOG_OTHER_TOKEN", "other-secret")
    monkeypatch.setenv("SAFE_VALUE", "kept")
    monkeypatch.setattr(
        worker,
        "_worker_dsn",
        lambda _lease: "worker-dsn",
    )
    environment = worker._child_environment(
        RadiusManualLease(
            login_role="adlog_radius_manual_a1",
            password="worker-secret",
            source_instance_id=worker._source_id(),
            subscription_id=worker._subscription_id(),
        )
    )
    assert environment["SLI_PLUGIN_PG_DSN"] == "worker-dsn"
    assert environment["SAFE_VALUE"] == "kept"
    assert "ADLOG_PG_ADMIN_PASSWORD" not in environment
    assert "ADLOG_PG_DSN" not in environment
    assert "ADLOG_OTHER_TOKEN" not in environment


def test_manual_worker_creates_missing_evidence_parent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    output = tmp_path / "artifacts" / "stage9" / "evidence" / "run.json"
    monkeypatch.setattr(worker, "ROOT", tmp_path)
    monkeypatch.setattr(
        worker,
        "execute",
        lambda: {
            "status": "passed",
            "source_contacted": True,
            "continuous_runtime_enabled": False,
            "autostart_enabled": False,
        },
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "stage9_radius_manual_worker.py",
            "--action",
            "execute",
            "--confirmation",
            worker.CONFIRMATION,
            "--output",
            str(output),
        ],
    )

    assert worker.main() == 0
    assert output.is_file()


def test_manual_worker_accepts_final_060_attestation_authority() -> None:
    source = Path(worker.__file__).read_text(encoding="utf-8").casefold()
    assert "radius-identity-owner60-production-attestation.json" in source
    assert "production_current_state_attestation" in source

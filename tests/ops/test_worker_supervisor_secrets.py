from __future__ import annotations

import sys

import pytest


def test_preflight_target_is_preserved_and_has_no_forced_default() -> None:
    from server.sli.ops.worker_supervisor_secrets import supervisor_environment_payload

    source = {
        "ADLOG_PG_DSN": "postgresql://example.invalid/example_db",
        "ADLOG_COLLECTION_PRINCIPAL": r"EXAMPLE\operator",
        "ADLOG_COLLECTION_PRINCIPAL_SID": "S-1-5-21-100000001-200000001-300000001-1000",
        "ADLOG_RADIUS_CURSOR_BOOTSTRAP_EVIDENCE_PATH": "D:/runtime/cursor-evidence.json",
        "ADLOG_RADIUS_REGISTRATION_APPLY_EVIDENCE_PATH": "D:/runtime/registration-evidence.json",
    }
    assert "ADLOG_COLLECTION_PREFLIGHT_SERVER" not in supervisor_environment_payload(source)
    source["ADLOG_COLLECTION_PREFLIGHT_SERVER"] = "dc01.example.test"
    assert supervisor_environment_payload(source)["ADLOG_COLLECTION_PREFLIGHT_SERVER"] == "dc01.example.test"
    for key in ("ADLOG_RADIUS_CURSOR_BOOTSTRAP_EVIDENCE_PATH", "ADLOG_RADIUS_REGISTRATION_APPLY_EVIDENCE_PATH"):
        assert supervisor_environment_payload(source)[key] == source[key]


def test_supervisor_environment_is_allowlisted_and_enforces_safe_runtime() -> None:
    from server.sli.ops.worker_supervisor_secrets import supervisor_environment_payload

    payload = supervisor_environment_payload(
        {
            "ADLOG_PG_DSN": "postgresql://example_runtime:example_password@127.0.0.1/example_db",
            "ADLOG_PG_ADMIN_USER": "admin",
            "ADLOG_PG_ADMIN_PASSWORD": "secret",
            "ADLOG_COLLECTION_PRINCIPAL": r"EXAMPLE\operator",
            "ADLOG_COLLECTION_PRINCIPAL_SID": "S-1-5-21-100000004-200000004-300000004-6995",
            "ADLOG_AD_CONTEXT_DOMAIN": "host13.example.invalid",
            "ADLOG_AD_CONTEXT_SEARCH_BASE": "DC=example,DC=local",
            "ADLOG_AD_CONTEXT_PRIVILEGED_GROUP_SIDS": "S-1-5-21-100000001-200000001-300000001-512",
            "ADLOG_AD_CONTEXT_VPN_GROUP_REFERENCES": "S-1-5-21-100000001-200000001-300000001-1701",
            "ADLOG_STORAGE_LIFECYCLE_AUTOMATION_ENABLED": "1",
            "ADLOG_STORAGE_LIFECYCLE_DELETE_ADMISSION": "APPLY-STAGE7-HOT-RETENTION-DELETE",
            "ADLOG_STORAGE_NO_ARCHIVE_DELETE_CONFIRMATION": (
                "DELETE_EXPLICIT_NO_ARCHIVE_ROWS_AFTER_SEMANTIC_COMPLETION"
            ),
            "ADLOG_AUTH_REQUIRED": "1",
            "ADLOG_TLS_CERT_PATH": "D:/runtime/tls/localhost.crt",
            "ADLOG_TLS_KEY_PATH": "D:/runtime/tls/localhost.key",
            "ADLOG_UI_MODE": "postgres",
            "ADLOG_AUTH_PASSWORD": "must-not-be-copied",
            "ADLOG_DISABLE_COLLECTION": "1",
            "UNRELATED": "ignore",
        }
    )

    assert payload["ADLOG_DB_BACKEND"] == "postgres"
    assert payload["ADLOG_COLLECTION_MAX_EVENTS_PER_CHANNEL"] == "50000"
    assert payload["ADLOG_EXTERNAL_STORAGE_V2_OUTBOX_WORKER"] == "1"
    assert payload["ADLOG_AD_CONTEXT_DOMAIN"] == "host13.example.invalid"
    assert payload["ADLOG_DISABLE_SCHEDULER"] == "1"
    # post_collection_worker.py is the sole designated production owner of
    # post-collection; any process that loads the supervisor environment must
    # be forced into external mode, never left on the in-process default.
    assert payload["ADLOG_EXTERNAL_POST_COLLECTION_WORKER"] == "1"
    assert payload["ADLOG_STORAGE_LIFECYCLE_AUTOMATION_ENABLED"] == "1"
    assert payload["ADLOG_STORAGE_LIFECYCLE_DELETE_ADMISSION"] == "APPLY-STAGE7-HOT-RETENTION-DELETE"
    assert payload["ADLOG_STORAGE_NO_ARCHIVE_DELETE_CONFIRMATION"] == (
        "DELETE_EXPLICIT_NO_ARCHIVE_ROWS_AFTER_SEMANTIC_COMPLETION"
    )
    assert payload["ADLOG_AUTH_REQUIRED"] == "1"
    assert payload["ADLOG_TLS_CERT_PATH"].endswith("localhost.crt")
    assert payload["ADLOG_TLS_KEY_PATH"].endswith("localhost.key")
    assert payload["ADLOG_UI_MODE"] == "postgres"
    assert "ADLOG_AUTH_PASSWORD" not in payload
    assert "ADLOG_DISABLE_COLLECTION" not in payload
    assert "UNRELATED" not in payload


def test_supervisor_environment_requires_runtime_dsn() -> None:
    from server.sli.ops.worker_supervisor_secrets import supervisor_environment_payload

    with pytest.raises(RuntimeError, match="ADLOG_PG_DSN"):
        supervisor_environment_payload({})


def test_supervisor_defaults_auth_on_and_preserves_explicit_proxy_opt_out():
    from server.sli.ops.worker_supervisor_secrets import supervisor_environment_payload

    source = {
        "ADLOG_PG_DSN": "host=127.0.0.1 dbname=synthetic",
        "ADLOG_COLLECTION_PRINCIPAL": r"EXAMPLE\operator",
        "ADLOG_COLLECTION_PRINCIPAL_SID": "S-1-5-21-100000004-200000004-300000004-6995",
    }
    assert supervisor_environment_payload(source)["ADLOG_AUTH_REQUIRED"] == "1"
    source.update({
        "ADLOG_AUTH_REQUIRED": "0", "ADLOG_ALLOW_UNAUTHENTICATED": "1",
        "ADLOG_TRUSTED_PROXIES": "192.0.2.2/32",
    })
    payload = supervisor_environment_payload(source)
    for name in ("ADLOG_AUTH_REQUIRED", "ADLOG_ALLOW_UNAUTHENTICATED", "ADLOG_TRUSTED_PROXIES"):
        assert payload[name] == source[name]


def test_supervisor_environment_preserves_configured_identity() -> None:
    from server.sli.ops.worker_supervisor_secrets import supervisor_environment_payload

    payload = supervisor_environment_payload(
        {
            "ADLOG_PG_DSN": "postgresql://example_runtime:example_password@127.0.0.1/example_db",
            "ADLOG_COLLECTION_PRINCIPAL": r"EXAMPLE\\prototype-owner",
            "ADLOG_COLLECTION_PRINCIPAL_SID": "S-1-5-21-100000004-200000004-300000004-6995",
        }
    )

    assert payload["ADLOG_COLLECTION_PRINCIPAL"] == r"EXAMPLE\\prototype-owner"
    assert payload["ADLOG_COLLECTION_PRINCIPAL_SID"].endswith("-6995")


def test_supervisor_environment_preserves_bounded_g11a_probe_authorization() -> None:
    """Dropping any plan-bound field would reopen transient env admission."""

    from server.sli.ops.worker_supervisor_secrets import supervisor_environment_payload

    payload = supervisor_environment_payload(
        {
            "ADLOG_PG_DSN": "postgresql://example.invalid/example_db",
            "ADLOG_COLLECTION_PRINCIPAL": r"EXAMPLE\operator",
            "ADLOG_COLLECTION_PRINCIPAL_SID": (
                "S-1-5-21-100000001-200000001-300000001-1000"
            ),
            "SLI_G11A3_DIRECTORY_SERVER": "directory.example.invalid",
            "SLI_G11A3_VPN_GROUP_SID": (
                "S-1-5-21-100000001-200000001-300000001-1001"
            ),
            "SLI_G11A3_PROBE_PLAN_ID": "G11A3-PROBE-CLOSED-GENERATION-V4",
        }
    )

    assert payload["SLI_G11A3_DIRECTORY_SERVER"] == "directory.example.invalid"
    assert payload["SLI_G11A3_VPN_GROUP_SID"].endswith("-1001")
    assert payload["SLI_G11A3_PROBE_PLAN_ID"] == (
        "G11A3-PROBE-CLOSED-GENERATION-V4"
    )


def test_supervisor_raw_cleanup_admission_updates_only_exact_flag(monkeypatch) -> None:
    from scripts.maintenance import worker_supervisor
    from server.sli.ops.worker_supervisor_secrets import WORKER_ENV_ALLOWLIST

    expected = {"ADLOG_DELETE_IMPORTED_RAW": "1"}
    assert set(expected) <= WORKER_ENV_ALLOWLIST
    observed: list[dict[str, str]] = []
    monkeypatch.setattr(
        worker_supervisor,
        "update_supervisor_environment",
        lambda updates: observed.append(dict(updates)) or {"status": "ok"},
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "worker_supervisor.py",
            "--admit-raw-cleanup",
            "--confirmation",
            "ENABLE-CONFIRMED-RAW-CLEANUP",
        ],
    )

    assert worker_supervisor.main() == 0
    assert observed == [expected]


def test_supervisor_copy_only_lifecycle_admission_denies_all_delete_lanes(monkeypatch) -> None:
    from scripts.maintenance import worker_supervisor
    from server.sli.ops.worker_supervisor_secrets import WORKER_ENV_ALLOWLIST

    expected = {
        "ADLOG_STORAGE_LIFECYCLE_AUTOMATION_ENABLED": "1",
        "ADLOG_STORAGE_LIFECYCLE_WARM_COPY_ADMISSION": "START-STAGE7-WARM-INCREMENTAL-COPY",
        "ADLOG_STORAGE_LIFECYCLE_DELETE_ADMISSION": "0",
        "ADLOG_STORAGE_NO_ARCHIVE_DELETE_CONFIRMATION": "0",
        "ADLOG_STORAGE_LIFECYCLE_DELETE_EXECUTION_ENABLED": "0",
    }
    assert set(expected) <= WORKER_ENV_ALLOWLIST
    observed: list[dict[str, str]] = []
    monkeypatch.setattr(
        worker_supervisor,
        "update_supervisor_environment",
        lambda updates: observed.append(dict(updates)) or {"status": "ok"},
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "worker_supervisor.py",
            "--admit-storage-lifecycle-copy-only",
            "--confirmation",
            "ENABLE-STORAGE-LIFECYCLE-COPY-ONLY",
        ],
    )

    assert worker_supervisor.main() == 0
    assert observed == [expected]


def test_supervisor_full_lifecycle_admission_enables_new_delete_execution_gate(monkeypatch) -> None:
    from scripts.maintenance import worker_supervisor

    observed: list[dict[str, str]] = []
    monkeypatch.setattr(
        worker_supervisor,
        "update_supervisor_environment",
        lambda updates: observed.append(dict(updates)) or {"status": "ok"},
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "worker_supervisor.py",
            "--admit-storage-lifecycle",
            "--confirmation",
            "ENABLE-STORAGE-LIFECYCLE-AUTOMATION",
        ],
    )

    assert worker_supervisor.main() == 0
    assert observed == [{
        "ADLOG_STORAGE_LIFECYCLE_AUTOMATION_ENABLED": "1",
        "ADLOG_STORAGE_LIFECYCLE_DELETE_ADMISSION": "APPLY-STAGE7-HOT-RETENTION-DELETE",
        "ADLOG_STORAGE_LIFECYCLE_DELETE_EXECUTION_ENABLED": "1",
    }]


@pytest.fixture
def fake_supervisor_dpapi(monkeypatch):
    import sys
    from types import SimpleNamespace

    from server.sli.ops import worker_supervisor_secrets as module

    prefix = b"fake-supervisor-dpapi:"

    def protect(data: bytes, _description: str, *_args: object) -> bytes:
        return prefix + bytes(data)

    def unprotect(blob: bytes, *_args: object) -> tuple[str, bytes]:
        assert bytes(blob).startswith(prefix)
        return "fake-supervisor-dpapi", bytes(blob)[len(prefix) :]

    monkeypatch.setitem(
        sys.modules,
        "win32crypt",
        SimpleNamespace(
            CryptProtectData=protect,
            CryptUnprotectData=unprotect,
        ),
    )
    monkeypatch.setattr(module.os, "name", "nt")
    monkeypatch.setattr(module, "_current_user_sid", lambda: "S-1-5-21-100000001-200000001-300000001-1000")
    monkeypatch.setattr(module, "_ensure_web_service_identity", lambda _sid: None)
    monkeypatch.setattr(module, "_write_protected_blob", lambda path, blob: path.write_bytes(blob))


def test_supervisor_preserves_explicit_nps_admission_without_default_enable():
    from server.sli.ops.worker_supervisor_secrets import supervisor_environment_payload

    source = {
        "ADLOG_PG_DSN": "postgresql://example.invalid/example_db",
        "ADLOG_COLLECTION_PRINCIPAL": r"EXAMPLE\operator",
        "ADLOG_COLLECTION_PRINCIPAL_SID": "S-1-5-21-100000001-200000001-300000001-1000",
    }
    assert "ADLOG_NPS_EVENTLOG_ENABLED" not in supervisor_environment_payload(source)
    for enabled in ("0", "1"):
        assert supervisor_environment_payload({
            **source, "ADLOG_NPS_EVENTLOG_ENABLED": enabled,
        })["ADLOG_NPS_EVENTLOG_ENABLED"] == enabled


def test_supervisor_environment_dpapi_round_trips_scoped_activation_gate_without_disclosure(
    tmp_path, fake_supervisor_dpapi, capsys
) -> None:
    import json

    from server.sli.ops.worker_supervisor_secrets import (
        load_supervisor_environment,
        provision_supervisor_environment,
        supervisor_environment_payload,
    )

    gate_path_key = "ADLOG_SCOPED_ACTIVATION_GATE_PATH"
    gate_digest_key = "ADLOG_SCOPED_ACTIVATION_GATE_SHA256"
    unrelated_key = "UNRELATED_SUPPLIED_VALUE"
    gate_path_value = str(tmp_path / "approved-scoped-activation-gate.json")
    gate_digest_value = "a" * 64
    source = {
        "ADLOG_PG_DSN": "postgresql://example.invalid/example_db",
        "ADLOG_COLLECTION_PRINCIPAL": r"EXAMPLE\\operator",
        "ADLOG_COLLECTION_PRINCIPAL_SID": "S-1-5-21-100000001-200000001-300000001-1000",
        gate_path_key: gate_path_value,
        gate_digest_key: gate_digest_value,
        unrelated_key: "must-be-filtered",
    }

    payload = supervisor_environment_payload(source)

    assert payload[gate_path_key] == gate_path_value
    assert payload[gate_digest_key] == gate_digest_value
    assert unrelated_key not in payload

    dpapi_path = tmp_path / "worker-supervisor.env.dpapi"
    provisioned = provision_supervisor_environment(source=source, path=dpapi_path)
    target = {
        gate_path_key: "inherited-gate-path",
        gate_digest_key: "inherited-gate-digest",
    }
    loaded = load_supervisor_environment(
        target=target,
        path=dpapi_path,
        override_existing=True,
    )

    assert target[gate_path_key] == gate_path_value
    assert target[gate_digest_key] == gate_digest_value
    assert unrelated_key not in target
    rendered_provisioned = json.dumps(provisioned, sort_keys=True)
    rendered_loaded = json.dumps(loaded, sort_keys=True)
    assert gate_path_value not in rendered_provisioned
    assert gate_digest_value not in rendered_provisioned
    assert gate_path_value not in rendered_loaded
    assert gate_digest_value not in rendered_loaded
    captured = capsys.readouterr()
    assert gate_path_value not in captured.out
    assert gate_digest_value not in captured.out
    assert gate_path_value not in captured.err
    assert gate_digest_value not in captured.err


def test_disarmed_v2_repair_digest_is_removed_from_an_inherited_target(
    tmp_path, fake_supervisor_dpapi,
) -> None:
    from server.sli.ops.worker_supervisor_secrets import (
        load_supervisor_environment,
        provision_supervisor_environment,
    )

    digest_key = "ADLOG_SEMANTIC_V2_QUARANTINE_REPAIR_PLAN_DIGEST"
    path = tmp_path / "worker-supervisor.env.dpapi"
    provision_supervisor_environment(
        source={
            "ADLOG_PG_DSN": "postgresql://example.invalid/example_db",
            "ADLOG_COLLECTION_PRINCIPAL": r"EXAMPLE\operator",
            "ADLOG_COLLECTION_PRINCIPAL_SID": "S-1-5-21-100000001-200000001-300000001-1000",
        },
        path=path,
    )
    target = {digest_key: "a" * 64}

    load_supervisor_environment(target=target, path=path, override_existing=True)

    assert digest_key not in target


def test_supervisor_arms_and_disarms_only_the_exact_v2_repair_digest(monkeypatch) -> None:
    from scripts.maintenance import worker_supervisor

    digest = "a" * 64
    updates: list[dict[str, str]] = []
    removals: list[set[str]] = []
    monkeypatch.setattr(
        worker_supervisor,
        "update_supervisor_environment",
        lambda values: updates.append(dict(values)) or {"status": "ok"},
    )
    monkeypatch.setattr(
        worker_supervisor,
        "remove_supervisor_environment_keys",
        lambda values: removals.append(set(values)) or {"status": "ok"},
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "worker_supervisor.py", "--arm-semantic-v2-quarantine-repair", digest,
            "--confirmation", "ARM-SEMANTIC-V2-QUARANTINE-REPAIR:" + digest,
        ],
    )
    assert worker_supervisor.main() == 0
    assert updates == [{"ADLOG_SEMANTIC_V2_QUARANTINE_REPAIR_PLAN_DIGEST": digest}]
    assert removals == []

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "worker_supervisor.py", "--disarm-semantic-v2-quarantine-repair",
            "--confirmation", "DISARM-SEMANTIC-V2-QUARANTINE-REPAIR",
        ],
    )
    assert worker_supervisor.main() == 0
    assert removals == [{"ADLOG_SEMANTIC_V2_QUARANTINE_REPAIR_PLAN_DIGEST"}]


def test_supervisor_dpapi_removal_round_trip_preserves_other_keys_without_disclosure(
    tmp_path, fake_supervisor_dpapi, capsys,
) -> None:
    import json

    from server.sli.ops.worker_supervisor_secrets import (
        load_supervisor_environment,
        provision_supervisor_environment,
        remove_supervisor_environment_keys,
    )

    digest_key = "ADLOG_SEMANTIC_V2_QUARANTINE_REPAIR_PLAN_DIGEST"
    digest = "a" * 64
    path = tmp_path / "worker-supervisor.env.dpapi"
    source = {
        "ADLOG_PG_DSN": "postgresql://example.invalid/example_db",
        "ADLOG_COLLECTION_PRINCIPAL": r"EXAMPLE\operator",
        "ADLOG_COLLECTION_PRINCIPAL_SID": "S-1-5-21-100000001-200000001-300000001-1000",
        "ADLOG_SEMANTIC_PRODUCTION_ENABLED": "1",
        digest_key: digest,
    }
    provision_supervisor_environment(source=source, path=path)

    removed = remove_supervisor_environment_keys([digest_key], path=path)
    target: dict[str, str] = {}
    load_supervisor_environment(target=target, path=path, override_existing=True)

    assert removed["removed_keys"] == [digest_key]
    assert target["ADLOG_PG_DSN"] == source["ADLOG_PG_DSN"]
    assert target["ADLOG_SEMANTIC_PRODUCTION_ENABLED"] == "1"
    assert digest_key not in target
    with pytest.raises(RuntimeError, match="removal is not permitted"):
        remove_supervisor_environment_keys(["ADLOG_SEMANTIC_PRODUCTION_ENABLED"], path=path)
    assert digest not in json.dumps(removed, sort_keys=True)
    captured = capsys.readouterr()
    assert digest not in captured.out
    assert digest not in captured.err


def test_revoke_then_investigation_admission_does_not_resurrect_v2_repair_scope(
    tmp_path, fake_supervisor_dpapi, monkeypatch,
) -> None:
    from scripts.maintenance import worker_supervisor
    from server.sli.ops import worker_supervisor_secrets as secrets

    digest_key = "ADLOG_SEMANTIC_V2_QUARANTINE_REPAIR_PLAN_DIGEST"
    digest = "a" * 64
    path = tmp_path / "worker-supervisor.env.dpapi"
    source = {
        "ADLOG_PG_DSN": "postgresql://example.invalid/example_db",
        "ADLOG_COLLECTION_PRINCIPAL": r"EXAMPLE\operator",
        "ADLOG_COLLECTION_PRINCIPAL_SID": "S-1-5-21-100000001-200000001-300000001-1000",
        "ADLOG_SEMANTIC_PRODUCTION_ENABLED": "1",
        "ADLOG_SEMANTIC_RUNTIME_MODE": "investigation-v1",
        "ADLOG_SEMANTIC_NORMALIZATION_ENABLED": "1",
        "ADLOG_SEMANTIC_ASSEMBLY_ENABLED": "1",
        "ADLOG_SEMANTIC_CORRELATION_ENABLED": "1",
        digest_key: digest,
    }
    secrets.provision_supervisor_environment(source=source, path=path)
    monkeypatch.setattr(
        worker_supervisor,
        "update_supervisor_environment_with_removals",
        lambda updates, removals: secrets.update_supervisor_environment_with_removals(
            updates, remove_keys=removals, path=path,
        ),
    )
    monkeypatch.setattr(
        worker_supervisor,
        "update_supervisor_environment",
        lambda updates: secrets.update_supervisor_environment(updates, path=path),
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "worker_supervisor.py", "--revoke-semantic-production",
            "--confirmation", "DISABLE-CONTINUOUS-SEMANTIC-PRODUCTION",
        ],
    )
    assert worker_supervisor.main() == 0
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "worker_supervisor.py", "--admit-semantic-investigation",
            "--confirmation", "ENABLE-CONTINUOUS-SEMANTIC-INVESTIGATION",
        ],
    )
    assert worker_supervisor.main() == 0

    target: dict[str, str] = {}
    secrets.load_supervisor_environment(target=target, path=path, override_existing=True)
    assert target["ADLOG_SEMANTIC_PRODUCTION_ENABLED"] == "1"
    assert target["ADLOG_SEMANTIC_RUNTIME_MODE"] == "investigation-v1"
    assert digest_key not in target

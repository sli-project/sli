from __future__ import annotations

from contextlib import contextmanager
import json

import pytest


pytestmark = pytest.mark.core


@pytest.mark.parametrize(
    ("module_name", "lock_name", "expected_exit"),
    [
        ("collection_worker", "collection_process_lock", 9),
        ("post_collection_worker", "post_collection_worker_lock", 9),
        ("entity_state_worker", "entity_state_worker_lock", 0),
    ],
)
def test_protected_environment_is_loaded_before_process_lock(
    monkeypatch,
    module_name: str,
    lock_name: str,
    expected_exit: int,
) -> None:
    module = __import__(
        f"scripts.runtime.{module_name}", fromlist=[module_name]
    )
    from server.sli.ops import worker_supervisor_secrets

    order: list[str] = []

    def load_environment() -> dict[str, object]:
        order.append("load")
        return {
            "status": "ok",
            "keys": ["ADLOG_PG_DSN"],
            "credential_values_exposed": False,
        }

    @contextmanager
    def rejected_lock():
        order.append("lock")
        yield False

    monkeypatch.setattr(
        worker_supervisor_secrets,
        "load_supervisor_environment",
        load_environment,
    )
    monkeypatch.setattr(module, lock_name, rejected_lock)
    monkeypatch.setattr(
        module.sys,
        "argv",
        [f"{module_name}.py", "--load-supervisor-environment", "--once"],
    )

    assert module.main() == expected_exit
    assert order == ["load", "lock"]


@pytest.mark.parametrize(
    ("module_name", "lock_name"),
    [
        ("collection_worker", "collection_process_lock"),
        ("post_collection_worker", "post_collection_worker_lock"),
        ("entity_state_worker", "entity_state_worker_lock"),
    ],
)
def test_legacy_worker_cli_does_not_load_protected_environment(
    monkeypatch,
    module_name: str,
    lock_name: str,
) -> None:
    module = __import__(
        f"scripts.runtime.{module_name}", fromlist=[module_name]
    )
    from server.sli.ops import worker_supervisor_secrets

    @contextmanager
    def rejected_lock():
        yield False

    monkeypatch.setattr(module, lock_name, rejected_lock)
    monkeypatch.setattr(
        worker_supervisor_secrets,
        "load_supervisor_environment",
        lambda: (_ for _ in ()).throw(
            AssertionError("legacy CLI must not load the protected environment")
        ),
    )
    monkeypatch.setattr(module.sys, "argv", [f"{module_name}.py", "--once"])

    module.main()


def test_ad_context_protected_mode_resolves_all_settings_without_cli_values(
    monkeypatch,
) -> None:
    from scripts.runtime import ad_context_snapshot_worker as module
    from server.sli.ops import worker_supervisor_secrets

    protected = {
        "ADLOG_AD_CONTEXT_DIRECTORY_SERVER": "dc-protected.example.test",
        "ADLOG_AD_CONTEXT_DOMAIN": "protected.example.test",
        "ADLOG_AD_CONTEXT_SEARCH_BASE": "DC=protected,DC=example,DC=test",
        "ADLOG_AD_CONTEXT_PRIVILEGED_GROUP_SIDS": "S-1-5-21-100000001-200000001-300000001-1001",
        "ADLOG_AD_CONTEXT_VPN_GROUP_REFERENCES": "S-1-5-21-100000001-200000001-300000001-1002",
    }
    captured: dict[str, object] = {}

    def load_environment() -> dict[str, object]:
        for name, value in protected.items():
            monkeypatch.setenv(name, value)
        return {
            "status": "ok",
            "keys": sorted(protected),
            "credential_values_exposed": False,
        }

    def run(config, *, once: bool) -> int:
        captured["config"] = config
        captured["once"] = once
        return 0

    monkeypatch.setattr(
        worker_supervisor_secrets,
        "load_supervisor_environment",
        load_environment,
    )
    monkeypatch.setattr(module, "run", run)

    assert module.main(["--load-supervisor-environment", "--once"]) == 0
    config = captured["config"]
    assert config.directory_server == protected["ADLOG_AD_CONTEXT_DIRECTORY_SERVER"]
    assert config.domain == protected["ADLOG_AD_CONTEXT_DOMAIN"]
    assert config.search_base == protected["ADLOG_AD_CONTEXT_SEARCH_BASE"]
    assert config.privileged_group_sids == (
        protected["ADLOG_AD_CONTEXT_PRIVILEGED_GROUP_SIDS"],
    )
    assert config.vpn_group_references == (
        protected["ADLOG_AD_CONTEXT_VPN_GROUP_REFERENCES"],
    )
    assert captured["once"] is True


def test_ad_context_protected_mode_uses_normal_directory_server_fallback(
    monkeypatch,
) -> None:
    from scripts.runtime import ad_context_snapshot_worker as module
    from server.sli.ops import worker_supervisor_secrets

    def load_environment() -> dict[str, object]:
        monkeypatch.delenv("ADLOG_AD_CONTEXT_DIRECTORY_SERVER", raising=False)
        monkeypatch.setenv("ADLOG_COLLECTION_PREFLIGHT_SERVER", "DC2")
        monkeypatch.setenv("ADLOG_AD_CONTEXT_DOMAIN", "example.test")
        monkeypatch.setenv("ADLOG_AD_CONTEXT_SEARCH_BASE", "DC=example,DC=test")
        monkeypatch.setenv(
            "ADLOG_AD_CONTEXT_PRIVILEGED_GROUP_SIDS",
            "S-1-5-21-100000002-200000002-300000002-1001",
        )
        monkeypatch.setenv(
            "ADLOG_AD_CONTEXT_VPN_GROUP_REFERENCES",
            "S-1-5-21-100000002-200000002-300000002-1002",
        )
        return {"status": "ok", "credential_values_exposed": False}

    captured: dict[str, object] = {}
    monkeypatch.setattr(
        worker_supervisor_secrets,
        "load_supervisor_environment",
        load_environment,
    )
    monkeypatch.setattr(
        module,
        "run",
        lambda config, *, once: captured.setdefault("config", config) and 0,
    )

    assert module.main(["--load-supervisor-environment", "--once"]) == 0
    assert captured["config"].directory_server == "DC2"


def test_ad_context_protected_mode_fails_closed_without_disclosing_values(
    monkeypatch,
    capsys,
) -> None:
    from scripts.runtime import ad_context_snapshot_worker as module
    from server.sli.ops import worker_supervisor_secrets

    sentinels = {
        "ADLOG_PG_DSN": "postgresql://example_user:example_password@db.example.test/sli",
        "ADLOG_PG_ADMIN_PASSWORD": "SECRET-ADMIN-PASSWORD",
        "ADLOG_COLLECTION_PRINCIPAL_SID": "S-1-5-21-100000007-200000008-300000009-6995",
        "ADLOG_AD_CONTEXT_DIRECTORY_SERVER": "SECRET-DIRECTORY-SERVER",
        "ADLOG_AD_CONTEXT_DOMAIN": "secret-domain.example.test",
        "ADLOG_AD_CONTEXT_PRIVILEGED_GROUP_SIDS": "S-1-5-21-100000007-200000008-300000009-1001",
        "ADLOG_AD_CONTEXT_VPN_GROUP_REFERENCES": "S-1-5-21-100000007-200000008-300000009-1002",
    }

    def load_environment() -> dict[str, object]:
        for name, value in sentinels.items():
            monkeypatch.setenv(name, value)
        monkeypatch.delenv("ADLOG_AD_CONTEXT_SEARCH_BASE", raising=False)
        return {
            "status": "ok",
            "keys": sorted(sentinels),
            "credential_values_exposed": False,
        }

    monkeypatch.setattr(
        worker_supervisor_secrets,
        "load_supervisor_environment",
        load_environment,
    )
    monkeypatch.setattr(
        module,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("source contact must not start")
        ),
    )

    assert module.main(["--load-supervisor-environment", "--once"]) == 2
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload == {
        "status": "refused",
        "reason": "ad_context_snapshot_configuration_missing",
        "missing": ["ADLOG_AD_CONTEXT_SEARCH_BASE"],
    }
    combined = captured.out + captured.err
    assert all(secret not in combined for secret in sentinels.values())


def test_ad_context_legacy_mode_still_requires_explicit_cli_settings() -> None:
    from scripts.runtime import ad_context_snapshot_worker as module

    with pytest.raises(SystemExit) as exc:
        module.parse_args(["--once"])

    assert exc.value.code == 2

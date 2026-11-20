from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest


def test_status_is_read_only_and_does_not_load_dpapi_environment(monkeypatch, capsys) -> None:
    from scripts.maintenance import http_copy_control as module
    from scripts.maintenance import server_control

    def fail_if_loaded() -> None:
        raise AssertionError("status must not load the protected runtime environment")

    monkeypatch.setattr(module, "load_supervisor_environment", fail_if_loaded)
    monkeypatch.setattr(
        server_control,
        "health",
        lambda url: {
            "status": "ok",
            "summary": {
                "runtime_identity": {
                    "runtime_instance_id": "runtime-test",
                    "build_id": "build-test",
                }
            },
        },
    )
    monkeypatch.setattr(server_control, "_listening_pids", lambda port: [3210])
    monkeypatch.setattr(sys, "argv", ["http_copy_control.py", "status"])

    assert module.main() == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["url"] == "http://127.0.0.1:18082/api/health"
    assert payload["runtime_identity"]["runtime_instance_id"] == "runtime-test"
    assert payload["status"] == "failed"
    assert payload["failure_reason"] == "http_copy_port_owner_mismatch"
    assert payload["listening_pids"] == [3210]


def test_http_copy_has_foreground_serve_mode_for_tool_job_lifetime() -> None:
    source = Path("scripts/maintenance/http_copy_control.py").read_text(encoding="utf-8")
    assert 'choices=("status", "restart", "serve")' in source
    assert 'if args.action == "serve"' in source
    assert '"ADLOG_RUNTIME_INSTANCE_ID"' in source
    assert "run_server(" in source


def test_status_confirms_single_listener_matching_health_pid(
    monkeypatch, capsys, tmp_path: Path
) -> None:
    from scripts.maintenance import http_copy_control as module
    from scripts.maintenance import server_control

    monkeypatch.setattr(
        module,
        "load_supervisor_environment",
        lambda: (_ for _ in ()).throw(AssertionError("status must stay read-only")),
    )
    monkeypatch.setattr(
        server_control,
        "health",
        lambda url: {
            "status": "ok",
            "summary": {
                "runtime_identity": {
                    "runtime_instance_id": "runtime-test",
                    "process_pid": 4408,
                }
            },
        },
    )
    monkeypatch.setattr(server_control, "_listening_pids", lambda port: [4408])
    monkeypatch.setattr(module, "STATE_PATH", tmp_path / "missing-state.json")
    monkeypatch.setattr(sys, "argv", ["http_copy_control.py", "status"])

    assert module.main() == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["listening_pids"] == [4408]
    assert payload["identity_verified"] is True
    assert payload["port_owner_verified"] is True
    assert payload["react_dir"] is None
    assert payload["react_dir_state"] == "missing"


def test_runtime_state_is_reported_only_for_the_matching_process(
    monkeypatch, tmp_path: Path
) -> None:
    from scripts.maintenance import http_copy_control as module

    react_dir = tmp_path / "project" / "web" / "app" / "react"
    react_dir.mkdir(parents=True)
    (react_dir / "index.html").write_text("<!doctype html>", encoding="utf-8")
    state_path = tmp_path / "http-copy-control.json"
    monkeypatch.setattr(module, "ROOT", tmp_path / "project")
    result = {
        "runtime_identity": {
            "runtime_instance_id": "runtime-current",
            "process_pid": 4408,
        }
    }

    module._write_runtime_state(react_dir, result, state_path=state_path)

    assert module._read_verified_runtime_state(
        result["runtime_identity"], state_path=state_path
    ) == (str(react_dir.resolve()), "verified")
    assert module._read_verified_runtime_state(
        {"runtime_instance_id": "runtime-other", "process_pid": 4408},
        state_path=state_path,
    ) == (None, "stale")


def test_restart_configuration_loads_secrets_and_forces_loopback_guards(
    monkeypatch, tmp_path
) -> None:
    from scripts.maintenance import http_copy_control as module

    react_dir = tmp_path / "react"
    react_dir.mkdir()
    (react_dir / "index.html").write_text("<!doctype html>", encoding="utf-8")
    monkeypatch.setattr(module, "ROOT", tmp_path)
    loaded: list[dict[str, object]] = []
    for name in (
        "ADLOG_DISABLE_SCHEDULER",
        "ADLOG_DISABLE_COLLECTION",
        "ADLOG_CONTINUOUS_RECOVERY",
        "ADLOG_AUTH_ALLOW_INSECURE_HTTP",
        "ADLOG_AUTH_COOKIE_SECURE",
        "ADLOG_TLS_CERT_PATH",
        "ADLOG_TLS_KEY_PATH",
        "ADLOG_REACT_WEB_DIR",
    ):
        monkeypatch.setenv(name, "test-original")
    def load_default_profile(**kwargs: object) -> dict[str, object]:
        loaded.append(dict(kwargs))
        os.environ.update({
            "ADLOG_PG_DSN": "postgresql://redacted",
            "ADLOG_DB_BACKEND": "postgres",
            "ADLOG_AUTH_REQUIRED": "1",
        })
        return {"status": "ok"}

    monkeypatch.setattr(module, "load_supervisor_environment", load_default_profile)

    module._configure(react_dir)

    assert loaded == [{"override_existing": True}]
    assert module.os.environ["ADLOG_DISABLE_SCHEDULER"] == "1"
    assert module.os.environ["ADLOG_DISABLE_COLLECTION"] == "1"
    assert module.os.environ["ADLOG_CONTINUOUS_RECOVERY"] == "false"
    assert module.os.environ["ADLOG_AUTH_ALLOW_INSECURE_HTTP"] == "1"
    assert module.os.environ["ADLOG_AUTH_COOKIE_SECURE"] == "0"
    assert module.os.environ["ADLOG_TLS_CERT_PATH"] == ""
    assert module.os.environ["ADLOG_TLS_KEY_PATH"] == ""
    assert module.os.environ["ADLOG_REACT_WEB_DIR"] == str(react_dir)


def test_configuration_rejects_react_dir_outside_candidate_root_before_profile_load(
    monkeypatch, tmp_path: Path
) -> None:
    from scripts.maintenance import http_copy_control as module

    candidate_root = tmp_path / "candidate"
    candidate_root.mkdir()
    foreign_react = tmp_path / "foreign" / "react"
    foreign_react.mkdir(parents=True)
    (foreign_react / "index.html").write_text("<!doctype html>", encoding="utf-8")
    loaded: list[object] = []
    monkeypatch.setattr(module, "ROOT", candidate_root)
    monkeypatch.setattr(module, "load_supervisor_environment", lambda **kwargs: loaded.append(kwargs))

    with pytest.raises(RuntimeError, match="candidate root"):
        module._configure(foreign_react)

    assert loaded == []


def test_configuration_rejects_missing_runtime_dsn_before_listener_control(
    monkeypatch, tmp_path: Path
) -> None:
    from scripts.maintenance import http_copy_control as module

    candidate_root = tmp_path / "candidate"
    react_dir = candidate_root / "web" / "app" / "react"
    react_dir.mkdir(parents=True)
    (react_dir / "index.html").write_text("<!doctype html>", encoding="utf-8")
    monkeypatch.setattr(module, "ROOT", candidate_root)
    monkeypatch.delenv("ADLOG_PG_DSN", raising=False)
    monkeypatch.setenv("ADLOG_DB_BACKEND", "postgres")
    monkeypatch.setenv("ADLOG_AUTH_REQUIRED", "1")
    monkeypatch.setattr(module, "load_supervisor_environment", lambda **kwargs: {"status": "ok"})

    with pytest.raises(RuntimeError, match="runtime PostgreSQL DSN"):
        module._configure(react_dir)


def test_configuration_rejects_missing_authentication_before_listener_control(
    monkeypatch, tmp_path: Path
) -> None:
    from scripts.maintenance import http_copy_control as module

    candidate_root = tmp_path / "candidate"
    react_dir = candidate_root / "web" / "app" / "react"
    react_dir.mkdir(parents=True)
    (react_dir / "index.html").write_text("<!doctype html>", encoding="utf-8")
    monkeypatch.setattr(module, "ROOT", candidate_root)
    monkeypatch.setenv("ADLOG_PG_DSN", "postgresql://redacted")
    monkeypatch.setenv("ADLOG_DB_BACKEND", "postgres")
    monkeypatch.delenv("ADLOG_AUTH_REQUIRED", raising=False)
    monkeypatch.setattr(module, "load_supervisor_environment", lambda **kwargs: {"status": "ok"})

    with pytest.raises(RuntimeError, match="authentication must be enabled"):
        module._configure(react_dir)


def test_configuration_loads_explicit_profile_and_strips_privileged_http_child_values(
    monkeypatch, tmp_path: Path
) -> None:
    from scripts.maintenance import http_copy_control as module
    from server.sli.ops.worker_supervisor_secrets import HTTP_FORBIDDEN_ENVIRONMENT

    candidate_root = tmp_path / "candidate"
    react_dir = candidate_root / "web" / "app" / "react"
    react_dir.mkdir(parents=True)
    (react_dir / "index.html").write_text("<!doctype html>", encoding="utf-8")
    profile_path = tmp_path / "current-user.env.dpapi"
    loaded: list[dict[str, object]] = []
    monkeypatch.setattr(module, "ROOT", candidate_root)

    def load_profile(**kwargs: object) -> dict[str, object]:
        loaded.append(dict(kwargs))
        os.environ.update({
            "ADLOG_PG_DSN": "postgresql://redacted",
            "ADLOG_DB_BACKEND": "postgres",
            "ADLOG_AUTH_REQUIRED": "1",
            "ADLOG_LOG_DIR": str(tmp_path / "production-logs"),
            **{name: "must-not-reach-http" for name in HTTP_FORBIDDEN_ENVIRONMENT},
        })
        return {"status": "ok"}

    monkeypatch.setattr(module, "load_supervisor_environment", load_profile)

    module._configure(react_dir, environment_file=profile_path)

    assert loaded == [{"path": profile_path, "override_existing": True}]
    assert all(name not in os.environ for name in HTTP_FORBIDDEN_ENVIRONMENT)
    assert os.environ["ADLOG_LOG_DIR"] == str(candidate_root / "data" / "logs")


@pytest.mark.parametrize("use_explicit_profile", (False, True))
def test_configuration_makes_sealed_profile_authoritative_over_inherited_runtime_values(
    monkeypatch, tmp_path: Path, use_explicit_profile: bool
) -> None:
    from scripts.maintenance import http_copy_control as module

    candidate_root = tmp_path / "candidate"
    react_dir = candidate_root / "web" / "app" / "react"
    react_dir.mkdir(parents=True)
    (react_dir / "index.html").write_text("<!doctype html>", encoding="utf-8")
    profile_path = tmp_path / "current-user.env.dpapi"
    loaded: list[dict[str, object]] = []
    sealed_values = {
        "ADLOG_PG_DSN": "postgresql://sealed-profile",
        "ADLOG_DB_BACKEND": "postgres",
        "ADLOG_AUTH_REQUIRED": "1",
    }
    monkeypatch.setattr(module, "ROOT", candidate_root)
    monkeypatch.setenv("ADLOG_PG_DSN", "postgresql://inherited-shell")
    monkeypatch.setenv("ADLOG_DB_BACKEND", "sqlite")
    monkeypatch.setenv("ADLOG_AUTH_REQUIRED", "0")

    def load_profile(**kwargs: object) -> dict[str, object]:
        loaded.append(dict(kwargs))
        if kwargs.get("override_existing"):
            os.environ.update(sealed_values)
        else:
            for name, value in sealed_values.items():
                os.environ.setdefault(name, value)
        return {"status": "ok"}

    monkeypatch.setattr(module, "load_supervisor_environment", load_profile)

    module._configure(
        react_dir,
        environment_file=profile_path if use_explicit_profile else None,
    )

    assert loaded == [
        {
            "override_existing": True,
            **({"path": profile_path} if use_explicit_profile else {}),
        }
    ]
    assert os.environ["ADLOG_PG_DSN"] == sealed_values["ADLOG_PG_DSN"]
    assert os.environ["ADLOG_DB_BACKEND"] == "postgres"
    assert os.environ["ADLOG_AUTH_REQUIRED"] == "1"


def test_restart_refuses_legacy_http_copy_listener_before_canonical_restart(
    monkeypatch, capsys, tmp_path: Path
) -> None:
    from scripts.maintenance import http_copy_control as module
    from scripts.maintenance import server_control

    restart_calls: list[dict[str, object]] = []
    react_dir = tmp_path / "candidate" / "web" / "app" / "react"
    react_dir.mkdir(parents=True)
    (react_dir / "index.html").write_text("<!doctype html>", encoding="utf-8")
    monkeypatch.setattr(module, "STATE_PATH", tmp_path / "http-copy-control.json")
    monkeypatch.setattr(module, "_configure", lambda *args, **kwargs: None)
    monkeypatch.setattr(server_control, "_listening_pids", lambda port: [8101] if port == 8081 else [])
    monkeypatch.setattr(
        server_control,
        "restart",
        lambda **kwargs: restart_calls.append(kwargs) or {
            "status": "ok",
            "runtime_identity": {"runtime_instance_id": "candidate", "process_pid": 18082},
        },
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["http_copy_control.py", "restart", "--react-dir", str(react_dir)],
    )

    assert module.main() == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "failed"
    assert payload["failure_reason"] == "legacy_http_copy_listener_present"
    assert restart_calls == []

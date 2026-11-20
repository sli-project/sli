from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.install import sli_install as inst
from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory

SECRET_PASSWORD = "Zq-very-secret-9917"
DSN_SECRET = "dsn-secret-8842"
VERSIONS = {item.version for item in forward_migration_inventory(inst.ROOT / "config" / "postgres_migrations")}


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for name in ("ADLOG_PG_DSN", "ADLOG_PG_ADMIN_PASSWORD", "ADLOG_PG_ADMIN_USER",
                 "SLI_ADMIN_PASSWORD", "SLI_PG_BIN_DIR", "SLI_PG_DATA_DIR"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ADLOG_PG_DSN", f"host=127.0.0.1 port=55433 dbname=sli_local user=adlog_user password={DSN_SECRET}")
    monkeypatch.setattr(inst, "_frontend_built", lambda root: True)
    calls: list[tuple] = []
    monkeypatch.setattr(inst, "run_child", lambda argv, **kw: calls.append((list(argv), kw)) or (0, "{}"))
    monkeypatch.setattr(inst, "create_admin_user", lambda u, p: calls.append(("user", u)))
    monkeypatch.setattr(inst, "probe_database", lambda dsn: {"reachable": False})
    return calls


def _installed(**over):
    state = {"reachable": True, "has_ledger": True, "versions": set(VERSIONS),
             "admins": ["platform-owner"], "storage_v2_admitted": True}
    state.update(over)
    return lambda dsn: state


def _pg_dirs(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    data = tmp_path / "data"
    bin_dir.mkdir()
    data.mkdir()
    (bin_dir / "psql.exe").write_text("x")
    monkeypatch.setenv("SLI_PG_BIN_DIR", str(bin_dir))
    monkeypatch.setenv("SLI_PG_DATA_DIR", str(data))


def test_plan_is_default_and_lists_ordered_steps(capsys, monkeypatch, tmp_path):
    _pg_dirs(tmp_path, monkeypatch)
    assert inst.main([]) == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan["mode"] == "plan" and plan["status"] == "ready"
    assert [s["id"] for s in plan["steps"]] == list(inst.STEP_ORDER)
    assert plan["steps"][0]["status"] == "pending"
    assert plan["database"]["state"] == "absent_or_unreachable"
    assert {p["id"] for p in plan["prerequisites"]} >= {
        "python_version", "frontend_build_present", "baseline_verified", "dsn_from_environment"}


def test_plan_blocks_without_dsn_or_frontend(capsys, monkeypatch):
    monkeypatch.delenv("ADLOG_PG_DSN")
    monkeypatch.setattr(inst, "_frontend_built", lambda root: False)
    assert inst.main(["plan"]) == 2
    plan = json.loads(capsys.readouterr().out)
    assert {"dsn_missing", "frontend_build_missing"} <= set(plan["blockers"])


def test_apply_requires_confirm_token(capsys, _env):
    assert inst.main(["apply"]) == 2
    assert inst.main(["apply", "--confirm", "yes"]) == 2
    assert "confirmation_required" in capsys.readouterr().err
    assert _env == []


def test_remote_dsn_refused_unless_allowed(capsys, monkeypatch):
    monkeypatch.setenv("ADLOG_PG_DSN", f"host=db.example.com port=5432 dbname=sli_main user=u password={DSN_SECRET}")
    probed = []
    monkeypatch.setattr(inst, "probe_database", lambda dsn: probed.append(dsn) or {"reachable": False})
    assert inst.main(["plan"]) == 2
    out = capsys.readouterr().out
    assert "remote_dsn_refused" in out and probed == [] and DSN_SECRET not in out
    monkeypatch.setattr(inst, "probe_database", _installed())
    inst.main(["plan", "--allow-remote-db"])
    plan = json.loads(capsys.readouterr().out)
    assert "remote_dsn_refused" not in plan["blockers"]


def test_installed_database_skips_done_steps_and_is_idempotent(capsys, monkeypatch, tmp_path, _env):
    monkeypatch.setattr(inst, "probe_database", _installed())
    out_dir = tmp_path / "out"
    argv = ["apply", "--confirm", "INSTALL-SLI", "--output-dir", str(out_dir)]
    assert inst.main(argv) == 0
    result = json.loads(capsys.readouterr().out)
    status = {s["id"]: s["status"] for s in result["steps"]}
    assert status["db_bootstrap"] == "skip" and status["first_admin"] == "skip"
    assert status["storage_v2_admission"] == "skip" and status["service_definitions"] == "done"
    assert _env == []  # no child script, no user creation
    assert (out_dir / "register-sli-tasks.ps1").is_file() and (out_dir / "start-sli-web.cmd").is_file()
    assert inst.main(argv) == 0
    again = json.loads(capsys.readouterr().out)
    assert {s["id"]: s["status"] for s in again["steps"]}["service_definitions"] == "skip"


def test_fresh_install_runs_bootstrap_with_stdin_secrets_only(capsys, monkeypatch, tmp_path, _env):
    _pg_dirs(tmp_path, monkeypatch)
    monkeypatch.setenv("ADLOG_PG_ADMIN_PASSWORD", SECRET_PASSWORD + "-pg")
    monkeypatch.setenv("SLI_ADMIN_PASSWORD", SECRET_PASSWORD)
    assert inst.main(["apply", "--confirm", "INSTALL-SLI", "--output-dir", str(tmp_path / "o")]) == 0
    captured = capsys.readouterr()
    for text in (captured.out, captured.err, (tmp_path / "o" / "install-receipt.json").read_text()):
        assert SECRET_PASSWORD not in text and DSN_SECRET not in text
    argv, kw = _env[0]
    assert argv[1].endswith("existing_postgres_bootstrap.py")
    assert not any(SECRET_PASSWORD in a or DSN_SECRET in a for a in argv)
    assert kw["stdin_text"] == SECRET_PASSWORD + "-pg\n" + SECRET_PASSWORD + "\n"
    storage = [c for c in _env if isinstance(c[0], list) and c[0][1].endswith("storage_v2_fresh_bootstrap.py")]
    assert storage and storage[0][1]["env"]["ADLOG_PG_ADMIN_PASSWORD"].startswith(SECRET_PASSWORD)


def test_missing_admin_creates_user_and_failure_hides_details(capsys, monkeypatch, tmp_path, _env):
    monkeypatch.setattr(inst, "probe_database", _installed(admins=[]))
    monkeypatch.setenv("SLI_ADMIN_PASSWORD", SECRET_PASSWORD)
    assert inst.main(["apply", "--confirm", "INSTALL-SLI", "--output-dir", str(tmp_path / "o")]) == 0
    assert ("user", "platform-owner") in _env

    def boom(username, password):
        raise RuntimeError(f"db said {SECRET_PASSWORD}")

    monkeypatch.setattr(inst, "create_admin_user", boom)
    capsys.readouterr()
    assert inst.main(["apply", "--confirm", "INSTALL-SLI", "--output-dir", str(tmp_path / "o")]) == 2
    out = capsys.readouterr().out
    assert "admin_creation_failed" in out and SECRET_PASSWORD not in out


def test_short_admin_password_rejected_before_side_effects(monkeypatch, tmp_path, _env, capsys):
    monkeypatch.setattr(inst, "probe_database", _installed(admins=[]))
    monkeypatch.setenv("SLI_ADMIN_PASSWORD", "short")
    assert inst.main(["apply", "--confirm", "INSTALL-SLI", "--output-dir", str(tmp_path / "o")]) == 2
    assert "admin_password_invalid" in capsys.readouterr().err
    assert _env == []


def test_behind_baseline_and_tls_rules(capsys, monkeypatch, tmp_path):
    monkeypatch.setattr(inst, "probe_database", _installed(versions={1}))
    assert inst.main(["plan"]) == 2
    assert "database_behind_baseline" in json.loads(capsys.readouterr().out)["blockers"]
    monkeypatch.setattr(inst, "probe_database", _installed())
    assert inst.main(["plan", "--host", "0.0.0.0"]) == 2
    assert "non_loopback_bind_requires_tls" in json.loads(capsys.readouterr().out)["blockers"]
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    cert.write_text("c")
    key.write_text("k")
    assert inst.main(["plan", "--host", "0.0.0.0", "--tls-cert", str(cert), "--tls-key", str(key)]) == 0
    files = inst.render_service_definitions(root=Path("C:/sli"), host="0.0.0.0", port=8443,
                                            tls_cert=cert, tls_key=key)
    assert "ADLOG_TLS_CERT_PATH" in files["start-sli-web.cmd"] and "--port 8443" in files["start-sli-web.cmd"]
    assert 'set "ADLOG_AUTH_REQUIRED=1"' in files["start-sli-web.cmd"]


@pytest.mark.parametrize('relative', [False, True])
def test_custom_output_task_targets_emitted_launcher(tmp_path, monkeypatch, capsys, _env, relative):
    monkeypatch.setattr(inst, 'probe_database', _installed())
    monkeypatch.setattr(inst.subprocess, 'run', lambda *a, **kw: pytest.fail('process invoked'))
    monkeypatch.chdir(tmp_path)
    output = Path("custom output's") if relative else tmp_path / "custom output's"
    assert inst.main(['apply', '--confirm', 'INSTALL-SLI', '--output-dir', str(output)]) == 0
    capsys.readouterr()
    launcher = output.resolve() / 'start-sli-web.cmd'
    ps = (output / 'register-sli-tasks.ps1').read_text()
    assert launcher.is_file()
    assert '$WebLauncher = ' + inst._ps(launcher) in ps
    assert "('/c \"' + $WebLauncher + '\"')" in ps
    assert "Join-Path $Root 'artifacts\\install\\start-sli-web.cmd'" not in ps
    assert _env == []


def test_default_task_launcher_stays_under_root():
    root = Path('C:/SLI Platform')
    ps = inst.render_service_definitions(root=root, host='127.0.0.1', port=8080,
                                         tls_cert=None, tls_key=None)['register-sli-tasks.ps1']
    assert '$WebLauncher = ' + inst._ps(root / 'artifacts' / 'install' / 'start-sli-web.cmd') in ps
    assert '$Root = ' + inst._ps(root) in ps
    assert '-WorkingDirectory $Root' in ps

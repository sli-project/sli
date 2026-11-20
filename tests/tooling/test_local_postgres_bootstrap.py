"""Isolated bootstrap guards; no production database/source access."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
from urllib.parse import urlunparse

import pytest

MODULE = "scripts.maintenance.local_postgres_bootstrap"
TOOLS = ("initdb", "pg_ctl", "psql", "postgres")
IDENTITY = {"principal": "TESTHOST\\bootstrap-user", "sid": "S-1-5-21-1-2-3-1001"}


def bootstrap_module():
    assert importlib.util.find_spec(MODULE) is not None, "bootstrap is not implemented"
    from scripts.maintenance import local_postgres_bootstrap
    return local_postgres_bootstrap


def arguments(tmp_path):
    return ["--app-root", str(tmp_path / "app"), "--bin-dir", str(tmp_path / "bin"),
            "--data-dir", str(tmp_path / "cluster" / "data"), "--database", "example_db"]


def prepared(tmp_path):
    mod = bootstrap_module()
    (tmp_path / "app").mkdir()
    (tmp_path / "bin").mkdir()
    opts = mod.parse_args(arguments(tmp_path))
    return mod, opts, mod.validate_paths(opts)


def tool_records(tmp_path, version="18.2"):
    records = {}
    for name in TOOLS:
        executable = tmp_path / "bin" / f"{name}.exe"
        executable.write_bytes(b"not executed")
        records[name] = {"path": str(executable), "version": version}
    return records


def completed(command, returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(command, returncode, stdout, stderr)


def test_cli_requires_explicit_paths_and_is_plan_only(tmp_path, capsys):
    mod = bootstrap_module()
    opts = mod.parse_args(arguments(tmp_path))
    assert opts.apply is False
    assert opts.confirm_new_cluster is None
    assert opts.database == "example_db"
    assert opts.port == 55433
    with pytest.raises(mod.BootstrapError, match="invalid_arguments"):
        mod.parse_args([])
    with pytest.raises(mod.BootstrapError, match="invalid_arguments"):
        mod.parse_args(arguments(tmp_path) + ["--password", "synthetic-secret"])
    assert "synthetic-secret" not in capsys.readouterr().err


@pytest.mark.parametrize("bad", ["postgres", "template0", "template1", "a; DROP DATABASE x", "A", "x" * 64])
def test_database_identifier_is_validated_before_lookup(tmp_path, bad):
    mod = bootstrap_module()
    args = arguments(tmp_path)
    args[-1] = bad
    with pytest.raises(mod.BootstrapError, match="invalid_database"):
        mod.parse_args(args)


@pytest.mark.parametrize("bad", [0, 1023, 65536])
def test_port_is_bounded(tmp_path, bad):
    mod = bootstrap_module()
    with pytest.raises(mod.BootstrapError, match="invalid_port"):
        mod.parse_args(arguments(tmp_path) + ["--port", str(bad)])


def test_path_guards_require_existing_app_and_bin(tmp_path):
    mod = bootstrap_module()
    opts = mod.parse_args(arguments(tmp_path))
    with pytest.raises(mod.BootstrapError, match="required_path_missing"):
        mod.validate_paths(opts)
    opts.app_root.mkdir()
    with pytest.raises(mod.BootstrapError, match="required_path_missing"):
        mod.validate_paths(opts)


def test_path_guards_never_overwrite_targets(tmp_path):
    mod, opts, paths = prepared(tmp_path)
    assert paths["profiles"] == opts.app_root / "data" / "runtime" / "local-postgres-18"
    assert not paths["profiles"].exists()
    opts.data_dir.mkdir(parents=True)
    sentinel = opts.data_dir / "do-not-change"
    sentinel.write_bytes(b"preserve")
    with pytest.raises(mod.BootstrapError, match="target_exists"):
        mod.validate_paths(opts)
    assert sentinel.read_bytes() == b"preserve"
    sentinel.unlink()
    opts.data_dir.rmdir()
    paths["profiles"].mkdir(parents=True)
    with pytest.raises(mod.BootstrapError, match="target_exists"):
        mod.validate_paths(opts)


def test_paths_reject_overlap_and_relative_targets(tmp_path):
    mod = bootstrap_module()
    opts = mod.parse_args(arguments(tmp_path))
    opts.app_root.mkdir()
    opts.bin_dir.mkdir()
    opts.data_dir = opts.app_root / "old-data"
    with pytest.raises(mod.BootstrapError, match="overlapping_paths"):
        mod.validate_paths(opts)
    opts.data_dir = Path("relative")
    with pytest.raises(mod.BootstrapError, match="unsafe_path"):
        mod.validate_paths(opts)


def test_paths_reject_symlink_or_reparse_ancestors(tmp_path):
    mod = bootstrap_module()
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    link_parent = tmp_path / "linked-parent"
    try:
        link_parent.symlink_to(real_parent, target_is_directory=True)
    except OSError:
        junction = subprocess.run(
            ["cmd.exe", "/d", "/c", "mklink", "/J", str(link_parent), str(real_parent)],
            capture_output=True, check=False,
        )
        assert junction.returncode == 0, "test requires a temporary Windows reparse point"
    try:
        (tmp_path / "app").mkdir()
        (tmp_path / "bin").mkdir()
        opts = mod.parse_args(arguments(tmp_path))
        opts.data_dir = link_parent / "new-data"
        with pytest.raises(mod.BootstrapError, match="unsafe_reparse_point"):
            mod.validate_paths(opts)
    finally:
        if link_parent.is_symlink():
            link_parent.unlink()
        else:
            link_parent.rmdir()  # Windows directory junction.


@pytest.mark.windows_only  # Resolves the trusted native whoami.exe before the fake runner.
def test_identity_comes_from_native_whoami_readback_not_environment():
    mod = bootstrap_module()
    seen = []

    def fake_runner(command, **kwargs):
        seen.append((command, kwargs))
        return completed(command, stdout='"NATIVEHOST\\native-user","S-1-5-21-9-8-7-1002"\n')

    identity = mod.local_identity({"USERNAME": "guessed-user", "USERDOMAIN": "GUESSED"}, runner=fake_runner)
    assert identity == {"principal": "NATIVEHOST\\native-user", "sid": "S-1-5-21-9-8-7-1002"}
    assert len(seen) == 1
    assert Path(seen[0][0][0]).name.casefold() == "whoami.exe"
    assert seen[0][0][1:] == ["/user", "/fo", "csv", "/nh"]


@pytest.mark.windows_only  # Reads the native Windows identity and verifies an NTFS DACL.
def test_native_private_directory_has_only_owner_system(tmp_path):
    mod = bootstrap_module()
    identity = mod.local_identity()
    assert identity["sid"].startswith("S-1-5-")
    assert "\\" in identity["principal"]
    target = tmp_path / "private"
    mod.create_private_directory(target, identity["sid"])
    assert mod.verify_private_directory(target, identity["sid"]) is True
    with pytest.raises(mod.BootstrapError, match="target_exists"):
        mod.create_private_directory(target, identity["sid"])


def test_child_environment_is_an_allowlist_and_excludes_credentials():
    mod = bootstrap_module()
    env = mod.child_environment(Path("C:/example/bin"), {
        "SystemRoot": "C:/Windows", "TEMP": "C:/temp", "TMP": "C:/tmp",
        "ComSpec": "C:/Windows/System32/cmd.exe", "WINDIR": "C:/Windows",
        "ADLOG_PG_DSN": "synthetic-secret", "PGPASSWORD": "synthetic-secret",
        "PGOPTIONS": "-c log_statement=all", "PATH": "untrusted", "PYTHONPATH": "untrusted",
    })
    assert env["PATH"] == str(Path("C:/example/bin"))
    assert set(env) == {"SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP", "PATH"}
    assert "synthetic-secret" not in json.dumps(env)
    assert "PGOPTIONS" not in env
    assert "untrusted" not in json.dumps(env)


def test_no_pipe_process_uses_devnull_for_all_standard_handles(monkeypatch):
    mod = bootstrap_module()
    observed = []

    def fake_run(command, **kwargs):
        observed.append((list(command), kwargs))
        return completed(command)

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    result = mod._run_process(
        ["pg_ctl.exe", "-w", "start"],
        env={"PATH": "C:/postgres/bin"},
        capture_output=False,
    )

    assert result.returncode == 0
    assert len(observed) == 1
    _command, kwargs = observed[0]
    assert "capture_output" not in kwargs
    assert kwargs["stdin"] is subprocess.DEVNULL
    assert kwargs["stdout"] is subprocess.DEVNULL
    assert kwargs["stderr"] is subprocess.DEVNULL


def test_bootstrap_sql_is_one_complete_statement_per_single_user_input_line():
    mod = bootstrap_module()
    roles = {"migration": "migration_role", "runtime": "runtime_role"}
    credentials = {
        "migration": "synthetic-migration-secret",
        "runtime": "synthetic-runtime-secret",
    }
    documents = (
        mod._superuser_password_sql("synthetic-super-secret"),
        mod._create_database_sql("example_db", roles, credentials),
        mod._database_permissions_sql(roles),
        mod._readback_sql("example_db", roles),
    )

    for document in documents:
        assert all(line.endswith(";") for line in document.splitlines() if line)


def test_single_user_readback_accepts_boolean_text_values():
    mod = bootstrap_module()
    roles = {"migration": "migration_role", "runtime": "runtime_role"}
    output = "\n".join((
        "bootstrap_readback|example_db|migration_role",
        "role|migration_role|true|false|false|false|false",
        "role|runtime_role|true|false|false|false|false",
    ))

    mod._verify_database_readback(output, "example_db", roles)


@pytest.mark.windows_only  # Resolves native Windows PowerShell for the DPAPI command.
def test_dpapi_protection_keeps_plaintext_out_of_argv_and_environment():
    mod = bootstrap_module()
    observed = []

    def fake_runner(command, *, env, input_text=None):
        observed.append({"command": list(command), "env": dict(env), "input": input_text})
        return completed(command, stdout="c2VhbGVk")

    plaintext = urlunparse(
        ("postgresql", "synthetic:secret@127.0.0.1:55433", "/example", "", "", "")
    )
    assert mod._dpapi_protect(plaintext, runner=fake_runner) == "c2VhbGVk"
    assert len(observed) == 1
    assert observed[0]["input"] == plaintext
    assert plaintext not in json.dumps(observed[0]["command"])
    assert plaintext not in json.dumps(observed[0]["env"])


def test_postgres_tools_must_be_exact_native_major_18(tmp_path):
    mod, _opts, paths = prepared(tmp_path)
    tool_records(tmp_path)

    def good_runner(command, **_kwargs):
        name = Path(command[0]).stem
        return completed(command, stdout=f"{name} (PostgreSQL) 18.2\n")

    tools = mod.validate_postgres_tools(paths["bin"], runner=good_runner)
    assert set(tools) == set(TOOLS)
    assert {entry["version"] for entry in tools.values()} == {"18.2"}

    def wrong_runner(command, **_kwargs):
        name = Path(command[0]).stem
        major = "17.6" if name == "psql" else "18.2"
        return completed(command, stdout=f"{name} (PostgreSQL) {major}\n")

    with pytest.raises(mod.BootstrapError, match="postgresql_18_required"):
        mod.validate_postgres_tools(paths["bin"], runner=wrong_runner)


def test_plan_is_canonical_secret_free_and_confirmation_bound(tmp_path):
    mod, opts, paths = prepared(tmp_path)
    tools = tool_records(tmp_path)
    plan = mod.build_plan(opts, paths, IDENTITY, tools)
    encoded = mod.canonical_json(plan)
    confirmation = mod.plan_confirmation(plan)
    assert encoded == json.dumps(plan, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    assert confirmation == hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    envelope = mod.plan_envelope(plan)
    assert envelope["confirmation_sha256"] == confirmation
    assert envelope["plan"] == plan
    blob = mod.canonical_json(envelope).lower()
    assert "password" not in blob
    assert "dsn" not in blob
    assert "migration" in plan["excluded_actions"]
    assert "application_schema" in plan["excluded_actions"]


def test_plan_cli_is_read_only_and_emits_only_canonical_json(tmp_path, monkeypatch, capsys):
    mod = bootstrap_module()
    (tmp_path / "app").mkdir()
    (tmp_path / "bin").mkdir()
    tools = tool_records(tmp_path)
    monkeypatch.setattr(mod, "local_identity", lambda *_args, **_kwargs: IDENTITY)
    monkeypatch.setattr(mod, "validate_postgres_tools", lambda *_args, **_kwargs: tools)
    rc = mod.main(arguments(tmp_path))
    captured = capsys.readouterr()
    assert rc == 0
    assert captured.err == ""
    assert captured.out.strip() == mod.canonical_json(json.loads(captured.out))
    document = json.loads(captured.out)
    assert document["mode"] == "plan"
    assert len(document["confirmation_sha256"]) == 64
    assert not (tmp_path / "cluster" / "data").exists()
    assert not (tmp_path / "app" / "data" / "runtime" / "local-postgres-18").exists()


def test_apply_requires_exact_current_plan_confirmation(tmp_path, monkeypatch, capsys):
    mod = bootstrap_module()
    (tmp_path / "app").mkdir()
    (tmp_path / "bin").mkdir()
    tools = tool_records(tmp_path)
    monkeypatch.setattr(mod, "local_identity", lambda *_args, **_kwargs: IDENTITY)
    monkeypatch.setattr(mod, "validate_postgres_tools", lambda *_args, **_kwargs: tools)
    monkeypatch.setattr(mod, "apply_bootstrap", lambda *_args, **_kwargs: pytest.fail("apply must not run"))
    rc = mod.main(arguments(tmp_path) + ["--apply", "--confirm-new-cluster", "0" * 64])
    captured = capsys.readouterr()
    assert rc == 2
    assert captured.out == ""
    assert json.loads(captured.err) == {"code": "confirmation_mismatch", "status": "error"}
    assert "example_db" not in captured.err
    assert not (tmp_path / "cluster" / "data").exists()


def test_matching_confirmation_is_the_only_apply_admission(tmp_path, monkeypatch, capsys):
    mod = bootstrap_module()
    (tmp_path / "app").mkdir()
    (tmp_path / "bin").mkdir()
    opts = mod.parse_args(arguments(tmp_path))
    paths = mod.validate_paths(opts)
    tools = tool_records(tmp_path)
    confirmation = mod.plan_confirmation(mod.build_plan(opts, paths, IDENTITY, tools))
    invoked = []
    monkeypatch.setattr(mod, "local_identity", lambda *_args, **_kwargs: IDENTITY)
    monkeypatch.setattr(mod, "validate_postgres_tools", lambda *_args, **_kwargs: tools)

    def fake_apply(*args, **kwargs):
        invoked.append((args, kwargs))
        return paths["profiles"] / "receipt.json"

    monkeypatch.setattr(mod, "apply_bootstrap", fake_apply)
    rc = mod.main(arguments(tmp_path) + ["--apply", "--confirm-new-cluster", confirmation])
    captured = capsys.readouterr()
    assert rc == 0
    assert len(invoked) == 1
    assert json.loads(captured.out) == {
        "confirmation_sha256": confirmation,
        "mode": "apply",
        "receipt": str(paths["profiles"] / "receipt.json"),
        "status": "complete",
    }
    assert captured.err == ""


def test_apply_creates_only_new_cluster_loopback_roles_and_sealed_candidates(tmp_path):
    mod, opts, paths = prepared(tmp_path)
    tools = tool_records(tmp_path)
    plan = mod.build_plan(opts, paths, IDENTITY, tools)
    confirmation = mod.plan_confirmation(plan)
    passwords = {
        "superuser": "synthetic-super-secret",
        "migration": "synthetic-migration-secret",
        "runtime": "synthetic-runtime-secret",
    }
    calls = []
    protected_plaintexts = []

    def directory_creator(target, _sid):
        target.mkdir(parents=True)

    def runner(command, *, env, input_text=None, capture_output=True):
        calls.append({
            "command": list(command),
            "env": dict(env),
            "input": input_text,
            "capture_output": capture_output,
        })
        name = Path(command[0]).stem.casefold()
        if name == "initdb":
            (paths["data"] / "postgresql.conf").write_text("# generated\n", encoding="utf-8")
            (paths["data"] / "pg_hba.conf").write_text("# generated\n", encoding="utf-8")
        if name == "postgres" and input_text and "bootstrap_readback" in input_text:
            return completed(command, stdout=(
                f"bootstrap_readback|{opts.database}|{plan['roles']['migration']}\n"
                f"role|{plan['roles']['migration']}|true|false|false|false|false\n"
                f"role|{plan['roles']['runtime']}|true|false|false|false|false\n"
            ))
        return completed(command)

    def protector(plaintext):
        protected_plaintexts.append(plaintext)
        return "sealed-" + hashlib.sha256(plaintext.encode("utf-8")).hexdigest()

    receipt_path = mod.apply_bootstrap(
        opts, paths, IDENTITY, tools, confirmation,
        runner=runner,
        password_factory=lambda label: passwords[label],
        protector=protector,
        directory_creator=directory_creator,
        directory_verifier=lambda _target, _sid: True,
    )

    assert receipt_path == paths["profiles"] / "receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt["status"] == "complete"
    assert receipt["confirmation_sha256"] == confirmation
    assert receipt["last_completed_stage"] == "profiles_written"
    assert len(protected_plaintexts) == 2
    assert all(text.startswith("postgresql://") for text in protected_plaintexts)

    argv_blob = json.dumps([call["command"] for call in calls])
    env_blob = json.dumps([call["env"] for call in calls])
    file_blob = "\n".join(path.read_text(encoding="utf-8") for path in paths["profiles"].iterdir())
    for secret in passwords.values():
        assert secret not in argv_blob
        assert secret not in env_blob
        assert secret not in file_blob
    assert "postgresql://" not in file_blob
    assert '"active":false' in file_blob
    assert '"protection":"windows-dpapi-current-user"' in file_blob

    initdb_call = next(call for call in calls if Path(call["command"][0]).stem.casefold() == "initdb")
    assert initdb_call["input"] is None
    assert "--auth-host=reject" in initdb_call["command"]
    assert "--auth-local=reject" in initdb_call["command"]
    assert not any(argument.startswith("--pwfile") for argument in initdb_call["command"])
    assert "--pwprompt" not in initdb_call["command"]

    process_names = [Path(call["command"][0]).stem.casefold() for call in calls]
    assert process_names == ["initdb", "postgres", "postgres", "postgres", "postgres", "pg_ctl"]
    postgres_calls = [call for call in calls if Path(call["command"][0]).stem.casefold() == "postgres"]
    assert [call["command"][-1] for call in postgres_calls] == [
        "postgres", "postgres", opts.database, "postgres",
    ]
    assert all(call["command"][1:4] == ["--single", "-D", str(paths["data"])]
               for call in postgres_calls)
    assert "ALTER ROLE postgres PASSWORD" in (postgres_calls[0]["input"] or "")
    assert passwords["superuser"] in (postgres_calls[0]["input"] or "")
    assert passwords["migration"] not in (postgres_calls[0]["input"] or "")
    assert passwords["runtime"] not in (postgres_calls[0]["input"] or "")
    assert passwords["migration"] in (postgres_calls[1]["input"] or "")
    assert passwords["runtime"] in (postgres_calls[1]["input"] or "")
    assert all(secret not in (postgres_calls[2]["input"] or "") for secret in passwords.values())
    assert all(secret not in (postgres_calls[3]["input"] or "") for secret in passwords.values())

    pg_ctl_call = calls[-1]
    assert pg_ctl_call["capture_output"] is False
    assert pg_ctl_call["input"] is None
    assert pg_ctl_call["command"][pg_ctl_call["command"].index("-l") + 1] == str(
        paths["data"] / "bootstrap-postgres.log")
    assert all("PGPASSWORD" not in call["env"] for call in calls)
    assert all("PGOPTIONS" not in call["env"] for call in calls)

    postgres_conf = (paths["data"] / "postgresql.conf").read_text(encoding="utf-8")
    pg_hba = (paths["data"] / "pg_hba.conf").read_text(encoding="utf-8")
    assert "listen_addresses = '127.0.0.1'" in postgres_conf
    assert f"port = {opts.port}" in postgres_conf
    assert "log_statement = 'none'" in postgres_conf
    assert "log_min_error_statement = 'panic'" in postgres_conf
    assert "log_parameter_max_length_on_error = 0" in postgres_conf
    assert "127.0.0.1/32" in pg_hba
    assert "scram-sha-256" in pg_hba
    assert "0.0.0.0/0" in pg_hba and "reject" in pg_hba
    assert " trust" not in pg_hba
    for secret in passwords.values():
        assert secret not in postgres_conf
        assert secret not in pg_hba

    all_input = "\n".join(call["input"] or "" for call in calls).lower()
    all_argv = argv_blob.lower()
    for forbidden in ("create schema", "alembic", "migration runner", "worker", "service", "scheduled task"):
        assert forbidden not in all_input
        assert forbidden not in all_argv


def test_partial_failure_writes_safe_receipt_once_and_preserves_state(tmp_path):
    mod, opts, paths = prepared(tmp_path)
    tools = tool_records(tmp_path)
    plan = mod.build_plan(opts, paths, IDENTITY, tools)
    confirmation = mod.plan_confirmation(plan)
    calls = []

    def directory_creator(target, _sid):
        target.mkdir(parents=True)

    def failing_runner(command, *, env, input_text=None):
        calls.append(list(command))
        return completed(command, returncode=1, stderr="synthetic-secret native diagnostics")

    with pytest.raises(mod.BootstrapError, match="bootstrap_partial_failure"):
        mod.apply_bootstrap(
            opts, paths, IDENTITY, tools, confirmation,
            runner=failing_runner,
            password_factory=lambda _label: "synthetic-secret",
            protector=lambda _plaintext: pytest.fail("profiles must not be written"),
            directory_creator=directory_creator,
            directory_verifier=lambda _target, _sid: True,
        )

    assert len(calls) == 1
    assert paths["data"].is_dir()
    assert paths["profiles"].is_dir()
    receipt_path = paths["profiles"] / "receipt.json"
    receipt_text = receipt_path.read_text(encoding="utf-8")
    receipt = json.loads(receipt_text)
    assert receipt["status"] == "partial_failure"
    assert receipt["last_completed_stage"] == "private_directories_created"
    assert receipt["error_code"] == "command_failed"
    assert "synthetic-secret" not in receipt_text
    assert "native diagnostics" not in receipt_text

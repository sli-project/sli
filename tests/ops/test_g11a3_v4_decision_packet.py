import inspect
import json
import os
import py_compile
import shutil
import subprocess
import sys
import venv
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
PRECONTACT = ROOT / "tests" / "fixtures" / "g11a3_precontact.ps1"


@pytest.fixture
def approved_python(tmp_path: Path) -> tuple[Path, Path, Path]:
    approved_venv = tmp_path / "approved-venv"
    venv.EnvBuilder(with_pip=False).create(approved_venv)
    bootstrap = approved_venv / "Lib" / "site-packages" / "win32" / "lib" / "pywin32_bootstrap.py"
    bootstrap.parent.mkdir(parents=True)
    bootstrap.write_text("# Synthetic bootstrap for import-path and DPAPI guard tests.\n", encoding="utf-8")
    return approved_venv / "Scripts" / "python.exe", approved_venv, bootstrap


def _one_run_command() -> str:
    return PRECONTACT.read_text(encoding="utf-8")


def _embedded_python(variable: str) -> str:
    command = _one_run_command()
    start_marker = f"${variable} = @'\n"
    if start_marker in command:
        return command.split(start_marker, 1)[1].split("\n'@", 1)[0]
    if variable == "pythonPreflight":
        suffix_marker = "$pythonPreflight = $pythonGuard + [Environment]::NewLine + @'\n"
        suffix = command.split(suffix_marker, 1)[1].split("\n'@", 1)[0]
        return _embedded_python("pythonGuard") + "\n" + suffix
    raise AssertionError(f"missing embedded Python: {variable}")


def _git(*args: str, cwd: Path) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _create_repository_with_linked_worktree(tmp_path: Path) -> tuple[Path, Path]:
    primary = tmp_path / "primary"
    linked = tmp_path / "linked"
    primary.mkdir()
    _git("init", "--initial-branch=main", cwd=primary)
    (primary / "seed.txt").write_text("seed\n", encoding="utf-8")
    (primary / ".gitignore").write_text(
        "__pycache__/\n*.pyc\n", encoding="utf-8"
    )
    _git("add", "seed.txt", ".gitignore", cwd=primary)
    _git(
        "-c",
        "user.name=SLI Test",
        "-c",
        "user.email=sli-test@example.invalid",
        "commit",
        "-m",
        "seed",
        cwd=primary,
    )
    _git("worktree", "add", "--detach", str(linked), "HEAD", cwd=primary)
    return primary, linked


def _run_precontact(repository: Path) -> subprocess.CompletedProcess[str]:
    command = _one_run_command()
    start_marker = "# G11A3_POWERSHELL_OPERATION_START\n"
    end_marker = "# G11A3_POWERSHELL_OPERATION_END"
    prefix, operation_and_suffix = command.split(start_marker, 1)
    operation, suffix = operation_and_suffix.split(end_marker, 1)
    precontact_operation = operation.split("    throw 'fixture_precontact_only'", 1)[0]
    precontact = (
        prefix
        + start_marker
        + precontact_operation
        + end_marker
        + suffix
    )
    head = _git("rev-parse", "HEAD", cwd=repository)
    precontact = precontact.replace(
        "'<40-hex-merged-main-from-owner-approval>'", f"'{head}'"
    )
    powershell = shutil.which("powershell.exe") or shutil.which("powershell")
    assert powershell is not None
    return subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", precontact],
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
    )


def _run_powershell_diagnostic_operation(
    operation: str,
) -> subprocess.CompletedProcess[str]:
    command = _one_run_command()
    start_marker = "# G11A3_POWERSHELL_OPERATION_START\n"
    end_marker = "# G11A3_POWERSHELL_OPERATION_END"
    assert start_marker in command
    assert end_marker in command
    prefix = command.split(start_marker, 1)[0] + start_marker
    suffix = end_marker + command.split(end_marker, 1)[1]
    powershell = shutil.which("powershell.exe") or shutil.which("powershell")
    assert powershell is not None
    return subprocess.run(
        [
            powershell,
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            prefix + operation + "\n" + suffix,
        ],
        check=False,
        capture_output=True,
        text=True,
    )


@pytest.mark.windows_only
def test_v4_powershell_boundary_redacts_pre_runner_failure_and_preserves_runner_json(
) -> None:
    pre_runner = _run_powershell_diagnostic_operation(
        "$failureStage = 'python_preflight'\n"
        "throw 'fixture-secret-exception'"
    )

    assert pre_runner.returncode != 0
    assert json.loads(pre_runner.stdout) == {
        "status": "failed",
        "failure_stage": "python_preflight",
        "credential_values_exposed": False,
    }
    assert "fixture-secret-exception" not in pre_runner.stdout
    assert "fixture-secret-exception" not in pre_runner.stderr

    runner_payload = {
        "status": "failed",
        "failure_stage": "probe_entrypoint",
        "credential_values_exposed": False,
    }
    runner_failure = _run_powershell_diagnostic_operation(
        "$failureStage = 'runner_result_validation'\n"
        "$probeExit = 1\n"
        f"$probeJson = '{json.dumps(runner_payload)}'\n"
        "$failureJson = Get-G11A3SafeRunnerFailureJson -ProbeJson $probeJson"
    )

    assert runner_failure.returncode != 0
    assert json.loads(runner_failure.stdout) == runner_payload



@pytest.mark.windows_only
def test_v4_preflight_rejects_primary_checkout(tmp_path: Path) -> None:
    primary, _linked = _create_repository_with_linked_worktree(tmp_path)

    result = _run_precontact(primary)

    assert result.returncode != 0
    assert json.loads(result.stdout) == {
        "status": "failed",
        "failure_stage": "python_preflight",
        "credential_values_exposed": False,
    }


@pytest.mark.windows_only
def test_v4_preflight_rejects_dirty_linked_worktree(tmp_path: Path) -> None:
    _primary, linked = _create_repository_with_linked_worktree(tmp_path)
    (linked / "untracked.txt").write_text("dirty\n", encoding="utf-8")

    result = _run_precontact(linked)

    assert result.returncode != 0
    assert json.loads(result.stdout) == {
        "status": "failed",
        "failure_stage": "python_preflight",
        "credential_values_exposed": False,
    }


@pytest.mark.windows_only
def test_v4_preflight_rejects_hidden_untracked_package_file(tmp_path: Path) -> None:
    _primary, linked = _create_repository_with_linked_worktree(tmp_path)
    _git("config", "status.showUntrackedFiles", "no", cwd=linked)
    package = linked / "server" / "app"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("# untracked package\n", encoding="utf-8")

    result = _run_precontact(linked)

    assert result.returncode != 0
    assert json.loads(result.stdout) == {
        "status": "failed",
        "failure_stage": "python_preflight",
        "credential_values_exposed": False,
    }


def test_v4_python_guard_rejects_ignored_differing_bytecode(
    tmp_path: Path,
) -> None:
    _primary, linked = _create_repository_with_linked_worktree(tmp_path)
    module_path = linked / "server" / "sli" / "ops" / "worker_supervisor_secrets.py"
    module_path.parent.mkdir(parents=True)
    safe_source = 'VALUE = "tracked_source"\n'
    module_path.write_text(safe_source, encoding="utf-8")
    _git("add", "server/sli/ops/worker_supervisor_secrets.py", cwd=linked)
    _git(
        "-c",
        "user.name=SLI Test",
        "-c",
        "user.email=sli-test@example.invalid",
        "commit",
        "-m",
        "tracked safe module",
        cwd=linked,
    )

    module_path.write_text('VALUE = "bytecode_payload"\n', encoding="utf-8")
    py_compile.compile(
        str(module_path),
        doraise=True,
        invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
    )
    module_path.write_text(safe_source, encoding="utf-8")
    assert _git("status", "--porcelain=v1", "--untracked-files=all", cwd=linked) == ""

    environment = os.environ.copy()
    environment["SLI_G11A3_APPROVED_WORKTREE"] = str(linked)
    control_code = """
import os
import sys
sys.path.insert(0, os.environ["SLI_G11A3_APPROVED_WORKTREE"])
from server.sli.ops import worker_supervisor_secrets as module
print(module.VALUE)
print(module.__file__)
"""
    control = subprocess.run(
        [sys.executable, "-I", "-S", "-B", "-c", control_code],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )
    assert "bytecode_payload" in control.stdout
    assert str(module_path) in control.stdout

    guard = _embedded_python("pythonGuard")
    guarded_code = guard + """
from server.sli.ops import worker_supervisor_secrets as module
print(module.VALUE)
"""
    guarded = subprocess.run(
        [sys.executable, "-I", "-S", "-B", "-c", guarded_code],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    assert guarded.returncode != 0
    assert "approved_worktree_bytecode_present" in guarded.stderr
    assert "bytecode_payload" not in guarded.stdout


@pytest.mark.windows_only
def test_v4_python_guard_loads_only_approved_bootstrap_despite_tracked_shadow(
    tmp_path: Path,
    approved_python: tuple[Path, Path, Path],
) -> None:
    _primary, linked = _create_repository_with_linked_worktree(tmp_path)
    marker_path = tmp_path / "hostile-bootstrap-executed.txt"
    shadow_path = linked / "pywin32_bootstrap.py"
    shadow_path.write_text(
        "__import__('pathlib').Path("
        "__import__('os').environ['SLI_G11A3_HOSTILE_MARKER']"
        ").write_text('executed\\n', encoding='utf-8')\n",
        encoding="utf-8",
    )
    _git("add", "pywin32_bootstrap.py", cwd=linked)
    _git(
        "-c",
        "user.name=SLI Test",
        "-c",
        "user.email=sli-test@example.invalid",
        "commit",
        "-m",
        "tracked hostile bootstrap shadow",
        cwd=linked,
    )

    python, approved_venv, expected_bootstrap = approved_python
    environment = os.environ.copy()
    environment["SLI_G11A3_APPROVED_WORKTREE"] = str(linked)
    environment["SLI_G11A3_APPROVED_VENV"] = str(approved_venv)
    environment["SLI_G11A3_HOSTILE_MARKER"] = str(marker_path)
    guard = _embedded_python("pythonGuard")
    guarded_code = guard + """
pywin32_bootstrap = load_approved_pywin32_bootstrap()
print(Path(pywin32_bootstrap.__file__).resolve(strict=True))
"""

    result = subprocess.run(
        [str(python), "-I", "-S", "-B", "-c", guarded_code],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == str(expected_bootstrap)
    assert not marker_path.exists()


def _fake_profile_protect(clear, description, entropy, reserved, prompt, flags):
    assert flags == 1
    assert json.loads(clear)["version"] == 2
    return b"synthetic-user-dpapi:" + clear


def _fake_profile_unprotect(blob, entropy, reserved, prompt, flags):
    assert flags == 1
    prefix = b"synthetic-user-dpapi:"
    assert blob.startswith(prefix)
    return "synthetic-description", blob[len(prefix):]


@pytest.mark.windows_only
def test_v4_profile_code_provisions_from_existing_dpapi_without_environment(
    tmp_path: Path,
    monkeypatch,
    approved_python: tuple[Path, Path, Path],
) -> None:
    from server.sli.ops import worker_supervisor_secrets as module
    from server.sli.ops.worker_supervisor_secrets import (
        WORKER_ENV_ALLOWLIST,
        load_supervisor_environment,
        provision_supervisor_environment,
    )

    approved_worktree = tmp_path / "approved-worktree"
    for relative_path in (
        Path("server/__init__.py"),
        Path("server/sli/__init__.py"),
        Path("server/sli/core/__init__.py"),
        Path("server/sli/core/paths.py"),
        Path("server/sli/ops/__init__.py"),
        Path("server/sli/ops/worker_supervisor_secrets.py"),
    ):
        target = approved_worktree / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative_path, target)

    source = {
        "ADLOG_PG_DSN": "postgresql://fixture.invalid/sli",
        "ADLOG_COLLECTION_PRINCIPAL": "FIXTURE\\collector",
        "ADLOG_COLLECTION_PRINCIPAL_SID": (
                "S-1-5-21-100000001-200000002-300000003-1001"
        ),
        "SLI_G11A3_DIRECTORY_SERVER": "fixture-dc.invalid",
        "SLI_G11A3_VPN_GROUP_SID": (
                "S-1-5-21-100000001-200000002-300000003-1002"
        ),
        "SLI_G11A3_PROBE_PLAN_ID": "G11A3-PROBE-CLOSED-GENERATION-V4",
    }
    # Keep both processes hermetic: the fixture SID is not a Windows account.
    fake_win32crypt = SimpleNamespace(
        CryptProtectData=_fake_profile_protect, CryptUnprotectData=_fake_profile_unprotect,
    )
    monkeypatch.setitem(sys.modules, "win32crypt", fake_win32crypt)
    monkeypatch.setattr(module, "_current_user_sid", lambda: source["ADLOG_COLLECTION_PRINCIPAL_SID"])
    monkeypatch.setattr(module, "_ensure_web_service_identity", lambda _sid: None)
    monkeypatch.setattr(module, "_write_protected_blob", lambda path, blob: path.write_bytes(blob))
    primary_profile = tmp_path / "primary-worker-supervisor.env.dpapi"
    temporary_profile = tmp_path / "g11a3-v4-live.env.dpapi"
    provision_supervisor_environment(source=source, path=primary_profile)

    command = _one_run_command()
    marker = "$profileCode = $pythonGuard + [Environment]::NewLine + @'\n"
    suffix = command.split(marker, 1)[1].split("\n'@", 1)[0]
    fake_setup = (
        "from types import SimpleNamespace\n"
        + inspect.getsource(_fake_profile_protect)
        + inspect.getsource(_fake_profile_unprotect)
        + f"""
sys.modules["win32crypt"] = SimpleNamespace(
    CryptProtectData=_fake_profile_protect, CryptUnprotectData=_fake_profile_unprotect,
)
from server.sli.ops import worker_supervisor_secrets as module
module._current_user_sid = lambda: {source["ADLOG_COLLECTION_PRINCIPAL_SID"]!r}
module._ensure_web_service_identity = lambda sid: None
module._write_protected_blob = lambda path, blob: path.write_bytes(blob)
"""
    )
    profile_code = _embedded_python("pythonGuard") + "\nimport json\n" + fake_setup + suffix
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in WORKER_ENV_ALLOWLIST and not key.startswith("SLI_G11A3_")
    }
    python, approved_venv, _ = approved_python
    environment.update(
        {
            "SLI_G11A3_APPROVED_WORKTREE": str(approved_worktree),
            "SLI_G11A3_APPROVED_VENV": str(approved_venv),
            "SLI_G11A3_SUPERVISOR_PROFILE": str(primary_profile),
            "SLI_G11A3_PROBE_PROFILE": str(temporary_profile),
        }
    )

    result = subprocess.run(
        [str(python), "-I", "-S", "-B", "-c", profile_code],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["status"] == "ok"
    reloaded: dict[str, str] = {}
    load_supervisor_environment(target=reloaded, path=temporary_profile)
    assert all(reloaded[name] == value for name, value in source.items())
    sealed = json.loads(temporary_profile.read_bytes().split(b":", 1)[1])
    assert sealed["owner_sid"] == source["ADLOG_COLLECTION_PRINCIPAL_SID"]

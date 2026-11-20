"""Offline contracts for the beta .NET MSI artifact workflow."""
import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/agent-msi.yml"


def workflow():
    # BaseLoader keeps GitHub's YAML 1.2 `on` key as a string.
    return yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)


def test_msi_workflow_builds_and_checks_dotnet_before_upload():
    config = workflow()
    assert set(config["on"]) == {"workflow_dispatch", "workflow_call"}
    assert config["permissions"] == {"contents": "read"}
    job = config["jobs"]["msi"]
    assert job["runs-on"] == "windows-2025"
    steps = job["steps"]
    runs = "\n".join(step.get("run", "") for step in steps)
    assert "tools/build-sli-agent-msi.ps1" not in runs
    assert "pip download" not in runs
    assert "inputs.product_version" not in runs
    setup, = [s for s in steps if s.get("uses", "").startswith("actions/setup-dotnet@")]
    assert setup["with"]["global-json-file"] == "agent-dotnet/global.json"
    build = next(i for i, s in enumerate(steps) if "Build-Msi.ps1" in s.get("run", ""))
    check = next(i for i, s in enumerate(steps) if "Test-MsiTables.ps1" in s.get("run", ""))
    package = next(i for i, s in enumerate(steps) if s.get("name") == "Package MSI and source manifest")
    upload = next(i for i, s in enumerate(steps) if s.get("uses", "").startswith("actions/upload-artifact@"))
    assert build < check < package < upload
    assert not any("if" in s or "continue-on-error" in s for s in steps[build:upload + 1])
    assert steps[upload]["with"]["name"] == "sli-agent-dotnet-msi-${{ inputs.commit || github.sha }}"
    assert steps[upload]["with"]["if-no-files-found"] == "error"
    assert "-MsvcRoot $env:SLI_MSVC_ROOT" in steps[build]["run"]
    assert "-WindowsSdkRoot $env:SLI_WINDOWS_SDK_ROOT" in steps[build]["run"]


def test_msi_actions_reuse_existing_pins_and_keep_checkout_read_only():
    existing = (ROOT / ".github/workflows/agent-dotnet.yml").read_text(encoding="utf-8")
    source = WORKFLOW.read_text(encoding="utf-8")
    uses = re.findall(r"uses: ([^\s]+) # v[^\n]+", source)
    steps = workflow()["jobs"]["msi"]["steps"]
    assert len(uses) == sum("uses" in s for s in steps)
    for action in uses:
        assert re.fullmatch(r"actions/[\w-]+@[0-9a-f]{40}", action)
        assert action in existing
    checkout, = [s for s in steps if s.get("uses", "").startswith("actions/checkout@")]
    assert checkout["with"]["ref"] == "${{ github.sha }}"
    assert checkout["with"]["persist-credentials"] == "false"
    assert "pull_request_target" not in source


@pytest.mark.parametrize("source_matches", [True, False], ids=["matching-source", "wrong-source"])
def test_msi_artifact_contains_only_msi_and_matching_source_manifest(tmp_path, source_matches):
    pwsh = shutil.which("pwsh")
    if not pwsh:
        pytest.skip("PowerShell is required to execute the packaging step")

    step, = [s for s in workflow()["jobs"]["msi"]["steps"] if s.get("name") == "Package MSI and source manifest"]
    checkout = tmp_path / "checkout"
    working_dir = checkout / step["working-directory"]
    working_dir.mkdir(parents=True)
    global_json = working_dir / "global.json"
    shutil.copyfile(ROOT / step["working-directory"] / "global.json", global_json)
    sdk = json.loads(global_json.read_text(encoding="utf-8"))["sdk"]["version"]

    subprocess.run(["git", "init", "--quiet", "--object-format=sha1", "--template="],
                   cwd=checkout, check=True, timeout=30)
    subprocess.run(["git", "add", "--", str(global_json)], cwd=checkout, check=True, timeout=30)
    subprocess.run([
        "git", "-c", "user.name=MSI Test", "-c", "user.email=msi@example.test",
        "-c", f"core.hooksPath={checkout / 'disabled-hooks'}", "commit", "--quiet",
        "--no-gpg-sign", "-m", "Test checkout",
    ], cwd=checkout, check=True, timeout=30)
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=checkout,
                                     text=True, timeout=30).strip()
    source_commit = commit if source_matches else ("1" if commit[0] == "0" else "0") + commit[1:]

    runner_temp = tmp_path / "runner-temp"
    output = runner_temp / "agent-dotnet"
    output.mkdir(parents=True)
    (output / "SliAgent.msi").write_bytes(b"synthetic MSI")
    script = runner_temp / "package.ps1"
    # The offline test exercises packaging without installing the agent SDK.
    script.write_text(
        """function dotnet {
    if ($args.Count -ne 1 -or $args[0] -cne '--version') { throw 'Expected dotnet --version.' }
    $global:LASTEXITCODE = 0
    $env:TEST_DOTNET_SDK
}
""" + step["run"],
        encoding="utf-8",
    )
    result = subprocess.run(
        [pwsh, "-NoProfile", "-File", str(script)], cwd=working_dir, env={
            **os.environ,
            "GITHUB_WORKSPACE": str(checkout),
            "RUNNER_TEMP": str(runner_temp),
            "SOURCE_COMMIT": source_commit,
            "TEST_DOTNET_SDK": sdk,
        }, capture_output=True, text=True, timeout=30,
    )

    artifact = runner_temp / "artifact"
    if not source_matches:
        assert result.returncode != 0
        assert "Unexpected MSI source checkout." in result.stdout + result.stderr
        assert not list(artifact.glob("*"))
        return

    assert result.returncode == 0, result.stdout + result.stderr
    name = f"SliAgent-{commit}.msi"
    assert {p.name for p in artifact.iterdir()} == {name, f"{name}.json"}
    assert (artifact / name).read_bytes() == b"synthetic MSI"
    assert json.loads((artifact / f"{name}.json").read_text(encoding="utf-8")) == {
        "source_commit": commit,
        "sha256": hashlib.sha256(b"synthetic MSI").hexdigest(),
        "dotnet_sdk": sdk,
    }


@pytest.mark.parametrize(("msvc", "sdk", "message"), [
    ("14.45.00000", "10.0.26100.0", "MSVC version must be 14.44.35207"),
    ("14.44.35207", "10.0.22621.0", "Windows SDK version must be 10.0.26100.0"),
    ("14.44.35207", "10.0.26100.0", "Missing locked toolchain input"),
])
def test_native_build_rejects_wrong_or_missing_toolchain_before_output(tmp_path, msvc, sdk, message):
    pwsh = shutil.which("pwsh")
    if not pwsh:
        pytest.skip("PowerShell is required to execute toolchain guards")
    output = tmp_path / "output/RegistrationCA.dll"
    result = subprocess.run([
        pwsh, "-NoProfile", "-File", str(ROOT / "agent-dotnet/tools/Build-RegistrationCA.ps1"),
        "-OutputFile", str(output), "-MsvcRoot", str(tmp_path / msvc),
        "-WindowsSdkRoot", str(tmp_path / "sdk"), "-WindowsSdkVersion", sdk,
    ], capture_output=True, text=True, timeout=30)
    assert result.returncode != 0
    assert message in result.stdout + result.stderr
    assert not output.parent.exists()

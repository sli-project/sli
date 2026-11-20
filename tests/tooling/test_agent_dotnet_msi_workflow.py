"""Offline contracts for the beta .NET MSI artifact workflow."""
import hashlib
import os
import re
import shutil
import subprocess
import zipfile
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
    assert set(config["on"]) == {"workflow_dispatch"}
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
    package = next(i for i, s in enumerate(steps) if "Compress-Archive" in s.get("run", ""))
    upload = next(i for i, s in enumerate(steps) if s.get("uses", "").startswith("actions/upload-artifact@"))
    assert build < check < package < upload
    assert not any("if" in s or "continue-on-error" in s for s in steps[build:upload + 1])
    assert steps[upload]["with"]["name"] == "sli-agent-dotnet-msi-${{ github.sha }}"
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


def test_msi_artifact_contains_complete_publish_and_matching_digests(tmp_path):
    pwsh = shutil.which("pwsh")
    if not pwsh:
        pytest.skip("PowerShell is required to execute the packaging step")
    output = tmp_path / "agent-dotnet"
    publish = output / "publish"
    publish.mkdir(parents=True)
    (output / "SliAgent.msi").write_bytes(b"synthetic MSI")
    payload = {"SliAgent.exe": b"synthetic executable", "SliAgent.dll": b"assembly", "runtime.json": b"{}"}
    for name, data in payload.items():
        (publish / name).write_bytes(data)
    step, = [s for s in workflow()["jobs"]["msi"]["steps"] if "Compress-Archive" in s.get("run", "")]
    script = tmp_path / "package.ps1"
    script.write_text(step["run"], encoding="utf-8")
    result = subprocess.run([pwsh, "-NoProfile", "-File", str(script)],
                            env={**os.environ, "RUNNER_TEMP": str(tmp_path)},
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    artifact = tmp_path / "artifact"
    assert {p.name for p in artifact.iterdir()} == {"SliAgent.msi", "SliAgent-publish-win-x64.zip", "SHA256SUMS"}
    with zipfile.ZipFile(artifact / "SliAgent-publish-win-x64.zip") as archive:
        assert {name.replace("\\", "/"): archive.read(name) for name in archive.namelist()} == payload
    lines = (artifact / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    for line in lines:
        digest, name = line.split("  ")
        assert digest == hashlib.sha256((artifact / name).read_bytes()).hexdigest()


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

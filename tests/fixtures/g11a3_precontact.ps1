# Synthetic precontact boundary fixture. The live operation is omitted.
function New-G11A3FailureJson {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            'python_preflight',
            'temporary_profile_check',
            'primary_profile_check',
            'profile_provision',
            'profile_attestation',
            'runner_invocation',
            'runner_result_validation',
            'cleanup'
        )]
        [string]$Stage
    )
    [ordered]@{
        status = 'failed'
        failure_stage = $Stage
        credential_values_exposed = $false
    } | ConvertTo-Json -Compress
}

function Get-G11A3SafeRunnerFailureJson {
    param([Parameter(Mandatory = $true)][string]$ProbeJson)

    try {
        $failureResult = $ProbeJson | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw 'g11a3_v4_probe_failed_without_safe_result'
    }
    $allowedFailureStages = @(
        'protected_profile_load',
        'plan_validation',
        'protected_values_validation',
        'identity_validation',
        'endpoint_resolution',
        'postgres_connect',
        'postgres_readonly_setup',
        'probe_entrypoint',
        'connection_close'
    )
    $failureFields = @($failureResult.PSObject.Properties.Name)
    $unexpectedFailureFields = @(
        $failureFields | Where-Object {
            $_ -notin @('status', 'failure_stage', 'credential_values_exposed')
        }
    )
    if (
        $failureResult.status -ne 'failed' -or
        $failureResult.failure_stage -notin $allowedFailureStages -or
        $failureResult.credential_values_exposed -ne $false -or
        $failureFields.Count -ne 3 -or
        $unexpectedFailureFields.Count -ne 0
    ) {
        throw 'g11a3_v4_probe_failed_with_unsafe_result'
    }
    $ProbeJson
}

$failureStage = 'python_preflight'
$failureJson = $null
$successJson = $null
$probeProfile = $null
$probeExit = 1
try {
# G11A3_POWERSHELL_OPERATION_START
$approvedMain = '<40-hex-merged-main-from-owner-approval>'
$actualMain = (& git rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $actualMain -ne $approvedMain) {
    throw 'approved_main_mismatch'
}

$worktreeRoot = (Get-Location).Path
$gitDir = (& git rev-parse --path-format=absolute --absolute-git-dir).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($gitDir)) {
    throw 'git_directory_unavailable'
}
$gitCommonDir = (& git rev-parse --path-format=absolute --git-common-dir).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($gitCommonDir)) {
    throw 'git_common_directory_unavailable'
}
if (
    [System.IO.Path]::GetFullPath($gitDir) -eq
    [System.IO.Path]::GetFullPath($gitCommonDir)
) {
    throw 'approved_linked_worktree_required'
}

$primaryRepositoryRoot = Split-Path $gitCommonDir -Parent
if (
    [System.IO.Path]::GetFullPath($worktreeRoot) -eq
    [System.IO.Path]::GetFullPath($primaryRepositoryRoot)
) {
    throw 'approved_non_primary_worktree_required'
}

$worktreeStatus = @(& git status --porcelain=v1 --untracked-files=all)
if ($LASTEXITCODE -ne 0) { throw 'approved_worktree_status_unavailable' }
if ($worktreeStatus.Count -ne 0) { throw 'approved_worktree_not_clean' }

$python = Join-Path $primaryRepositoryRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw 'approved_python_unavailable'
}
$approvedVenv = Split-Path (Split-Path $python -Parent) -Parent

    $env:SLI_G11A3_APPROVED_WORKTREE = $worktreeRoot
    $env:SLI_G11A3_APPROVED_VENV = $approvedVenv
    $pythonGuard = @'
# G11A3_BYTECODE_GUARD_START
import importlib.util
import os
import sys
from pathlib import Path

worktree = Path(os.environ["SLI_G11A3_APPROVED_WORKTREE"]).resolve(strict=True)
if (
    sys.flags.isolated != 1
    or sys.flags.no_site != 1
    or not sys.dont_write_bytecode
):
    raise SystemExit("approved_python_mode_invalid")
if "site" in sys.modules:
    raise SystemExit("approved_automatic_site_path_present")

def fail_walk(error):
    raise SystemExit("approved_worktree_bytecode_scan_failed") from error

for _root, directory_names, file_names in os.walk(
    worktree,
    topdown=True,
    onerror=fail_walk,
    followlinks=False,
):
    if any(name.casefold() == "__pycache__" for name in directory_names):
        raise SystemExit("approved_worktree_bytecode_present")
    if any(Path(name).suffix.casefold() == ".pyc" for name in file_names):
        raise SystemExit("approved_worktree_bytecode_present")

approved_venv = Path(os.environ["SLI_G11A3_APPROVED_VENV"]).resolve(strict=True)
if Path(sys.prefix).resolve(strict=True) != approved_venv:
    raise SystemExit("approved_venv_mismatch")
site_packages_path = approved_venv / "Lib" / "site-packages"
if not site_packages_path.is_dir():
    raise SystemExit("approved_site_packages_unavailable")
site_packages = site_packages_path.resolve(strict=True)
pywin32_paths = (
    site_packages / "win32",
    site_packages / "win32" / "lib",
)
if any(not path.is_dir() for path in pywin32_paths):
    raise SystemExit("approved_pywin32_path_unavailable")

def load_approved_pywin32_bootstrap():
    module_name = "pywin32_bootstrap"
    if module_name in sys.modules:
        raise SystemExit("approved_pywin32_bootstrap_preloaded")
    expected_bootstrap = (
        site_packages / "win32" / "lib" / "pywin32_bootstrap.py"
    ).resolve(strict=True)
    bootstrap_spec = importlib.util.spec_from_file_location(
        module_name,
        expected_bootstrap,
    )
    if (
        bootstrap_spec is None
        or bootstrap_spec.loader is None
        or bootstrap_spec.origin is None
        or Path(bootstrap_spec.origin).resolve(strict=True) != expected_bootstrap
    ):
        raise SystemExit("approved_pywin32_bootstrap_spec_invalid")
    bootstrap_module = importlib.util.module_from_spec(bootstrap_spec)
    sys.modules[module_name] = bootstrap_module
    try:
        bootstrap_spec.loader.exec_module(bootstrap_module)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise
    if Path(bootstrap_module.__file__).resolve(strict=True) != expected_bootstrap:
        raise SystemExit("approved_pywin32_bootstrap_outside_site_packages")
    return bootstrap_module

if any(
    "site-packages" in {part.casefold() for part in Path(entry).parts}
    for entry in sys.path
    if entry
):
    raise SystemExit("approved_automatic_site_path_present")
sys.path.insert(0, str(worktree))
sys.path.extend(str(path) for path in (site_packages, *pywin32_paths))
# G11A3_BYTECODE_GUARD_END
'@
    $pythonPreflight = $pythonGuard + [Environment]::NewLine + @'
import importlib
import importlib.metadata
import json
from packaging.requirements import Requirement

lock_path = worktree / "requirements.lock.txt"
if not lock_path.is_file():
    raise SystemExit("requirements_lock_unavailable")
for raw_line in lock_path.read_text(encoding="utf-8").splitlines():
    line = raw_line.strip()
    if not line or line.startswith("#"):
        continue
    requirement = Requirement(line)
    if requirement.marker is not None and not requirement.marker.evaluate():
        continue
    specifiers = list(requirement.specifier)
    if len(specifiers) != 1 or specifiers[0].operator != "==":
        raise SystemExit("requirements_lock_not_exact")
    if importlib.metadata.version(requirement.name) != specifiers[0].version:
        raise SystemExit("requirements_lock_version_mismatch")

pywin32_bootstrap = load_approved_pywin32_bootstrap()
import win32crypt

module_names = (
    "server.sli.ops.worker_supervisor_secrets",
    "scripts.maintenance.stage9_g11a3_probe_live_runner",
)
modules = [importlib.import_module(name) for name in module_names]
inside = []
for module in modules:
    module_file = Path(module.__file__).resolve(strict=True)
    try:
        module_file.relative_to(worktree)
    except ValueError as exc:
        raise SystemExit("project_module_outside_approved_worktree") from exc
    inside.append(True)

print(json.dumps({
    "status": "ok",
    "isolated": sys.flags.isolated == 1,
    "no_site": sys.flags.no_site == 1,
    "dont_write_bytecode": sys.dont_write_bytecode,
    "worktree_bytecode_absent": True,
    "lock_parity": True,
    "explicit_pywin32_bootstrap": True,
    "project_modules_inside_worktree": all(inside),
}, sort_keys=True))
'@

    $failureStage = 'python_preflight'
    $preflightJson = & $python -I -S -B -c $pythonPreflight 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'approved_python_preflight_failed' }
    $preflightResult = $preflightJson | ConvertFrom-Json -ErrorAction Stop
    if (
        $preflightResult.status -ne 'ok' -or
        -not $preflightResult.isolated -or
        -not $preflightResult.no_site -or
        -not $preflightResult.dont_write_bytecode -or
        -not $preflightResult.worktree_bytecode_absent -or
        -not $preflightResult.lock_parity -or
        -not $preflightResult.explicit_pywin32_bootstrap -or
        -not $preflightResult.project_modules_inside_worktree
    ) {
        throw 'approved_python_attestation_failed'
    }
    throw 'fixture_precontact_only'
    $profileCode = $pythonGuard + [Environment]::NewLine + @'
import json
pywin32_bootstrap = load_approved_pywin32_bootstrap()
import win32crypt
from server.sli.ops.worker_supervisor_secrets import (
    load_supervisor_environment,
    provision_supervisor_environment,
)
source_profile = Path(os.environ["SLI_G11A3_SUPERVISOR_PROFILE"])
protected_environment = {}
load_supervisor_environment(target=protected_environment, path=source_profile)
profile = Path(os.environ["SLI_G11A3_PROBE_PROFILE"])
print(json.dumps(
    provision_supervisor_environment(source=protected_environment, path=profile),
    sort_keys=True,
))
'@
# G11A3_POWERSHELL_OPERATION_END
}
catch {
    if ($null -eq $failureJson) {
        $failureJson = New-G11A3FailureJson -Stage $failureStage
    }
}
finally {
    $cleanupFailed = $false
    if (
        $null -ne $probeProfile -and
        (Test-Path -LiteralPath $probeProfile)
    ) {
        try {
            Remove-Item -LiteralPath $probeProfile -Force -ErrorAction Stop
        }
        catch {
            $cleanupFailed = $true
        }
    }
    Remove-Item Env:SLI_G11A3_PROBE_PROFILE -ErrorAction SilentlyContinue
    Remove-Item Env:SLI_G11A3_SUPERVISOR_PROFILE -ErrorAction SilentlyContinue
    Remove-Item Env:SLI_G11A3_APPROVED_WORKTREE -ErrorAction SilentlyContinue
    Remove-Item Env:SLI_G11A3_APPROVED_VENV -ErrorAction SilentlyContinue
    if ($cleanupFailed -and $null -eq $failureJson) {
        $failureJson = New-G11A3FailureJson -Stage 'cleanup'
    }
}

if ($null -ne $failureJson) {
    $failureJson
    exit 1
}
if ($null -eq $successJson) {
    New-G11A3FailureJson -Stage 'runner_result_validation'
    exit 1
}
$successJson

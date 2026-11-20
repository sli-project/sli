[CmdletBinding()]
param(
    [ValidateRange(10, 3600)]
    [int]$IntervalSeconds = 120
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0

$BootstrapJobSource = @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public sealed class BootstrapJob
{
    private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    private const int JobObjectExtendedLimitInformation = 9;
    private const uint HANDLE_FLAG_INHERIT = 0x00000001;

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObjectW(IntPtr jobAttributes, string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetHandleInformation(
        IntPtr handle, uint mask, uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(
        IntPtr job, int informationClass,
        ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION information,
        uint informationLength);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(
        IntPtr job, IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool IsProcessInJob(
        IntPtr process, IntPtr job, out bool result);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    private readonly IntPtr handle;

    private BootstrapJob(IntPtr handle)
    {
        this.handle = handle;
    }

    public bool BindingVerified { get { return true; } }
    public bool KillOnClose { get { return true; } }
    public bool HandleInheritable { get { return false; } }

    private static InvalidOperationException Failure(string code)
    {
        int error = Marshal.GetLastWin32Error();
        return new InvalidOperationException(
            code + ":" + error,
            new Win32Exception(error));
    }

    public static BootstrapJob CreateAndBindCurrentProcess()
    {
        IntPtr job = CreateJobObjectW(IntPtr.Zero, null);
        if (job == IntPtr.Zero || job == new IntPtr(-1))
        {
            throw Failure("bootstrap_job_create_failed");
        }

        try
        {
            // Handles created with null security attributes are non-inheritable;
            // enforce that contract explicitly before any child launch.
            if (!SetHandleInformation(job, HANDLE_FLAG_INHERIT, 0))
            {
                throw Failure("bootstrap_job_noninherit_failed");
            }

            JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits =
                new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            limits.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if (!SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                ref limits,
                (uint)Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION))))
            {
                throw Failure("bootstrap_job_kill_on_close_failed");
            }

            IntPtr process = GetCurrentProcess();
            if (!AssignProcessToJobObject(job, process))
            {
                throw Failure("bootstrap_job_assignment_failed");
            }

            bool bound;
            if (!IsProcessInJob(process, job, out bound) || !bound)
            {
                throw Failure("bootstrap_job_binding_not_verified");
            }

            return new BootstrapJob(job);
        }
        catch
        {
            // Before assignment this releases the failed job. After assignment,
            // kill-on-close deliberately fails the bootstrap shut.
            CloseHandle(job);
            throw;
        }
    }
}
'@

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$VenvRoot = Join-Path $ProjectRoot ".venv"
$Python = Join-Path $VenvRoot "Scripts\python.exe"
$Requirements = Join-Path $ProjectRoot "requirements.txt"
$Supervisor = Join-Path $ProjectRoot "scripts\maintenance\worker_supervisor.py"
$Evidence = Join-Path $ProjectRoot "data\maintenance\worker-supervisor-bootstrap.json"

function Write-BootstrapEvidence {
    param([hashtable]$Payload)
    $Payload.generated_at_utc = [DateTimeOffset]::UtcNow.ToString("o")
    $Payload.project_root = $ProjectRoot
    $Payload.python_exists = Test-Path -LiteralPath $Python
    $Payload.supervisor_exists = Test-Path -LiteralPath $Supervisor
    $Payload.requirements_exists = Test-Path -LiteralPath $Requirements
    $Payload.credential_values_exposed = $false
    $directory = Split-Path -Parent $Evidence
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
    $temporary = "$Evidence.tmp"
    $Payload | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $Evidence -Force
}

function Resolve-Uv {
    $command = Get-Command uv.exe -ErrorAction SilentlyContinue
    if (-not $command) {
        $command = Get-Command uv -ErrorAction SilentlyContinue
    }
    if ($command) {
        return [string]$command.Source
    }
    $candidates = @(
        (Join-Path $env:LOCALAPPDATA "hermes\bin\uv.exe"),
        (Join-Path $env:USERPROFILE ".local\bin\uv.exe")
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }
    throw "uv_not_found_for_worker_supervisor_bootstrap"
}

$LifecycleJob = $null
$BootstrapExitCode = 1
try {
    Add-Type -TypeDefinition $BootstrapJobSource -Language CSharp -ErrorAction Stop
    $LifecycleJob = [BootstrapJob]::CreateAndBindCurrentProcess()
    if (-not $LifecycleJob.BindingVerified) {
        throw "bootstrap_job_binding_not_verified"
    }

    if (-not (Test-Path -LiteralPath $Supervisor)) {
        throw "worker_supervisor_script_missing"
    }
    if (-not (Test-Path -LiteralPath $Requirements)) {
        throw "requirements_file_missing"
    }

    $Repaired = $false
    if (-not (Test-Path -LiteralPath $Python)) {
        $Uv = Resolve-Uv
        # Self-heal contract: uv venv followed by uv pip install.
        & $Uv venv $VenvRoot --python 3.14
        if ($LASTEXITCODE -ne 0) {
            throw "uv_venv_failed:$LASTEXITCODE"
        }
        & $Uv pip install --python $Python -r $Requirements
        if ($LASTEXITCODE -ne 0) {
            throw "uv_pip_install_failed:$LASTEXITCODE"
        }
        $Repaired = $true
    }

    & $Python -c "import psycopg, win32api"
    if ($LASTEXITCODE -ne 0) {
        $Uv = Resolve-Uv
        & $Uv pip install --python $Python -r $Requirements
        if ($LASTEXITCODE -ne 0) {
            throw "runtime_dependency_repair_failed:$LASTEXITCODE"
        }
        & $Python -c "import psycopg, win32api"
        if ($LASTEXITCODE -ne 0) {
            throw "runtime_dependency_preflight_failed:$LASTEXITCODE"
        }
        $Repaired = $true
    }

    Write-BootstrapEvidence @{
        status = "ready"
        environment_repaired = $Repaired
        interval_seconds = $IntervalSeconds
        lifecycle_job_bound = [bool]$LifecycleJob.BindingVerified
        lifecycle_job_kill_on_close = [bool]$LifecycleJob.KillOnClose
        lifecycle_job_handle_inheritable = [bool]$LifecycleJob.HandleInheritable
    }

    & $Python $Supervisor --interval-seconds $IntervalSeconds
    $SupervisorExitCode = $LASTEXITCODE
    Write-BootstrapEvidence @{
        status = "supervisor_exited"
        environment_repaired = $Repaired
        interval_seconds = $IntervalSeconds
        supervisor_exit_code = $SupervisorExitCode
        lifecycle_job_bound = [bool]$LifecycleJob.BindingVerified
        lifecycle_job_kill_on_close = [bool]$LifecycleJob.KillOnClose
        lifecycle_job_handle_inheritable = [bool]$LifecycleJob.HandleInheritable
    }
    $BootstrapExitCode = $SupervisorExitCode
} catch {
    Write-BootstrapEvidence @{
        status = "failed"
        interval_seconds = $IntervalSeconds
        error_type = $_.Exception.GetType().Name
        error_message = $_.Exception.Message
        lifecycle_job_bound = [bool]($null -ne $LifecycleJob)
    }
    $BootstrapExitCode = 1
} finally {
    # Do not explicitly close a kill-on-close job containing this process.
    # Retain it through the complete supervisor wait; process teardown closes
    # the handle and atomically terminates every remaining descendant.
    [GC]::KeepAlive($LifecycleJob)
}
exit $BootstrapExitCode

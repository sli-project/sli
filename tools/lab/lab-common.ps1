<#
Shared lab helpers. Dot-source only; Windows PowerShell 5.1, elevated administrator.
All lab state stays in C:\SLI-Lab, with a protected SYSTEM/Administrators DACL.
Never enable transcripts for provisioning/enrollment. Dot-sourcing has no side effects.
#>
#Requires -Version 5.1
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:LabRoot = 'C:\SLI-Lab'
$script:LabMarker = 'SLI-LAB-SYNTHETIC'

function Assert-LabAdministrator {
    $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'lab_admin_required' }
}

function Assert-LabPath([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    if ($full.StartsWith('\\')) { throw 'lab_local_path_required' }
    $current = $full
    while ($current) {
        if ((Test-Path -LiteralPath $current) -and
            ((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'lab_reparse_path_rejected'
        }
        $current = [IO.Path]::GetDirectoryName($current)
    }
    return $full
}

function New-LabAcl([bool]$Directory) {
    $type = if ($Directory) { 'Security.AccessControl.DirectorySecurity' } else { 'Security.AccessControl.FileSecurity' }
    $acl = New-Object $type
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    foreach ($text in @('S-1-5-18', 'S-1-5-32-544')) {
        $sid = New-Object Security.Principal.SecurityIdentifier($text)
        $inherit = if ($Directory) { 'ContainerInherit, ObjectInherit' } else { 'None' }
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', $inherit, 'None', 'Allow')))
    }
    return $acl
}

function Initialize-LabDirectory([string]$Path = $script:LabRoot) {
    $safe = Assert-LabPath $Path
    $null = [IO.Directory]::CreateDirectory($safe, (New-LabAcl $true))
    Set-Acl -LiteralPath $safe -AclObject (New-LabAcl $true)
}

function Write-LabSecret([string]$Path, [string]$Value) {
    $safe = Assert-LabPath $Path
    # CreateNew prevents overwriting an existing file/hard link; DACL precedes bytes.
    $stream = New-Object IO.FileStream($safe, [IO.FileMode]::CreateNew,
        [Security.AccessControl.FileSystemRights]::Write, [IO.FileShare]::None,
        4096, [IO.FileOptions]::WriteThrough, (New-LabAcl $false))
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally { $stream.Dispose() }
}

function New-LabPassword {
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $bytes = New-Object byte[] 32
        $rng.GetBytes($bytes)
        return 'Aa1!' + [Convert]::ToBase64String($bytes)
    } finally { $rng.Dispose() }
}

function Assert-LabDomain {
    Import-Module ActiveDirectory
    $domain = Get-ADDomain
    if ($domain.DNSRoot -cne 'demo.example' -or $domain.NetBIOSName -cne 'DEMO') { throw 'lab_foreign_domain_rejected' }
    if (-not (Test-Path -LiteralPath (Join-Path $script:LabRoot 'domain-owned'))) { throw 'lab_domain_not_owned' }
    return $domain
}

function Assert-LabOwned($Object) {
    if ($Object.Description -cne $script:LabMarker) { throw 'lab_existing_object_not_owned' }
}

function Ensure-LabObject([scriptblock]$Find, [scriptblock]$Create) {
    $object = & $Find
    if ($null -ne $object) { Assert-LabOwned $object; return $object }
    return (& $Create)
}

function ConvertTo-LabArgument([string]$Value) {
    if ($Value.Contains([char]0)) { throw 'lab_invalid_argument' }
    return '"' + [regex]::Replace([regex]::Replace($Value, '(\\*)"', '$1$1\"'), '(\\+)$', '$1$1') + '"'
}

function ConvertTo-LabMsiArgument([string]$Value) {
    # Windows Installer requires bare switches and quotes around property values only.
    if ($Value.Contains([char]0)) { throw 'lab_invalid_argument' }
    if ($Value.StartsWith('/')) { return $Value }
    if ($Value -cmatch '^([A-Z_][A-Z0-9_]*)=(.*)$') {
        return $Matches[1] + '="' + $Matches[2].Replace('"', '""') + '"'
    }
    return '"' + $Value.Replace('"', '""') + '"'
}

function Invoke-LabProcess([string]$File, [string[]]$Arguments, [int]$TimeoutSeconds = 120) {
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $File
    if ([IO.Path]::GetFileName($File) -ieq 'msiexec.exe') {
        $info.Arguments = ($Arguments | ForEach-Object { ConvertTo-LabMsiArgument $_ }) -join ' '
    } else {
        $info.Arguments = ($Arguments | ForEach-Object { ConvertTo-LabArgument $_ }) -join ' '
    }
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $info
    $started = $false
    try {
        if (-not $process.Start()) { throw 'lab_process_start_failed' }
        $started = $true
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) { $process.Kill(); throw 'lab_process_timeout' }
        $null = $stderr.GetAwaiter().GetResult()
        return [pscustomobject]@{ ExitCode = $process.ExitCode; Stdout = $stdout.GetAwaiter().GetResult() }
    } finally {
        if ($started -and -not $process.HasExited) { $process.Kill() }
        $process.Dispose()
    }
}

function New-LabExpected([string]$Scenario, [string]$Target, [datetime]$Start,
    [int[]]$EventIds, [bool]$Executed, [string]$ObjectId = '', [string]$SourceAddress = '',
    [string]$TargetSid = '', [string]$RelatedObjectId = '', [string]$EventObjectId = '') {
    return [ordered]@{
        schema_version = 1; run_id = [guid]::NewGuid().ToString(); scenario = $Scenario
        started_at_utc = $Start.ToUniversalTime().ToString('o'); ended_at_utc = [datetime]::UtcNow.ToString('o')
        actor = 'lab-system'; target = $Target
        source_address = $(if ($SourceAddress) { $SourceAddress } else { $null })
        event_ids = @($EventIds); executed = $Executed
        object_id = $(if ($ObjectId) { $ObjectId } else { $null })
        target_sid = $(if ($TargetSid) { $TargetSid } else { $null })
        related_object_id = $(if ($RelatedObjectId) { $RelatedObjectId } else { $null })
        event_object_id = $(if ($EventObjectId) { $EventObjectId } else { $null })
    }
}

function Assert-LabSshTarget([string]$Target) {
    if ($Target.StartsWith('-') -or $Target -cnotmatch '^(?:[A-Za-z0-9_.-]+@)?[A-Za-z0-9][A-Za-z0-9.-]*$') { throw 'lab_ssh_target_invalid' }
}

function Invoke-LabRemote([string]$Target, [string]$Key, [string]$Command, [int]$TimeoutSeconds = 120, [switch]$AllowReboot) {
    Assert-LabSshTarget $Target
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Command))
    $result = Invoke-LabProcess 'ssh.exe' @('-i', $Key, '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=accept-new',
        '-o', 'ConnectTimeout=10', $Target, 'powershell.exe', '-NoProfile', '-NonInteractive',
        '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $encoded) $TimeoutSeconds
    if ($result.ExitCode -ne 0 -and -not ($AllowReboot -and $result.Stdout.Contains('lab_rebooting'))) { throw 'lab_ssh_failed' }
    return $result.Stdout.Trim()
}

function Copy-LabFile([string]$Target, [string]$Key, [string]$LocalPath, [string]$RemotePath, [switch]$Download) {
    Assert-LabSshTarget $Target
    if ($RemotePath -cnotmatch '^C:/SLI-Lab/[A-Za-z0-9._*/-]+$' -or $RemotePath.Contains('..')) { throw 'lab_remote_path_invalid' }
    $remote = $Target + ':' + $RemotePath
    $paths = if ($Download) { @($remote, $LocalPath) } else { @($LocalPath, $remote) }
    $result = Invoke-LabProcess 'scp.exe' (@('-O', '-i', $Key, '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=accept-new') + $paths) 120
    if ($result.ExitCode -ne 0) { throw 'lab_scp_failed' }
}

function Write-LabExpected($Row) {
    $folder = Join-Path $script:LabRoot 'expected'
    Initialize-LabDirectory $folder
    $path = Join-Path $folder ([datetime]::UtcNow.ToString('yyyy-MM-dd') + '.jsonl')
    $null = Assert-LabPath $path
    $Row | ConvertTo-Json -Compress -Depth 8 | Add-Content -LiteralPath $path -Encoding UTF8
}

function Invoke-LabAudit([string]$Guid, [string]$Success = 'enable', [string]$Failure = 'enable') {
    $result = Invoke-LabProcess (Join-Path $env:WINDIR 'System32\auditpol.exe') @(
        '/set', "/subcategory:$Guid", "/success:$Success", "/failure:$Failure")
    if ($result.ExitCode -ne 0) { throw 'lab_audit_failed' }
}

<#
Owner PC: .\tools\lab\lab-tunnel.ps1 -Target $vds -IdentityFile $key
Runs a hidden reconnecting SSH supervisor. VDS port binds only 127.0.0.1; the local
SLI endpoint stays private. Existing host keys are checked; first connection uses TOFU.
Keep PC awake. Stop the printed supervisor PID AND its child ssh.exe to close the tunnel.
Use -Foreground for a blocking supervisor (Ctrl+C stops it). No server settings change.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Target,
    [string]$IdentityFile = (Join-Path $env:USERPROFILE '.ssh\id_ed25519_demo'),
    [switch]$Foreground
)
. "$PSScriptRoot\lab-common.ps1"

function Invoke-LabTunnel {
    Assert-LabSshTarget $Target
    $key = Assert-LabPath $IdentityFile
    if (-not (Test-Path -LiteralPath $key -PathType Leaf)) { throw 'lab_ssh_key_missing' }
    if (-not $Foreground) {
        $command = "& '" + $PSCommandPath.Replace("'", "''") + "' -Target '" + $Target.Replace("'", "''") +
            "' -IdentityFile '" + $key.Replace("'", "''") + "' -Foreground"
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
        $process = Start-Process -FilePath "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" `
            -ArgumentList @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $encoded) -WindowStyle Hidden -PassThru
        Write-Output ('lab_tunnel_supervisor_pid=' + $process.Id)
        return
    }
    $hash = [Security.Cryptography.SHA256]::Create()
    try { $label = ([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($Target.ToLowerInvariant())))).Replace('-', '') }
    finally { $hash.Dispose() }
    $mutex = New-Object Threading.Mutex($false, ('Local\SLI-Lab-Tunnel-' + $label))
    $locked = $false
    try {
        try { $locked = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $locked = $true }
        if (-not $locked) { return }
        while ($true) {
            # Capture diagnostics; they can contain operator names/addresses. Never echo them.
            try { $null = Invoke-LabProcess 'ssh.exe' @('-i', $key, '-N', '-o', 'BatchMode=yes',
                '-o', 'StrictHostKeyChecking=accept-new', '-o', 'ExitOnForwardFailure=yes', '-o', 'ConnectTimeout=10',
                '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=3',
                '-R', '127.0.0.1:8443:localhost:8443', $Target) 2147483 } catch { }
            Start-Sleep -Seconds 5
        }
    } finally {
        if ($locked) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    try { Invoke-LabTunnel } catch { Write-Output 'lab_tunnel_failed'; exit 1 }
}

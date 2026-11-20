<#
Owner PC (elevated PowerShell 5.1, OpenSSH client + Docker CLI):
  .\tools\lab\lab-orchestrate.ps1 -Target $vds -MsiPath $msi -CaFile $ca -MsiSha256 $sha256
SSH key defaults to ~/.ssh/id_ed25519_demo; bootstrap SSH administrator/key must exist.
Copies scripts, creates the domain across two reboots, waits for population/task readiness,
opens the tunnel, installs/prepares MSI, issues one token via local Docker and copies it.
Re-running reuses domain/objects/identity. An already enrolled agent needs no new token.
Only server write is issue_token; assignment of collection policies is deliberately separate.
Public CA must trust a server certificate with localhost SAN. No TLS bypass is supported.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Target,
    [Parameter(Mandatory)][string]$MsiPath,
    [Parameter(Mandatory)][string]$CaFile,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$MsiSha256,
    [string]$IdentityFile = (Join-Path $env:USERPROFILE '.ssh\id_ed25519_demo'),
    [ValidatePattern('^[A-Za-z0-9_.-]+$')][string]$Container = 'sli-api-1'
)
. "$PSScriptRoot\lab-common.ps1"

function Invoke-LabOrchestrator {
    Assert-LabAdministrator
    Assert-LabSshTarget $Target
    $key = Assert-LabPath $IdentityFile
    $msi = Assert-LabPath $MsiPath
    $ca = Assert-LabPath $CaFile
    if ((Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash -ine $MsiSha256) { throw 'lab_msi_hash_mismatch' }
    $pem = [IO.File]::ReadAllText($ca)
    if ($pem -notmatch '-----BEGIN CERTIFICATE-----' -or $pem -match 'PRIVATE KEY') { throw 'lab_public_ca_required' }
    # The secure parent exists before scp writes any bytes (including future token transfers).
    $bootstrap = '$ErrorActionPreference = ''Stop''; '
    foreach ($name in @('Assert-LabPath', 'New-LabAcl', 'Initialize-LabDirectory')) {
        $bootstrap += 'function ' + $name + ' {' + (Get-Item "function:$name").Definition + "}; "
    }
    $bootstrap += "Initialize-LabDirectory 'C:\SLI-Lab'; Initialize-LabDirectory 'C:\SLI-Lab\bootstrap'"
    $null = Invoke-LabRemote $Target $key $bootstrap
    foreach ($name in @('lab-common.ps1', 'lab-01-domain.ps1', 'lab-02-populate.ps1', 'lab-03-simulate.ps1', 'lab-04-agent.ps1', 'lab-data.json')) {
        Copy-LabFile $Target $key (Join-Path $PSScriptRoot $name) ("C:/SLI-Lab/$name")
    }
    $null = Invoke-LabRemote $Target $key '& C:\SLI-Lab\lab-01-domain.ps1' 900 -AllowReboot
    $ready = $false
    $watch = [Diagnostics.Stopwatch]::StartNew()
    while ($watch.Elapsed.TotalMinutes -lt 30) {
        try {
            $state = Invoke-LabRemote $Target $key "if (Test-Path C:\SLI-Lab\domain-ready) { 'ready' }" 30
            if ($state -ceq 'ready') { $ready = $true; break }
        } catch { }
        Start-Sleep -Seconds 15
    }
    if (-not $ready) { throw 'lab_domain_readiness_timeout' }
    Write-Output 'lab_domain_population_ready'
    & "$PSScriptRoot\lab-tunnel.ps1" -Target $Target -IdentityFile $key
    $tunnelReady = $false
    for ($i = 0; $i -lt 12; $i++) {
        $state = Invoke-LabRemote $Target $key '$c = New-Object Net.Sockets.TcpClient; try { $c.Connect(''127.0.0.1'',8443); ''ready'' } catch { ''pending'' } finally { $c.Dispose() }'
        if ($state -ceq 'ready') { $tunnelReady = $true; break }
        Start-Sleep -Seconds 5
    }
    if (-not $tunnelReady) { throw 'lab_tunnel_readiness_timeout' }
    Copy-LabFile $Target $key $msi 'C:/SLI-Lab/bootstrap/SLI-Agent-1.0.0-x64.msi'
    Copy-LabFile $Target $key $ca 'C:/SLI-Lab/bootstrap/server-ca.pem'
    $null = Invoke-LabRemote $Target $key ("& C:\SLI-Lab\lab-04-agent.ps1 -Phase Prepare -MsiSha256 '$MsiSha256'") 900
    $parent = Join-Path $env:ProgramData 'SLI-Lab-Transfer'
    Initialize-LabDirectory $parent
    $stage = Join-Path $parent ([guid]::NewGuid().ToString())
    Initialize-LabDirectory $stage
    try {
        Copy-LabFile $Target $key "$stage\prepare.json" 'C:/SLI-Lab/bootstrap/prepare.json' -Download
        $public = Get-Content -LiteralPath "$stage\prepare.json" -Raw | ConvertFrom-Json
        $hostId = [guid]::Parse($public.host_id).ToString()
        if ($public.key_fingerprint -cnotmatch '^[0-9a-f]{64}$') { throw 'lab_identity_invalid' }
        if (-not $public.enrolled) {
            $issued = Invoke-LabProcess 'docker.exe' @('exec', $Container, 'python', '-m', 'server.sli.agents.issue_token',
                '--host-id', $hostId, '--key-fingerprint', $public.key_fingerprint, '--ttl', '900', '--actor', 'sli-lab-orchestrator') 30
            if ($issued.ExitCode -ne 0 -or $issued.Stdout.Trim() -cnotmatch '^[A-Za-z0-9_-]{43}$') { throw 'lab_token_issue_failed' }
            Write-LabSecret "$stage\enrollment.token" $issued.Stdout.Trim()
            $issued = $null
            try { Copy-LabFile $Target $key "$stage\enrollment.token" 'C:/SLI-Lab/bootstrap/enrollment.token' }
            finally { Remove-Item -LiteralPath "$stage\enrollment.token" -Force }
            Write-Output (Invoke-LabRemote $Target $key '& C:\SLI-Lab\lab-04-agent.ps1 -Phase Enroll' 240)
        } else {
            Write-Output (Invoke-LabRemote $Target $key '& C:\SLI-Lab\lab-04-agent.ps1 -Phase Wait' 240)
        }
    } finally {
        $issued = $null
        # Delete only direct files in this uniquely created stage; never recurse through links.
        Get-ChildItem -LiteralPath (Assert-LabPath $stage) -File | ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force }
        Remove-Item -LiteralPath $stage -Force
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    try { Invoke-LabOrchestrator } catch { Write-Output 'lab_orchestration_failed'; exit 1 }
}

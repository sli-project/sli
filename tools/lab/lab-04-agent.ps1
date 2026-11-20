<#
VDS: lab-04-agent.ps1 -Phase Prepare -MsiSha256 <public SHA256>; then -Phase Enroll.
lab-orchestrate.ps1 copies MSI/CA, runs Prepare, issues a host-bound token on owner PC,
copies it into the already protected C:\SLI-Lab\bootstrap and runs Enroll.
URL is https://localhost:8443 through lab-tunnel.ps1; TLS CA and hostname are verified.
Reruns reuse an owned MSI identity; foreign config/service is rejected. No server policy
is assigned. Wait reports registered separately from collection_enabled (policy required).
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('Prepare', 'Enroll', 'Wait')][string]$Phase = 'Prepare',
    [ValidatePattern('^[0-9a-fA-F]{64}$')][string]$MsiSha256,
    [int]$WaitSeconds = 180
)
. "$PSScriptRoot\lab-common.ps1"

function Invoke-LabAgent {
    Assert-LabAdministrator
    $null = Assert-LabDomain
    Initialize-LabDirectory "$script:LabRoot\bootstrap"
    $root = Join-Path $env:ProgramData 'SLI\Agent'
    $configPath = Join-Path $root 'agent.json'
    $python = Join-Path $env:ProgramFiles 'SLI\Agent\python.exe'
    if ($Phase -eq 'Prepare') {
        if (-not $MsiSha256) { throw 'lab_msi_hash_required' }
        $msi = Assert-LabPath "$script:LabRoot\bootstrap\SLI-Agent-1.0.0-x64.msi"
        if ((Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash -ine $MsiSha256) { throw 'lab_msi_hash_mismatch' }
        $existing = Get-Service -Name SLIAgent -ErrorAction SilentlyContinue
        if ($existing -and (-not (Test-Path -LiteralPath "$root\.msi-owned") -or
            -not (Test-Path -LiteralPath "$script:LabRoot\agent-owned"))) { throw 'lab_foreign_agent_rejected' }
        if (-not $existing) {
            $ca = Assert-LabPath "$script:LabRoot\bootstrap\server-ca.pem"
            $pem = [IO.File]::ReadAllText($ca)
            if ($pem -notmatch '-----BEGIN CERTIFICATE-----' -or $pem -match 'PRIVATE KEY') { throw 'lab_ca_invalid' }
            'owned' | Set-Content -LiteralPath "$script:LabRoot\agent-owned" -Encoding UTF8
            $result = Invoke-LabProcess "$env:WINDIR\System32\msiexec.exe" @('/i', $msi, '/qn', '/norestart',
                'SERVER_URL=https://localhost:8443', "CA_FILE=$ca") 600
            if ($result.ExitCode -notin @(0, 3010)) { throw 'lab_msi_install_failed' }
        }
    }
    if (-not (Test-Path -LiteralPath "$root\.msi-owned") -or
        -not (Test-Path -LiteralPath "$script:LabRoot\agent-owned")) { throw 'lab_foreign_agent_rejected' }
    $config = Get-Content -LiteralPath (Assert-LabPath $configPath) -Raw | ConvertFrom-Json
    if ($config.server_url.TrimEnd('/') -cne 'https://localhost:8443' -or $config.service_identity_sid -cne 'S-1-5-18') { throw 'lab_agent_config_mismatch' }
    $state = Assert-LabPath $config.state_dir
    $identityPath = Join-Path $state 'identity.json'
    if ($Phase -eq 'Prepare') {
        Stop-Service SLIAgent
        $result = Invoke-LabProcess $python @('-I', '-B', '-m', 'sli_agent', '--config', $configPath, 'prepare')
        if ($result.ExitCode -ne 0) { throw 'lab_prepare_failed' }
        $identity = $result.Stdout | ConvertFrom-Json
        $hostId = [guid]::Parse($identity.host_id).ToString()
        if ($identity.key_fingerprint -cnotmatch '^[0-9a-f]{64}$') { throw 'lab_prepare_response_invalid' }
        [ordered]@{ host_id = $hostId; key_fingerprint = $identity.key_fingerprint; enrolled = (Test-Path -LiteralPath $identityPath) } |
            ConvertTo-Json -Compress | Set-Content -LiteralPath "$script:LabRoot\bootstrap\prepare.json" -Encoding UTF8
        Write-Output 'lab_agent_prepared'
        return
    }
    if ($Phase -eq 'Enroll') {
        $source = Assert-LabPath "$script:LabRoot\bootstrap\enrollment.token"
        $target = Assert-LabPath "$root\enrollment.token"
        Stop-Service SLIAgent
        try {
            if (-not (Test-Path -LiteralPath $identityPath)) {
                Set-Acl -LiteralPath $source -AclObject (New-LabAcl $false)
                $token = [IO.File]::ReadAllText($source).Trim()
                if ($token -cnotmatch '^[A-Za-z0-9_-]{43}$') { throw 'lab_token_invalid' }
                if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Force }
                Write-LabSecret $target $token
            }
        } finally {
            $token = $null
            if (Test-Path -LiteralPath $source) { Remove-Item -LiteralPath $source -Force }
        }
        Start-Service SLIAgent
    }
    if ($Phase -eq 'Wait') { Start-Service SLIAgent }
    $watch = [Diagnostics.Stopwatch]::StartNew()
    while ($watch.Elapsed.TotalSeconds -lt $WaitSeconds) {
        if ((Get-Service SLIAgent).Status -ne 'Running') { throw 'lab_agent_service_stopped' }
        if (Test-Path -LiteralPath $identityPath) {
            $statusPath = Join-Path $state 'status.json'
            if (Test-Path -LiteralPath $statusPath) {
                $status = Get-Content -LiteralPath $statusPath -Raw | ConvertFrom-Json
                if ($status.error_code -eq $null -and [datetime]::Parse($status.observed_at_utc).ToUniversalTime() -gt [datetime]::UtcNow.AddMinutes(-2)) {
                    if ($status.collection_enabled) { Write-Output 'lab_agent_registered_collection_active'; return }
                    Write-Output 'lab_agent_registered_waiting_for_server_policy'
                    return
                }
            }
        }
        Start-Sleep -Seconds 2
    }
    # The service normally consumes the file before trying enrollment. Remove timeout leftovers.
    if ($Phase -eq 'Enroll' -and (Test-Path -LiteralPath "$root\enrollment.token")) { Remove-Item -LiteralPath "$root\enrollment.token" -Force }
    throw 'lab_agent_registration_timeout'
}

if ($MyInvocation.InvocationName -ne '.') {
    try { Invoke-LabAgent } catch { Write-Output 'lab_agent_failed'; exit 1 }
}

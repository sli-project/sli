[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CollectorIdentity,

    [ValidateSet("Plan", "Apply", "Verify")]
    [string]$Action = "Plan",

    [string]$DomainController,
    [pscredential]$Credential,
    [string[]]$ProbeServer = @(),
    [string[]]$ProbeChannel = @(
        "Security",
        "System",
        "Directory Service",
        "Microsoft-Windows-PowerShell/Operational",
        "Microsoft-Windows-TaskScheduler/Operational",
        "DNS Server"
    ),
    [string]$Confirm
)

$ErrorActionPreference = "Stop"
$EventLogReadersSid = "S-1-5-32-573"
$ApplyConfirmation = "SLI-GRANT-EVENT-LOG-READ"
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$EvidencePath = Join-Path $ProjectRoot "data\maintenance\collector-read-access.json"

function Write-Evidence {
    param([hashtable]$Payload)

    $Payload.generated_at_utc = [DateTimeOffset]::UtcNow.ToString("o")
    $Payload.action = $Action
    $Payload.collector_identity = $CollectorIdentity
    $Payload.event_log_readers_sid = $EventLogReadersSid
    $Payload.credential_exposed = $false
    $directory = Split-Path -Parent $EvidencePath
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
    $temporary = "$EvidencePath.tmp"
    $Payload | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $EvidencePath -Force
}

function Resolve-WritableServer {
    if (-not [string]::IsNullOrWhiteSpace($DomainController)) {
        return $DomainController.Trim()
    }
    $discovered = Get-ADDomainController -Discover -Writable -ErrorAction Stop
    $resolved = [string](@($discovered.HostName)[0])
    if ([string]::IsNullOrWhiteSpace($resolved)) {
        throw "A writable domain controller could not be discovered."
    }
    return $resolved
}

function Get-AdObjects {
    param([string]$Server)

    $common = @{
        Server = $Server
        ErrorAction = "Stop"
    }
    if ($null -ne $Credential) {
        $common.Credential = $Credential
    }
    $samAccountName = ($CollectorIdentity -split "\\")[-1]
    $group = Get-ADGroup @common -Identity $EventLogReadersSid
    $user = Get-ADUser @common -Identity $samAccountName
    $members = @(Get-ADGroupMember @common -Identity $group)
    return @{
        Common = $common
        Group = $group
        User = $user
        Members = $members
    }
}

Import-Module ActiveDirectory -ErrorAction Stop
$server = Resolve-WritableServer
$objects = Get-AdObjects -Server $server
$common = $objects.Common
$group = $objects.Group
$user = $objects.User
$userSid = [string]$user.SID
$alreadyMember = @(
    $objects.Members |
        Where-Object { ([string]$_.SID).Equals($userSid, [System.StringComparison]::OrdinalIgnoreCase) }
).Count -gt 0

if ($Action -eq "Plan") {
    $result = @{
        status = "planned"
        writable_domain_controller = $server
        collector_sam_account_name = [string]$user.SamAccountName
        collector_sid = $userSid
        target_group = [string]$group.DistinguishedName
        already_member = $alreadyMember
        changes_required = -not $alreadyMember
        apply_confirmation = $ApplyConfirmation
        surveyed_system_changed = $false
    }
    Write-Evidence $result
    $result | ConvertTo-Json -Depth 6
    exit 0
}

if ($Action -eq "Apply") {
    if ($Confirm -ne $ApplyConfirmation) {
        throw "Apply requires -Confirm $ApplyConfirmation"
    }
    if (-not $alreadyMember) {
        Add-ADGroupMember @common -Identity $group -Members $user
    }
    $readback = Get-AdObjects -Server $server
    $isMember = @(
        $readback.Members |
            Where-Object { ([string]$_.SID).Equals($userSid, [System.StringComparison]::OrdinalIgnoreCase) }
    ).Count -gt 0
    if (-not $isMember) {
        throw "Event Log Readers membership was not confirmed after Apply."
    }
    $result = @{
        status = "ok"
        writable_domain_controller = $server
        collector_sam_account_name = [string]$user.SamAccountName
        collector_sid = $userSid
        target_group = [string]$group.DistinguishedName
        already_member = $alreadyMember
        membership_confirmed = $isMember
        changed = -not $alreadyMember
        relogin_required = -not $alreadyMember
        surveyed_system_changed = -not $alreadyMember
    }
    Write-Evidence $result
    $result | ConvertTo-Json -Depth 6
    exit 0
}

if ($ProbeServer.Count -eq 0) {
    throw "Verify requires at least one -ProbeServer."
}

$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$currentPrincipal = [string]$currentIdentity.Name
$currentSid = [string]$currentIdentity.User.Value
$tokenGroups = @($currentIdentity.Groups | ForEach-Object { [string]$_.Value })
$expectedPrincipal = $CollectorIdentity
$principalMatches = (
    $currentPrincipal.Equals($expectedPrincipal, [System.StringComparison]::OrdinalIgnoreCase) -or
    (($currentPrincipal -split "\\")[-1]).Equals(
        ($expectedPrincipal -split "\\")[-1],
        [System.StringComparison]::OrdinalIgnoreCase
    )
)
$sidMatches = $currentSid.Equals($userSid, [System.StringComparison]::OrdinalIgnoreCase)
$groupInToken = $tokenGroups -contains $EventLogReadersSid

if (-not $principalMatches -or -not $sidMatches) {
    throw "Verify must run as the exact collector identity after a new Windows logon."
}

$probes = @()
foreach ($probeHost in $ProbeServer) {
    foreach ($channel in $ProbeChannel) {
        $previousErrorPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = "Continue"
            $nativeOutput = @(
                & "$env:SystemRoot\System32\wevtutil.exe" `
                    qe $channel "/r:$probeHost" "/c:1" "/rd:true" "/f:xml" 2>&1
            )
            $exitCode = $LASTEXITCODE
        }
        finally {
            $ErrorActionPreference = $previousErrorPreference
        }
        $probes += @{
            server = $probeHost
            channel = $channel
            status = if ($exitCode -eq 0) { "ok" } else { "failed" }
            exit_code = $exitCode
            error = if ($exitCode -eq 0) { $null } else { [string]($nativeOutput | Select-Object -First 1) }
        }
    }
}
$failed = @($probes | Where-Object { $_.status -ne "ok" })
$result = @{
    status = if ($failed.Count -eq 0) { "ok" } else { "failed" }
    writable_domain_controller = $server
    current_principal = $currentPrincipal
    current_sid = $currentSid
    collector_sid = $userSid
    directory_membership_confirmed = $alreadyMember
    group_in_current_token = $groupInToken
    group_token_note = "Domain-local resource groups may be added only to the remote resource token; remote channel probes are authoritative."
    probes = $probes
    failed_probe_count = $failed.Count
    surveyed_system_changed = $false
}
Write-Evidence $result
$result | ConvertTo-Json -Depth 8
if ($failed.Count -gt 0) {
    exit 2
}

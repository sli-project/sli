[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Plan", "Apply", "Verify")]
    [string]$Action,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedComputerName,

    [string]$Channel = "DNS Server",

    [string]$Confirm,

    [string]$EvidencePath
)

$ErrorActionPreference = "Stop"
$EventLogReadersSid = "S-1-5-32-573"
$ApplyConfirmation = "SLI-GRANT-LOCAL-CHANNEL-READ"
$CurrentComputerName = [string]$env:COMPUTERNAME
$CurrentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$CurrentPrincipal = New-Object System.Security.Principal.WindowsPrincipal($CurrentIdentity)
$IsAdministrator = $CurrentPrincipal.IsInRole(
    [System.Security.Principal.WindowsBuiltInRole]::Administrator
)

function Get-BoundedText {
    param(
        [AllowNull()][object]$Value,
        [int]$MaximumLength = 600
    )

    if ($null -eq $Value) {
        return $null
    }
    $text = ([string]$Value) -replace "[\u0000-\u0008\u000B\u000C\u000E-\u001F]", " "
    $text = $text.Trim()
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $null
    }
    if ($text.Length -gt $MaximumLength) {
        return $text.Substring(0, $MaximumLength)
    }
    return $text
}

function Write-Result {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Payload,
        [int]$ExitCode = 0
    )

    $Payload.action = $Action
    $Payload.channel = $Channel
    $Payload.computer_name = $CurrentComputerName
    $Payload.expected_computer_name = $ExpectedComputerName
    $Payload.operator_identity = $CurrentIdentity.Name
    $Payload.administrator_token = [bool]$IsAdministrator
    $Payload.event_log_readers_sid = $EventLogReadersSid
    $Payload.credential_exposed = $false
    $Payload.generated_at_utc = [DateTimeOffset]::UtcNow.ToString("o")
    $json = $Payload | ConvertTo-Json -Depth 8
    if (-not [string]::IsNullOrWhiteSpace($EvidencePath)) {
        $fullEvidencePath = [System.IO.Path]::GetFullPath($EvidencePath)
        $directory = Split-Path -Parent $fullEvidencePath
        if (-not [string]::IsNullOrWhiteSpace($directory)) {
            New-Item -ItemType Directory -Force -Path $directory | Out-Null
        }
        $temporary = "$fullEvidencePath.tmp"
        $json | Set-Content -LiteralPath $temporary -Encoding UTF8
        Move-Item -LiteralPath $temporary -Destination $fullEvidencePath -Force
    }
    $json
    exit $ExitCode
}

function Invoke-LocalWevtutil {
    param([string[]]$Arguments)

    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $output = @(& "$env:SystemRoot\System32\wevtutil.exe" @Arguments 2>&1)
        return @{
            ExitCode = $LASTEXITCODE
            Output = @($output | ForEach-Object { [string]$_ })
        }
    }
    finally {
        $ErrorActionPreference = $previousPreference
    }
}

function Get-LocalChannelSddl {
    $read = Invoke-LocalWevtutil -Arguments @("gl", $Channel, "/f:xml")
    if ($read.ExitCode -ne 0) {
        throw "Cannot read the local channel configuration: $(Get-BoundedText -Value ($read.Output | Select-Object -First 1))"
    }
    [xml]$document = [string]::Join([Environment]::NewLine, $read.Output)
    $sddl = [string]$document.channel.channelAccess
    if ([string]::IsNullOrWhiteSpace($sddl)) {
        throw "The local channel access SDDL is missing."
    }
    return $sddl
}

function Get-SddlPlan {
    param([Parameter(Mandatory = $true)][string]$Sddl)

    $descriptor = New-Object System.Security.AccessControl.CommonSecurityDescriptor(
        $false,
        $false,
        $Sddl
    )
    $hasRead = @(
        $descriptor.DiscretionaryAcl |
            Where-Object {
                $_.AceQualifier -eq [System.Security.AccessControl.AceQualifier]::AccessAllowed -and
                ([string]$_.SecurityIdentifier).Equals(
                    $EventLogReadersSid,
                    [System.StringComparison]::OrdinalIgnoreCase
                ) -and
                (($_.AccessMask -band 1) -eq 1)
            }
    ).Count -gt 0
    $proposedSddl = $Sddl
    if (-not $hasRead) {
        $readAce = "(A;;0x1;;;$EventLogReadersSid)"
        $saclIndex = $Sddl.IndexOf("S:", [System.StringComparison]::Ordinal)
        $proposedSddl = if ($saclIndex -ge 0) {
            $Sddl.Insert($saclIndex, $readAce)
        }
        else {
            "$Sddl$readAce"
        }
        [void](New-Object System.Security.AccessControl.CommonSecurityDescriptor(
            $false,
            $false,
            $proposedSddl
        ))
    }
    return @{
        HasRead = [bool]$hasRead
        ProposedSddl = [string]$proposedSddl
    }
}

if (-not $CurrentComputerName.Equals(
    $ExpectedComputerName,
    [System.StringComparison]::OrdinalIgnoreCase
)) {
    Write-Result -Payload @{
        status = "blocked"
        reason = "unexpected_computer"
        surveyed_system_changed = $false
    } -ExitCode 2
}

try {
    $originalSddl = Get-LocalChannelSddl
    $plan = Get-SddlPlan -Sddl $originalSddl
}
catch {
    Write-Result -Payload @{
        status = "blocked"
        reason = "channel_acl_unreadable"
        diagnostic = Get-BoundedText -Value $_.Exception.Message
        surveyed_system_changed = $false
    } -ExitCode 2
}

if ($Action -eq "Plan") {
    Write-Result -Payload @{
        status = if ($IsAdministrator) { "planned" } else { "blocked" }
        reason = if ($IsAdministrator) { $null } else { "administrator_token_required" }
        read_ace_present = [bool]$plan.HasRead
        change_required = -not [bool]$plan.HasRead
        current_sddl = $originalSddl
        proposed_sddl = [string]$plan.ProposedSddl
        apply_confirmation = $ApplyConfirmation
        surveyed_system_changed = $false
    } -ExitCode $(if ($IsAdministrator) { 0 } else { 2 })
}

if ($Action -eq "Apply") {
    if (-not $IsAdministrator) {
        Write-Result -Payload @{
            status = "blocked"
            reason = "administrator_token_required"
            surveyed_system_changed = $false
        } -ExitCode 2
    }
    if ($Confirm -ne $ApplyConfirmation) {
        Write-Result -Payload @{
            status = "blocked"
            reason = "apply_confirmation_required"
            apply_confirmation = $ApplyConfirmation
            surveyed_system_changed = $false
        } -ExitCode 2
    }
    if (-not [bool]$plan.HasRead) {
        $write = Invoke-LocalWevtutil -Arguments @(
            "sl", $Channel, "/ca:$($plan.ProposedSddl)"
        )
        if ($write.ExitCode -ne 0) {
            $failedReadbackSddl = $null
            try {
                $failedReadbackSddl = Get-LocalChannelSddl
            }
            catch {
                $failedReadbackSddl = $null
            }
            Write-Result -Payload @{
                status = "failed"
                reason = "channel_acl_write_failed"
                exit_code = $write.ExitCode
                diagnostic = Get-BoundedText -Value ($write.Output | Select-Object -First 1)
                original_sddl = $originalSddl
                readback_sddl = $failedReadbackSddl
                surveyed_system_changed = if ($null -eq $failedReadbackSddl) {
                    $null
                }
                else {
                    -not $failedReadbackSddl.Equals(
                        $originalSddl,
                        [System.StringComparison]::Ordinal
                    )
                }
            } -ExitCode 3
        }
    }
}

try {
    $finalSddl = Get-LocalChannelSddl
    $finalPlan = Get-SddlPlan -Sddl $finalSddl
}
catch {
    Write-Result -Payload @{
        status = "failed"
        reason = "channel_acl_readback_failed"
        original_sddl = $originalSddl
        surveyed_system_changed = if ($Action -eq "Apply" -and -not [bool]$plan.HasRead) {
            $null
        }
        else {
            $false
        }
        diagnostic = Get-BoundedText -Value $_.Exception.Message
    } -ExitCode 3
}

$query = Invoke-LocalWevtutil -Arguments @(
    "qe", $Channel, "/c:1", "/rd:true", "/f:xml"
)
$changed = $Action -eq "Apply" -and -not $finalSddl.Equals(
    $originalSddl,
    [System.StringComparison]::Ordinal
)
$verified = [bool]$finalPlan.HasRead -and $query.ExitCode -eq 0
Write-Result -Payload @{
    status = if ($verified) { "ok" } else { "failed" }
    read_ace_present = [bool]$finalPlan.HasRead
    query_status = if ($query.ExitCode -eq 0) { "ok" } else { "failed" }
    query_exit_code = $query.ExitCode
    query_error = if ($query.ExitCode -eq 0) {
        $null
    }
    else {
        Get-BoundedText -Value ($query.Output | Select-Object -First 1)
    }
    original_sddl = $originalSddl
    final_sddl = $finalSddl
    changed = [bool]$changed
    surveyed_system_changed = [bool]$changed
    external_service_readback_required = $true
} -ExitCode $(if ($verified) { 0 } else { 2 })

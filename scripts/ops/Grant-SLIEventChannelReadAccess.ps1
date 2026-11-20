[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$Server,

    [Parameter(Mandatory = $true)]
    [string[]]$Channel,

    [ValidateSet("Plan", "Apply", "Verify")]
    [string]$Action = "Plan",

    [string]$Confirm,

    [System.Management.Automation.PSCredential]$Credential
)

$ErrorActionPreference = "Stop"
$EventLogReadersSid = "S-1-5-32-573"
$ApplyConfirmation = "SLI-GRANT-CHANNEL-READ"
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$EvidencePath = Join-Path $ProjectRoot "data\maintenance\event-channel-read-access.json"

function Expand-ListArgument {
    param([string[]]$Value)

    return @(
        $Value |
            ForEach-Object { [string]$_ -split "," } |
            ForEach-Object { $_.Trim() } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Select-Object -Unique
    )
}

$Server = @(Expand-ListArgument -Value $Server)
$Channel = @(Expand-ListArgument -Value $Channel)
if ($Server.Count -eq 0 -or $Channel.Count -eq 0) {
    throw "At least one server and one channel are required."
}

function Write-Evidence {
    param([hashtable]$Payload)

    $Payload.generated_at_utc = [DateTimeOffset]::UtcNow.ToString("o")
    $Payload.action = $Action
    $Payload.event_log_readers_sid = $EventLogReadersSid
    $Payload.credential_exposed = $false
    $directory = Split-Path -Parent $EvidencePath
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
    $temporary = "$EvidencePath.tmp"
    $Payload | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $EvidencePath -Force
}

function Invoke-Wevtutil {
    param([string[]]$Arguments)

    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $output = @(& "$env:SystemRoot\System32\wevtutil.exe" @Arguments 2>&1)
        return @{
            ExitCode = $LASTEXITCODE
            Output = $output
        }
    }
    finally {
        $ErrorActionPreference = $previousPreference
    }
}

function Get-BoundedDiagnosticText {
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

function Set-RemoteChannelSddl {
    param(
        [Parameter(Mandatory = $true)][string]$TargetServer,
        [Parameter(Mandatory = $true)][string]$TargetChannel,
        [Parameter(Mandatory = $true)][string]$Sddl
    )
    if ($null -eq $Credential) {
        return Invoke-Wevtutil -Arguments @(
            "sl", $TargetChannel, "/r:$TargetServer", "/ca:$Sddl"
        )
    }
    $sessionOption = New-PSSessionOption -OpenTimeout 10000 -OperationTimeout 30000
    try {
        $remote = Invoke-Command `
            -ComputerName $TargetServer `
            -Credential $Credential `
            -Authentication Negotiate `
            -SessionOption $sessionOption `
            -ScriptBlock {
                param([string]$ChannelName, [string]$ChannelSddl)
                $output = @(
                    & "$env:SystemRoot\System32\wevtutil.exe" `
                        "sl" $ChannelName "/ca:$ChannelSddl" 2>&1
                )
                [pscustomobject]@{
                    ExitCode = $LASTEXITCODE
                    Output = @($output | ForEach-Object { [string]$_ })
                }
            } `
            -ArgumentList $TargetChannel, $Sddl `
            -ErrorAction Stop
        return @{
            ExitCode = [int]$remote.ExitCode
            Output = @($remote.Output)
            Diagnostic = if ([int]$remote.ExitCode -eq 0) {
                $null
            }
            else {
                @{
                    failure_kind = "remote_wevtutil_failed"
                    message = Get-BoundedDiagnosticText -Value ($remote.Output | Select-Object -First 1)
                }
            }
        }
    }
    catch {
        return @{
            ExitCode = -1
            Output = @("powershell_remoting_failed")
            Diagnostic = @{
                failure_kind = "powershell_remoting_failed"
                exception_type = $_.Exception.GetType().FullName
                category_reason = Get-BoundedDiagnosticText -Value $_.CategoryInfo.Reason
                fully_qualified_error_id = Get-BoundedDiagnosticText -Value $_.FullyQualifiedErrorId
                hresult = $_.Exception.HResult
                message = Get-BoundedDiagnosticText -Value $_.Exception.Message
            }
        }
    }
}

function Test-RemoteCredentialContext {
    param(
        [Parameter(Mandatory = $true)][string]$TargetServer
    )

    if ($null -eq $Credential) {
        return @{
            server = $TargetServer
            status = "not_requested"
        }
    }
    $sessionOption = New-PSSessionOption -OpenTimeout 10000 -OperationTimeout 30000
    try {
        $remote = Invoke-Command `
            -ComputerName $TargetServer `
            -Credential $Credential `
            -Authentication Negotiate `
            -SessionOption $sessionOption `
            -ScriptBlock {
                $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
                [pscustomobject]@{
                    Identity = $identity.Name
                    IsAdministrator = $principal.IsInRole(
                        [System.Security.Principal.WindowsBuiltInRole]::Administrator
                    )
                    ComputerName = $env:COMPUTERNAME
                }
            } `
            -ErrorAction Stop
        return @{
            server = $TargetServer
            status = if ([bool]$remote.IsAdministrator) { "ready" } else { "insufficient" }
            remote_identity = [string]$remote.Identity
            remote_computer = [string]$remote.ComputerName
            administrator_token = [bool]$remote.IsAdministrator
        }
    }
    catch {
        return @{
            server = $TargetServer
            status = "failed"
            administrator_token = $null
            diagnostic = @{
                failure_kind = "powershell_remoting_failed"
                exception_type = $_.Exception.GetType().FullName
                category_reason = Get-BoundedDiagnosticText -Value $_.CategoryInfo.Reason
                fully_qualified_error_id = Get-BoundedDiagnosticText -Value $_.FullyQualifiedErrorId
                hresult = $_.Exception.HResult
                message = Get-BoundedDiagnosticText -Value $_.Exception.Message
            }
        }
    }
}

function Get-ChannelSddl {
    param([string]$TargetServer, [string]$TargetChannel)

    $read = Invoke-Wevtutil -Arguments @(
        "gl", $TargetChannel, "/r:$TargetServer", "/f:xml"
    )
    if ($read.ExitCode -ne 0) {
        throw "Cannot read $TargetServer / $TargetChannel channel configuration: $($read.Output | Select-Object -First 1)"
    }
    [xml]$document = [string]::Join([Environment]::NewLine, $read.Output)
    $sddl = [string]$document.channel.channelAccess
    if ([string]::IsNullOrWhiteSpace($sddl)) {
        throw "Channel access SDDL is missing for $TargetServer / $TargetChannel."
    }
    return $sddl
}

function Get-SddlPlan {
    param([string]$Sddl)

    $descriptor = New-Object System.Security.AccessControl.CommonSecurityDescriptor(
        $false,
        $false,
        $Sddl
    )
    $targetSid = New-Object System.Security.Principal.SecurityIdentifier(
        $EventLogReadersSid
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
        $saclIndex = $Sddl.IndexOf(
            "S:",
            [System.StringComparison]::Ordinal
        )
        $proposedSddl = if ($saclIndex -ge 0) {
            $Sddl.Insert($saclIndex, $readAce)
        }
        else {
            "$Sddl$readAce"
        }
        # Refuse before Apply if the minimally edited descriptor is invalid.
        [void](New-Object System.Security.AccessControl.CommonSecurityDescriptor(
            $false,
            $false,
            $proposedSddl
        ))
    }
    return @{
        HasRead = $hasRead
        Sddl = $proposedSddl
    }
}

$plans = @()
foreach ($targetServer in $Server) {
    foreach ($targetChannel in $Channel) {
        try {
            $currentSddl = Get-ChannelSddl `
                -TargetServer $targetServer `
                -TargetChannel $targetChannel
            $plan = Get-SddlPlan -Sddl $currentSddl
            $plans += @{
                server = $targetServer
                channel = $targetChannel
                read_status = "ok"
                read_error = $null
                read_ace_present = [bool]$plan.HasRead
                change_required = -not [bool]$plan.HasRead
                current_sddl = $currentSddl
                proposed_sddl = [string]$plan.Sddl
            }
        }
        catch {
            $plans += @{
                server = $targetServer
                channel = $targetChannel
                read_status = "failed"
                read_error = $_.Exception.Message
                read_ace_present = $null
                change_required = $null
                current_sddl = $null
                proposed_sddl = $null
            }
        }
    }
}

$unreadable = @($plans | Where-Object { $_.read_status -ne "ok" })
if ($Action -eq "Plan") {
    $credentialPreflight = @()
    if ($null -ne $Credential) {
        $credentialPreflight = @(
            $Server |
                ForEach-Object {
                    Test-RemoteCredentialContext -TargetServer ([string]$_)
                }
        )
    }
    $credentialBlocked = @(
        $credentialPreflight |
            Where-Object { $_.status -ne "ready" }
    )
    $planBlocked = $unreadable.Count -gt 0 -or $credentialBlocked.Count -gt 0
    $result = @{
        status = if ($planBlocked) { "blocked" } else { "planned" }
        changes_required = @($plans | Where-Object { $_.change_required -eq $true }).Count
        unreadable_target_count = $unreadable.Count
        targets = $plans
        apply_confirmation = $ApplyConfirmation
        surveyed_system_changed = $false
        credential_preflight = $credentialPreflight
    }
    Write-Evidence $result
    $result | ConvertTo-Json -Depth 8
    exit $(if ($planBlocked) { 2 } else { 0 })
}

if ($unreadable.Count -gt 0) {
    $result = @{
        status = "blocked"
        reason = "target_channel_acl_unreadable"
        unreadable_target_count = $unreadable.Count
        targets = $plans
        surveyed_system_changed = $false
    }
    Write-Evidence $result
    $result | ConvertTo-Json -Depth 8
    exit 2
}

if ($Action -eq "Apply") {
    if ($Confirm -ne $ApplyConfirmation) {
        throw "Apply requires -Confirm $ApplyConfirmation"
    }
    $applyResults = @()
    foreach ($plan in $plans) {
        if (-not $plan.change_required) {
            $applyResults += @{
                server = $plan.server
                channel = $plan.channel
                status = "already_present"
                exit_code = 0
            }
            continue
        }
        $write = Set-RemoteChannelSddl `
            -TargetServer ([string]$plan.server) `
            -TargetChannel ([string]$plan.channel) `
            -Sddl ([string]$plan.proposed_sddl)
        if ($write.ExitCode -ne 0) {
            $applyResults += @{
                server = $plan.server
                channel = $plan.channel
                status = "failed"
                exit_code = $write.ExitCode
                error_code = "wevtutil_set_log_failed"
                diagnostic = $write.Diagnostic
            }
            $remaining = @(
                $plans |
                    Where-Object {
                        $_.change_required -and
                        -not @($applyResults.server).Contains($_.server)
                    } |
                    ForEach-Object {
                        @{
                            server = $_.server
                            channel = $_.channel
                            status = "not_attempted"
                            exit_code = $null
                        }
                    }
            )
            $result = @{
                status = "failed"
                reason = "target_channel_acl_write_failed"
                failed_target = @{
                    server = $plan.server
                    channel = $plan.channel
                    exit_code = $write.ExitCode
                    diagnostic = $write.Diagnostic
                }
                apply_results = @($applyResults) + @($remaining)
                targets = $plans
                surveyed_system_changed = $null
                readback_required = $true
            }
            Write-Evidence $result
            $result | ConvertTo-Json -Depth 8
            exit 3
        }
        $applyResults += @{
            server = $plan.server
            channel = $plan.channel
            status = "applied_pending_readback"
            exit_code = 0
        }
    }
}

$readback = @()
foreach ($targetServer in $Server) {
    foreach ($targetChannel in $Channel) {
        $currentSddl = Get-ChannelSddl `
            -TargetServer $targetServer `
            -TargetChannel $targetChannel
        $acl = Get-SddlPlan -Sddl $currentSddl
        $query = Invoke-Wevtutil -Arguments @(
            "qe", $targetChannel, "/r:$targetServer", "/c:1", "/rd:true", "/f:xml"
        )
        $readback += @{
            server = $targetServer
            channel = $targetChannel
            read_ace_present = [bool]$acl.HasRead
            query_status = if ($query.ExitCode -eq 0) { "ok" } else { "failed" }
            query_exit_code = $query.ExitCode
            query_error = if ($query.ExitCode -eq 0) { $null } else { [string]($query.Output | Select-Object -First 1) }
        }
    }
}
$failed = @(
    $readback |
        Where-Object { -not $_.read_ace_present -or $_.query_status -ne "ok" }
)
$result = @{
    status = if ($failed.Count -eq 0) { "ok" } else { "failed" }
    changed = $Action -eq "Apply" -and @($plans | Where-Object { $_.change_required }).Count -gt 0
    targets = $readback
    failed_target_count = $failed.Count
    surveyed_system_changed = $Action -eq "Apply" -and @($plans | Where-Object { $_.change_required }).Count -gt 0
}
Write-Evidence $result
$result | ConvertTo-Json -Depth 8
if ($failed.Count -gt 0) {
    exit 2
}

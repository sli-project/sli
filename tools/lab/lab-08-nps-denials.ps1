<#
One-shot real NPS LAB scenario. Run locally on the administrator-owned NPS host.
Requires IAS, a preconfigured loopback RADIUS client, the nps-owned marker, and
credentials\nps-radius.secret provisioned with Write-LabSecret. No service/audit/
RADIUS policy is changed. Channel secrets remain in the SLI secret mechanism.
Native 6273 readback proves only Windows evidence, never SLI queue or delivery.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('Boundary', 'Surge')][string]$Scenario = 'Boundary',
    [ValidateRange(60, 3600)][int]$WindowSeconds = 300
)
. "$PSScriptRoot\lab-common.ps1"

function Invoke-NpsDenials([int]$Count) {
    $output = & python "$PSScriptRoot\nps_denials.py" --count $Count
    if ($LASTEXITCODE -ne 0) { throw 'nps_lab_attempt_unverified' }
    $result = $output | ConvertFrom-Json
    if ($result.state -ne 'radius_reject_verified' -or $result.rejected -ne $Count) {
        throw 'nps_lab_attempt_unverified'
    }
}

function Get-NpsDenials([datetime]$Since) {
    $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 6273; StartTime = $Since } -ErrorAction SilentlyContinue)
    $matching = @($events | Where-Object {
        $xml = [xml]$_.ToXml()
        $name = @($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' })
        $name.Count -eq 1 -and $name[0].'#text' -ceq 'labsim-nps-denied'
    })
    return $matching.Count
}

try {
    Assert-LabAdministrator
    $null = Assert-LabDomain
    if (-not (Test-Path -LiteralPath (Join-Path $script:LabRoot 'nps-owned')) -or
        (Get-Service -Name IAS -ErrorAction SilentlyContinue).Status -ne 'Running') {
        throw 'nps_lab_not_available'
    }
    $start = [datetime]::Now
    if ($Scenario -eq 'Boundary') {
        Invoke-NpsDenials 19
        Start-Sleep -Seconds 2
        $below = Get-NpsDenials $start
        if ($below -ne 19) { throw 'nps_lab_6273_unverified' }
        Invoke-NpsDenials 1
        Start-Sleep -Seconds 2
        $current = Get-NpsDenials $start
        if ($current -ne 20) { throw 'nps_lab_6273_unverified' }
        $previous = $null
    } else {
        # Reserve a full window for the already-running collector's tail
        # coverage before generating the comparison baseline.
        Start-Sleep -Seconds $WindowSeconds
        $start = [datetime]::Now
        Invoke-NpsDenials 20
        Start-Sleep -Seconds 2
        $previous = Get-NpsDenials $start
        if ($previous -ne 20) { throw 'nps_lab_6273_unverified' }
        # Equal source windows must also be confirmed by collection coverage.
        $remaining = $WindowSeconds - ([datetime]::Now - $start).TotalSeconds
        if ($remaining -gt 0) { Start-Sleep -Seconds ([math]::Ceiling($remaining)) }
        $currentStart = [datetime]::Now
        Invoke-NpsDenials 60
        Start-Sleep -Seconds 2
        $current = Get-NpsDenials $currentStart
        if ($current -ne 60) { throw 'nps_lab_6273_unverified' }
    }
    [pscustomobject]@{ state = 'native_6273_verified'; scenario = $Scenario; current = $current
        previous = $previous; window_seconds = $WindowSeconds; coverage = 'not_proven'
        sli_queue = 'not_proven'; smtp = 'not_proven'; telegram = 'not_proven' } | ConvertTo-Json -Compress
} catch {
    # Fixed diagnostics only; no exception messages, EventData or identities.
    '{"state":"not_proven","code":"nps_lab_unavailable"}'
    exit 1
}

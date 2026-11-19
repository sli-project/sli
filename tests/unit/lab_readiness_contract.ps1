#Requires -Version 5.1
# Hermetic fixtures only. No domain provisioning, services, task or registry operations.
$ErrorActionPreference = 'Stop'
$lab = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../tools/lab'))
. "$lab/lab-verify.ps1" -DomainId 1 -ApiKeyFile 'synthetic-unused' -IdentityFile 'synthetic-unused'
function New-TestRow([string]$Scenario = 'workday_logon') {
    $r = New-LabExpected $Scenario 'lab.u003' ([datetime]'2026-10-09T10:00:00Z') @(4624) $true
    $r.ended_at_utc = '2026-10-09T10:00:01Z'
    if ($Scenario.StartsWith('file_')) {
        $r.actor = 'DEMO\lab.u003'; $r.event_ids = @(4663, 5145)
        $r.file_path = '\\LAB-DC01.demo.example\LAB-Finance\fixture.txt'
        $r.share = 'LAB-Finance'; $r.operation = 'read'; $r.destination_path = $null
        $r.outcome = 'success'; $r.audit_required = $true; $r.local_time = '2026-10-09T13:00:01+03:00'
    }
    return [pscustomobject]$r
}
foreach ($scenario in @('file_read', 'file_modify', 'file_delete', 'file_rename', 'file_permissions',
    'file_mass_read', 'file_mass_delete', 'file_off_hours', 'file_denied', 'file_fixture_create')) {
    Assert-LabExpected (New-TestRow $scenario)
}
foreach ($change in @(
    @{ outcome = "success`n" },
    @{ file_path = "\\LAB-DC01.demo.example\LAB-Finance\fixture.txt`n" },
    @{ destination_path = "\\LAB-DC01.demo.example\LAB-Finance\fixture.txt`n" },
    @{ local_time = "2026-10-09T13:00:01+03:00`n" },
    @{ target_sid = "S-1-5-21-1-2-3-4`n" },
    @{ target = "lab.u003`n"; actor = "DEMO\lab.u003`n" },
    @{ actor = 'DEMO\Administrator' }, @{ share = 'SYSVOL' }, @{ operation = 'auditpol' },
    @{ file_path = '\\LAB-DC01.demo.example\LAB-Finance\..\private.txt' },
    @{ destination_path = 'C:\private.txt' }, @{ audit_required = $false }, @{ outcome = 'anything' },
    @{ local_time = '2026-10-09T13:00:01' }, @{ event_ids = @(4624) }, @{ scenario = 'file_unknown' }
)) {
    $row = New-TestRow 'file_read'
    foreach ($key in $change.Keys) { $row.$key = $change[$key] }
    $rejected = $false
    try { Assert-LabExpected $row } catch { $rejected = $true }
    if (-not $rejected) { throw 'invalid_file_row_accepted' }
}
$row = New-TestRow 'file_read'
$row.PSObject.Properties.Remove('share')
$row | Add-Member -NotePropertyName SHARE -NotePropertyValue 'LAB-Finance'
$rejected = $false
try { Assert-LabExpected $row } catch { $rejected = $true }
if (-not $rejected) { throw 'case_mutated_schema_key_accepted' }
$row = New-TestRow 'file_read'; $row | Add-Member -NotePropertyName private -NotePropertyValue 'synthetic'
try { Assert-LabExpected $row; throw 'extra_field_accepted' } catch {
    if ($_.Exception.Message -eq 'extra_field_accepted') { throw }
}
$stage = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $stage
try {
    $key = Join-Path $stage 'synthetic.key'; [IO.File]::WriteAllText($key, 'synthetic-unused')
    . "$lab/lab-verify.ps1" -DomainId 1 -ApiKeyFile $key -IdentityFile $key -ExpectedDirectory $stage
    # Normalize JSON numeric types across PS editions, as existing collection fixtures do.
    function ConvertFrom-Json {
        param([Parameter(ValueFromPipeline)][string]$InputObject)
        process {
            $row = Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $InputObject
            $row.schema_version = [int]$row.schema_version
            $row.event_ids = @($row.event_ids | ForEach-Object { [int]$_ })
            return $row
        }
    }
    $script:AdMatches = 0; $script:FormattedRows = @()
    function Read-LabReport { param($Resource, $Filters, $Collection) return [pscustomobject]@{ Items = @(); Complete = $true } }
    function Find-LabEvent {
        param($Expected, $Rows, $Used)
        if (Test-LabFileExpected $Expected) { throw 'file_sent_to_ad_matcher' }
        $script:AdMatches++
        return [pscustomobject]@{ event_db_id = 1 }
    }
    function Format-Table { param([Parameter(ValueFromPipeline)]$InputObject, [switch]$AutoSize) process { $script:FormattedRows += $InputObject } }
    foreach ($mode in @('ad', 'mixed', 'file', 'failed-file')) {
        $script:FormattedRows = @(); $script:AdMatches = 0
        $rows = switch ($mode) {
            'ad' { New-TestRow }
            'mixed' { New-TestRow; New-TestRow 'file_read' }
            'file' { New-TestRow 'file_read' }
            'failed-file' { $r = New-TestRow 'file_read'; $r.executed = $false; $r }
        }
        $rows | ForEach-Object { $_ | ConvertTo-Json -Compress } | Set-Content (Join-Path $stage 'expected.jsonl') -Encoding UTF8
        $code = Invoke-LabVerify
        $wanted = if ($mode -eq 'ad') { 0 } else { 2 }
        if ($code -ne $wanted) { throw 'verification_exit_contract' }
        $matches = if ($mode -in @('ad', 'mixed')) { 1 } else { 0 }
        if ($script:AdMatches -ne $matches) { throw 'ad_comparison_skipped' }
        if ($mode -ne 'ad' -and @($script:FormattedRows | Where-Object { $_.File -eq 'UNAVAILABLE' }).Count -ne 1) { throw 'file_comparison_claimed_complete' }
        if ($mode -eq 'failed-file' -and $script:FormattedRows[0].Event -ne 'SCENARIO_FAILED') { throw 'scenario_failure_hidden' }
    }
} finally {
    Get-ChildItem -LiteralPath $stage -File | Remove-Item -Force
    Remove-Item -LiteralPath $stage -Force
}
Write-Output 'lab_readiness_contract_passed'

# Copy only the bootstrap under test; fake all Windows/domain dependencies and child scripts.
& {
    $stage = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $stage
    try {
        Copy-Item -LiteralPath "$lab/lab-01-domain.ps1" -Destination "$stage/lab-01-domain.ps1"
        [IO.File]::WriteAllText("$stage/lab-common.ps1", '$script:LabRoot = $PSScriptRoot')
        . "$stage/lab-01-domain.ps1"
        function Assert-LabAdministrator {}
        function Initialize-LabDirectory {}
        function Assert-LabDomain {}
        function Get-CimInstance { return [pscustomobject]@{ PartOfDomain = $true; DomainRole = 5 } }
        function Get-ADDomainController {
            if (Test-Path -LiteralPath "$script:LabRoot\domain-ready") { throw 'stale_marker_during_ad_poll' }
            $script:AdPolls++
            if ($script:AdUnavailable) { throw 'synthetic_ad_unavailable' }
        }
        function Start-Sleep { param($Seconds) $script:MockSleeps++ }
        function Unregister-ScheduledTask { param($TaskName, [switch]$Confirm, $ErrorAction) $script:Removed++ }
        $Continue = $true
        foreach ($stale in @($false, $true)) {
            foreach ($failure in @('ad-unavailable', 'populate', 'simulate', 'throw', 'none')) {
                $script:Removed = 0
                $script:AdUnavailable = $failure -eq 'ad-unavailable'
                $script:AdPolls = 0; $script:MockSleeps = 0
                $global:ReadinessChildCalls = 0
                $marker = Join-Path $stage 'domain-ready'
                if (Test-Path $marker) { Remove-Item $marker }
                if ($stale) { 'old-ready' | Set-Content -LiteralPath $marker }
                $populate = if ($failure -eq 'populate') { 'exit 1' } elseif ($failure -eq 'throw') { "throw 'synthetic'" } else { "Write-Output 'synthetic_population'" }
                $simulate = if ($failure -eq 'simulate') { 'exit 1' } else { "Write-Output 'synthetic_simulation'" }
                [IO.File]::WriteAllText("$stage/lab-02-populate.ps1", '$global:ReadinessChildCalls++; ' + $populate)
                [IO.File]::WriteAllText("$stage/lab-03-simulate.ps1", '$global:ReadinessChildCalls++; ' + $simulate)
                $global:LASTEXITCODE = 99
                $failed = $false
                try { $null = Invoke-LabDomain } catch { $failed = $true }
                if ($failure -eq 'ad-unavailable' -and ($script:AdPolls -ne 60 -or $script:MockSleeps -ne 60 -or $global:ReadinessChildCalls -ne 0)) { throw 'ad_unavailable_poll_contract' }
                if ($failure -eq 'none') {
                    if ($failed -or -not (Test-Path $marker) -or $script:Removed -ne 1) { throw 'successful_bootstrap_not_ready' }
                } elseif (-not $failed -or (Test-Path $marker) -or $script:Removed -ne 0) { throw 'failed_bootstrap_claimed_ready' }
            }
        }
    } finally {
        Get-ChildItem -LiteralPath $stage -File | Remove-Item -Force
        Remove-Item -LiteralPath $stage -Force
    }
}
Write-Output 'lab_bootstrap_exit_contract_passed'

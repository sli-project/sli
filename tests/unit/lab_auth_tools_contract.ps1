#Requires -Version 5.1
# Portable hermetic authentication contracts; no AD, network, DB or secret access.
param([switch]$ReportFailures)
$ErrorActionPreference = 'Stop'
$env:USERPROFILE = [IO.Path]::GetTempPath()
$lab = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../tools/lab'))
function Assert-Test([bool]$Condition, [string]$Code) { if (-not $Condition) { throw ('lab_auth_test_' + $Code) } }
. "$lab/lab-03-simulate.ps1"
$script:captured = @()
function Write-LabExpected { param($Row); $script:captured += $Row }
function Invoke-LabBind { param($Account, $Password, $SuccessExpected); return $true }
$null = Invoke-LabLogon 'single_account_brute' 'lab.u001' $false 'synthetic-unused-password'
Assert-Test (($script:captured[0].event_ids -join ',') -eq '4625,4776') 'failure_alternatives'
Assert-Test $script:captured[0].executed 'attempt_executed'

. "$lab/lab-verify.ps1" -DomainId 1 -ApiKeyFile 'synthetic-unused'
$script:LabHeaders = @{}
$script:LabExactCache = @{}
$script:LabEvidenceUnavailable = $false
if ($ReportFailures) {
    Add-Type -TypeDefinition @'
using System;
public class LabTestHttpFailure : Exception {
    public object Response { get; private set; }
    public LabTestHttpFailure(object response) : base("synthetic-private-response") { Response = response; }
}
'@
    function Invoke-RestMethod {
        param($Method, $Uri, $Headers, $TimeoutSec)
        if ($script:PartialPage) {
            $script:PartialPage = $false
            return @{ state = 'ok'; items = @(1); has_more = $true; next_cursor = 'next' }
        }
        throw (New-Object LabTestHttpFailure ([pscustomobject]@{ StatusCode = [Net.HttpStatusCode]$script:HttpStatus }))
    }
    foreach ($case in @(@{ status = 401; reason = 'lab_report_authentication_required' },
                        @{ status = 403; reason = 'lab_report_access_denied' })) {
        $script:HttpStatus = $case.status
        $script:PartialPage = $true
        $output = @(Read-LabReport 'events.journal/data' @{} 3>&1)
        $warnings = @($output | Where-Object { $_ -is [Management.Automation.WarningRecord] })
        $page = $output | Where-Object { $_ -isnot [Management.Automation.WarningRecord] }
        Assert-Test (-not $page.Complete -and $page.Items.Count -eq 1 -and $page.Items[0] -eq 1) 'auth_preserves_partial_page'
        Assert-Test ($warnings.Count -eq 1 -and [string]$warnings[0] -eq $case.reason) 'report_auth_reason'
        Assert-Test ((Get-LabMatchState $null $page.Complete) -eq 'UNAVAILABLE') 'auth_not_missing'
        $script:LabExactCache.Clear()
        $output = @(Read-LabExactEvent '42' 3>&1)
        $warnings = @($output | Where-Object { $_ -is [Management.Automation.WarningRecord] })
        $item = $output | Where-Object { $_ -isnot [Management.Automation.WarningRecord] }
        Assert-Test ($null -eq $item) 'exact_auth_unavailable'
        Assert-Test ($warnings.Count -eq 1 -and [string]$warnings[0] -eq $case.reason) 'exact_auth_reason'
    }
    $script:HttpStatus = 500
    $output = @(Read-LabReport 'events.journal/data' @{} 3>&1)
    $warnings = @($output | Where-Object { $_ -is [Management.Automation.WarningRecord] })
    $page = $output | Where-Object { $_ -isnot [Management.Automation.WarningRecord] }
    Assert-Test (-not $page.Complete -and $page.Items.Count -eq 0 -and $warnings.Count -eq 0) 'other_error_not_auth'
    Write-Output 'lab_report_failure_contracts_passed'
    exit 0
}
$expected = [pscustomobject](New-LabExpected 'single_account_brute' 'lab.u001' ([datetime]'2026-10-09T10:00:00Z') @(4625, 4776) $true '' '127.0.0.1')
$expected.ended_at_utc = '2026-10-09T10:00:02Z'
Assert-LabExpected $expected
function New-TestEvent([int]$Id, [int]$EventId, $Code) {
    return [pscustomobject]@{ event_db_id = $Id; event_id = $EventId; time_created_utc = '2026-10-09T10:00:01Z';
        source_host = @{ hostname = 'LAB-DC01.demo.example' }; affected_account = @{ name = 'lab.u001' };
        source_address = $null; result_code = $Code }
}
$events = @(1..20 | ForEach-Object { $event = New-TestEvent $_ 4625 $null; $event.source_address = '127.0.0.1'; $event }) +
    @(21..25 | ForEach-Object { New-TestEvent $_ 4776 '0xc0000234' })
$used = @{}
foreach ($attempt in 1..25) { Assert-Test ($null -ne (Find-LabEvent $expected $events $used)) 'all_25_attempts_found' }
Assert-Test ($used.Count -eq 25) 'unique_evidence'
Assert-Test ($null -eq (Find-LabEvent $expected $events $used)) 'no_event_reuse'

# Old JSONL manifests must also recognize failed NTLM credential validation.
$expected.event_ids = @(4625)
$ntlm = New-TestEvent 30 4776 '0xC0000234'
Assert-Test ($null -ne (Find-LabEvent $expected @($ntlm) @{})) 'legacy_manifest'
foreach ($scenario in @('wrong_password', 'password_spray', 'disabled_logon')) {
    $expected.scenario = $scenario
    Assert-Test ($null -ne (Find-LabEvent $expected @($ntlm) @{})) ('ntlm_' + $scenario)
}
$expected.scenario = 'single_account_brute'
foreach ($code in @('0', '0x0', '0x00000000', '00000000', $null, '', 'invalid', '0xc0000234junk')) {
    $script:LabEvidenceUnavailable = $false
    $ntlm.result_code = $code
    Assert-Test ($null -eq (Find-LabEvent $expected @($ntlm) @{})) 'nonfailure_rejected'
    if (-not $code -or $code -in @('invalid', '0xc0000234junk')) {
        Assert-Test $script:LabEvidenceUnavailable 'unknown_status_unavailable'
    }
}
$ntlm.result_code = '0xc0000234'
$ntlm.affected_account.name = 'lab.u002'
Assert-Test ($null -eq (Find-LabEvent $expected @($ntlm) @{})) 'foreign_account'
$ntlm.affected_account.name = 'lab.u001'
$ntlm.source_host.hostname = 'LAB-WS01.demo.example'
Assert-Test ($null -eq (Find-LabEvent $expected @($ntlm) @{})) 'foreign_dc'
$ntlm.source_host.hostname = 'LAB-DC01.demo.example'
$ntlm.time_created_utc = '2026-10-08T10:00:01Z'
Assert-Test ($null -eq (Find-LabEvent $expected @($ntlm) @{})) 'outside_window'
$ntlm.time_created_utc = '2026-10-09T10:00:01Z'
$expected.scenario = 'workday_logon'; $expected.event_ids = @(4624)
Assert-Test ($null -eq (Find-LabEvent $expected @($ntlm) @{})) 'failure_not_success'
$expected.scenario = 'single_account_brute'; $expected.event_ids = @(4625)
$logon = New-TestEvent 31 4625 $null
$logon.source_address = '192.0.2.1'
Assert-Test ($null -eq (Find-LabEvent $expected @($logon) @{})) '4625_source_still_checked'

# Journal rows need exact-event hydration to obtain the saved native Status.
function Invoke-RestMethod {
    param($Method, $Uri, $Headers, $TimeoutSec)
    return @{ item = @{ event_db_id = 32; event_id = 4776; time_created_utc = '2026-10-09T10:00:01Z';
        server = 'LAB-DC01.demo.example'; target_user_name = 'lab.u001'; event_data = @{ Status = '0xc0000234' } } }
}
$journal = [pscustomobject]@{ id = 32; event_id = 4776; time_created_utc = '2026-10-09T10:00:01Z' }
Assert-Test ($null -ne (Find-LabEvent $expected @($journal) @{})) 'hydrated_status'
Write-Output 'lab_auth_contracts_passed'

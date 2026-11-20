<#
Owner PC: .\tools\lab\lab-verify.ps1 -Target $vds -DomainId $demoDomainId -ApiKeyFile $protectedApiKey
Downloads expected/*.jsonl through SSH, or use -ExpectedDirectory for an existing copy.
Requires an existing API key with report/evidence grants and trusted HTTPS on owner PC.
Only GET requests; never creates keys or assigns policies. API errors/partial pages are
UNAVAILABLE, not MISSING. Each event is consumed once; matching checks DC, time and identity.
Snapshot changes require baseline + later snapshots; collection delays may require rerun.
The table contains synthetic targets only, no source rows, operator names or API diagnostics.
Exit 0 = all required evidence found; 2 = missing/unavailable/failed scenario; 1 = setup error.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Target,
    [string]$ExpectedDirectory,
    [Parameter(Mandatory)][ValidateRange(1, 2147483647)][int]$DomainId,
    [Parameter(Mandatory)][string]$ApiKeyFile,
    [string]$IdentityFile = (Join-Path $env:USERPROFILE '.ssh\id_ed25519_demo'),
    [string]$ServerUrl = 'https://localhost:8443',
    [string]$SourceHost = 'LAB-DC01.demo.example',
    [ValidateRange(0, 60)][int]$EventToleranceSeconds = 2,
    [ValidateRange(60, 86400)][int]$SnapshotLagSeconds = 86400
)
. "$PSScriptRoot\lab-common.ps1"

function Get-LabField($Object, [string]$Path) {
    foreach ($part in $Path.Split('.')) {
        if ($null -eq $Object) { return $null }
        if ($Object -is [Collections.IDictionary]) { $Object = $Object[$part] }
        else { $property = $Object.PSObject.Properties[$part]; if ($null -eq $property) { return $null }; $Object = $property.Value }
    }
    return $Object
}

function Test-LabFileExpected($Row) {
    return ($Row.scenario -is [string] -and $Row.scenario -cin @(
        'file_read', 'file_modify', 'file_delete', 'file_rename', 'file_permissions',
        'file_mass_read', 'file_mass_delete', 'file_off_hours', 'file_denied', 'file_fixture_create'))
}

function Assert-LabExpected($Row) {
    $required = @('schema_version', 'run_id', 'scenario', 'started_at_utc', 'ended_at_utc', 'actor', 'target',
        'source_address', 'event_ids', 'executed', 'object_id', 'target_sid', 'related_object_id', 'event_object_id')
    $fileRow = Test-LabFileExpected $Row
    if ($fileRow) { $required += @('file_path', 'share', 'operation', 'destination_path', 'outcome', 'audit_required', 'local_time') }
    $keys = @($Row.PSObject.Properties.Name)
    if ($keys.Count -ne $required.Count -or @($required | Where-Object { $keys -cnotcontains $_ }).Count) { throw 'lab_expected_schema_invalid' }
    $actor = if ($fileRow) { 'DEMO\' + $Row.target } else { 'lab-system' }
    if ($Row.schema_version -isnot [int] -or $Row.schema_version -ne 1 -or $Row.actor -cne $actor -or $Row.target -cnotmatch '^lab\.(u\d{3}|svc\d{2})\z|^LAB-[A-Za-z]+\z') { throw 'lab_expected_identity_invalid' }
    $scenarios = @('workday_logon', 'night_logon', 'wrong_password', 'password_spray', 'single_account_brute',
        'disabled_logon', 'privileged_add', 'gpo_change', 'audit_change')
    if ((-not $fileRow -and $Row.scenario -cnotin $scenarios) -or $Row.executed -isnot [bool] -or $Row.source_address -notin @($null, '127.0.0.1')) { throw 'lab_expected_scenario_invalid' }
    if ($fileRow) {
        if ($Row.share -isnot [string] -or $Row.share -cnotin @('LAB-Finance', 'LAB-HR', 'LAB-Projects', 'LAB-Common', 'LAB-Exchange') -or
            $Row.operation -isnot [string] -or $Row.operation -cnotin @('read', 'create', 'modify', 'delete', 'rename', 'permissions') -or
            $Row.audit_required -isnot [bool] -or -not $Row.audit_required -or $Row.outcome -isnot [string] -or
            $Row.outcome -cnotmatch '^(success|access_denied|not_attempted|logon_error|empty_file|missing_file|unknown_operation|io_error_\d+)\z') {
            throw 'lab_expected_file_invalid'
        }
        $prefix = '\\LAB-DC01.demo.example\' + $Row.share + '\'
        foreach ($key in @('file_path', 'destination_path')) {
            $path = $Row.$key
            if ($key -eq 'destination_path' -and $null -eq $path) { continue }
            if ($path -isnot [string] -or -not $path.StartsWith($prefix, [StringComparison]::Ordinal) -or
                $path.Substring($prefix.Length) -cnotmatch '^([A-Za-z0-9_-]+\.(txt|csv)|Сводка-01\.csv)\z') { throw 'lab_expected_file_path_invalid' }
        }
        # Parse only explicit offsets; DateTimeOffset.Parse otherwise assumes local time.
        if ($Row.local_time -isnot [string] -or $Row.local_time -cnotmatch '(Z|[+-]\d{2}:\d{2})\z') { throw 'lab_expected_file_time_invalid' }
        try { $null = [datetimeoffset]::Parse($Row.local_time) } catch { throw 'lab_expected_file_time_invalid' }
    }
    $null = [guid]::Parse($Row.run_id)
    foreach ($key in @('object_id', 'related_object_id', 'event_object_id')) { if ($null -ne $Row.$key) { $null = [guid]::Parse($Row.$key) } }
    if ($Row.target_sid -and $Row.target_sid -cnotmatch '^S-1-5-21-\d+-\d+-\d+-\d+\z') { throw 'lab_expected_sid_invalid' }
    $start = [datetimeoffset]::Parse($Row.started_at_utc)
    $end = [datetimeoffset]::Parse($Row.ended_at_utc)
    if ($start.Offset -ne [timespan]::Zero -or $end.Offset -ne [timespan]::Zero -or $end -lt $start) { throw 'lab_expected_time_invalid' }
    if ($Row.event_ids -isnot [array] -or -not $Row.event_ids.Count) { throw 'lab_expected_events_invalid' }
    $eventIds = if ($fileRow) { @(4656, 4660, 4663, 4670, 5145) } else { @(4624, 4625, 4776, 4719, 4728, 5136) }
    foreach ($id in $Row.event_ids) { if ($id -isnot [int] -or $id -notin $eventIds) { throw 'lab_expected_events_invalid' } }
}

function Write-LabAuthenticationFailure($Failure) {
    # Fixed codes only: HTTP error bodies and exception messages can contain secrets.
    switch ([int](Get-LabField $Failure 'Exception.Response.StatusCode')) {
        401 { Write-Warning 'lab_report_authentication_required' }
        403 { Write-Warning 'lab_report_access_denied' }
    }
}

function Read-LabReport([string]$Resource, [hashtable]$Filters, [string]$Collection = '') {
    $items = New-Object Collections.Generic.List[object]
    $query = @{} + $Filters
    $query.limit = '200'
    $seen = @{}
    $complete = $true
    for ($i = 0; $i -lt 100; $i++) {
        $args = @($query.Keys | Sort-Object | ForEach-Object { [uri]::EscapeDataString($_) + '=' + [uri]::EscapeDataString([string]$query[$_]) }) -join '&'
        try {
            $page = Invoke-RestMethod -Method Get -Uri ($ServerUrl.TrimEnd('/') + '/api/v2/reports/' + $Resource + '?' + $args) `
                -Headers $script:LabHeaders -TimeoutSec 30
            $state = Get-LabField $page 'state'
            if ($state -notin @('ok', 'empty', 'partial')) { throw 'lab_report_unavailable' }
            if ($state -eq 'partial') { $complete = $false }
            $rows = Get-LabField $page 'items'
            if ($Collection) {
                $collections = Get-LabField $page 'collections'
                if ($collections -is [Collections.IDictionary]) { $rows = $collections[$Collection] }
                else {
                    $property = if ($null -ne $collections) { $collections.PSObject.Properties[$Collection] }
                    $rows = $null
                    if ($null -ne $property) { $rows = $property.Value }
                }
                # Preserve empty arrays; absent or malformed history is unavailable.
                if ($rows -isnot [array]) { throw 'lab_report_collection_unavailable' }
            }
            foreach ($row in @($rows)) { if ($null -ne $row) { $items.Add($row) } }
            if (-not (Get-LabField $page 'has_more')) { return [pscustomobject]@{ Items = $items.ToArray(); Complete = $complete } }
            $cursor = [string](Get-LabField $page 'next_cursor')
            if (-not $cursor -or $seen.ContainsKey($cursor)) { throw 'lab_report_cursor_invalid' }
            $seen[$cursor] = $true
            $query.cursor = $cursor
        } catch {
            Write-LabAuthenticationFailure $_
            return [pscustomobject]@{ Items = $items.ToArray(); Complete = $false }
        }
    }
    return [pscustomobject]@{ Items = $items.ToArray(); Complete = $false }
}

function Find-LabEvent($Expected, [object[]]$Rows, [hashtable]$Used) {
    $start = [datetimeoffset]::Parse($Expected.started_at_utc).AddSeconds(-$EventToleranceSeconds)
    $end = [datetimeoffset]::Parse($Expected.ended_at_utc).AddSeconds($EventToleranceSeconds)
    $failureScenario = $Expected.scenario -in @('wrong_password', 'password_spray', 'single_account_brute', 'disabled_logon')
    $eventIds = @($Expected.event_ids)
    # Keep old JSONL manifests usable when the DC emits only NTLM validation.
    if ($failureScenario -and $eventIds -contains 4625) { $eventIds += 4776 }
    foreach ($row in $Rows) {
        $id = [string](Get-LabField $row 'event_db_id')
        if (-not $id) { $id = [string](Get-LabField $row 'id') }
        if (-not $id -or $Used.ContainsKey($id) -or $eventIds -notcontains (Get-LabField $row 'event_id')) { continue }
        $raw = Get-LabField $row 'time_created_utc'
        if (-not $raw) { continue }
        $stamp = [datetimeoffset]::Parse($raw)
        if ($stamp -lt $start -or $stamp -gt $end) { continue }
        if (-not (Get-LabField $row 'event_db_id')) {
            $row = Read-LabExactEvent $id
            if ($null -eq $row) { $script:LabEvidenceUnavailable = $true; continue }
        }
        $eventId = Get-LabField $row 'event_id'
        if ($eventIds -notcontains $eventId) { continue }
        if ($eventId -eq 4776) {
            if (-not $failureScenario) { continue }
            $code = [string](Get-LabField $row 'result_code')
            if (-not $code) { $code = [string](Get-LabField $row 'outcome.result_code') }
            $code = $code.Trim()
            if ($code -notmatch '^(?:0x)?[0-9a-f]{1,8}$') { $script:LabEvidenceUnavailable = $true; continue }
            if ([Convert]::ToUInt32(($code -replace '^0x', ''), 16) -eq 0) { continue }
        }
        $hostName = Get-LabField $row 'source_host.hostname'
        if (-not $hostName) { $script:LabEvidenceUnavailable = $true; continue }
        if ($hostName -ine $SourceHost) { continue }
        # 4776 has no IP field: compare DC, account, time and native failure code.
        if ($Expected.source_address -and $eventId -ne 4776) {
            $address = [string](Get-LabField $row 'source_address')
            if (-not $address -or $address -eq '-') { $script:LabEvidenceUnavailable = $true; continue }
            if ($address -ine $Expected.source_address -and $address -ine ('::ffff:' + $Expected.source_address)) { continue }
        }
        if ($Expected.target_sid) {
            $sid = Get-LabField $row 'member.sid'
            if (-not $sid) { $script:LabEvidenceUnavailable = $true; continue }
            if ($sid -cne $Expected.target_sid) { continue }
        } elseif ($Expected.target.StartsWith('lab.')) {
            $name = [string](Get-LabField $row 'affected_account.name')
            if (-not $name) { $script:LabEvidenceUnavailable = $true; continue }
            $name = ($name -split '\\')[-1] -replace '@demo\.example$', ''
            if ($name -ine $Expected.target) { continue }
        } elseif ($Expected.scenario -eq 'gpo_change') {
            $object = [string](Get-LabField $row 'object_id')
            if (-not $object) { $script:LabEvidenceUnavailable = $true; continue }
            if ($object.Trim('{}') -ine $Expected.event_object_id) { continue }
        } elseif ($Expected.scenario -eq 'audit_change') {
            $subcategory = [string](Get-LabField $row 'audit_subcategory_guid')
            if (-not $subcategory) { $script:LabEvidenceUnavailable = $true; continue }
            if ($subcategory.Trim('{}') -ine '0cce9215-69ae-11d9-bed3-505054503030') { continue }
        }
        $Used[$id] = $true
        return $row
    }
    return $null
}

function Find-LabChange($Expected, [object[]]$Rows) {
    $start = [datetimeoffset]::Parse($Expected.started_at_utc)
    $end = [datetimeoffset]::Parse($Expected.ended_at_utc).AddSeconds($SnapshotLagSeconds)
    $kind = if ($Expected.scenario -eq 'privileged_add') { 'membership_added' } else { 'attribute_changed' }
    foreach ($row in $Rows) {
        $object = [string](Get-LabField $row 'object_id')
        $raw = Get-LabField $row 'observed_at'
        if (-not $raw -or -not $object -or $object.Trim('{}') -ine $Expected.object_id -or (Get-LabField $row 'kind') -cne $kind) { continue }
        if ($Expected.related_object_id -and ([string](Get-LabField $row 'related_object_id')).Trim('{}') -ine $Expected.related_object_id) { continue }
        $stamp = [datetimeoffset]::Parse($raw)
        if ($stamp -ge $start -and $stamp -le $end) { return $row }
    }
    return $null
}

function Get-LabMatchState($Match, [bool]$Complete) {
    if ($null -ne $Match) { return 'FOUND' }
    if ($Complete) { return 'MISSING' }
    return 'UNAVAILABLE'
}

function Read-LabExactEvent([string]$Id) {
    if ($script:LabExactCache.ContainsKey($Id)) { return $script:LabExactCache[$Id] }
    try {
        if ($Id -cnotmatch '^\d+$') { throw 'lab_event_id_invalid' }
        $response = Invoke-RestMethod -Method Get -Uri ($ServerUrl.TrimEnd('/') + '/api/v1/events/' + $Id) -Headers $script:LabHeaders -TimeoutSec 30
        $item = Get-LabField $response 'item'
        $address = Get-LabField $item 'ip_address'
        if (-not $address) { $address = Get-LabField $item 'event_data.IpAddress' }
        $result = [pscustomobject]@{
            event_db_id = Get-LabField $item 'event_db_id'; event_id = Get-LabField $item 'event_id'
            time_created_utc = Get-LabField $item 'time_created_utc'
            source_host = @{ hostname = (Get-LabField $item 'server') }
            affected_account = @{ name = (Get-LabField $item 'target_user_name') }
            member = @{ sid = (Get-LabField $item 'event_data.MemberSid') }
            source_address = $address; object_id = Get-LabField $item 'event_data.ObjectGUID'
            result_code = Get-LabField $item 'event_data.Status'
            audit_subcategory_guid = Get-LabField $item 'event_data.SubcategoryGuid'
        }
        if ([string]$result.event_db_id -cne $Id) { throw 'lab_event_identity_mismatch' }
    } catch {
        Write-LabAuthenticationFailure $_
        $result = $null
    }
    $script:LabExactCache[$Id] = $result
    return $result
}

function Invoke-LabVerify {
    $uri = [uri]$ServerUrl
    if (-not $uri.IsAbsoluteUri -or $uri.Scheme -cne 'https' -or $uri.UserInfo -or $uri.AbsolutePath -ne '/' -or $uri.Query -or $uri.Fragment) { throw 'lab_https_origin_required' }
    $script:LabHeaders = @{ Authorization = 'Bearer ' + [IO.File]::ReadAllText((Assert-LabPath $ApiKeyFile)).Trim() }
    $script:LabExactCache = @{}
    $stage = $null
    try {
        if (-not $ExpectedDirectory) {
            Assert-LabAdministrator
            $parent = Join-Path $env:ProgramData 'SLI-Lab-Verify'
            Initialize-LabDirectory $parent
            $stage = Join-Path $parent ([guid]::NewGuid().ToString())
            Initialize-LabDirectory $stage
            Copy-LabFile $Target (Assert-LabPath $IdentityFile) $stage 'C:/SLI-Lab/expected/*.jsonl' -Download
            $ExpectedDirectory = $stage
        }
        $expected = @(
            Get-ChildItem -LiteralPath (Assert-LabPath $ExpectedDirectory) -Filter '*.jsonl' -File | Sort-Object Name | ForEach-Object {
                foreach ($line in Get-Content -LiteralPath (Assert-LabPath $_.FullName) -Encoding UTF8) {
                    if ($line.Trim()) { $row = $line | ConvertFrom-Json; Assert-LabExpected $row; $row }
                }
            }
        )
        if (-not $expected.Count) { throw 'lab_expected_empty' }
        $start = ($expected | ForEach-Object { [datetimeoffset]::Parse($_.started_at_utc) } | Sort-Object | Select-Object -First 1).AddSeconds(-$EventToleranceSeconds)
        $last = $expected | ForEach-Object { [datetimeoffset]::Parse($_.ended_at_utc) } | Sort-Object | Select-Object -Last 1
        $end = $last.AddSeconds($SnapshotLagSeconds)
        $filters = @{ domain = [string]$DomainId; period = 'custom'; from = $start.ToString('o'); to = $end.ToString('o') }
        # Snapshot lag must not fill journal pages with unrelated later events.
        $eventFilters = @{ period = 'custom'; from = $start.ToString('o'); to = $last.AddSeconds($EventToleranceSeconds).ToString('o'); server = $SourceHost }
        $events = Read-LabReport 'events.journal/data' $eventFilters
        $ad = Read-LabReport 'ad.infrastructure/data' ($filters + @{ tab = 'changes' }) -Collection 'changes'
        # GPO declaration has no domain parameter. GUID matching prevents cross-domain matches.
        $gpoFilters = @{ period = 'custom'; from = $start.ToString('o'); to = $end.ToString('o'); tab = 'changes' }
        $gpo = Read-LabReport 'ad.gpo.v2/data' $gpoFilters -Collection 'changes'
        $problemFilters = @{ domain = [string]$DomainId; time_from = $start.ToString('o'); time_to = $end.ToString('o') }
        $problems = Read-LabReport 'security.problems/data' $problemFilters
        $problemEvidence = New-Object Collections.Generic.List[object]
        $problemsComplete = $problems.Complete
        foreach ($problem in $problems.Items) {
            $id = [string](Get-LabField $problem 'id')
            if ($id -cnotmatch '^\d+$') { $problemsComplete = $false; continue }
            $detail = Read-LabReport ("security.problems/rows/$id/detail") $problemFilters
            if (-not $detail.Complete) { $problemsComplete = $false }
            foreach ($row in $detail.Items) { $problemEvidence.Add($row) }
        }
        $used = @{}
        $table = @(
            foreach ($row in $expected | Sort-Object started_at_utc) {
                if (Test-LabFileExpected $row) {
                    # Never feed file events into the AD matcher or claim unperformed checks passed.
                    Write-Warning 'lab_file_verification_unavailable'
                    [pscustomobject]@{ Expected = $row.scenario; Target = $row.target
                        Event = $(if ($row.executed) { 'UNAVAILABLE' } else { 'SCENARIO_FAILED' })
                        'AD/GPO' = '-'; Problem = '-'; File = 'UNAVAILABLE' }
                    continue
                }
                $event = $null
                $eventState = 'SCENARIO_FAILED'
                $changeState = '-'
                $problemState = '-'
                if ($row.executed) {
                    $script:LabEvidenceUnavailable = $false
                    $event = Find-LabEvent $row $events.Items $used
                    $eventState = Get-LabMatchState $event ($events.Complete -and -not $script:LabEvidenceUnavailable)
                    if ($row.scenario -in @('privileged_add', 'gpo_change')) {
                        $report = if ($row.scenario -eq 'gpo_change') { $gpo } else { $ad }
                        $changeState = Get-LabMatchState (Find-LabChange $row $report.Items) $report.Complete
                    }
                    if ($row.scenario -in @('password_spray', 'single_account_brute', 'audit_change', 'disabled_logon')) {
                        $evidence = $null
                        if ($null -ne $event) { $evidence = $problemEvidence.ToArray() | Where-Object { (Get-LabField $_ 'event_db_id') -eq $event.event_db_id } | Select-Object -First 1 }
                        $problemState = Get-LabMatchState $evidence $problemsComplete
                    }
                }
                [pscustomobject]@{ Expected = $row.scenario; Target = $row.target; Event = $eventState; 'AD/GPO' = $changeState; Problem = $problemState; File = '-' }
            }
        )
        $table | Format-Table -AutoSize | Out-Host
        if (@($table | Where-Object { $_.Event -ne 'FOUND' -or $_.'AD/GPO' -notin @('FOUND', '-') -or $_.Problem -notin @('FOUND', '-') -or $_.File -notin @('FOUND', '-') }).Count) { return 2 }
        return 0
    } finally {
        $script:LabHeaders.Clear()
        $script:LabExactCache.Clear()
        if ($stage) {
            Get-ChildItem -LiteralPath (Assert-LabPath $stage) -File | ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force }
            Remove-Item -LiteralPath $stage -Force
        }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    try { exit (Invoke-LabVerify) } catch { Write-Output 'lab_verify_failed'; exit 1 }
}

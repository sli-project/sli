#Requires -Version 5.1
# Hermetic verifier query-window contract; no network, AD or database.
$ErrorActionPreference = 'Stop'
$lab = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../tools/lab'))
$stage = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $stage
try {
    $key = Join-Path $stage 'synthetic.key'
    [IO.File]::WriteAllText($key, 'synthetic-unused')
    $rows = @(foreach ($minute in @(0, 2)) {
        [ordered]@{ schema_version = 1; run_id = '00000000-0000-4000-8000-000000000001';
            scenario = 'workday_logon'; actor = 'lab-system'; target = 'lab.u001';
            started_at_utc = ('2026-10-09T10:0' + $minute + ':00Z');
            ended_at_utc = ('2026-10-09T10:0' + $minute + ':04Z');
            source_address = '127.0.0.1'; event_ids = @(4624); executed = $true;
            object_id = $null; target_sid = $null; related_object_id = $null; event_object_id = $null }
    })
    $rows | ForEach-Object { $_ | ConvertTo-Json -Compress } |
        Set-Content (Join-Path $stage 'expected.jsonl') -Encoding UTF8
    . "$lab/lab-verify.ps1" -DomainId 1 -ApiKeyFile $key -IdentityFile $key -ExpectedDirectory $stage -SnapshotLagSeconds 3600
    # Emulate PS5.1 JSON integers and date strings while exercising the real verifier.
    function ConvertFrom-Json {
        param([Parameter(ValueFromPipeline)][string]$InputObject)
        process {
            $options = @{}
            if ((Get-Command Microsoft.PowerShell.Utility\ConvertFrom-Json).Parameters.ContainsKey('DateKind')) {
                $options.DateKind = 'String'
            }
            $row = Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $InputObject @options
            $row.schema_version = [int]$row.schema_version
            $row.event_ids = @($row.event_ids | ForEach-Object { [int]$_ })
            return $row
        }
    }
    $script:Requests = @{}
    function Invoke-RestMethod {
        param($Method, $Uri, $Headers, $TimeoutSec)
        if ($Method -ne 'Get') { throw 'unexpected_mutation' }
        $query = @{}
        foreach ($pair in ([uri]$Uri).Query.TrimStart('?').Split('&')) {
            $parts = $pair.Split('=', 2)
            $query[$parts[0]] = [uri]::UnescapeDataString($parts[1])
        }
        $resource = ([uri]$Uri).AbsolutePath
        $script:Requests[$resource] = $query
        $items = @()
        if ($resource -eq '/api/v2/reports/events.journal/data') {
            # The API is newest-first. A snapshot-sized window fills every page
            # with unrelated later events and never reaches the scenario cohort.
            if ([datetimeoffset]$query.to -gt [datetimeoffset]'2026-10-09T10:02:06Z') {
                return @{ state = 'ok'; items = @(); has_more = $true; next_cursor = [guid]::NewGuid().ToString() }
            }
            $items = @(foreach ($minute in @(0, 2)) {
                @{ event_db_id = (1 + $minute); event_id = 4624;
                    time_created_utc = ('2026-10-09T10:0' + $minute + ':06Z');
                    source_host = @{ hostname = $SourceHost }; affected_account = @{ name = 'lab.u001' };
                    source_address = '127.0.0.1' }
            })
        }
        return @{ state = 'ok'; items = $items; has_more = $false }
    }
    $result = Invoke-LabVerify
    if ($result -ne 0) { throw 'scenario_cohort_hidden_by_snapshot_window' }
    $events = $script:Requests['/api/v2/reports/events.journal/data']
    if ([datetimeoffset]$events.from -ne [datetimeoffset]'2026-10-09T09:59:58Z' -or
        [datetimeoffset]$events.to -ne [datetimeoffset]'2026-10-09T10:02:06Z') { throw 'event_tolerance_window_incorrect' }
    foreach ($resource in @('ad.infrastructure', 'ad.gpo.v2')) {
        if ([datetimeoffset]$script:Requests[('/api/v2/reports/' + $resource + '/data')].to -ne
            [datetimeoffset]'2026-10-09T11:02:04Z') { throw 'snapshot_lag_window_lost' }
    }
    if ([datetimeoffset]$script:Requests['/api/v2/reports/security.problems/data'].time_to -ne
        [datetimeoffset]'2026-10-09T11:02:04Z') { throw 'problem_window_changed' }
    Write-Output 'lab_verify_window_contract_passed'
} finally {
    Get-ChildItem -LiteralPath $stage -File | ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force }
    Remove-Item -LiteralPath $stage -Force
}

#Requires -Version 5.1
# Hermetic named report collection contract; no network, AD or database.
$ErrorActionPreference = 'Stop'
$lab = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../tools/lab'))
. "$lab/lab-verify.ps1" -DomainId 1 -ApiKeyFile 'synthetic-unused' -IdentityFile 'synthetic-unused'
$script:LabHeaders = @{}
$script:Pages = @()
$script:Requests = New-Object Collections.Generic.List[string]
function Invoke-RestMethod {
    param($Method, $Uri, $Headers, $TimeoutSec)
    if ($Method -ne 'Get') { throw 'unexpected_mutation' }
    $script:Requests.Add($Uri)
    $index = $script:Requests.Count - 1
    return $script:Pages[$index]
}
foreach ($resource in @('ad.infrastructure/data', 'ad.gpo.v2/data')) {
    $script:Requests.Clear()
    $script:Pages = @(
        @{ state = 'partial'; items = @(@{ id = 'wrong-primary-row' });
            collections = @{ changes = @(@{ id = 'change-one' }) }; has_more = $true; next_cursor = 'page-two' },
        [pscustomobject]@{ state = 'ok'; items = @();
            collections = [pscustomobject]@{ changes = @([pscustomobject]@{ id = 'change-two' }) }; has_more = $false }
    )
    $result = Read-LabReport $resource @{ tab = 'changes' } -Collection 'changes'
    if ($result.Complete -or $result.Items.Count -ne 2 -or
        $result.Items[0].id -ne 'change-one' -or $result.Items[1].id -ne 'change-two') { throw 'history_collection_not_read' }
    if ($script:Requests.Count -ne 2 -or $script:Requests[1] -notmatch 'cursor=page-two') { throw 'history_pagination_lost' }
    foreach ($empty in @(@{ changes = @() }, [pscustomobject]@{ changes = @() })) {
        $script:Requests.Clear()
        $script:Pages = @(@{ state = 'ok'; items = @(); collections = $empty; has_more = $false })
        $result = Read-LabReport $resource @{} -Collection 'changes'
        if (-not $result.Complete -or $result.Items.Count) { throw 'empty_history_not_complete' }
    }
    foreach ($invalid in @(@{}, @{ changes = $null }, @{ changes = 'invalid' }, [pscustomobject]@{})) {
        $script:Requests.Clear()
        $script:Pages = @(@{ state = 'ok'; items = @(@{ id = 'wrong-primary-row' }); collections = $invalid; has_more = $false })
        $result = Read-LabReport $resource @{} -Collection 'changes'
        if ($result.Complete -or $result.Items.Count) { throw 'missing_history_claimed_complete' }
    }
}
$script:Requests.Clear()
$script:Pages = @(@{ state = 'ok'; items = @(@{ id = 'journal-row' }); has_more = $false })
$result = Read-LabReport 'events.journal/data' @{}
if (-not $result.Complete -or $result.Items.Count -ne 1 -or $result.Items[0].id -ne 'journal-row') { throw 'primary_items_changed' }

$stage = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $stage
try {
    $key = Join-Path $stage 'synthetic.key'
    [IO.File]::WriteAllText($key, 'synthetic-unused')
    $objectId = '00000000-0000-4000-8000-000000000002'
    $relatedId = '00000000-0000-4000-8000-000000000003'
    $eventObjectId = '00000000-0000-4000-8000-000000000004'
    $sid = 'S-1-5-21-100000001-200000002-300000003-1001'
    $expected = @(foreach ($scenario in @('privileged_add', 'gpo_change')) {
        [ordered]@{ schema_version = 1; run_id = '00000000-0000-4000-8000-000000000001';
            scenario = $scenario; actor = 'lab-system';
            target = $(if ($scenario -eq 'privileged_add') { 'lab.u001' } else { 'LAB-Lock' });
            started_at_utc = '2026-10-09T10:00:00Z'; ended_at_utc = '2026-10-09T10:00:01Z';
            source_address = $null; event_ids = @($(if ($scenario -eq 'privileged_add') { 4728 } else { 5136 }));
            executed = $true; object_id = $objectId;
            target_sid = $(if ($scenario -eq 'privileged_add') { $sid } else { $null });
            related_object_id = $(if ($scenario -eq 'privileged_add') { $relatedId } else { $null });
            event_object_id = $(if ($scenario -eq 'gpo_change') { $eventObjectId } else { $null }) }
    })
    $expected | ForEach-Object { $_ | ConvertTo-Json -Compress } |
        Set-Content (Join-Path $stage 'expected.jsonl') -Encoding UTF8
    . "$lab/lab-verify.ps1" -DomainId 1 -ApiKeyFile $key -IdentityFile $key -ExpectedDirectory $stage
    function ConvertFrom-Json {
        param([Parameter(ValueFromPipeline)][string]$InputObject)
        process {
            # Preserve PS5.1 date strings on newer PowerShell versions.
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
    function Invoke-RestMethod {
        param($Method, $Uri, $Headers, $TimeoutSec)
        if ($Method -ne 'Get') { throw 'unexpected_mutation' }
        $resource = ([uri]$Uri).AbsolutePath
        if ($resource -eq '/api/v2/reports/events.journal/data') {
            return @{ state = 'ok'; has_more = $false; items = @(
                @{ event_db_id = 1; event_id = 4728; time_created_utc = '2026-10-09T10:00:00Z';
                    source_host = @{ hostname = $SourceHost }; member = @{ sid = $sid } },
                @{ event_db_id = 2; event_id = 5136; time_created_utc = '2026-10-09T10:00:00Z';
                    source_host = @{ hostname = $SourceHost }; object_id = $eventObjectId }
            ) }
        }
        $changes = @()
        if ($resource -eq '/api/v2/reports/ad.infrastructure/data') {
            $changes = @(@{ object_id = $objectId; related_object_id = $relatedId;
                kind = 'membership_added'; observed_at = '2026-10-09T11:00:00Z' })
        } elseif ($resource -eq '/api/v2/reports/ad.gpo.v2/data') {
            $changes = @(@{ object_id = $objectId; kind = 'attribute_changed'; observed_at = '2026-10-09T11:00:00Z' })
        }
        return @{ state = 'partial'; items = @(); collections = @{ changes = $changes }; has_more = $false }
    }
    if ((Invoke-LabVerify) -ne 0) { throw 'verifier_history_collection_not_wired' }
} finally {
    Get-ChildItem -LiteralPath $stage -File | ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force }
    Remove-Item -LiteralPath $stage -Force
}
Write-Output 'lab_verify_collections_contract_passed'

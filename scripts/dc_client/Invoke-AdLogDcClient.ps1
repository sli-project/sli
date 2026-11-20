#requires -version 5.1
[CmdletBinding()]
param(
    [string]$ServerName = $env:COMPUTERNAME,
    [string[]]$Channels = @("Security"),
    [int]$MaxEventsPerChannel = 500,
    [int]$ChannelTimeoutSeconds = 300,
    [string]$AfterRecordIdsJson = "",
    [string]$OutputRoot = "C:\ProgramData\AdLogReports\spool",
    [string]$CentralDropPath = "",
    [switch]$CollectMessage
)

# The same cutover setting as the Python legacy admission gate.
if ($null -ne $env:SLI_LEGACY_COLLECTION_DISABLED -and $env:SLI_LEGACY_COLLECTION_DISABLED.Trim() -ne "0") {
    throw "legacy collection disabled by SLI_LEGACY_COLLECTION_DISABLED; use agent modules and core job handlers"
}

$ErrorActionPreference = "Stop"

function Safe-Name {
    param([string]$Value)
    return ($Value -replace '[\\/:*?"<>| ]+', '_')
}

function Count-JsonlLines {
    param([string]$Path)
    if (-not (Test-Path -Path $Path)) { return 0 }
    $count = 0
    Get-Content -Path $Path -Encoding UTF8 -ErrorAction SilentlyContinue | ForEach-Object {
        if (-not [string]::IsNullOrWhiteSpace($_)) { $count++ }
    }
    return $count
}

$afterRecordIds = $null
if (-not [string]::IsNullOrWhiteSpace($AfterRecordIdsJson)) {
    $afterRecordIds = $AfterRecordIdsJson | ConvertFrom-Json
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outDir = Join-Path -Path $OutputRoot -ChildPath "$(Safe-Name $ServerName)-$timestamp"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$summaryPath = Join-Path -Path $outDir -ChildPath "collection-summary.json"

$summary = [ordered]@{
    computer_name = $ServerName
    connect_address = "local"
    started_at = (Get-Date).ToUniversalTime().ToString("o")
    collection_mode = "dc_client_local_spool"
    requested_collection_mode = "dc_client"
    collector_backend = "dc_client_powershell_no_python"
    collect_message = [bool]$CollectMessage
    max_events_per_channel = $MaxEventsPerChannel
    channel_timeout_seconds = $ChannelTimeoutSeconds
    channels = @()
}

function Save-Summary {
    $summary | ConvertTo-Json -Depth 8 | Set-Content -Path $summaryPath -Encoding UTF8
}

Save-Summary
Write-Host "Collection output: $outDir"
Write-Host "Summary: $summaryPath"

foreach ($channel in $Channels) {
    $safeChannel = Safe-Name $channel
    $outFile = Join-Path -Path $outDir -ChildPath "$safeChannel.jsonl"
    $afterRecordId = $null
    if ($null -ne $afterRecordIds) {
        $property = $afterRecordIds.PSObject.Properties[$channel]
        if ($null -ne $property -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)) {
            $afterRecordId = [int64]$property.Value
        }
    }
    $info = [ordered]@{
        channel = $channel
        after_record_id = $afterRecordId
        max_events = $MaxEventsPerChannel
        timeout_seconds = $ChannelTimeoutSeconds
        file = $outFile
        status = "started"
        count = 0
        error = $null
        started_at = (Get-Date).ToUniversalTime().ToString("o")
        finished_at = $null
        duration_seconds = $null
        cursor_strategy = if ($null -ne $afterRecordId) { "record_id" } else { "oldest_batch" }
        collector_backend = "dc_client_powershell_no_python"
    }
    $summary.channels += $info
    Save-Summary
    Write-Host "Starting channel: $channel"
    $started = Get-Date

    $job = Start-Job -ArgumentList $channel,$outFile,$afterRecordId,$MaxEventsPerChannel,[bool]$CollectMessage -ScriptBlock {
        param([string]$Channel,[string]$OutFile,[object]$AfterRecordId,[int]$MaxEvents,[bool]$CollectMessage)
        $ErrorActionPreference = "Stop"
        $args = @{ LogName = $Channel; ErrorAction = "Stop"; Oldest = $true }
        if ($null -ne $AfterRecordId) {
            $args.FilterXPath = "*[System[EventRecordID > $AfterRecordId]]"
        }
        if ($MaxEvents -gt 0) { $args.MaxEvents = $MaxEvents }
        $count = 0
        Get-WinEvent @args | ForEach-Object {
            $event = $_
            $properties = @()
            foreach ($property in $event.Properties) { $properties += $property.Value }
            $row = [ordered]@{
                computer_name = $env:COMPUTERNAME
                connect_address = "local"
                channel = $Channel
                provider_name = $event.ProviderName
                event_id = $event.Id
                version = $event.Version
                level = $event.Level
                task = $event.Task
                opcode = $event.Opcode
                keywords = [string]$event.Keywords
                record_id = $event.RecordId
                time_created = if ($event.TimeCreated) { $event.TimeCreated.ToUniversalTime().ToString("o") } else { $null }
                machine_name = $event.MachineName
                user_id = if ($event.UserId) { $event.UserId.Value } else { $null }
                message = if ($CollectMessage) { $event.Message } else { $null }
                properties = $properties
                xml = $event.ToXml()
            }
            $row | ConvertTo-Json -Depth 8 -Compress | Add-Content -Path $OutFile -Encoding UTF8
            $count++
            if (($count % 500) -eq 0) { Write-Host "Progress channel: $Channel count=$count record_id=$($event.RecordId)" }
        }
        return [pscustomobject]@{ status="completed"; count=$count; error=$null }
    }

    $completed = Wait-Job -Job $job -Timeout $ChannelTimeoutSeconds
    if ($null -eq $completed) {
        Stop-Job -Job $job -ErrorAction SilentlyContinue
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path -Path $outFile)) { "" | Set-Content -Path $outFile -Encoding UTF8 }
        $partial = Count-JsonlLines -Path $outFile
        $info.status = if ($partial -gt 0) { "partial_timeout" } else { "timeout" }
        $info.count = $partial
        $info.error = "Channel timed out after $ChannelTimeoutSeconds seconds."
        Write-Host "Timed out channel: $channel after ${ChannelTimeoutSeconds}s partial_count=$partial"
    }
    else {
        $result = Receive-Job -Job $job -ErrorAction SilentlyContinue | Select-Object -Last 1
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        if ($null -eq $result) {
            $info.status = "failed"
            $info.error = "Channel job finished without result."
        }
        else {
            $info.status = [string]$result.status
            $info.count = [int]$result.count
            $info.error = $result.error
        }
        Write-Host "Completed channel: $channel count=$($info.count)"
    }
    $info.finished_at = (Get-Date).ToUniversalTime().ToString("o")
    $info.duration_seconds = [math]::Round(((Get-Date) - $started).TotalSeconds, 3)
    for ($i = 0; $i -lt $summary.channels.Count; $i++) {
        if ($summary.channels[$i].channel -eq $channel) { $summary.channels[$i] = $info; break }
    }
    Save-Summary
}

$summary.finished_at = (Get-Date).ToUniversalTime().ToString("o")
Save-Summary

if (-not [string]::IsNullOrWhiteSpace($CentralDropPath)) {
    New-Item -ItemType Directory -Force -Path $CentralDropPath | Out-Null
    $target = Join-Path -Path $CentralDropPath -ChildPath (Split-Path -Path $outDir -Leaf)
    Copy-Item -Path $outDir -Destination $target -Recurse -Force
    Write-Host "Copied spool to: $target"
}

#requires -version 5.1
[CmdletBinding()]
param(
    [string]$ComputerName = $env:LOGONSERVER.TrimStart("\"),
    [string]$SourceName = "",
    [int]$Hours = 1,
    [int]$MaxEventsPerChannel = 200,
    [string]$ChannelMaxEventsJson = "",
    [string]$ChannelTimeoutSecondsJson = "",
    [string]$StartTimeUtc = "",
    [string]$ChannelStartTimesJson = "",
    [string]$ChannelAfterRecordIdsJson = "",
    [int]$ChannelTimeoutSeconds = 120,
    [string[]]$Channels = @(
        "Security",
        "System",
        "Directory Service",
        "Microsoft-Windows-PowerShell/Operational",
        "Microsoft-Windows-TaskScheduler/Operational",
        "DNS Server"
    ),
    [string]$OutputRoot = "data\raw\pilot",
    # PowerShell -File receives command-line arguments from external callers as strings.
    # Keep this parameter object-typed and normalize it below so Python/subprocess
    # launches can pass values like False, $false, 0, or true without binder errors.
    [object]$CollectMessage = $false,
    [ValidateSet("auto", "current", "backfill", "recovery")]
    [string]$RequestedCollectionMode = "auto"
)

$ErrorActionPreference = "Stop"

# The same cutover setting as the Python legacy admission gate.
if ($null -ne $env:SLI_LEGACY_COLLECTION_DISABLED -and $env:SLI_LEGACY_COLLECTION_DISABLED.Trim() -ne "0") {
    throw "legacy collection disabled by SLI_LEGACY_COLLECTION_DISABLED; use agent modules and core job handlers"
}

function ConvertTo-BooleanFlag {
    param([object]$Value)

    if ($null -eq $Value) {
        return $false
    }
    if ($Value -is [bool]) {
        return [bool]$Value
    }
    if ($Value -is [int] -or $Value -is [long]) {
        return ([int64]$Value) -ne 0
    }

    $text = ([string]$Value).Trim()
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $false
    }
    $normalized = $text.TrimStart('$').ToLowerInvariant()
    switch ($normalized) {
        "true" { return $true }
        "false" { return $false }
        "1" { return $true }
        "0" { return $false }
        "yes" { return $true }
        "no" { return $false }
        default {
            throw "Invalid boolean value for CollectMessage: $Value. Use true/false/1/0."
        }
    }
}

function ConvertTo-ChannelList {
    param([string[]]$Value)

    $result = @()
    foreach ($item in @($Value)) {
        foreach ($channel in ([string]$item -split ",")) {
            $normalized = $channel.Trim()
            if (-not [string]::IsNullOrWhiteSpace($normalized)) {
                $result += $normalized
            }
        }
    }
    return [string[]]$result
}

$CollectMessage = ConvertTo-BooleanFlag -Value $CollectMessage
$Channels = ConvertTo-ChannelList -Value $Channels

if ([string]::IsNullOrWhiteSpace($ComputerName)) {
    throw "ComputerName is empty. Pass -ComputerName DC_NAME."
}
if ([string]::IsNullOrWhiteSpace($SourceName)) {
    $SourceName = $ComputerName
}

if (-not [string]::IsNullOrWhiteSpace($StartTimeUtc)) {
    $startTime = ([datetime]::Parse($StartTimeUtc)).ToUniversalTime()
    $collectionMode = "since_start_time_utc"
}
else {
    $startTime = (Get-Date).AddHours(-1 * $Hours)
    $collectionMode = "last_hours"
}

$channelStartTimes = $null
if (-not [string]::IsNullOrWhiteSpace($ChannelStartTimesJson)) {
    $channelStartTimes = $ChannelStartTimesJson | ConvertFrom-Json
    $collectionMode = "per_channel_start_time_utc"
}

$channelAfterRecordIds = $null
if (-not [string]::IsNullOrWhiteSpace($ChannelAfterRecordIdsJson)) {
    $channelAfterRecordIds = $ChannelAfterRecordIdsJson | ConvertFrom-Json
    $collectionMode = "per_channel_record_id"
}

$channelMaxEvents = $null
if (-not [string]::IsNullOrWhiteSpace($ChannelMaxEventsJson)) {
    $channelMaxEvents = $ChannelMaxEventsJson | ConvertFrom-Json
}

$channelTimeoutSecondsMap = $null
if (-not [string]::IsNullOrWhiteSpace($ChannelTimeoutSecondsJson)) {
    $channelTimeoutSecondsMap = $ChannelTimeoutSecondsJson | ConvertFrom-Json
}

function Get-ChannelStartTime {
    param(
        [string]$Channel,
        [datetime]$DefaultStartTime
    )
    if ($null -ne $channelStartTimes) {
        $property = $channelStartTimes.PSObject.Properties[$Channel]
        if ($null -ne $property -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)) {
            return ([datetime]::Parse([string]$property.Value)).ToUniversalTime()
        }
    }
    return $DefaultStartTime
}

function Get-ChannelAfterRecordId {
    param([string]$Channel)
    if ($null -ne $channelAfterRecordIds) {
        $property = $channelAfterRecordIds.PSObject.Properties[$Channel]
        if ($null -ne $property -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)) {
            return [int64]$property.Value
        }
    }
    return $null
}

function Get-ChannelMaxEvents {
    param(
        [string]$Channel,
        [int]$DefaultMaxEvents
    )
    if ($null -ne $channelMaxEvents) {
        $property = $channelMaxEvents.PSObject.Properties[$Channel]
        if ($null -ne $property -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)) {
            return [int]$property.Value
        }
    }
    return $DefaultMaxEvents
}

function Get-ChannelTimeoutSeconds {
    param(
        [string]$Channel,
        [int]$DefaultTimeoutSeconds
    )
    if ($null -ne $channelTimeoutSecondsMap) {
        $property = $channelTimeoutSecondsMap.PSObject.Properties[$Channel]
        if ($null -ne $property -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)) {
            return [int]$property.Value
        }
    }
    return $DefaultTimeoutSeconds
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$safeComputer = $SourceName -replace '[\\/:*?"<>| ]+', '_'
$outDir = Join-Path -Path $OutputRoot -ChildPath "$safeComputer-$timestamp"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$summary = [ordered]@{
    computer_name = $SourceName
    connect_address = $ComputerName
    started_at = (Get-Date).ToUniversalTime().ToString("o")
    start_time_local = $startTime.ToString("o")
    start_time_utc = $startTime.ToUniversalTime().ToString("o")
    collection_mode = $collectionMode
    requested_collection_mode = $RequestedCollectionMode
    collector_backend = "powershell"
    backend_reason = "powershell_collector"
    collect_message = $CollectMessage
    hours = $Hours
    max_events_per_channel = $MaxEventsPerChannel
    channel_timeout_seconds = $ChannelTimeoutSeconds
    channels = @()
}

$summaryPath = Join-Path -Path $outDir -ChildPath "collection-summary.json"
$internalLogPath = Join-Path -Path $outDir -ChildPath "collector-internal.log"

function Save-Summary {
    $summary | ConvertTo-Json -Depth 8 | Set-Content -Path $summaryPath -Encoding UTF8
}

function Write-InternalLog {
    param(
        [string]$Event,
        [hashtable]$Fields = @{}
    )
    $payload = [ordered]@{
        ts = (Get-Date).ToUniversalTime().ToString("o")
        event = $Event
        computer_name = $SourceName
        connect_address = $ComputerName
    }
    foreach ($key in $Fields.Keys) {
        $payload[$key] = $Fields[$key]
    }
    $payload | ConvertTo-Json -Depth 8 -Compress | Add-Content -Path $internalLogPath -Encoding UTF8
}


function Count-JsonlLines {
    param([string]$Path)
    if (-not (Test-Path -Path $Path)) {
        return 0
    }
    $count = 0
    Get-Content -Path $Path -Encoding UTF8 -ErrorAction SilentlyContinue | ForEach-Object {
        if (-not [string]::IsNullOrWhiteSpace($_)) {
            $count++
        }
    }
    return $count
}

function Set-ChannelSummary {
    param([object]$ChannelInfo)
    for ($i = 0; $i -lt $summary.channels.Count; $i++) {
        if ($summary.channels[$i].channel -eq $ChannelInfo.channel) {
            $summary.channels[$i] = $ChannelInfo
            return
        }
    }
    $summary.channels += $ChannelInfo
}

Save-Summary
Write-InternalLog -Event "collection_started" -Fields @{
    requested_collection_mode = $RequestedCollectionMode
    collection_mode = $collectionMode
    collect_message = $CollectMessage
    collector_backend = "powershell"
}
Write-Host "Collection output: $outDir"
Write-Host "Summary: $summaryPath"

foreach ($channel in $Channels) {
    $channelStartTime = Get-ChannelStartTime -Channel $channel -DefaultStartTime $startTime
    $channelAfterRecordId = Get-ChannelAfterRecordId -Channel $channel
    $channelMaxEventsForRun = Get-ChannelMaxEvents -Channel $channel -DefaultMaxEvents $MaxEventsPerChannel
    $channelTimeoutSecondsForRun = Get-ChannelTimeoutSeconds -Channel $channel -DefaultTimeoutSeconds $ChannelTimeoutSeconds
    $safeChannel = $channel -replace '[\\/:*?"<>| ]+', '_'
    $outFile = Join-Path -Path $outDir -ChildPath "$safeChannel.jsonl"
    $channelInfo = [ordered]@{
        channel = $channel
        start_time_utc = $channelStartTime.ToUniversalTime().ToString("o")
        after_record_id = $channelAfterRecordId
        max_events = $channelMaxEventsForRun
        timeout_seconds = $channelTimeoutSecondsForRun
        file = $outFile
        status = "started"
        count = 0
        error = $null
        error_type = $null
        error_category = $null
        script_stack_trace = $null
        started_at = (Get-Date).ToUniversalTime().ToString("o")
        collector_backend = "powershell"
        backend_reason = "powershell_collector"
        finished_at = $null
        duration_seconds = $null
        cursor_strategy = if ($null -ne $channelAfterRecordId) { "record_id" } else { "time_window" }
        cursor_fallback_reason = $null
        latest_available_record_id = $null
    }

    Set-ChannelSummary -ChannelInfo $channelInfo
    Save-Summary
    Write-InternalLog -Event "channel_started" -Fields @{
        channel = $channel
        start_time_utc = $channelStartTime.ToUniversalTime().ToString("o")
        after_record_id = $channelAfterRecordId
        max_events = $channelMaxEventsForRun
        timeout_seconds = $channelTimeoutSecondsForRun
    }
    Write-Host "Starting channel: $channel"
    $channelStartedAt = Get-Date

    $job = Start-Job -ArgumentList $ComputerName, $SourceName, $channel, $outFile, $channelStartTime, $channelAfterRecordId, $channelMaxEventsForRun, $CollectMessage -ScriptBlock {
        param(
            [string]$ComputerName,
            [string]$SourceName,
            [string]$Channel,
            [string]$OutFile,
            [datetime]$ChannelStartTime,
            [object]$ChannelAfterRecordId,
            [int]$MaxEventsPerChannel,
            [bool]$CollectMessage
        )
        $ErrorActionPreference = "Stop"
        try {
            $getWinEventArgs = @{
                ComputerName = $ComputerName
                ErrorAction = "Stop"
                Oldest = $true
            }

            $cursorStrategy = "time_window"
            $cursorFallbackReason = $null
            $latestAvailableRecordId = $null
            if ($null -ne $ChannelAfterRecordId) {
                $cursorStrategy = "record_id"
                try {
                    $latestEvent = Get-WinEvent -ComputerName $ComputerName -LogName $Channel -MaxEvents 1 -ErrorAction Stop
                    if ($null -ne $latestEvent) {
                        $latestAvailableRecordId = [int64]$latestEvent.RecordId
                    }
                }
                catch {
                    # If the channel has no newest event or access check is inconclusive,
                    # keep the precise cursor query. The main read below will surface errors.
                    $latestAvailableRecordId = $null
                }
            }

            if ($null -ne $ChannelAfterRecordId -and $null -ne $latestAvailableRecordId -and $latestAvailableRecordId -lt [int64]$ChannelAfterRecordId) {
                $cursorStrategy = "time_window_fallback"
                $cursorFallbackReason = "latest_record_id_before_saved_cursor"
                $getWinEventArgs.FilterHashtable = @{
                    LogName = $Channel
                    StartTime = $ChannelStartTime
                }
            }
            elseif ($null -ne $ChannelAfterRecordId) {
                $xpath = "*[System[EventRecordID > $ChannelAfterRecordId]]"
                $getWinEventArgs.LogName = $Channel
                $getWinEventArgs.FilterXPath = $xpath
            }
            else {
                $getWinEventArgs.FilterHashtable = @{
                    LogName = $Channel
                    StartTime = $ChannelStartTime
                }
            }
            if ($MaxEventsPerChannel -gt 0) {
                $getWinEventArgs.MaxEvents = $MaxEventsPerChannel
            }

            $count = 0
            Get-WinEvent @getWinEventArgs | ForEach-Object {
                $event = $_
                $properties = @()
                foreach ($property in $event.Properties) {
                    $properties += $property.Value
                }

                $row = [ordered]@{
                    computer_name = $SourceName
                    connect_address = $ComputerName
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
            }

            return [pscustomobject]@{
                status = "completed"
                count = $count
                error = $null
                error_type = $null
                error_category = $null
                script_stack_trace = $null
                cursor_strategy = $cursorStrategy
                cursor_fallback_reason = $cursorFallbackReason
                latest_available_record_id = $latestAvailableRecordId
            }
        }
        catch {
            $message = $_.Exception.Message
            if ($_.FullyQualifiedErrorId -like "*NoMatchingEventsFound*" -or $message -match "No events were found|Не найдено событий") {
                "" | Set-Content -Path $OutFile -Encoding UTF8
                return [pscustomobject]@{
                    status = "completed"
                    count = 0
                    error = $null
                    error_type = $null
                    error_category = $null
                    script_stack_trace = $null
                    cursor_strategy = $cursorStrategy
                    cursor_fallback_reason = $cursorFallbackReason
                    latest_available_record_id = $latestAvailableRecordId
                }
            }
            "" | Set-Content -Path $OutFile -Encoding UTF8
            return [pscustomobject]@{
                status = "failed"
                count = 0
                error = $message
                error_type = $_.Exception.GetType().FullName
                error_category = $_.CategoryInfo.Category
                script_stack_trace = $_.ScriptStackTrace
                cursor_strategy = $cursorStrategy
                cursor_fallback_reason = $cursorFallbackReason
                latest_available_record_id = $latestAvailableRecordId
            }
        }
    }

    $completed = Wait-Job -Job $job -Timeout $channelTimeoutSecondsForRun
    if ($null -eq $completed) {
        Stop-Job -Job $job -ErrorAction SilentlyContinue
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path -Path $outFile)) {
            "" | Set-Content -Path $outFile -Encoding UTF8
        }
        $partialCount = Count-JsonlLines -Path $outFile
        if ($partialCount -gt 0) {
            $channelInfo.status = "partial_timeout"
            $channelInfo.count = $partialCount
            $channelInfo.error = "Channel timed out after $channelTimeoutSecondsForRun seconds; $partialCount partial events were saved."
            Write-InternalLog -Event "channel_timeout" -Fields @{
                channel = $channel
                status = $channelInfo.status
                partial_count = $partialCount
                timeout_seconds = $channelTimeoutSecondsForRun
                error = $channelInfo.error
            }
            Write-Host "Timed out channel: $channel after ${channelTimeoutSecondsForRun}s partial_count=$partialCount"
        }
        else {
            $channelInfo.status = "timeout"
            $channelInfo.count = 0
            $channelInfo.error = "Channel timed out after $channelTimeoutSecondsForRun seconds."
            Write-InternalLog -Event "channel_timeout" -Fields @{
                channel = $channel
                status = $channelInfo.status
                partial_count = 0
                timeout_seconds = $channelTimeoutSecondsForRun
                error = $channelInfo.error
            }
            Write-Host "Timed out channel: $channel after ${channelTimeoutSecondsForRun}s"
        }
    }
    else {
        if ($null -ne $channelAfterRecordId) {
            $null = $channelAfterRecordId
        }
        $result = Receive-Job -Job $job -ErrorAction SilentlyContinue | Select-Object -Last 1
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        if ($null -eq $result) {
            $channelInfo.status = "failed"
            $channelInfo.error = "Channel job finished without result."
        }
        else {
            $channelInfo.status = [string]$result.status
            $channelInfo.count = [int]$result.count
            $channelInfo.error = $result.error
            if ($result.PSObject.Properties["error_type"]) { $channelInfo.error_type = $result.error_type }
            if ($result.PSObject.Properties["error_category"]) { $channelInfo.error_category = $result.error_category }
            if ($result.PSObject.Properties["script_stack_trace"]) { $channelInfo.script_stack_trace = $result.script_stack_trace }
            if ($result.PSObject.Properties["cursor_strategy"]) { $channelInfo.cursor_strategy = [string]$result.cursor_strategy }
            if ($result.PSObject.Properties["cursor_fallback_reason"]) { $channelInfo.cursor_fallback_reason = $result.cursor_fallback_reason }
            if ($result.PSObject.Properties["latest_available_record_id"]) { $channelInfo.latest_available_record_id = $result.latest_available_record_id }
        }
        if ($channelInfo.status -eq "completed") {
            Write-Host "Completed channel: $channel count=$($channelInfo.count)"
        }
        else {
            Write-InternalLog -Event "channel_failed" -Fields @{
                channel = $channel
                error = $channelInfo.error
                error_type = $channelInfo.error_type
                error_category = $channelInfo.error_category
                script_stack_trace = $channelInfo.script_stack_trace
            }
            Write-Host "Failed channel: $channel error=$($channelInfo.error)"
        }
    }

    $channelInfo.finished_at = (Get-Date).ToUniversalTime().ToString("o")
    $channelInfo.duration_seconds = [math]::Round(((Get-Date) - $channelStartedAt).TotalSeconds, 3)
    Set-ChannelSummary -ChannelInfo $channelInfo
    Save-Summary
}

$summary.finished_at = (Get-Date).ToUniversalTime().ToString("o")
Save-Summary
Write-InternalLog -Event "collection_finished" -Fields @{
    finished_at = $summary.finished_at
}

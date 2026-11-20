#requires -version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$TargetsPath,
    [Parameter(Mandatory = $true)][ValidateRange(1, 720)][int]$WindowHours,
    [Parameter(Mandatory = $true)][ValidateRange(1, 1000)][int]$MaxEventsPerTarget,
    [Parameter(Mandatory = $true)][ValidateRange(1, 100)][int]$MaxAccountingFilesPerTarget,
    [Parameter(Mandatory = $true)][ValidateRange(5, 120)][int]$TargetTimeoutSeconds,
    [Parameter(Mandatory = $true)][ValidateRange(1, 20)][int]$MaxTargets
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$configuration = Get-Content -LiteralPath $TargetsPath -Raw -Encoding UTF8 | ConvertFrom-Json
$targets = @($configuration.targets)
if ($targets.Count -lt 1 -or $targets.Count -gt $MaxTargets) {
    throw "Target count is outside the approved bound."
}

$startUtc = [datetime]::UtcNow.AddHours(-1 * $WindowHours)
$results = [System.Collections.Generic.List[object]]::new()

foreach ($target in $targets) {
    $sourceName = [string]$target.source_name
    $connectAddress = [string]$target.connect_address
    if ([string]::IsNullOrWhiteSpace($sourceName) -or [string]::IsNullOrWhiteSpace($connectAddress)) {
        throw "Every target requires source_name and connect_address."
    }

    $job = Start-Job -ArgumentList @(
        $sourceName,
        $connectAddress,
        $startUtc,
        $MaxEventsPerTarget,
        $MaxAccountingFilesPerTarget
    ) -ScriptBlock {
        param(
            [string]$SourceName,
            [string]$ConnectAddress,
            [datetime]$StartUtc,
            [int]$MaxEvents,
            [int]$MaxAccountingFiles
        )

        $ErrorActionPreference = "Stop"
        $eventStatus = "not_observed"
        $eventErrorType = $null
        $events = @()
        try {
            $events = @(
                Get-WinEvent -ComputerName $ConnectAddress -FilterHashtable @{
                    LogName = "Security"
                    Id = @(6272, 6273)
                    StartTime = $StartUtc
                } -MaxEvents ($MaxEvents + 1) -ErrorAction Stop
            )
            $eventStatus = if ($events.Count -gt 0) { "observed" } else { "not_observed" }
        }
        catch {
            if ([string]$_.FullyQualifiedErrorId -like "NoMatchingEventsFound*") {
                $events = @()
                $eventStatus = "not_observed"
            }
            else {
                $events = @()
                $eventStatus = "inaccessible"
                $eventErrorType = $_.Exception.GetType().FullName
            }
        }

        $truncated = $events.Count -gt $MaxEvents
        $selected = @($events | Select-Object -First $MaxEvents)
        $fieldNames = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::Ordinal
        )
        $providerNames = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
        $xmlParseErrors = 0
        foreach ($event in $selected) {
            if (-not [string]::IsNullOrWhiteSpace([string]$event.ProviderName)) {
                [void]$providerNames.Add([string]$event.ProviderName)
            }
            try {
                [xml]$eventXml = $event.ToXml()
                foreach ($data in @($eventXml.Event.EventData.Data)) {
                    $name = [string]$data.Name
                    if (-not [string]::IsNullOrWhiteSpace($name)) {
                        [void]$fieldNames.Add($name)
                    }
                }
            }
            catch {
                $xmlParseErrors += 1
            }
        }

        $eventGroups = @(
            $selected |
                Group-Object -Property Id |
                Sort-Object -Property Name |
                ForEach-Object {
                    [ordered]@{
                        event_id = [int]$_.Name
                        count = [int]$_.Count
                    }
                }
        )
        $eventTimes = @($selected | ForEach-Object { $_.TimeCreated.ToUniversalTime() })
        $recordIds = @($selected | ForEach-Object { [long]$_.RecordId })

        $service = [ordered]@{
            status = "inaccessible"
            present = $null
            runtime_status = $null
            error_type = $null
        }
        try {
            $ias = Get-Service -ComputerName $ConnectAddress -Name "IAS" -ErrorAction Stop
            $service.status = "observed"
            $service.present = $true
            $service.runtime_status = [string]$ias.Status
        }
        catch {
            if ([string]$_.FullyQualifiedErrorId -like "NoServiceFoundForGivenName*") {
                $service.status = "not_observed"
                $service.present = $false
            }
            else {
                $service.error_type = $_.Exception.GetType().FullName
            }
        }

        $accounting = [ordered]@{
            scope = "default_windows_nps_logfiles_path_in_prefix_only"
            status = "inaccessible"
            observed_count = 0
            truncated = $false
            selected_total_bytes = 0
            oldest_write_utc = $null
            newest_write_utc = $null
            error_type = $null
        }
        try {
            $defaultPath = "\\$ConnectAddress\c$\Windows\System32\LogFiles"
            $files = @(
                Get-ChildItem -LiteralPath $defaultPath -Filter "IN*.log" -File -ErrorAction Stop |
                    Sort-Object -Property LastWriteTimeUtc -Descending |
                    Select-Object -First ($MaxAccountingFiles + 1)
            )
            $accounting.status = if ($files.Count -gt 0) { "observed" } else { "not_observed" }
            $accounting.truncated = $files.Count -gt $MaxAccountingFiles
            $selectedFiles = @($files | Select-Object -First $MaxAccountingFiles)
            $accounting.observed_count = $selectedFiles.Count
            $accounting.selected_total_bytes = [long](
                ($selectedFiles | Measure-Object -Property Length -Sum).Sum
            )
            if ($selectedFiles.Count -gt 0) {
                $writeTimes = @($selectedFiles | ForEach-Object { $_.LastWriteTimeUtc })
                $accounting.oldest_write_utc = (
                    $writeTimes | Sort-Object | Select-Object -First 1
                ).ToString("o")
                $accounting.newest_write_utc = (
                    $writeTimes | Sort-Object -Descending | Select-Object -First 1
                ).ToString("o")
            }
        }
        catch {
            $accounting.error_type = $_.Exception.GetType().FullName
        }

        [ordered]@{
            source_name = $SourceName
            status = "completed"
            event_query = [ordered]@{
                status = $eventStatus
                error_type = $eventErrorType
                selected_count = $selected.Count
                truncated = $truncated
                groups = $eventGroups
                providers = @($providerNames | Sort-Object)
                eventdata_field_names = @($fieldNames | Sort-Object)
                xml_parse_errors = $xmlParseErrors
                oldest_time_utc = if ($eventTimes.Count -gt 0) {
                    ($eventTimes | Sort-Object | Select-Object -First 1).ToString("o")
                } else { $null }
                newest_time_utc = if ($eventTimes.Count -gt 0) {
                    ($eventTimes | Sort-Object -Descending | Select-Object -First 1).ToString("o")
                } else { $null }
                min_record_id = if ($recordIds.Count -gt 0) {
                    [long]($recordIds | Measure-Object -Minimum).Minimum
                } else { $null }
                max_record_id = if ($recordIds.Count -gt 0) {
                    [long]($recordIds | Measure-Object -Maximum).Maximum
                } else { $null }
            }
            nps_service = $service
            default_accounting_files = $accounting
        }
    }

    $completed = Wait-Job -Job $job -Timeout $TargetTimeoutSeconds
    if ($null -eq $completed) {
        Stop-Job -Job $job -ErrorAction SilentlyContinue
        $results.Add([ordered]@{
            source_name = $sourceName
            status = "timeout"
            event_query = [ordered]@{
                status = "inaccessible"
                error_type = "TargetTimeout"
                selected_count = 0
                truncated = $false
                groups = @()
                providers = @()
                eventdata_field_names = @()
                xml_parse_errors = 0
            }
            nps_service = [ordered]@{
                status = "inaccessible"
                present = $null
                runtime_status = $null
                error_type = "TargetTimeout"
            }
            default_accounting_files = [ordered]@{
                scope = "default_windows_nps_logfiles_path_in_prefix_only"
                status = "inaccessible"
                observed_count = 0
                truncated = $false
                selected_total_bytes = 0
                error_type = "TargetTimeout"
            }
        })
    }
    else {
        $received = @(Receive-Job -Job $job -ErrorAction Stop)
        if ($received.Count -ne 1) {
            throw "Remote preflight returned an unexpected item count."
        }
        $item = $received[0]
        $results.Add([ordered]@{
            source_name = [string]$item.source_name
            status = [string]$item.status
            event_query = $item.event_query
            nps_service = $item.nps_service
            default_accounting_files = $item.default_accounting_files
        })
    }
    Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
}

[ordered]@{
    schema_version = 1
    probe = "stage9-radius-readonly-preflight"
    read_only = $true
    contains_event_payload = $false
    contains_accounting_file_names = $false
    contains_accounting_file_contents = $false
    window_hours = $WindowHours
    event_ids = @(6272, 6273)
    targets = @($results)
} | ConvertTo-Json -Depth 12 -Compress

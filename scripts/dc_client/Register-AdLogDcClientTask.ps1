#requires -version 5.1
[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [string]$TaskName = "AdLogReports Dc Client Spool",
    [string]$ScriptPath = "C:\Program Files\AdLogReports\Invoke-AdLogDcClient.ps1",
    [string]$CentralDropPath = "",
    [string]$OutputRoot = "C:\ProgramData\AdLogReports\spool",
    [int]$IntervalMinutes = 5,
    [string]$Channels = "Security",
    [int]$MaxEventsPerChannel = 500,
    [switch]$Apply
)

# The same cutover setting as the Python legacy admission gate.
if ($null -ne $env:SLI_LEGACY_COLLECTION_DISABLED -and $env:SLI_LEGACY_COLLECTION_DISABLED.Trim() -ne "0") {
    throw "legacy collection disabled by SLI_LEGACY_COLLECTION_DISABLED; use agent modules and core job handlers"
}

# Retained for a clear failure for old installation commands. A copied spool is
# not a durable ingestion acknowledgment and cannot safely advance a cursor.
throw "dc_client_one_shot_only: recurring registration is unsupported without a durable ingestion acknowledgment and source-generation cursor. Use Invoke-AdLogDcClient.ps1 only for intentional manual exports. Existing scheduled tasks are not changed; review and disable them separately or migrate to the supported agent collector."

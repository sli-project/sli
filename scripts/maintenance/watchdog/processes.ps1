param(
    [ValidateSet('inventory', 'identity', 'kill', 'repair-kill', 'stop')][string]$Mode,
    [int]$WinPid,
    [long]$StartTicks,
    [string]$CiScript,
    [string]$ConflictScript
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'repair-identity.ps1')
try {
    if ($Mode -in @('inventory', 'repair-kill')) {
        $ciAnchor = ConvertTo-RepairPath $CiScript
        $conflictAnchor = ConvertTo-RepairPath $ConflictScript
        if (-not $ciAnchor -or -not $conflictAnchor -or $ciAnchor -eq $conflictAnchor) { exit 1 }
    }
    if ($Mode -eq 'inventory') {
        # Read only; do not output command lines, env assignments or secrets.
        $rows = Get-CimInstance Win32_Process
        foreach ($row in $rows) {
            $repair = Get-AuthorizedRepair $row $CiScript $ConflictScript
            if ($repair) {
                $kind = $repair.Kind
                $prNumber = $repair.Pr
                try { $startTime = (Get-Process -Id $row.ProcessId).StartTime.ToUniversalTime(); $ticks = $startTime.Ticks } catch { continue }
                $started = [long](($startTime - [datetime]'1970-01-01').TotalSeconds)
                "{0}`t{1}`t{2}`t{3}`t{4}" -f $kind, $prNumber, $row.ProcessId, $ticks, $started
            }
        }
        exit 0
    }
    $process = Get-Process -Id $WinPid -ErrorAction SilentlyContinue
    if (-not $process) {
        if ($Mode -in @('kill', 'repair-kill', 'stop')) { exit 0 }
        exit 1
    }
    $actualTicks = $process.StartTime.ToUniversalTime().Ticks
    if ($Mode -eq 'identity') { "{0} {1}" -f $WinPid, $actualTicks; exit 0 }
    # A recycled PID means our old worker is gone. Never kill the new owner.
    if ($actualTicks -ne $StartTicks) { exit 0 }
    if ($Mode -eq 'stop') {
        # Guard selects children individually; /T would also kill younger children.
        Stop-Process -InputObject $process -Force -ErrorAction Stop
        exit 0
    }
    if ($Mode -eq 'repair-kill') {
        $current = Get-CimInstance Win32_Process -Filter "ProcessId=$WinPid"
        if (-not (Get-AuthorizedRepair $current $CiScript $ConflictScript)) { exit 1 }
        # Refresh creation identity after the command query as well. taskkill
        # remains PID-based; this check does not eliminate its check/use race.
        $process = Get-Process -Id $WinPid -ErrorAction Stop
        if ($process.StartTime.ToUniversalTime().Ticks -ne $StartTicks) { exit 0 }
    }
    & "$env:SystemRoot\System32\taskkill.exe" /PID $WinPid /T /F *> $null
    if ($LASTEXITCODE -ne 0) {
        $stillThere = Get-Process -Id $WinPid -ErrorAction SilentlyContinue
        if ($stillThere -and $stillThere.StartTime.ToUniversalTime().Ticks -eq $StartTicks) { exit 1 }
    }
    exit 0
} catch { exit 1 }

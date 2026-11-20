param([Parameter(Mandatory=$true)][string]$WatchdogRoot)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
try {
    $root = [IO.Path]::GetFullPath($WatchdogRoot).Replace('\', '/').TrimEnd('/')
    $scratch = (Join-Path $env:LOCALAPPDATA 'Temp/claude').Replace('\', '/').TrimEnd('/')
    $rows = @(Get-CimInstance Win32_Process | ForEach-Object {
        $row = $_
        $kind = 'other'
        $directory = ''
        if ($row.Name -match '^(curl|git|gh|codex)(?:\.exe)?$') { $kind = $Matches[1].ToLowerInvariant() }
        if ($row.Name -match '^bash(?:\.exe)?$' -and $row.CommandLine -match '^\s*(?:"[^"]*bash(?:\.exe)?"|\S*?bash(?:\.exe)?)\s+(?:--login\s+)?(?:"(?<quoted>[^"]+\.sh)"|(?<plain>[^\s"'']+\.sh))(?:\s|$)') {
            $script = $Matches.quoted
            if (-not $script) { $script = $Matches.plain }
            $script = $script.Replace('\', '/') -replace '^/([a-zA-Z])/', '$1:/'
            $name = [IO.Path]::GetFileNameWithoutExtension($script)
            $directory = [IO.Path]::GetDirectoryName($script).Replace('\', '/')
            if (($name -eq 'watchdog' -or $name -eq 'worker') -and $directory -ieq $root) { $kind = $name }
            elseif ($name -in @('run_qmv3', 'codex_task_v3') -and $directory.StartsWith($scratch + '/', [StringComparison]::OrdinalIgnoreCase) -and $directory.EndsWith('/scratchpad')) { $kind = $name }
            elseif ($name -in @('ci_fix', 'conflict_fix') -and $directory -ieq (Split-Path $root -Parent).Replace('\', '/')) { $kind = $name }
            elseif ($name -eq 'update' -and $directory -ieq ((Split-Path $root -Parent).Replace('\', '/') + '/update')) { $kind = 'update' }
        }
        try { $start = (Get-Process -Id $row.ProcessId -ErrorAction Stop).StartTime.ToUniversalTime() } catch { return }
        [pscustomobject]@{ pid = [int]$row.ProcessId; parent = [int]$row.ParentProcessId; kind = $kind; directory = $directory; ticks = $start.Ticks; started = [long](($start - [datetime]'1970-01-01').TotalSeconds) }
    })
    ConvertTo-Json -InputObject $rows -Depth 3 -Compress
} catch { exit 1 }

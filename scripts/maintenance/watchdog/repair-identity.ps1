# Pure matching helpers; no process observations or mutations.
function ConvertTo-RepairPath([string]$Value) {
    if (-not $Value -or $Value -ne $Value.Trim()) { return $null }
    $value = $Value.Replace('\', '/')
    # Git Bash may retain the POSIX drive form in Win32_Process.CommandLine.
    if ($value -match '^/([A-Za-z])/(.*)$') { $value = $Matches[1] + ':/' + $Matches[2] }
    if ($value -notmatch '^[A-Za-z]:/' -or $value -match '(^|/)\.{1,2}(/|$)' -or $value.Contains('//')) { return $null }
    return $value.ToLowerInvariant()
}

function Get-AuthorizedRepair($Row, [string]$CiScript, [string]$ConflictScript) {
    if (-not $Row -or $Row.Name -notmatch '^bash(?:\.exe)?$') { return $null }
    # A complete script operand in a deliberately bounded Bash invocation.
    # Never scan later arguments or command strings for a known basename.
    $pattern = '^\s*(?:"[^"\r\n]*[/\\]bash(?:\.exe)?"|[^\s"'']*bash(?:\.exe)?)\s+(?:--login\s+)?(?:"(?<quoted>[^"\r\n]+)"|(?<plain>[^\s"'']+))\s+(?<pr>[1-9][0-9]*)(?:\s|$)'
    $commandLine = [string]$Row.CommandLine
    if ($commandLine -notmatch $pattern) { return $null }
    $operand = $Matches.quoted
    if (-not $operand) { $operand = $Matches.plain }
    $prNumber = $Matches.pr
    $actual = ConvertTo-RepairPath $operand
    $ci = ConvertTo-RepairPath $CiScript
    $conflict = ConvertTo-RepairPath $ConflictScript
    # Both anchors must be unambiguous absolute paths, even if only one matches.
    if (-not $actual -or -not $ci -or -not $conflict -or $ci -eq $conflict) { return $null }
    if ($actual -eq $ci) { return @{ Kind = 'ci_fix'; Pr = $prNumber } }
    if ($actual -eq $conflict) { return @{ Kind = 'conflict_fix'; Pr = $prNumber } }
    return $null
}

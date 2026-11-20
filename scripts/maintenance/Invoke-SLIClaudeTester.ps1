param(
    [Parameter(Mandatory = $true)]
    [string]$TaskFile,

    [ValidateRange(0.05, 0.50)]
    [double]$BudgetUsd = 0.15,

    [ValidateSet("low", "medium")]
    [string]$Effort = "low",

    [ValidateSet("haiku", "sonnet")]
    [string]$Model = "haiku",

    [ValidateRange(1, 5)]
    [int]$ExpectedItems = 1,

    [string]$ResultPath = "",

    [switch]$ValidateOnly
)

$ErrorActionPreference = "Stop"
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$TaskPath = (Resolve-Path -LiteralPath $TaskFile).Path

if (-not $TaskPath.StartsWith($ProjectRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Claude task file must be inside the project directory."
}

$TaskText = Get-Content -LiteralPath $TaskPath -Raw -Encoding UTF8
if ([string]::IsNullOrWhiteSpace($TaskText)) {
    throw "Claude task file is empty."
}
if ($TaskText.Length -gt 12000) {
    throw "Claude task is too large: maximum 12000 characters."
}

$ClaudeCommand = Get-Command "claude.exe" -ErrorAction SilentlyContinue
$ClaudeCandidate = if ($ClaudeCommand) {
    $ClaudeCommand.Source
} else {
    Join-Path $env:LOCALAPPDATA "Microsoft\WinGet\Links\claude.exe"
}
if (-not (Test-Path -LiteralPath $ClaudeCandidate -PathType Leaf)) {
    throw "Claude Code CLI was not found."
}

# Windows PowerShell 5.1 can resolve a WinGet symlink through Get-Command but
# then fail to execute that link with "No application is associated". Invoke
# the link target directly so every caller uses the same reliable path.
$ClaudeItem = Get-Item -LiteralPath $ClaudeCandidate -Force
if ($ClaudeItem.LinkType -eq "SymbolicLink" -and $ClaudeItem.Target) {
    $ClaudeTarget = [string]@($ClaudeItem.Target)[0]
    if (-not [System.IO.Path]::IsPathRooted($ClaudeTarget)) {
        $ClaudeTarget = Join-Path $ClaudeItem.DirectoryName $ClaudeTarget
    }
    if (-not (Test-Path -LiteralPath $ClaudeTarget -PathType Leaf)) {
        throw "Claude Code CLI link target was not found."
    }
    $ClaudeExe = (Resolve-Path -LiteralPath $ClaudeTarget).Path
} else {
    $ClaudeExe = $ClaudeItem.FullName
}

function ConvertTo-SLIProcessArgument {
    param([AllowEmptyString()][string]$Value)

    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') {
        return $Value
    }
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('"')
    $backslashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq [char]'\') {
            $backslashes += 1
            continue
        }
        if ($character -eq [char]'"') {
            if ($backslashes -gt 0) {
                [void]$builder.Append([char]'\', $backslashes * 2)
                $backslashes = 0
            }
            [void]$builder.Append('\"')
            continue
        }
        if ($backslashes -gt 0) {
            [void]$builder.Append([char]'\', $backslashes)
            $backslashes = 0
        }
        [void]$builder.Append($character)
    }
    if ($backslashes -gt 0) {
        [void]$builder.Append([char]'\', $backslashes * 2)
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Invoke-SLIClaudeProcess {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,
        [AllowEmptyString()]
        [string]$InputText = ""
    )

    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $ClaudeExe
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.Arguments = (
        $Arguments | ForEach-Object {
            ConvertTo-SLIProcessArgument -Value ([string]$_)
        }
    ) -join " "
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $startInfo.StandardOutputEncoding = $utf8
    $startInfo.StandardErrorEncoding = $utf8

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            throw "Claude process did not start."
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not [string]::IsNullOrEmpty($InputText)) {
            $process.StandardInput.Write($InputText)
        }
        $process.StandardInput.Close()
        $process.WaitForExit()
        return [pscustomobject]@{
            exit_code = $process.ExitCode
            stdout = $stdoutTask.GetAwaiter().GetResult()
            stderr = $stderrTask.GetAwaiter().GetResult()
        }
    } finally {
        $process.Dispose()
    }
}

if (-not $ResultPath) {
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $ResultPath = Join-Path $ProjectRoot "artifacts\claude\claude-task-$stamp.json"
} elseif (-not [System.IO.Path]::IsPathRooted($ResultPath)) {
    $ResultPath = Join-Path $ProjectRoot $ResultPath
}
$ResultPath = [System.IO.Path]::GetFullPath($ResultPath)
if (-not $ResultPath.StartsWith($ProjectRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Claude result must be stored inside the project directory."
}

function ConvertFrom-ClaudeJson {
    param([object[]]$Lines)

    $text = ($Lines | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
    try {
        return $text | ConvertFrom-Json
    } catch {
        return [pscustomobject]@{
            is_error = $true
            subtype = "invalid_cli_json"
            result = $text.Substring(0, [Math]::Min(4000, $text.Length))
        }
    }
}

function Get-ClaudeUsage {
    $run = Invoke-SLIClaudeProcess -Arguments @(
        "--print", "--output-format", "json", "/usage"
    )
    $payload = ConvertFrom-ClaudeJson -Lines @($run.stdout)
    $text = [string]$payload.result
    $session = $null
    $week = $null
    if ($text -match "Current session:\s*(\d+)% used") {
        $session = [int]$Matches[1]
    }
    if ($text -match "Current week \(all models\):\s*(\d+)% used") {
        $week = [int]$Matches[1]
    }
    return [pscustomobject]@{
        exit_code = $run.exit_code
        session_used_percent = $session
        week_used_percent = $week
        summary = $text
        stderr = [string]$run.stderr
    }
}

$budgetText = $BudgetUsd.ToString("0.00", [System.Globalization.CultureInfo]::InvariantCulture)
$plan = [ordered]@{
    status = "planned"
    task_file = $TaskPath
    task_characters = $TaskText.Length
    expected_items = $ExpectedItems
    effort = $Effort
    model = $Model
    budget_usd = $budgetText
    allowed_tools = @("Read", "Glob", "Grep")
    denied_tools = @("Edit", "Write", "NotebookEdit", "Bash")
    communication_language = "English"
    project_mutation_allowed = $false
}

if ($ValidateOnly) {
    $plan | ConvertTo-Json -Depth 6
    exit 0
}

$before = Get-ClaudeUsage
if ($before.exit_code -ne 0 -or $null -eq $before.session_used_percent) {
    throw "Could not read Claude usage before the task."
}
if ($before.session_used_percent -ge 85 -or $before.week_used_percent -ge 85) {
    throw "Claude task is blocked: remaining usage is below the safe threshold."
}

$prompt = @"
You are the trusted independent tester on the SLI team.
Read-only task. Do not edit files, Git, databases, runtime, or surveyed systems.
Do not use the network and do not run tests. Return only the requested compact
result through the required JSON schema. Do not include analysis, Markdown, code
quotes, or introductory text. This task requires exactly $ExpectedItems review
item(s).

$TaskText
"@

$schemaObject = [ordered]@{
    type = "object"
    additionalProperties = $false
    required = @("findings")
    properties = [ordered]@{
        findings = [ordered]@{
            type = "array"
            minItems = $ExpectedItems
            maxItems = $ExpectedItems
            items = [ordered]@{
                type = "object"
                additionalProperties = $false
                required = @("id", "status", "location", "reason")
                properties = [ordered]@{
                    id = @{ type = "integer" }
                    status = @{
                        type = "string"
                        enum = @(
                            "confirmed",
                            "disputed",
                            "already_fixed",
                            "inactive",
                            "needs_evidence"
                        )
                    }
                    location = @{ type = "string"; maxLength = 160 }
                    reason = @{ type = "string"; maxLength = 240 }
                }
            }
        }
    }
}
$schema = $schemaObject | ConvertTo-Json -Depth 12 -Compress
$schemaArgument = $schema

$arguments = @(
    "--print",
    "--output-format", "json",
    "--model", $Model,
    "--effort", $Effort,
    "--max-budget-usd", $budgetText,
    "--system-prompt", "You are a read-only SLI code tester. Inspect only named files. Return the exact requested compact result. Never edit, execute tests, use the network, or inspect unrelated files.",
    "--no-session-persistence",
    "--disable-slash-commands",
    "--setting-sources", "user",
    "--json-schema", $schemaArgument,
    "--allowedTools", "Read,Glob,Grep",
    "--disallowedTools", "Edit,Write,NotebookEdit,Bash"
)

$taskRun = Invoke-SLIClaudeProcess -Arguments $arguments -InputText $prompt
$taskExitCode = $taskRun.exit_code
$taskResult = ConvertFrom-ClaudeJson -Lines @($taskRun.stdout)
$after = Get-ClaudeUsage

$structuredFindings = @()
if (
    $null -ne $taskResult.structured_output -and
    $null -ne $taskResult.structured_output.findings
) {
    $structuredFindings = @($taskResult.structured_output.findings)
}
$structuredValid = (
    $structuredFindings.Count -eq $ExpectedItems
)
$useful = (
    $taskExitCode -eq 0 -and
    -not [bool]$taskResult.is_error -and
    -not [string]::IsNullOrWhiteSpace([string]$taskResult.result) -and
    $structuredValid
)
$efficiency = if ($useful) { "useful" } else { "waste" }
$usage = $taskResult.usage

$evidence = [ordered]@{
    status = if ($useful) { "ok" } else { "failed" }
    generated_at_utc = [DateTime]::UtcNow.ToString("o")
    plan = $plan
    limit_before = $before
    limit_after = $after
    task_exit_code = $taskExitCode
    task_stderr = ([string]$taskRun.stderr).Substring(
        0,
        [Math]::Min(4000, ([string]$taskRun.stderr).Length)
    )
    task = $taskResult
    efficiency = [ordered]@{
        classification = $efficiency
        total_cost_usd = $taskResult.total_cost_usd
        input_tokens = $usage.input_tokens
        cache_creation_input_tokens = $usage.cache_creation_input_tokens
        cache_read_input_tokens = $usage.cache_read_input_tokens
        output_tokens = $usage.output_tokens
        returned_items = $structuredFindings.Count
        cost_per_item_usd = if ($structuredFindings.Count -gt 0) {
            [double]$taskResult.total_cost_usd / $structuredFindings.Count
        } else {
            $null
        }
        output_tokens_per_item = if ($structuredFindings.Count -gt 0) {
            [int][Math]::Ceiling([double]$usage.output_tokens / $structuredFindings.Count)
        } else {
            $null
        }
        session_usage_delta_percent = (
            [int]$after.session_used_percent - [int]$before.session_used_percent
        )
        week_usage_delta_percent = (
            [int]$after.week_used_percent - [int]$before.week_used_percent
        )
        useful_result_returned = $useful
    }
}

$parent = Split-Path -Parent $ResultPath
New-Item -ItemType Directory -Force -Path $parent | Out-Null
$temporary = "$ResultPath.tmp"
$evidence | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $temporary -Encoding UTF8
Move-Item -LiteralPath $temporary -Destination $ResultPath -Force

[pscustomobject]@{
    Status = $evidence.status
    UsageBefore = "$($before.session_used_percent)% / week $($before.week_used_percent)%"
    UsageAfter = "$($after.session_used_percent)% / week $($after.week_used_percent)%"
    CostUSD = $taskResult.total_cost_usd
    OutputTokens = $usage.output_tokens
    ReturnedItems = $structuredFindings.Count
    Efficiency = $efficiency
    Result = $ResultPath
} | Format-List

if (-not $useful) {
    exit 1
}

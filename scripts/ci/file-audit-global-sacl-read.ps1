$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows' -or $env:GITHUB_REPOSITORY -ne 'sli-project/sli') {
    throw 'Requires a disposable SLI project runner.'
}
$inputRoot = Join-Path $env:RUNNER_TEMP 'sli-audit-read-input'
$windows = @(Get-ChildItem -LiteralPath $inputRoot -Filter 'Sli.Agent.Windows.dll' -File -Recurse)
if ($windows.Count -ne 1) { throw 'The pinned publish artifact must contain one Windows assembly.' }
$payload = $windows[0].Directory.FullName
$work = Join-Path $env:RUNNER_TEMP ('sli-audit-policy-read-' + [Guid]::NewGuid().ToString('N'))
$evidence = Join-Path $env:RUNNER_TEMP 'sli-audit-read-evidence.json'
New-Item -ItemType Directory -Path $work | Out-Null
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'file-audit-global-sacl-read.cs') -Destination (Join-Path $work 'Program.cs')
$escaped = [Security.SecurityElement]::Escape($payload)
$project = @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net10.0-windows</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
  </PropertyGroup>
  <ItemGroup>
    <Reference Include="System.Diagnostics.EventLog"><HintPath>$escaped\System.Diagnostics.EventLog.dll</HintPath></Reference>
  </ItemGroup>
</Project>
"@
$projectPath = Join-Path $work 'Probe.csproj'
$project | Set-Content -LiteralPath $projectPath
$dotnet = (Get-Command dotnet -CommandType Application).Source
$bin = Join-Path $work 'output'
& $dotnet build $projectPath --nologo -c Release -o $bin
if ($LASTEXITCODE -ne 0) { throw 'Native probe compilation failed.' }
$assembly = Join-Path $bin 'Probe.dll'
$arguments = '"{0}" "{1}" "{2}"' -f $assembly, $payload, $evidence
$action = New-ScheduledTaskAction -Execute $dotnet -Argument $arguments -WorkingDirectory $work
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
$task = 'SliReadGlobalSacl_' + [Guid]::NewGuid().ToString('N')
Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Settings $settings | Out-Null
try {
    Start-ScheduledTask -TaskName $task
    $deadline = (Get-Date).AddMinutes(2)
    do {
        Start-Sleep -Seconds 1
        $finished = (Test-Path -LiteralPath $evidence -PathType Leaf) -and (Get-ScheduledTask -TaskName $task).State -eq 'Ready'
    } until ($finished -or (Get-Date) -ge $deadline)
    if (-not $finished) { throw "The LocalSystem read did not finish. Task status $((Get-ScheduledTaskInfo -TaskName $task).LastTaskResult)." }
    Get-Content -LiteralPath $evidence -Raw | Write-Host
    if ((Get-ScheduledTaskInfo -TaskName $task).LastTaskResult -ne 0) { throw 'The isolated diagnostic process did not complete.' }
}
finally {
    Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $task -Confirm:$false
}

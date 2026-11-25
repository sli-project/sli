$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows' -or $env:GITHUB_REPOSITORY -ne 'sli-project/sli') {
    throw 'Requires a disposable SLI project runner.'
}
if (Get-Service -Name SLIAgentNet -ErrorAction SilentlyContinue) {
    throw 'A pre-existing SLI agent is outside the fixture.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'The hosted Windows runner does not have elevated MSI access.'
}
$evidence = Join-Path $env:RUNNER_TEMP 'sli-msi-proof-evidence'
$downloads = Join-Path $env:RUNNER_TEMP 'sli-msi-proof-input'
$work = Join-Path $env:RUNNER_TEMP ('sli-owned-share-' + [Guid]::NewGuid().ToString('N'))
$root = Join-Path $work 'share'
$probe = Join-Path $work 'probe'
$shareName = 'SliFileProof_' + [Guid]::NewGuid().ToString('N') + '$'
$taskName = 'SliFileAuditProof_' + [Guid]::NewGuid().ToString('N')
$msi = Join-Path $downloads "SliAgent-$env:KIT_COMMIT.msi"
$resultFile = Join-Path $evidence 'native.json'
$manifest = Get-Content -LiteralPath ($msi + '.json') -Raw | ConvertFrom-Json
$digest = (Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash.ToLowerInvariant()
if ($manifest.source_commit -cne $env:KIT_COMMIT -or $manifest.sha256 -cne $digest) {
    throw 'MSI source or digest differs from the verified package manifest.'
}
New-Item -ItemType Directory -Path $evidence, $root, $probe | Out-Null
[ordered]@{ commit = $env:KIT_COMMIT; msi_artifact = $env:MSI_ARTIFACT_ID; sha256 = $digest } |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $evidence 'package.json')
Set-Content -LiteralPath (Join-Path $root 'synthetic.txt') -Value 'disposable local SMB fixture'
$installAttempted = $false
$shareCreated = $false
$taskCreated = $false
try {
    $installAttempted = $true
    $installer = Start-Process -FilePath msiexec.exe -ArgumentList @(
        '/i', ('"{0}"' -f $msi), '/qn', '/norestart',
        'SERVER_URL=https://127.0.0.1:1', 'ENROLL_TOKEN=synthetic-unused-bootstrap'
    ) -Wait -PassThru -WindowStyle Hidden
    if ($installer.ExitCode -ne 0) { throw "MSI install exit $($installer.ExitCode)" }
    $service = Get-CimInstance Win32_Service -Filter "Name='SLIAgentNet'"
    if ($service.State -ne 'Running' -or $service.ProcessId -le 0 -or $service.StartName -ne 'LocalSystem') {
        throw 'The installed service did not run as LocalSystem.'
    }
    [ordered]@{ state = $service.State; account = $service.StartName; msi_install_exit = $installer.ExitCode } |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $evidence 'service.json')
    $installed = Join-Path $env:ProgramFiles 'SLI\AgentNet'
    $windowsDll = Join-Path $installed 'Sli.Agent.Windows.dll'
    if (-not (Test-Path -LiteralPath $windowsDll -PathType Leaf)) { throw 'Installed native agent assembly is missing.' }

    $systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $systemAccount = $systemSid.Translate([Security.Principal.NTAccount]).Value
    New-SmbShare -Name $shareName -Path $root -FullAccess $systemAccount | Out-Null
    $shareCreated = $true
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'file-audit-installed-windows.cs') -Destination (Join-Path $probe 'Program.cs')
    $escaped = [Security.SecurityElement]::Escape($installed)
    $project = @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net10.0-windows</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
  </PropertyGroup>
  <ItemGroup>
    <Reference Include="Sli.Agent.Core"><HintPath>$escaped\Sli.Agent.Core.dll</HintPath><Private>false</Private></Reference>
    <Reference Include="Sli.Agent.Protocol"><HintPath>$escaped\Sli.Agent.Protocol.dll</HintPath><Private>false</Private></Reference>
    <Reference Include="Sli.Agent.Windows"><HintPath>$escaped\Sli.Agent.Windows.dll</HintPath><Private>false</Private></Reference>
  </ItemGroup>
</Project>
"@
    $projectPath = Join-Path $probe 'Probe.csproj'
    $project | Set-Content -LiteralPath $projectPath
    $dotnet = (Get-Command dotnet -CommandType Application).Source
    $bin = Join-Path $probe 'output'
    & $dotnet build $projectPath --nologo -c Release -o $bin
    if ($LASTEXITCODE -ne 0) { throw 'Native probe compilation failed.' }
    $assembly = Join-Path $bin 'Probe.dll'
    $arguments = '"{0}" "{1}" "{2}" "{3}" "{4}"' -f $assembly, $installed, $shareName, $root, $resultFile
    $action = New-ScheduledTaskAction -Execute $dotnet -Argument $arguments -WorkingDirectory $work
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $taskSettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 3)
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $taskPrincipal -Settings $taskSettings | Out-Null
    $taskCreated = $true
    Start-ScheduledTask -TaskName $taskName
    $deadline = (Get-Date).AddMinutes(3)
    do {
        Start-Sleep -Seconds 1
        $finished = (Test-Path -LiteralPath $resultFile -PathType Leaf) -and (Get-ScheduledTask -TaskName $taskName).State -eq 'Ready'
    } until ($finished -or (Get-Date) -ge $deadline)
    if (-not $finished) { throw "The LocalSystem probe did not finish. Task status $((Get-ScheduledTaskInfo -TaskName $taskName).LastTaskResult)." }
    Get-Content -LiteralPath $resultFile -Raw | Write-Host
    if ((Get-ScheduledTaskInfo -TaskName $taskName).LastTaskResult -ne 0) {
        throw 'The native read-only check reported a blocker. See native.json.'
    }
}
finally {
    if ($taskCreated) {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    }
    if ($shareCreated) { Remove-SmbShare -Name $shareName -Force -Confirm:$false }
    if ($installAttempted) {
        $removal = Start-Process -FilePath msiexec.exe -ArgumentList @('/x', ('"{0}"' -f $msi), '/qn', '/norestart', 'PURGE_QUEUE=1') -Wait -PassThru -WindowStyle Hidden
        if ($removal.ExitCode -notin 0, 1605) { throw "Fixture MSI cleanup exit $($removal.ExitCode)" }
        if (Get-Service -Name SLIAgentNet -ErrorAction SilentlyContinue) { throw 'Fixture service remains after cleanup.' }
    }
}

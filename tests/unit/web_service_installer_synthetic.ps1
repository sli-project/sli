#requires -Version 5.1
# No installer execution, elevation, real CIM/registry/service/port access.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\..\scripts\ops\WebServer-ServiceSafety.ps1')

function Assert-True($Value, $Message) { if (-not $Value) { throw $Message } }
function Reset-Fixture {
    $script:root = Join-Path ([IO.Path]::GetTempPath()) 'synthetic SLI'
    $hostPath = Join-Path $script:root '.venv\pythonservice.exe'
    $script:stops = 0
    $script:connections = @()
    $script:queryFailure = $false
    $script:residualListener = $false
    $script:service = [pscustomobject]@{PathName=('"' + $hostPath + '"'); State='Running'; ProcessId=100}
    $script:processes = @{
        100 = [pscustomobject]@{ExecutablePath=$hostPath; CreationDate=[datetime]'2026-01-01'; ParentProcessId=10}
        200 = [pscustomobject]@{ExecutablePath='C:\synthetic SLI\.venv\Scripts\python.exe'; CreationDate=[datetime]'2026-01-02'; ParentProcessId=100}
        300 = [pscustomobject]@{ExecutablePath='C:\Python\python.exe'; CreationDate=[datetime]'2026-01-03'; ParentProcessId=200}
        400 = [pscustomobject]@{ExecutablePath='C:\foreign.exe'; CreationDate=[datetime]'2026-01-02'; ParentProcessId=10}
    }
    $script:className = 'server.service.sli_web_service.SLIWebServerService'
    $script:classRoot = $script:root
}
function Get-CimInstance {
    param($ClassName, $Filter, $ErrorAction)
    if ($ClassName -eq 'Win32_Service') {
        if ($null -ne $script:service) {
            # Return a new object, like CIM, not shared mock state modified by Add-Member.
            [pscustomobject]@{PathName=$script:service.PathName; State=$script:service.State; ProcessId=$script:service.ProcessId}
        }
    } elseif ($ClassName -eq 'Win32_Process') {
        $script:processes[[int]($Filter -replace '^ProcessId=', '')]
    } else { throw 'Unexpected CIM query' }
}
function Get-NetTCPConnection {
    param($ErrorAction)
    if ($script:queryFailure) { throw 'Synthetic access denied' }
    $script:connections
}
function Get-Item {
    param($LiteralPath, $ErrorAction)
    $key = [pscustomobject]@{}
    $key | Add-Member ScriptMethod GetValue {
        param($Name)
        if ($Name -eq '') { return $script:className }
        if ($Name -eq 'PythonPath') { return "$script:classRoot;C:\synthetic extras" }
        throw 'Unexpected registry value'
    }
    $key
}
function Stop-Service {
    param($Name, $ErrorAction)
    Assert-True ($Name -eq 'SLIWebServer') 'Wrong service stopped'
    $script:stops++
    $script:service.State = 'Stopped'
    if (-not $script:residualListener) { $script:connections = @() }
}
function Get-Service {
    param($Name, $ErrorAction)
    $controller = [pscustomobject]@{}
    $controller | Add-Member ScriptMethod WaitForStatus { param($Status, $Timeout) }
    $controller
}
function Listen($ProcessId) { [pscustomobject]@{LocalPort=8080; State='Listen'; OwningProcess=$ProcessId} }
function Expect-Refusal([int]$ExpectedStops=0) {
    $refused = $false
    try { Stop-OwnedSLIWebService -ProjectRoot $script:root } catch { $refused = $true }
    Assert-True $refused 'Expected fail-closed refusal'
    Assert-True ($script:stops -eq $ExpectedStops) 'Unexpected service mutation'
}

Reset-Fixture
$script:service = $null
Stop-OwnedSLIWebService -ProjectRoot $script:root
Assert-True ($script:stops -eq 0) 'Empty port should not stop anything'

Reset-Fixture
$script:connections = @(Listen 400)
Expect-Refusal
Reset-Fixture
$script:service = $null
$script:connections = @(Listen 300)
Expect-Refusal
Reset-Fixture
$script:connections = @(Listen 300; Listen 400)
Expect-Refusal
Reset-Fixture
$script:connections = @(Listen 300; Listen 300)
Stop-OwnedSLIWebService -ProjectRoot $script:root
Assert-True ($script:stops -eq 1) 'Owned descendants should stop through SCM exactly once'
Reset-Fixture
Stop-OwnedSLIWebService -ProjectRoot $script:root
Assert-True ($script:stops -eq 1) 'Reinstall must stop running owned service even without a listener'
Reset-Fixture
$script:queryFailure = $true
Expect-Refusal
Reset-Fixture
$script:service.PathName = '"C:\foreign\pythonservice.exe"'
Expect-Refusal
Reset-Fixture
$script:classRoot = 'C:\other checkout'
Expect-Refusal
Reset-Fixture
$script:className = 'foreign.Class'
Expect-Refusal
Reset-Fixture
$script:service.State = 'Start Pending'
Expect-Refusal
Reset-Fixture
$script:connections = @(Listen 300)
$script:processes[200].CreationDate = [datetime]'2026-02-01'
Expect-Refusal
Reset-Fixture
$script:connections = @(Listen 300)
$script:processes.Remove(200)
Expect-Refusal
Reset-Fixture
$script:connections = @(Listen 300)
$script:residualListener = $true
Expect-Refusal 1

# Decode and execute only the generated invocation against a synthetic capture script.
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
[IO.Directory]::CreateDirectory($tempRoot) | Out-Null
try {
    $capture = Join-Path $tempRoot 'capture '' $; (literal).ps1'
    [IO.File]::WriteAllText($capture, '[CmdletBinding()]param([bool]$Start=$true,[string]$StartupType="auto") [pscustomobject]@{Start=$Start; StartupType=$StartupType}')
    foreach ($bound in @(@{}, @{Start=$false}, @{Start=$true; StartupType='manual'}, @{Start=$false; StartupType='disabled'}, @{StartupType='delayed'})) {
        $encoded = New-SLIServiceElevationCommand -ScriptPath $capture -BoundParameters $bound
        $command = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encoded))
        $actual = & ([scriptblock]::Create($command))
        $expectedStart = if ($bound.ContainsKey('Start')) { $bound.Start } else { $true }
        $expectedType = if ($bound.ContainsKey('StartupType')) { $bound.StartupType } else { 'auto' }
        Assert-True ($actual.Start -eq $expectedStart) 'Boolean lost during elevation serialization'
        Assert-True ($actual.StartupType -ceq $expectedType) 'Startup type lost during elevation serialization'
    }
    $attack = "'; throw 'INJECTION'; #"
    $encoded = New-SLIServiceElevationCommand -ScriptPath $capture -BoundParameters @{Start=$false; StartupType=$attack}
    $actual = & ([scriptblock]::Create([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encoded))))
    Assert-True ($actual.StartupType -ceq $attack) 'Data became executable code'
} finally {
    # Remove only synthetic files created above.
    [IO.File]::Delete($capture)
    [IO.Directory]::Delete($tempRoot)
}
Write-Output 'Synthetic service ownership and elevation contracts passed.'

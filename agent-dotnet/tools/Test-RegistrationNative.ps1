param(
    [Parameter(Mandatory)][string]$OutputRoot,
    [string]$MsvcRoot='C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207',
    [string]$WindowsSdkRoot='C:\Program Files (x86)\Windows Kits\10',
    [string]$WindowsSdkVersion='10.0.26100.0'
)
$ErrorActionPreference='Stop'
$project=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$native=Join-Path $project 'installer/native'
$tests=Join-Path $project 'tests/native'
$output=[IO.Path]::GetFullPath($OutputRoot)
$fixture=Join-Path $output 'fixtures'
$compiler=Join-Path $MsvcRoot 'bin/Hostx64/x64/cl.exe'
if(-not (Test-Path -LiteralPath $compiler)){throw 'Installed MSVC x64 compiler is required; no installation is attempted.'}
New-Item -ItemType Directory -Force -Path $output,$fixture | Out-Null
$env:TEMP=$fixture; $env:TMP=$fixture
$env:PATH=(Join-Path $MsvcRoot 'bin/Hostx64/x64')+';'+$env:PATH
$env:INCLUDE=((Join-Path $MsvcRoot 'include'),(Join-Path $WindowsSdkRoot "Include/$WindowsSdkVersion/ucrt"),(Join-Path $WindowsSdkRoot "Include/$WindowsSdkVersion/shared"),(Join-Path $WindowsSdkRoot "Include/$WindowsSdkVersion/um")) -join ';'
$env:LIB=((Join-Path $MsvcRoot 'lib/x64'),(Join-Path $WindowsSdkRoot "Lib/$WindowsSdkVersion/ucrt/x64"),(Join-Path $WindowsSdkRoot "Lib/$WindowsSdkVersion/um/x64")) -join ';'
$flags=@('/nologo','/std:c++20','/utf-8','/W4','/WX','/MT','/EHsc','/DUNICODE','/D_UNICODE','/DWIN32_LEAN_AND_MEAN','/DNOMINMAX','/guard:cf','/GS',('/I'+$native))
$suites=@(
    @{name='Contract'; sources=@('RegistrationContract.cpp'); libraries=@('winhttp.lib','ws2_32.lib'); definitions=@()},
    @{name='Security'; sources=@('RegistrationContract.cpp','Snapshot.cpp','BootstrapStage.cpp'); libraries=@('winhttp.lib','ws2_32.lib','bcrypt.lib','advapi32.lib','shell32.lib','ole32.lib'); definitions=@('/DREGISTRATION_TESTS')},
    @{name='Flow'; sources=@('Handoff.cpp','Snapshot.cpp'); libraries=@('bcrypt.lib','advapi32.lib'); definitions=@()}
)
foreach($suite in $suites){
    $directory=Join-Path $output $suite.name
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
    $binary=Join-Path $directory ($suite.name+'Tests.exe')
    $sources=@((Join-Path $tests ($suite.name+'Tests.cpp'))) + @($suite.sources | ForEach-Object {Join-Path $native $_})
    & $compiler @flags @($suite.definitions) @sources ('/Fo'+$directory+'\') ('/Fe'+$binary) /link /DYNAMICBASE /NXCOMPAT /guard:cf @($suite.libraries)
    if($LASTEXITCODE -ne 0){throw ($suite.name+' compilation failed')}
    if($suite.name -eq 'Security'){& $binary $fixture}else{& $binary}
    if($LASTEXITCODE -ne 0){throw ($suite.name+' tests failed')}
}
# Exercise the command's move on synthetic state without running its MSI/service entry point.
$consoleScript=Join-Path $project '../server-dotnet/src/Sli.Server/Agents/Control/InstallAgent.ps1'
$parseErrors=$null
$syntax=[Management.Automation.Language.Parser]::ParseFile($consoleScript,[ref]$null,[ref]$parseErrors)
if($parseErrors.Count){throw 'Console install command must parse'}
$move=$syntax.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Move-PreviousAgentState'},$false)
. ([scriptblock]::Create($move.Extent.Text))
$root=Join-Path $fixture ('reconnect-'+[guid]::NewGuid().ToString('N'))
$state=Join-Path $root 'state'
$archive=Join-Path $root 'previous'
New-Item -ItemType Directory $root,$state | Out-Null
[IO.File]::WriteAllText((Join-Path $state 'identity.json'),'synthetic old identity')
if(!(Move-PreviousAgentState $state $archive)){throw 'Existing agent state was not moved'}
New-Item -ItemType Directory $state | Out-Null
if((Test-Path -LiteralPath (Join-Path $state 'identity.json')) -or
    [IO.File]::ReadAllText((Join-Path $archive 'identity.json')) -ne 'synthetic old identity'){
    throw 'Reconnect did not preserve the old identity separately from the new state'
}
Write-Output 'PASS reconnect preserves previous identity outside active state'
# This executes only fixture binaries, never Windows Installer or the production custom-action DLL.

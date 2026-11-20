param(
    [Parameter(Mandatory)][string]$OutputFile,
    [string]$MsvcRoot='C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207',
    [string]$WindowsSdkRoot='C:\Program Files (x86)\Windows Kits\10',
    [string]$WindowsSdkVersion='10.0.26100.0'
)
$ErrorActionPreference='Stop'
# Alternate installation roots are allowed; toolchain versions remain locked.
if((Split-Path -Leaf $MsvcRoot.TrimEnd('\','/')) -cne '14.44.35207'){throw 'MSVC version must be 14.44.35207'}
if($WindowsSdkVersion -cne '10.0.26100.0'){throw 'Windows SDK version must be 10.0.26100.0'}
$native=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../installer/native'))
$output=[IO.Path]::GetFullPath($OutputFile)
$directory=Split-Path -Parent $output
$compiler=Join-Path $MsvcRoot 'bin/Hostx64/x64/cl.exe'
$required=@(
    $compiler,
    (Join-Path $MsvcRoot 'bin/Hostx64/x64/link.exe'),
    (Join-Path $MsvcRoot 'include/vector'),
    (Join-Path $MsvcRoot 'lib/x64/libcmt.lib'),
    (Join-Path $WindowsSdkRoot "Include/$WindowsSdkVersion/ucrt/stdio.h"),
    (Join-Path $WindowsSdkRoot "Include/$WindowsSdkVersion/shared/sdkddkver.h"),
    (Join-Path $WindowsSdkRoot "Include/$WindowsSdkVersion/um/Windows.h"),
    (Join-Path $WindowsSdkRoot "Lib/$WindowsSdkVersion/ucrt/x64/ucrt.lib"),
    (Join-Path $WindowsSdkRoot "Lib/$WindowsSdkVersion/um/x64/msi.lib")
)
foreach($file in $required){if(-not (Test-Path -LiteralPath $file -PathType Leaf)){throw "Missing locked toolchain input: $file; this build never installs it."}}
New-Item -ItemType Directory -Force -Path $directory | Out-Null
$env:PATH=(Join-Path $MsvcRoot 'bin/Hostx64/x64')+';'+$env:PATH
$env:INCLUDE=((Join-Path $MsvcRoot 'include'),(Join-Path $WindowsSdkRoot "Include/$WindowsSdkVersion/ucrt"),(Join-Path $WindowsSdkRoot "Include/$WindowsSdkVersion/shared"),(Join-Path $WindowsSdkRoot "Include/$WindowsSdkVersion/um")) -join ';'
$env:LIB=((Join-Path $MsvcRoot 'lib/x64'),(Join-Path $WindowsSdkRoot "Lib/$WindowsSdkVersion/ucrt/x64"),(Join-Path $WindowsSdkRoot "Lib/$WindowsSdkVersion/um/x64")) -join ';'
$sources=@('RegistrationCA.cpp','RegistrationContract.cpp','Snapshot.cpp','BootstrapStage.cpp','Handoff.cpp') | ForEach-Object { Join-Path $native $_ }
& $compiler /nologo /std:c++20 /utf-8 /W4 /WX /MT /EHsc /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /DNOMINMAX /guard:cf /GS /LD @sources `
    ('/Fo'+$directory+'\') ('/Fe'+$output) /link /DYNAMICBASE /NXCOMPAT /guard:cf winhttp.lib ws2_32.lib bcrypt.lib advapi32.lib shell32.lib ole32.lib msi.lib comdlg32.lib user32.lib
if($LASTEXITCODE -ne 0){throw 'Native registration custom-action build failed'}

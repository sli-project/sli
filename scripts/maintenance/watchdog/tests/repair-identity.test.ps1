# Pure fixtures, no CIM, Get-Process, taskkill, services, or host mutation.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../repair-identity.ps1')
$ci = 'D:\owned project\ci_fix.sh'
$conflict = 'D:\owned project\conflict_fix.sh'
$cases = @(
    @{ Command = 'bash "D:\owned project\ci_fix.sh" 42 name'; Kind = 'ci_fix' },
    @{ Command = 'bash --login "/d/owned project/conflict_fix.sh" 42 name'; Kind = 'conflict_fix' },
    @{ Command = 'bash "D:\foreign\ci_fix.sh" 42 name'; Kind = $null },
    @{ Command = 'bash ci_fix.sh 42 name'; Kind = $null },
    @{ Command = "bash 'D:\owned project\ci_fix.sh' 42 name"; Kind = $null },
    @{ Command = 'bash -c "echo ci_fix.sh 42 name"'; Kind = $null },
    @{ Command = 'bash "D:\owned project\other.sh" 42 "D:\owned project\ci_fix.sh"'; Kind = $null },
    @{ Command = 'bash "D:\owned project\..\owned project\ci_fix.sh" 42 name'; Kind = $null },
    @{ Command = 'bash "D:\owned project\ci_fix.sh.bak" 42 name'; Kind = $null },
    @{ Command = 'bash "D:\owned project\ci_fix.sh" 0 name'; Kind = $null }
)
foreach ($case in $cases) {
    $row = [pscustomobject]@{ Name = 'bash.exe'; CommandLine = $case.Command }
    $result = Get-AuthorizedRepair $row $ci $conflict
    if ($case.Kind) {
        if (-not $result -or $result.Kind -ne $case.Kind -or $result.Pr -ne '42') { throw 'Expected authorized repair' }
    } elseif ($result) { throw 'Foreign or ambiguous repair was authorized' }
}
$row = [pscustomobject]@{ Name = 'bash.exe'; CommandLine = 'bash "D:\owned project\ci_fix.sh" 42 name' }
if (Get-AuthorizedRepair $row 'ci_fix.sh' $conflict) { throw 'Relative configuration accepted' }

$row = [pscustomobject]@{ Name = 'bash.exe'; CommandLine = "bash `"D:\O'Brien\ci_fix.sh`" 42 name" }
$result = Get-AuthorizedRepair $row "D:\O'Brien\ci_fix.sh" $conflict
if (-not $result -or $result.Kind -ne 'ci_fix') { throw 'Literal apostrophe in double-quoted path rejected' }
$row = [pscustomobject]@{ Name = 'bash.exe'; CommandLine = "bash `"D:\owned project\ci_fix.sh`" 42 --name `"O'Brien`"" }
if (-not (Get-AuthorizedRepair $row $ci $conflict)) { throw 'Literal apostrophe in later argument rejected' }
Write-Output 'PASS repair identity pure fixtures'

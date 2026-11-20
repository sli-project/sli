"""Local PowerShell execution of the exact-GUID boundary; no directory contact."""
import os
from pathlib import Path
import subprocess

import pytest


@pytest.mark.windows_only
def test_exact_guid_batches_preserve_identity_coverage_and_atomic_dc_results(tmp_path):
    root = Path(__file__).resolve().parents[2]
    script = tmp_path / "exact.ps1"
    script.write_text(r'''param($Source)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if (@($errors).Count) { throw 'parse_error' }
$node=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-SLIExactLogonRows'},$true)
if ($null -eq $node) { throw 'missing_exact_batch_helper' }
. ([scriptblock]::Create($node.Extent.Text))
$script:all=@(1..129|ForEach-Object { [pscustomobject]@{ObjectGUID=[guid]::Parse(('00112233-4455-6677-8899-{0:x12}' -f $_));lastLogon=[long]$_} })
function Get-ADUser {
 param($Server,$LDAPFilter,$SearchBase,$SearchScope,$ResultSetSize,$Properties,$ErrorAction)
 $script:calls++
 if ($Server -ne 'dc.test' -or $SearchBase -ne 'DC=test' -or $SearchScope -ne 'Subtree') { throw 'scope_changed' }
 if (($Properties -join ',') -ne 'ObjectGUID,lastLogon') { throw 'properties_widened' }
 $matches=[regex]::Matches($LDAPFilter,'\(objectGUID=((?:\\[0-9a-f]{2}){16})\)')
 if ($matches.Count -lt 1 -or $matches.Count -gt 128 -or $ResultSetSize -ne $matches.Count+1) { throw 'unbounded_query' }
 if ($script:calls -eq 1 -and -not $LDAPFilter.Contains('(objectGUID=\33\22\11\00\55\44\77\66\88\99\00\00\00\00\00\01)')) { throw 'guid_byte_order_wrong' }
 $rows=@(foreach($m in $matches) {
   $bytes=[byte[]]@([regex]::Matches($m.Groups[1].Value,'[0-9a-f]{2}')|ForEach-Object{[Convert]::ToByte($_.Value,16)})
   $id=[guid]::new($bytes)
   $script:all|Where-Object ObjectGUID -eq $id
 })
 if ($script:mode -eq 'second_failure' -and $script:calls -eq 2) { throw 'dc_unavailable' }
 if ($script:mode -eq 'missing') { return @($rows|Select-Object -Skip 1) }
 if ($script:mode -eq 'duplicate') { return @($rows)+@($rows[0]) }
 if ($script:mode -eq 'extra') { return @($rows)+@([pscustomobject]@{ObjectGUID=[guid]::NewGuid();lastLogon=999}) }
 return $rows
}
foreach($count in @(0,1,128,129)) {
 $script:calls=0;$script:mode='ok';$progress=0;$script:progressEvents=@()
 $users=if($count -eq 0){@()}else{@($script:all|Select-Object -First $count)}
 $result=@(Get-SLIExactLogonRows -Users $users -Server 'dc.test' -SearchBase 'DC=test' -QueryCount ([ref]$progress) -OnQuery {param($n) $script:progressEvents+=,$n})
 if ($result.Count -ne $count -or $script:calls -ne [math]::Ceiling($count/128.0) -or $progress -ne $script:calls) { throw 'batch_shape_wrong' }
 if ($script:progressEvents.Count -ne $script:calls) { throw 'progress_missing' }
}
foreach($mode in @('missing','duplicate','extra','second_failure')) {
 $script:mode=$mode;$script:calls=0;$progress=0;$caught=$false
 $escaped=[Collections.Generic.List[object]]::new()
 try { Get-SLIExactLogonRows -Users $script:all -Server 'dc.test' -SearchBase 'DC=test' -QueryCount ([ref]$progress)|ForEach-Object{$escaped.Add($_)} } catch {$caught=$true}
 if (-not $caught -or $escaped.Count -ne 0) { throw 'failed_dc_leaked_partial_rows' }
 if ($progress -ne $script:calls) { throw 'failed_call_not_counted' }
}
Write-Output 'PASS'
''', encoding="utf-8")
    executable = str(Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe")
    result = subprocess.run([executable, "-NoProfile", "-NonInteractive", "-File", str(script), str(root / "scripts/ad_context/Export-AdAuditContextBundle.ps1")], capture_output=True, text=True, timeout=30, creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "PASS"

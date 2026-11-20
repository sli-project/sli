"""Execute only the pure byte guard extracted from the collector AST."""
import os
from pathlib import Path
import subprocess

import pytest


@pytest.mark.host_dependent  # needs the RSAT ActiveDirectory module types
@pytest.mark.windows_only
def test_base_byte_guard_exact_size_and_source_isolation(tmp_path):
    root = Path(__file__).resolve().parents[2]
    harness = tmp_path / "byte-guard.ps1"
    harness.write_text(r'''param($SourcePath)
$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($SourcePath,[ref]$tokens,[ref]$errors)
if (@($errors).Count) { throw 'parse_error' }
foreach ($name in @('ConvertTo-SLIBaseSizeValue','Measure-SLIBaseRowsJsonBytes')) {
    $node=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
    if ($null -eq $node) { throw "missing_function:$name" }
    . ([scriptblock]::Create($node.Extent.Text))
}
$script:getterCalls=0
$unicode=[string][char]0x0416
$user=[pscustomobject]@{ObjectGUID=[guid]'00000000-0000-0000-0000-000000000001';SID=[Security.Principal.SecurityIdentifier]::new('S-1-5-18');Name='n';ObjectClass='user';Description=($unicode+'"'+[char]10+'\');MemberOf=@('one');Empty=@();Missing=$null;When=[datetime]::Parse('2026-01-01T00:00:00Z').ToUniversalTime();Enabled=$true}
$user|Add-Member -MemberType ScriptProperty -Name Dangerous -Value {$script:getterCalls++; throw 'unselected_getter_called'}
$properties=@('ObjectGUID','SID','Description','MemberOf','Empty','Missing','When','Enabled')
$beforeMember=$user.MemberOf
$expected='{"users":[{"Description":"'+$unicode+'\"\n\\","Empty":[],"Enabled":true,"MemberOf":["one"],"Missing":null,"Name":"n","ObjectClass":"user","ObjectGUID":"00000000-0000-0000-0000-000000000001","SID":"S-1-5-18","When":"2026-01-01T00:00:00.0000000Z"}],"computers":[]}'
$expectedBytes=[Text.Encoding]::UTF8.GetByteCount($expected)
$measured=Measure-SLIBaseRowsJsonBytes -Users @($user) -Computers @() -UserProperties $properties -ComputerProperties @() -ByteLimit $expectedBytes
if ($measured -ne $expectedBytes) { throw "size_mismatch:$measured/$expectedBytes" }
$failed=$false
try { $null=Measure-SLIBaseRowsJsonBytes -Users @($user) -Computers @() -UserProperties $properties -ComputerProperties @() -ByteLimit ($expectedBytes-1) } catch { if ($_.Exception.Message -ne 'ad_snapshot_base_v1_byte_bound_exceeded') { throw }; $failed=$true }
if (-not $failed) { throw 'byte_overflow_accepted' }
if ($script:getterCalls -ne 0 -or $user.ObjectGUID -isnot [guid] -or -not [object]::ReferenceEquals($beforeMember,$user.MemberOf) -or $user.MemberOf.Count -ne 1) { throw 'source_changed' }
# Account for comma separators in both arrays without changing source values.
$emptySize=Measure-SLIBaseRowsJsonBytes -Users @() -Computers @() -UserProperties @() -ComputerProperties @() -ByteLimit 1024
if ($emptySize -ne [Text.Encoding]::UTF8.GetByteCount('{"users":[],"computers":[]}')) { throw 'empty_envelope_wrong' }
$doubleSize=Measure-SLIBaseRowsJsonBytes -Users @($user,$user) -Computers @() -UserProperties $properties -ComputerProperties @() -ByteLimit 4096
if ($doubleSize -ne (2*$expectedBytes-$emptySize+1)) { throw 'comma_accounting_wrong' }
foreach ($case in @(@{Value=@();Json='[]'}, @{Value=@('one');Json='["one"]'}, @{Value=@($null);Json='[null]'})) {
    $r=[pscustomobject]@{Value=$case.Value}
    $wanted='{"users":[{"Name":null,"ObjectClass":null,"Value":'+$case.Json+'}],"computers":[]}'
    $actual=Measure-SLIBaseRowsJsonBytes -Users @($r) -Computers @() -UserProperties @('Value') -ComputerProperties @() -ByteLimit 4096
    if ($actual -ne [Text.Encoding]::UTF8.GetByteCount($wanted)) { throw 'array_shape_lost' }
}
[void][Reflection.Assembly]::LoadWithPartialName('Microsoft.ActiveDirectory.Management')
$adValues=[Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]::new()
[void]$adValues.Add('one')
$adRow=[pscustomobject]@{Value=$adValues}
$actual=Measure-SLIBaseRowsJsonBytes -Users @($adRow) -Computers @() -UserProperties @('Value') -ComputerProperties @() -ByteLimit 4096
if ($actual -ne [Text.Encoding]::UTF8.GetByteCount('{"users":[{"Name":null,"ObjectClass":null,"Value":["one"]}],"computers":[]}')) { throw 'ad_collection_shape_lost' }
$adUser=[Microsoft.ActiveDirectory.Management.ADUser]::new()
$adUser.ObjectGUID=[guid]'00000000-0000-0000-0000-000000000001'
$adUser.SamAccountName='fixture-user'
$adUser|Add-Member -NotePropertyName MemberOf -NotePropertyValue $adValues
$adComputer=[Microsoft.ActiveDirectory.Management.ADComputer]::new()
$adComputer.ObjectGUID=[guid]'00000000-0000-0000-0000-000000000002'
$adComputer.DNSHostName='fixture.example.test'
if ($adUser.PSObject.Properties['MemberOf'].Value -isnot [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]) { throw 'ad_dynamic_fixture_invalid' }
$actual=Measure-SLIBaseRowsJsonBytes -Users @($adUser) -Computers @($adComputer) -UserProperties @('MemberOf','ObjectGUID','SamAccountName') -ComputerProperties @('DNSHostName','ObjectGUID') -ByteLimit 4096
if ($actual -ne [Text.Encoding]::UTF8.GetByteCount('{"users":[{"MemberOf":["one"],"Name":null,"ObjectClass":null,"ObjectGUID":"00000000-0000-0000-0000-000000000001","SamAccountName":"fixture-user"}],"computers":[{"DNSHostName":"fixture.example.test","Name":null,"ObjectClass":null,"ObjectGUID":"00000000-0000-0000-0000-000000000002"}]}')) { throw 'ad_object_projection_wrong' }
if ($adValues.Count -ne 1 -or $adValues[0] -ne 'one' -or $adComputer.ObjectGUID -isnot [guid]) { throw 'ad_fixture_mutated' }
foreach ($bad in @([pscustomobject]@{nested=@{value='bad'}}, [object[]]@([pscustomobject]@{value='bad'}), [object[]]@(,[object[]]@('nested')))) {
    $badRow=[pscustomobject]@{Name='n';ObjectClass='user';Bad=$bad}
    $failed=$false
    try { $null=Measure-SLIBaseRowsJsonBytes -Users @($badRow) -Computers @() -UserProperties @('Bad') -ComputerProperties @() -ByteLimit 4096 } catch { if ($_.Exception.Message -ne 'ad_snapshot_base_v1_value_unsupported') { throw }; $failed=$true }
    if (-not $failed) { throw 'complex_value_accepted' }
}
Write-Output 'PASS'
''', encoding="utf-8")
    powershell = str(Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe")
    result = subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-File", str(harness), str(root / "scripts/ad_context/Export-AdAuditContextBundle.ps1")], capture_output=True, text=True, timeout=60, creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "PASS"

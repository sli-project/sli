param([Parameter(Mandatory)][string]$OracleAssembly,[Parameter(Mandatory)][string]$NativeHarness,[Parameter(Mandatory)][string]$FixtureRoot)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$OutputEncoding = [Text.UTF8Encoding]::new($false)
$root = $PSScriptRoot

[Reflection.Assembly]::LoadFrom([IO.Path]::GetFullPath($OracleAssembly)) | Out-Null
$now = [DateTimeOffset]::Parse('2026-10-25T12:00:00Z')
$body = '{"contract_id":"sli.agent-registration.v1","server_url":"https://SLI.example.test:8443","ca_sha256":"' + ('A' * 64) + '","enrollment":{"kind":"group","token":"' + ('g' * 43) + '","computer_entity_id":7,"expires_at":"2026-10-25T13:00:00Z"}}'
$cases = [ordered]@{
    valid=$body
    reordered=$body.Replace('"contract_id":"sli.agent-registration.v1","server_url":"https://SLI.example.test:8443"','"server_url":"https://SLI.example.test:8443","contract_id":"sli.agent-registration.v1"')
    uppercase_scheme=$body.Replace('https://','HTTPS://')
    default_port=$body.Replace(':8443',':443')
    root_slash=$body.Replace(':8443"',':8443/"')
    ipv6=$body.Replace('SLI.example.test','[::1]')
    expiry_fraction=$body.Replace('13:00:00Z','12:00:00.0000001+00:00')
    expiry_seven_days=$body.Replace('2026-10-25T13:00:00Z','2026-11-01T12:00:00+00:00')
    expiry_past=$body.Replace('13:00:00Z','12:00:00Z')
    expiry_offset=$body.Replace('13:00:00Z','13:00:00+01:00')
    expiry_invalid_day=$body.Replace('2026-10-25T13:00:00Z','2026-02-30T13:00:00Z')
    max_integer=$body.Replace(':7,',':9223372036854775807,')
    over_integer=$body.Replace(':7,',':9223372036854775808,')
    beyond_double_exact=$body.Replace(':7,',':9007199254740993,')
    integer_zero=$body.Replace(':7,',':0,')
    integer_float=$body.Replace(':7,',':1.0,')
    integer_exponent=$body.Replace(':7,',':1e0,')
    integer_bool=$body.Replace(':7,',':true,')
    integer_string=$body.Replace(':7,',':"7",')
    duplicate=$body.Replace('"kind":"group"','"kind":"group","kind":"group"')
    decoded_duplicate=$body.Replace('"kind":"group"','"kind":"group","\u006bind":"group"')
    escaped_token=$body.Replace(('g' * 43),(('\u0067' * 43)))
    unknown=$body.Replace('}}','},"extra":true}')
    trailing_comma=$body.Replace('}}','},}')
    comment=$body.Replace('{"contract_id"','{/* comment */"contract_id"')
    escaped_surrogate=$body.Replace('"group"','"\ud800"')
    unknown_version=$body.Replace('.v1','.v2')
    single_use=$body.Replace('"group"','"single"')
    pin_short=$body.Replace(('A' * 64),'bad')
    http=$body.Replace('https://','http://')
    credentials=$body.Replace('SLI.example.test','user:pass@SLI.example.test')
    path=$body.Replace(':8443"',':8443/path"')
    query=$body.Replace(':8443"',':8443/?x=1"')
    fragment=$body.Replace(':8443"',':8443/#x"')
    empty=''
    array='[]'
    null='null'
    broken='{broken'
    oversize=('x' * 16385)
    unicode_host=$body.Replace('SLI.example.test','bücher.example.test')
    normalized_dot_path=$body.Replace(':8443"',':8443/path/../"')
    token_final_newline=$body.Replace(('g' * 43),(('g' * 43) + '\n'))
}
$scratch = [IO.Path]::GetFullPath($FixtureRoot)
New-Item -ItemType Directory -Force -Path $scratch | Out-Null
$differences = @()
foreach ($entry in $cases.GetEnumerator()) {
    $bytes = [Text.UTF8Encoding]::new($false,$true).GetBytes($entry.Value)
    $path = Join-Path $scratch ($entry.Key + '.json')
    [IO.File]::WriteAllBytes($path,$bytes)
    $oracle = $null
    try { $oracle = [Sli.Agent.Core.RegistrationFile]::Parse([ReadOnlyMemory[byte]]::new($bytes),$now) } catch { }
    $native = @(& $NativeHarness --parse $path)
    if ($LASTEXITCODE -ne 0) { throw ('Native harness failure: '+$entry.Key) }
    $accepted = $native.Count -gt 0 -and $native[0] -eq 'accept'
    $same = $accepted -eq ($null -ne $oracle)
    # RegistrationFile does not expose entity directly; validate it using the existing enrollment reader.
    if ($accepted -and $null -ne $oracle) {
        $input = [Sli.Agent.Core.EnrollmentInput]::Parse($oracle.EnrollmentJson,$now)
        $same = $native[1] -ceq $oracle.ServerUrl.AbsoluteUri -and $native[2] -ceq $oracle.CaSha256 -and $native[3] -eq $input.ComputerEntityId
    }
    if (-not $same) { $differences += [pscustomobject]@{case=$entry.Key;native=$accepted;oracle=($null -ne $oracle)} }
}
"Corpus=$($cases.Count); differences=$($differences.Count)"
$differences | ConvertTo-Json -Depth 3
if ($differences.Count -ne 2 -or @($differences | Where-Object { $_.case -notin @('normalized_dot_path','token_final_newline') -or $_.native -or -not $_.oracle }).Count) { throw 'Unexpected parser divergence' }
'PASS 40 matching cases and 2 documented stricter refusals; not complete parser equivalence'

#requires -Version 5.1
# SPDX-License-Identifier: Apache-2.0
# Service identity only. Policy is data on stdin; source XML never goes to disk.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.DirectoryServices
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
$policy = [Console]::In.ReadToEnd() | ConvertFrom-Json
try {
    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) { throw 'missing' }
    Import-Module GroupPolicy -ErrorAction Stop
    if (-not (Get-Command Get-GPOReport, Get-GPPermission -ErrorAction Stop)) { throw 'missing' }
} catch {
    [Console]::Out.Write('{"error_code":"agent_gpo_group_policy_unavailable"}')
    exit 0
}
Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts/ad_context/GpoReportContract.psm1') -Force -ErrorAction Stop
$auth = [DirectoryServices.AuthenticationTypes]::Secure -bor
    [DirectoryServices.AuthenticationTypes]::Signing -bor [DirectoryServices.AuthenticationTypes]::Sealing
$clock = [Diagnostics.Stopwatch]::StartNew()
$timeout = [TimeSpan]::FromSeconds([Math]::Min(30, [int]$policy.capture_seconds))
$script:ObservedAt = (Get-Date).ToUniversalTime().ToString('o')
$server = if (@($policy.dc).Count) { [string]$policy.dc[0] } else { [string]$policy.domain_dns }
$domainDns = [string]$policy.domain_dns
$overflow = $false
$partial = $false
$script:CapturedBytes = 0
$gpos = [Collections.Generic.List[object]]::new()
$scopes = [Collections.Generic.List[object]]::new()
$links = [Collections.Generic.List[object]]::new()
$settings = [Collections.Generic.List[object]]::new()
$permissions = [Collections.Generic.List[object]]::new()
$acl = [Collections.Generic.List[object]]::new()
$wmi = [Collections.Generic.List[object]]::new()
$unresolved = [Collections.Generic.List[object]]::new()
$records = [Collections.Generic.List[object]]::new()
$errors = [Collections.Generic.List[object]]::new()

function New-Entry([string]$Dn) {
    if ($server -notmatch '^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$') { throw 'agent_gpo_endpoint_invalid' }
    $entry = [DirectoryServices.DirectoryEntry]::new(('LDAP://' + $server + '/' + $Dn))
    $entry.AuthenticationType = $auth
    return $entry
}

function State([string]$Status, [string]$Source, $Value = $null) {
    @{ status=$Status; source=$Source; value=$Value; observed_at=$script:ObservedAt; detail=$null; error=$null; coverage=$null }
}

function Failure([string]$Stage, [Exception]$Exception) {
    $script:partial = $true
    $status = 'failed'
    if ($Exception -is [UnauthorizedAccessException] -or $Exception.Message -match '(?i)access.*denied|unauthorized') { $status='access_denied' }
    elseif ($Exception -is [IO.FileNotFoundException] -or $Exception -is [IO.DirectoryNotFoundException]) { $status='no_record' }
    elseif ($Exception -is [Xml.XmlException] -or $Exception -is [FormatException] -or $Exception.Message -match '(?i)parse|invalid.*xml|sysvol_path_invalid') { $status='parse_error' }
    $errors.Add(@{code=('agent_gpo_' + $Stage + '_' + $status); source=$Stage; status=$status; message=$null})
    State $status $Stage
}

function Search([string]$Base, [string]$Filter, [string[]]$Names, [bool]$BaseOnly = $false) {
    if ($script:overflow) { return }
    if ($clock.Elapsed.TotalSeconds -ge [int]$policy.capture_seconds) { throw 'agent_gpo_time_limit' }
    $entry = New-Entry $Base
    $searcher = [DirectoryServices.DirectorySearcher]::new($entry)
    $result = $null
    try {
        $searcher.Filter = $Filter
        $searcher.PageSize = 500
        $searcher.SizeLimit = [int]$policy.max_objects + 1
        $searcher.ServerTimeLimit = $timeout
        $searcher.ClientTimeout = $timeout
        $searcher.ReferralChasing = [DirectoryServices.ReferralChasingOption]::None
        if ($BaseOnly) { $searcher.SearchScope = [DirectoryServices.SearchScope]::Base }
        [void]$searcher.PropertiesToLoad.AddRange($Names)
        $result = $searcher.FindAll()
        if ($result.Count -gt [int]$policy.max_objects) { $script:overflow = $true; return }
        foreach ($row in $result) {
            $props = @{}
            foreach ($name in $Names) {
                $values = @($row.Properties[$name.ToLowerInvariant()])
                if ($values.Count) {
                    $value = $values[0]
                    if ($name -eq 'objectguid') { $value = [Guid]::new([byte[]]$value).ToString() }
                    elseif ($name -eq 'objectsid') { $value = [Security.Principal.SecurityIdentifier]::new([byte[]]$value, 0).Value }
                    elseif ($value -is [datetime]) { $value = $value.ToUniversalTime().ToString('o') }
                    $props[$name.ToLowerInvariant()] = $value
                }
            }
            $props
        }
    } finally {
        if ($null -ne $result) { $result.Dispose() }
        $searcher.Dispose(); $entry.Dispose()
    }
}

function Within-Budget($Value) {
    # Account normalized rows as they arrive, before retaining more source data.
    $bytes = [Text.Encoding]::UTF8.GetByteCount((ConvertTo-Json -InputObject $Value -Depth 100 -Compress)) + 1
    if ($script:CapturedBytes + $bytes -gt [int]$policy.max_bytes) { $script:overflow=$true; return $false }
    $script:CapturedBytes += $bytes
    return $true
}

function Stable-Id([string]$Prefix, [string]$Seed) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Seed))
        $bytes = New-Object byte[] 16
        [Array]::Copy($hash, $bytes, 16)
        $id = [Guid]::new($bytes)
        "$Prefix-$($id.ToString().ToLowerInvariant())"
    } finally { $sha.Dispose() }
}

function Guid-Text($Value) {
    $match = [regex]::Match([string]$Value, '(?i)[{]?(?<id>[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})[}]?')
    if ($match.Success) { return $match.Groups['id'].Value.ToUpperInvariant() }
    return $null
}

function Wmi-Date($Value) {
    if ($null -eq $Value) { return $null }
    $match=[regex]::Match([string]$Value, '^(?<stamp>\d{14})')
    if ($match.Success) {
        try {
            return [datetime]::ParseExact($match.Groups['stamp'].Value, 'yyyyMMddHHmmss', [Globalization.CultureInfo]::InvariantCulture).ToUniversalTime().ToString('o')
        } catch { }
    }
    return [string]$Value
}

function Get-ConfinedGptPath([string]$OriginalPath, [string]$PolicyGuid) {
    $domainPattern = [regex]::Escape($domainDns)
    $hosts = '(?:' + $domainPattern + '|' + [regex]::Escape($server) + ')'
    $pattern = '^\\\\' + $hosts + '\\SYSVOL\\' + $domainPattern + '\\Policies\\\{' + [regex]::Escape($PolicyGuid) + '\}$'
    if ($OriginalPath -notmatch $pattern) { throw 'agent_gpo_sysvol_path_invalid' }
    $root = '\\' + $server + '\SYSVOL\' + $domainDns + '\Policies\'
    $path = $root + '{' + $PolicyGuid + '}\GPT.INI'
    if (-not [IO.Path]::GetFullPath($path).StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'agent_gpo_sysvol_path_invalid'
    }
    # Refuse reparse points as well as lexical traversal; never enumerate SYSVOL.
    foreach ($probe in @($root.TrimEnd('\'), ($root + '{' + $PolicyGuid + '}'), $path)) {
        if ([IO.File]::GetAttributes($probe) -band [IO.FileAttributes]::ReparsePoint) { throw 'agent_gpo_sysvol_path_invalid' }
    }
    $path
}

$rootStates = @{}
foreach ($name in @('gpo_list','gpo_reports','gpc_directory','sysvol_gpt','links','permissions','wmi_filters')) {
    $rootStates[$name] = State 'not_evaluated' $name
}
try {
    $root = New-Entry 'RootDSE'
    try {
        $domainNc = [string]$root.Properties['defaultNamingContext'][0]
        $configNc = [string]$root.Properties['configurationNamingContext'][0]
        if (-not @($policy.dc).Count) { $server = [string]$root.Properties['dnsHostName'][0] }
    } finally { $root.Dispose() }
    $expectedNc = (@($domainDns.Split('.') | ForEach-Object { 'DC=' + $_ }) -join ',')
    if ($domainNc -ine $expectedNc -or (@($policy.search_bases).Count -and
        (@($policy.search_bases).Count -ne 1 -or $policy.search_bases[0] -ine $domainNc))) { throw 'agent_gpo_scope_mismatch' }
    $domainRows = @(Search $domainNc '(objectClass=domainDNS)' @('objectsid','distinguishedname','name','gplink','gpoptions') $true)
    if ($domainRows.Count -ne 1 -or $domainRows[0].objectsid -ne $policy.domain_sid) { throw 'agent_gpo_domain_mismatch' }
} catch {
    [Console]::Out.Write('{"error_code":"agent_gpo_capture_failed"}')
    exit 0
}

$gpcRows = @()
try {
    $gpcRows = @(Search ('CN=Policies,CN=System,' + $domainNc) '(objectClass=groupPolicyContainer)' @(
        'name','objectguid','displayname','description','distinguishedname','gpcfilesyspath','gpcfunctionalityversion',
        'gpcmachineextensionnames','gpcuserextensionnames','gpcwqlfilter','versionnumber','flags','whencreated','whenchanged'))
    $rootStates.gpo_list = State 'observed' 'LDAP groupPolicyContainer'
    $rootStates.gpc_directory = State 'observed' 'LDAP groupPolicyContainer'
} catch {
    $rootStates.gpo_list = Failure 'gpc_directory' $_.Exception
    $rootStates.gpc_directory = $rootStates.gpo_list
}

$byDn = @{}
$reportsOk = $gptOk = $permissionsOk = 0
foreach ($gpc in $gpcRows) {
    if ($overflow) { break }
    if ($clock.Elapsed.TotalSeconds -ge [int]$policy.capture_seconds) { $overflow = $true; break }
    $guid = Guid-Text $gpc['name']
    if (-not $guid) { $overflow = $true; continue }
    $id = 'gpo-' + $guid.ToLowerInvariant()
    $version = if ($null -ne $gpc['versionnumber']) { [long]$gpc['versionnumber'] } else { $null }
    $flags = if ($null -ne $gpc['flags']) { [int]$gpc['flags'] } else { $null }
    $wmiGuid = Guid-Text $gpc['gpcwqlfilter']
    $sourceStates = @{
        gpo=(State 'observed' 'LDAP groupPolicyContainer'); gpc=(State 'observed' 'LDAP groupPolicyContainer');
        report=(State 'not_evaluated' 'Get-GPOReport XML'); gpt=(State 'not_evaluated' 'GPT.INI');
        permissions=(State 'not_evaluated' 'Get-GPPermission'); acl=(State 'not_evaluated' 'DirectoryServices DACL');
        links=(State 'not_evaluated' 'gPLink'); wmi_filter=(State 'not_applicable' 'gPCWQLFilter')
    }
    if ($gpc['gpcwqlfilter'] -and -not $wmiGuid) {
        $sourceStates.wmi_filter = State 'parse_error' 'gPCWQLFilter'
        $partial=$true
    }
    $row = @{
        id=$id; guid=$guid; display_name=if ($gpc['displayname']) {[string]$gpc['displayname']} else {[string]$gpc['name']}; domain_name=$domainDns;
        owner=@{name=$null; sid=$null}; description=$gpc['description']; creation_time=$gpc['whencreated']; modification_time=$gpc['whenchanged'];
        gpo_status=if ($null -eq $flags) { $null } else { @('AllSettingsEnabled','UserSettingsDisabled','ComputerSettingsDisabled','AllSettingsDisabled')[$flags -band 3] };
        computer=@{enabled=if ($null -ne $flags) {($flags -band 2) -eq 0} else {$null}; directory_version=if ($null -ne $version) {$version -band 65535} else {$null}; sysvol_version=$null; settings_count=0; extensions=@(); source_state=$sourceStates.report};
        user=@{enabled=if ($null -ne $flags) {($flags -band 1) -eq 0} else {$null}; directory_version=if ($null -ne $version) {($version -shr 16) -band 65535} else {$null}; sysvol_version=$null; settings_count=0; extensions=@(); source_state=$sourceStates.report};
        gpc=@{object_guid=$gpc['objectguid']; distinguished_name=$gpc['distinguishedname']; gpc_file_sys_path=$gpc['gpcfilesyspath'];
            flags=@{raw=$flags; computer_disabled=if ($null -ne $flags) {[bool]($flags -band 2)} else {$null}; user_disabled=if ($null -ne $flags) {[bool]($flags -band 1)} else {$null}};
            functionality_version=$gpc['gpcfunctionalityversion']; version_number=$version;
            machine_extension_names=@([regex]::Matches([string]$gpc['gpcmachineextensionnames'], '(?i)\{([0-9a-f-]{36})\}') | ForEach-Object {$_.Groups[1].Value.ToUpperInvariant()} | Select-Object -Unique);
            user_extension_names=@([regex]::Matches([string]$gpc['gpcuserextensionnames'], '(?i)\{([0-9a-f-]{36})\}') | ForEach-Object {$_.Groups[1].Value.ToUpperInvariant()} | Select-Object -Unique); wmi_filter_raw=$gpc['gpcwqlfilter']};
        gpt=@{path=$gpc['gpcfilesyspath']; probe_path=$null; status='not_evaluated'; ini_version=$null; detail=$null};
        wmi_filter_id=if ($wmiGuid) {'wmi-' + $wmiGuid.ToLowerInvariant()} else {$null}; link_ids=@(); setting_ids=@(); permission_ids=@();
        source_states=$sourceStates; unresolved_link_references=@(); collection_errors=@()
    }
    $reportFacts = $permissionFacts = $null
    try {
        # Return XML in memory; the bounded helper that writes a raw temp XML is
        # deliberately not used. Python's capture deadline kills the whole tree.
        $xmlText = Get-GPOReport -Guid ([Guid]$guid) -Domain $domainDns -Server $server -ReportType Xml -ErrorAction Stop
        $reportFacts = ConvertFrom-SLIGpoReportXml -XmlText $xmlText
        [xml]$document = $xmlText
        foreach ($side in @('computer','user')) {
            $normalized = ConvertTo-SLIGpoV2Settings -Xml $document -GpoId $id -GpoName $row.display_name -Side $side -Maximum 5000 -ObservedAt $script:ObservedAt
            foreach ($setting in @($normalized.rows)) {
                if (-not (Within-Budget $setting)) { break }
                $settings.Add($setting); $row.setting_ids += $setting.id
            }
            $row[$side].settings_count = @($normalized.rows).Count
            $row[$side].extensions = @($normalized.rows | Select-Object -ExpandProperty extension -Unique)
            $row[$side].source_state = State $normalized.source_status 'Get-GPOReport XML'
            if ($normalized.truncated) { $partial = $true }
        }
        $reportStatus=if ($row.computer.source_state.status -eq 'partial' -or $row.user.source_state.status -eq 'partial') {'partial'} elseif (
            $row.computer.source_state.status -eq 'missing_in_source' -and $row.user.source_state.status -eq 'missing_in_source') {'missing_in_source'} else {'observed'}
        $sourceStates.report = State $reportStatus 'Get-GPOReport XML'
        if ($reportStatus -ne 'observed') { $partial=$true }
        $reportsOk++
    } catch {
        $sourceStates.report = Failure 'gpo_report' $_.Exception
        $row.computer.source_state = $row.user.source_state = $sourceStates.report
    } finally { $xmlText = $document = $null }
    if ($overflow) { break }
    try {
        $entry = New-Entry ([string]$gpc['distinguishedname'])
        try {
            $entry.Options.SecurityMasks = [DirectoryServices.SecurityMasks]::Dacl -bor [DirectoryServices.SecurityMasks]::Owner
            $entry.RefreshCache(@('ntSecurityDescriptor'))
            $descriptor = $entry.ObjectSecurity
            $raw = [Security.AccessControl.RawSecurityDescriptor]::new($descriptor.GetSecurityDescriptorBinaryForm(), 0)
            if ($null -eq $raw.DiscretionaryAcl -or $null -eq $raw.Owner) { throw 'agent_gpo_acl_missing' }
            $row.owner.sid = $raw.Owner.Value
            try { $row.owner.name = $raw.Owner.Translate([Security.Principal.NTAccount]).Value } catch { }
            $aclPartial = $false
            for ($index=0; $index -lt $raw.DiscretionaryAcl.Count; $index++) {
                if ($acl.Count -ge 100000) { $aclPartial = $true; break }
                $ace = $raw.DiscretionaryAcl[$index]
                if ($ace -isnot [Security.AccessControl.QualifiedAce] -or $ace.IsCallback -or
                    [string]$ace.AceQualifier -notin @('AccessAllowed','AccessDenied')) { $aclPartial = $true; continue }
                $objectType = [Guid]::Empty
                if ($ace -is [Security.AccessControl.ObjectAce] -and
                    ($ace.ObjectAceFlags -band [Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent)) { $objectType=$ace.ObjectAceType }
                $propagation = 0
                if ($ace.AceFlags -band [Security.AccessControl.AceFlags]::InheritOnly) { $propagation = $propagation -bor 2 }
                if ($ace.AceFlags -band [Security.AccessControl.AceFlags]::NoPropagateInherit) { $propagation = $propagation -bor 1 }
                $aceRow=@{id=(Stable-Id 'ace' ($id + '|' + $index)); gpo_id=$id; ace_index=$index; trustee_sid=$ace.SecurityIdentifier.Value;
                    access_mask=[long]$ace.AccessMask; access_control_type=if ([string]$ace.AceQualifier -eq 'AccessAllowed') {'Allow'} else {'Deny'};
                    object_type=[string]$objectType; inherited=[bool]($ace.AceFlags -band [Security.AccessControl.AceFlags]::Inherited); propagation_flags=$propagation}
                if (-not (Within-Budget $aceRow)) { break }
                $acl.Add($aceRow)
            }
            $sourceStates.acl = State $(if ($aclPartial) {'partial'} else {'observed'}) 'DirectoryServices DACL'
            if ($aclPartial) { $partial=$true }
        } finally { $entry.Dispose() }
    } catch { $sourceStates.acl = Failure 'acl' $_.Exception }
    if ($overflow) { break }
    try {
        $permissionFacts = ConvertFrom-SLIGpoPermissionObjects -PermissionObjects @(Get-GPPermission -Guid ([Guid]$guid) -All -Domain $domainDns -Server $server -ErrorAction Stop)
        foreach ($permission in @($permissionFacts.permissions)) {
            $permissionId = Stable-Id 'perm' ($id + '|' + $permission.trustee_sid + '|' + $permission.permission)
            if ($permissionId -in $row.permission_ids) {
                $permissionId = Stable-Id 'perm' ($id + '|' + $permission.trustee_sid + '|' + $permission.permission + '|' + $permission.denied + '|' + $permission.inherited)
            }
            $permissionRow=@{id=$permissionId; gpo_id=$id; gpo_name=$row.display_name; trustee_name=$null; trustee_sid=$permission.trustee_sid;
                trustee_type=$permission.trustee_type; permission=$permission.permission; denied=$permission.denied; inherited=$permission.inherited;
                source_state=(State 'observed' 'Get-GPPermission -All')}
            if (-not (Within-Budget $permissionRow)) { break }
            $permissions.Add($permissionRow)
            $row.permission_ids += $permissionId
        }
        $sourceStates.permissions = State 'observed' 'Get-GPPermission -All'
        $permissionsOk++
    } catch { $sourceStates.permissions = Failure 'permissions' $_.Exception }
    if ($overflow) { break }
    try {
        $path = Get-ConfinedGptPath ([string]$gpc['gpcfilesyspath']) $guid
        $row.gpt.probe_path = Split-Path $path -Parent
        if ([IO.FileInfo]::new($path).Length -gt 65536) { throw 'agent_gpo_gpt_size_limit' }
        $ini = [IO.File]::ReadAllText($path)
        $match = [regex]::Match($ini, '(?im)^\s*Version\s*=\s*(\d+)\s*$')
        if (-not $match.Success -or [long]$match.Groups[1].Value -gt 4294967295) { throw 'agent_gpo_gpt_parse_error' }
        $iniVersion = [long]$match.Groups[1].Value
        $row.gpt.ini_version = $iniVersion
        $row.gpt.status = 'observed'
        $row.computer.sysvol_version = $iniVersion -band 65535
        $row.user.sysvol_version = ($iniVersion -shr 16) -band 65535
        $sourceStates.gpt = State 'observed' 'GPT.INI' $iniVersion
        $gptOk++
    } catch {
        $sourceStates.gpt = Failure 'gpt_ini' $_.Exception
        $row.gpt.status = $sourceStates.gpt.status
    } finally { $ini = $null }
    $description=if ($row.description -and ([string]$row.description).Length -gt 4096) {([string]$row.description).Substring(0,4096)} elseif ($row.description) {[string]$row.description} else {$null}
    $baseAttributes = [ordered]@{display_name=$row.display_name; sam_account_name=$null; distinguished_name=$null; enabled=$null;
        object_class='gpo'; created_utc=$row.creation_time; modified_utc=$row.modification_time; description=$description;
        gpo_security_filtering_effective_evaluated=$false; gpo_security_filtering_collected=$false}
    $attributes = if ($null -ne $reportFacts -and $null -ne $permissionFacts) {
        Merge-SLIGpoGovernanceAttributes -BaseAttributes $baseAttributes -ReportFacts $reportFacts -PermissionFacts $permissionFacts
    } else { $baseAttributes }
    $record=@{record_type='entity'; record_key=('ad:' + ([string]$policy.domain_sid).ToLowerInvariant() + ':' + ([string]$gpc['objectguid']).ToLowerInvariant());
        section='gpo_governance'; observed_at_utc=$script:ObservedAt; identity=@{kind='gpo'; domain_sid=$policy.domain_sid; object_guid=$gpc['objectguid']; object_sid=$null}; attributes=$attributes}
    if (-not (Within-Budget $record) -or -not (Within-Budget $row)) { break }
    $records.Add($record)
    $gpos.Add($row)
    $byDn[([string]$gpc['distinguishedname']).ToLowerInvariant()]=$row
}
foreach ($pair in @(@('gpo_reports',$reportsOk),@('sysvol_gpt',$gptOk),@('permissions',$permissionsOk))) {
    $rootStates[$pair[0]] = State $(if ($pair[1] -eq $gpos.Count) {'observed'} elseif ($pair[1] -gt 0) {'partial'} else {'failed'}) $pair[0]
    $rootStates[$pair[0]].coverage = @{requested=$gpos.Count; successful=$pair[1]; failed=($gpos.Count-$pair[1])}
}

try {
    $linksPartial=$false
    $scopeInputs = @(@{type='domain'; object=$domainRows[0]})
    foreach ($ou in @(Search $domainNc '(objectClass=organizationalUnit)' @('distinguishedname','name','canonicalname','gplink','gpoptions'))) {
        $scopeInputs += @{type='ou'; object=$ou}
    }
    foreach ($site in @(Search ('CN=Sites,' + $configNc) '(objectClass=site)' @('distinguishedname','name','canonicalname','gplink','gpoptions'))) {
        $scopeInputs += @{type='site'; object=$site}
    }
    foreach ($scopeInput in $scopeInputs) {
        $props=$scopeInput.object; $dn=[string]$props['distinguishedname']; $scopeId=Stable-Id 'scope' $dn.ToLowerInvariant()
        $direct=@(); $order=0; $scopePartial=$false
        $matches=[regex]::Matches([string]$props['gplink'], '(?is)\[(?<path>LDAP://.*?);(?<options>\d+)\]')
        if ((($matches | ForEach-Object {$_.Value}) -join '') -ne [string]$props['gplink']) { $scopePartial=$true; $linksPartial=$true; $partial=$true }
        foreach ($match in $matches) {
            $order++; $target=$match.Groups['path'].Value.Substring(7); $options=[int]$match.Groups['options'].Value
            $gpo=$byDn[$target.ToLowerInvariant()]
            if ($null -eq $gpo) {
                $unresolvedRow=@{scope_id=$scopeId; scope_dn=$dn; gpc_dn=$target; raw_options=$options; order=$order}
                if (-not (Within-Budget $unresolvedRow)) { break }
                $unresolved.Add($unresolvedRow)
                continue
            }
            $linkId=Stable-Id 'link' ($dn.ToLowerInvariant() + '|' + $gpo.id + '|' + $order)
            $linkRow=@{id=$linkId; gpo_id=$gpo.id; gpo_name=$gpo.display_name; scope_id=$scopeId; scope_name=$props['name'];
                scope_type=$scopeInput.type; scope_dn=$dn; enabled=(($options -band 1) -eq 0); enforced=(($options -band 2) -ne 0);
                order=$order; order_source='gPLink sequence'; raw_options=$options; source_state=(State 'observed' 'gPLink parser')}
            if (-not (Within-Budget $linkRow)) { break }
            $links.Add($linkRow)
            $direct += $linkId; $gpo.link_ids += $linkId
        }
        if ($overflow) { break }
        $scopeRow=@{id=$scopeId; name=$props['name']; scope_type=$scopeInput.type; distinguished_name=$dn; canonical_path=$props['canonicalname'];
            gpo_inheritance_blocked=if ($null -eq $props['gpoptions']) {$null} else {([int]$props['gpoptions'] -band 1) -ne 0};
            direct_link_ids=$direct; source_states=@{directory=(State 'observed' 'DirectoryServices'); links=(State $(if ($scopePartial) {'partial'} else {'observed'}) 'gPLink parser')}; collection_errors=@()}
        if (-not (Within-Budget $scopeRow)) { break }
        $scopes.Add($scopeRow)
    }
    $rootStates.links = State $(if ($linksPartial) {'partial'} else {'observed'}) 'gPLink/gPOptions inventory'
    $rootStates.links.coverage=@{scopes=$scopes.Count; links=$links.Count; unresolved=$unresolved.Count}
} catch { $rootStates.links = Failure 'links' $_.Exception }
foreach ($gpo in $gpos) { $gpo.source_states.links=$rootStates.links }

try {
    $wmiRows=@(Search ('CN=SOM,CN=WMIPolicy,CN=System,' + $domainNc) '(objectClass=msWMI-Som)' @(
        'name','distinguishedname','mswmi-id','mswmi-name','mswmi-parm1','mswmi-parm2','mswmi-author','mswmi-creationdate','mswmi-changedate'))
    $byWmi=@{}
    foreach ($item in $wmiRows) {
        $guid=Guid-Text $item['mswmi-id']
        if (-not $guid) { $guid=Guid-Text $item['name'] }
        if (-not $guid) { $partial=$true; continue }
        $wid='wmi-' + $guid.ToLowerInvariant(); $queries=@()
        foreach ($match in [regex]::Matches([string]$item['mswmi-parm2'], '(?is)WQL;(?<namespace>[^;]+);(?<query>.*?)(?=(?:;\d+;\d+;\d+;\d+;WQL;)|$)')) {
            $queries += @{namespace=$match.Groups['namespace'].Value.Trim(); query=$match.Groups['query'].Value.Trim().TrimEnd(';')}
        }
        $filter=@{id=$wid; guid=$guid; name=$item['mswmi-name']; distinguished_name=$item['distinguishedname']; description=$item['mswmi-parm1'];
            author=$item['mswmi-author']; creation_time=(Wmi-Date $item['mswmi-creationdate']); modification_time=(Wmi-Date $item['mswmi-changedate']);
            queries=$queries; used_by_gpo_ids=@(); source_state=(State $(if ($queries.Count) {'observed'} else {'parse_error'}) 'LDAP msWMI-Som'); collection_errors=@()}
        if (-not (Within-Budget $filter)) { break }
        $wmi.Add($filter); $byWmi[$wid]=$filter
    }
    $rootStates.wmi_filters=State 'observed' 'LDAP msWMI-Som'
    foreach ($gpo in $gpos) {
        if (-not $gpo.wmi_filter_id) { continue }
        $filter=$byWmi[$gpo.wmi_filter_id]
        if ($null -eq $filter) {
            $gpo.source_states.wmi_filter=State 'no_record' 'gPCWQLFilter'; $rootStates.wmi_filters.status='partial'; $partial=$true
        } else {
            $filter.used_by_gpo_ids += $gpo.id; $gpo.source_states.wmi_filter=$filter.source_state
            if ($filter.source_state.status -ne 'observed') { $rootStates.wmi_filters.status='partial'; $partial=$true }
        }
    }
} catch {
    $rootStates.wmi_filters=Failure 'wmi_filters' $_.Exception
    foreach ($gpo in $gpos) { if ($gpo.wmi_filter_id) { $gpo.source_states.wmi_filter=$rootStates.wmi_filters } }
}

$snapshot=@{schema_version='sli.ad-gpo.snapshot/1.0'; collector_version='sli-agent/gpo-snapshot/1'; demo=$false;
    started_at=$script:ObservedAt; completed_at=(Get-Date).ToUniversalTime().ToString('o'); observed_at=$script:ObservedAt;
    collection_status=if ($partial -or $overflow) {'partial'} else {'complete'};
    domain=@{sid=$policy.domain_sid; dns_name=$domainDns; dns_root=$domainDns; distinguished_name=$domainNc; query_dc=$server; query_server=$server; configuration_naming_context=$configNc};
    scope=@{domain=$domainDns; include_sites=$true; settings_mode='Full'; permissions=$true; sysvol=$true}; source_states=$rootStates;
    gpos=@($gpos.ToArray()); scopes=@($scopes.ToArray()); links=@($links.ToArray()); settings=@($settings.ToArray()); permissions=@($permissions.ToArray());
    acl=@($acl.ToArray()); wmi_filters=@($wmi.ToArray()); unresolved_links=@($unresolved.ToArray()); collection_errors=@($errors.ToArray())}
$result=@{domain=@{sid=$policy.domain_sid; dns_name=$domainDns; default_nc=$domainNc}; snapshot=$snapshot; records=@($records.ToArray()); overflow=$overflow}
$json=ConvertTo-Json -InputObject $result -Depth 100 -Compress
if ($overflow -or [Text.Encoding]::UTF8.GetByteCount($json) -gt [int]$policy.max_bytes) {
    foreach ($name in @('gpos','scopes','links','settings','permissions','acl','wmi_filters','unresolved_links')) { $snapshot[$name]=@() }
    $snapshot.collection_status='partial'; $result.records=@(); $result.overflow=$true
    $json=ConvertTo-Json -InputObject $result -Depth 100 -Compress
}
[Console]::Out.Write($json)

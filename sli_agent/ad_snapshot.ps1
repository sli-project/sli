# SPDX-License-Identifier: Apache-2.0
# Service credentials only. Policy is data on stdin, never executable code.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.DirectoryServices
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
$policy = [Console]::In.ReadToEnd() | ConvertFrom-Json
$auth = [DirectoryServices.AuthenticationTypes]::Secure -bor
    [DirectoryServices.AuthenticationTypes]::Signing -bor [DirectoryServices.AuthenticationTypes]::Sealing
$timeout = [TimeSpan]::FromSeconds([Math]::Min(30, [int]$policy.capture_seconds))
$objects = [Collections.Generic.List[object]]::new()
$surveys = [Collections.Generic.List[object]]::new()
$states = @{}
$limit = [int]$policy.max_objects
$clock = [Diagnostics.Stopwatch]::StartNew()
$attributes = @($policy.ldap_attributes)
$server = if (@($policy.dc).Count) { [string]$policy.dc[0] } else { [string]$policy.domain_dns }

function New-Entry([string]$Dc, [string]$Dn) {
    if ($Dc -notmatch '^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$') { throw 'agent_ad_endpoint_invalid' }
    $entry = [DirectoryServices.DirectoryEntry]::new(('LDAP://' + $Dc + '/' + $Dn))
    $entry.AuthenticationType = $auth
    return $entry
}

function Convert-Value([string]$Name, $Value) {
    if ($Name -eq 'msds-allowedtoactonbehalfofotheridentity') {
        # Only a digest and bounded allow-ACE trustees leave this process.
        # This is configured delegation evidence, not an effective ACL check.
        $result = @{ present = $true; status = 'parse_error'; sids = $null; descriptor_sha256 = $null }
        try {
            if ($Value -isnot [byte[]] -or $Value.Length -eq 0) { return $result }
            $sha = [Security.Cryptography.SHA256]::Create()
            try { $result.descriptor_sha256 = ([BitConverter]::ToString($sha.ComputeHash($Value))).Replace('-', '').ToLowerInvariant() }
            finally { $sha.Dispose() }
            $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new([byte[]]$Value, 0)
            if ($null -eq $descriptor.DiscretionaryAcl) { return $result }
            $sids = [Collections.Generic.List[string]]::new()
            $result.status = 'observed'
            foreach ($ace in $descriptor.DiscretionaryAcl) {
                # Denies, callback/object ACEs and inheritance need a full ACL
                # evaluation. Never report their omission as a complete list.
                if ($ace -isnot [Security.AccessControl.CommonAce] -or $ace.IsCallback -or
                    [string]$ace.AceQualifier -ne 'AccessAllowed' -or [int]$ace.AceFlags -ne 0) {
                    $result.status = 'partial'; continue
                }
                # RBCD checks the control-access right (or generic all).
                if (($ace.AccessMask -band 0x100) -eq 0 -and ($ace.AccessMask -band 0x10000000) -eq 0) { continue }
                if ($sids.Count -ge 256) { $result.status = 'partial'; break }
                $sids.Add($ace.SecurityIdentifier.Value)
            }
            $result.sids = @($sids | Sort-Object -Unique)
        } catch { $result.status = 'parse_error'; $result.sids = $null }
        return $result
    }
    if ($Name -eq 'objectguid') { return [Guid]::new([byte[]]$Value).ToString() }
    if ($Name -in @('objectsid', 'sidhistory')) { return [Security.Principal.SecurityIdentifier]::new([byte[]]$Value, 0).Value }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('o') }
    if ($Value -is [byte[]]) { return $null } # No arbitrary binary fields.
    if ($Value -is [string] -or $Value -is [ValueType]) { return $Value }
    # ADSI large integers on DirectoryEntry (SearchResult supplies Int64).
    if ($null -ne $Value.PSObject.Properties['HighPart']) {
        return ([long]$Value.HighPart -shl 32) -bor ([long]$Value.LowPart -band 0xffffffffL)
    }
    return $null
}

function Read-Properties($Properties) {
    $result = @{}
    foreach ($name in $Properties.PropertyNames) {
        $lower = ([string]$name).ToLowerInvariant()
        if ($lower -notin $attributes -and $lower -notmatch '^member;range=\d+-(\d+|\*)$') { continue }
        # Operational XML is parsed locally into bounded replication fields;
        # raw XML must never leave the PowerShell process.
        if ($lower -in @('msds-replattributemetadata', 'msds-ncreplinboundneighbors')) { continue }
        $values = @($Properties[$name] | ForEach-Object { Convert-Value $lower $_ })
        if ($lower -in @('member', 'memberof', 'serviceprincipalname', 'sidhistory', 'proxyaddresses',
                         'othertelephone', 'msds-allowedtodelegateto', 'objectclass', 'msds-hasmasterncs', 'msds-enabledfeature') -or
            $lower.StartsWith('member;range=')) { $result[$lower] = $values }
        elseif ($values.Count) { $result[$lower] = $values[0] }
    }
    return $result
}

function Search-Rows([string]$Dc, [string]$Base, [string]$Filter, [string[]]$Names, [bool]$BaseOnly = $false) {
    $entry = New-Entry $Dc $Base
    $searcher = [DirectoryServices.DirectorySearcher]::new($entry)
    $results = $null
    try {
        $searcher.Filter = $Filter
        $searcher.PageSize = 500
        $searcher.SizeLimit = $limit + 1
        $searcher.ServerTimeLimit = $timeout
        $searcher.ClientTimeout = $timeout
        $searcher.ReferralChasing = [DirectoryServices.ReferralChasingOption]::None
        if ($BaseOnly) { $searcher.SearchScope = [DirectoryServices.SearchScope]::Base }
        [void]$searcher.PropertiesToLoad.AddRange($Names)
        $results = $searcher.FindAll()
        foreach ($row in $results) { Read-Properties $row.Properties }
        if ($results.Count -gt $limit) { throw 'agent_ad_size_limit' }
    } finally {
        if ($null -ne $results) { $results.Dispose() }
        $searcher.Dispose()
        $entry.Dispose()
    }
}

function Complete-Members($Properties) {
    $ranges = @($Properties.Keys | Where-Object { $_ -like 'member;range=*' })
    if (-not $ranges.Count) { return }
    $entry = New-Entry $server ([string]$Properties.distinguishedname)
    try {
        $current = [string]$ranges[0]
        $count = @($Properties[$current]).Count
        while ($current -notmatch '-\*$') {
            $match = [regex]::Match($current, '^member;range=(\d+)-(\d+)$')
            if (-not $match.Success) { throw 'agent_ad_member_range_invalid' }
            $start = [int]$match.Groups[2].Value + 1
            $requested = 'member;range=' + $start + '-' + ($start + 1499)
            $entry.RefreshCache(@($requested))
            $returned = @($entry.Properties.PropertyNames | Where-Object { $_ -match ('^member;range=' + $start + '-(\d+|\*)$') })
            if ($returned.Count -ne 1) { throw 'agent_ad_member_range_invalid' }
            $current = [string]$returned[0]
            $values = @($entry.Properties[$current] | ForEach-Object { [string]$_ })
            $Properties[$current] = $values
            $count += $values.Count
            if ($count -gt $limit) { throw 'agent_ad_size_limit' }
        }
    } finally { $entry.Dispose() }
}

function Collect([string]$Base, [string]$Filter, [string]$Kind, [string]$Section) {
    try {
        foreach ($properties in @(Search-Rows $server $Base $Filter $attributes)) {
            if ($objects.Count -ge $limit) { throw 'agent_ad_size_limit' }
            if ($Kind -eq 'ad_group') {
                try { Complete-Members $properties } catch { $states['directory_group_graph'] = 'partial' }
            }
            $objects.Add(@{ kind = $Kind; properties = $properties })
        }
    } catch { $states[$Section] = 'partial' }
}

$root = New-Entry $server 'RootDSE'
try {
    $root.RefreshCache(@('defaultNamingContext', 'configurationNamingContext', 'schemaNamingContext', 'rootDomainNamingContext'))
    $domainNc = [string]$root.Properties['defaultNamingContext'][0]
    $configNc = [string]$root.Properties['configurationNamingContext'][0]
    $schemaNc = [string]$root.Properties['schemaNamingContext'][0]
    $forestNc = [string]$root.Properties['rootDomainNamingContext'][0]
} finally { $root.Dispose() }
$domainRows = @(Search-Rows $server $domainNc '(objectClass=domainDNS)' $attributes $true)
if ($domainRows.Count -ne 1 -or $domainRows[0].objectsid -ne $policy.domain_sid) { throw 'agent_ad_domain_mismatch' }
# Validate both domain identities, including a service bound to another forest.
$domainDns = ($domainNc -split ',' | ForEach-Object { $_ -replace '^DC=', '' }) -join '.'
if ($domainDns -ne $policy.domain_dns) { throw 'agent_ad_domain_mismatch' }
$domain = @{ sid = $domainRows[0].objectsid; dns_name = $domainDns; default_nc = $domainNc;
             configuration_nc = $configNc; schema_nc = $schemaNc; forest_nc = $forestNc }
$schemaAttributes = @{}
$metadataNames = @('mslaps-passwordexpirationtime', 'ms-mcs-admpwdexpirationtime', 'msds-allowedtoactonbehalfofotheridentity')
try {
    $schemaRows = @(Search-Rows $server $schemaNc '(&(objectClass=attributeSchema)(|(lDAPDisplayName=msLAPS-PasswordExpirationTime)(lDAPDisplayName=ms-Mcs-AdmPwdExpirationTime)(lDAPDisplayName=msDS-AllowedToActOnBehalfOfOtherIdentity)))' @('ldapdisplayname'))
    foreach ($name in $metadataNames) { $schemaAttributes[$name] = 'absent' }
    foreach ($row in $schemaRows) { $schemaAttributes[([string]$row.ldapdisplayname).ToLowerInvariant()] = 'present' }
} catch {
    foreach ($name in $metadataNames) { $schemaAttributes[$name] = 'not_evaluated' }
}
$objects.Add(@{ kind = 'domain'; properties = $domainRows[0] })
$bases = if (@($policy.search_bases).Count) { @($policy.search_bases) } else { @($domainNc) }
foreach ($base in $bases) {
    if ($base -ne $domainNc -and -not $base.EndsWith(',' + $domainNc, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'agent_ad_search_base_invalid'
    }
    Collect $base '(|(&(objectCategory=person)(objectClass=user))(objectClass=msDS-ManagedServiceAccount)(objectClass=msDS-GroupManagedServiceAccount))' 'ad_user' 'directory_accounts'
    Collect $base '(&(objectCategory=computer)(!(objectClass=msDS-ManagedServiceAccount))(!(objectClass=msDS-GroupManagedServiceAccount)))' 'ad_computer' 'directory_accounts'
}
# Group resolution is domain-wide even when accounts have a narrower search base.
Collect $domainNc '(objectCategory=group)' 'ad_group' 'directory_group_graph'
Collect $domainNc '(objectClass=foreignSecurityPrincipal)' 'security_principal' 'directory_group_graph'
Collect $domainNc '(objectClass=organizationalUnit)' 'security_principal' 'domain_posture'
Collect $domainNc '(objectClass=trustedDomain)' 'domain_trust' 'domain_posture'
# The default password policy lives on the domain object. Fine-grained PSOs
# have their own GUIDs and policy fields, read without managed password secrets.
Collect $domainNc '(objectClass=msDS-PasswordSettings)' 'password_policy' 'domain_posture'
Collect ('CN=Sites,' + $configNc) '(objectClass=site)' 'security_principal' 'domain_posture'
Collect ('CN=Sites,' + $configNc) '(objectClass=nTDSDSA)' 'domain_controller' 'domain_health'
Collect ('CN=Sites,' + $configNc) '(objectClass=nTDSConnection)' 'replication_link' 'domain_health'
# FSMO owners on domain, RID manager, infrastructure, schema and partitions.
$fsmo = @{}
foreach ($spec in @(@('pdc_emulator', $domainNc), @('rid_master', ('CN=RID Manager$,CN=System,' + $domainNc)),
                    @('infrastructure_master', ('CN=Infrastructure,' + $domainNc)), @('schema_master', $schemaNc),
                    @('domain_naming_master', ('CN=Partitions,' + $configNc)))) {
    try {
        $rows = @(Search-Rows $server $spec[1] '(objectClass=*)' @('fsmoroleowner') $true)
        $ownerDn = [string]$rows[0]['fsmoroleowner']
        $serverDn = $ownerDn.Substring($ownerDn.IndexOf(',') + 1)
        $owners = @(Search-Rows $server $serverDn '(objectClass=server)' @('dnshostname') $true)
        if ($owners.Count -ne 1 -or -not $owners[0].ContainsKey('dnshostname')) { throw 'agent_ad_fsmo_unresolved' }
        $fsmo[$spec[0]] = $owners[0]['dnshostname']
    } catch { $states['domain_posture'] = 'partial' }
}
$controllers = @(Search-Rows $server $domainNc '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))' $attributes)
$dcs = @(@($controllers | ForEach-Object { $_['dnshostname'] }) + @($policy.dc) | Where-Object { $_ } | Sort-Object -Unique)
if ($dcs.Count -gt 64) { throw 'agent_ad_dc_limit' }
$health = [Collections.Generic.List[object]]::new()
$replication = [Collections.Generic.List[object]]::new()
$dcMetadata = @{}
foreach ($settings in @($objects | Where-Object { $_.kind -eq 'domain_controller' })) {
    try {
        $p = $settings.properties
        $settingsDn = [string]$p.distinguishedname
        $parentDn = $settingsDn.Substring($settingsDn.IndexOf(',') + 1)
        $parents = @(Search-Rows $server $parentDn '(objectClass=server)' @('serverreference') $true)
        $computerDn = [string]$parents[0]['serverreference']
        $siteDn = ($settingsDn -split ',CN=Sites,', 2)[0]
        $dcMetadata[$computerDn.ToLowerInvariant()] = @{
            site_name = ($siteDn -split ',CN=')[-1]
            is_global_catalog = $p.ContainsKey('options') -and (([int]$p.options -band 1) -ne 0)
            is_read_only = if ($p.ContainsKey('msds-isrodc')) { [bool]$p['msds-isrodc'] } else { $null }
        }
    } catch { $states['domain_health'] = 'partial' }
}
function Read-HealthCheck([string]$Dc, [string]$Test) {
    if ($clock.Elapsed.TotalSeconds + 6 -ge [int]$policy.capture_seconds) { return 'not_collected' }
    $binary = Join-Path $env:SystemRoot 'System32\dcdiag.exe'
    if (-not [IO.File]::Exists($binary)) { return 'unavailable' }
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $binary
    $info.Arguments = '/s:' + $Dc + ' /test:' + $Test + ' /q'
    if ($Test -eq 'DNS') { $info.Arguments += ' /DnsBasic' }
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    try {
        if (-not $process.Start()) { return 'unavailable' }
        # Drain diagnostics without retaining text or an unbounded string.
        $stdout = $process.StandardOutput.BaseStream.CopyToAsync([IO.Stream]::Null)
        $stderr = $process.StandardError.BaseStream.CopyToAsync([IO.Stream]::Null)
        if (-not $process.WaitForExit(5000)) {
            & (Join-Path $env:SystemRoot 'System32\taskkill.exe') /PID $process.Id /T /F 2>$null | Out-Null
            return 'timeout'
        }
        if ($process.ExitCode -eq 0) { return 'passed' }
        return 'failed'
    } catch { return 'unavailable' }
    finally { $process.Dispose() }
}
foreach ($controller in $controllers) {
    $dc = [string]$controller.dnshostname
    if ($dc -notmatch '^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$') { $states['domain_health'] = 'partial'; continue }
    $checks = @{}
    foreach ($spec in @(@('advertising_state', 'Advertising'), @('connectivity_state', 'Connectivity'),
                        @('services_state', 'Services'), @('sysvol_state', 'SysVolCheck'), @('dns_state', 'DNS'))) {
        $checks[$spec[0]] = Read-HealthCheck $dc $spec[1]
    }
    $checks['netlogon_state'] = 'not_collected'
    if (@($checks.Values | Where-Object { $_ -ne 'passed' }).Count) { $states['domain_health'] = 'partial' }
    $metadata = $dcMetadata[([string]$controller.distinguishedname).ToLowerInvariant()]
    if ($null -eq $metadata) { $states['domain_health'] = 'partial'; $metadata = @{} }
    $metadata['operation_master_roles'] = @($fsmo.Keys | Where-Object { $fsmo[$_] -eq $dc } | Sort-Object)
    $health.Add(@{ properties = $controller; checks = $checks; metadata = $metadata })
    $dcObject = $null
    try {
        $context = [DirectoryServices.ActiveDirectory.DirectoryContext]::new(
            [DirectoryServices.ActiveDirectory.DirectoryContextType]::DirectoryServer, $dc)
        $dcObject = [DirectoryServices.ActiveDirectory.DomainController]::GetDomainController($context)
        foreach ($neighbor in $dcObject.GetAllReplicationNeighbors()) {
            if ($replication.Count -ge $limit) { throw 'agent_ad_size_limit' }
            $replication.Add(@{ source_dc = [string]$neighbor.SourceServer; destination_dc = $dc;
                naming_context = [string]$neighbor.PartitionName;
                last_replication_attempt_utc = $neighbor.LastReplicationAttempt.ToUniversalTime().ToString('o');
                last_replication_success_utc = $neighbor.LastReplicationSuccess.ToUniversalTime().ToString('o');
                consecutive_failure_count = [int]$neighbor.ConsecutiveFailureCount;
                last_replication_result = [int]$neighbor.LastReplicationResult })
        }
    } catch { $states['domain_health'] = 'partial' }
    finally { if ($null -ne $dcObject) { $dcObject.Dispose() } }
}
if ($null -ne $policy.expensive_flags.PSObject.Properties['exact_last_logon'] -and $policy.expensive_flags.exact_last_logon) {
    foreach ($dc in $dcs) {
        $values = @{}
        $status = 'complete'
        try {
            foreach ($row in @(Search-Rows $dc $domainNc '(|(&(objectCategory=person)(objectClass=user))(objectCategory=computer)(objectClass=msDS-ManagedServiceAccount)(objectClass=msDS-GroupManagedServiceAccount))' @('objectguid', 'lastlogon'))) {
                $values[$row['objectguid']] = $row['lastlogon']
            }
        } catch { $status = 'failed'; $values = @{} }
        $surveys.Add(@{ dc = $dc; status = $status; values = $values })
    }
}
# Optional adapters return explicit states. No external diagnostic text is sent.
$optional = @{}
foreach ($flag in @('dns', 'ad_site', 'inventory')) {
    $requested = $null -ne $policy.expensive_flags.PSObject.Properties[$flag] -and $policy.expensive_flags.$flag
    $optional[$flag] = @{ status = if ($requested) { 'not_evaluated' } else { 'not_collected' }; values = @{} }
}
if ($null -ne $policy.expensive_flags.PSObject.Properties['dns'] -and $policy.expensive_flags.dns) {
    $optional['dns'].status = 'observed'
    foreach ($computer in @($objects | Where-Object { $_.kind -eq 'ad_computer' })) {
        $p = $computer.properties
        $addresses = @()
        $status = 'not_evaluated'
        if ($p.ContainsKey('dnshostname') -and $p.dnshostname -match '^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$') {
            try {
                $task = [Net.Dns]::GetHostAddressesAsync([string]$p.dnshostname)
                if (-not $task.Wait(5000)) { throw 'agent_ad_dns_timeout' }
                $addresses = @($task.Result | ForEach-Object { $_.ToString() } | Sort-Object -Unique)
                $status = if ($addresses.Count) { 'observed' } else { 'no_record' }
            } catch { $status = 'failed'; $optional['dns'].status = 'partial' }
        }
        $optional['dns'].values[$p.objectguid] = @{ status = $status; value = $addresses }
    }
}
if ($null -ne $policy.expensive_flags.PSObject.Properties['ad_site'] -and $policy.expensive_flags.ad_site) {
    try {
        $attributes += 'siteobject'
        $optional['ad_site'].subnets = @(Search-Rows $server ('CN=Subnets,CN=Sites,' + $configNc) '(objectClass=subnet)' @('name', 'siteobject'))
        $optional['ad_site'].status = 'observed'
    } catch { $optional['ad_site'].status = 'failed' }
}
if ($null -ne $policy.expensive_flags.PSObject.Properties['inventory'] -and $policy.expensive_flags.inventory) {
    Add-Type -AssemblyName System.Management
    $optional['inventory'].status = 'observed'
    foreach ($computer in @($objects | Where-Object { $_.kind -eq 'ad_computer' })) {
        $p = $computer.properties
        $disks = @()
        $status = 'not_evaluated'
        if ($p.ContainsKey('dnshostname') -and $p.dnshostname -match '^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$') {
            $searcher = $null
            $results = $null
            try {
                $options = [Management.ConnectionOptions]::new()
                $options.Authentication = [Management.AuthenticationLevel]::PacketPrivacy
                $options.Timeout = [TimeSpan]::FromSeconds(5)
                $scope = [Management.ManagementScope]::new(('\\' + $p.dnshostname + '\root\cimv2'), $options)
                $query = [Management.ObjectQuery]::new('SELECT DeviceID,Size,FreeSpace FROM Win32_LogicalDisk WHERE DriveType=3')
                $enumeration = [Management.EnumerationOptions]::new()
                $enumeration.Timeout = [TimeSpan]::FromSeconds(5)
                $searcher = [Management.ManagementObjectSearcher]::new($scope, $query, $enumeration)
                $results = $searcher.Get()
                $disks = @($results | Select-Object -First 64 | ForEach-Object {
                    @{ device_id = [string]$_.DeviceID; size = [long]$_.Size; free_space = [long]$_.FreeSpace }
                })
                $status = 'observed'
            } catch { $status = 'failed'; $optional['inventory'].status = 'partial' }
            finally {
                if ($null -ne $results) { $results.Dispose() }
                if ($null -ne $searcher) { $searcher.Dispose() }
            }
        }
        $optional['inventory'].values[$p.objectguid] = @{ status = $status; value = $disks }
    }
}
@{ domain = $domain; objects = @($objects.ToArray()); states = $states; surveys = @($surveys.ToArray());
   fsmo = $fsmo; optional = $optional; query_dc = $server; health = @($health.ToArray());
   replication = @($replication.ToArray()); schema_attributes = $schemaAttributes } | ConvertTo-Json -Depth 12 -Compress

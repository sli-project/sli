#requires -Version 5.1

<#
.SYNOPSIS
    Read-only collector for the AD computers and servers evidence-first HTML prototype.

.DESCRIPTION
    Reads computer objects from Active Directory, optionally resolves DNS A/AAAA,
    optionally maps IPv4 addresses to AD Sites, and optionally calculates the maximum
    non-replicated lastLogon value across all discovered domain controllers.

    The script does not change AD, DNS, computers, groups, permissions, registry,
    services, firewall rules, event logs, or any remote state. It only reads sources
    and writes one local JSON snapshot.

    Missing, not_collected, not_evaluated, partial, failed, access_denied and no_record
    are emitted as distinct source states. A failure in an optional source does not discard the
    successfully collected AD inventory.
#>

[CmdletBinding()]
param(
    [string]$Server,
    [string]$SearchBase,
    [string]$OutputPath,
    [switch]$SkipDns,
    [switch]$CollectAdSite,
    [switch]$CollectExactLastLogon
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$SchemaVersion = '2.0'
$CollectorVersion = 'evidence-collector-1.0'
$StartedAt = (Get-Date).ToUniversalTime()
$GlobalErrors = New-Object System.Collections.Generic.List[object]
$DnsResolverAvailable = $null -ne (Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue)

function Convert-ToIsoDate {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return $null }
    try {
        return ([datetime]$Value).ToUniversalTime().ToString('o')
    }
    catch {
        return $null
    }
}

function Convert-FileTimeToIsoDate {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return $null }
    try {
        $FileTime = [int64]$Value
        if ($FileTime -le 0) { return $null }
        return [datetime]::FromFileTimeUtc($FileTime).ToString('o')
    }
    catch {
        return $null
    }
}

function New-SourceState {
    param(
        [Parameter(Mandatory = $true)][string]$Status,
        [Parameter(Mandatory = $true)][string]$Source,
        [AllowNull()][object]$Value = $null,
        [AllowNull()][datetime]$ObservedAt = $null,
        [AllowNull()][object]$ErrorObject = $null,
        [AllowNull()][object]$Details = $null
    )

    [pscustomobject]@{
        status      = $Status
        source      = $Source
        value       = $Value
        observed_at = if ($null -ne $ObservedAt) { $ObservedAt.ToUniversalTime().ToString('o') } else { $null }
        error       = $ErrorObject
        details     = $Details
    }
}

function New-CollectionError {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Code,
        [Parameter(Mandatory = $true)][string]$Message,
        [AllowNull()][string]$Target = $null,
        [ValidateSet('failed', 'access_denied', 'parse_error')][string]$Status = 'failed'
    )

    [pscustomobject]@{
        source  = $Source
        status  = $Status
        code    = $Code
        message = $Message
        target  = $Target
    }
}

function Get-ErrorCode {
    param([Parameter(Mandatory = $true)][System.Management.Automation.ErrorRecord]$ErrorRecord)

    if ($ErrorRecord.FullyQualifiedErrorId) {
        return [string]$ErrorRecord.FullyQualifiedErrorId
    }
    if ($ErrorRecord.Exception -and $ErrorRecord.Exception.GetType()) {
        return [string]$ErrorRecord.Exception.GetType().FullName
    }
    return 'unknown_error'
}

function Get-ErrorStatus {
    param([Parameter(Mandatory = $true)][System.Management.Automation.ErrorRecord]$ErrorRecord)

    $Text = (($ErrorRecord.FullyQualifiedErrorId, $ErrorRecord.Exception.Message) -join ' ').ToLowerInvariant()
    if ($Text -match 'access is denied|access denied|unauthorized|insufficient access|insufficient rights|permission') {
        return 'access_denied'
    }
    if ($Text -match 'parse|format exception|invalid format|conversion') {
        return 'parse_error'
    }
    return 'failed'
}

function Test-IsDnsNoRecordError {
    param([Parameter(Mandatory = $true)][System.Management.Automation.ErrorRecord]$ErrorRecord)

    $Text = (($ErrorRecord.FullyQualifiedErrorId, $ErrorRecord.Exception.Message) -join ' ').ToLowerInvariant()
    return (
        $Text -match 'dns_error_rcode_name_error' -or
        $Text -match 'dns name does not exist' -or
        $Text -match 'non-existent domain' -or
        $Text -match 'no records' -or
        $Text -match 'name error'
    )
}

function Get-AggregateErrorStatus {
    param([AllowNull()][object[]]$Errors)

    $Statuses = @($Errors | ForEach-Object { [string]$_.status } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
    if ($Statuses.Count -eq 1 -and $Statuses[0] -in @('access_denied', 'parse_error')) {
        return $Statuses[0]
    }
    return 'failed'
}

function Resolve-ComputerAddresses {
    param([AllowNull()][string]$DnsHostName)

    if ($SkipDns) {
        return [pscustomobject]@{
            State = New-SourceState -Status 'not_collected' -Source 'dns'
            IPv4  = @()
            IPv6  = @()
        }
    }

    if ([string]::IsNullOrWhiteSpace($DnsHostName)) {
        return [pscustomobject]@{
            State = New-SourceState -Status 'missing_in_source' -Source 'dns' -ObservedAt (Get-Date) -Details ([pscustomobject]@{ missing_field = 'DNSHostName' })
            IPv4  = @()
            IPv6  = @()
        }
    }

    if (-not $DnsResolverAvailable) {
        $ResolverError = New-CollectionError -Source 'dns' -Code 'resolve_dns_name_not_available' -Message 'Resolve-DnsName cmdlet is not available on this host.' -Target $DnsHostName
        return [pscustomobject]@{
            State = New-SourceState -Status 'failed' -Source 'dns' -ObservedAt (Get-Date) -ErrorObject @($ResolverError)
            IPv4  = @()
            IPv6  = @()
        }
    }

    $ObservedAt = Get-Date
    $IPv4 = New-Object System.Collections.Generic.List[string]
    $IPv6 = New-Object System.Collections.Generic.List[string]
    $Errors = New-Object System.Collections.Generic.List[object]
    $NoRecordFamilies = New-Object System.Collections.Generic.List[string]

    foreach ($QueryType in @('A', 'AAAA')) {
        try {
            $Records = @(Resolve-DnsName -Name $DnsHostName -Type $QueryType -DnsOnly -QuickTimeout -ErrorAction Stop)
            foreach ($Record in $Records) {
                $IpProperty = $Record.PSObject.Properties['IPAddress']
                if ($null -eq $IpProperty -or [string]::IsNullOrWhiteSpace([string]$IpProperty.Value)) { continue }
                if ($QueryType -eq 'A') {
                    [void]$IPv4.Add([string]$IpProperty.Value)
                }
                elseif ($QueryType -eq 'AAAA') {
                    [void]$IPv6.Add([string]$IpProperty.Value)
                }
            }
            if ($Records.Count -eq 0) {
                [void]$NoRecordFamilies.Add($QueryType)
            }
        }
        catch {
            if (Test-IsDnsNoRecordError -ErrorRecord $_) {
                [void]$NoRecordFamilies.Add($QueryType)
            }
            else {
                [void]$Errors.Add((New-CollectionError -Source 'dns' -Code (Get-ErrorCode -ErrorRecord $_) -Message $_.Exception.Message -Target $DnsHostName -Status (Get-ErrorStatus -ErrorRecord $_)))
            }
        }
    }

    $IPv4Unique = @($IPv4 | Sort-Object -Unique)
    $IPv6Unique = @($IPv6 | Sort-Object -Unique)
    $Value = [pscustomobject]@{ ipv4 = $IPv4Unique; ipv6 = $IPv6Unique }
    $Details = [pscustomobject]@{
        queried_families  = @('A', 'AAAA')
        no_record_families = @($NoRecordFamilies)
        error_count       = $Errors.Count
    }

    if (($IPv4Unique.Count + $IPv6Unique.Count) -gt 0 -and $Errors.Count -eq 0) {
        $State = New-SourceState -Status 'observed' -Source 'dns' -Value $Value -ObservedAt $ObservedAt -Details $Details
    }
    elseif (($IPv4Unique.Count + $IPv6Unique.Count) -gt 0) {
        $State = New-SourceState -Status 'partial' -Source 'dns' -Value $Value -ObservedAt $ObservedAt -ErrorObject @($Errors) -Details $Details
    }
    elseif ($Errors.Count -gt 0) {
        $ErrorStatus = Get-AggregateErrorStatus -Errors @($Errors)
        $State = New-SourceState -Status $ErrorStatus -Source 'dns' -ObservedAt $ObservedAt -ErrorObject @($Errors) -Details $Details
    }
    else {
        $State = New-SourceState -Status 'no_record' -Source 'dns' -Value $Value -ObservedAt $ObservedAt -Details $Details
    }

    [pscustomobject]@{
        State = $State
        IPv4  = $IPv4Unique
        IPv6  = $IPv6Unique
    }
}

function Convert-IPv4ToUInt32 {
    param([Parameter(Mandatory = $true)][string]$Address)

    $Parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($Address, [ref]$Parsed)) { return $null }
    $Bytes = $Parsed.GetAddressBytes()
    if ($Bytes.Count -ne 4) { return $null }
    [array]::Reverse($Bytes)
    return [BitConverter]::ToUInt32($Bytes, 0)
}

function Get-IPv4SubnetMatch {
    param(
        [Parameter(Mandatory = $true)][string]$Address,
        [Parameter(Mandatory = $true)][object[]]$SubnetRecords
    )

    $AddressValue = Convert-IPv4ToUInt32 -Address $Address
    if ($null -eq $AddressValue) { return $null }

    $CandidateMatches = New-Object System.Collections.Generic.List[object]
    foreach ($Subnet in $SubnetRecords) {
        $Name = [string]$Subnet.Name
        $CidrMatch = [regex]::Match($Name, '^([^/]+)/([0-9]{1,2})$')
        if (-not $CidrMatch.Success) { continue }
        $NetworkAddress = $CidrMatch.Groups[1].Value
        $PrefixLength = [int]$CidrMatch.Groups[2].Value
        if ($PrefixLength -lt 0 -or $PrefixLength -gt 32) { continue }
        $NetworkValue = Convert-IPv4ToUInt32 -Address $NetworkAddress
        if ($null -eq $NetworkValue) { continue }

        if ($PrefixLength -eq 0) {
            [uint32]$Mask = 0
        }
        else {
            [uint32]$Mask = [uint32]([math]::Pow(2, 32) - [math]::Pow(2, (32 - $PrefixLength)))
        }

        $SiteValue = [string]$Subnet.Site
        if ($SiteValue -match '^CN=([^,]+),') {
            $SiteValue = $Matches[1]
        }

        if (($AddressValue -band $Mask) -eq ($NetworkValue -band $Mask)) {
            [void]$CandidateMatches.Add([pscustomobject]@{
                PrefixLength = $PrefixLength
                Subnet       = $Name
                Site         = $SiteValue
            })
        }
    }

    return $CandidateMatches | Sort-Object PrefixLength -Descending | Select-Object -First 1
}

function Get-OuPath {
    param(
        [AllowNull()][string]$CanonicalName,
        [AllowNull()][string]$DistinguishedName
    )

    if (-not [string]::IsNullOrWhiteSpace($CanonicalName)) {
        $Segments = @($CanonicalName -split '/')
        if ($Segments.Count -gt 2) {
            return (@($Segments[1..($Segments.Count - 2)]) -join ' / ')
        }
        if ($Segments.Count -eq 2) { return 'Корень домена' }
    }

    if (-not [string]::IsNullOrWhiteSpace($DistinguishedName)) {
        $OuParts = @($DistinguishedName -split '(?<!\\),' | Where-Object { $_ -match '(?i)^OU=' } | ForEach-Object { $_.Substring(3) -replace '\\,', ',' })
        if ($OuParts.Count -gt 0) {
            [array]::Reverse($OuParts)
            return ($OuParts -join ' / ')
        }
        return 'Корень домена'
    }

    return $null
}

function Get-OsBuild {
    param([AllowNull()][string]$OperatingSystemVersion)

    if ([string]::IsNullOrWhiteSpace($OperatingSystemVersion)) { return $null }
    if ($OperatingSystemVersion -match '\(([0-9]+)\)') { return $Matches[1] }
    if ($OperatingSystemVersion -match '^[0-9]+\.[0-9]+\.([0-9]+)') { return $Matches[1] }
    return $null
}

function Get-OsFamily {
    param([AllowNull()][string]$OperatingSystem)

    $Value = ([string]$OperatingSystem).ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    if ($Value -match 'server\s+2025') { return 'Windows Server 2025' }
    if ($Value -match 'server\s+2022') { return 'Windows Server 2022' }
    if ($Value -match 'server\s+2019') { return 'Windows Server 2019' }
    if ($Value -match 'server\s+2016') { return 'Windows Server 2016' }
    if ($Value -match 'server\s+2012') { return 'Windows Server 2012' }
    if ($Value -match 'windows\s+11') { return 'Windows 11' }
    if ($Value -match 'windows\s+10') { return 'Windows 10' }
    if ($Value -match 'linux|ubuntu|rocky|red hat|debian|suse') { return 'Linux' }
    if ($Value -match 'mac\s*os|macos') { return 'macOS' }
    return [string]$OperatingSystem
}

function Get-DeviceClassification {
    param(
        [Parameter(Mandatory = $true)][object]$Computer,
        [Parameter(Mandatory = $true)][System.Collections.Generic.HashSet[string]]$DomainControllerNames
    )

    $NameLower = ([string]$Computer.Name).ToLowerInvariant()
    $OperatingSystem = [string]$Computer.OperatingSystem
    $SpnText = (@($Computer.ServicePrincipalName) -join ' ')

    if ($DomainControllerNames.Contains($NameLower)) {
        return [pscustomobject]@{
            status  = 'observed'
            value   = 'server'
            rule_id = 'device-classification/dc-list-v1'
            evidence = @('Computer name is present in Get-ADDomainController output')
        }
    }
    if ($OperatingSystem -match '(?i)\bserver\b') {
        return [pscustomobject]@{
            status  = 'observed'
            value   = 'server'
            rule_id = 'device-classification/os-server-v1'
            evidence = @("OperatingSystem contains Server: $OperatingSystem")
        }
    }
    if ($OperatingSystem -match '(?i)windows\s+(11|10|8(?:\.1)?|7|vista|xp)\b|mac\s*os') {
        return [pscustomobject]@{
            status  = 'observed'
            value   = 'workstation'
            rule_id = 'device-classification/client-os-v1'
            evidence = @("OperatingSystem matches a client OS rule: $OperatingSystem")
        }
    }
    if ($SpnText -match '(?i)(LDAP|GC)/') {
        return [pscustomobject]@{
            status  = 'partial'
            value   = 'unknown'
            rule_id = 'device-classification/directory-spn-signal-v1'
            evidence = @('LDAP or GC SPN was observed, but this signal alone is not sufficient to classify the object as a server')
        }
    }

    return [pscustomobject]@{
        status  = 'partial'
        value   = 'unknown'
        rule_id = 'device-classification/1'
        evidence = @('No explicit type and no unambiguous OS or DC-list rule matched')
    }
}

function Get-ExactLastLogonMap {
    param(
        [Parameter(Mandatory = $true)][object[]]$DomainControllers,
        [AllowNull()][string]$SearchBase
    )

    $Result = @{}
    $FailedDcs = New-Object System.Collections.Generic.List[string]
    $SuccessfulDcs = New-Object System.Collections.Generic.List[string]
    $Errors = New-Object System.Collections.Generic.List[object]

    foreach ($Dc in $DomainControllers) {
        $DcHost = [string]$Dc.HostName
        try {
            $Parameters = @{
                Server     = $DcHost
                Filter     = '*'
                Properties = @('lastLogon', 'ObjectGUID')
            }
            if (-not [string]::IsNullOrWhiteSpace($SearchBase)) {
                $Parameters.SearchBase = $SearchBase
            }

            $Rows = @(Get-ADComputer @Parameters)
            foreach ($Row in $Rows) {
                $Key = ([string]$Row.ObjectGUID).ToLowerInvariant()
                if (-not $Result.ContainsKey($Key)) {
                    $Result[$Key] = [pscustomobject]@{
                        MaxFileTime = [int64]0
                        MaxDc       = $null
                    }
                }
                $FileTime = [int64]$Row.lastLogon
                if ($FileTime -gt $Result[$Key].MaxFileTime) {
                    $Result[$Key].MaxFileTime = $FileTime
                    $Result[$Key].MaxDc = $DcHost
                }
            }
            [void]$SuccessfulDcs.Add($DcHost)
        }
        catch {
            [void]$FailedDcs.Add($DcHost)
            $ExactError = New-CollectionError -Source 'exact_last_logon' -Code (Get-ErrorCode -ErrorRecord $_) -Message $_.Exception.Message -Target $DcHost -Status (Get-ErrorStatus -ErrorRecord $_)
            [void]$Errors.Add($ExactError)
            [void]$GlobalErrors.Add($ExactError)
        }
    }

    [pscustomobject]@{
        Values        = $Result
        SuccessfulDcs = @($SuccessfulDcs)
        FailedDcs     = @($FailedDcs)
        Errors        = @($Errors)
        TotalDc       = $DomainControllers.Count
    }
}

try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    throw "ActiveDirectory module could not be loaded: $($_.Exception.Message)"
}

if ([string]::IsNullOrWhiteSpace($Server)) {
    $Server = (Get-ADDomainController -Discover -Writable -ErrorAction Stop).HostName
}
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $PWD ("ad-inventory-{0:yyyyMMdd-HHmmss}.json" -f (Get-Date))
}

$Domain = Get-ADDomain -Server $Server -ErrorAction Stop
$DomainControllers = @(Get-ADDomainController -Filter * -Server $Server -ErrorAction Stop)
$DomainControllerNames = New-Object -TypeName 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)
foreach ($Dc in $DomainControllers) {
    if ($Dc.Name) { [void]$DomainControllerNames.Add(([string]$Dc.Name).ToLowerInvariant()) }
    if ($Dc.HostName) {
        $ShortName = ([string]$Dc.HostName).Split('.')[0]
        [void]$DomainControllerNames.Add($ShortName.ToLowerInvariant())
    }
}

$Properties = @(
    'Enabled',
    'DNSHostName',
    'OperatingSystem',
    'OperatingSystemVersion',
    'OperatingSystemServicePack',
    'LastLogonDate',
    'lastLogonTimestamp',
    'PasswordLastSet',
    'whenCreated',
    'whenChanged',
    'Description',
    'Location',
    'ManagedBy',
    'CanonicalName',
    'DistinguishedName',
    'ServicePrincipalName',
    'userAccountControl',
    'TrustedForDelegation',
    'TrustedToAuthForDelegation',
    'ObjectGUID',
    'SID'
)

$QueryParameters = @{
    Server     = $Server
    Filter     = '*'
    Properties = $Properties
}
if (-not [string]::IsNullOrWhiteSpace($SearchBase)) {
    $QueryParameters.SearchBase = $SearchBase
}

try {
    $Computers = @(Get-ADComputer @QueryParameters)
}
catch {
    $Failure = New-CollectionError -Source 'ad' -Code (Get-ErrorCode -ErrorRecord $_) -Message $_.Exception.Message -Target $Server -Status (Get-ErrorStatus -ErrorRecord $_)
    [void]$GlobalErrors.Add($Failure)
    $FailedSnapshot = [ordered]@{
        schema_version = $SchemaVersion
        metadata = [ordered]@{
            snapshot_id      = [guid]::NewGuid().ToString()
            label            = 'AD inventory failed snapshot'
            started_at       = $StartedAt.ToString('o')
            completed_at     = (Get-Date).ToUniversalTime().ToString('o')
            query_dc         = $Server
            domain           = $Domain.DNSRoot
            search_base      = $SearchBase
            collection_status = 'failed'
            object_count     = 0
            collector_version = $CollectorVersion
            sources          = @([pscustomobject]@{ name = 'ad'; status = [string]$Failure.status; requested = $true })
            errors           = @($GlobalErrors)
        }
        objects = @()
    }
    $ParentDirectory = Split-Path -Parent $OutputPath
    if ($ParentDirectory -and -not (Test-Path -LiteralPath $ParentDirectory)) {
        New-Item -ItemType Directory -Path $ParentDirectory -Force | Out-Null
    }
    $FailedSnapshot | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
    throw "AD computer query failed. A failed snapshot was saved to $OutputPath"
}

$SubnetRecords = @()
$SiteStageError = $null
if ($CollectAdSite) {
    try {
        $SubnetRecords = @(Get-ADReplicationSubnet -Filter * -Server $Server -Properties Site -ErrorAction Stop)
    }
    catch {
        $SiteStageError = New-CollectionError -Source 'site' -Code (Get-ErrorCode -ErrorRecord $_) -Message $_.Exception.Message -Target $Server -Status (Get-ErrorStatus -ErrorRecord $_)
        [void]$GlobalErrors.Add($SiteStageError)
    }
}

$ExactData = $null
if ($CollectExactLastLogon) {
    $ExactData = Get-ExactLastLogonMap -DomainControllers $DomainControllers -SearchBase $SearchBase
}

$Objects = New-Object System.Collections.Generic.List[object]
$DnsStatusCounts = @{}
$OsStatusCounts = @{}
$SiteStatusCounts = @{}
$LastLogonTimestampStatusCounts = @{}
$ExactStatusCounts = @{}

foreach ($Computer in $Computers) {
    $CollectedAt = Get-Date
    $ObjectErrors = New-Object System.Collections.Generic.List[object]
    $Classification = Get-DeviceClassification -Computer $Computer -DomainControllerNames $DomainControllerNames
    $RoleHint = if ([string]$Classification.rule_id -eq 'device-classification/dc-list-v1') {
        'Контроллер домена'
    }
    elseif ([string]$Classification.value -eq 'server') {
        'Сервер'
    }
    elseif ([string]$Classification.value -eq 'workstation') {
        'Рабочая станция'
    }
    else {
        $null
    }
    $RoleEvidence = (@($Classification.evidence) -join '; ')

    $DnsResult = Resolve-ComputerAddresses -DnsHostName ([string]$Computer.DNSHostName)
    $DnsStatus = [string]$DnsResult.State.status
    if (-not $DnsStatusCounts.ContainsKey($DnsStatus)) { $DnsStatusCounts[$DnsStatus] = 0 }
    $DnsStatusCounts[$DnsStatus]++
    if ($DnsResult.State.error) {
        foreach ($DnsError in @($DnsResult.State.error)) { [void]$ObjectErrors.Add($DnsError) }
    }

    if (-not $CollectAdSite) {
        $SiteState = New-SourceState -Status 'not_collected' -Source 'site'
        $AdSite = $null
    }
    elseif ($null -ne $SiteStageError) {
        $SiteState = New-SourceState -Status ([string]$SiteStageError.status) -Source 'site' -ObservedAt $CollectedAt -ErrorObject $SiteStageError
        $AdSite = $null
        [void]$ObjectErrors.Add($SiteStageError)
    }
    elseif (@($DnsResult.IPv4).Count -eq 0) {
        $SiteState = New-SourceState -Status 'not_evaluated' -Source 'site' -ObservedAt $CollectedAt -Details ([pscustomobject]@{
            reason            = 'no_ipv4_for_site_mapping'
            dependency        = 'dns'
            dependency_status = [string]$DnsResult.State.status
        })
        $AdSite = $null
    }
    else {
        $BestMatch = $null
        foreach ($Address in @($DnsResult.IPv4)) {
            $Match = Get-IPv4SubnetMatch -Address $Address -SubnetRecords $SubnetRecords
            if ($null -ne $Match -and ($null -eq $BestMatch -or $Match.PrefixLength -gt $BestMatch.PrefixLength)) {
                $BestMatch = $Match
            }
        }
        if ($null -ne $BestMatch -and -not [string]::IsNullOrWhiteSpace([string]$BestMatch.Site)) {
            $AdSite = [string]$BestMatch.Site
            $SiteState = New-SourceState -Status 'observed' -Source 'site' -Value $AdSite -ObservedAt $CollectedAt -Details ([pscustomobject]@{ matched_subnet = $BestMatch.Subnet; prefix_length = $BestMatch.PrefixLength })
        }
        else {
            $AdSite = $null
            $SiteState = New-SourceState -Status 'no_record' -Source 'site' -ObservedAt $CollectedAt -Details ([pscustomobject]@{ reason = 'no_matching_ad_subnet'; ipv4 = @($DnsResult.IPv4) })
        }
    }
    $SiteStatus = [string]$SiteState.status
    if (-not $SiteStatusCounts.ContainsKey($SiteStatus)) { $SiteStatusCounts[$SiteStatus] = 0 }
    $SiteStatusCounts[$SiteStatus]++

    $ObjectKey = ([string]$Computer.ObjectGUID).ToLowerInvariant()
    if (-not $CollectExactLastLogon) {
        $ExactLastLogon = $null
        $ExactState = New-SourceState -Status 'not_collected' -Source 'exact_last_logon'
    }
    elseif ($ExactData.SuccessfulDcs.Count -eq 0) {
        $ExactLastLogon = $null
        $ExactFailureStatus = Get-AggregateErrorStatus -Errors @($ExactData.Errors)
        $ExactState = New-SourceState -Status $ExactFailureStatus -Source 'exact_last_logon' -ObservedAt $CollectedAt -ErrorObject @($ExactData.Errors) -Details ([pscustomobject]@{ queried_dc = 0; total_dc = $ExactData.TotalDc; failed_dc = @($ExactData.FailedDcs) })
        foreach ($ExactError in @($ExactData.Errors)) { [void]$ObjectErrors.Add($ExactError) }
    }
    else {
        $ExactEntry = $ExactData.Values[$ObjectKey]
        $FileTime = if ($null -ne $ExactEntry) { [int64]$ExactEntry.MaxFileTime } else { [int64]0 }
        $ExactLastLogon = Convert-FileTimeToIsoDate -Value $FileTime
        $Details = [pscustomobject]@{
            queried_dc = $ExactData.SuccessfulDcs.Count
            total_dc   = $ExactData.TotalDc
            failed_dc  = @($ExactData.FailedDcs)
            max_dc     = if ($null -ne $ExactEntry) { $ExactEntry.MaxDc } else { $null }
        }
        if ($ExactData.SuccessfulDcs.Count -lt $ExactData.TotalDc) {
            $ExactState = New-SourceState -Status 'partial' -Source 'exact_last_logon' -Value $ExactLastLogon -ObservedAt $CollectedAt -ErrorObject @($ExactData.Errors) -Details $Details
        }
        elseif ($null -ne $ExactLastLogon) {
            $ExactState = New-SourceState -Status 'observed' -Source 'exact_last_logon' -Value $ExactLastLogon -ObservedAt $CollectedAt -Details $Details
        }
        else {
            $ExactState = New-SourceState -Status 'missing_in_source' -Source 'exact_last_logon' -ObservedAt $CollectedAt -Details $Details
        }
    }
    $ExactStatus = [string]$ExactState.status
    if (-not $ExactStatusCounts.ContainsKey($ExactStatus)) { $ExactStatusCounts[$ExactStatus] = 0 }
    $ExactStatusCounts[$ExactStatus]++

    $LastLogonTimestamp = Convert-FileTimeToIsoDate -Value $Computer.lastLogonTimestamp
    $LastLogonTimestampState = if ($null -ne $LastLogonTimestamp) {
        New-SourceState -Status 'observed' -Source 'last_logon_timestamp' -Value $LastLogonTimestamp -ObservedAt $CollectedAt
    }
    else {
        New-SourceState -Status 'missing_in_source' -Source 'last_logon_timestamp' -ObservedAt $CollectedAt
    }
    $LastLogonTimestampStatus = [string]$LastLogonTimestampState.status
    if (-not $LastLogonTimestampStatusCounts.ContainsKey($LastLogonTimestampStatus)) { $LastLogonTimestampStatusCounts[$LastLogonTimestampStatus] = 0 }
    $LastLogonTimestampStatusCounts[$LastLogonTimestampStatus]++

    $OperatingSystemState = if (-not [string]::IsNullOrWhiteSpace([string]$Computer.OperatingSystem)) {
        New-SourceState -Status 'observed' -Source 'os' -Value ([pscustomobject]@{
            name         = [string]$Computer.OperatingSystem
            version      = [string]$Computer.OperatingSystemVersion
            service_pack = [string]$Computer.OperatingSystemServicePack
        }) -ObservedAt $CollectedAt
    }
    else {
        New-SourceState -Status 'missing_in_source' -Source 'os' -ObservedAt $CollectedAt -Details ([pscustomobject]@{ missing_field = 'OperatingSystem' })
    }
    $OperatingSystemStatus = [string]$OperatingSystemState.status
    if (-not $OsStatusCounts.ContainsKey($OperatingSystemStatus)) { $OsStatusCounts[$OperatingSystemStatus] = 0 }
    $OsStatusCounts[$OperatingSystemStatus]++

    $Sources = [ordered]@{
        ad                   = New-SourceState -Status 'observed' -Source 'ad' -ObservedAt $CollectedAt
        dns                  = $DnsResult.State
        os                   = $OperatingSystemState
        site                 = $SiteState
        last_logon_timestamp = $LastLogonTimestampState
        exact_last_logon     = $ExactState
        dc_events            = New-SourceState -Status 'not_collected' -Source 'dc_events'
    }

    [void]$Objects.Add([pscustomobject]@{
        id                           = [string]$Computer.ObjectGUID
        objectGuid                   = [string]$Computer.ObjectGUID
        name                         = [string]$Computer.Name
        dnsHostName                  = [string]$Computer.DNSHostName
        enabled                      = [bool]$Computer.Enabled
        deviceType                   = [string]$Classification.value
        classification               = $Classification
        ipv4s                        = @($DnsResult.IPv4)
        ipv6s                        = @($DnsResult.IPv6)
        osName                       = [string]$Computer.OperatingSystem
        osVersion                    = [string]$Computer.OperatingSystemVersion
        osBuild                      = Get-OsBuild -OperatingSystemVersion ([string]$Computer.OperatingSystemVersion)
        osFamily                     = Get-OsFamily -OperatingSystem ([string]$Computer.OperatingSystem)
        servicePack                  = [string]$Computer.OperatingSystemServicePack
        ou                           = Get-OuPath -CanonicalName ([string]$Computer.CanonicalName) -DistinguishedName ([string]$Computer.DistinguishedName)
        distinguishedName            = [string]$Computer.DistinguishedName
        canonicalName                = [string]$Computer.CanonicalName
        domain                       = [string]$Domain.DNSRoot
        adSite                       = $AdSite
        lastLogonTimestamp           = $LastLogonTimestamp
        exactLastLogon               = $ExactLastLogon
        eventLastSeen                = $null
        passwordLastSet              = Convert-ToIsoDate -Value $Computer.PasswordLastSet
        whenCreated                  = Convert-ToIsoDate -Value $Computer.whenCreated
        whenChanged                  = Convert-ToIsoDate -Value $Computer.whenChanged
        description                  = [string]$Computer.Description
        location                     = [string]$Computer.Location
        managedBy                    = [string]$Computer.ManagedBy
        sid                          = [string]$Computer.SID
        userAccountControl           = [int]$Computer.userAccountControl
        spns                         = @($Computer.ServicePrincipalName)
        trustedForDelegation         = [bool]$Computer.TrustedForDelegation
        trustedToAuthForDelegation   = [bool]$Computer.TrustedToAuthForDelegation
        roleHint                     = $RoleHint
        roleEvidence                 = $RoleEvidence
        collectedAt                  = $CollectedAt.ToUniversalTime().ToString('o')
        queryDc                      = $Server
        collectorVersion             = $CollectorVersion
        sources                      = $Sources
        collectionErrors             = @($ObjectErrors)
    })
}

function Get-StageStatus {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Counts,
        [Parameter(Mandatory = $true)][int]$ObjectCount,
        [switch]$WasSkipped
    )

    if ($WasSkipped) { return 'not_collected' }
    if ($ObjectCount -eq 0) { return 'observed' }
    if ($Counts.Count -eq 0) { return 'failed' }

    $FailureStatuses = @('failed', 'access_denied', 'parse_error')
    $FailureCount = 0
    foreach ($StatusName in $FailureStatuses) {
        if ($Counts.ContainsKey($StatusName)) { $FailureCount += [int]$Counts[$StatusName] }
    }
    if ($FailureCount -eq $ObjectCount) {
        $PresentFailures = @($FailureStatuses | Where-Object { $Counts.ContainsKey($_) -and [int]$Counts[$_] -gt 0 })
        if ($PresentFailures.Count -eq 1) { return $PresentFailures[0] }
        return 'failed'
    }
    if ($FailureCount -gt 0 -or $Counts.ContainsKey('partial') -or $Counts.ContainsKey('not_evaluated')) {
        return 'partial'
    }
    return 'observed'
}

$ObjectCount = $Objects.Count
$DnsStageStatus = Get-StageStatus -Counts $DnsStatusCounts -ObjectCount $ObjectCount -WasSkipped:$SkipDns
$OsStageStatus = Get-StageStatus -Counts $OsStatusCounts -ObjectCount $ObjectCount
$SiteStageStatus = Get-StageStatus -Counts $SiteStatusCounts -ObjectCount $ObjectCount -WasSkipped:(-not $CollectAdSite)
$LastLogonTimestampStageStatus = Get-StageStatus -Counts $LastLogonTimestampStatusCounts -ObjectCount $ObjectCount
$ExactStageStatus = Get-StageStatus -Counts $ExactStatusCounts -ObjectCount $ObjectCount -WasSkipped:(-not $CollectExactLastLogon)
$CollectionStatus = if (
    $DnsStageStatus -notin @('observed', 'not_collected') -or
    $OsStageStatus -notin @('observed', 'not_collected') -or
    $SiteStageStatus -notin @('observed', 'not_collected') -or
    $LastLogonTimestampStageStatus -notin @('observed', 'not_collected') -or
    $ExactStageStatus -notin @('observed', 'not_collected') -or
    $GlobalErrors.Count -gt 0
) { 'partial' } else { 'complete' }

$CompletedAt = (Get-Date).ToUniversalTime()
$Snapshot = [ordered]@{
    schema_version = $SchemaVersion
    metadata = [ordered]@{
        snapshot_id       = [guid]::NewGuid().ToString()
        label             = "AD inventory $($CompletedAt.ToString('yyyy-MM-dd HH:mm:ss')) UTC"
        started_at        = $StartedAt.ToString('o')
        completed_at      = $CompletedAt.ToString('o')
        query_dc          = $Server
        domain            = [string]$Domain.DNSRoot
        search_base       = $SearchBase
        collection_status = $CollectionStatus
        object_count      = $Objects.Count
        collector_version = $CollectorVersion
        sources           = @(
            [pscustomobject]@{ name = 'ad'; status = 'observed'; requested = $true; counts = [pscustomobject]@{ observed = $Objects.Count } }
            [pscustomobject]@{ name = 'dns'; status = $DnsStageStatus; requested = (-not $SkipDns.IsPresent); counts = [pscustomobject]$DnsStatusCounts }
            [pscustomobject]@{ name = 'os'; status = $OsStageStatus; requested = $true; counts = [pscustomobject]$OsStatusCounts }
            [pscustomobject]@{ name = 'site'; status = $SiteStageStatus; requested = $CollectAdSite.IsPresent; counts = [pscustomobject]$SiteStatusCounts }
            [pscustomobject]@{ name = 'last_logon_timestamp'; status = $LastLogonTimestampStageStatus; requested = $true; counts = [pscustomobject]$LastLogonTimestampStatusCounts }
            [pscustomobject]@{ name = 'exact_last_logon'; status = $ExactStageStatus; requested = $CollectExactLastLogon.IsPresent; counts = [pscustomobject]$ExactStatusCounts }
            [pscustomobject]@{ name = 'dc_events'; status = 'not_collected'; requested = $false; counts = $null }
        )
        errors            = @($GlobalErrors)
    }
    objects = @($Objects)
}

$ParentDirectory = Split-Path -Parent $OutputPath
if ($ParentDirectory -and -not (Test-Path -LiteralPath $ParentDirectory)) {
    New-Item -ItemType Directory -Path $ParentDirectory -Force | Out-Null
}

$Snapshot | ConvertTo-Json -Depth 14 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
Write-Host ("Saved {0} objects to: {1}" -f $Objects.Count, $OutputPath)
Write-Host ("Snapshot status: {0}; DNS: {1}; AD Site: {2}; exact lastLogon: {3}" -f $CollectionStatus, $DnsStageStatus, $SiteStageStatus, $ExactStageStatus)

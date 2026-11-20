#requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [Parameter(Mandatory = $true)][guid]$RunId,
    [Parameter(Mandatory = $true)][string]$DirectoryServer,
    [Parameter(Mandatory = $true)][string]$SearchBase,
    [Parameter(Mandatory = $true)][string]$Domain,
    [Parameter(Mandatory = $true)][string]$Sections,
    [Parameter(Mandatory = $true)][ValidateSet("ad_snapshot_base_v1", "directory_security_v1", "directory_group_graph_v1", "directory_exact_logon_v1", "vpn_security_v1", "gpo_governance_v2", "gpo_governance_v3", "gpo_governance_v4", "domain_posture_v1", "domain_health_v1")][string]$CollectionProfile,
    [Parameter(Mandatory = $true)][ValidateSet("full", "targeted", "reconcile")][string]$Mode,
    [string]$PrivilegedGroups = "",
    [string]$VpnGroups = "",
    [ValidateRange(1, 3650)][int]$InactiveDays = 180,
    [Parameter(Mandatory = $true)][ValidateRange(1, 50000)][int]$MaxRecords,
    [Parameter(Mandatory = $true)][ValidateRange(1024, 26214400)][int]$MaxBundleBytes,
    [Parameter(Mandatory = $true)][ValidateRange(1, 50000)][int]$MaxDirectoryAccounts,
    [ValidateRange(0, 50000)][int]$MaxDirectoryUsers = 0,
    [ValidateRange(0, 50000)][int]$MaxDirectoryComputers = 0,
    [ValidateRange(1, 50000)][int]$MaxDirectoryGroups = 10000,
    [ValidateRange(1, 50000)][int]$MaxDirectoryMemberships = 35000,
    [Parameter(Mandatory = $true)][ValidateRange(1, 50000)][int]$MaxVpnMembers,
    [Parameter(Mandatory = $true)][ValidateRange(1, 50000)][int]$MaxGpos,
    [string]$TechnicalServers = "",
    [ValidateRange(5, 60)][int]$TechnicalInventoryTimeoutSeconds = 20,
    [string]$ProgressPath = ""
)

$ErrorActionPreference = "Stop"

# The same cutover setting as the Python legacy admission gate.
if ($null -ne $env:SLI_LEGACY_COLLECTION_DISABLED -and $env:SLI_LEGACY_COLLECTION_DISABLED.Trim() -ne "0") {
    throw "legacy collection disabled by SLI_LEGACY_COLLECTION_DISABLED; use agent modules and core job handlers"
}
Set-StrictMode -Version Latest
$script:ProgressClock = [Diagnostics.Stopwatch]::StartNew()

function Write-SLICollectorProgress {
    param(
        [ValidateSet("starting", "base_users_start", "base_users_end", "base_computers_start", "base_computers_end", "raw_serialization_start", "raw_serialization_end", "accounts_start", "accounts_end", "group_graph_start", "group_graph_end", "exact_logon_start", "exact_logon_queries", "exact_logon_queried", "exact_logon_end", "final_serialization_start", "final_serialization_end", "completed")][string]$Phase,
        [int]$UserCount = -1, [int]$ComputerCount = -1, [int]$RecordCount = -1,
        [int]$ExactQueries = -1, [int]$DcCount = -1
    )
    if ([string]::IsNullOrWhiteSpace($ProgressPath)) { return }
    try {
        $fullPath = [IO.Path]::GetFullPath($ProgressPath)
        if (-not [IO.Path]::IsPathRooted($ProgressPath) -or $fullPath.StartsWith('\\')) { return }
        $bundlePath = [IO.Path]::GetFullPath($OutputPath)
        $pending = $fullPath + '.partial'
        if ([string]::Equals($fullPath, $bundlePath, [StringComparison]::OrdinalIgnoreCase) -or [string]::Equals($pending, $bundlePath, [StringComparison]::OrdinalIgnoreCase)) { return }
        if ([IO.Path]::GetDirectoryName($fullPath) -ne [IO.Path]::GetDirectoryName($bundlePath)) { return }
        $payload = [ordered]@{ phase = $Phase; elapsed_sec = [int][math]::Floor($script:ProgressClock.Elapsed.TotalSeconds) }
        $counts = [ordered]@{ user_count = $UserCount; computer_count = $ComputerCount; record_count = $RecordCount; exact_queries_completed = $ExactQueries; dc_count = $DcCount }
        foreach ($key in $counts.Keys) {
            if ($counts[$key] -ge 0 -and $counts[$key] -le 10000000) { $payload[$key] = $counts[$key] }
        }
        $text = ConvertTo-Json -InputObject $payload -Compress
        [IO.File]::WriteAllText($pending, $text, [Text.UTF8Encoding]::new($false))
        if ([IO.File]::Exists($fullPath)) { [IO.File]::Replace($pending, $fullPath, [NullString]::Value) }
        else { [IO.File]::Move($pending, $fullPath) }
    } catch { } # Optional local diagnostics must not change collection semantics.
}

Write-SLICollectorProgress -Phase starting
Import-Module (Join-Path $PSScriptRoot "ActiveDirectoryContext.psm1") -Force -ErrorAction Stop

function ConvertTo-UtcText {
    param([Parameter(Mandatory = $true)][datetime]$Value)
    return $Value.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
}

function ConvertTo-OptionalUtcText {
    param($Value)
    if ($null -eq $Value) { return $null }
    return ConvertTo-UtcText -Value ([datetime]$Value)
}

function Get-OptionalProperty {
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)][string]$Name
    )
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function ConvertTo-SLIBaseSizeValue {
    param([AllowNull()][object]$Value, [int]$ByteLimit, [int]$Depth = 0)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string] -or $Value -is [char]) {
        $text = [string]$Value
        if ([Text.Encoding]::UTF8.GetByteCount($text) -gt $ByteLimit) { throw 'ad_snapshot_base_v1_byte_bound_exceeded' }
        return $text
    }
    if ($Value -is [bool]) { return $Value }
    if ($Value -is [guid]) { return $Value.ToString('D') }
    if ($Value -is [Security.Principal.SecurityIdentifier]) { return $Value.Value }
    if ($Value -is [datetime] -or $Value -is [datetimeoffset]) { return $Value.ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture) }
    if ($Value -is [byte] -or $Value -is [sbyte] -or $Value -is [int16] -or $Value -is [uint16] -or $Value -is [int32] -or $Value -is [uint32] -or $Value -is [int64] -or $Value -is [uint64] -or $Value -is [decimal] -or $Value -is [single] -or $Value -is [double]) {
        if ([double]::IsNaN([double]$Value) -or [double]::IsInfinity([double]$Value)) { throw 'ad_snapshot_base_v1_value_unsupported' }
        return $Value
    }
    if ($Depth -eq 0 -and ($Value -is [array] -or $Value.GetType().FullName -eq 'Microsoft.ActiveDirectory.Management.ADPropertyValueCollection')) {
        $items = [Collections.Generic.List[object]]::new()
        [long]$size = 2
        foreach ($item in $Value) {
            $converted = ConvertTo-SLIBaseSizeValue -Value $item -ByteLimit $ByteLimit -Depth 1
            $itemJson = if ($null -eq $converted) { 'null' } else { ConvertTo-Json -InputObject $converted -Depth 2 -Compress }
            $size += [Text.Encoding]::UTF8.GetByteCount($itemJson)
            if ($items.Count -gt 0) { $size += 1 }
            if ($size -gt $ByteLimit) { throw 'ad_snapshot_base_v1_byte_bound_exceeded' }
            $items.Add($converted)
        }
        return ,$items.ToArray()
    }
    throw 'ad_snapshot_base_v1_value_unsupported'
}

function Measure-SLIBaseRowsJsonBytes {
    param([object[]]$Users, [object[]]$Computers, [string[]]$UserProperties, [string[]]$ComputerProperties, [ValidateRange(1, 26214400)][int]$ByteLimit)
    [long]$total = [Text.Encoding]::UTF8.GetByteCount('{"users":[],"computers":[]}')
    if ($total -gt $ByteLimit) { throw 'ad_snapshot_base_v1_byte_bound_exceeded' }
    foreach ($family in @(@{ Rows = $Users; Properties = $UserProperties }, @{ Rows = $Computers; Properties = $ComputerProperties })) {
        $names = @(@($family.Properties) + @('Name', 'ObjectClass') | Sort-Object -Unique)
        $rowCount = 0
        foreach ($sourceRow in $family.Rows) {
            $total += 2 # Object braces; array brackets already belong to the envelope.
            if ($rowCount -gt 0) { $total += 1 }
            $propertyCount = 0
            foreach ($name in $names) {
                # Index only selected properties: never enumerate or serialize ADObject getters.
                $property = $sourceRow.PSObject.Properties[$name]
                $value = $null
                if ($null -ne $property) { $value = $property.Value }
                $converted = ConvertTo-SLIBaseSizeValue -Value $value -ByteLimit $ByteLimit
                $propertyJson = ConvertTo-Json -InputObject ([ordered]@{ $name = $converted }) -Depth 3 -Compress
                $total += [Text.Encoding]::UTF8.GetByteCount($propertyJson) - 2
                if ($propertyCount -gt 0) { $total += 1 }
                if ($total -gt $ByteLimit) { throw 'ad_snapshot_base_v1_byte_bound_exceeded' }
                $propertyCount += 1
            }
            $rowCount += 1
        }
    }
    return $total
}

function Get-SLIExactLogonRows {
    param([AllowEmptyCollection()][object[]]$Users, [string]$Server, [string]$SearchBase, [ref]$QueryCount, [scriptblock]$OnQuery = {})
    if ($null -eq $Users -or $Users.Count -eq 0) { return }
    # Buffer one DC completely: failed/missing batches must never emit partial rows.
    $allRows = [Collections.Generic.List[object]]::new()
    for ($offset = 0; $offset -lt $Users.Count; $offset += 128) {
        $last = [math]::Min($offset + 127, $Users.Count - 1)
        $expected = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $clauses = foreach ($user in $Users[$offset..$last]) {
            $guid = [guid]$user.ObjectGUID
            if (-not $expected.Add($guid.ToString('D'))) { throw 'exact_logon_duplicate_base_identity' }
            $escaped = ($guid.ToByteArray() | ForEach-Object { '\{0:x2}' -f $_ }) -join ''
            '(objectGUID={0})' -f $escaped
        }
        $filter = '(&(objectCategory=person)(objectClass=user)(|{0}))' -f ($clauses -join '')
        $QueryCount.Value += 1
        try {
            $rows = @(Get-ADUser -Server $Server -LDAPFilter $filter -SearchBase $SearchBase -SearchScope Subtree -ResultSetSize ($expected.Count + 1) -Properties ObjectGUID,lastLogon -ErrorAction Stop)
        } finally { & $OnQuery $QueryCount.Value }
        $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($row in $rows) {
            $key = ([guid]$row.ObjectGUID).ToString('D')
            if (-not $expected.Contains($key) -or -not $seen.Add($key)) { throw 'exact_logon_batch_identity_mismatch' }
        }
        if ($seen.Count -ne $expected.Count) { throw 'exact_logon_batch_identity_missing' }
        foreach ($row in $rows) { $allRows.Add($row) }
    }
    return $allRows.ToArray()
}

function ConvertTo-SparseAttributes {
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Attributes)
    $result = [ordered]@{}
    foreach ($key in $Attributes.Keys) {
        $value = $Attributes[$key]
        if ($null -eq $value) { continue }
        if ($value -is [string] -and [string]::IsNullOrWhiteSpace($value)) { continue }
        if ($value -is [System.Array] -and $value.Count -eq 0) { continue }
        $result[[string]$key] = $value
    }
    return $result
}

function ConvertFrom-FileTimeUtc {
    param($Value)
    if ($null -eq $Value) { return $null }
    $raw = [int64]$Value
    if ($raw -le 0 -or $raw -eq [int64]::MaxValue) { return $null }
    return ConvertTo-UtcText -Value ([datetime]::FromFileTimeUtc($raw))
}

function Get-PasswordExpiryProjection {
    param([Parameter(Mandatory = $true)]$User)
    $neverExpires = Get-OptionalProperty -Object $User -Name "PasswordNeverExpires"
    $rawExpiry = Get-OptionalProperty -Object $User -Name "msDS-UserPasswordExpiryTimeComputed"
    $resultantPso = Get-OptionalProperty -Object $User -Name "msDS-ResultantPSO"
    $status = "missing_in_source"
    $expiryUtc = $null
    if ($null -ne $neverExpires -and [bool]$neverExpires) {
        $status = "not_applicable"
    }
    elseif ($null -ne $rawExpiry) {
        try {
            $rawExpiryInt = [int64]$rawExpiry
            if ($rawExpiryInt -eq [int64]::MaxValue) {
                $status = "not_applicable"
            }
            elseif ($rawExpiryInt -le 0) {
                $status = "not_evaluated"
            }
            else {
                $expiryUtc = ConvertFrom-FileTimeUtc -Value $rawExpiryInt
                $status = if ($null -ne $expiryUtc) { "observed" } else { "not_evaluated" }
            }
        }
        catch {
            $status = "parse_error"
        }
    }
    $policyDn = if ($null -ne $resultantPso) { [string]$resultantPso } else { $null }
    $policyName = $null
    if ($policyDn -and $policyDn -match '^CN=((?:\\.|[^,])+),') {
        $policyName = $Matches[1].Replace('\,', ',').Replace('\\', '\')
    }
    return [ordered]@{
        password_expiry_status = $status
        password_expiry_utc = $expiryUtc
        effective_password_policy_dn = $policyDn
        effective_password_policy_name = $policyName
        effective_password_policy_source = if ($policyDn) { "msDS-ResultantPSO" } else { $null }
    }
}

function Get-StableRecordKey {
    param(
        [Parameter(Mandatory = $true)][string]$DomainSid,
        [Parameter(Mandatory = $true)][guid]$ObjectGuid
    )
    return ("ad:{0}:{1}" -f $DomainSid.ToLowerInvariant(), $ObjectGuid.ToString().ToLowerInvariant())
}

function ConvertTo-LdapFilterValue {
    param([Parameter(Mandatory = $true)][string]$Value)
    return $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace(([string][char]0), '\00')
}

function ConvertTo-AdEntityRecord {
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)][string]$DomainSid,
        [Parameter(Mandatory = $true)][string]$ObservedAtUtc,
        [Parameter(Mandatory = $true)][string]$Section
    )
    $kind = switch ([string]$Object.objectClass) {
        "group" { "ad_group" }
        "computer" { "ad_computer" }
        "user" { "ad_user" }
        default { "security_principal" }
    }
    $objectGuid = [guid](Get-OptionalProperty -Object $Object -Name "ObjectGUID")
    $recordKey = Get-StableRecordKey -DomainSid $DomainSid -ObjectGuid $objectGuid
    $sid = Get-OptionalProperty -Object $Object -Name "SID"
    if ($null -eq $sid) { $sid = Get-OptionalProperty -Object $Object -Name "objectSid" }
    $lastLogon = Get-OptionalProperty -Object $Object -Name "LastLogonDate"
    $createdAt = Get-OptionalProperty -Object $Object -Name "whenCreated"
    $enabledValue = Get-OptionalProperty -Object $Object -Name "Enabled"
    $dnsHostNameValue = Get-OptionalProperty -Object $Object -Name "DNSHostName"
    $operatingSystemValue = Get-OptionalProperty -Object $Object -Name "OperatingSystem"
    $operatingSystemVersionValue = Get-OptionalProperty -Object $Object -Name "OperatingSystemVersion"
    $operatingSystemServicePackValue = Get-OptionalProperty -Object $Object -Name "OperatingSystemServicePack"
    $canonicalNameValue = Get-OptionalProperty -Object $Object -Name "CanonicalName"
    $descriptionValue = Get-OptionalProperty -Object $Object -Name "Description"
    $locationValue = Get-OptionalProperty -Object $Object -Name "Location"
    $managedByValue = Get-OptionalProperty -Object $Object -Name "ManagedBy"
    $passwordLastSetValue = Get-OptionalProperty -Object $Object -Name "PasswordLastSet"
    $whenChangedValue = Get-OptionalProperty -Object $Object -Name "whenChanged"
    $servicePrincipalNames = Get-OptionalProperty -Object $Object -Name "servicePrincipalName"
    if ($null -eq $servicePrincipalNames) { $servicePrincipalNames = Get-OptionalProperty -Object $Object -Name "ServicePrincipalNames" }
    $trustedForDelegationValue = Get-OptionalProperty -Object $Object -Name "TrustedForDelegation"
    $trustedToAuthForDelegationValue = Get-OptionalProperty -Object $Object -Name "TrustedToAuthForDelegation"
    $userAccountControlValue = Get-OptionalProperty -Object $Object -Name "userAccountControl"
    $inactiveCutoff = ([datetime]$ObservedAtUtc).ToUniversalTime().AddDays(-1 * $InactiveDays)
    $isInactive = $null
    $inactivityBasis = "not_applicable"
    if ($kind -in @("ad_user", "ad_computer")) {
        if ($null -ne $lastLogon) {
            $isInactive = ([datetime]$lastLogon).ToUniversalTime() -lt $inactiveCutoff
            $inactivityBasis = "last_logon"
        }
        elseif ($null -ne $createdAt) {
            $isInactive = ([datetime]$createdAt).ToUniversalTime() -lt $inactiveCutoff
            $inactivityBasis = "creation_time_without_logon"
        }
        else {
            $inactivityBasis = "insufficient_time_evidence"
        }
    }
    $attributeStates = $null
    $computerReferenceAttributeStates = $null
    if ($kind -eq "ad_computer") {
        $attributeStates = [ordered]@{
            enabled = [ordered]@{ state = if ($null -ne $enabledValue) { "present" } else { "absent_in_source" }; source_attribute = "Enabled" }
            last_logon_utc = [ordered]@{ state = if ($null -ne $lastLogon) { "present" } else { "absent_in_source" }; source_attribute = "LastLogonDate" }
            dns_host_name = [ordered]@{ state = if ($null -ne $dnsHostNameValue) { "present" } else { "absent_in_source" }; source_attribute = "DNSHostName" }
            operating_system = [ordered]@{ state = if ($null -ne $operatingSystemValue) { "present" } else { "absent_in_source" }; source_attribute = "OperatingSystem" }
            operating_system_version = [ordered]@{ state = if ($null -ne $operatingSystemVersionValue) { "present" } else { "absent_in_source" }; source_attribute = "OperatingSystemVersion" }
        }
        $computerReferenceAttributeStates = [ordered]@{
            enabled = [ordered]@{ state = if ($null -ne $enabledValue) { "present" } else { "absent_in_source" }; source_attribute = "Enabled" }
            last_logon_utc = [ordered]@{ state = if ($null -ne $lastLogon) { "present" } else { "absent_in_source" }; source_attribute = "LastLogonDate" }
            dns_host_name = [ordered]@{ state = if ($null -ne $dnsHostNameValue) { "present" } else { "absent_in_source" }; source_attribute = "DNSHostName" }
            operating_system = [ordered]@{ state = if ($null -ne $operatingSystemValue) { "present" } else { "absent_in_source" }; source_attribute = "OperatingSystem" }
            operating_system_version = [ordered]@{ state = if ($null -ne $operatingSystemVersionValue) { "present" } else { "absent_in_source" }; source_attribute = "OperatingSystemVersion" }
            operating_system_service_pack = [ordered]@{ state = if ($null -ne $operatingSystemServicePackValue) { "present" } else { "absent_in_source" }; source_attribute = "OperatingSystemServicePack" }
            canonical_name = [ordered]@{ state = if ($null -ne $canonicalNameValue) { "present" } else { "absent_in_source" }; source_attribute = "CanonicalName" }
            description = [ordered]@{ state = if ($null -ne $descriptionValue) { "present" } else { "absent_in_source" }; source_attribute = "Description" }
            location = [ordered]@{ state = if ($null -ne $locationValue) { "present" } else { "absent_in_source" }; source_attribute = "Location" }
            managed_by = [ordered]@{ state = if ($null -ne $managedByValue) { "present" } else { "absent_in_source" }; source_attribute = "ManagedBy" }
            password_last_set_utc = [ordered]@{ state = if ($null -ne $passwordLastSetValue) { "present" } else { "absent_in_source" }; source_attribute = "PasswordLastSet" }
            created_utc = [ordered]@{ state = if ($null -ne $createdAt) { "present" } else { "absent_in_source" }; source_attribute = "whenCreated" }
            when_changed_utc = [ordered]@{ state = if ($null -ne $whenChangedValue) { "present" } else { "absent_in_source" }; source_attribute = "whenChanged" }
            service_principal_names = [ordered]@{ state = if ($null -ne $servicePrincipalNames) { "present" } else { "absent_in_source" }; source_attribute = "servicePrincipalName" }
            trusted_for_delegation = [ordered]@{ state = if ($null -ne $trustedForDelegationValue) { "present" } else { "absent_in_source" }; source_attribute = "TrustedForDelegation" }
            trusted_to_auth_for_delegation = [ordered]@{ state = if ($null -ne $trustedToAuthForDelegationValue) { "present" } else { "absent_in_source" }; source_attribute = "TrustedToAuthForDelegation" }
            user_account_control = [ordered]@{ state = if ($null -ne $userAccountControlValue) { "present" } else { "absent_in_source" }; source_attribute = "userAccountControl" }
        }
    }
    $passwordExpiry = if ($kind -eq "ad_user") { Get-PasswordExpiryProjection -User $Object } else { $null }
    return [ordered]@{
        record_type = "entity"
        record_key = $recordKey
        section = $Section
        observed_at_utc = $ObservedAtUtc
        identity = [ordered]@{
            kind = $kind
            domain_sid = $DomainSid
            object_guid = $objectGuid.ToString()
            object_sid = if ($null -ne $sid) { [string]$sid } else { $null }
        }
        attributes = (ConvertTo-SparseAttributes -Attributes ([ordered]@{
            display_name = [string](Get-OptionalProperty -Object $Object -Name "Name")
            sam_account_name = if (Get-OptionalProperty -Object $Object -Name "SamAccountName") { [string](Get-OptionalProperty -Object $Object -Name "SamAccountName") } else { $null }
            distinguished_name = if (Get-OptionalProperty -Object $Object -Name "DistinguishedName") { [string](Get-OptionalProperty -Object $Object -Name "DistinguishedName") } else { $null }
            enabled = if ($null -ne $enabledValue) { [bool]$enabledValue } else { $null }
            object_class = [string](Get-OptionalProperty -Object $Object -Name "objectClass")
            user_principal_name = if (Get-OptionalProperty -Object $Object -Name "UserPrincipalName") { [string](Get-OptionalProperty -Object $Object -Name "UserPrincipalName") } else { $null }
            created_utc = ConvertTo-OptionalUtcText $createdAt
            last_logon_utc = ConvertTo-OptionalUtcText $lastLogon
            last_logon_timestamp_utc = ConvertTo-OptionalUtcText $lastLogon
            is_inactive = $isInactive
            inactivity_basis = $inactivityBasis
            inactive_threshold_days = $InactiveDays
            password_last_set_utc = ConvertTo-OptionalUtcText $passwordLastSetValue
            password_never_expires = if ($null -ne (Get-OptionalProperty -Object $Object -Name "PasswordNeverExpires")) { [bool](Get-OptionalProperty -Object $Object -Name "PasswordNeverExpires") } else { $null }
            password_expiry_status = if ($null -ne $passwordExpiry) { $passwordExpiry.password_expiry_status } else { $null }
            password_expiry_utc = if ($null -ne $passwordExpiry) { $passwordExpiry.password_expiry_utc } else { $null }
            effective_password_policy_dn = if ($null -ne $passwordExpiry) { $passwordExpiry.effective_password_policy_dn } else { $null }
            effective_password_policy_name = if ($null -ne $passwordExpiry) { $passwordExpiry.effective_password_policy_name } else { $null }
            effective_password_policy_source = if ($null -ne $passwordExpiry) { $passwordExpiry.effective_password_policy_source } else { $null }
            department = if (Get-OptionalProperty -Object $Object -Name "Department") { [string](Get-OptionalProperty -Object $Object -Name "Department") } else { $null }
            title = if (Get-OptionalProperty -Object $Object -Name "Title") { [string](Get-OptionalProperty -Object $Object -Name "Title") } else { $null }
            email = if (Get-OptionalProperty -Object $Object -Name "EmailAddress") { [string](Get-OptionalProperty -Object $Object -Name "EmailAddress") } else { $null }
            mail = if (Get-OptionalProperty -Object $Object -Name "mail") { [string](Get-OptionalProperty -Object $Object -Name "mail") } else { $null }
            given_name = if (Get-OptionalProperty -Object $Object -Name "GivenName") { [string](Get-OptionalProperty -Object $Object -Name "GivenName") } else { $null }
            surname = if (Get-OptionalProperty -Object $Object -Name "Surname") { [string](Get-OptionalProperty -Object $Object -Name "Surname") } else { $null }
            canonical_name = if ($canonicalNameValue) { [string]$canonicalNameValue } else { $null }
            company = if (Get-OptionalProperty -Object $Object -Name "Company") { [string](Get-OptionalProperty -Object $Object -Name "Company") } else { $null }
            manager = if (Get-OptionalProperty -Object $Object -Name "Manager") { [string](Get-OptionalProperty -Object $Object -Name "Manager") } else { $null }
            employee_id = if (Get-OptionalProperty -Object $Object -Name "EmployeeID") { [string](Get-OptionalProperty -Object $Object -Name "EmployeeID") } else { $null }
            employee_number = if (Get-OptionalProperty -Object $Object -Name "EmployeeNumber") { [string](Get-OptionalProperty -Object $Object -Name "EmployeeNumber") } else { $null }
            office = if (Get-OptionalProperty -Object $Object -Name "Office") { [string](Get-OptionalProperty -Object $Object -Name "Office") } else { $null }
            telephone_number = if (Get-OptionalProperty -Object $Object -Name "OfficePhone") { [string](Get-OptionalProperty -Object $Object -Name "OfficePhone") } else { $null }
            mobile = if (Get-OptionalProperty -Object $Object -Name "MobilePhone") { [string](Get-OptionalProperty -Object $Object -Name "MobilePhone") } else { $null }
            ip_phone = if (Get-OptionalProperty -Object $Object -Name "IPPhone") { [string](Get-OptionalProperty -Object $Object -Name "IPPhone") } else { $null }
            fax = if (Get-OptionalProperty -Object $Object -Name "Fax") { [string](Get-OptionalProperty -Object $Object -Name "Fax") } else { $null }
            street_address = if (Get-OptionalProperty -Object $Object -Name "StreetAddress") { [string](Get-OptionalProperty -Object $Object -Name "StreetAddress") } else { $null }
            city = if (Get-OptionalProperty -Object $Object -Name "City") { [string](Get-OptionalProperty -Object $Object -Name "City") } else { $null }
            state = if (Get-OptionalProperty -Object $Object -Name "State") { [string](Get-OptionalProperty -Object $Object -Name "State") } else { $null }
            postal_code = if (Get-OptionalProperty -Object $Object -Name "PostalCode") { [string](Get-OptionalProperty -Object $Object -Name "PostalCode") } else { $null }
            country = if (Get-OptionalProperty -Object $Object -Name "Country") { [string](Get-OptionalProperty -Object $Object -Name "Country") } else { $null }
            description = if ($descriptionValue) { [string]$descriptionValue } else { $null }
            location = if ($locationValue) { [string]$locationValue } else { $null }
            managed_by = if ($managedByValue) { [string]$managedByValue } else { $null }
            script_path = if (Get-OptionalProperty -Object $Object -Name "scriptPath") { [string](Get-OptionalProperty -Object $Object -Name "scriptPath") } else { $null }
            home_directory = if (Get-OptionalProperty -Object $Object -Name "homeDirectory") { [string](Get-OptionalProperty -Object $Object -Name "homeDirectory") } else { $null }
            home_drive = if (Get-OptionalProperty -Object $Object -Name "homeDrive") { [string](Get-OptionalProperty -Object $Object -Name "homeDrive") } else { $null }
            profile_path = if (Get-OptionalProperty -Object $Object -Name "profilePath") { [string](Get-OptionalProperty -Object $Object -Name "profilePath") } else { $null }
            proxy_addresses = @((Get-OptionalProperty -Object $Object -Name "ProxyAddresses"))
            other_telephones = @((Get-OptionalProperty -Object $Object -Name "OtherTelephone"))
            service_principal_names = @($servicePrincipalNames)
            password_expired = if ($null -ne (Get-OptionalProperty -Object $Object -Name "PasswordExpired")) { [bool](Get-OptionalProperty -Object $Object -Name "PasswordExpired") } else { $null }
            password_not_required = if ($null -ne (Get-OptionalProperty -Object $Object -Name "PasswordNotRequired")) { [bool](Get-OptionalProperty -Object $Object -Name "PasswordNotRequired") } else { $null }
            cannot_change_password = if ($null -ne (Get-OptionalProperty -Object $Object -Name "CannotChangePassword")) { [bool](Get-OptionalProperty -Object $Object -Name "CannotChangePassword") } else { $null }
            smartcard_logon_required = if ($null -ne (Get-OptionalProperty -Object $Object -Name "SmartcardLogonRequired")) { [bool](Get-OptionalProperty -Object $Object -Name "SmartcardLogonRequired") } else { $null }
            does_not_require_preauth = if ($null -ne (Get-OptionalProperty -Object $Object -Name "DoesNotRequirePreAuth")) { [bool](Get-OptionalProperty -Object $Object -Name "DoesNotRequirePreAuth") } else { $null }
            trusted_for_delegation = if ($null -ne $trustedForDelegationValue) { [bool]$trustedForDelegationValue } else { $null }
            trusted_to_auth_for_delegation = if ($null -ne $trustedToAuthForDelegationValue) { [bool]$trustedToAuthForDelegationValue } else { $null }
            account_not_delegated = if ($null -ne (Get-OptionalProperty -Object $Object -Name "AccountNotDelegated")) { [bool](Get-OptionalProperty -Object $Object -Name "AccountNotDelegated") } else { $null }
            allow_reversible_password_encryption = if ($null -ne (Get-OptionalProperty -Object $Object -Name "AllowReversiblePasswordEncryption")) { [bool](Get-OptionalProperty -Object $Object -Name "AllowReversiblePasswordEncryption") } else { $null }
            use_des_key_only = if ($null -ne (Get-OptionalProperty -Object $Object -Name "UseDESKeyOnly")) { [bool](Get-OptionalProperty -Object $Object -Name "UseDESKeyOnly") } else { $null }
            user_account_control = $userAccountControlValue
            msds_supported_encryption_types = Get-OptionalProperty -Object $Object -Name "msDS-SupportedEncryptionTypes"
            when_created_utc = ConvertTo-OptionalUtcText $createdAt
            when_changed_utc = ConvertTo-OptionalUtcText $whenChangedValue
            last_bad_password_attempt_utc = ConvertTo-OptionalUtcText (Get-OptionalProperty -Object $Object -Name "LastBadPasswordAttempt")
            bad_password_count_at_query_dc = Get-OptionalProperty -Object $Object -Name "badPwdCount"
            admin_count = if ($null -ne (Get-OptionalProperty -Object $Object -Name "AdminCount")) { [int](Get-OptionalProperty -Object $Object -Name "AdminCount") } else { $null }
            account_expiration_utc = ConvertTo-OptionalUtcText (Get-OptionalProperty -Object $Object -Name "AccountExpirationDate")
            locked_out = if ($null -ne (Get-OptionalProperty -Object $Object -Name "LockedOut")) { [bool](Get-OptionalProperty -Object $Object -Name "LockedOut") } else { $null }
            dns_host_name = if ($dnsHostNameValue) { [string]$dnsHostNameValue } else { $null }
            operating_system = if ($operatingSystemValue) { [string]$operatingSystemValue } else { $null }
            operating_system_version = if ($operatingSystemVersionValue) { [string]$operatingSystemVersionValue } else { $null }
            operating_system_service_pack = if ($operatingSystemServicePackValue) { [string]$operatingSystemServicePackValue } else { $null }
            attribute_states = $attributeStates
            computer_reference_attribute_states = $computerReferenceAttributeStates
        }))
    }
}

function Write-EntityRecord {
    param(
        [Parameter(Mandatory = $true)]$Record,
        [Parameter(Mandatory = $true)]$Records,
        [Parameter(Mandatory = $true)]$EntityRecords,
        [Parameter(Mandatory = $true)][int]$RecordLimit
    )
    $key = [string]$Record.record_key
    if ($EntityRecords.ContainsKey($key)) {
        $retained = $EntityRecords[$key]
        foreach ($containerName in @("attributes", "provenance")) {
            $incomingProperty = if ($Record -is [System.Collections.IDictionary]) {
                if ($Record.Contains($containerName)) { $Record[$containerName] } else { $null }
            }
            else {
                $property = $Record.PSObject.Properties[$containerName]
                if ($null -ne $property) { $property.Value } else { $null }
            }
            if ($null -eq $incomingProperty) { continue }

            $retainedProperty = if ($retained -is [System.Collections.IDictionary]) {
                if ($retained.Contains($containerName)) { $retained[$containerName] } else { $null }
            }
            else {
                $property = $retained.PSObject.Properties[$containerName]
                if ($null -ne $property) { $property.Value } else { $null }
            }
            if ($null -eq $retainedProperty) {
                $retainedProperty = [ordered]@{}
                if ($retained -is [System.Collections.IDictionary]) {
                    $retained[$containerName] = $retainedProperty
                }
                else {
                    $retained | Add-Member -NotePropertyName $containerName -NotePropertyValue $retainedProperty
                }
            }

            $incomingKeys = if ($incomingProperty -is [System.Collections.IDictionary]) {
                @($incomingProperty.Keys)
            }
            else {
                @($incomingProperty.PSObject.Properties.Name)
            }
            foreach ($attributeName in $incomingKeys) {
                $alreadyPresent = if ($retainedProperty -is [System.Collections.IDictionary]) {
                    $retainedProperty.Contains($attributeName)
                }
                else {
                    $null -ne $retainedProperty.PSObject.Properties[$attributeName]
                }
                if ($alreadyPresent) { continue }
                if ($incomingProperty -is [System.Collections.IDictionary]) {
                    $value = $incomingProperty[$attributeName]
                }
                else {
                    $value = $incomingProperty.PSObject.Properties[$attributeName].Value
                }
                if ($retainedProperty -is [System.Collections.IDictionary]) {
                    $retainedProperty[$attributeName] = $value
                }
                else {
                    $retainedProperty | Add-Member -NotePropertyName $attributeName -NotePropertyValue $value
                }
            }
        }
        return $key
    }
    if ($Records.Count -ge $RecordLimit) { throw "AD audit context record budget exceeded." }
    $EntityRecords[$key] = $Record
    $Records.Add($Record)
    return $key
}

function Write-DataQualityRecord {
    param(
        [Parameter(Mandatory = $true)][string]$Section,
        [Parameter(Mandatory = $true)][string]$Code,
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter(Mandatory = $true)][string]$ObservedAtUtc,
        [Parameter(Mandatory = $true)]$Records,
        [Parameter(Mandatory = $true)][int]$RecordLimit
    )
    $safeMessage = if ($Message.Length -gt 4096) { $Message.Substring(0, 4096) } else { $Message }
    if ($Records.Count -ge $RecordLimit) { return }
    $Records.Add([ordered]@{
        record_type = "data_quality"
        record_key = ("dq:{0}:{1}" -f $Section, $Code)
        section = $Section
        observed_at_utc = $ObservedAtUtc
        classification = "DataQuality"
        code = $Code
        message = $safeMessage
    })
}

function Get-BoundedTechnicalInventory {
    param(
        [Parameter(Mandatory = $true)][string]$ComputerName,
        [Parameter(Mandatory = $true)][ValidateRange(5, 60)][int]$TimeoutSeconds
    )
    $job = Start-Job -ScriptBlock {
        param([string]$Target, [int]$OperationTimeoutSeconds)
        $session = $null
        try {
            $options = New-CimSessionOption -Protocol Dcom
            $session = New-CimSession -ComputerName $Target -SessionOption $options -OperationTimeoutSec $OperationTimeoutSeconds -ErrorAction Stop
            $disks = @(Get-CimInstance -CimSession $session -ClassName Win32_LogicalDisk -Filter "DriveType=3" -Property DeviceID, Size, FreeSpace -ErrorAction Stop)
            $network = @(Get-CimInstance -CimSession $session -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled=true" -Property IPAddress -ErrorAction Stop)
            [pscustomobject]@{
                status = "complete"
                ip_addresses = @($network | ForEach-Object { @($_.IPAddress) } | Where-Object { $_ -and $_.Length -le 64 } | Sort-Object -Unique)
                logical_disks = @($disks | Sort-Object DeviceID | ForEach-Object {
                    "{0}|{1}|{2}" -f [string]$_.DeviceID, [uint64]$_.Size, [uint64]$_.FreeSpace
                })
            }
        }
        finally {
            if ($null -ne $session) { Remove-CimSession -CimSession $session -ErrorAction SilentlyContinue }
        }
    } -ArgumentList $ComputerName, $TimeoutSeconds
    try {
        if (-not (Wait-Job -Job $job -Timeout $TimeoutSeconds)) {
            Stop-Job -Job $job -ErrorAction SilentlyContinue
            return [ordered]@{ status = "timeout"; ip_addresses = @(); logical_disks = @() }
        }
        if ($job.State -ne "Completed") {
            [void](Receive-Job -Job $job -ErrorAction SilentlyContinue)
            return [ordered]@{ status = "failed"; ip_addresses = @(); logical_disks = @() }
        }
        $payload = @(Receive-Job -Job $job -ErrorAction Stop) | Select-Object -Last 1
        if ($null -eq $payload -or [string]$payload.status -ne "complete") {
            return [ordered]@{ status = "failed"; ip_addresses = @(); logical_disks = @() }
        }
        return [ordered]@{
            status = "complete"
            ip_addresses = @($payload.ip_addresses)
            logical_disks = @($payload.logical_disks)
        }
    }
    catch {
        return [ordered]@{ status = "failed"; ip_addresses = @(); logical_disks = @() }
    }
    finally {
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
    }
}

$requestedSections = @($Sections.Split(",", [System.StringSplitOptions]::RemoveEmptyEntries) | ForEach-Object { $_.Trim() })
$supportedSections = @("directory_accounts", "directory_group_graph", "directory_exact_logon", "vpn_membership", "gpo_governance", "domain_posture", "domain_health")
if (@($requestedSections | Where-Object { $_ -notin $supportedSections }).Count -gt 0) {
    throw "The AD audit context collector received an unsupported section."
}
$baseProfileSections = @("directory_accounts", "directory_group_graph", "directory_exact_logon")
$isBaseProfile = $CollectionProfile -eq "ad_snapshot_base_v1"
if ($isBaseProfile) {
    if ($requestedSections.Count -ne $baseProfileSections.Count -or @(Compare-Object $requestedSections $baseProfileSections).Count -ne 0) {
        throw "ad_snapshot_base_v1 requires the exact bounded base-dependent section set."
    }
}
elseif ($requestedSections.Count -ne 1) { throw "Standalone section collectors require exactly one section." }
$expectedProfile = switch ($requestedSections[0]) {
    "directory_accounts" { "directory_security_v1" }
    "directory_group_graph" { "directory_group_graph_v1" }
    "directory_exact_logon" { "directory_exact_logon_v1" }
    "vpn_membership" { "vpn_security_v1" }
    "gpo_governance" { "gpo_governance_v2" }
    "domain_posture" { "domain_posture_v1" }
    "domain_health" { "domain_health_v1" }
}
if ($isBaseProfile) {
    # Exact profile validation is complete above.
} elseif ($requestedSections[0] -eq "gpo_governance") {
    if ($CollectionProfile -notin @("gpo_governance_v2", "gpo_governance_v3", "gpo_governance_v4")) { throw "CollectionProfile does not match the requested section." }
} elseif ($CollectionProfile -ne $expectedProfile) {
    throw "CollectionProfile does not match the requested section."
}
$vpnReferences = @($VpnGroups.Split(",", [System.StringSplitOptions]::RemoveEmptyEntries) | ForEach-Object { $_.Trim() })
$technicalServerValues = @($TechnicalServers.Split(",", [System.StringSplitOptions]::RemoveEmptyEntries) | ForEach-Object { $_.Trim() })
if ($technicalServerValues.Count -gt 50 -or @($technicalServerValues | Where-Object { $_ -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$' }).Count -gt 0) {
    throw "TechnicalServers contains an invalid or unbounded source list."
}
$technicalServerSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($technicalServer in $technicalServerValues) { [void]$technicalServerSet.Add($technicalServer.Split(".")[0]) }
if ($requestedSections -contains "vpn_membership" -and $vpnReferences.Count -eq 0) {
    throw "The vpn_membership section requires at least one exact VPN group reference."
}

Import-Module ActiveDirectory -ErrorAction Stop
$started = [datetime]::UtcNow
$observedAt = ConvertTo-UtcText -Value $started
$domainData = Get-ADDomain -Server $DirectoryServer -Identity $Domain -ErrorAction Stop
$domainDnsName = [string]$domainData.DNSRoot
if (-not $domainDnsName.Equals($Domain, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "DirectoryServer returned a domain that differs from the requested DNS domain."
}
$domainSid = [string]$domainData.DomainSID
$records = [System.Collections.Generic.List[object]]::new()
$entityRecords = @{}
$seenRelations = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$sectionStatus = @{}
$sectionStarted = @{}
$vpnGroupSids = [System.Collections.Generic.List[string]]::new()

foreach ($section in $requestedSections) {
    $sectionStatus[$section] = "complete"
    $sectionStarted[$section] = [datetime]::UtcNow
}

$baseUsers = @()
$baseComputers = @()
$baseUserGuidAllowlist = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$baseComputerGuidAllowlist = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
if ($CollectionProfile -eq "ad_snapshot_base_v1") {
    $approvedLimit = [int][math]::Min($MaxRecords, $MaxDirectoryAccounts)
    $userLimit = if ($MaxDirectoryUsers -gt 0) { $MaxDirectoryUsers } else { [int][math]::Floor($approvedLimit / 2) }
    $computerLimit = if ($MaxDirectoryComputers -gt 0) { $MaxDirectoryComputers } else { $approvedLimit - $userLimit }
    if ($userLimit -lt 1 -or $computerLimit -lt 1 -or ($userLimit + $computerLimit) -gt $approvedLimit) {
        throw "ad_snapshot_base_v1 independent directory limits are invalid."
    }
    $baseUserProperties = @(
        "ObjectGUID", "SID", "SamAccountName", "UserPrincipalName", "DistinguishedName", "Enabled",
        "whenCreated", "LastLogonDate", "PasswordLastSet", "PasswordNeverExpires", "Department", "Title", "EmailAddress",
        "AdminCount", "AccountExpirationDate", "LockedOut", "DisplayName", "GivenName", "Surname", "CanonicalName",
        "Company", "Manager", "EmployeeID", "EmployeeNumber", "Office", "OfficePhone", "MobilePhone", "IPPhone", "Fax",
        "StreetAddress", "City", "State", "PostalCode", "Country", "Description", "ProxyAddresses", "OtherTelephone",
        "mail", "servicePrincipalName", "scriptPath", "homeDirectory", "homeDrive", "profilePath",
        "PasswordExpired", "PasswordNotRequired", "CannotChangePassword", "SmartcardLogonRequired", "DoesNotRequirePreAuth",
        "TrustedForDelegation", "TrustedToAuthForDelegation", "UseDESKeyOnly", "AccountNotDelegated",
        "AllowReversiblePasswordEncryption", "userAccountControl", "msDS-SupportedEncryptionTypes", "whenChanged",
        "LastBadPasswordAttempt", "badPwdCount", "msDS-UserPasswordExpiryTimeComputed", "msDS-ResultantPSO",
        "MemberOf", "PrimaryGroupID"
    ) | Sort-Object -Unique
    $baseComputerProperties = @(
        "ObjectGUID", "SID", "SamAccountName", "DistinguishedName", "Enabled", "whenCreated", "LastLogonDate",
        "lastLogonTimestamp", "DNSHostName", "OperatingSystem", "OperatingSystemVersion", "OperatingSystemServicePack",
        "CanonicalName", "Description", "Location", "ManagedBy", "PasswordLastSet", "whenChanged",
        "servicePrincipalName", "TrustedForDelegation", "TrustedToAuthForDelegation", "userAccountControl", "MemberOf", "PrimaryGroupID"
    ) | Sort-Object -Unique
    if ($baseUserProperties.Count -gt 96 -or $baseComputerProperties.Count -gt 32) { throw "ad_snapshot_base_v1_property_union_exceeded" }
    $baseClock = [Diagnostics.Stopwatch]::StartNew()
    $baseUserQuery = @{
        Server = $DirectoryServer; LDAPFilter = "(&(objectCategory=person)(objectClass=user))"; SearchBase = $SearchBase
        SearchScope = "Subtree"; ResultSetSize = ($userLimit + 1); Properties = $baseUserProperties; ErrorAction = "Stop"
    }
    Write-SLICollectorProgress -Phase base_users_start
    $baseUsers = @(Get-ADUser @baseUserQuery)
    Write-SLICollectorProgress -Phase base_users_end -UserCount $baseUsers.Count
    if ($baseUsers.Count -gt $userLimit) { throw "ad_snapshot_base_v1_user_record_bound_exceeded" }
    $baseComputerQuery = @{
        Server = $DirectoryServer; LDAPFilter = "(objectClass=computer)"; SearchBase = $SearchBase
        SearchScope = "Subtree"; ResultSetSize = ($computerLimit + 1); Properties = $baseComputerProperties; ErrorAction = "Stop"
    }
    Write-SLICollectorProgress -Phase base_computers_start -UserCount $baseUsers.Count
    $baseComputers = @(Get-ADComputer @baseComputerQuery)
    Write-SLICollectorProgress -Phase base_computers_end -UserCount $baseUsers.Count -ComputerCount $baseComputers.Count
    if ($baseComputers.Count -gt $computerLimit) { throw "ad_snapshot_base_v1_computer_record_bound_exceeded" }
    if ($baseClock.Elapsed.TotalSeconds -gt 300) { throw "ad_snapshot_base_v1_time_bound_exceeded" }
    foreach ($baseUser in $baseUsers) {
        if (-not $baseUserGuidAllowlist.Add(([guid]$baseUser.ObjectGUID).ToString().ToLowerInvariant())) { throw "ad_snapshot_base_v1_duplicate_user_guid" }
    }
    foreach ($baseComputer in $baseComputers) {
        if (-not $baseComputerGuidAllowlist.Add(([guid]$baseComputer.ObjectGUID).ToString().ToLowerInvariant())) { throw "ad_snapshot_base_v1_duplicate_computer_guid" }
    }
    Write-SLICollectorProgress -Phase raw_serialization_start -UserCount $baseUsers.Count -ComputerCount $baseComputers.Count
    $baseRowsBytes = Measure-SLIBaseRowsJsonBytes -Users $baseUsers -Computers $baseComputers -UserProperties $baseUserProperties -ComputerProperties $baseComputerProperties -ByteLimit $MaxBundleBytes
    Write-SLICollectorProgress -Phase raw_serialization_end -UserCount $baseUsers.Count -ComputerCount $baseComputers.Count
    if ($baseRowsBytes -gt $MaxBundleBytes) { throw "ad_snapshot_base_v1_byte_bound_exceeded" }
}
# P4-END-AD-SNAPSHOT-BASE-V1

if ($requestedSections -contains "directory_accounts") {
    Write-SLICollectorProgress -Phase accounts_start -RecordCount $records.Count
    try {
        $remaining = $MaxRecords - $records.Count
        $approvedLimit = [int][math]::Min($remaining, $MaxDirectoryAccounts)
        $userLimit = if ($MaxDirectoryUsers -gt 0) { $MaxDirectoryUsers } else { [int][math]::Floor($approvedLimit / 2) }
        $computerLimit = if ($MaxDirectoryComputers -gt 0) { $MaxDirectoryComputers } else { $approvedLimit - $userLimit }
        if ($userLimit -lt 1 -or $computerLimit -lt 1) {
            throw "Directory object budget must reserve at least one user and one computer."
        }
        if (($userLimit + $computerLimit) -gt $approvedLimit) {
            throw "Independent directory object budgets exceed the approved total limit."
        }
        $userProperties = @(
            "ObjectGUID", "SID", "SamAccountName", "UserPrincipalName", "DistinguishedName", "Enabled",
            "whenCreated", "LastLogonDate", "PasswordLastSet", "PasswordNeverExpires", "Department", "Title", "EmailAddress",
            "AdminCount", "AccountExpirationDate", "LockedOut", "DisplayName", "GivenName", "Surname", "CanonicalName",
            "Company", "Manager", "EmployeeID", "EmployeeNumber", "Office", "OfficePhone", "MobilePhone", "IPPhone", "Fax",
            "StreetAddress", "City", "State", "PostalCode", "Country", "Description", "ProxyAddresses", "OtherTelephone",
            "mail", "servicePrincipalName", "scriptPath", "homeDirectory", "homeDrive", "profilePath",
            "PasswordExpired", "PasswordNotRequired", "CannotChangePassword",
            "SmartcardLogonRequired", "DoesNotRequirePreAuth", "TrustedForDelegation", "TrustedToAuthForDelegation", "UseDESKeyOnly",
            "AccountNotDelegated", "AllowReversiblePasswordEncryption", "userAccountControl", "msDS-SupportedEncryptionTypes",
            "whenChanged", "LastBadPasswordAttempt", "badPwdCount", "msDS-UserPasswordExpiryTimeComputed", "msDS-ResultantPSO"
        )
        # In AD schema `computer` inherits from `user`.  objectClass=user alone
        # therefore admits computer accounts into a user inventory.
        $users = if ($isBaseProfile) { $baseUsers } else { @(Get-ADUser -Server $DirectoryServer -LDAPFilter "(&(objectCategory=person)(objectClass=user))" -SearchBase $SearchBase -SearchScope Subtree -ResultSetSize ($userLimit + 1) -Properties $userProperties -ErrorAction Stop) }
        $usersTruncated = (-not $isBaseProfile) -and $users.Count -gt $userLimit
        if (-not $isBaseProfile) { $users = @($users | Select-Object -First $userLimit) }
        $passwordExpiryIncompleteCount = 0
        foreach ($user in $users) {
            $record = ConvertTo-AdEntityRecord -Object $user -DomainSid $domainSid -ObservedAtUtc $observedAt -Section "directory_accounts"
            if ([string]$record.attributes.password_expiry_status -notin @("observed", "not_applicable")) {
                $passwordExpiryIncompleteCount += 1
            }
            [void](Write-EntityRecord -Record $record -Records $records -EntityRecords $entityRecords -RecordLimit $MaxRecords)
        }
        $computerProperties = @(
            "ObjectGUID", "SID", "SamAccountName", "DistinguishedName", "Enabled",
            "whenCreated", "LastLogonDate", "DNSHostName", "OperatingSystem", "OperatingSystemVersion", "OperatingSystemServicePack",
            "CanonicalName", "Description", "Location", "ManagedBy", "PasswordLastSet", "whenChanged",
            "servicePrincipalName", "TrustedForDelegation", "TrustedToAuthForDelegation", "userAccountControl"
        )
        $computers = if ($isBaseProfile) { $baseComputers } else { @(Get-ADComputer -Server $DirectoryServer -LDAPFilter "(objectClass=computer)" -SearchBase $SearchBase -SearchScope Subtree -ResultSetSize ($computerLimit + 1) -Properties $computerProperties -ErrorAction Stop) }
        $computersTruncated = (-not $isBaseProfile) -and $computers.Count -gt $computerLimit
        if (-not $isBaseProfile) { $computers = @($computers | Select-Object -First $computerLimit) }
        foreach ($computer in $computers) {
            $record = ConvertTo-AdEntityRecord -Object $computer -DomainSid $domainSid -ObservedAtUtc $observedAt -Section "directory_accounts"
            $computerName = [string](Get-OptionalProperty -Object $computer -Name "Name")
            if ($technicalServerSet.Contains($computerName)) {
                $technical = Get-BoundedTechnicalInventory -ComputerName $computerName -TimeoutSeconds $TechnicalInventoryTimeoutSeconds
                $record.attributes["technical_inventory_status"] = [string]$technical.status
                $record.attributes["technical_inventory_observed_at_utc"] = $observedAt
                $record.attributes["ip_addresses"] = @($technical.ip_addresses)
                $record.attributes["logical_disks"] = @($technical.logical_disks)
                if ([string]$technical.status -ne "complete") {
                    Write-DataQualityRecord -Section "directory_accounts" -Code ("technical_inventory_{0}_{1}" -f $computerName.ToLowerInvariant(), [string]$technical.status) -Message ("Read-only technical inventory is unavailable for {0}." -f $computerName) -ObservedAtUtc $observedAt -Records $records -RecordLimit $MaxRecords
                }
            }
            [void](Write-EntityRecord -Record $record -Records $records -EntityRecords $entityRecords -RecordLimit $MaxRecords)
        }
        if ($usersTruncated -or $computersTruncated) {
            $sectionStatus["directory_accounts"] = "partial"
            Write-DataQualityRecord -Section "directory_accounts" -Code "directory_accounts_truncated" -Message ("Directory inventory reached independent limits: users={0}, computers={1}." -f $userLimit, $computerLimit) -ObservedAtUtc $observedAt -Records $records -RecordLimit $MaxRecords
        }
        if ($passwordExpiryIncompleteCount -gt 0) {
            $sectionStatus["directory_accounts"] = "partial"
            Write-DataQualityRecord -Section "directory_accounts" -Code "password_expiry_partial" -Message ("Password expiry was not fully evaluable for {0} collected users; per-user source states were preserved." -f $passwordExpiryIncompleteCount) -ObservedAtUtc $observedAt -Records $records -RecordLimit $MaxRecords
        }
    }
    catch {
        $sectionStatus["directory_accounts"] = if (@($records | Where-Object { $_.section -eq "directory_accounts" }).Count -gt 0) { "partial" } else { "failed" }
        Write-DataQualityRecord -Section "directory_accounts" -Code "directory_accounts_failed" -Message $_.Exception.Message -ObservedAtUtc $observedAt -Records $records -RecordLimit $MaxRecords
    }
}

if ($requestedSections -contains "directory_accounts") { Write-SLICollectorProgress -Phase accounts_end -RecordCount $records.Count }
if ($requestedSections -contains "directory_group_graph") {
    Write-SLICollectorProgress -Phase group_graph_start -RecordCount $records.Count
    try {
        $domainSearchBase = [string](Get-OptionalProperty -Object $domainData -Name "DistinguishedName")
        $groupLimit = [int][math]::Min($MaxDirectoryGroups, [math]::Max(1, $MaxRecords - 2))
        $groups = @(Get-ADGroup -Server $DirectoryServer -Filter * -SearchBase $domainSearchBase -SearchScope Subtree -ResultSetSize ($groupLimit + 1) -Properties ObjectGUID, SID, SamAccountName, DistinguishedName, CanonicalName, GroupCategory, GroupScope, ManagedBy, Description, MemberOf -ErrorAction Stop)
        $groupsTruncated = $groups.Count -gt $groupLimit
        $groups = @($groups | Sort-Object ObjectGUID | Select-Object -First $groupLimit)

        $groupByDn = @{}
        $groupBySid = @{}
        $groupRecordByDn = @{}
        foreach ($group in $groups) {
            $record = ConvertTo-AdEntityRecord -Object $group -DomainSid $domainSid -ObservedAtUtc $observedAt -Section "directory_group_graph"
            $record.attributes = ConvertTo-SparseAttributes -Attributes ([ordered]@{
                display_name = [string](Get-OptionalProperty -Object $group -Name "Name")
                sam_account_name = [string](Get-OptionalProperty -Object $group -Name "SamAccountName")
                distinguished_name = [string](Get-OptionalProperty -Object $group -Name "DistinguishedName")
                canonical_name = [string](Get-OptionalProperty -Object $group -Name "CanonicalName")
                object_class = "group"
                group_category = [string](Get-OptionalProperty -Object $group -Name "GroupCategory")
                group_scope = [string](Get-OptionalProperty -Object $group -Name "GroupScope")
                managed_by = [string](Get-OptionalProperty -Object $group -Name "ManagedBy")
                description = [string](Get-OptionalProperty -Object $group -Name "Description")
            })
            $key = Write-EntityRecord -Record $record -Records $records -EntityRecords $entityRecords -RecordLimit $MaxRecords
            $dn = [string]$group.DistinguishedName
            $sidText = [string]$group.SID
            $groupByDn[$dn] = $key
            $groupBySid[$sidText] = $key
            $groupRecordByDn[$dn] = $record
        }

        $configuredUserLimit = if ($MaxDirectoryUsers -gt 0) { $MaxDirectoryUsers } else { [int][math]::Floor($MaxDirectoryAccounts / 2) }
        $availableUserSlots = [math]::Max(1, $MaxRecords - $records.Count - 1)
        $userLimit = [int][math]::Min($configuredUserLimit, $availableUserSlots)
        if ($isBaseProfile) { $graphUsers = $baseUsers }
        else { $graphUsers = @(Get-ADUser -Server $DirectoryServer -LDAPFilter "(&(objectCategory=person)(objectClass=user))" -SearchBase $SearchBase -SearchScope Subtree -ResultSetSize ($userLimit + 1) -Properties ObjectGUID, SID, SamAccountName, DistinguishedName, DisplayName, MemberOf, PrimaryGroupID -ErrorAction Stop) }
        $usersTruncated = (-not $isBaseProfile) -and ($graphUsers.Count -gt $userLimit -or $userLimit -lt $configuredUserLimit)
        if (-not $isBaseProfile) { $graphUsers = @($graphUsers | Sort-Object ObjectGUID | Select-Object -First $userLimit) }
        $configuredComputerLimit = if ($MaxDirectoryComputers -gt 0) { $MaxDirectoryComputers } else { [math]::Max(1, $MaxDirectoryAccounts - $configuredUserLimit) }
        $graphComputerLimit = [int][math]::Min($configuredComputerLimit, [math]::Max(1, $MaxRecords - $records.Count - $graphUsers.Count - 1))
        if ($isBaseProfile) { $graphComputers = $baseComputers; $graphComputersTruncated = $false }
        else {
            $graphComputers = @(Get-ADComputer -Server $DirectoryServer -Filter * -SearchBase $SearchBase -SearchScope Subtree -ResultSetSize ($graphComputerLimit + 1) -Properties ObjectGUID, SID, SamAccountName, DistinguishedName, MemberOf, PrimaryGroupID -ErrorAction Stop)
            $graphComputersTruncated = $graphComputers.Count -gt $graphComputerLimit -or $graphComputerLimit -lt $configuredComputerLimit
            $graphComputers = @($graphComputers | Sort-Object ObjectGUID | Select-Object -First $graphComputerLimit)
        }
        $graphPrincipals = @($graphUsers) + @($graphComputers)
        $userRecordByDn = @{}
        foreach ($user in $graphPrincipals) {
            $record = ConvertTo-AdEntityRecord -Object $user -DomainSid $domainSid -ObservedAtUtc $observedAt -Section "directory_group_graph"
            $record.attributes = ConvertTo-SparseAttributes -Attributes ([ordered]@{
                display_name = if (Get-OptionalProperty -Object $user -Name "DisplayName") { [string]$user.DisplayName } else { [string]$user.Name }
                sam_account_name = [string]$user.SamAccountName
                distinguished_name = [string]$user.DistinguishedName
                object_class = if ([string]$user.ObjectClass -eq "computer") { "computer" } else { "user" }
                primary_group_id = Get-OptionalProperty -Object $user -Name "PrimaryGroupID"
            })
            [void](Write-EntityRecord -Record $record -Records $records -EntityRecords $entityRecords -RecordLimit $MaxRecords)
            $userRecordByDn[[string]$user.DistinguishedName] = $entityRecords[[string]$record.record_key]
        }

        $membershipCount = 0
        $unresolvedCount = 0
        $relationBudgetReached = $false
        foreach ($group in $groups) {
            $sourceDn = [string]$group.DistinguishedName
            $sourceKey = [string]$groupByDn[$sourceDn]
            $unresolvedParents = [System.Collections.Generic.List[string]]::new()
            foreach ($parentDnValue in @($group.MemberOf)) {
                $parentDn = [string]$parentDnValue
                if (-not $groupByDn.ContainsKey($parentDn)) {
                    $unresolvedCount += 1
                    if ($unresolvedParents.Count -lt 256) { $unresolvedParents.Add($parentDn) }
                    continue
                }
                if ($membershipCount -ge $MaxDirectoryMemberships -or $records.Count -ge $MaxRecords) {
                    $relationBudgetReached = $true
                    break
                }
                $targetKey = [string]$groupByDn[$parentDn]
                $relationKey = ("member-of:directory-group-graph:{0}:{1}:direct" -f $sourceKey, $targetKey)
                if ($seenRelations.Add($relationKey)) {
                    $records.Add([ordered]@{
                        record_type = "relation"; record_key = $relationKey; section = "directory_group_graph"; observed_at_utc = $observedAt
                        relation_kind = "member_of"; source_record_key = $sourceKey; target_record_key = $targetKey
                        attributes = [ordered]@{ membership_type = "direct"; source_section = "directory_group_graph" }
                    })
                    $membershipCount += 1
                }
            }
            if ($unresolvedParents.Count -gt 0) {
                $groupRecordByDn[$sourceDn].attributes["unresolved_parent_dns"] = @($unresolvedParents)
            }
            if ($relationBudgetReached) { break }
        }

        if (-not $relationBudgetReached) {
            foreach ($user in $graphPrincipals) {
                $userDn = [string]$user.DistinguishedName
                $record = $userRecordByDn[$userDn]
                $sourceKey = [string]$record.record_key
                $unresolvedGroups = [System.Collections.Generic.List[string]]::new()
                foreach ($groupDnValue in @($user.MemberOf)) {
                    $groupDn = [string]$groupDnValue
                    if (-not $groupByDn.ContainsKey($groupDn)) {
                        $unresolvedCount += 1
                        if ($unresolvedGroups.Count -lt 256) { $unresolvedGroups.Add($groupDn) }
                        continue
                    }
                    if ($membershipCount -ge $MaxDirectoryMemberships -or $records.Count -ge $MaxRecords) {
                        $relationBudgetReached = $true
                        break
                    }
                    $targetKey = [string]$groupByDn[$groupDn]
                    $relationKey = ("member-of:directory-group-graph:{0}:{1}:direct" -f $sourceKey, $targetKey)
                    if ($seenRelations.Add($relationKey)) {
                        $records.Add([ordered]@{
                            record_type = "relation"; record_key = $relationKey; section = "directory_group_graph"; observed_at_utc = $observedAt
                            relation_kind = "member_of"; source_record_key = $sourceKey; target_record_key = $targetKey
                            attributes = [ordered]@{ membership_type = "direct"; source_section = "directory_group_graph" }
                        })
                        $membershipCount += 1
                    }
                }
                if ($unresolvedGroups.Count -gt 0) { $record.attributes["unresolved_group_dns"] = @($unresolvedGroups) }
                $primaryGroupId = Get-OptionalProperty -Object $user -Name "PrimaryGroupID"
                if ($null -ne $primaryGroupId) {
                    $primarySid = ("{0}-{1}" -f $domainSid, [int64]$primaryGroupId)
                    if ($groupBySid.ContainsKey($primarySid)) {
                        if ($membershipCount -ge $MaxDirectoryMemberships -or $records.Count -ge $MaxRecords) {
                            $relationBudgetReached = $true
                        }
                        else {
                            $targetKey = [string]$groupBySid[$primarySid]
                            $relationKey = ("member-of:directory-group-graph:{0}:{1}:primary" -f $sourceKey, $targetKey)
                            if ($seenRelations.Add($relationKey)) {
                                $records.Add([ordered]@{
                                    record_type = "relation"; record_key = $relationKey; section = "directory_group_graph"; observed_at_utc = $observedAt
                                    relation_kind = "member_of"; source_record_key = $sourceKey; target_record_key = $targetKey
                                    attributes = [ordered]@{ membership_type = "primary"; source_section = "directory_group_graph" }
                                })
                                $membershipCount += 1
                            }
                        }
                    }
                    else {
                        $record.attributes["unresolved_primary_group_sid"] = $primarySid
                        $unresolvedCount += 1
                    }
                }
                if ($relationBudgetReached) { break }
            }
        }

        if ($groupsTruncated -or $usersTruncated -or $graphComputersTruncated -or $relationBudgetReached -or $unresolvedCount -gt 0) {
            $sectionStatus["directory_group_graph"] = "partial"
        }
        if ($groupsTruncated -or $usersTruncated -or $graphComputersTruncated) {
            Write-DataQualityRecord -Section "directory_group_graph" -Code "directory_group_graph_truncated" -Message ("Group graph reached bounded entity limits: users={0}, groups={1}, computers={2}." -f $userLimit, $groupLimit, $graphComputerLimit) -ObservedAtUtc $observedAt -Records $records -RecordLimit $MaxRecords
        }
        if ($relationBudgetReached) {
            Write-DataQualityRecord -Section "directory_group_graph" -Code "directory_group_memberships_truncated" -Message ("Group graph reached the bounded membership limit of {0}." -f $MaxDirectoryMemberships) -ObservedAtUtc $observedAt -Records $records -RecordLimit $MaxRecords
        }
        if ($unresolvedCount -gt 0) {
            Write-DataQualityRecord -Section "directory_group_graph" -Code "directory_group_links_unresolved" -Message ("The collector preserved {0} unresolved direct or primary group links." -f $unresolvedCount) -ObservedAtUtc $observedAt -Records $records -RecordLimit $MaxRecords
        }
    }
    catch {
        $sectionStatus["directory_group_graph"] = if (@($records | Where-Object { $_.section -eq "directory_group_graph" }).Count -gt 0) { "partial" } else { "failed" }
        Write-DataQualityRecord -Section "directory_group_graph" -Code "directory_group_graph_failed" -Message $_.Exception.Message -ObservedAtUtc $observedAt -Records $records -RecordLimit $MaxRecords
    }
}

if ($requestedSections -contains "directory_group_graph") { Write-SLICollectorProgress -Phase group_graph_end -RecordCount $records.Count }
if ($requestedSections -contains "directory_exact_logon") {
    Write-SLICollectorProgress -Phase exact_logon_start -RecordCount $records.Count
    try {
        $configuredUserLimit = if ($MaxDirectoryUsers -gt 0) { $MaxDirectoryUsers } else { [int][math]::Floor($MaxDirectoryAccounts / 2) }
        $userLimit = [int][math]::Min($configuredUserLimit, [math]::Max(1, $MaxRecords - 1))
        if ($isBaseProfile) { $baseUsersForExactLogon = $baseUsers }
        else { $baseUsersForExactLogon = @(Get-ADUser -Server $DirectoryServer -LDAPFilter "(&(objectCategory=person)(objectClass=user))" -SearchBase $SearchBase -SearchScope Subtree -ResultSetSize ($userLimit + 1) -Properties ObjectGUID, SID, SamAccountName, DistinguishedName, DisplayName -ErrorAction Stop) }
        $baseUsersTruncated = (-not $isBaseProfile) -and ($baseUsersForExactLogon.Count -gt $userLimit -or $userLimit -lt $configuredUserLimit)
        if (-not $isBaseProfile) { $baseUsersForExactLogon = @($baseUsersForExactLogon | Sort-Object ObjectGUID | Select-Object -First $userLimit) }
        $domainControllers = @(Get-ADDomainController -Server $DirectoryServer -Filter * -ErrorAction Stop | Sort-Object HostName)
        if ($domainControllers.Count -eq 0) { throw "No domain controllers were discovered for exact lastLogon collection." }

        $maxLogonByGuid = @{}
        $successfulDcs = [System.Collections.Generic.List[string]]::new()
        $failedDcs = [System.Collections.Generic.List[string]]::new()
        $exactProgressCount = 0
        Write-SLICollectorProgress -Phase exact_logon_queries -ExactQueries 0 -DcCount $domainControllers.Count -UserCount $baseUsersForExactLogon.Count
        foreach ($domainController in $domainControllers) {
            $dcName = [string]$domainController.HostName
            try {
                $rows = if ($isBaseProfile) {
                    @(Get-SLIExactLogonRows -Users $baseUsersForExactLogon -Server $dcName -SearchBase $SearchBase -QueryCount ([ref]$exactProgressCount) -OnQuery {
                        param($queryCount)
                        Write-SLICollectorProgress -Phase exact_logon_queries -ExactQueries $queryCount -DcCount $domainControllers.Count -UserCount $baseUsersForExactLogon.Count
                    })
                } else {
                    @(Get-ADUser -Server $dcName -LDAPFilter "(&(objectCategory=person)(objectClass=user))" -SearchBase $SearchBase -SearchScope Subtree -ResultSetSize ($userLimit + 1) -Properties ObjectGUID, lastLogon -ErrorAction Stop)
                }
                if ((-not $isBaseProfile) -and $rows.Count -gt $userLimit) {
                    $failedDcs.Add($dcName)
                    continue
                }
                foreach ($row in $rows) {
                    $guidKey = ([guid]$row.ObjectGUID).ToString().ToLowerInvariant()
                    if ($isBaseProfile -and -not $baseUserGuidAllowlist.Contains($guidKey)) { throw "exact_logon_identity_outside_base_allowlist" }
                    $rawLastLogon = Get-OptionalProperty -Object $row -Name "lastLogon"
                    if ($null -eq $rawLastLogon) { continue }
                    $value = [int64]$rawLastLogon
                    if ($value -gt 0 -and (-not $maxLogonByGuid.ContainsKey($guidKey) -or $value -gt [int64]$maxLogonByGuid[$guidKey])) {
                        $maxLogonByGuid[$guidKey] = $value
                    }
                }
                $successfulDcs.Add($dcName)
            }
            catch {
                $failedDcs.Add($dcName)
            }
        }

        Write-SLICollectorProgress -Phase exact_logon_queried -ExactQueries $exactProgressCount -DcCount $domainControllers.Count -UserCount $baseUsersForExactLogon.Count
        $coverageStatus = if ($successfulDcs.Count -eq 0) { "failed" } elseif ($failedDcs.Count -gt 0) { "partial" } else { "observed" }
        foreach ($user in $baseUsersForExactLogon) {
            $guidKey = ([guid]$user.ObjectGUID).ToString().ToLowerInvariant()
            $exactUtc = if ($maxLogonByGuid.ContainsKey($guidKey)) { ConvertFrom-FileTimeUtc -Value $maxLogonByGuid[$guidKey] } else { $null }
            $userStatus = if ($coverageStatus -eq "failed") {
                "failed"
            }
            elseif ($coverageStatus -eq "partial") {
                "partial"
            }
            elseif ($null -ne $exactUtc) {
                "observed"
            }
            else {
                "no_record"
            }
            $record = ConvertTo-AdEntityRecord -Object $user -DomainSid $domainSid -ObservedAtUtc $observedAt -Section "directory_exact_logon"
            $record.attributes = ConvertTo-SparseAttributes -Attributes ([ordered]@{
                display_name = if ($user.DisplayName) { [string]$user.DisplayName } else { [string]$user.Name }
                sam_account_name = [string]$user.SamAccountName
                distinguished_name = [string]$user.DistinguishedName
                object_class = "user"
                exact_last_logon_utc = $exactUtc
                exact_last_logon_status = $userStatus
                exact_last_logon_discovered_dc_count = $domainControllers.Count
                exact_last_logon_successful_dc_count = $successfulDcs.Count
                exact_last_logon_failed_dcs = @($failedDcs)
            })
            $record.attributes["exact_last_logon_failed_dcs"] = @($failedDcs)
            [void](Write-EntityRecord -Record $record -Records $records -EntityRecords $entityRecords -RecordLimit $MaxRecords)
        }

        if ($coverageStatus -ne "observed" -or $baseUsersTruncated) {
            $sectionStatus["directory_exact_logon"] = if ($coverageStatus -eq "failed") { "failed" } else { "partial" }
        }
        if ($baseUsersTruncated) {
            Write-DataQualityRecord -Section "directory_exact_logon" -Code "exact_last_logon_users_truncated" -Message ("Exact lastLogon collection reached the bounded user limit of {0}." -f $userLimit) -ObservedAtUtc $observedAt -Records $records -RecordLimit $MaxRecords
        }
        if ($failedDcs.Count -gt 0) {
            Write-DataQualityRecord -Section "directory_exact_logon" -Code "exact_last_logon_dc_coverage_partial" -Message ("Exact lastLogon coverage: successful DCs={0}, failed or truncated DCs={1}." -f $successfulDcs.Count, $failedDcs.Count) -ObservedAtUtc $observedAt -Records $records -RecordLimit $MaxRecords
        }
    }
    catch {
        $sectionStatus["directory_exact_logon"] = if (@($records | Where-Object { $_.section -eq "directory_exact_logon" }).Count -gt 0) { "partial" } else { "failed" }
        Write-DataQualityRecord -Section "directory_exact_logon" -Code "directory_exact_logon_failed" -Message $_.Exception.Message -ObservedAtUtc $observedAt -Records $records -RecordLimit $MaxRecords
    }
}

if ($requestedSections -contains "directory_exact_logon") { Write-SLICollectorProgress -Phase exact_logon_end -RecordCount $records.Count }
if ($requestedSections -contains "vpn_membership") {
    try {
        $vpnMembersRead = 0
        $unsupportedPrincipalCount = 0
        $pendingGroups = [System.Collections.Generic.Queue[string]]::new()
        $processedGroups = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($reference in $vpnReferences) { $pendingGroups.Enqueue($reference) }
        while ($pendingGroups.Count -gt 0) {
            $groupReference = $pendingGroups.Dequeue()
            $group = Get-ADGroup -Server $DirectoryServer -Identity $groupReference -Properties ObjectGUID, SID, SamAccountName, DistinguishedName -ErrorAction Stop
            if (-not ([string]$group.DistinguishedName).EndsWith($SearchBase, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "Selected VPN group is outside SearchBase."
            }
            if (-not $processedGroups.Add([string]$group.DistinguishedName)) { continue }
            if ($vpnReferences -contains [string]$groupReference) { $vpnGroupSids.Add([string]$group.SID) }
            $groupRecord = ConvertTo-AdEntityRecord -Object $group -DomainSid $domainSid -ObservedAtUtc $observedAt -Section "vpn_membership"
            $groupKey = Write-EntityRecord -Record $groupRecord -Records $records -EntityRecords $entityRecords -RecordLimit $MaxRecords

            $remainingRecords = $MaxRecords - $records.Count
            $remainingMemberBudget = [math]::Max(0, $MaxVpnMembers - $vpnMembersRead)
            $memberCapacity = [int][math]::Min([math]::Floor([math]::Max(0, $remainingRecords) / 2), $remainingMemberBudget)
            $queryLimit = $memberCapacity + 1
            $escapedGroupDn = ConvertTo-LdapFilterValue -Value ([string]$group.DistinguishedName)
            $members = @(Get-ADObject -Server $DirectoryServer -LDAPFilter ("(memberOf={0})" -f $escapedGroupDn) -SearchBase $SearchBase -SearchScope Subtree -ResultSetSize $queryLimit -Properties ObjectGUID, objectSid, SamAccountName, DistinguishedName, objectClass -ErrorAction Stop)
            if ($members.Count -gt $memberCapacity) { throw "VPN member query exceeded the approved record budget." }
            foreach ($member in $members) {
                $vpnMembersRead += 1
                $resolved = switch ([string]$member.objectClass) {
                    "user" {
                        Get-ADUser -Server $DirectoryServer -Identity $member.DistinguishedName -Properties ObjectGUID, SID, SamAccountName, UserPrincipalName, DistinguishedName, Enabled, whenCreated, LastLogonDate, PasswordLastSet, PasswordNeverExpires, Department, Title, EmailAddress, AdminCount, AccountExpirationDate, LockedOut -ErrorAction Stop
                    }
                    "group" { Get-ADGroup -Server $DirectoryServer -Identity $member.DistinguishedName -Properties ObjectGUID, SID, SamAccountName, DistinguishedName -ErrorAction Stop }
                    "contact" {
                        Get-ADObject -Server $DirectoryServer -Identity $member.DistinguishedName -Properties ObjectGUID, objectSid, SamAccountName, DistinguishedName, objectClass -ErrorAction Stop
                    }
                    default {
                        $unsupportedPrincipalCount += 1
                        Get-ADObject -Server $DirectoryServer -Identity $member.DistinguishedName -Properties ObjectGUID, objectSid, SamAccountName, DistinguishedName, objectClass -ErrorAction Stop
                    }
                }
                $memberRecord = ConvertTo-AdEntityRecord -Object $resolved -DomainSid $domainSid -ObservedAtUtc $observedAt -Section "vpn_membership"
                $memberKey = Write-EntityRecord -Record $memberRecord -Records $records -EntityRecords $entityRecords -RecordLimit $MaxRecords
                if ([string]$member.objectClass -eq "group" -and -not $processedGroups.Contains([string]$resolved.DistinguishedName)) {
                    $pendingGroups.Enqueue([string]$resolved.DistinguishedName)
                }
                $relationKey = ("member-of:vpn:{0}:{1}" -f $memberKey, $groupKey)
                if ($seenRelations.Add($relationKey)) {
                    if ($records.Count -ge $MaxRecords) { throw "AD audit context record budget exceeded." }
                    $records.Add([ordered]@{
                        record_type = "relation"
                        record_key = $relationKey
                        section = "vpn_membership"
                        observed_at_utc = $observedAt
                        relation_kind = "member_of"
                        source_record_key = $memberKey
                        target_record_key = $groupKey
                        attributes = [ordered]@{ membership_type = "direct"; source_section = "vpn_membership" }
                    })
                }
            }
        }
        if ($unsupportedPrincipalCount -gt 0) {
            $sectionStatus["vpn_membership"] = "partial"
            Write-DataQualityRecord -Section "vpn_membership" -Code "unsupported_principal_kind" -Message ("VPN membership contains {0} principals that are not local users or groups." -f $unsupportedPrincipalCount) -ObservedAtUtc $observedAt -Records $records -RecordLimit $MaxRecords
        }
    }
    catch {
        $sectionStatus["vpn_membership"] = if (@($records | Where-Object { $_.section -eq "vpn_membership" }).Count -gt 0) { "partial" } else { "failed" }
        Write-DataQualityRecord -Section "vpn_membership" -Code "vpn_membership_failed" -Message $_.Exception.Message -ObservedAtUtc $observedAt -Records $records -RecordLimit $MaxRecords
    }
}

if ($requestedSections -contains "domain_posture") {
    try {
        $posture = Get-SLIDomainPostureRecords -DirectoryServer $DirectoryServer -Domain $Domain -DomainSid $domainSid -ObservedAtUtc $observedAt
        foreach ($record in @($posture.records)) {
            [void](Write-EntityRecord -Record $record -Records $records -EntityRecords $entityRecords -RecordLimit $MaxRecords)
        }
        foreach ($collectionError in @($posture.errors)) {
            $sectionStatus["domain_posture"] = "partial"
            Write-DataQualityRecord -Section "domain_posture" -Code ([string]$collectionError.code) -Message ([string]$collectionError.message) -ObservedAtUtc $observedAt -Records $records -RecordLimit $MaxRecords
        }
    }
    catch {
        $sectionStatus["domain_posture"] = if (@($records | Where-Object { $_.section -eq "domain_posture" }).Count -gt 0) { "partial" } else { "failed" }
        Write-DataQualityRecord -Section "domain_posture" -Code "domain_posture_failed" -Message $_.Exception.Message -ObservedAtUtc $observedAt -Records $records -RecordLimit $MaxRecords
    }
}

if ($requestedSections -contains "domain_health") {
    try {
        $health = Get-SLIDomainHealthRecords -DirectoryServer $DirectoryServer -Domain $Domain -DomainSid $domainSid -ObservedAtUtc $observedAt
        foreach ($record in @($health.records)) {
            [void](Write-EntityRecord -Record $record -Records $records -EntityRecords $entityRecords -RecordLimit $MaxRecords)
        }
        foreach ($collectionError in @($health.errors)) {
            $sectionStatus["domain_health"] = "partial"
            Write-DataQualityRecord -Section "domain_health" -Code ([string]$collectionError.code) -Message ([string]$collectionError.message) -ObservedAtUtc $observedAt -Records $records -RecordLimit $MaxRecords
        }
    }
    catch {
        $sectionStatus["domain_health"] = if (@($records | Where-Object { $_.section -eq "domain_health" }).Count -gt 0) { "partial" } else { "failed" }
        Write-DataQualityRecord -Section "domain_health" -Code "domain_health_failed" -Message $_.Exception.Message -ObservedAtUtc $observedAt -Records $records -RecordLimit $MaxRecords
    }
}

if ($CollectionProfile -eq "gpo_governance_v4") {
    $gpoV2CollectorPath = Join-Path -Path $PSScriptRoot -ChildPath "Export-AdGpoV2Snapshot.ps1"
    $gpoV2OutputPath = $OutputPath + ".gpo-v2.tmp.json"
    $gpoCompatibilityPath = $OutputPath + ".gpo-compatibility.tmp.json"
    try {
        & $gpoV2CollectorPath -Domain $Domain -Server $DirectoryServer `
            -OutputPath $gpoV2OutputPath -CompatibilityProjectionPath $gpoCompatibilityPath `
            -MaxSettingsPerGpo 2048 | Out-Null
        if (-not (Test-Path -LiteralPath $gpoV2OutputPath) -or -not (Test-Path -LiteralPath $gpoCompatibilityPath)) {
            throw "GPO V4 acquisition did not produce both required projections."
        }
        $gpoV2Snapshot = Get-Content -LiteralPath $gpoV2OutputPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $gpoCompatibilityProjection = Get-Content -LiteralPath $gpoCompatibilityPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($gpoV2Snapshot.demo -eq $true) { throw "Production GPO V2 collection returned demo data." }
        if ($gpoCompatibilityProjection.schema_version -ne "sli.ad-gpo.compatibility-projection/1.0") {
            throw "Unsupported GPO compatibility projection contract."
        }
        if ([string]$gpoCompatibilityProjection.domain_sid -ne $domainSid) {
            throw "GPO compatibility projection domain SID mismatch."
        }
        if ([string]$gpoCompatibilityProjection.observed_at_utc -ne [string]$gpoV2Snapshot.observed_at) {
            throw "GPO projections do not share one observation time."
        }
        $compatibilityRecords = @($gpoCompatibilityProjection.records)
        if (
            [int]$gpoCompatibilityProjection.record_count -ne $compatibilityRecords.Count -or
            $compatibilityRecords.Count -gt $MaxGpos -or
            ($records.Count + $compatibilityRecords.Count) -gt $MaxRecords
        ) { throw "GPO compatibility projection count is invalid or unbounded." }
        $compatibilityRecordsJson = ConvertTo-Json -InputObject $compatibilityRecords -Depth 20 -Compress
        $compatibilityHasher = [Security.Cryptography.SHA256]::Create()
        try {
            $compatibilityDigest = $compatibilityHasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($compatibilityRecordsJson))
        } finally { $compatibilityHasher.Dispose() }
        $compatibilityHash = -join ($compatibilityDigest | ForEach-Object { $_.ToString("x2") })
        if ($compatibilityHash -ne [string]$gpoCompatibilityProjection.records_sha256) {
            throw "GPO compatibility projection hash mismatch."
        }
        $observedAt = [string]$gpoCompatibilityProjection.observed_at_utc
        foreach ($compatibilityRecord in $compatibilityRecords) {
            if (
                [string]$compatibilityRecord.section -ne "gpo_governance" -or
                [string]$compatibilityRecord.observed_at_utc -ne $observedAt -or
                [string]$compatibilityRecord.identity.domain_sid -ne $domainSid
            ) { throw "GPO compatibility projection record boundary mismatch." }
            [void](Write-EntityRecord -Record $compatibilityRecord -Records $records -EntityRecords $entityRecords -RecordLimit $MaxRecords)
        }
        # A valid empty projection is not evidence of a successful inventory.
        # Missing status from older collectors is deliberately treated as partial.
        $gpoAcquisitionComplete = (
            $null -ne $gpoCompatibilityProjection.PSObject.Properties["collection_status"] -and
            $null -ne $gpoV2Snapshot.PSObject.Properties["collection_status"] -and
            $null -ne $gpoV2Snapshot.PSObject.Properties["source_states"] -and
            $null -ne $gpoV2Snapshot.source_states -and
            $null -ne $gpoV2Snapshot.source_states.PSObject.Properties["gpo_list"] -and
            $null -ne $gpoV2Snapshot.source_states.PSObject.Properties["gpc_directory"] -and
            $null -ne $gpoV2Snapshot.source_states.gpo_list -and
            $null -ne $gpoV2Snapshot.source_states.gpc_directory -and
            $null -ne $gpoV2Snapshot.source_states.gpo_list.PSObject.Properties["status"] -and
            $null -ne $gpoV2Snapshot.source_states.gpc_directory.PSObject.Properties["status"] -and
            $gpoCompatibilityProjection.collection_status -eq "complete" -and
            $gpoV2Snapshot.collection_status -eq "complete" -and
            $gpoV2Snapshot.source_states.gpo_list.status -eq "observed" -and
            $gpoV2Snapshot.source_states.gpc_directory.status -eq "observed"
        )
        $sectionStatus["gpo_governance"] = if ($gpoAcquisitionComplete) { "complete" } else { "partial" }
    } finally {
        if (Test-Path -LiteralPath $gpoV2OutputPath) { Remove-Item -LiteralPath $gpoV2OutputPath -Force }
        if (Test-Path -LiteralPath $gpoCompatibilityPath) { Remove-Item -LiteralPath $gpoCompatibilityPath -Force }
    }
}

if ($requestedSections -contains "gpo_governance") {
    if ($CollectionProfile -ne "gpo_governance_v4") {
    try {
        $gpoModulePath = Join-Path $PSScriptRoot "GpoReportContract.psm1"
        Import-Module $gpoModulePath -Force -ErrorAction Stop
        $reportContract = Get-SLIGpoReportContract
        $permissionContract = Get-SLIGpoPermissionContract
        $combinedTimeLimitSeconds = 240
        $gpoClock = [Diagnostics.Stopwatch]::StartNew()
        $reportBytesTotal = 0L
        $permissionBytesTotal = 0L
        $permissionRowsTotal = 0L
        $domainSearchBase = [string](Get-OptionalProperty -Object $domainData -Name "DistinguishedName")
        if (-not $SearchBase.Equals($domainSearchBase, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "GPO governance requires SearchBase equal to the requested domain root."
        }
        $gpoSearchBase = "CN=Policies,CN=System,$domainSearchBase"
        $gpoQueryLimit = $MaxGpos + 1
        $gpos = @(Get-ADObject -Server $DirectoryServer -LDAPFilter "(objectClass=groupPolicyContainer)" -SearchBase $gpoSearchBase -SearchScope OneLevel -ResultSetSize $gpoQueryLimit -Properties Name, ObjectGUID, DisplayName, Description, whenCreated, whenChanged -ErrorAction Stop | Sort-Object ObjectGUID)
        if ($gpos.Count -gt $MaxGpos) { throw "GPO inventory exceeded the approved section budget." }
        if (
            $gpos.Count -gt $reportContract.policy_limit -or
            $gpos.Count -gt $permissionContract.policy_limit
        ) {
            throw "GPO count exceeded the proven report or permission contract."
        }
        if (($records.Count + $gpos.Count) -gt $MaxRecords) { throw "GPO inventory exceeded the approved record budget." }
        foreach ($gpo in $gpos) {
            if ($gpoClock.Elapsed.TotalSeconds -gt $combinedTimeLimitSeconds) {
                throw "gpo_governance_total_time_ceiling_exceeded"
            }
            # A GPC has two different identifiers: the LDAP objectGUID is the
            # stable directory-object identity, while GroupPolicy cmdlets
            # expect the policy GUID stored in the GPC Name/CN.
            $gpoDirectoryObjectGuid = [guid]$gpo.ObjectGUID
            $gpoPolicyGuid = [guid]([string]$gpo.Name)
            $reportRead = Invoke-SLIBoundedGpoReportRead -Guid $gpoPolicyGuid `
                -Domain $Domain -Server $DirectoryServer
            $permissionRead = Invoke-SLIBoundedGpoPermissionRead -Guid $gpoPolicyGuid `
                -Domain $Domain -Server $DirectoryServer
            $reportBytesTotal += [long]$reportRead.response_bytes
            $permissionBytesTotal += [long]$permissionRead.response_bytes
            $permissionRowsTotal += [long]$permissionRead.facts.permission_count
            if ($gpoClock.Elapsed.TotalSeconds -gt $combinedTimeLimitSeconds) {
                throw "gpo_governance_total_time_ceiling_exceeded"
            }
            if ($reportBytesTotal -gt $reportContract.total_response_bytes_limit) {
                throw "gpo_report_total_response_size_ceiling_exceeded"
            }
            if (
                $permissionBytesTotal -gt
                $permissionContract.total_response_bytes_limit
            ) {
                throw "gpo_permission_total_response_size_ceiling_exceeded"
            }
            if (
                $permissionRowsTotal -gt
                $permissionContract.total_permission_limit
            ) {
                throw "gpo_permission_total_count_ceiling_exceeded"
            }
            $recordKey = Get-StableRecordKey -DomainSid $domainSid -ObjectGuid $gpoDirectoryObjectGuid
            $description = Get-OptionalProperty -Object $gpo -Name "Description"
            $baseAttributes = [ordered]@{
                display_name = if ($gpo.DisplayName) { [string]$gpo.DisplayName } else { [string]$gpo.Name }
                sam_account_name = $null
                distinguished_name = $null
                enabled = $null
                object_class = "gpo"
                created_utc = ConvertTo-OptionalUtcText (Get-OptionalProperty -Object $gpo -Name "whenCreated")
                modified_utc = ConvertTo-OptionalUtcText (Get-OptionalProperty -Object $gpo -Name "whenChanged")
                description = if ($description -and $description.Length -gt 4096) { $description.Substring(0, 4096) } elseif ($description) { [string]$description } else { $null }
            }
            $attributes = Merge-SLIGpoGovernanceAttributes `
                -BaseAttributes $baseAttributes `
                -ReportFacts $reportRead.facts `
                -PermissionFacts $permissionRead.facts
            $record = [ordered]@{
                record_type = "entity"
                record_key = $recordKey
                section = "gpo_governance"
                observed_at_utc = $observedAt
                identity = [ordered]@{ kind = "gpo"; domain_sid = $domainSid; object_guid = $gpoDirectoryObjectGuid.ToString(); object_sid = $null }
                attributes = $attributes
            }
            [void](Write-EntityRecord -Record $record -Records $records -EntityRecords $entityRecords -RecordLimit $MaxRecords)
        }
        $sectionStatus["gpo_governance"] = "complete"
    }
    catch {
        $sectionStatus["gpo_governance"] = if (@($records | Where-Object { $_.section -eq "gpo_governance" }).Count -gt 0) { "partial" } else { "failed" }
        Write-DataQualityRecord -Section "gpo_governance" -Code "gpo_governance_failed" -Message $_.Exception.Message -ObservedAtUtc $observedAt -Records $records -RecordLimit $MaxRecords
    }
    }
}

$finished = [datetime]::UtcNow
$sectionRows = foreach ($section in $requestedSections) {
    [ordered]@{
        name = $section
        status = $sectionStatus[$section]
        record_count = @($records | Where-Object { $_.section -eq $section }).Count
        duration_ms = [int][math]::Round(($finished - $sectionStarted[$section]).TotalMilliseconds)
        error_code = if ($sectionStatus[$section] -eq "complete") { $null } else { "collection_incomplete" }
    }
}
$gpoV2Snapshot = if ($CollectionProfile -eq "gpo_governance_v4") { $gpoV2Snapshot } else { $null }
if ($CollectionProfile -eq "gpo_governance_v3") {
    $gpoV2CollectorPath = Join-Path -Path $PSScriptRoot -ChildPath "Export-AdGpoV2Snapshot.ps1"
    $gpoV2OutputPath = $OutputPath + ".gpo-v2.tmp.json"
    try {
        & $gpoV2CollectorPath -Domain $Domain -Server $DirectoryServer -OutputPath $gpoV2OutputPath -MaxSettingsPerGpo 2048 | Out-Null
        $gpoV2Snapshot = Get-Content -LiteralPath $gpoV2OutputPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($gpoV2Snapshot.demo -eq $true) { throw "Production GPO V2 collection returned demo data." }
    } finally {
        if (Test-Path -LiteralPath $gpoV2OutputPath) { Remove-Item -LiteralPath $gpoV2OutputPath -Force }
    }
}

$bundle = [ordered]@{
    schema_version = "ad-context-bundle/v1"
    source_pack_id = "sli.windows.ad-context"
    source_pack_version = "0.10.0"
    run_id = $RunId.ToString()
    mode = $Mode
    domain = [ordered]@{ sid = $domainSid; dns_name = $domainDnsName }
    scope = [ordered]@{
        search_base = $SearchBase
        privileged_group_sids = @()
        vpn_group_sids = @($vpnGroupSids | Sort-Object -Unique)
        collection_profile = $CollectionProfile
    }
    observed_at_utc = $observedAt
    sections = @($sectionRows)
    records = @($records | ForEach-Object { $_ })
}
if ($null -ne $gpoV2Snapshot) { $bundle["gpo_v2_snapshot"] = $gpoV2Snapshot }
if ($requestedSections -contains "directory_group_graph") {
    $bundle.scope["computer_membership_collected"] = $sectionStatus["directory_group_graph"] -eq "complete"
}

$parent = Split-Path -Parent $OutputPath
if ($parent -and -not (Test-Path -LiteralPath $parent)) { [System.IO.Directory]::CreateDirectory($parent) | Out-Null }
Write-SLICollectorProgress -Phase final_serialization_start -RecordCount $records.Count
$json = $bundle | ConvertTo-Json -Depth 12 -Compress
Write-SLICollectorProgress -Phase final_serialization_end -RecordCount $records.Count
$bundleBytes = [System.Text.Encoding]::UTF8.GetByteCount($json)
if ($bundleBytes -gt $MaxBundleBytes) {
    throw "AD audit context bundle byte budget exceeded: actual=$bundleBytes limit=$MaxBundleBytes."
}
[System.IO.File]::WriteAllText($OutputPath, $json, [System.Text.UTF8Encoding]::new($false))
$stream = [System.IO.File]::OpenRead($OutputPath)
$hasher = [System.Security.Cryptography.SHA256]::Create()
try { $hashBytes = $hasher.ComputeHash($stream) }
finally { $stream.Dispose(); $hasher.Dispose() }
$sha256 = ([System.BitConverter]::ToString($hashBytes)).Replace('-', '').ToLowerInvariant()
[System.IO.File]::WriteAllText(($OutputPath + ".sha256"), ($sha256 + "  " + [System.IO.Path]::GetFileName($OutputPath)), [System.Text.UTF8Encoding]::new($false))
Write-Output $OutputPath
Write-SLICollectorProgress -Phase completed -RecordCount $records.Count

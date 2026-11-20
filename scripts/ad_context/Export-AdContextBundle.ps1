[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [Parameter(Mandatory = $true)][guid]$RunId,
    [Parameter(Mandatory = $true)][string]$DirectoryServer,
    [Parameter(Mandatory = $true)][string]$SearchBase,
    [Parameter(Mandatory = $true)][string]$Domain,
    [Parameter(Mandatory = $true)][string]$Sections,
    [Parameter(Mandatory = $true)][ValidateSet("privileged_membership_v1")][string]$CollectionProfile,
    [Parameter(Mandatory = $true)][ValidateSet("full", "targeted", "reconcile")][string]$Mode,
    [Parameter(Mandatory = $true)][string]$PrivilegedGroups,
    [Parameter(Mandatory = $true)][ValidateRange(1, 50000)][int]$MaxRecords,
    [Parameter(Mandatory = $true)][ValidateRange(1024, 26214400)][int]$MaxBundleBytes
)

$ErrorActionPreference = "Stop"

# The same cutover setting as the Python legacy admission gate.
if ($null -ne $env:SLI_LEGACY_COLLECTION_DISABLED -and $env:SLI_LEGACY_COLLECTION_DISABLED.Trim() -ne "0") {
    throw "legacy collection disabled by SLI_LEGACY_COLLECTION_DISABLED; use agent modules and core job handlers"
}
Set-StrictMode -Version Latest

function ConvertTo-UtcText {
    param([Parameter(Mandatory = $true)][datetime]$Value)
    return $Value.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
}

function Get-StableRecordKey {
    param(
        [Parameter(Mandatory = $true)][string]$DomainSid,
        [Parameter(Mandatory = $true)][guid]$ObjectGuid
    )
    return ("ad:{0}:{1}" -f $DomainSid.ToLowerInvariant(), $ObjectGuid.ToString().ToLowerInvariant())
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

function ConvertTo-LdapFilterValue {
    param([Parameter(Mandatory = $true)][string]$Value)
    return $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace(([string][char]0), '\00')
}

function ConvertTo-EntityRecord {
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)][string]$DomainSid,
        [Parameter(Mandatory = $true)][string]$ObservedAtUtc
    )
    $kind = switch ([string]$Object.objectClass) {
        "group" { "ad_group" }
        "computer" { "ad_computer" }
        "user" { "ad_user" }
        default { "security_principal" }
    }
    $recordKey = Get-StableRecordKey -DomainSid $DomainSid -ObjectGuid ([guid]$Object.ObjectGUID)
    return [ordered]@{
        record_type = "entity"
        record_key = $recordKey
        section = "privileged_membership"
        observed_at_utc = $ObservedAtUtc
        identity = [ordered]@{
            kind = $kind
            domain_sid = $DomainSid
            object_guid = ([guid]$Object.ObjectGUID).ToString()
            object_sid = if (Get-OptionalProperty -Object $Object -Name "SID") { [string](Get-OptionalProperty -Object $Object -Name "SID") } elseif (Get-OptionalProperty -Object $Object -Name "objectSid") { [string](Get-OptionalProperty -Object $Object -Name "objectSid") } else { $null }
        }
        attributes = [ordered]@{
            display_name = [string]$Object.Name
            sam_account_name = if (Get-OptionalProperty -Object $Object -Name "SamAccountName") { [string](Get-OptionalProperty -Object $Object -Name "SamAccountName") } else { $null }
            distinguished_name = [string]$Object.DistinguishedName
            enabled = if ($null -ne (Get-OptionalProperty -Object $Object -Name "Enabled")) { [bool](Get-OptionalProperty -Object $Object -Name "Enabled") } else { $null }
            object_class = [string]$Object.objectClass
        }
    }
}

$requestedSections = @($Sections.Split(",", [System.StringSplitOptions]::RemoveEmptyEntries) | ForEach-Object { $_.Trim() })
if ($requestedSections.Count -ne 1 -or $requestedSections[0] -ne "privileged_membership") {
    throw "The first AD Context collector slice supports only privileged_membership."
}
$groupReferences = @($PrivilegedGroups.Split(",", [System.StringSplitOptions]::RemoveEmptyEntries) | ForEach-Object { $_.Trim() })
if ($groupReferences.Count -eq 0) {
    throw "At least one privileged group is required."
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
$seenEntities = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$seenRelations = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$scopedGroupSids = [System.Collections.Generic.List[string]]::new()
$pendingGroups = [System.Collections.Generic.Queue[string]]::new()
$processedGroups = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($groupReference in $groupReferences) { $pendingGroups.Enqueue($groupReference) }

while ($pendingGroups.Count -gt 0) {
    $groupReference = $pendingGroups.Dequeue()
    $group = Get-ADGroup -Server $DirectoryServer -Identity $groupReference -Properties ObjectGUID, SID, SamAccountName, DistinguishedName -ErrorAction Stop
    if (-not ([string]$group.DistinguishedName).EndsWith($SearchBase, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Selected privileged group is outside SearchBase."
    }
    if (-not $processedGroups.Add([string]$group.DistinguishedName)) { continue }
    $groupRecord = ConvertTo-EntityRecord -Object $group -DomainSid $domainSid -ObservedAtUtc $observedAt
    if ($groupReferences -contains [string]$groupReference) {
        $scopedGroupSids.Add([string]$group.SID)
    }
    if ($seenEntities.Add([string]$groupRecord.record_key)) {
        $records.Add($groupRecord)
        if ($records.Count -gt $MaxRecords) { throw "AD Context record budget exceeded." }
    }
    # Query the direct memberOf backlink with a server-side result ceiling.  In
    # contrast to Get-ADGroupMember this does not materialize an unbounded group
    # before the canary record budget can be enforced.
    $remainingRecords = $MaxRecords - $records.Count
    $memberCapacity = [int][math]::Floor([math]::Max(0, $remainingRecords) / 2)
    $queryLimit = $memberCapacity + 1
    $escapedGroupDn = ConvertTo-LdapFilterValue -Value ([string]$group.DistinguishedName)
    $members = @(Get-ADObject -Server $DirectoryServer -LDAPFilter ("(memberOf={0})" -f $escapedGroupDn) -SearchBase $SearchBase -SearchScope Subtree -ResultSetSize $queryLimit -Properties ObjectGUID, objectSid, SamAccountName, DistinguishedName, objectClass -ErrorAction Stop)
    if ($members.Count -gt $memberCapacity) {
        throw "AD Context member query exceeded the approved record budget."
    }
    foreach ($member in $members) {
        $resolved = switch ([string]$member.objectClass) {
            "user" { Get-ADUser -Server $DirectoryServer -Identity $member.DistinguishedName -Properties ObjectGUID, SID, SamAccountName, DistinguishedName, Enabled -ErrorAction Stop }
            "computer" { Get-ADComputer -Server $DirectoryServer -Identity $member.DistinguishedName -Properties ObjectGUID, SID, SamAccountName, DistinguishedName, Enabled -ErrorAction Stop }
            "group" { Get-ADGroup -Server $DirectoryServer -Identity $member.DistinguishedName -Properties ObjectGUID, SID, SamAccountName, DistinguishedName -ErrorAction Stop }
            default { Get-ADObject -Server $DirectoryServer -Identity $member.DistinguishedName -Properties ObjectGUID, objectSid, SamAccountName, DistinguishedName -ErrorAction Stop }
        }
        $memberRecord = ConvertTo-EntityRecord -Object $resolved -DomainSid $domainSid -ObservedAtUtc $observedAt
        if ($seenEntities.Add([string]$memberRecord.record_key)) {
            $records.Add($memberRecord)
            if ($records.Count -gt $MaxRecords) { throw "AD Context record budget exceeded." }
        }
        if ([string]$member.objectClass -eq "group" -and -not $processedGroups.Contains([string]$resolved.DistinguishedName)) {
            $pendingGroups.Enqueue([string]$resolved.DistinguishedName)
        }
        $relationKey = ("member-of:{0}:{1}" -f $memberRecord.record_key, $groupRecord.record_key)
        if ($seenRelations.Add($relationKey)) {
            $records.Add([ordered]@{
            record_type = "relation"
            record_key = $relationKey
            section = "privileged_membership"
            observed_at_utc = $observedAt
            relation_kind = "member_of"
            source_record_key = $memberRecord.record_key
            target_record_key = $groupRecord.record_key
            attributes = [ordered]@{
                membership_type = "direct"
                source_section = "privileged_membership"
            }
            })
            if ($records.Count -gt $MaxRecords) { throw "AD Context record budget exceeded." }
        }
    }
}

$finished = [datetime]::UtcNow
$bundle = [ordered]@{
    schema_version = "ad-context-bundle/v1"
    source_pack_id = "sli.windows.ad-context"
    source_pack_version = "0.5.0"
    run_id = $RunId.ToString()
    mode = $Mode
    domain = [ordered]@{
        sid = $domainSid
        dns_name = $domainDnsName
    }
    scope = [ordered]@{
        search_base = $SearchBase
        privileged_group_sids = @($scopedGroupSids | Sort-Object -Unique)
        collection_profile = $CollectionProfile
    }
    observed_at_utc = $observedAt
    sections = @([ordered]@{
        name = "privileged_membership"
        status = "complete"
        record_count = $records.Count
        duration_ms = [int][math]::Round(($finished - $started).TotalMilliseconds)
        error_code = $null
    })
    records = @($records | ForEach-Object { $_ })
}

$parent = Split-Path -Parent $OutputPath
if ($parent -and -not (Test-Path -LiteralPath $parent)) {
    [System.IO.Directory]::CreateDirectory($parent) | Out-Null
}
$json = $bundle | ConvertTo-Json -Depth 12
$bundleBytes = [System.Text.Encoding]::UTF8.GetByteCount($json)
if ($bundleBytes -gt $MaxBundleBytes) { throw "AD Context bundle byte budget exceeded." }
[System.IO.File]::WriteAllText($OutputPath, $json, [System.Text.UTF8Encoding]::new($false))
$stream = [System.IO.File]::OpenRead($OutputPath)
$hasher = [System.Security.Cryptography.SHA256]::Create()
try {
    $hashBytes = $hasher.ComputeHash($stream)
}
finally {
    $stream.Dispose()
    $hasher.Dispose()
}
$sha256 = ([System.BitConverter]::ToString($hashBytes)).Replace('-', '').ToLowerInvariant()
[System.IO.File]::WriteAllText(($OutputPath + ".sha256"), ($sha256 + "  " + [System.IO.Path]::GetFileName($OutputPath)), [System.Text.UTF8Encoding]::new($false))
Write-Output $OutputPath

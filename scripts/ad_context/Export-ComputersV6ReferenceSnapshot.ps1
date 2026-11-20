#requires -Version 5.1

<#
.SYNOPSIS
    V6-only production entry point for the approved Computers reference collector.

.DESCRIPTION
    Pins and invokes the immutable approved reference collector without changing its
    parameters, defaults, output schema, or failure semantics. This dedicated lane
    keeps DNS, AD-Site, and exact-lastLogon work outside the shared low-cost AD
    context collector. The delegated collector is read-only and writes exactly the
    requested local JSON snapshot.
#>

[CmdletBinding()]
param(
    [string]$Server,
    [string]$SearchBase,
    [string]$OutputPath,
    [switch]$SkipDns,
    [switch]$CollectAdSite,
    [switch]$CollectExactLastLogon,
    [string]$CoordinatorBaseInputPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# The same cutover setting as the Python legacy admission gate.
if ($null -ne $env:SLI_LEGACY_COLLECTION_DISABLED -and $env:SLI_LEGACY_COLLECTION_DISABLED.Trim() -ne "0") {
    throw "legacy collection disabled by SLI_LEGACY_COLLECTION_DISABLED; use agent modules and core job handlers"
}

$ApprovedReferenceSha256 = 'caf0ee7e590e133a4e834bb31997e5253a5e707e347e677158260ab7085154d5'
$ReferenceCollector = Join-Path $PSScriptRoot 'collect_ad_inventory_evidence.ps1'

if (-not (Test-Path -LiteralPath $ReferenceCollector -PathType Leaf)) {
    throw "Approved Computers reference collector was not found: $ReferenceCollector"
}

$ActualReferenceSha256 = (Get-FileHash -LiteralPath $ReferenceCollector -Algorithm SHA256).Hash.ToLowerInvariant()
if ($ActualReferenceSha256 -ne $ApprovedReferenceSha256) {
    throw "Approved Computers reference collector hash mismatch. Expected $ApprovedReferenceSha256; got $ActualReferenceSha256."
}

$ForwardParameters = @{}
foreach ($ParameterName in @(
    'Server',
    'SearchBase',
    'OutputPath',
    'SkipDns',
    'CollectAdSite',
    'CollectExactLastLogon'
)) {
    if ($PSBoundParameters.ContainsKey($ParameterName)) {
        $ForwardParameters[$ParameterName] = $PSBoundParameters[$ParameterName]
    }
}

$Utf8Strict = New-Object System.Text.UTF8Encoding($false, $true)
$ReferenceSource = [IO.File]::ReadAllText($ReferenceCollector, $Utf8Strict)

# The approved collector casts AD's multi-value wrapper directly to Int64.
# On Windows PowerShell 5.1 an empty `lastLogon` ADPropertyValueCollection raises
# `ArgumentException` and aborts the complete exact-lastLogon stage. Keep the
# reference file immutable and apply this one bounded runtime compatibility fix:
# an empty attribute is the AD file-time value 0, while a present scalar keeps
# the reference conversion and max-per-DC semantics.
$UnsafeExactLogonCast = '                $FileTime = [int64]$Row.lastLogon'
$SafeExactLogonCast = @'
                $RawLastLogon = @($Row.lastLogon)
                $FileTime = if ($RawLastLogon.Count -eq 0 -or $null -eq $RawLastLogon[0] -or [string]::IsNullOrWhiteSpace([string]$RawLastLogon[0])) {
                    [int64]0
                }
                else {
                    [int64]$RawLastLogon[0]
                }
'@
$ExactLogonCastCount = ([regex]::Matches($ReferenceSource, [regex]::Escape($UnsafeExactLogonCast))).Count
if ($ExactLogonCastCount -ne 1) {
    throw "Approved collector exact-lastLogon compatibility anchor mismatch: $ExactLogonCastCount"
}
$ReferenceSource = $ReferenceSource.Replace($UnsafeExactLogonCast, $SafeExactLogonCast.TrimEnd("`r", "`n"))

# Windows PowerShell can also reject AD's DirectoryServer collection while
# binding it to object[] before the function body runs. Iteration does not need
# that coercion, so remove only this parameter type at the pinned anchor.
$TypedDomainControllers = '[Parameter(Mandatory = $true)][object[]]$DomainControllers'
$UntypedDomainControllers = '[Parameter(Mandatory = $true)]$DomainControllers'
$DomainControllersAnchorCount = ([regex]::Matches($ReferenceSource, [regex]::Escape($TypedDomainControllers))).Count
if ($DomainControllersAnchorCount -ne 1) {
    throw "Approved collector domain-controller compatibility anchor mismatch: $DomainControllersAnchorCount"
}
$ReferenceSource = $ReferenceSource.Replace($TypedDomainControllers, $UntypedDomainControllers)

# PowerShell 5.1's dynamic binder can also fail while applying @() to generic
# List<T> instances in the exact-lastLogon return object. ToArray() preserves
# the same ordered values without the broken binder path.
$GenericListArrayBlock = @'
        SuccessfulDcs = @($SuccessfulDcs)
        FailedDcs     = @($FailedDcs)
        Errors        = @($Errors)
'@
$StableArrayBlock = @'
        SuccessfulDcs = $SuccessfulDcs.ToArray()
        FailedDcs     = $FailedDcs.ToArray()
        Errors        = $Errors.ToArray()
'@
$GenericListArrayAnchorCount = ([regex]::Matches($ReferenceSource, [regex]::Escape($GenericListArrayBlock.TrimEnd("`r", "`n")))).Count
if ($GenericListArrayAnchorCount -ne 1) {
    throw "Approved collector generic-list compatibility anchor mismatch: $GenericListArrayAnchorCount"
}
$ReferenceSource = $ReferenceSource.Replace($GenericListArrayBlock.TrimEnd("`r", "`n"), $StableArrayBlock.TrimEnd("`r", "`n"))

# A domain may legitimately have no AD replication subnet records. The
# reference function already returns no match for that case; allow the empty
# collection to reach the function instead of failing parameter binding.
$StrictSubnetParameter = '[Parameter(Mandatory = $true)][object[]]$SubnetRecords'
$EmptySubnetParameter = '[Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$SubnetRecords'
$SubnetParameterAnchorCount = ([regex]::Matches($ReferenceSource, [regex]::Escape($StrictSubnetParameter))).Count
if ($SubnetParameterAnchorCount -ne 1) {
    throw "Approved collector subnet compatibility anchor mismatch: $SubnetParameterAnchorCount"
}
$ReferenceSource = $ReferenceSource.Replace($StrictSubnetParameter, $EmptySubnetParameter)

# DateTime is a non-nullable value type. `[AllowNull()]` alone does not make the
# reference's optional observation timestamp bindable when a source was not
# collected. Nullable<DateTime> preserves both timestamp and null semantics.
$NonNullableObservedAt = '[AllowNull()][datetime]$ObservedAt = $null'
$NullableObservedAt = '[AllowNull()][Nullable[datetime]]$ObservedAt = $null'
$ObservedAtAnchorCount = ([regex]::Matches($ReferenceSource, [regex]::Escape($NonNullableObservedAt))).Count
if ($ObservedAtAnchorCount -ne 1) {
    throw "Approved collector observed-at compatibility anchor mismatch: $ObservedAtAnchorCount"
}
$ReferenceSource = $ReferenceSource.Replace($NonNullableObservedAt, $NullableObservedAt)

# ADPropertyValueCollection and generic List<T> hit the same PowerShell 5.1
# object-array binder defect when the report object is assembled. Materialize
# both through stable paths without changing values or ordering.
$UnsafeSpnProjection = '        spns                         = @($Computer.ServicePrincipalName)'
$SafeSpnProjection = '        spns                         = @($Computer.ServicePrincipalName | ForEach-Object { [string]$_ })'
$SpnProjectionAnchorCount = ([regex]::Matches($ReferenceSource, [regex]::Escape($UnsafeSpnProjection))).Count
if ($SpnProjectionAnchorCount -ne 1) {
    throw "Approved collector SPN compatibility anchor mismatch: $SpnProjectionAnchorCount"
}
$ReferenceSource = $ReferenceSource.Replace($UnsafeSpnProjection, $SafeSpnProjection)

$UnsafeObjectErrors = '        collectionErrors             = @($ObjectErrors)'
$SafeObjectErrors = '        collectionErrors             = $ObjectErrors.ToArray()'
$ObjectErrorsAnchorCount = ([regex]::Matches($ReferenceSource, [regex]::Escape($UnsafeObjectErrors))).Count
if ($ObjectErrorsAnchorCount -ne 1) {
    throw "Approved collector object-errors compatibility anchor mismatch: $ObjectErrorsAnchorCount"
}
$ReferenceSource = $ReferenceSource.Replace($UnsafeObjectErrors, $SafeObjectErrors)

# The final snapshot contains two more generic lists. Materialize them directly
# so a successful full collection is not lost during JSON assembly.
$UnsafeGlobalErrors = '        errors            = @($GlobalErrors)'
$SafeGlobalErrors = '        errors            = $GlobalErrors.ToArray()'
$GlobalErrorsAnchorCount = ([regex]::Matches($ReferenceSource, [regex]::Escape($UnsafeGlobalErrors))).Count
if ($GlobalErrorsAnchorCount -ne 1) {
    throw "Approved collector global-errors compatibility anchor mismatch: $GlobalErrorsAnchorCount"
}
$ReferenceSource = $ReferenceSource.Replace($UnsafeGlobalErrors, $SafeGlobalErrors)

$UnsafeObjects = '    objects = @($Objects)'
$SafeObjects = '    objects = $Objects.ToArray()'
$ObjectsAnchorCount = ([regex]::Matches($ReferenceSource, [regex]::Escape($UnsafeObjects))).Count
if ($ObjectsAnchorCount -ne 1) {
    throw "Approved collector objects compatibility anchor mismatch: $ObjectsAnchorCount"
}
$ReferenceSource = $ReferenceSource.Replace($UnsafeObjects, $SafeObjects)

# Coordinator mode is enrichment-only.  The standalone branch above remains
# byte-compatible for rollback/manual use, while this branch replaces only the
# reference collector's full computer inventory with a hash-verified base set.
$BaseComputerGuidAllowlist = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
if ($PSBoundParameters.ContainsKey('CoordinatorBaseInputPath')) {
    if ([string]::IsNullOrWhiteSpace($CoordinatorBaseInputPath) -or -not (Test-Path -LiteralPath $CoordinatorBaseInputPath -PathType Leaf)) {
        throw 'coordinator_base_input_missing'
    }
    $baseInputBytes = [IO.File]::ReadAllBytes($CoordinatorBaseInputPath)
    if ($baseInputBytes.Length -le 0 -or $baseInputBytes.Length -gt 67108864) { throw 'coordinator_base_input_size_out_of_bounds' }
    $baseInput = $Utf8Strict.GetString($baseInputBytes) | ConvertFrom-Json
    if ([string]$baseInput.schema_version -ne 'sli.ad-computer-base/1.0') { throw 'coordinator_base_schema_invalid' }
    $baseRowsJson = [string]$baseInput.objects_json
    $baseRowsBytes = [Text.Encoding]::UTF8.GetBytes($baseRowsJson)
    $baseHasher = [Security.Cryptography.SHA256]::Create()
    try { $baseRowsHash = -join ($baseHasher.ComputeHash($baseRowsBytes) | ForEach-Object { $_.ToString('x2') }) }
    finally { $baseHasher.Dispose() }
    if ($baseRowsHash -ne [string]$baseInput.objects_sha256) { throw 'coordinator_base_hash_mismatch' }
    $CoordinatorComputers = @($baseRowsJson | ConvertFrom-Json | ForEach-Object { $_ })
    if ($CoordinatorComputers.Count -ne [int]$baseInput.object_count -or $CoordinatorComputers.Count -gt 50000) {
        throw 'coordinator_base_count_out_of_bounds'
    }
    foreach ($baseComputer in $CoordinatorComputers) {
        $baseGuid = ([guid]$baseComputer.ObjectGUID).ToString().ToLowerInvariant()
        if (-not $BaseComputerGuidAllowlist.Add($baseGuid)) { throw 'coordinator_base_identity_duplicate' }
    }

    $standaloneQuery = '$Computers = @(Get-ADComputer @QueryParameters)'
    if (([regex]::Matches($ReferenceSource, [regex]::Escape($standaloneQuery))).Count -ne 1) { throw 'coordinator_base_query_anchor_mismatch' }
    $ReferenceSource = $ReferenceSource.Replace($standaloneQuery, '$Computers = @($CoordinatorComputers)')

    $fullExactQuery = '$Rows = @(Get-ADComputer @Parameters)'
    $boundedExactQuery = @'
            $Rows = @(
                foreach ($AllowedGuid in $BaseComputerGuidAllowlist) {
                    Get-ADComputer -Server $DcHost -Identity $AllowedGuid -Properties @('lastLogon', 'ObjectGUID') -ErrorAction Stop
                }
            )
            foreach ($AllowedRow in $Rows) {
                $AllowedRowGuid = ([guid]$AllowedRow.ObjectGUID).ToString().ToLowerInvariant()
                if (-not $BaseComputerGuidAllowlist.Contains($AllowedRowGuid)) { throw 'coordinator_base_identity_mismatch' }
            }
'@
    if (([regex]::Matches($ReferenceSource, [regex]::Escape($fullExactQuery))).Count -ne 1) { throw 'coordinator_exact_query_anchor_mismatch' }
    $ReferenceSource = $ReferenceSource.Replace($fullExactQuery, $boundedExactQuery.TrimEnd("`r", "`n"))
}
$ReferenceScript = [ScriptBlock]::Create($ReferenceSource)
try {
    & $ReferenceScript @ForwardParameters
}
catch {
    Write-Error ("Reference collector failed.`n{0}`n{1}" -f $_.Exception.ToString(), $_.ScriptStackTrace)
    throw
}

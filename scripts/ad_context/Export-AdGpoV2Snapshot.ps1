#requires -Version 5.1
<#
.SYNOPSIS
    Read-only inventory collector for the evidence-first Active Directory GPO report.
.DESCRIPTION
    Reads Group Policy objects, their directory containers, SYSVOL GPT.INI files,
    links on sites/domains/OUs, normalized XML report leaves, permissions, and
    WMI filters. The script never changes Active Directory, Group Policy, or SYSVOL.

    The resulting JSON is an observation snapshot, not RSoP. It does not prove
    that a GPO applied to a particular user or computer.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$Domain,

    [Parameter()]
    [string]$Server,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = (Join-Path -Path $PWD -ChildPath ("ad-gpo-snapshot-{0}.json" -f (Get-Date -Format "yyyyMMdd-HHmmss"))),

    [Parameter()]
    [ValidateSet("Full", "None")]
    [string]$SettingsMode = "Full",

    [Parameter()]
    [bool]$IncludeSites = $true,

    [Parameter()]
    [switch]$SkipPermissions,

    [Parameter()]
    [switch]$SkipSysvol,

    [Parameter()]
    [ValidateRange(100, 20000)]
    [int]$MaxSettingsPerGpo = 5000,

    [Parameter()]
    [string]$CompatibilityProjectionPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

# The same cutover setting as the Python legacy admission gate.
if ($null -ne $env:SLI_LEGACY_COLLECTION_DISABLED -and $env:SLI_LEGACY_COLLECTION_DISABLED.Trim() -ne "0") {
    throw "legacy collection disabled by SLI_LEGACY_COLLECTION_DISABLED; use agent modules and core job handlers"
}

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module GroupPolicy -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot "GpoReportContract.psm1") -Force -ErrorAction Stop

$script:ObservedAt = (Get-Date).ToUniversalTime().ToString("o")
$script:CollectorVersion = "1.1.0"
$script:AllowedSourceStates = @(
    "observed",
    "not_collected",
    "not_evaluated",
    "missing_in_source",
    "no_record",
    "partial",
    "failed",
    "access_denied",
    "parse_error",
    "not_applicable"
)

function New-SourceState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("observed", "not_collected", "not_evaluated", "missing_in_source", "no_record", "partial", "failed", "access_denied", "parse_error", "not_applicable")]
        [string]$Status,
        [Parameter(Mandatory = $true)]
        [string]$Source,
        [Parameter()]
        [AllowNull()]
        [string]$Detail,
        [Parameter()]
        [AllowNull()]
        [string]$Error,
        [Parameter()]
        [AllowNull()]
        [object]$Coverage,
        [Parameter()]
        [AllowNull()]
        [object]$Value
    )

    [pscustomobject][ordered]@{
        status      = $Status
        source      = $Source
        value       = $Value
        observed_at = $script:ObservedAt
        detail      = $Detail
        error       = $Error
        coverage    = $Coverage
    }
}

function Get-ErrorStatus {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][System.Exception]$Exception)

    if ($Exception -is [System.UnauthorizedAccessException] -or $Exception.Message -match "(?i)access.*denied|unauthorized") {
        return "access_denied"
    }
    if ($Exception -is [System.Xml.XmlException] -or $Exception -is [System.FormatException] -or $Exception.Message -match "(?i)parse|malformed|invalid xml") {
        return "parse_error"
    }
    if ($Exception -is [System.IO.FileNotFoundException] -or $Exception -is [System.Management.Automation.ItemNotFoundException] -or $Exception.Message -match "(?i)cannot find|not found|does not exist") {
        return "no_record"
    }
    return "failed"
}

function New-CollectionError {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Stage,
        [Parameter(Mandatory = $true)][string]$Status,
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter()][AllowNull()][string]$EntityType,
        [Parameter()][AllowNull()][string]$EntityId
    )

    [pscustomobject][ordered]@{
        source      = $Stage
        stage       = $Stage
        status      = $Status
        code        = ("{0}_{1}" -f $Stage, $Status)
        message     = $Message
        target      = $EntityId
        entity_type = $EntityType
        entity_id   = $EntityId
        observed_at = $script:ObservedAt
    }
}

function ConvertTo-IsoUtc {
    [CmdletBinding()]
    param([Parameter()][AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    try { return ([datetime]$Value).ToUniversalTime().ToString("o") } catch { return [string]$Value }
}

function Get-FirstPropertyValue {
    [CmdletBinding()]
    param(
        [Parameter()][AllowNull()][object]$InputObject,
        [Parameter(Mandatory = $true)][string[]]$Names
    )
    if ($null -eq $InputObject) { return $null }
    foreach ($name in $Names) {
        $property = $InputObject.PSObject.Properties[$name]
        if ($null -ne $property -and $null -ne $property.Value) { return $property.Value }
    }
    return $null
}

function ConvertTo-StringArray {
    [CmdletBinding()]
    param([Parameter()][AllowNull()][object]$Value)
    if ($null -eq $Value) { return @() }
    if ($Value -is [string]) { return @([string]$Value) }
    return @($Value | ForEach-Object { [string]$_ })
}

function Normalize-GuidText {
    [CmdletBinding()]
    param([Parameter()][AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    $match = [regex]::Match([string]$Value, "(?i)[{]?(?<guid>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})[}]?")
    if (-not $match.Success) { return $null }
    return $match.Groups["guid"].Value.ToUpperInvariant()
}

function New-StableId {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Prefix,
        [Parameter(Mandatory = $true)][string]$Seed
    )
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Seed)
        $hash = $sha.ComputeHash($bytes)
        $guidBytes = New-Object byte[] 16
        [Array]::Copy($hash, $guidBytes, 16)
        $guid = New-Object Guid (,$guidBytes)
        return ("{0}-{1}" -f $Prefix, $guid.ToString().ToLowerInvariant())
    }
    finally { $sha.Dispose() }
}

function Get-Sha256Hex {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text))
        return (($hash | ForEach-Object { $_.ToString("x2") }) -join "")
    }
    finally { $sha.Dispose() }
}

function Resolve-AccountSid {
    [CmdletBinding()]
    param([Parameter()][AllowNull()][object]$Identity)
    if ($null -eq $Identity -or [string]::IsNullOrWhiteSpace([string]$Identity)) { return $null }
    try {
        $account = New-Object System.Security.Principal.NTAccount ([string]$Identity)
        return [string]$account.Translate([System.Security.Principal.SecurityIdentifier])
    }
    catch { return $null }
}

function Get-GpoSideEnabled {
    [CmdletBinding()]
    param(
        [Parameter()][AllowNull()][object]$SideObject,
        [Parameter(Mandatory = $true)][string]$GpoStatus,
        [Parameter(Mandatory = $true)][ValidateSet("computer", "user")][string]$Side
    )
    $direct = Get-FirstPropertyValue -InputObject $SideObject -Names @("Enabled")
    if ($null -ne $direct) { return [bool]$direct }
    if ($GpoStatus -eq "AllSettingsDisabled") { return $false }
    if ($Side -eq "computer" -and $GpoStatus -eq "ComputerSettingsDisabled") { return $false }
    if ($Side -eq "user" -and $GpoStatus -eq "UserSettingsDisabled") { return $false }
    return $true
}

function Get-GpcExtensionIds {
    [CmdletBinding()]
    param([Parameter()][AllowNull()][object]$Value)
    $ids = New-Object System.Collections.ArrayList
    foreach ($item in (ConvertTo-StringArray $Value)) {
        foreach ($match in [regex]::Matches($item, "(?i)[{](?<guid>[0-9a-f-]{36})[}]")) {
            $guid = $match.Groups["guid"].Value.ToUpperInvariant()
            if (-not $ids.Contains($guid)) { [void]$ids.Add($guid) }
        }
    }
    return @($ids)
}

function ConvertFrom-GPLink {
    [CmdletBinding()]
    param([Parameter()][AllowNull()][string]$Raw)

    $result = New-Object System.Collections.ArrayList
    if ([string]::IsNullOrWhiteSpace($Raw)) { return @() }
    $matches = [regex]::Matches($Raw, "(?is)\[(?<path>LDAP://.*?);(?<options>\d+)\]")
    $order = 0
    foreach ($match in $matches) {
        $order++
        $path = $match.Groups["path"].Value
        $dn = $path.Substring("LDAP://".Length)
        $options = [int]$match.Groups["options"].Value
        [void]$result.Add([pscustomobject][ordered]@{
            gpc_dn       = $dn
            raw_options  = $options
            enabled      = (($options -band 1) -eq 0)
            enforced     = (($options -band 2) -ne 0)
            order        = $order
            order_source = "gPLink sequence"
        })
    }
    return @($result)
}

function ConvertFrom-WmiParm2 {
    [CmdletBinding()]
    param([Parameter()][AllowNull()][string]$Raw)

    $queries = New-Object System.Collections.ArrayList
    if ([string]::IsNullOrWhiteSpace($Raw)) { return @() }

    $pattern = "(?is)WQL;(?<namespace>[^;]+);(?<query>.*?)(?=(?:;\d+;\d+;\d+;\d+;WQL;)|$)"
    foreach ($match in [regex]::Matches($Raw, $pattern)) {
        $namespace = $match.Groups["namespace"].Value.Trim()
        $query = $match.Groups["query"].Value.Trim().TrimEnd(";")
        if (-not [string]::IsNullOrWhiteSpace($query)) {
            [void]$queries.Add([pscustomobject][ordered]@{
                namespace = $namespace
                query     = $query
            })
        }
    }

    if ($queries.Count -eq 0) {
        [void]$queries.Add([pscustomobject][ordered]@{
            namespace = $null
            query     = $Raw
        })
    }
    return @($queries)
}

function ConvertFrom-WmiDateText {
    [CmdletBinding()]
    param([Parameter()][AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    $text = [string]$Value
    $match = [regex]::Match($text, "^(?<stamp>\d{14})")
    if ($match.Success) {
        try {
            $parsed = [datetime]::ParseExact($match.Groups["stamp"].Value, "yyyyMMddHHmmss", [Globalization.CultureInfo]::InvariantCulture)
            return $parsed.ToUniversalTime().ToString("o")
        }
        catch { }
    }
    return $text
}

function Get-XmlNodePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][System.Xml.XmlNode]$Node,
        [Parameter(Mandatory = $true)][System.Xml.XmlNode]$StopNode
    )
    $parts = New-Object System.Collections.ArrayList
    $cursor = $Node
    while ($null -ne $cursor -and $cursor -ne $StopNode) {
        if ($cursor.NodeType -eq [System.Xml.XmlNodeType]::Element) {
            [void]$parts.Insert(0, $cursor.LocalName)
        }
        $cursor = $cursor.ParentNode
    }
    return ($parts -join "/")
}

function Convert-GpoReportSettings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][xml]$Xml,
        [Parameter(Mandatory = $true)][string]$GpoId,
        [Parameter(Mandatory = $true)][string]$GpoName,
        [Parameter(Mandatory = $true)][ValidateSet("computer", "user")][string]$Side,
        [Parameter(Mandatory = $true)][int]$Maximum
    )

    $rows = New-Object System.Collections.ArrayList
    $seenSettingFingerprints = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    $sideNodeName = if ($Side -eq "computer") { "Computer" } else { "User" }
    $sideNode = $Xml.SelectSingleNode("/*[local-name()='GPO']/*[local-name()='$sideNodeName']")
    if ($null -eq $sideNode) {
        return [pscustomobject][ordered]@{ rows = @(); truncated = $false; source_status = "missing_in_source" }
    }

    $sideNode = $sideNode.CloneNode($true)
    Protect-SLIGpoXmlValues -Node $sideNode

    $auditCounts = @{}
    foreach ($subcategory in $sideNode.SelectNodes(".//*[local-name()='SubcategoryGuid']")) {
        $auditCounts[$subcategory.InnerText.Trim()]++
    }
    $extensionNodes = $sideNode.SelectNodes("./*[local-name()='ExtensionData']/*[local-name()='Extension']")
    foreach ($extensionNode in $extensionNodes) {
        $extensionName = $null
        $nameNode = $extensionNode.SelectSingleNode("./*[local-name()='Name']")
        if ($null -ne $nameNode -and -not [string]::IsNullOrWhiteSpace($nameNode.InnerText)) {
            $extensionName = $nameNode.InnerText.Trim()
        }
        if ([string]::IsNullOrWhiteSpace($extensionName)) {
            $typeAttribute = $extensionNode.Attributes | Where-Object { $_.LocalName -eq "type" } | Select-Object -First 1
            if ($null -ne $typeAttribute) { $extensionName = [string]$typeAttribute.Value }
        }
        if ([string]::IsNullOrWhiteSpace($extensionName)) { $extensionName = "Extension" }

        $leafNodes = $extensionNode.SelectNodes(".//*[not(*)]")
        foreach ($leaf in $leafNodes) {
            if ($rows.Count -ge $Maximum) {
                return [pscustomobject][ordered]@{ rows = @($rows); truncated = $true; source_status = "partial" }
            }
            if ($leaf.LocalName -eq "Name" -and $leaf.ParentNode -eq $extensionNode) { continue }

            $value = $leaf.InnerText
            if ($null -ne $value) { $value = $value.Trim() }
            if ([string]::IsNullOrWhiteSpace($value) -and $leaf.Attributes.Count -gt 0) {
                $pairs = @($leaf.Attributes | ForEach-Object { "{0}={1}" -f $_.LocalName, $_.Value })
                $value = $pairs -join "; "
            }
            if ([string]::IsNullOrWhiteSpace($value)) { continue }

            $path = Get-XmlNodePath -Node $leaf -StopNode $extensionNode
            $category = if ($null -ne $leaf.ParentNode) { $leaf.ParentNode.LocalName } else { $extensionName }
            $seed = "{0}|{1}|{2}|{3}|{4}|{5}" -f $GpoId, $Side, $extensionName, $path, $leaf.LocalName, $value
            $fingerprint = Get-Sha256Hex -Text $seed
            if (-not $seenSettingFingerprints.Add($fingerprint)) { continue }
            $setting = [ordered]@{
                id              = New-StableId -Prefix "setting" -Seed $seed
                gpo_id          = $GpoId
                gpo_name        = $GpoName
                side            = $Side
                extension       = $extensionName
                category        = $category
                path            = $path
                setting_name    = $leaf.LocalName
                value_display   = $value
                operation       = "Observed"
                source_xml_path = "/GPO/$sideNodeName/ExtensionData/Extension/$path"
                source_state    = New-SourceState -Status "observed" -Source "Get-GPOReport XML normalizer" -Detail $null -Error $null -Coverage $null -Value $null
                fingerprint     = $fingerprint
            }
            $mode = Get-SLIGpoAuditMode -Leaf $leaf -GuidCounts $auditCounts
            if ($null -ne $mode) { $setting['audit_mode'] = $mode }
            [void]$rows.Add([pscustomobject]$setting)
        }
    }

    return [pscustomobject][ordered]@{ rows = @($rows); truncated = $false; source_status = "observed" }
}

function Get-ProbeGptPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$OriginalPath,
        [Parameter(Mandatory = $true)][string]$QueryServer
    )
    $match = [regex]::Match($OriginalPath, "(?i)^\\\\[^\\]+\\SYSVOL\\(?<tail>.+)$")
    if ($match.Success) { return "\\$QueryServer\SYSVOL\$($match.Groups['tail'].Value)" }
    return $OriginalPath
}

function Read-GptIniVersion {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$GptPath)
    $iniPath = Join-Path -Path $GptPath -ChildPath "GPT.INI"
    $content = [System.IO.File]::ReadAllText($iniPath)
    $match = [regex]::Match($content, "(?im)^\s*Version\s*=\s*(?<version>\d+)\s*$")
    if (-not $match.Success) { throw (New-Object System.FormatException "GPT.INI does not contain a numeric Version entry.") }
    return [long]$match.Groups["version"].Value
}

$startedAt = (Get-Date).ToUniversalTime().ToString("o")
$collectionErrors = New-Object System.Collections.ArrayList
$gpoRecords = New-Object System.Collections.ArrayList
$scopeRecords = New-Object System.Collections.ArrayList
$linkRecords = New-Object System.Collections.ArrayList
$settingRecords = New-Object System.Collections.ArrayList
$permissionRecords = New-Object System.Collections.ArrayList
$aclRecords = New-Object System.Collections.ArrayList
$wmiRecords = New-Object System.Collections.ArrayList
$unresolvedLinks = New-Object System.Collections.ArrayList
$compatibilityReportFacts = @{}
$compatibilityPermissionFacts = @{}

$rootStates = [ordered]@{
    gpo_list      = New-SourceState -Status "not_evaluated" -Source "Get-GPO -All" -Detail "Сбор ещё не выполнен" -Error $null -Coverage $null -Value $null
    gpo_reports   = New-SourceState -Status "not_evaluated" -Source "Get-GPOReport XML" -Detail "Сбор ещё не выполнен" -Error $null -Coverage $null -Value $null
    gpc_directory = New-SourceState -Status "not_evaluated" -Source "Get-ADObject groupPolicyContainer" -Detail "Сбор ещё не выполнен" -Error $null -Coverage $null -Value $null
    sysvol_gpt    = New-SourceState -Status "not_evaluated" -Source "gPCFileSysPath/GPT.INI" -Detail "Сбор ещё не выполнен" -Error $null -Coverage $null -Value $null
    links         = New-SourceState -Status "not_evaluated" -Source "gPLink/gPOptions inventory" -Detail "Сбор ещё не выполнен" -Error $null -Coverage $null -Value $null
    permissions   = New-SourceState -Status "not_evaluated" -Source "Get-GPPermission -All" -Detail "Сбор ещё не выполнен" -Error $null -Coverage $null -Value $null
    wmi_filters   = New-SourceState -Status "not_evaluated" -Source "Get-ADObject msWMI-Som" -Detail "Сбор ещё не выполнен" -Error $null -Coverage $null -Value $null
}

$domainLookup = @{}
if (-not [string]::IsNullOrWhiteSpace($Domain)) { $domainLookup["Identity"] = $Domain }
if (-not [string]::IsNullOrWhiteSpace($Server)) { $domainLookup["Server"] = $Server }
$domainInfo = Get-ADDomain @domainLookup -ErrorAction Stop
$domainDns = [string]$domainInfo.DNSRoot
$domainDn = [string]$domainInfo.DistinguishedName
$queryServer = if ([string]::IsNullOrWhiteSpace($Server)) { [string]$domainInfo.PDCEmulator } else { $Server }
$rootDse = Get-ADRootDSE -Server $queryServer -ErrorAction Stop
$configDn = [string]$rootDse.configurationNamingContext

$gpParams = @{ Domain = $domainDns; Server = $queryServer }
$adServerParams = @{ Server = $queryServer }

$gpcByGuid = @{}
$gpcByDn = @{}
try {
    $gpcSearchBase = "CN=Policies,CN=System,$domainDn"
    $gpcObjects = @(Get-ADObject -LDAPFilter "(objectClass=groupPolicyContainer)" -SearchBase $gpcSearchBase -Properties ObjectGUID, displayName, Description, gPCFileSysPath, gPCFunctionalityVersion, gPCMachineExtensionNames, gPCUserExtensionNames, gPCWQLFilter, versionNumber, flags, whenCreated, whenChanged @adServerParams -ErrorAction Stop)
    foreach ($gpc in $gpcObjects) {
        $guidText = Normalize-GuidText -Value $gpc.Name
        if ($null -ne $guidText) { $gpcByGuid[$guidText] = $gpc }
        $gpcByDn[[string]$gpc.DistinguishedName.ToLowerInvariant()] = $gpc
    }
    $rootStates.gpc_directory = New-SourceState -Status "observed" -Source "Get-ADObject groupPolicyContainer" -Detail $null -Error $null -Coverage ([pscustomobject]@{ objects = $gpcObjects.Count }) -Value $null
}
catch {
    $status = Get-ErrorStatus -Exception $_.Exception
    $rootStates.gpc_directory = New-SourceState -Status $status -Source "Get-ADObject groupPolicyContainer" -Detail "Каталог GPC не собран" -Error $_.Exception.Message -Coverage $null -Value $null
    [void]$collectionErrors.Add((New-CollectionError -Stage "gpc_directory" -Status $status -Message $_.Exception.Message -EntityType "domain" -EntityId $domainDn))
}

$gpoObjects = @()
try {
    $gpoObjects = @(Get-GPO -All @gpParams -ErrorAction Stop)
    $rootStates.gpo_list = New-SourceState -Status "observed" -Source "Get-GPO -All" -Detail $null -Error $null -Coverage ([pscustomobject]@{ gpos = $gpoObjects.Count }) -Value $null
}
catch {
    $status = Get-ErrorStatus -Exception $_.Exception
    $rootStates.gpo_list = New-SourceState -Status $status -Source "Get-GPO -All" -Detail "Список GPO не собран" -Error $_.Exception.Message -Coverage $null -Value $null
    [void]$collectionErrors.Add((New-CollectionError -Stage "gpo_list" -Status $status -Message $_.Exception.Message -EntityType "domain" -EntityId $domainDn))
}

$gpoById = @{}
$gpoIdByGuid = @{}
$gpoIdByGpcDn = @{}
foreach ($gpo in $gpoObjects) {
    $guidText = Normalize-GuidText -Value $gpo.Id
    if ($null -eq $guidText) { continue }
    $gpoId = "gpo-$($guidText.ToLowerInvariant())"
    $gpoIdByGuid[$guidText] = $gpoId

    $gpc = $null
    if ($gpcByGuid.ContainsKey($guidText)) { $gpc = $gpcByGuid[$guidText] }
    if ($null -ne $gpc) { $gpoIdByGpcDn[[string]$gpc.DistinguishedName.ToLowerInvariant()] = $gpoId }

    $statusText = [string]$gpo.GpoStatus
    $computerEnabled = Get-GpoSideEnabled -SideObject $gpo.Computer -GpoStatus $statusText -Side "computer"
    $userEnabled = Get-GpoSideEnabled -SideObject $gpo.User -GpoStatus $statusText -Side "user"
    $ownerName = [string]$gpo.Owner
    $ownerSid = Resolve-AccountSid -Identity $ownerName
    $gpcPath = if ($null -ne $gpc) { [string]$gpc.gPCFileSysPath } else { $null }
    $gpcFlags = if ($null -ne $gpc -and $null -ne $gpc.flags) { [int]$gpc.flags } else { 0 }
    $wmiRaw = if ($null -ne $gpc) { [string]$gpc.gPCWQLFilter } else { $null }
    $wmiGuid = Normalize-GuidText -Value $wmiRaw

    $record = [pscustomobject][ordered]@{
        id                = $gpoId
        guid              = $guidText
        display_name      = [string]$gpo.DisplayName
        domain_name       = $domainDns
        owner             = [pscustomobject][ordered]@{ name = $ownerName; sid = $ownerSid }
        description       = [string](Get-FirstPropertyValue -InputObject $gpo -Names @("Description"))
        creation_time     = ConvertTo-IsoUtc -Value $gpo.CreationTime
        modification_time = ConvertTo-IsoUtc -Value $gpo.ModificationTime
        gpo_status        = $statusText
        computer          = [pscustomobject][ordered]@{
            enabled           = $computerEnabled
            directory_version = Get-FirstPropertyValue -InputObject $gpo.Computer -Names @("DSVersion", "DirectoryVersion")
            sysvol_version    = Get-FirstPropertyValue -InputObject $gpo.Computer -Names @("SysvolVersion", "SysVolVersion")
            settings_count    = 0
            extensions        = @()
            source_state      = New-SourceState -Status "not_evaluated" -Source "Get-GPOReport XML" -Detail "Отчёт ещё не обработан" -Error $null -Coverage $null -Value $null
        }
        user              = [pscustomobject][ordered]@{
            enabled           = $userEnabled
            directory_version = Get-FirstPropertyValue -InputObject $gpo.User -Names @("DSVersion", "DirectoryVersion")
            sysvol_version    = Get-FirstPropertyValue -InputObject $gpo.User -Names @("SysvolVersion", "SysVolVersion")
            settings_count    = 0
            extensions        = @()
            source_state      = New-SourceState -Status "not_evaluated" -Source "Get-GPOReport XML" -Detail "Отчёт ещё не обработан" -Error $null -Coverage $null -Value $null
        }
        gpc               = [pscustomobject][ordered]@{
            distinguished_name     = if ($null -ne $gpc) { [string]$gpc.DistinguishedName } else { $null }
            gpc_file_sys_path      = $gpcPath
            flags                  = [pscustomobject][ordered]@{
                raw               = $gpcFlags
                computer_disabled = -not $computerEnabled
                user_disabled     = -not $userEnabled
            }
            functionality_version  = if ($null -ne $gpc) { $gpc.gPCFunctionalityVersion } else { $null }
            version_number         = if ($null -ne $gpc) { $gpc.versionNumber } else { $null }
            machine_extension_names = if ($null -ne $gpc) { @(Get-GpcExtensionIds -Value $gpc.gPCMachineExtensionNames) } else { @() }
            user_extension_names    = if ($null -ne $gpc) { @(Get-GpcExtensionIds -Value $gpc.gPCUserExtensionNames) } else { @() }
            wmi_filter_raw          = $wmiRaw
        }
        gpt               = [pscustomobject][ordered]@{
            path        = $gpcPath
            probe_path  = $null
            status      = "not_evaluated"
            ini_version = $null
            detail      = "GPT.INI ещё не проверен"
        }
        wmi_filter_id     = if ($null -ne $wmiGuid) { "wmi-$($wmiGuid.ToLowerInvariant())" } else { $null }
        link_ids          = @()
        setting_ids       = @()
        permission_ids    = @()
        source_states     = [ordered]@{
            gpo         = New-SourceState -Status "observed" -Source "Get-GPO -All" -Detail $null -Error $null -Coverage $null -Value $null
            report      = New-SourceState -Status "not_evaluated" -Source "Get-GPOReport XML" -Detail "Отчёт ещё не обработан" -Error $null -Coverage $null -Value $null
            gpc         = if ($null -ne $gpc) { New-SourceState -Status "observed" -Source "Get-ADObject groupPolicyContainer" -Detail $null -Error $null -Coverage $null -Value $null } else { New-SourceState -Status "no_record" -Source "Get-ADObject groupPolicyContainer" -Detail "GPC не найден по GUID" -Error $null -Coverage $null -Value $null }
            gpt         = New-SourceState -Status "not_evaluated" -Source "gPCFileSysPath/GPT.INI" -Detail "GPT.INI ещё не проверен" -Error $null -Coverage $null -Value $null
            links       = New-SourceState -Status "not_evaluated" -Source "gPLink inventory" -Detail "Ссылки ещё не обработаны" -Error $null -Coverage $null -Value $null
            permissions = New-SourceState -Status "not_evaluated" -Source "Get-GPPermission -All" -Detail "Разрешения ещё не обработаны" -Error $null -Coverage $null -Value $null
            wmi_filter  = if ($null -eq $wmiGuid) { New-SourceState -Status "not_applicable" -Source "gPCWQLFilter" -Detail "WMI-фильтр не назначен" -Error $null -Coverage $null -Value $null } else { New-SourceState -Status "not_evaluated" -Source "gPCWQLFilter" -Detail "Ссылка ещё не разрешена" -Error $null -Coverage $null -Value $null }
        }
        unresolved_link_references = @()
        collection_errors = @()
    }
    [void]$gpoRecords.Add($record)
    $gpoById[$gpoId] = $record
}

# Read WMI filter objects before resolving per-GPO references.
$wmiByGuid = @{}
try {
    $wmiSearchBase = "CN=SOM,CN=WMIPolicy,CN=System,$domainDn"
    $wmiObjects = @(Get-ADObject -LDAPFilter "(objectClass=msWMI-Som)" -SearchBase $wmiSearchBase -Properties "msWMI-ID", "msWMI-Name", "msWMI-Parm1", "msWMI-Parm2", "msWMI-Author", "msWMI-CreationDate", "msWMI-ChangeDate" @adServerParams -ErrorAction Stop)
    foreach ($wmi in $wmiObjects) {
        $guidText = Normalize-GuidText -Value $wmi.'msWMI-ID'
        if ($null -eq $guidText) { $guidText = Normalize-GuidText -Value $wmi.Name }
        if ($null -eq $guidText) { continue }
        $wmiId = "wmi-$($guidText.ToLowerInvariant())"
        $record = [pscustomobject][ordered]@{
            id                = $wmiId
            guid              = $guidText
            distinguished_name = [string]$wmi.DistinguishedName
            name              = [string]$wmi.'msWMI-Name'
            description       = [string]$wmi.'msWMI-Parm1'
            author            = [string]$wmi.'msWMI-Author'
            creation_time     = ConvertFrom-WmiDateText -Value $wmi.'msWMI-CreationDate'
            modification_time = ConvertFrom-WmiDateText -Value $wmi.'msWMI-ChangeDate'
            queries           = @(ConvertFrom-WmiParm2 -Raw ([string]$wmi.'msWMI-Parm2'))
            used_by_gpo_ids   = @()
            source_state      = New-SourceState -Status "observed" -Source "Get-ADObject msWMI-Som" -Detail $null -Error $null -Coverage $null -Value $null
            collection_errors = @()
        }
        [void]$wmiRecords.Add($record)
        $wmiByGuid[$guidText] = $record
    }
    $rootStates.wmi_filters = New-SourceState -Status "observed" -Source "Get-ADObject msWMI-Som" -Detail $null -Error $null -Coverage ([pscustomobject]@{ objects = $wmiRecords.Count; unresolved_references = 0 }) -Value $null
}
catch {
    $status = Get-ErrorStatus -Exception $_.Exception
    $rootStates.wmi_filters = New-SourceState -Status $status -Source "Get-ADObject msWMI-Som" -Detail "WMI-фильтры не собраны" -Error $_.Exception.Message -Coverage $null -Value $null
    [void]$collectionErrors.Add((New-CollectionError -Stage "wmi_filters" -Status $status -Message $_.Exception.Message -EntityType "domain" -EntityId $domainDn))
}

$unresolvedWmiCount = 0
foreach ($gpoRecord in $gpoRecords) {
    if ($null -eq $gpoRecord.wmi_filter_id) { continue }
    $wmiGuid = $gpoRecord.wmi_filter_id.Substring("wmi-".Length).ToUpperInvariant()
    if ($wmiByGuid.ContainsKey($wmiGuid)) {
        $wmiRecord = $wmiByGuid[$wmiGuid]
        $wmiRecord.used_by_gpo_ids += $gpoRecord.id
        $gpoRecord.source_states.wmi_filter = New-SourceState -Status "observed" -Source "gPCWQLFilter -> msWMI-Som" -Detail $wmiRecord.name -Error $null -Coverage $null -Value $null
    }
    else {
        $unresolvedWmiCount++
        $baseState = $rootStates.wmi_filters.status
        $status = if ($baseState -eq "observed") { "no_record" } else { $baseState }
        $gpoRecord.source_states.wmi_filter = New-SourceState -Status $status -Source "gPCWQLFilter -> msWMI-Som" -Detail "WMI reference was not resolved" -Error $null -Coverage $null -Value $null
    }
}
if ($null -ne $rootStates.wmi_filters.coverage) { $rootStates.wmi_filters.coverage.unresolved_references = $unresolvedWmiCount }
if ($unresolvedWmiCount -gt 0 -and $rootStates.wmi_filters.status -eq "observed") { $rootStates.wmi_filters.status = "partial" }

# Collect all supported scope-of-management objects and parse gPLink/gPOptions.
$scopeStageFailures = 0
$scopeInputs = New-Object System.Collections.ArrayList
try {
    $domainScope = Get-ADObject -Identity $domainDn -Properties gPLink, gPOptions, canonicalName, name @adServerParams -ErrorAction Stop
    [void]$scopeInputs.Add([pscustomobject]@{ object = $domainScope; type = "domain"; name = $domainDns; canonical = "$domainDns/" })
}
catch {
    $scopeStageFailures++
    $status = Get-ErrorStatus -Exception $_.Exception
    [void]$collectionErrors.Add((New-CollectionError -Stage "domain_links" -Status $status -Message $_.Exception.Message -EntityType "domain" -EntityId $domainDn))
}

try {
    $ous = @(Get-ADOrganizationalUnit -Filter * -SearchBase $domainDn -SearchScope Subtree -Properties gPLink, gPOptions, canonicalName @adServerParams -ErrorAction Stop)
    foreach ($ou in $ous) {
        [void]$scopeInputs.Add([pscustomobject]@{ object = $ou; type = "ou"; name = [string]$ou.Name; canonical = [string]$ou.CanonicalName })
    }
}
catch {
    $scopeStageFailures++
    $status = Get-ErrorStatus -Exception $_.Exception
    [void]$collectionErrors.Add((New-CollectionError -Stage "ou_links" -Status $status -Message $_.Exception.Message -EntityType "domain" -EntityId $domainDn))
}

if ($IncludeSites) {
    try {
        $siteSearchBase = "CN=Sites,$configDn"
        $sites = @(Get-ADObject -LDAPFilter "(objectClass=site)" -SearchBase $siteSearchBase -Properties gPLink, gPOptions, name @adServerParams -ErrorAction Stop)
        foreach ($site in $sites) {
            [void]$scopeInputs.Add([pscustomobject]@{ object = $site; type = "site"; name = [string]$site.Name; canonical = "Sites/$($site.Name)" })
        }
    }
    catch {
        $scopeStageFailures++
        $status = Get-ErrorStatus -Exception $_.Exception
        [void]$collectionErrors.Add((New-CollectionError -Stage "site_links" -Status $status -Message $_.Exception.Message -EntityType "forest" -EntityId $configDn))
    }
}
else {
    $scopeStageFailures++
    [void]$collectionErrors.Add((New-CollectionError -Stage "site_links" -Status "not_collected" -Message "Site links were explicitly excluded by IncludeSites=false." -EntityType "forest" -EntityId $configDn))
}

foreach ($input in $scopeInputs) {
    $scopeObject = $input.object
    $scopeDn = [string]$scopeObject.DistinguishedName
    $scopeId = New-StableId -Prefix "scope" -Seed $scopeDn.ToLowerInvariant()
    $rawLinks = [string]$scopeObject.gPLink
    $parsedLinks = @(ConvertFrom-GPLink -Raw $rawLinks)
    $directLinkIds = New-Object System.Collections.ArrayList

    foreach ($parsed in $parsedLinks) {
        $gpcDnKey = $parsed.gpc_dn.ToLowerInvariant()
        if ($gpoIdByGpcDn.ContainsKey($gpcDnKey)) {
            $gpoId = $gpoIdByGpcDn[$gpcDnKey]
            $gpoRecord = $gpoById[$gpoId]
            $linkSeed = "{0}|{1}|{2}" -f $scopeDn.ToLowerInvariant(), $gpoId, $parsed.order
            $linkId = New-StableId -Prefix "link" -Seed $linkSeed
            $link = [pscustomobject][ordered]@{
                id           = $linkId
                gpo_id       = $gpoId
                gpo_name     = $gpoRecord.display_name
                scope_id     = $scopeId
                scope_name   = [string]$input.name
                scope_type   = [string]$input.type
                scope_dn     = $scopeDn
                enabled      = [bool]$parsed.enabled
                enforced     = [bool]$parsed.enforced
                order        = [int]$parsed.order
                order_source = [string]$parsed.order_source
                raw_options  = [int]$parsed.raw_options
                source_state = New-SourceState -Status "observed" -Source "gPLink parser" -Detail $null -Error $null -Coverage $null -Value $null
            }
            [void]$linkRecords.Add($link)
            [void]$directLinkIds.Add($linkId)
            $gpoRecord.link_ids += $linkId
        }
        else {
            $unresolvedId = New-StableId -Prefix "unresolved-link" -Seed ("{0}|{1}|{2}" -f $scopeDn, $parsed.gpc_dn, $parsed.order)
            [void]$unresolvedLinks.Add([pscustomobject][ordered]@{
                id          = $unresolvedId
                scope_id    = $scopeId
                scope_dn    = $scopeDn
                raw_gpc_dn  = $parsed.gpc_dn
                raw_options = [int]$parsed.raw_options
                source_state = New-SourceState -Status "no_record" -Source "gPLink parser" -Detail "GPC DN отсутствует среди собранных GPO" -Error $null -Coverage $null -Value $null
            })
        }
    }

    $blocked = $false
    if ($null -ne $scopeObject.gPOptions) { $blocked = (([int]$scopeObject.gPOptions -band 1) -ne 0) }
    [void]$scopeRecords.Add([pscustomobject][ordered]@{
        id                      = $scopeId
        name                    = [string]$input.name
        scope_type              = [string]$input.type
        distinguished_name      = $scopeDn
        canonical_path          = [string]$input.canonical
        gpo_inheritance_blocked = $blocked
        direct_link_ids         = @($directLinkIds)
        source_states           = [ordered]@{
            directory = New-SourceState -Status "observed" -Source "Get-ADObject gPLink/gPOptions" -Detail $null -Error $null -Coverage $null -Value $null
            links     = New-SourceState -Status "observed" -Source "gPLink parser" -Detail "Прямые ссылки разобраны" -Error $null -Coverage ([pscustomobject]@{ parsed = $parsedLinks.Count; unresolved = @($parsedLinks).Count - @($directLinkIds).Count }) -Value $null
        }
        collection_errors = @()
    })
}

if ($scopeStageFailures -eq 0) {
    $rootStates.links = New-SourceState -Status "observed" -Source "gPLink/gPOptions inventory" -Detail $null -Error $null -Coverage ([pscustomobject]@{ scopes = $scopeRecords.Count; links = $linkRecords.Count; unresolved = $unresolvedLinks.Count }) -Value $null
}
else {
    $rootStates.links = New-SourceState -Status "partial" -Source "gPLink/gPOptions inventory" -Detail "Не все supported SOM были собраны; квалификация unlinked недоступна." -Error $null -Coverage ([pscustomobject]@{ scopes = $scopeRecords.Count; links = $linkRecords.Count; unresolved = $unresolvedLinks.Count; failed_stages = $scopeStageFailures }) -Value $null
}
foreach ($gpoRecord in $gpoRecords) {
    $gpoRecord.source_states.links = New-SourceState -Status $rootStates.links.status -Source "gPLink inventory" -Detail ("Наблюдаемых ссылок: {0}" -f $gpoRecord.link_ids.Count) -Error $rootStates.links.error -Coverage $rootStates.links.coverage -Value $null
}

# Read per-GPO report XML and normalize leaf observations.
$reportSuccess = 0
$reportFailed = 0
if ($SettingsMode -eq "None") {
    $rootStates.gpo_reports = New-SourceState -Status "not_collected" -Source "Get-GPOReport XML" -Detail "Отключено параметром SettingsMode=None" -Error $null -Coverage ([pscustomobject]@{ requested = $gpoRecords.Count; successful = 0; failed = 0 }) -Value $null
    foreach ($gpoRecord in $gpoRecords) {
        $state = New-SourceState -Status "not_collected" -Source "Get-GPOReport XML" -Detail "Отключено параметром SettingsMode=None" -Error $null -Coverage $null -Value $null
        $gpoRecord.source_states.report = $state
        $gpoRecord.computer.source_state = $state
        $gpoRecord.user.source_state = $state
    }
}
else {
    foreach ($gpoObject in $gpoObjects) {
        $guidText = Normalize-GuidText -Value $gpoObject.Id
        if ($null -eq $guidText) { continue }
        $gpoId = $gpoIdByGuid[$guidText]
        $gpoRecord = $gpoById[$gpoId]
        try {
            $xmlText = Get-GPOReport -Guid ([Guid]$guidText) -ReportType Xml @gpParams -ErrorAction Stop
            [xml]$xml = $xmlText
            if (-not [string]::IsNullOrWhiteSpace($CompatibilityProjectionPath)) {
                $compatibilityReportFacts[$guidText] = ConvertFrom-SLIGpoReportXml -XmlText $xmlText
            }
            $computerResult = Convert-GpoReportSettings -Xml $xml -GpoId $gpoId -GpoName $gpoRecord.display_name -Side "computer" -Maximum $MaxSettingsPerGpo
            $remaining = [Math]::Max(0, $MaxSettingsPerGpo - $computerResult.rows.Count)
            $userResult = Convert-GpoReportSettings -Xml $xml -GpoId $gpoId -GpoName $gpoRecord.display_name -Side "user" -Maximum $remaining
            foreach ($row in @($computerResult.rows) + @($userResult.rows)) {
                [void]$settingRecords.Add($row)
                $gpoRecord.setting_ids += $row.id
            }
            $gpoRecord.computer.settings_count = $computerResult.rows.Count
            $gpoRecord.user.settings_count = $userResult.rows.Count
            $gpoRecord.computer.extensions = @($computerResult.rows | Select-Object -ExpandProperty extension -Unique)
            $gpoRecord.user.extensions = @($userResult.rows | Select-Object -ExpandProperty extension -Unique)
            $combinedStatus = if ($computerResult.truncated -or $userResult.truncated) { "partial" } elseif ($computerResult.source_status -eq "missing_in_source" -and $userResult.source_status -eq "missing_in_source") { "missing_in_source" } else { "observed" }
            $detail = if ($combinedStatus -eq "partial") { "Нормализация ограничена MaxSettingsPerGpo=$MaxSettingsPerGpo" } else { "XML прочитан и нормализован" }
            $state = New-SourceState -Status $combinedStatus -Source "Get-GPOReport XML" -Detail $detail -Error $null -Coverage ([pscustomobject]@{ settings = $gpoRecord.setting_ids.Count }) -Value $null
            $gpoRecord.source_states.report = $state
            $gpoRecord.computer.source_state = New-SourceState -Status $computerResult.source_status -Source "Get-GPOReport XML" -Detail $detail -Error $null -Coverage ([pscustomobject]@{ settings = $computerResult.rows.Count }) -Value $null
            $gpoRecord.user.source_state = New-SourceState -Status $userResult.source_status -Source "Get-GPOReport XML" -Detail $detail -Error $null -Coverage ([pscustomobject]@{ settings = $userResult.rows.Count }) -Value $null
            $reportSuccess++
        }
        catch {
            $reportFailed++
            $status = Get-ErrorStatus -Exception $_.Exception
            $state = New-SourceState -Status $status -Source "Get-GPOReport XML" -Detail "XML-отчёт GPO не обработан" -Error $_.Exception.Message -Coverage $null -Value $null
            $gpoRecord.source_states.report = $state
            $gpoRecord.computer.source_state = $state
            $gpoRecord.user.source_state = $state
            $errorRecord = New-CollectionError -Stage "gpo_report" -Status $status -Message $_.Exception.Message -EntityType "gpo" -EntityId $gpoId
            $gpoRecord.collection_errors += $errorRecord
            [void]$collectionErrors.Add($errorRecord)
        }
    }
    $reportRootStatus = if ($reportFailed -eq 0) { "observed" } elseif ($reportSuccess -gt 0) { "partial" } else { "failed" }
    $rootStates.gpo_reports = New-SourceState -Status $reportRootStatus -Source "Get-GPOReport XML" -Detail $null -Error $null -Coverage ([pscustomobject]@{ requested = $gpoRecords.Count; successful = $reportSuccess; failed = $reportFailed; rows = $settingRecords.Count }) -Value $null
}

# Read ordered GPC DACLs separately from the summarized GPPermission levels.
# Raw ACE order preserves explicit/inherited allow/deny precedence.
foreach ($gpoObject in $gpoObjects) {
    $guidText = Normalize-GuidText -Value $gpoObject.Id
    if ($null -eq $guidText) { continue }
    $gpoRecord = $gpoById[$gpoIdByGuid[$guidText]]
    $gpoRecord.source_states.acl = New-SourceState -Status "not_collected" -Source "GPC nTSecurityDescriptor DACL" -Detail $null -Error $null -Coverage $null -Value $null
    if ($SkipPermissions) { continue }
    try {
        $gpc = $gpcByGuid[$guidText]
        if ($null -eq $gpc) { throw "GPC unavailable for DACL collection" }
        $aclObject = Get-ADObject -Identity $gpc.DistinguishedName -Properties nTSecurityDescriptor @adServerParams -ErrorAction Stop
        $descriptor = $aclObject.nTSecurityDescriptor
        if ($null -eq $descriptor) { throw "GPC DACL was not returned" }
        $raw = [System.Security.AccessControl.RawSecurityDescriptor]::new($descriptor.GetSecurityDescriptorBinaryForm(), 0)
        if ($null -eq $raw.DiscretionaryAcl) { throw "Null GPC DACL is unsupported" }
        $aclPartial = $false
        for ($aceIndex = 0; $aceIndex -lt $raw.DiscretionaryAcl.Count; $aceIndex++) {
            if ($aclRecords.Count -ge 100000) { $aclPartial = $true; break }
            $ace = $raw.DiscretionaryAcl[$aceIndex]
            if ($ace -isnot [System.Security.AccessControl.QualifiedAce] -or $ace.IsCallback -or [string]$ace.AceQualifier -notin @("AccessAllowed", "AccessDenied")) {
                $aclPartial = $true
                continue
            }
            $objectType = [Guid]::Empty
            if ($ace -is [System.Security.AccessControl.ObjectAce] -and ($ace.ObjectAceFlags -band [System.Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent)) { $objectType = $ace.ObjectAceType }
            [void]$aclRecords.Add([pscustomobject][ordered]@{
                id = New-StableId -Prefix "ace" -Seed ("{0}|{1}" -f $gpoRecord.id, $aceIndex)
                gpo_id = $gpoRecord.id
                ace_index = $aceIndex
                trustee_sid = [string]$ace.SecurityIdentifier.Value
                access_mask = [int64]$ace.AccessMask
                access_control_type = if ([string]$ace.AceQualifier -eq "AccessAllowed") { "Allow" } else { "Deny" }
                object_type = [string]$objectType
                inherited = [bool]($ace.AceFlags -band [System.Security.AccessControl.AceFlags]::Inherited)
                propagation_flags = if ($ace.AceFlags -band [System.Security.AccessControl.AceFlags]::InheritOnly) { 2 } else { 0 }
            })
        }
        $gpoRecord.source_states.acl = New-SourceState -Status $(if ($aclPartial) { "partial" } else { "observed" }) -Source "GPC nTSecurityDescriptor DACL" -Detail $null -Error $null -Coverage ([pscustomobject]@{ rows = $raw.DiscretionaryAcl.Count }) -Value $null
    }
    catch {
        $gpoRecord.source_states.acl = New-SourceState -Status (Get-ErrorStatus -Exception $_.Exception) -Source "GPC nTSecurityDescriptor DACL" -Detail "GPC DACL unavailable" -Error $null -Coverage $null -Value $null
    }
}

# Read permissions per GPO.
$permissionSuccess = 0
$permissionFailed = 0
if ($SkipPermissions) {
    $rootStates.permissions = New-SourceState -Status "not_collected" -Source "Get-GPPermission -All" -Detail "Отключено параметром SkipPermissions" -Error $null -Coverage ([pscustomobject]@{ requested = $gpoRecords.Count; successful = 0; failed = 0; rows = 0 }) -Value $null
    foreach ($gpoRecord in $gpoRecords) { $gpoRecord.source_states.permissions = $rootStates.permissions }
}
else {
    foreach ($gpoObject in $gpoObjects) {
        $guidText = Normalize-GuidText -Value $gpoObject.Id
        if ($null -eq $guidText) { continue }
        $gpoId = $gpoIdByGuid[$guidText]
        $gpoRecord = $gpoById[$gpoId]
        try {
            $permissionRows = @(Get-GPPermission -Guid ([Guid]$guidText) -All @gpParams -ErrorAction Stop)
            if (-not [string]::IsNullOrWhiteSpace($CompatibilityProjectionPath)) {
                $compatibilityPermissionFacts[$guidText] = ConvertFrom-SLIGpoPermissionObjects -PermissionObjects $permissionRows
            }
            foreach ($permission in $permissionRows) {
                $trustee = $permission.Trustee
                $trusteeName = [string](Get-FirstPropertyValue -InputObject $trustee -Names @("Name"))
                $trusteeSid = [string](Get-FirstPropertyValue -InputObject $trustee -Names @("Sid", "SID"))
                $trusteeType = [string](Get-FirstPropertyValue -InputObject $trustee -Names @("SidType", "Type"))
                $permissionText = [string]$permission.Permission
                $seed = "{0}|{1}|{2}" -f $gpoId, $trusteeSid, $permissionText
                $record = [pscustomobject][ordered]@{
                    id           = New-StableId -Prefix "perm" -Seed $seed
                    gpo_id       = $gpoId
                    gpo_name     = $gpoRecord.display_name
                    trustee_name = $trusteeName
                    trustee_sid  = $trusteeSid
                    trustee_type = $trusteeType
                    permission   = $permissionText
                    inherited    = [bool](Get-FirstPropertyValue -InputObject $permission -Names @("Inherited"))
                    source_state = New-SourceState -Status "observed" -Source "Get-GPPermission -All" -Detail $null -Error $null -Coverage $null -Value $null
                }
                [void]$permissionRecords.Add($record)
                $gpoRecord.permission_ids += $record.id
            }
            $gpoRecord.source_states.permissions = New-SourceState -Status "observed" -Source "Get-GPPermission -All" -Detail ("Строк: {0}" -f $permissionRows.Count) -Error $null -Coverage ([pscustomobject]@{ rows = $permissionRows.Count }) -Value $null
            $permissionSuccess++
        }
        catch {
            $permissionFailed++
            $status = Get-ErrorStatus -Exception $_.Exception
            $state = New-SourceState -Status $status -Source "Get-GPPermission -All" -Detail "Разрешения GPO не собраны" -Error $_.Exception.Message -Coverage $null -Value $null
            $gpoRecord.source_states.permissions = $state
            $errorRecord = New-CollectionError -Stage "gpo_permissions" -Status $status -Message $_.Exception.Message -EntityType "gpo" -EntityId $gpoId
            $gpoRecord.collection_errors += $errorRecord
            [void]$collectionErrors.Add($errorRecord)
        }
    }
    $permissionRootStatus = if ($permissionFailed -eq 0) { "observed" } elseif ($permissionSuccess -gt 0) { "partial" } else { "failed" }
    $rootStates.permissions = New-SourceState -Status $permissionRootStatus -Source "Get-GPPermission -All" -Detail $null -Error $null -Coverage ([pscustomobject]@{ requested = $gpoRecords.Count; successful = $permissionSuccess; failed = $permissionFailed; rows = $permissionRecords.Count }) -Value $null
}

# Read GPT.INI on a UNC path explicitly pinned to the selected DC when possible.
$gptSuccess = 0
$gptFailed = 0
if ($SkipSysvol) {
    $rootStates.sysvol_gpt = New-SourceState -Status "not_collected" -Source "gPCFileSysPath/GPT.INI" -Detail "Отключено параметром SkipSysvol" -Error $null -Coverage ([pscustomobject]@{ requested = $gpoRecords.Count; successful = 0; failed = 0 }) -Value $null
    foreach ($gpoRecord in $gpoRecords) {
        $gpoRecord.gpt.status = "not_collected"
        $gpoRecord.gpt.detail = "Отключено параметром SkipSysvol"
        $gpoRecord.source_states.gpt = $rootStates.sysvol_gpt
    }
}
else {
    foreach ($gpoRecord in $gpoRecords) {
        $gptPath = [string]$gpoRecord.gpc.gpc_file_sys_path
        if ([string]::IsNullOrWhiteSpace($gptPath)) {
            $gptFailed++
            $state = New-SourceState -Status "missing_in_source" -Source "gPCFileSysPath/GPT.INI" -Detail "gPCFileSysPath отсутствует" -Error $null -Coverage $null -Value $null
            $gpoRecord.gpt.status = "missing_in_source"
            $gpoRecord.gpt.detail = "gPCFileSysPath отсутствует"
            $gpoRecord.source_states.gpt = $state
            continue
        }
        $probePath = Get-ProbeGptPath -OriginalPath $gptPath -QueryServer $queryServer
        $gpoRecord.gpt.probe_path = $probePath
        try {
            $iniVersion = Read-GptIniVersion -GptPath $probePath
            $gpoRecord.gpt.status = "observed"
            $gpoRecord.gpt.ini_version = $iniVersion
            $gpoRecord.gpt.detail = "GPT.INI прочитан на выбранном UNC-источнике"
            $gpoRecord.source_states.gpt = New-SourceState -Status "observed" -Source "gPCFileSysPath/GPT.INI" -Detail $gpoRecord.gpt.detail -Error $null -Coverage ([pscustomobject]@{ probe_path = $probePath }) -Value $iniVersion
            $gptSuccess++
        }
        catch {
            $gptFailed++
            $status = Get-ErrorStatus -Exception $_.Exception
            $gpoRecord.gpt.status = $status
            $gpoRecord.gpt.detail = $_.Exception.Message
            $gpoRecord.source_states.gpt = New-SourceState -Status $status -Source "gPCFileSysPath/GPT.INI" -Detail "GPT.INI не прочитан" -Error $_.Exception.Message -Coverage ([pscustomobject]@{ probe_path = $probePath }) -Value $null
            $errorRecord = New-CollectionError -Stage "gpt_ini" -Status $status -Message $_.Exception.Message -EntityType "gpo" -EntityId $gpoRecord.id
            $gpoRecord.collection_errors += $errorRecord
            [void]$collectionErrors.Add($errorRecord)
        }
    }
    $gptRootStatus = if ($gptFailed -eq 0) { "observed" } elseif ($gptSuccess -gt 0) { "partial" } else { "failed" }
    $rootStates.sysvol_gpt = New-SourceState -Status $gptRootStatus -Source "gPCFileSysPath/GPT.INI" -Detail "Проверяется только выбранный UNC/DC; это не all-DC replication check." -Error $null -Coverage ([pscustomobject]@{ requested = $gpoRecords.Count; successful = $gptSuccess; failed = $gptFailed; query_server = $queryServer }) -Value $null
}

$rootStatuses = @($rootStates.Values | ForEach-Object { $_.status })
$collectionStatus = if ($rootStatuses -contains "failed" -or $rootStatuses -contains "access_denied" -or $rootStatuses -contains "parse_error") { "partial" } elseif ($rootStatuses -contains "partial" -or $rootStatuses -contains "not_collected" -or $rootStatuses -contains "not_evaluated") { "partial" } else { "complete" }
$completedAt = (Get-Date).ToUniversalTime().ToString("o")

$snapshot = [pscustomobject][ordered]@{
    schema_version    = "sli.ad-gpo.snapshot/1.0"
    collector_version = $script:CollectorVersion
    demo              = $false
    demo_notice       = $null
    started_at        = $startedAt
    completed_at      = $completedAt
    observed_at       = $script:ObservedAt
    collection_status = $collectionStatus
    domain            = [pscustomobject][ordered]@{
        dns_name                     = $domainDns
        dns_root                     = $domainDns
        netbios_name                 = [string]$domainInfo.NetBIOSName
        distinguished_name           = $domainDn
        forest                       = [string]$domainInfo.Forest
        query_dc                     = $queryServer
        query_server                 = $queryServer
        pdc_emulator                 = [string]$domainInfo.PDCEmulator
        configuration_naming_context = $configDn
    }
    scope             = [pscustomobject][ordered]@{
        domain        = $domainDns
        include_sites = $IncludeSites
        settings_mode = $SettingsMode
        permissions   = -not [bool]$SkipPermissions
        sysvol        = -not [bool]$SkipSysvol
    }
    source_states     = [pscustomobject]$rootStates
    gpos              = @($gpoRecords)
    scopes            = @($scopeRecords)
    links             = @($linkRecords)
    settings          = @($settingRecords)
    permissions       = @($permissionRecords)
    acl               = @($aclRecords)
    wmi_filters       = @($wmiRecords)
    unresolved_links  = @($unresolvedLinks)
    collection_errors = @($collectionErrors)
}

$outputDirectory = Split-Path -Parent $OutputPath
if (-not [string]::IsNullOrWhiteSpace($outputDirectory) -and -not [System.IO.Directory]::Exists($outputDirectory)) {
    [System.IO.Directory]::CreateDirectory($outputDirectory) | Out-Null
}
$json = $snapshot | ConvertTo-Json -Depth 100
$utf8WithoutBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($OutputPath, $json, $utf8WithoutBom)

if (-not [string]::IsNullOrWhiteSpace($CompatibilityProjectionPath)) {
    $compatibilityRecords = New-Object System.Collections.ArrayList
    foreach ($gpoObject in $gpoObjects) {
        $guidText = Normalize-GuidText -Value $gpoObject.Id
        if (
            $null -eq $guidText -or
            -not $compatibilityReportFacts.ContainsKey($guidText) -or
            -not $compatibilityPermissionFacts.ContainsKey($guidText)
        ) { throw "compatibility_projection_incomplete_source_observation" }
        if (-not $gpcByGuid.ContainsKey($guidText)) {
            throw "compatibility_projection_missing_gpc_identity"
        }
        $gpc = $gpcByGuid[$guidText]
        if ($null -eq $gpc.ObjectGUID) { throw "compatibility_projection_missing_gpc_objectguid" }
        $gpoDirectoryObjectGuid = ([guid]$gpc.ObjectGUID).ToString()
        $description = Get-FirstPropertyValue -InputObject $gpc -Names @("Description")
        $baseAttributes = [ordered]@{
            display_name = if ($gpc.DisplayName) { [string]$gpc.DisplayName } else { [string]$gpc.Name }
            sam_account_name = $null
            distinguished_name = $null
            enabled = $null
            object_class = "gpo"
            created_utc = ConvertTo-IsoUtc -Value $gpc.whenCreated
            modified_utc = ConvertTo-IsoUtc -Value $gpc.whenChanged
            description = if ($description -and ([string]$description).Length -gt 4096) { ([string]$description).Substring(0, 4096) } elseif ($description) { [string]$description } else { $null }
        }
        $attributes = Merge-SLIGpoGovernanceAttributes `
            -BaseAttributes $baseAttributes `
            -ReportFacts $compatibilityReportFacts[$guidText] `
            -PermissionFacts $compatibilityPermissionFacts[$guidText]
        [void]$compatibilityRecords.Add([pscustomobject][ordered]@{
            record_type = "entity"
            record_key = "ad:$(([string]$domainInfo.DomainSID).ToLowerInvariant()):$($gpoDirectoryObjectGuid.ToLowerInvariant())"
            section = "gpo_governance"
            observed_at_utc = $script:ObservedAt
            identity = [pscustomobject][ordered]@{
                kind = "gpo"
                domain_sid = [string]$domainInfo.DomainSID
                object_guid = $gpoDirectoryObjectGuid
                object_sid = $null
            }
            attributes = [pscustomobject]$attributes
        })
    }
    $compatibilityRecordsJson = ConvertTo-Json -InputObject @($compatibilityRecords) -Depth 20 -Compress
    if ([Text.Encoding]::UTF8.GetByteCount($compatibilityRecordsJson) -gt 26214400) {
        throw "compatibility_projection_size_ceiling_exceeded"
    }
    $compatibilityProjection = [pscustomobject][ordered]@{
        schema_version = "sli.ad-gpo.compatibility-projection/1.0"
        collection_status = $collectionStatus
        domain_sid = [string]$domainInfo.DomainSID
        observed_at_utc = $script:ObservedAt
        record_count = $compatibilityRecords.Count
        records_sha256 = Get-Sha256Hex -Text $compatibilityRecordsJson
        records = @($compatibilityRecords)
    }
    $compatibilityDirectory = Split-Path -Parent $CompatibilityProjectionPath
    if (-not [string]::IsNullOrWhiteSpace($compatibilityDirectory) -and -not [IO.Directory]::Exists($compatibilityDirectory)) {
        [IO.Directory]::CreateDirectory($compatibilityDirectory) | Out-Null
    }
    [IO.File]::WriteAllText(
        $CompatibilityProjectionPath,
        ($compatibilityProjection | ConvertTo-Json -Depth 20),
        $utf8WithoutBom
    )
}

[pscustomobject][ordered]@{
    ok                = $true
    output_path       = [System.IO.Path]::GetFullPath($OutputPath)
    schema_version    = $snapshot.schema_version
    collection_status = $snapshot.collection_status
    gpos              = $snapshot.gpos.Count
    scopes            = $snapshot.scopes.Count
    links             = $snapshot.links.Count
    settings          = $snapshot.settings.Count
    permissions       = $snapshot.permissions.Count
    wmi_filters       = $snapshot.wmi_filters.Count
    errors            = $snapshot.collection_errors.Count
}

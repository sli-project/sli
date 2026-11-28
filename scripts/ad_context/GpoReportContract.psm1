Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-SLIGpoReportContract {
    [CmdletBinding()]
    param()
    [pscustomobject][ordered]@{
        policy_limit = 72
        report_type = "Xml"
        per_policy_time_limit_seconds = 30
        total_time_limit_seconds = 900
        single_response_bytes_limit = 33554432
        total_response_bytes_limit = 268435456
        per_policy_setting_limit = 2048
        per_setting_property_limit = 64
        setting_property_value_length_limit = 4096
        file_poll_interval_ms = 50
        processing_order = "one_policy_at_a_time_stop_on_first_breach"
    }
}

function Get-SLIGpoPermissionContract {
    [CmdletBinding()]
    param()
    [pscustomobject][ordered]@{
        policy_limit = 72
        per_policy_permission_limit = 4096
        total_permission_limit = 65536
        per_policy_time_limit_seconds = 30
        total_time_limit_seconds = 900
        single_response_bytes_limit = 2097152
        total_response_bytes_limit = 67108864
        processing_order = "one_policy_at_a_time_stop_on_first_breach"
    }
}

function Get-SLIRequiredObjectProperty {
    param(
        [Parameter(Mandatory = $true)]$InputObject,
        [Parameter(Mandatory = $true)][string]$Name
    )
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) {
        throw "gpo_permission_missing_$($Name.ToLowerInvariant())"
    }
    $property.Value
}

function ConvertFrom-SLIGpoPermissionObjects {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$PermissionObjects
    )
    $contract = Get-SLIGpoPermissionContract
    if ($PermissionObjects.Count -gt $contract.per_policy_permission_limit) {
        throw "permission_count_ceiling_exceeded"
    }
    $allowedPermissionTypes = @(
        "GpoApply", "GpoRead", "GpoEdit",
        "GpoEditDeleteModifySecurity", "GpoCustom"
    )
    $allowedTrusteeTypes = @(
        "User", "Group", "Domain", "Alias", "WellKnownGroup",
        "DeletedAccount", "Invalid", "Unknown", "Computer", "Label"
    )
    $normalized = @(
        foreach ($permissionObject in $PermissionObjects) {
            $trustee = Get-SLIRequiredObjectProperty $permissionObject "Trustee"
            $sidValue = Get-SLIRequiredObjectProperty $trustee "Sid"
            try {
                $sid = ([Security.Principal.SecurityIdentifier]$sidValue).Value
            } catch {
                throw "invalid_gpo_permission_sid"
            }
            $trusteeType = [string](
                Get-SLIRequiredObjectProperty $trustee "SidType"
            )
            if ($trusteeType -notin $allowedTrusteeTypes) {
                throw "unsupported_gpo_permission_trustee_type"
            }
            $permission = [string](
                Get-SLIRequiredObjectProperty $permissionObject "Permission"
            )
            if ($permission -notin $allowedPermissionTypes) {
                throw "unsupported_gpo_permission_type"
            }
            [pscustomobject][ordered]@{
                trustee_sid = $sid
                trustee_type = $trusteeType
                permission = $permission
                denied = [bool](
                    Get-SLIRequiredObjectProperty $permissionObject "Denied"
                )
                inherited = [bool](
                    Get-SLIRequiredObjectProperty $permissionObject "Inherited"
                )
            }
        }
    )
    $serialized = ConvertTo-Json -InputObject @($normalized) -Depth 4 -Compress
    $responseBytes = [Text.Encoding]::UTF8.GetByteCount($serialized)
    if ($responseBytes -gt $contract.single_response_bytes_limit) {
        throw "response_size_ceiling_exceeded"
    }
    $applyAllowSids = @(
        $normalized |
            Where-Object { $_.permission -eq "GpoApply" -and -not $_.denied } |
            ForEach-Object { $_.trustee_sid } |
            Sort-Object -Unique
    )
    $applyDenySids = @(
        $normalized |
            Where-Object { $_.permission -eq "GpoApply" -and $_.denied } |
            ForEach-Object { $_.trustee_sid } |
            Sort-Object -Unique
    )
    [pscustomobject][ordered]@{
        permission_count = $normalized.Count
        response_bytes = $responseBytes
        permissions = @($normalized)
        gpo_apply_allow_sids = $applyAllowSids
        gpo_apply_deny_sids = $applyDenySids
        effective_access_evaluated = $false
    }
}

function Merge-SLIGpoGovernanceAttributes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$BaseAttributes,
        [Parameter(Mandatory = $true)]$ReportFacts,
        [Parameter(Mandatory = $true)]$PermissionFacts
    )
    if (
        $null -eq $ReportFacts.attributes -or
        $PermissionFacts.effective_access_evaluated -ne $false
    ) {
        throw "invalid_gpo_governance_merge_input"
    }
    $result = [ordered]@{}
    foreach ($key in $BaseAttributes.Keys) {
        $result[[string]$key] = $BaseAttributes[$key]
    }
    foreach ($key in @(
        "gpo_computer_enabled", "gpo_user_enabled",
        "link_count", "gpo_link_enabled_count", "gpo_link_enforced_count",
        "links", "gpo_wmi_filter_present", "gpo_wmi_filter_id",
        "gpo_startup_script_count", "gpo_logon_script_count",
        "gpo_scheduled_task_count", "gpo_service_count",
        "gpo_local_group_count", "gpo_settings"
    )) {
        $result[$key] = $ReportFacts.attributes.$key
    }
    if ($ReportFacts.attributes.modified_utc) {
        $result["modified_utc"] = $ReportFacts.attributes.modified_utc
    }
    $computerEnabled = $ReportFacts.attributes.gpo_computer_enabled
    $userEnabled = $ReportFacts.attributes.gpo_user_enabled
    $result["application_state"] = if (
        $computerEnabled -eq $true -and $userEnabled -eq $true
    ) {
        "both_enabled"
    } elseif ($computerEnabled -eq $true -and $userEnabled -eq $false) {
        "computer_only"
    } elseif ($computerEnabled -eq $false -and $userEnabled -eq $true) {
        "user_only"
    } elseif ($computerEnabled -eq $false -and $userEnabled -eq $false) {
        "disabled"
    } else {
        $null
    }
    $result["gpo_security_filtering_sids"] = @(
        $PermissionFacts.gpo_apply_allow_sids
    )
    $result["gpo_security_filtering_deny_sids"] = @(
        $PermissionFacts.gpo_apply_deny_sids
    )
    $result["gpo_security_filtering_collected"] = $true
    $result["gpo_security_filtering_effective_evaluated"] = $false
    $result["gpo_permission_count"] = [int]$PermissionFacts.permission_count
    $result["gpo_permission_custom_count"] = @(
        $PermissionFacts.permissions |
            Where-Object { $_.permission -eq "GpoCustom" }
    ).Count
    $result
}

function Get-SLIXmlChildText {
    param($Node, [string]$LocalName)
    if ($null -eq $Node) { return $null }
    $child = $Node.SelectSingleNode("./*[local-name()='$LocalName']")
    if ($null -eq $child) { return $null }
    $text = [string]$child.InnerText
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    $text.Trim()
}

function ConvertTo-SLINullableBoolean {
    param($Value)
    if ($null -eq $Value) { return $null }
    switch (([string]$Value).ToLowerInvariant()) {
        "true" { return $true }
        "false" { return $false }
        default { return $null }
    }
}

function Get-SLIGpoComponentCount {
    param($Section, [string]$Container, [string]$Item)
    if ($null -eq $Section) { return 0 }
    @($Section.SelectNodes(
        ".//*[local-name()='$Container']//*[local-name()='$Item']"
    )).Count
}

function Get-SLIGpoScriptCount {
    param($Section, [string]$ExpectedType)
    if ($null -eq $Section) { return 0 }
    $count = 0
    foreach ($script in @($Section.SelectNodes(".//*[local-name()='Script']"))) {
        $type = Get-SLIXmlChildText -Node $script -LocalName "Type"
        if ($type -and $type.Equals(
            $ExpectedType, [StringComparison]::OrdinalIgnoreCase
        )) { $count += 1 }
    }
    $count
}

function Test-SLIGpoSensitiveFieldName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    ($Name.ToLowerInvariant() -replace '[^a-z0-9]', '') -match '(password|cpassword|passwd|pwd|secret|privatekey|token|credential|apikey|accesskey|sharedkey|presharedkey|psk|encryptionkey|decryptionkey|symmetrickey|signingkey|keymaterial|passphrase|connectionstring)'
}

function Test-SLIGpoSensitiveValue {
    param([string]$Text, $RedactedFields)
    $sensitive = $false
    foreach ($match in [regex]::Matches($Text, '(?:^|[\s;,{<])["'']?(?<name>[\w.:-]+)["'']?\s*(?:=|:)\s*["'']?(?<label>[\w.:-]+)?')) {
        $name = $match.Groups['name'].Value
        $label = $match.Groups['label'].Value
        if (Test-SLIGpoSensitiveFieldName $name) {
            $sensitive = $true
            $null = $RedactedFields.Add($name.ToLowerInvariant())
        }
        if ($name -in @('name', 'key', 'valueName', 'property') -and
            (Test-SLIGpoSensitiveFieldName $label)) {
            $sensitive = $true
            $null = $RedactedFields.Add($label.ToLowerInvariant())
        }
    }
    if ($Text -match '-----BEGIN .*PRIVATE KEY-----') {
        $sensitive = $true
        $null = $RedactedFields.Add('privatekey')
    }
    return $sensitive
}

function Protect-SLIGpoXmlValues {
    param(
        [Parameter(Mandatory = $true)]$Node,
        $RedactedFields = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase),
        [bool]$SensitiveContext = $false,
        $ContextNode = $null
    )
    # Mask the tree before either normalizer reads text, attributes or hashes.
    $hidden = 'значение скрыто'
    $sensitive = $SensitiveContext
    $contextNodes = @($Node)
    if ($null -ne $ContextNode) { $contextNodes += @($ContextNode.SelectNodes('ancestor::*')) }
    foreach ($context in $contextNodes) {
        if (Test-SLIGpoSensitiveFieldName $context.LocalName) {
            $sensitive = $true
            $null = $RedactedFields.Add(([string]$context.LocalName).ToLowerInvariant())
        }
        foreach ($attribute in @($context.Attributes)) {
            if ($attribute.LocalName -in @('name', 'key', 'valueName', 'property') -and
                (Test-SLIGpoSensitiveFieldName $attribute.Value)) {
                $sensitive = $true
                $null = $RedactedFields.Add(([string]$attribute.Value).ToLowerInvariant())
            }
        }
        foreach ($child in @($context.SelectNodes('./*'))) {
            if ($child.LocalName -in @('Name', 'PolicyName', 'DisplayName', 'Key', 'KeyPath', 'ValueName', 'Property') -and
                (Test-SLIGpoSensitiveFieldName $child.InnerText)) {
                $sensitive = $true
                $null = $RedactedFields.Add(([string]$child.InnerText).ToLowerInvariant())
            }
        }
    }
    foreach ($attribute in @($Node.Attributes)) {
        if ($attribute.Prefix -eq 'xmlns' -or $attribute.Name -eq 'xmlns') { continue }
        if ($sensitive -or (Test-SLIGpoSensitiveFieldName $attribute.LocalName) -or
            (Test-SLIGpoSensitiveValue -Text $attribute.Value -RedactedFields $RedactedFields)) {
            if (Test-SLIGpoSensitiveFieldName $attribute.LocalName) {
                $null = $RedactedFields.Add(([string]$attribute.LocalName).ToLowerInvariant())
            }
            $attribute.Value = $hidden
        }
    }
    if (@($Node.SelectNodes('./*')).Count -eq 0) {
        $text = [string]$Node.InnerText
        if (Test-SLIGpoSensitiveValue -Text $text -RedactedFields $RedactedFields) {
            $sensitive = $true
        }
        if ($sensitive -and -not [string]::IsNullOrWhiteSpace($text)) { $Node.InnerText = $hidden }
    } else {
        foreach ($child in @($Node.SelectNodes('./*'))) {
            Protect-SLIGpoXmlValues -Node $child -RedactedFields $RedactedFields -SensitiveContext $sensitive
        }
    }
}

function ConvertTo-SLIGpoSettingFact {
    param(
        [Parameter(Mandatory = $true)]$Node,
        [Parameter(Mandatory = $true)][string]$Scope,
        [Parameter(Mandatory = $true)]$Contract
    )
    $properties = [ordered]@{}
    $redacted = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    $truncated = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    $parent = if ($Node.ParentNode) { [string]$Node.ParentNode.LocalName } else { '' }
    $contextNode = $Node
    $Node = $Node.CloneNode($true)
    Protect-SLIGpoXmlValues -Node $Node -RedactedFields $redacted -ContextNode $contextNode
    $propertyNodes = @($Node) + @($Node.SelectNodes('.//*'))
    foreach ($propertyNode in $propertyNodes) {
        foreach ($attribute in @($propertyNode.Attributes)) {
            $name = ([string]$attribute.LocalName).ToLowerInvariant()
            if (Test-SLIGpoSensitiveFieldName $name) {
                $null = $redacted.Add($name)
                continue
            }
            $value = ([string]$attribute.Value).Trim()
            if ([string]::IsNullOrWhiteSpace($value) -or $properties.Contains($name)) {
                continue
            }
            if ($value.Length -gt $Contract.setting_property_value_length_limit) {
                $null = $truncated.Add($name)
                $value = $value.Substring(0, $Contract.setting_property_value_length_limit)
            }
            $properties[$name] = $value
        }
        if (@($propertyNode.SelectNodes('./*')).Count -eq 0) {
            $name = ([string]$propertyNode.LocalName).ToLowerInvariant()
            if (Test-SLIGpoSensitiveFieldName $name) {
                if (-not [string]::IsNullOrWhiteSpace([string]$propertyNode.InnerText)) {
                    $null = $redacted.Add($name)
                }
                continue
            }
            $value = ([string]$propertyNode.InnerText).Trim()
            if ([string]::IsNullOrWhiteSpace($value) -or $properties.Contains($name)) {
                continue
            }
            if ($value.Length -gt $Contract.setting_property_value_length_limit) {
                $null = $truncated.Add($name)
                $value = $value.Substring(0, $Contract.setting_property_value_length_limit)
            }
            $properties[$name] = $value
        }
        if ($properties.Count -gt $Contract.per_setting_property_limit) {
            throw 'gpo_setting_property_count_ceiling_exceeded'
        }
    }
    $kind = [string]$Node.LocalName
    $path = if ($parent) { "$parent/$kind" } else { $kind }
    $redactedFields = @($redacted | Sort-Object)
    $truncatedFields = @($truncated | Sort-Object)
    $hashInput = [pscustomobject][ordered]@{
        scope = $Scope
        kind = $kind
        path = $path
        properties = [pscustomobject]$properties
        redacted_fields = $redactedFields
        truncated_fields = $truncatedFields
        sensitive_value_present = ($redactedFields.Count -gt 0)
    }
    $serialized = ConvertTo-Json $hashInput -Depth 6 -Compress
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($serialized))
    } finally {
        $sha.Dispose()
    }
    [pscustomobject][ordered]@{
        scope = $Scope
        kind = $kind
        path = $path
        properties = [pscustomobject]$properties
        redacted_fields = $redactedFields
        truncated_fields = $truncatedFields
        sensitive_value_present = ($redactedFields.Count -gt 0)
        sha256 = -join ($digest | ForEach-Object { $_.ToString('x2') })
    }
}

function Get-SLIGpoSettingFacts {
    param($Computer, $User, $Contract)
    $itemNames = @(
        'Script', 'Task', 'TaskV2', 'ImmediateTask', 'ImmediateTaskV2',
        'Service', 'Group', 'Registry', 'Policy', 'Drive', 'Printer',
        'Shortcut', 'Environment', 'File', 'Folder', 'IniFile',
        'DataSource', 'Device', 'PowerOptions', 'StartMenu',
        'InternetSettings', 'ScheduledTask'
    )
    $settings = @()
    foreach ($scopeDefinition in @(
        [pscustomobject]@{ name = 'computer'; node = $Computer },
        [pscustomobject]@{ name = 'user'; node = $User }
    )) {
        if ($null -eq $scopeDefinition.node) { continue }
        foreach ($node in @($scopeDefinition.node.SelectNodes('.//*'))) {
            if ([string]$node.LocalName -notin $itemNames) { continue }
            $settings += ConvertTo-SLIGpoSettingFact `
                -Node $node -Scope $scopeDefinition.name -Contract $Contract
            if ($settings.Count -gt $Contract.per_policy_setting_limit) {
                throw 'gpo_setting_count_ceiling_exceeded'
            }
        }
    }
    @($settings)
}

function ConvertFrom-SLIGpoReportXml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$XmlText
    )
    $contract = Get-SLIGpoReportContract
    $byteCount = [Text.Encoding]::UTF8.GetByteCount($XmlText)
    if ($byteCount -gt $contract.single_response_bytes_limit) {
        throw "response_size_ceiling_exceeded"
    }
    try {
        [xml]$document = $XmlText
    } catch {
        throw "invalid_gpo_report_xml"
    }
    $root = $document.SelectSingleNode("/*[local-name()='GPO']")
    if ($null -eq $root) { throw "invalid_gpo_report_xml" }
    $computer = $root.SelectSingleNode("./*[local-name()='Computer']")
    $user = $root.SelectSingleNode("./*[local-name()='User']")
    $links = @($root.SelectNodes("./*[local-name()='LinksTo']"))
    $linkTargets = @(
        foreach ($link in $links) {
            $target = Get-SLIXmlChildText -Node $link -LocalName "SOMPath"
            if ($target) { $target }
        }
    )
    $linkEnabled = @(
        $links | Where-Object {
            (ConvertTo-SLINullableBoolean (
                Get-SLIXmlChildText -Node $_ -LocalName "Enabled"
            )) -eq $true
        }
    ).Count
    $linkEnforced = @(
        $links | Where-Object {
            (ConvertTo-SLINullableBoolean (
                Get-SLIXmlChildText -Node $_ -LocalName "NoOverride"
            )) -eq $true
        }
    ).Count
    $filter = $root.SelectSingleNode("./*[local-name()='FilterData']")
    $filterId = Get-SLIXmlChildText -Node $filter -LocalName "ID"
    $settings = Get-SLIGpoSettingFacts $computer $user $contract
    [pscustomobject][ordered]@{
        response_bytes = $byteCount
        attributes = [pscustomobject][ordered]@{
            modified_utc = Get-SLIXmlChildText -Node $root -LocalName "ModifiedTime"
            gpo_computer_enabled = ConvertTo-SLINullableBoolean (
                Get-SLIXmlChildText -Node $computer -LocalName "Enabled"
            )
            gpo_user_enabled = ConvertTo-SLINullableBoolean (
                Get-SLIXmlChildText -Node $user -LocalName "Enabled"
            )
            link_count = $links.Count
            gpo_link_enabled_count = $linkEnabled
            gpo_link_enforced_count = $linkEnforced
            links = @($linkTargets)
            gpo_security_filtering_collected = $false
            gpo_wmi_filter_present = [bool]$filterId
            gpo_wmi_filter_id = $filterId
            gpo_startup_script_count = Get-SLIGpoScriptCount $computer "Startup"
            gpo_logon_script_count = Get-SLIGpoScriptCount $user "Logon"
            gpo_scheduled_task_count = (
                (Get-SLIGpoComponentCount $computer "ScheduledTasks" "Task") +
                (Get-SLIGpoComponentCount $user "ScheduledTasks" "Task")
            )
            gpo_service_count = (
                (Get-SLIGpoComponentCount $computer "Services" "Service") +
                (Get-SLIGpoComponentCount $user "Services" "Service")
            )
            gpo_local_group_count = (
                (Get-SLIGpoComponentCount $computer "Groups" "Group") +
                (Get-SLIGpoComponentCount $user "Groups" "Group")
            )
            gpo_settings = @($settings)
        }
    }
}

function Invoke-SLIBoundedGpoReportRead {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][guid]$Guid,
        [Parameter(Mandatory = $true)][string]$Domain,
        [Parameter(Mandatory = $true)][string]$Server
    )
    $contract = Get-SLIGpoReportContract
    $path = Join-Path ([IO.Path]::GetTempPath()) (
        "sli-gpo-{0}-{1}.xml" -f $Guid, [guid]::NewGuid()
    )
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $job = Start-Job -ScriptBlock {
        param($PolicyGuid, $DomainName, $DirectoryServer, $OutputPath)
        Import-Module GroupPolicy -ErrorAction Stop
        Get-GPOReport -Guid $PolicyGuid -Domain $DomainName -Server $DirectoryServer `
            -ReportType Xml -Path $OutputPath -ErrorAction Stop
    } -ArgumentList $Guid, $Domain, $Server, $path
    try {
        while ($job.State -in @("NotStarted", "Running")) {
            Start-Sleep -Milliseconds $contract.file_poll_interval_ms
            if ($clock.Elapsed.TotalSeconds -gt $contract.per_policy_time_limit_seconds) {
                Stop-Job $job
                throw "time_ceiling_exceeded"
            }
            if ((Test-Path -LiteralPath $path) -and (
                (Get-Item -LiteralPath $path).Length -gt
                $contract.single_response_bytes_limit
            )) {
                Stop-Job $job
                throw "response_size_ceiling_exceeded"
            }
            $job = Get-Job -Id $job.Id
        }
        Receive-Job $job -ErrorAction Stop | Out-Null
        if (-not (Test-Path -LiteralPath $path)) { throw "gpo_report_missing" }
        $length = (Get-Item -LiteralPath $path).Length
        if ($length -gt $contract.single_response_bytes_limit) {
            throw "response_size_ceiling_exceeded"
        }
        $facts = ConvertFrom-SLIGpoReportXml (
            Get-Content -LiteralPath $path -Raw
        )
        [pscustomobject][ordered]@{
            duration_ms = $clock.ElapsedMilliseconds
            response_bytes = $length
            facts = $facts
        }
    } finally {
        $clock.Stop()
        if ($job) { Remove-Job $job -Force -ErrorAction SilentlyContinue }
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-SLIBoundedGpoPermissionRead {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][guid]$Guid,
        [Parameter(Mandatory = $true)][string]$Domain,
        [Parameter(Mandatory = $true)][string]$Server
    )
    $contract = Get-SLIGpoPermissionContract
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $job = Start-Job -ScriptBlock {
        param(
            $PolicyGuid, $DomainName, $DirectoryServer,
            $PermissionLimit
        )
        Import-Module GroupPolicy -ErrorAction Stop
        $count = 0
        Get-GPPermission -Guid $PolicyGuid -All -DomainName $DomainName `
            -Server $DirectoryServer -ErrorAction Stop |
            ForEach-Object {
                $count += 1
                if ($count -gt $PermissionLimit) {
                    throw "permission_count_ceiling_exceeded"
                }
                [pscustomobject][ordered]@{
                    Trustee = [pscustomobject][ordered]@{
                        Sid = [string]$_.Trustee.Sid.Value
                        SidType = [string]$_.Trustee.SidType
                    }
                    Permission = [string]$_.Permission
                    Denied = [bool]$_.Denied
                    Inherited = [bool]$_.Inherited
                }
            }
    } -ArgumentList (
        $Guid, $Domain, $Server, $contract.per_policy_permission_limit
    )
    try {
        $null = Wait-Job $job -Timeout $contract.per_policy_time_limit_seconds
        if ($job.State -ne "Completed") {
            Stop-Job $job
            throw "time_ceiling_exceeded"
        }
        $permissionObjects = @(Receive-Job $job -ErrorAction Stop)
        $facts = ConvertFrom-SLIGpoPermissionObjects $permissionObjects
        [pscustomobject][ordered]@{
            duration_ms = $clock.ElapsedMilliseconds
            response_bytes = $facts.response_bytes
            facts = $facts
        }
    } finally {
        $clock.Stop()
        if ($job) { Remove-Job $job -Force -ErrorAction SilentlyContinue }
    }
}

Export-ModuleMember -Function `
    Get-SLIGpoReportContract, Get-SLIGpoPermissionContract, `
    ConvertFrom-SLIGpoReportXml, ConvertFrom-SLIGpoPermissionObjects, `
    Merge-SLIGpoGovernanceAttributes, Invoke-SLIBoundedGpoReportRead, `
    Invoke-SLIBoundedGpoPermissionRead, Protect-SLIGpoXmlValues

# The v2 leaf contract is shared with the retained legacy exporter.
function SLIV2-New-SourceState {
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

function SLIV2-New-StableId {
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

function SLIV2-Get-Sha256Hex {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text))
        return (($hash | ForEach-Object { $_.ToString("x2") }) -join "")
    }
    finally { $sha.Dispose() }
}

function SLIV2-Get-XmlNodePath {
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

function SLIV2-Get-RegistrySettings($Node) {
    $key = $Node.SelectSingleNode("./*[local-name()='KeyPath' or local-name()='Key']")
    if ($null -eq $key -or [string]::IsNullOrWhiteSpace($key.InnerText)) { return }
    $policyName = $Node.SelectSingleNode("./*[local-name()='PolicyName' or local-name()='DisplayName' or local-name()='Name']")
    $valueNodes = @($Node.SelectNodes("./*[local-name()='Value']"))
    if ($valueNodes.Count -eq 0) { $valueNodes = @($Node) }
    foreach ($valueNode in $valueNodes) {
        $valueName = if ($valueNode -eq $Node) { $Node.SelectSingleNode("./*[local-name()='ValueName']") }
            else { $valueNode.SelectSingleNode("./*[local-name()='Name' or local-name()='ValueName']") }
        $data = @($valueNode.SelectNodes(".//*[not(*) and (local-name()='Number' or local-name()='String' or local-name()='Data' or local-name()='ValueData')]/text()"))
        if ($data.Count -eq 0 -and $valueNode -ne $Node) { $data = @($valueNode.SelectNodes('./text()')) }
        $path = $key.InnerText.Trim().TrimEnd('\')
        if ($null -ne $valueName -and -not [string]::IsNullOrWhiteSpace($valueName.InnerText)) { $path += '\' + $valueName.InnerText.Trim() }
        [pscustomobject]@{ path = $path; name = if ($null -ne $policyName) { $policyName.InnerText.Trim() } else { '' };
            value = ($data | ForEach-Object { $_.Value.Trim() } | Where-Object { $_ -ne '' }) -join "`n" }
    }
}

function Get-SLIGpoAuditMode {
    param([System.Xml.XmlElement]$Leaf, [hashtable]$GuidCounts)

    $parent = $Leaf.ParentNode
    if ($Leaf.LocalName -eq 'SubcategoryGuid') {
        if ($GuidCounts[$Leaf.InnerText.Trim()] -ne 1) { return }
    } elseif ($Leaf.LocalName -ne 'SubcategoryName' -or $parent.SelectSingleNode("./*[local-name()='SubcategoryGuid']")) {
        return
    }

    $values = $parent.SelectNodes("./*[local-name()='SettingValue']")
    if ($values.Count -eq 1 -and $values[0].InnerText.Trim() -match '^[0-4]$') {
        return $values[0].InnerText.Trim()
    }
    $inclusion = $parent.SelectNodes("./*[local-name()='InclusionSetting']")
    if ($inclusion.Count -ne 1) { return }
    switch -Regex ($inclusion[0].InnerText.Trim()) {
        '^(0|None|Not Configured)$' { '0' }
        '^(1|Success)$' { '1' }
        '^(2|Failure)$' { '2' }
        '^(3|Success and Failure|Success,\s*Failure)$' { '3' }
        '^(4|No Auditing)$' { '4' }
    }
}

function SLIV2-Get-UserRightSetting($Node) {
    $name = $Node.SelectSingleNode("./*[local-name()='Name']").InnerText.Trim()
    $members = foreach ($member in $Node.SelectNodes("./*[local-name()='Member']")) {
        $principal = $member.SelectSingleNode("./*[local-name()='Name']")
        if ($null -eq $principal -or [string]::IsNullOrWhiteSpace($principal.InnerText)) {
            $principal = $member.SelectSingleNode("./*[local-name()='SID' or local-name()='Sid']")
        }
        if ($null -ne $principal -and -not [string]::IsNullOrWhiteSpace($principal.InnerText)) { $principal.InnerText.Trim() }
    }
    $value = if ($members -contains 'значение скрыто') { 'значение скрыто' } else {
        ($members | Sort-Object -Unique) -join "`n"
    }
    [pscustomobject]@{ path = 'UserRightsAssignment'; name = $name; value = $value }
}

function ConvertTo-SLIGpoV2Settings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][xml]$Xml,
        [Parameter(Mandatory = $true)][string]$GpoId,
        [Parameter(Mandatory = $true)][string]$GpoName,
        [Parameter(Mandatory = $true)][ValidateSet("computer", "user")][string]$Side,
        [Parameter(Mandatory = $true)][int]$Maximum,
        [Parameter(Mandatory = $true)][string]$ObservedAt
    )

    $script:ObservedAt = $ObservedAt
    $rows = New-Object System.Collections.ArrayList
    $seenSettingFingerprints = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    $sideNodeName = if ($Side -eq "computer") { "Computer" } else { "User" }
    $sideNode = $Xml.SelectSingleNode("/*[local-name()='GPO']/*[local-name()='$sideNodeName']")
    if ($null -eq $sideNode) {
        return [pscustomobject][ordered]@{ rows = @(); truncated = $false; source_status = "missing_in_source" }
    }

    $sideNode = $sideNode.CloneNode($true)
    Protect-SLIGpoXmlValues -Node $sideNode

    # Retain the parent association before generic leaf paths and values are deduplicated.
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

        $registryGroup = "local-name()='RegistrySetting' and *[local-name()='KeyPath' or local-name()='Key']"
        $accountGroup = "local-name()='Account' and *[local-name()='Name'] and *[local-name()='SettingNumber' or local-name()='SettingBoolean' or local-name()='SettingString']"
        $rightsGroup = "local-name()='UserRightsAssignment' and *[local-name()='Name']"
        $groups = $extensionNode.SelectNodes(".//*[($registryGroup) or ($accountGroup) or ($rightsGroup)]")
        foreach ($group in $groups) {
            $xmlPath = SLIV2-Get-XmlNodePath -Node $group -StopNode $extensionNode
            $category = switch ($group.LocalName) {
                'RegistrySetting' { 'Registry' }
                'UserRightsAssignment' { 'User Rights Assignment' }
                default { 'Account Policy' }
            }
            $entries = if ($group.LocalName -eq 'RegistrySetting') { @(SLIV2-Get-RegistrySettings $group) }
            elseif ($group.LocalName -eq 'UserRightsAssignment') { @(SLIV2-Get-UserRightSetting $group) }
            else {
                $name = $group.SelectSingleNode("./*[local-name()='Name']").InnerText.Trim()
                $content = $group.SelectSingleNode("./*[local-name()='SettingNumber' or local-name()='SettingBoolean' or local-name()='SettingString']")
                [pscustomobject]@{ path = ''; name = $name; value = $content.InnerText.Trim() }
            }
            foreach ($entry in $entries) {
                $identity = "$GpoId|$Side|$category|$($entry.path)"
                $fingerprint = SLIV2-Get-Sha256Hex -Text "$identity|$($entry.name)|$($entry.value)"
                if (-not $seenSettingFingerprints.Add($fingerprint)) { continue }
                if ($rows.Count -ge $Maximum) {
                    return [pscustomobject][ordered]@{ rows = @($rows); truncated = $true; source_status = "partial" }
                }
                [void]$rows.Add([pscustomobject][ordered]@{
                    id = SLIV2-New-StableId -Prefix 'setting' -Seed "$identity|$($entry.name)|$($entry.value)"
                    gpo_id = $GpoId; gpo_name = $GpoName; side = $Side; extension = $extensionName
                    category = $category; path = $entry.path; setting_name = $entry.name; value_display = $entry.value
                    operation = 'Observed'; source_xml_path = "/GPO/$sideNodeName/ExtensionData/Extension/$xmlPath"
                    source_state = SLIV2-New-SourceState -Status 'observed' -Source 'Get-GPOReport XML normalizer' -Detail $null -Error $null -Coverage $null -Value $null
                    fingerprint = $fingerprint
                })
            }
        }
        $leafNodes = $extensionNode.SelectNodes(".//*[not(*)]")
        foreach ($leaf in $leafNodes) {
            if ($null -ne $leaf.SelectSingleNode("ancestor::*[($registryGroup) or ($accountGroup) or ($rightsGroup)]")) { continue }
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

            $path = SLIV2-Get-XmlNodePath -Node $leaf -StopNode $extensionNode
            $category = if ($null -ne $leaf.ParentNode) { $leaf.ParentNode.LocalName } else { $extensionName }
            $seed = "{0}|{1}|{2}|{3}|{4}|{5}" -f $GpoId, $Side, $extensionName, $path, $leaf.LocalName, $value
            $fingerprint = SLIV2-Get-Sha256Hex -Text $seed
            if (-not $seenSettingFingerprints.Add($fingerprint)) { continue }
            $setting = [ordered]@{
                id              = SLIV2-New-StableId -Prefix "setting" -Seed $seed
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
                source_state    = SLIV2-New-SourceState -Status "observed" -Source "Get-GPOReport XML normalizer" -Detail $null -Error $null -Coverage $null -Value $null
                fingerprint     = $fingerprint
            }
            $mode = Get-SLIGpoAuditMode -Leaf $leaf -GuidCounts $auditCounts
            if ($null -ne $mode) { $setting['audit_mode'] = $mode }
            [void]$rows.Add([pscustomobject]$setting)
        }
    }

    return [pscustomobject][ordered]@{ rows = @($rows); truncated = $false; source_status = "observed" }
}


Export-ModuleMember -Function ConvertTo-SLIGpoV2Settings, Get-SLIGpoAuditMode

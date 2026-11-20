Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function New-SLIDomainPostureCheck {
    param(
        [string]$Key,
        [string]$EntityKind,
        [string]$SearchScope,
        [string]$Filter,
        [string[]]$Attributes,
        [string]$ExpectedRecordOrder,
        [int]$TimeLimitSeconds,
        [int]$RecordLimit,
        [int]$ResponseBytesLimit,
        [bool]$SecurityDescriptorDacl = $false
    )
    [pscustomobject][ordered]@{
        key = $Key
        entity_kind = $EntityKind
        ldap_base = "domain_head"
        search_scope = $SearchScope
        filter = $Filter
        attributes = @($Attributes)
        expected_record_order = $ExpectedRecordOrder
        time_limit_seconds = $TimeLimitSeconds
        record_limit = $RecordLimit
        response_bytes_limit = $ResponseBytesLimit
        security_descriptor_dacl = $SecurityDescriptorDacl
    }
}

function Get-SLIDomainPostureContract {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern("^DC=[^,]+(,DC=[^,]+)+$")]
        [string]$DomainDn
    )
    $checks = @(
        (New-SLIDomainPostureCheck `
            -Key "domain_password_policy" -EntityKind "password_policy" `
            -SearchScope "Base" -Filter "(objectClass=domainDNS)" `
            -Attributes @(
                "objectGUID", "distinguishedName", "minPwdLength", "maxPwdAge",
                "minPwdAge", "pwdHistoryLength", "pwdProperties",
                "lockoutThreshold", "lockoutDuration", "lockOutObservationWindow"
            ) -ExpectedRecordOrder "exactly 1" `
            -TimeLimitSeconds 15 -RecordLimit 1 -ResponseBytesLimit 262144)
        (New-SLIDomainPostureCheck `
            -Key "dcsync_domain_dacl" -EntityKind "domain" `
            -SearchScope "Base" -Filter "(objectClass=domainDNS)" `
            -Attributes @(
                "objectGUID", "objectSid", "distinguishedName",
                "nTSecurityDescriptor"
            ) -ExpectedRecordOrder "exactly 1 domain object; up to thousands of DACL ACEs inside the bounded descriptor" `
            -TimeLimitSeconds 30 -RecordLimit 1 -ResponseBytesLimit 4194304 `
            -SecurityDescriptorDacl $true)
        (New-SLIDomainPostureCheck `
            -Key "delegation" -EntityKind "security_principal" `
            -SearchScope "Subtree" `
            -Filter "(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(msDS-AllowedToDelegateTo=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))" `
            -Attributes @(
                "objectGUID", "objectSid", "objectClass", "sAMAccountName",
                "dNSHostName", "userAccountControl", "msDS-AllowedToDelegateTo",
                "msDS-AllowedToActOnBehalfOfOtherIdentity"
            ) -ExpectedRecordOrder "zero to tens of thousands of principals" `
            -TimeLimitSeconds 30 -RecordLimit 20000 -ResponseBytesLimit 16777216)
        (New-SLIDomainPostureCheck `
            -Key "user_service_principal_names" -EntityKind "ad_user" `
            -SearchScope "Subtree" `
            -Filter "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))" `
            -Attributes @(
                "objectGUID", "objectSid", "sAMAccountName",
                "servicePrincipalName", "userAccountControl"
            ) -ExpectedRecordOrder "zero to tens of thousands of user accounts" `
            -TimeLimitSeconds 45 -RecordLimit 50000 -ResponseBytesLimit 16777216)
        (New-SLIDomainPostureCheck `
            -Key "kerberos_preauth_disabled" -EntityKind "ad_user" `
            -SearchScope "Subtree" `
            -Filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" `
            -Attributes @(
                "objectGUID", "objectSid", "sAMAccountName", "userAccountControl"
            ) -ExpectedRecordOrder "zero to thousands of user accounts" `
            -TimeLimitSeconds 30 -RecordLimit 20000 -ResponseBytesLimit 8388608)
        (New-SLIDomainPostureCheck `
            -Key "sid_history" -EntityKind "security_principal" `
            -SearchScope "Subtree" -Filter "(sIDHistory=*)" `
            -Attributes @(
                "objectGUID", "objectSid", "objectClass", "sAMAccountName",
                "dNSHostName", "sIDHistory"
            ) -ExpectedRecordOrder "zero to tens of thousands of principals" `
            -TimeLimitSeconds 30 -RecordLimit 20000 -ResponseBytesLimit 8388608)
        (New-SLIDomainPostureCheck `
            -Key "domain_trusts" -EntityKind "domain_trust" `
            -SearchScope "Subtree" -Filter "(objectClass=trustedDomain)" `
            -Attributes @(
                "objectGUID", "distinguishedName", "trustPartner", "flatName",
                "securityIdentifier", "trustDirection", "trustType",
                "trustAttributes", "whenChanged"
            ) -ExpectedRecordOrder "zero to hundreds of trust objects" `
            -TimeLimitSeconds 20 -RecordLimit 1024 -ResponseBytesLimit 2097152)
        (New-SLIDomainPostureCheck `
            -Key "domain_controllers" -EntityKind "domain_controller" `
            -SearchScope "Subtree" `
            -Filter "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" `
            -Attributes @(
                "objectGUID", "objectSid", "sAMAccountName", "dNSHostName",
                "operatingSystem", "operatingSystemVersion", "userAccountControl"
            ) -ExpectedRecordOrder "one to hundreds of domain controllers" `
            -TimeLimitSeconds 20 -RecordLimit 4096 -ResponseBytesLimit 4194304)
    )
    foreach ($check in $checks) {
        $check.ldap_base = $DomainDn
        $check
    }
}

function Get-SLILdapResponseByteCount {
    param($Response)
    $bytes = 0L
    foreach ($entry in $Response.Entries) {
        $bytes += [Text.Encoding]::UTF8.GetByteCount([string]$entry.DistinguishedName)
        foreach ($attributeName in $entry.Attributes.AttributeNames) {
            $bytes += [Text.Encoding]::UTF8.GetByteCount([string]$attributeName)
            foreach ($value in $entry.Attributes[$attributeName]) {
                if ($value -is [byte[]]) {
                    $bytes += $value.Length
                } else {
                    $bytes += [Text.Encoding]::UTF8.GetByteCount([string]$value)
                }
            }
        }
    }
    $bytes
}

function Invoke-SLIDomainPostureRead {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Server,
        [Parameter(Mandatory = $true)][string]$DomainDn
    )
    Add-Type -AssemblyName System.DirectoryServices.Protocols
    foreach ($check in @(Get-SLIDomainPostureContract -DomainDn $DomainDn)) {
        $identifier = [DirectoryServices.Protocols.LdapDirectoryIdentifier]::new(
            $Server, 389, $false, $false
        )
        $connection = [DirectoryServices.Protocols.LdapConnection]::new($identifier)
        try {
            $clock = [Diagnostics.Stopwatch]::StartNew()
            $connection.AuthType = [DirectoryServices.Protocols.AuthType]::Negotiate
            $connection.SessionOptions.ProtocolVersion = 3
            $connection.Timeout = [TimeSpan]::FromSeconds($check.time_limit_seconds)
            $connection.Bind()
            $remaining = [TimeSpan]::FromSeconds($check.time_limit_seconds) - $clock.Elapsed
            if ($remaining.TotalMilliseconds -le 0) {
                throw "time_ceiling_exceeded"
            }
            $scope = [DirectoryServices.Protocols.SearchScope][Enum]::Parse(
                [DirectoryServices.Protocols.SearchScope],
                [string]$check.search_scope
            )
            $request = [DirectoryServices.Protocols.SearchRequest]::new(
                $check.ldap_base, $check.filter, $scope, [string[]]$check.attributes
            )
            $request.SizeLimit = $check.record_limit
            $request.TimeLimit = $remaining
            if ($check.security_descriptor_dacl) {
                [void]$request.Controls.Add(
                    [DirectoryServices.Protocols.SecurityDescriptorFlagControl]::new(
                        [DirectoryServices.Protocols.SecurityMasks]::Dacl
                    )
                )
            }
            $response = [DirectoryServices.Protocols.SearchResponse]$connection.SendRequest(
                $request, $remaining
            )
            $recordCount = $response.Entries.Count
            $responseBytes = Get-SLILdapResponseByteCount -Response $response
            $clock.Stop()
            if ($clock.Elapsed.TotalSeconds -gt $check.time_limit_seconds) {
                throw "time_ceiling_exceeded"
            }
            if ($recordCount -gt $check.record_limit) {
                throw "record_ceiling_exceeded"
            }
            if ($responseBytes -gt $check.response_bytes_limit) {
                throw "response_size_ceiling_exceeded"
            }
            [pscustomobject][ordered]@{
                check = $check.key
                status = "PASS"
                outcome = "complete"
                duration_ms = $clock.ElapsedMilliseconds
                record_count = $recordCount
                response_bytes = $responseBytes
                time_limit_seconds = $check.time_limit_seconds
                record_limit = $check.record_limit
                response_bytes_limit = $check.response_bytes_limit
                error_code = $null
            }
        } catch {
            $clock.Stop()
            $message = [string]$_.Exception.Message
            $errorCode = if (
                $message -match "time_ceiling_exceeded|timeout|timed out"
            ) {
                "ldap_time_limit_exceeded"
            } else {
                "ldap_read_failed"
            }
            [pscustomobject][ordered]@{
                check = $check.key
                status = "PARTIAL"
                outcome = "error"
                duration_ms = $clock.ElapsedMilliseconds
                record_count = $null
                response_bytes = $null
                time_limit_seconds = $check.time_limit_seconds
                record_limit = $check.record_limit
                response_bytes_limit = $check.response_bytes_limit
                error_code = $errorCode
            }
        } finally {
            $connection.Dispose()
        }
    }
}

Export-ModuleMember -Function Get-SLIDomainPostureContract, Invoke-SLIDomainPostureRead

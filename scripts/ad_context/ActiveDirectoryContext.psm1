Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function ConvertTo-SLIUtcText {
    param($Value)
    if ($null -eq $Value) { return $null }
    ([datetime]$Value).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
}

function New-SLIStableGuid {
    param([Parameter(Mandatory = $true)][string]$Value)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $hash = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value.ToLowerInvariant())) }
    finally { $sha.Dispose() }
    $bytes = [byte[]]::new(16)
    [Array]::Copy($hash, $bytes, 16)
    $bytes[7] = ($bytes[7] -band 15) -bor 64
    $bytes[8] = ($bytes[8] -band 63) -bor 128
    [guid]::new($bytes)
}

function Get-SLIObjectGuid {
    param($Object, [string]$FallbackKey)
    foreach ($name in @("ObjectGUID", "ObjectGuid")) {
        $property = $Object.PSObject.Properties[$name]
        if ($null -ne $property -and $null -ne $property.Value) { return [guid]$property.Value }
    }
    New-SLIStableGuid -Value $FallbackKey
}

function Get-SLIOptionalValue {
    param($Object, [string]$Name)
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    $property.Value
}

function New-SLIInfrastructureRecord {
    param(
        [string]$Kind, [string]$StableKey, [string]$DomainSid,
        [string]$ObservedAtUtc, [hashtable]$Attributes,
        $ObjectGuid = $null, $ObjectSid = $null, [string]$Section
    )
    $guid = if ($null -ne $ObjectGuid) { [guid]$ObjectGuid } else { New-SLIStableGuid -Value $StableKey }
    [ordered]@{
        record_type = "entity"
        record_key = ("ad-infrastructure:{0}:{1}" -f $Kind, $StableKey.ToLowerInvariant())
        section = $Section
        observed_at_utc = $ObservedAtUtc
        identity = [ordered]@{
            kind = $Kind
            domain_sid = $DomainSid
            object_guid = $guid.ToString()
            object_sid = if ($null -ne $ObjectSid) { [string]$ObjectSid } else { $null }
        }
        attributes = $Attributes
    }
}

function Get-SLILdapPolicy {
    param([string]$Server)
    $base = $null
    $parameters = $null
    try {
        $base = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine, $Server
        )
        $parameters = $base.OpenSubKey("SYSTEM\CurrentControlSet\Services\NTDS\Parameters")
        $integrity = if ($null -ne $parameters) { $parameters.GetValue("LDAPServerIntegrity", $null) } else { $null }
        $binding = if ($null -ne $parameters) { $parameters.GetValue("LdapEnforceChannelBinding", $null) } else { $null }
        [ordered]@{
            signing = if ($null -eq $integrity) { "unknown" } elseif ([int]$integrity -ge 2) { "require_signing" } else { "not_required" }
            channel_binding = if ($null -eq $binding) { "unknown" } elseif ([int]$binding -ge 2) { "always" } elseif ([int]$binding -eq 1) { "when_supported" } else { "never" }
            error = $null
        }
    }
    catch {
        [ordered]@{ signing = "unknown"; channel_binding = "unknown"; error = "ldap_policy_unavailable" }
    }
    finally {
        if ($null -ne $parameters) { $parameters.Dispose() }
        if ($null -ne $base) { $base.Dispose() }
    }
}

function Get-SLIDomainPostureRecords {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$DirectoryServer,
        [Parameter(Mandatory = $true)][string]$Domain,
        [Parameter(Mandatory = $true)][string]$DomainSid,
        [Parameter(Mandatory = $true)][string]$ObservedAtUtc,
        [ValidateRange(1, 1024)][int]$MaxTrusts = 256
    )
    $records = [Collections.Generic.List[object]]::new()
    $errors = [Collections.Generic.List[object]]::new()

    $domainData = Get-ADDomain -Server $DirectoryServer -Identity $Domain -ErrorAction Stop
    $forestData = Get-ADForest -Server $DirectoryServer -Identity ([string]$domainData.Forest) -ErrorAction Stop
    $domainObject = Get-ADObject -Server $DirectoryServer -Identity ([string]$domainData.DistinguishedName) -Properties ObjectGUID, ms-DS-MachineAccountQuota -ErrorAction Stop
    $ldap = Get-SLILdapPolicy -Server $DirectoryServer
    if ($ldap.error) { $errors.Add([ordered]@{ code = $ldap.error; message = "LDAP policy registry values were not available." }) }
    $recycleEnabled = $null
    try {
        $recycle = Get-ADOptionalFeature -Server $DirectoryServer -Identity "Recycle Bin Feature" -Properties EnabledScopes -ErrorAction Stop
        $recycleEnabled = @($recycle.EnabledScopes).Count -gt 0
    } catch { $errors.Add([ordered]@{ code = "recycle_bin_state_unavailable"; message = $_.Exception.Message }) }

    $domainAttributes = [ordered]@{
        display_name = [string]$domainData.DNSRoot
        forest_name = [string]$domainData.Forest
        netbios_name = [string]$domainData.NetBIOSName
        distinguished_name = [string]$domainData.DistinguishedName
        domain_mode = [string]$domainData.DomainMode
        forest_mode = [string]$forestData.ForestMode
        pdc_emulator = [string]$domainData.PDCEmulator
        rid_master = [string]$domainData.RIDMaster
        infrastructure_master = [string]$domainData.InfrastructureMaster
        schema_master = [string]$forestData.SchemaMaster
        domain_naming_master = [string]$forestData.DomainNamingMaster
        recycle_bin_enabled = $recycleEnabled
        machine_account_quota = [int](Get-SLIOptionalValue -Object $domainObject -Name "ms-DS-MachineAccountQuota")
        ldap_signing_requirement = [string]$ldap.signing
        ldap_channel_binding_requirement = [string]$ldap.channel_binding
    }
    $records.Add((New-SLIInfrastructureRecord -Kind "domain" -StableKey ([string]$domainData.DNSRoot) -DomainSid $DomainSid -ObservedAtUtc $ObservedAtUtc -Section "domain_posture" -ObjectGuid $domainObject.ObjectGUID -ObjectSid $DomainSid -Attributes $domainAttributes))

    try {
        $policy = Get-ADDefaultDomainPasswordPolicy -Server $DirectoryServer -Identity $Domain -ErrorAction Stop
        $policyAttributes = [ordered]@{
            display_name = "Default domain policy"
            password_min_length = [int]$policy.MinPasswordLength
            password_max_age = [string]$policy.MaxPasswordAge
            password_min_age = [string]$policy.MinPasswordAge
            password_history_length = [int]$policy.PasswordHistoryCount
            password_properties = @($policy.PasswordProperties | ForEach-Object { [string]$_ })
            lockout_threshold = [int]$policy.LockoutThreshold
            lockout_duration = [string]$policy.LockoutDuration
            lockout_observation_window = [string]$policy.LockoutObservationWindow
        }
        $records.Add((New-SLIInfrastructureRecord -Kind "password_policy" -StableKey ("{0}:default-password-policy" -f $Domain) -DomainSid $DomainSid -ObservedAtUtc $ObservedAtUtc -Section "domain_posture" -Attributes $policyAttributes))
    } catch { $errors.Add([ordered]@{ code = "password_policy_unavailable"; message = $_.Exception.Message }) }

    try {
        $trusts = @(Get-ADObject -Server $DirectoryServer -LDAPFilter "(objectClass=trustedDomain)" -SearchBase ("CN=System,{0}" -f [string]$domainData.DistinguishedName) -SearchScope OneLevel -ResultSetSize ($MaxTrusts + 1) -Properties ObjectGUID, DistinguishedName, trustPartner, flatName, trustDirection, trustType, trustAttributes -ErrorAction Stop)
        if ($trusts.Count -gt $MaxTrusts) { throw "domain_trust_limit_exceeded" }
        foreach ($trust in $trusts) {
            $partner = if (Get-SLIOptionalValue $trust "trustPartner") { [string](Get-SLIOptionalValue $trust "trustPartner") } else { [string]$trust.Name }
            $directionValue = [int](Get-SLIOptionalValue $trust "trustDirection")
            $direction = switch ($directionValue) { 1 { "Inbound" } 2 { "Outbound" } 3 { "BiDirectional" } default { "Unknown" } }
            $typeValue = [int](Get-SLIOptionalValue $trust "trustType")
            $type = switch ($typeValue) { 1 { "Downlevel" } 2 { "Uplevel" } 3 { "MIT" } 4 { "DCE" } default { "Unknown" } }
            $attributes = [ordered]@{
                display_name = $partner
                distinguished_name = [string](Get-SLIOptionalValue $trust "DistinguishedName")
                trust_partner = $partner
                trust_flat_name = [string](Get-SLIOptionalValue $trust "flatName")
                trust_direction = $direction
                trust_type = $type
                trust_attributes = [int](Get-SLIOptionalValue $trust "trustAttributes")
            }
            $records.Add((New-SLIInfrastructureRecord -Kind "domain_trust" -StableKey ("{0}:trust:{1}" -f $Domain, $partner) -DomainSid $DomainSid -ObservedAtUtc $ObservedAtUtc -Section "domain_posture" -ObjectGuid (Get-SLIObjectGuid $trust ("trust:{0}" -f $partner)) -Attributes $attributes))
        }
    } catch { $errors.Add([ordered]@{ code = "domain_trusts_unavailable"; message = $_.Exception.Message }) }

    [pscustomobject]@{ records = @($records); errors = @($errors) }
}

function Invoke-SLIBoundedDcdiag {
    param(
        [string]$Server, [ValidateSet("Advertising", "Connectivity", "Services", "SysVolCheck", "DNS")][string]$TestName,
        [ValidateRange(5, 120)][int]$CommandTimeoutSeconds,
        [ValidateRange(1024, 1048576)][int]$MaxDiagnosticBytes
    )
    $arguments = if ($TestName -eq "DNS") { "/s:$Server /test:DNS /DnsBasic /q" } else { "/s:$Server /test:$TestName /q" }
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = "dcdiag.exe"
    $info.Arguments = $arguments
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    $started = $false
    $streams = @()
    try {
        $clock = [Diagnostics.Stopwatch]::StartNew()
        if (-not $process.Start()) { throw "dcdiag_start_failed" }
        $started = $true
        # Keep one fixed-size read outstanding on EACH pipe; retain no output history.
        # Per-stream encoders preserve UTF-8 byte accounting across surrogate pairs.
        foreach ($reader in @($process.StandardOutput, $process.StandardError)) {
            $buffer = [char[]]::new(4096)
            $streams += @{
                Reader = $reader; Buffer = $buffer; Encoder = [Text.Encoding]::UTF8.GetEncoder()
                Bytes = [byte[]]::new([Text.Encoding]::UTF8.GetMaxByteCount(4096))
                Read = $reader.ReadAsync($buffer, 0, $buffer.Length); Done = $false
            }
        }
        $totalBytes = 0L
        while ($true) {
            if ($clock.Elapsed.TotalSeconds -ge $CommandTimeoutSeconds) {
                return [ordered]@{ state = "timeout"; error_code = "dcdiag_timeout" }
            }
            foreach ($stream in $streams) {
                if ($stream.Done) { continue }
                $read = $stream.Read
                if (-not $read.IsCompleted) { continue }
                # Completed/faulted tasks only: GetResult cannot wait on a pipe.
                $count = $read.GetAwaiter().GetResult()
                # GetBytes advances encoder state; GetByteCount alone does not.
                $totalBytes += $stream.Encoder.GetBytes($stream.Buffer, 0, $count, $stream.Bytes, 0, ($count -eq 0))
                if ($totalBytes -gt $MaxDiagnosticBytes) {
                    return [ordered]@{ state = "unavailable"; error_code = "dcdiag_output_limit_exceeded" }
                }
                if ($count -eq 0) { $stream.Done = $true }
                else { $stream.Read = $stream.Reader.ReadAsync($stream.Buffer, 0, $stream.Buffer.Length) }
            }
            # Exit alone is insufficient: descendants may still hold a pipe open.
            if ($process.HasExited -and $streams[0].Done -and $streams[1].Done) { break }
            Start-Sleep -Milliseconds 10
        }
        if ($process.ExitCode -eq 0) { return [ordered]@{ state = "passed"; error_code = $null } }
        [ordered]@{ state = "failed"; error_code = ("dcdiag_{0}_failed" -f $TestName.ToLowerInvariant()) }
    }
    catch { [ordered]@{ state = "unavailable"; error_code = "dcdiag_unavailable" } }
    finally {
        if ($started) {
            try {
                if (-not $process.HasExited) {
                    # Preserve tree cleanup on Windows PowerShell 5.1 too, but
                    # bound the helper instead of invoking taskkill synchronously.
                    $treeKill = $process.GetType().GetMethod("Kill", [type[]]@([bool]))
                    if ($null -ne $treeKill) { $process.Kill($true) }
                    else {
                        $killInfo = [Diagnostics.ProcessStartInfo]::new()
                        $killInfo.FileName = "taskkill.exe"
                        $killInfo.Arguments = "/PID $($process.Id) /T /F"
                        $killInfo.UseShellExecute = $false
                        $killInfo.CreateNoWindow = $true
                        $killer = [Diagnostics.Process]::new()
                        $killer.StartInfo = $killInfo
                        try {
                            if ($killer.Start() -and -not $killer.WaitForExit(1000)) { $killer.Kill() }
                        } catch { }
                        finally { $killer.Dispose() }
                        if (-not $process.HasExited) { $process.Kill() }
                    }
                }
                $null = $process.WaitForExit(1000)
            } catch { } # Cleanup failure must never manufacture a health pass.
        }
        foreach ($stream in $streams) {
            # Close inherited pipes even if EOF never arrives. Never wait on a read.
            try { $stream.Reader.BaseStream.Dispose() } catch { }
            try { $stream.Reader.Dispose() } catch { }
            # Observe faults already completed by closure; do not await a pending
            # read, including one whose inherited pipe never signalled EOF.
            if ($stream.Read.IsFaulted) { $null = $stream.Read.Exception }
        }
        $process.Dispose()
    }
}

function ConvertTo-SLIReplicationRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Metadata,
        [Parameter(Mandatory = $true)][string]$DomainSid,
        [Parameter(Mandatory = $true)][string]$ObservedAtUtc
    )
    $partner = [string]$Metadata.Partner
    $source = if ($partner -match "(?i)CN=NTDS Settings,CN=([^,]+)") { $Matches[1] } else { $partner }
    $destination = [string]$Metadata.Server
    $partition = [string]$Metadata.Partition
    $failures = [int]$Metadata.ConsecutiveReplicationFailures
    $result = [int]$Metadata.LastReplicationResult
    $state = if ($failures -eq 0 -and $result -eq 0) { "passed" } else { "failed" }
    $key = "{0}|{1}|{2}" -f $source, $destination, $partition
    New-SLIInfrastructureRecord -Kind "replication_link" -StableKey $key -DomainSid $DomainSid -ObservedAtUtc $ObservedAtUtc -Section "domain_health" -Attributes ([ordered]@{
        display_name = ("{0} -> {1}" -f $source, $destination)
        source_dc = $source
        destination_dc = $destination
        naming_context = $partition
        last_replication_attempt_utc = ConvertTo-SLIUtcText $Metadata.LastReplicationAttempt
        last_replication_success_utc = ConvertTo-SLIUtcText $Metadata.LastReplicationSuccess
        consecutive_failure_count = $failures
        last_replication_result = $result
        replication_state = $state
    })
}

function ConvertTo-SLIDomainControllerRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$DomainController,
        [Parameter(Mandatory = $true)]$ComputerObject,
        [Parameter(Mandatory = $true)][hashtable]$Checks,
        [Parameter(Mandatory = $true)][string]$DomainSid,
        [Parameter(Mandatory = $true)][string]$ObservedAtUtc
    )
    $hostName = [string]$DomainController.HostName
    New-SLIInfrastructureRecord -Kind "ad_computer" -StableKey $hostName -DomainSid $DomainSid -ObservedAtUtc $ObservedAtUtc -Section "domain_health" -ObjectGuid $ComputerObject.ObjectGUID -ObjectSid $ComputerObject.SID -Attributes ([ordered]@{
        display_name = [string]$DomainController.Name
        distinguished_name = [string]$ComputerObject.DistinguishedName
        dns_host_name = $hostName
        operating_system = [string](Get-SLIOptionalValue $ComputerObject "OperatingSystem")
        operating_system_version = [string](Get-SLIOptionalValue $ComputerObject "OperatingSystemVersion")
        infrastructure_role = "domain_controller"
        site_name = [string]$DomainController.Site
        is_global_catalog = [bool]$DomainController.IsGlobalCatalog
        is_read_only = [bool]$DomainController.IsReadOnly
        operation_master_roles = @($DomainController.OperationMasterRoles | ForEach-Object { [string]$_ })
        advertising_state = [string]$Checks.advertising
        connectivity_state = [string]$Checks.connectivity
        services_state = [string]$Checks.services
        sysvol_state = [string]$Checks.sysvol
        netlogon_state = [string]$Checks.netlogon
        dns_state = [string]$Checks.dns
        health_error_codes = @($Checks.errors)
    })
}

function Get-SLIDomainHealthRecords {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$DirectoryServer,
        [Parameter(Mandatory = $true)][string]$Domain,
        [Parameter(Mandatory = $true)][string]$DomainSid,
        [Parameter(Mandatory = $true)][string]$ObservedAtUtc,
        [ValidateRange(1, 256)][int]$MaxDomainControllers = 64,
        [ValidateRange(1, 50000)][int]$MaxReplicationLinks = 10000,
        [ValidateRange(5, 120)][int]$CommandTimeoutSeconds = 45,
        [ValidateRange(1024, 1048576)][int]$MaxDiagnosticBytes = 262144
    )
    $records = [Collections.Generic.List[object]]::new()
    $errors = [Collections.Generic.List[object]]::new()
    $controllers = @(Get-ADDomainController -Server $DirectoryServer -Filter * -ErrorAction Stop | Sort-Object HostName)
    if ($controllers.Count -gt $MaxDomainControllers) { throw "domain_controller_limit_exceeded" }
    foreach ($controller in $controllers) {
        $hostName = [string]$controller.HostName
        $computer = Get-ADComputer -Server $DirectoryServer -Identity ([string]$controller.ComputerObjectDN) -Properties ObjectGUID, SID, OperatingSystem, OperatingSystemVersion -ErrorAction Stop
        $advertising = Invoke-SLIBoundedDcdiag -Server $hostName -TestName Advertising -CommandTimeoutSeconds $CommandTimeoutSeconds -MaxDiagnosticBytes $MaxDiagnosticBytes
        $connectivity = Invoke-SLIBoundedDcdiag -Server $hostName -TestName Connectivity -CommandTimeoutSeconds $CommandTimeoutSeconds -MaxDiagnosticBytes $MaxDiagnosticBytes
        $services = Invoke-SLIBoundedDcdiag -Server $hostName -TestName Services -CommandTimeoutSeconds $CommandTimeoutSeconds -MaxDiagnosticBytes $MaxDiagnosticBytes
        $sysvol = Invoke-SLIBoundedDcdiag -Server $hostName -TestName SysVolCheck -CommandTimeoutSeconds $CommandTimeoutSeconds -MaxDiagnosticBytes $MaxDiagnosticBytes
        $dns = Invoke-SLIBoundedDcdiag -Server $hostName -TestName DNS -CommandTimeoutSeconds $CommandTimeoutSeconds -MaxDiagnosticBytes $MaxDiagnosticBytes
        $netlogonState = try { if (Test-Path -LiteralPath ("\\{0}\NETLOGON" -f $hostName) -ErrorAction Stop) { "passed" } else { "failed" } } catch { "unavailable" }
        $errorCodes = @($advertising, $connectivity, $services, $sysvol, $dns | ForEach-Object { $_.error_code } | Where-Object { $_ })
        $records.Add((ConvertTo-SLIDomainControllerRecord -DomainController $controller -ComputerObject $computer -Checks @{
            advertising = [string]$advertising.state
            connectivity = [string]$connectivity.state
            services = [string]$services.state
            sysvol = [string]$sysvol.state
            netlogon = $netlogonState
            dns = [string]$dns.state
            errors = @($errorCodes)
        } -DomainSid $DomainSid -ObservedAtUtc $ObservedAtUtc))
    }
    try {
        $metadata = @(Get-ADReplicationPartnerMetadata -Target $Domain -Scope Domain -EnumerationServer $DirectoryServer -ErrorAction Stop)
        if ($metadata.Count -gt $MaxReplicationLinks) { throw "replication_link_limit_exceeded" }
        foreach ($row in $metadata) { $records.Add((ConvertTo-SLIReplicationRecord -Metadata $row -DomainSid $DomainSid -ObservedAtUtc $ObservedAtUtc)) }
    } catch { $errors.Add([ordered]@{ code = "replication_metadata_unavailable"; message = $_.Exception.Message }) }
    [pscustomobject]@{ records = @($records); errors = @($errors) }
}

Export-ModuleMember -Function Get-SLIDomainPostureRecords, Get-SLIDomainHealthRecords, ConvertTo-SLIReplicationRecord, ConvertTo-SLIDomainControllerRecord

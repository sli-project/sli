#requires -Version 5.1
# SPDX-License-Identifier: Apache-2.0
# Stage 1 only: integrated credentials, existing objects/handles, no AD writes.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version Latest
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$result = @{}
function Set-Check([string]$Key, [string]$Status, [string]$Reason) {
    $result[$Key] = @{status=$Status; reason=$Reason}
}
function Set-Access([string]$Key, [bool]$Allowed) {
    if ($Allowed) { Set-Check $Key 'available' 'verified' }
    else { Set-Check $Key 'denied' 'access_denied' }
}

try {
    $policy = [Console]::In.ReadToEnd() | ConvertFrom-Json
    foreach ($key in @('identity','domain','gpo_create','gpt_create','gpo_edit','gpo_acl','gpt_edit','package')) {
        Set-Check $key 'unavailable' 'read_failed'
    }
    if (@($policy.allowed_ou_guids).Count -lt 1 -or @($policy.allowed_ou_guids).Count -gt 128) { throw 'scope' }
    for ($i=0; $i -lt @($policy.allowed_ou_guids).Count; $i++) { Set-Check "ou_$i" 'unavailable' 'read_failed' }
    if ($policy.dc -notmatch '^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$' -or
        $policy.domain_dns -notmatch '^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$' -or
        $policy.domain_sid -notmatch '^S-1-5-21-\d+-\d+-\d+$') { throw 'scope' }

    Add-Type -AssemblyName System.DirectoryServices
    $auth = [DirectoryServices.AuthenticationTypes]::Secure -bor
        [DirectoryServices.AuthenticationTypes]::Signing -bor [DirectoryServices.AuthenticationTypes]::Sealing
    function Open-Entry([string]$Dn) {
        $e = [DirectoryServices.DirectoryEntry]::new(('LDAP://' + $policy.dc + '/' + $Dn))
        $e.AuthenticationType = $auth
        return $e
    }
    function Read-Descriptor($Entry) {
        # RootDSE does not implement this option. Request it only when reading
        # a securable AD object, and bypass PowerShell's ADSI property adapter.
        $Entry.psbase.Options.SecurityMasks = [DirectoryServices.SecurityMasks]'Owner,Group,Dacl'
        return ,$Entry.psbase.ObjectSecurity.GetSecurityDescriptorBinaryForm()
    }
    function Find-One($Root, [string]$Filter, [string[]]$Properties) {
        $s = [DirectoryServices.DirectorySearcher]::new($Root)
        try {
            $s.Filter = $Filter
            $s.ClientTimeout = [TimeSpan]::FromSeconds(10)
            $s.ServerTimeLimit = [TimeSpan]::FromSeconds(10)
            $s.SizeLimit = 2
            foreach ($p in $Properties) { [void]$s.PropertiesToLoad.Add($p) }
            $rows = $s.FindAll()
            try {
                if ($rows.Count -ne 1) { throw 'ambiguous' }
                $entry = Open-Entry ([string]$rows[0].Properties['distinguishedname'][0])
                return $entry
            } finally { $rows.Dispose() }
        } finally { $s.Dispose() }
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $groups = @($identity.Groups | ForEach-Object { $_.Value })
        $forbidden = @('S-1-5-18','S-1-5-32-544','S-1-5-32-548','S-1-5-32-549','S-1-5-32-550','S-1-5-32-551')
        $privileged = @($groups | Where-Object {
            $_ -in $forbidden -or $_ -match '^S-1-5-21-\d+-\d+-\d+-(512|516|518|519|520|521)$'
        }).Count -gt 0
        if ($identity.User.Value -ne $policy.writer_sid -or $identity.User.Value -in $forbidden -or
            $privileged -or $groups -notcontains 'S-1-5-6') {
            Set-Check 'identity' 'denied' 'identity_rejected'
            throw 'identity'
        }
    } finally { $identity.Dispose() }
    if ((Get-CimInstance Win32_ComputerSystem -OperationTimeoutSec 10).DomainRole -notin @(4,5)) {
        Set-Check 'identity' 'denied' 'identity_rejected'
        throw 'identity'
    }
    $root = Open-Entry 'RootDSE'
    try {
        $nc = [string]$root.Properties['defaultNamingContext'][0]
        $schemaNc = [string]$root.Properties['schemaNamingContext'][0]
        $expectedNc = (@($policy.domain_dns.Split('.') | ForEach-Object { 'DC=' + $_ }) -join ',')
        if ($nc -ine $expectedNc -or [string]$root.Properties['dnsHostName'][0] -ine $policy.dc) {
            Set-Check 'domain' 'denied' 'domain_mismatch'
            throw 'domain'
        }
    } finally { $root.Dispose() }
    $domain = Open-Entry $nc
    try {
        $sid = [Security.Principal.SecurityIdentifier]::new([byte[]]$domain.Properties['objectSid'][0], 0)
        if ($sid.Value -cne $policy.domain_sid) {
            Set-Check 'domain' 'denied' 'domain_mismatch'
            throw 'domain'
        }
        $writerSid = [Security.Principal.SecurityIdentifier]::new([string]$policy.writer_sid)
        $bytes = [byte[]]::new($writerSid.BinaryLength)
        $writerSid.GetBinaryForm($bytes, 0)
        $escaped = ($bytes | ForEach-Object { '\' + $_.ToString('x2') }) -join ''
        $gmsa = Find-One $domain ('(&(objectClass=msDS-GroupManagedServiceAccount)(objectSid=' + $escaped + '))') @('distinguishedName')
        $gmsa.Dispose()
        # Resolve the domain's well-known controllers OU rather than its name.
        $dcOu = Open-Entry ('<WKGUID=a361b2ffffd211d1aa4b00c04fd7d83a,' + $nc + '>')
        try { $dcOuDn = [string]$dcOu.Properties['distinguishedName'][0] }
        finally { $dcOu.Dispose() }
        if (-not $dcOuDn) { throw 'scope' }
    } finally { $domain.Dispose() }
    Set-Check 'identity' 'available' 'verified'
    Set-Check 'domain' 'available' 'verified'

    # Native access checks use the actual process token, including deny ACEs and
    # group membership. No inference from the presence of an Allow ACE.
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
public static class SliGpoAccess {
    [StructLayout(LayoutKind.Sequential)] struct Mapping { public uint Read, Write, Execute, All; }
    [StructLayout(LayoutKind.Sequential)] struct ObjectType { public ushort Level, Reserved; public IntPtr Guid; }
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool DuplicateToken(IntPtr token, int level, out IntPtr duplicate);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool AccessCheckByTypeResultList(
        byte[] sd, IntPtr self, IntPtr token, uint desired, ObjectType[] types, uint count,
        ref Mapping mapping, IntPtr privileges, ref uint length, uint[] granted, uint[] errors);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern SafeFileHandle CreateFile(
        string name, uint access, uint sharing, IntPtr security, uint disposition, uint flags, IntPtr template);
    public static bool DirectoryAccess(string path, uint access) {
        // OPEN_EXISTING + BACKUP_SEMANTICS: request rights on the directory;
        // never create a test file, GPT, directory or policy.
        using (SafeFileHandle h = CreateFile(path, access, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero)) {
            if (!h.IsInvalid) return true;
            int error = Marshal.GetLastWin32Error();
            if (error == 5) return false;
            throw new Win32Exception(error);
        }
    }
    public static bool Check(byte[] sd, uint access, Guid[] hierarchy) {
        IntPtr token = IntPtr.Zero, privileges = IntPtr.Zero;
        ObjectType[] types = new ObjectType[hierarchy.Length];
        try {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent()) {
                if (!DuplicateToken(identity.Token, 2, out token)) throw new Win32Exception();
            }
            for (int i=0; i<types.Length; i++) {
                types[i].Level = (ushort)i;
                types[i].Guid = Marshal.AllocHGlobal(16);
                Marshal.StructureToPtr(hierarchy[i], types[i].Guid, false);
            }
            Mapping mapping = new Mapping { Read=0x20094, Write=0x20028, Execute=0x20004, All=0xF01FF };
            uint length=1024;
            privileges = Marshal.AllocHGlobal((int)length);
            uint[] granted = new uint[types.Length], errors = new uint[types.Length];
            bool ok = AccessCheckByTypeResultList(sd, IntPtr.Zero, token, access, types, (uint)types.Length,
                ref mapping, privileges, ref length, granted, errors);
            if (!ok && Marshal.GetLastWin32Error() == 122) {
                Marshal.FreeHGlobal(privileges);
                privileges = Marshal.AllocHGlobal((int)length);
                ok = AccessCheckByTypeResultList(sd, IntPtr.Zero, token, access, types, (uint)types.Length,
                    ref mapping, privileges, ref length, granted, errors);
            }
            if (!ok) throw new Win32Exception();
            int last=types.Length-1;
            return errors[last] == 0 && (granted[last] & access) == access;
        } finally {
            foreach (ObjectType type in types) if (type.Guid != IntPtr.Zero) Marshal.FreeHGlobal(type.Guid);
            if (privileges != IntPtr.Zero) Marshal.FreeHGlobal(privileges);
            if (token != IntPtr.Zero) CloseHandle(token);
        }
    }
}
'@
    $schema = Open-Entry $schemaNc
    function Schema-Info([string]$Name) {
        $entry = Find-One $schema ('(lDAPDisplayName=' + $Name + ')') @('distinguishedName')
        try {
            $set = $null
            if ($entry.Properties['attributeSecurityGUID'].Count) { $set = [Guid]::new([byte[]]$entry.Properties['attributeSecurityGUID'][0]) }
            return @{guid=[Guid]::new([byte[]]$entry.Properties['schemaIDGUID'][0]); set=$set}
        } finally { $entry.Dispose() }
    }
    try {
        $gpcClass = (Schema-Info 'groupPolicyContainer').guid
        $ouClass = (Schema-Info 'organizationalUnit').guid
        $link = Schema-Info 'gPLink'
    } finally { $schema.Dispose() }
    $policies = Open-Entry ('CN=Policies,CN=System,' + $nc)
    try { Set-Access 'gpo_create' ([SliGpoAccess]::Check((Read-Descriptor $policies), 1, @($gpcClass))) }
    catch { Set-Check 'gpo_create' 'unavailable' 'read_failed' }
    finally { $policies.Dispose() }

    for ($i=0; $i -lt @($policy.allowed_ou_guids).Count; $i++) {
        $ou = $null
        try {
            $guid = [Guid]::Parse([string]$policy.allowed_ou_guids[$i])
            $ou = Open-Entry ('<GUID=' + $guid.ToString('D') + '>')
            $dn = [string]$ou.Properties['distinguishedName'][0]
            if (@($ou.Properties['objectClass']) -notcontains 'organizationalUnit' -or
                -not $dn.EndsWith(',' + $nc, [StringComparison]::OrdinalIgnoreCase) -or
                $dn -ieq $dcOuDn -or $dn.EndsWith(',' + $dcOuDn, [StringComparison]::OrdinalIgnoreCase)) {
                Set-Check "ou_$i" 'denied' 'scope_rejected'
                continue
            }
            $hierarchy = @($ouClass)
            if ($link.set) { $hierarchy += $link.set }
            $hierarchy += $link.guid
            Set-Access "ou_$i" ([SliGpoAccess]::Check((Read-Descriptor $ou), 0x30, $hierarchy))
        } catch { Set-Check "ou_$i" 'unavailable' 'read_failed' }
        finally { if ($ou) { $ou.Dispose() } }
    }
    $sysvol = '\\' + $policy.dc + '\SYSVOL\' + $policy.domain_dns + '\Policies'
    try { Set-Access 'gpt_create' ([SliGpoAccess]::DirectoryAccess($sysvol, 0x20005)) }
    catch { Set-Check 'gpt_create' 'unavailable' 'read_failed' }
    if ($null -eq $policy.managed_gpo_guid) {
        foreach ($key in @('gpo_edit','gpo_acl','gpt_edit')) { Set-Check $key 'not_applicable' 'no_managed_gpo' }
    } else {
        $gpo = $null
        try {
            $guid = '{' + ([Guid]::Parse([string]$policy.managed_gpo_guid)).ToString().ToUpperInvariant() + '}'
            $gpo = Open-Entry ('CN=' + $guid + ',CN=Policies,CN=System,' + $nc)
            $sd = Read-Descriptor $gpo
            Set-Access 'gpo_edit' ([SliGpoAccess]::Check($sd, 0x30037, @($gpcClass)))
            Set-Access 'gpo_acl' ([SliGpoAccess]::Check($sd, 0x40000, @($gpcClass)))
        } catch {
            Set-Check 'gpo_edit' 'unavailable' 'read_failed'
            Set-Check 'gpo_acl' 'unavailable' 'read_failed'
        } finally { if ($gpo) { $gpo.Dispose() } }
        try { Set-Access 'gpt_edit' ([SliGpoAccess]::DirectoryAccess(($sysvol + '\' + $guid), 0x1301bf)) }
        catch { Set-Check 'gpt_edit' 'unavailable' 'read_failed' }
    }
    try {
        $file = Get-Item -LiteralPath $policy.msi_path
        if ($file.PSIsContainer -or $file.FullName.StartsWith('\\') -or $file.Extension -ine '.msi' -or
            ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'package' }
        $signature = Get-AuthenticodeSignature -LiteralPath $file.FullName
        $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $signer = ([BitConverter]::ToString($sha.ComputeHash($signature.SignerCertificate.RawData))).Replace('-','').ToLowerInvariant() }
        finally { $sha.Dispose() }
        if ($signature.Status -ne 'Valid' -or $hash -cne $policy.msi_sha256 -or $signer -cne $policy.signer_sha256) { throw 'signature' }
        Set-Check 'package' 'available' 'verified'
    } catch { Set-Check 'package' 'denied' 'signature_invalid' }
} catch {
    # Do not emit exception text, LDAP paths, principals or source attributes.
}
[Console]::Out.Write(($result | ConvertTo-Json -Depth 4 -Compress))

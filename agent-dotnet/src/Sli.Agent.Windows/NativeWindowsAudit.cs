using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Security.AccessControl;
using System.Diagnostics;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Win32;
using Microsoft.VisualBasic.FileIO;
using Sli.Agent.Core;

namespace Sli.Agent.Windows;

[SupportedOSPlatform("windows")]
public sealed class NativeWindowsAudit(string directory, IDurableFiles files) : IWindowsAudit
{
    private readonly WindowsAuditManager _manager = new(directory, files, new WindowsAuditApi());
    public JsonObject Reconcile(AgentPolicy policy, DateTimeOffset now) => _manager.Reconcile(policy, now);
}

/// <summary>Native audit calls and fixed local ADSI operations; no server supplied commands.</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsAuditApi : IWindowsAuditApi
{
    public static bool HasDomainRootAudit(string sddl)
    {
        var acl = new RawSecurityDescriptor(sddl).SystemAcl;
        return acl is not null && acl.Cast<GenericAce>().Any(ace => ace is QualifiedAce rule
            && !rule.IsCallback && rule.AceQualifier == AceQualifier.SystemAudit
            && (rule.AceFlags & (AceFlags.SuccessfulAccess | AceFlags.ContainerInherit)) == (AceFlags.SuccessfulAccess | AceFlags.ContainerInherit)
            && (rule.AceFlags & AceFlags.NoPropagateInherit) == 0
            && (rule.AccessMask & (0x20 | 0x10000000 | 0x40000000)) != 0
            && (rule.SecurityIdentifier.IsWellKnown(WellKnownSidType.WorldSid) || rule.SecurityIdentifier.IsWellKnown(WellKnownSidType.AuthenticatedUserSid))
            && (rule is not ObjectAce obj || obj.ObjectAceFlags == ObjectAceFlags.None));
    }

    public string WithDomainRootAudit(string sddl)
    {
        if (HasDomainRootAudit(sddl)) return sddl;
        var descriptor = new RawSecurityDescriptor(sddl);
        descriptor.SystemAcl ??= new RawAcl(GenericAcl.AclRevisionDS, 1);
        int index = 0;
        while (index < descriptor.SystemAcl.Count && (descriptor.SystemAcl[index].AceFlags & AceFlags.Inherited) == 0) index++;
        descriptor.SystemAcl.InsertAce(index, new CommonAce(AceFlags.ContainerInherit | AceFlags.SuccessfulAccess,
            AceQualifier.SystemAudit, 0x20, new SecurityIdentifier(WellKnownSidType.WorldSid, null), false, null));
        descriptor.SetFlags(descriptor.ControlFlags | ControlFlags.SystemAclPresent);
        return descriptor.GetSddlForm(AccessControlSections.Audit);
    }

    public DomainRootAuditSnapshot? ReadDomainRootAudit()
    {
        var result = DomainRootRequest(new JsonObject());
        string domain = result["domain"]!.GetValue<string>(), sddl = result["sddl"]!.GetValue<string>();
        return new(domain, sddl, HasDomainRootAudit(sddl));
    }

    public void SetDomainRootAudit(string domain, string expected, string sddl)
    {
        if (!IsSystem) throw new AgentException("agent_audit_system_required");
        DomainRootRequest(new JsonObject { ["domain"] = domain, ["expected"] = expected, ["sddl"] = sddl });
    }

    private static JsonObject DomainRootRequest(JsonObject request)
    {
        // Fixed, shipped ADSI operation; only JSON data travels on stdin. No RSAT module is required.
        const string script = """
            $ErrorActionPreference = 'Stop'
            [Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
            [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
            try {
                $request = [Console]::In.ReadToEnd() | ConvertFrom-Json
                $auth = [DirectoryServices.AuthenticationTypes]::Secure -bor [DirectoryServices.AuthenticationTypes]::Signing -bor [DirectoryServices.AuthenticationTypes]::Sealing
                $dse = [DirectoryServices.DirectoryEntry]::new('LDAP://localhost/RootDSE', $null, $null, $auth)
                $domain = [string]$dse.Properties['defaultNamingContext'][0]
                if ([string]::IsNullOrWhiteSpace($domain)) { throw 'domain' }
                $root = [DirectoryServices.DirectoryEntry]::new(('LDAP://localhost/' + $domain), $null, $null, $auth)
                $root.Options.SecurityMasks = [DirectoryServices.SecurityMasks]::Sacl
                $root.RefreshCache(@('ntSecurityDescriptor'))
                $security = $root.ObjectSecurity
                $sddl = $security.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Audit)
                if ($null -ne $request.sddl) {
                    if ($request.domain -cne $domain -or $request.expected -cne $sddl) { throw 'conflict' }
                    $security.SetSecurityDescriptorSddlForm([string]$request.sddl, [Security.AccessControl.AccessControlSections]::Audit)
                    $root.ObjectSecurity = $security
                    $root.CommitChanges()
                    $root.RefreshCache(@('ntSecurityDescriptor'))
                    $sddl = $root.ObjectSecurity.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Audit)
                }
                @{ domain = $domain; sddl = $sddl } | ConvertTo-Json -Compress
            } catch { exit 1 }
            finally { if ($null -ne $root) { $root.Dispose() }; if ($null -ne $dse) { $dse.Dispose() } }
            """;
        using var privilege = new SecurityPrivilege();
        using var process = new Process { StartInfo = new ProcessStartInfo {
            FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true,
            StandardInputEncoding = new UTF8Encoding(false), StandardOutputEncoding = new UTF8Encoding(false) } };
        foreach (var arg in new[] { "-NoProfile", "-NonInteractive", "-EncodedCommand", Convert.ToBase64String(Encoding.Unicode.GetBytes(script)) }) process.StartInfo.ArgumentList.Add(arg);
        if (!process.Start()) throw new AgentException("agent_domain_audit_failed");
        try
        {
            var errors = process.StandardError.BaseStream.CopyToAsync(Stream.Null);
            process.StandardInput.Write(request.ToJsonString()); process.StandardInput.Close();
            var output = new StringBuilder(); var buffer = new char[4096]; int count;
            while ((count = process.StandardOutput.Read(buffer, 0, buffer.Length)) > 0)
            {
                if (output.Length + count > 1024 * 1024) throw new AgentException("agent_domain_audit_failed");
                output.Append(buffer, 0, count);
            }
            process.WaitForExit(); errors.GetAwaiter().GetResult();
            if (process.ExitCode != 0) throw new AgentException("agent_domain_audit_failed");
            return JsonNode.Parse(output.ToString().TrimStart('\uFEFF'))!.AsObject();
        }
        finally { if (!process.HasExited) { process.Kill(entireProcessTree: true); process.WaitForExit(); } }
    }
    private Dictionary<string, string>? _scopedPolicies;
    private const string CommandKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit";
    private const string CommandValue = "ProcessCreationIncludeCmdLine_Enabled";
    private const string AuditCse = "{f3ccc681-b74c-4060-9f26-cd84525dca2a}";
    public bool IsSystem => WindowsIdentity.GetCurrent().User?.IsWellKnown(WellKnownSidType.LocalSystemSid) == true;

    public Dictionary<string, int> Query(IReadOnlyCollection<string> guids)
    {
        var result = new Dictionary<string, int>();
        if (guids.Count == 0) return result;
        var ids = guids.Select(Guid.Parse).Order().ToArray();
        using var privilege = new SecurityPrivilege();
        if (!AuditQuerySystemPolicy(ids, (uint)ids.Length, out var buffer))
            throw new FileAuditNativeReadException("agent_audit_query_failed", unchecked((uint)Marshal.GetLastPInvokeError()));
        try
        {
            var size = Marshal.SizeOf<PolicyInformation>();
            for (var i = 0; i < ids.Length; i++)
            {
                var row = Marshal.PtrToStructure<PolicyInformation>(buffer + i * size);
                var id = row.Subcategory.ToString("D");
                if (row.Mask > 4 || !guids.Contains(id) || !result.TryAdd(id, (int)(row.Mask & 3))) throw new AgentException("agent_audit_query_invalid");
            }
            if (result.Count != guids.Count) throw new AgentException("agent_audit_query_invalid");
            return result;
        }
        finally { AuditFree(buffer); }
    }

    public void Set(IReadOnlyDictionary<string, int> changes)
    {
        if (!IsSystem) throw new AgentException("agent_audit_system_required");
        var rows = changes.Select(pair => new PolicyInformation { Subcategory = Guid.Parse(pair.Key), Mask = pair.Value == 0 ? 4u : (uint)pair.Value }).ToArray();
        using var privilege = new SecurityPrivilege();
        if (!AuditSetSystemPolicy(rows, (uint)rows.Length)) throw new AgentException("agent_audit_set_failed");
    }

    private static RegistryKey Machine() => RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
    private static int? ReadDword(string path, string name)
    {
        using var root = Machine();
        using var key = root.OpenSubKey(path);
        var value = key?.GetValue(name);
        if (value is null) return null;
        if (value is not int number) throw new AgentException("agent_audit_registry_invalid");
        return number;
    }

    public int? CommandLine
    {
        get
        {
            var value = ReadDword(CommandKey, CommandValue);
            if (value is not (null or 0 or 1)) throw new AgentException("agent_audit_registry_invalid");
            return value;
        }
        set
        {
            if (!IsSystem || value is not (null or 0 or 1)) throw new AgentException("agent_audit_system_required");
            using var root = Machine();
            using var key = root.CreateSubKey(CommandKey);
            if (value is null) key.DeleteValue(CommandValue, false);
            else key.SetValue(CommandValue, value.Value, RegistryValueKind.DWord);
        }
    }

    public string Ownership()
    {
        try
        {
            using var root = Machine();
            using var history = root.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History\" + AuditCse);
            if (history is not null)
            {
                if (history.SubKeyCount > 1024) return "unknown";
                foreach (var name in history.GetSubKeyNames())
                {
                    using var item = history.OpenSubKey(name);
                    if (item?.GetValue("FileSysPath") is string path && path.StartsWith(@"\\", StringComparison.Ordinal)) return "managed_by_gpo";
                }
            }
            var force = ReadDword(@"SYSTEM\CurrentControlSet\Control\Lsa", "SCENoApplyLegacyAuditPolicy");
            return ReadRsop(force, commandOnly: false);
        }
        catch (Exception exception) when (exception is not OperationCanceledException) { return "unknown"; }
    }

    public string Ownership(IReadOnlyCollection<string> guids)
    {
        _scopedPolicies = null;
        // Legacy category policy cannot safely be resolved per subcategory.
        if (ReadDword(@"SYSTEM\CurrentControlSet\Control\Lsa", "SCENoApplyLegacyAuditPolicy") != 1) return Ownership();
        try
        {
            using var root = Machine();
            using var history = root.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History\" + AuditCse);
            if (history is null || history.SubKeyCount is 0 or > 1024) return Ownership();
            var owners = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var key in history.GetSubKeyNames())
            {
                using var item = history.OpenSubKey(key);
                if (item?.GetValue("FileSysPath") is not string directory || !directory.StartsWith(@"\\", StringComparison.Ordinal)) return Ownership();
                if (item.GetValue("DisplayName") is not string display || string.IsNullOrWhiteSpace(display) || display.Length > 200 || display.Any(char.IsControl)) return Ownership();
                var path = Path.Combine(directory, @"Microsoft\Windows NT\Audit\audit.csv");
                // Unreadable policy is not proof that a setting is locally owned.
                if (new FileInfo(path).Length > 1024 * 1024) return Ownership();
                using var parser = new TextFieldParser(path) { TextFieldType = FieldType.Delimited, HasFieldsEnclosedInQuotes = true };
                parser.SetDelimiters(",");
                var header = parser.ReadFields() ?? [];
                int guidColumn = Array.FindIndex(header, h => h.Equals("Subcategory GUID", StringComparison.OrdinalIgnoreCase));
                int valueColumn = Array.FindIndex(header, h => h.Equals("Setting Value", StringComparison.OrdinalIgnoreCase));
                if (guidColumn < 0 || valueColumn < 0) return Ownership();
                while (!parser.EndOfData)
                {
                    var fields = parser.ReadFields() ?? [];
                    if (fields.Length != header.Length || !Guid.TryParse(fields[guidColumn], out var id)
                        || !int.TryParse(fields[valueColumn], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var mask)
                        || mask is < 0 or > 3) return Ownership();
                    string guid = id.ToString("D");
                    if (!guids.Contains(guid)) continue;
                    // Multiple contributing policies are named without guessing precedence.
                    owners[guid] = owners.TryGetValue(guid, out var previous) && previous != display ? (previous + "; " + display)[..Math.Min(200, previous.Length + display.Length + 2)] : display;
                }
            }
            _scopedPolicies = owners;
            return owners.Count > 0 ? "managed_by_gpo" : "ok";
        }
        catch (Exception exception) when (exception is not OperationCanceledException) { return Ownership(); }
    }

    public IReadOnlyDictionary<string, string> PolicyNames(IReadOnlyCollection<string> guids) =>
        _scopedPolicies ?? new Dictionary<string, string>();

    public string CommandLineOwnership() => ReadRsop(null, commandOnly: true);

    public JsonObject PowershellLogging()
    {
        using var channel = new System.Diagnostics.Eventing.Reader.EventLogConfiguration("Microsoft-Windows-PowerShell/Operational");
        var flag = ReadDword(@"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging");
        if (flag is not (null or 0 or 1)) throw new AgentException("agent_audit_registry_invalid");
        return new JsonObject { ["channel_enabled"] = channel.IsEnabled, ["script_block_logging_enabled"] = flag == 1 };
    }

    private static string ReadRsop(int? force, bool commandOnly)
    {
        object? locator = null, service = null, rows = null, legacy = null;
        try
        {
            locator = Activator.CreateInstance(Type.GetTypeFromProgID("WbemScripting.SWbemLocator")!);
            service = ((dynamic)locator!).ConnectServer(".", @"root\RSOP\Computer");
            rows = ((dynamic)service).ExecQuery(commandOnly
                ? "SELECT * FROM RSOP_RegistryPolicySetting WHERE valueName='ProcessCreationIncludeCmdLine_Enabled'"
                : "SELECT * FROM RSOP_GPO");
            foreach (dynamic row in (System.Collections.IEnumerable)rows)
            {
                try
                {
                    if (commandOnly ? ((string)row.keyName).EndsWith(CommandKey, StringComparison.OrdinalIgnoreCase)
                        : (bool)row.enabled && !(bool)row.accessDenied && (bool)row.filterAllowed
                          && ((string)row.fileSystemPath).StartsWith(@"\\", StringComparison.Ordinal)
                          && ((string)row.extensionIds).Contains(AuditCse, StringComparison.OrdinalIgnoreCase)) return "managed_by_gpo";
                }
                finally { Marshal.FinalReleaseComObject(row); }
            }
            if (!commandOnly && force != 1)
            {
                legacy = ((dynamic)service).ExecQuery("SELECT * FROM RSOP_AuditPolicy");
                if ((int)((dynamic)legacy).Count > 0) return "managed_by_gpo";
            }
            return "ok";
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            if (commandOnly || force != 1) return "unknown";
            if (NetGetJoinInformation(null, out var name, out var status) != 0) return "unknown";
            try { return status == 3 ? "unknown" : "ok"; }
            finally { NetApiBufferFree(name); }
        }
        finally
        {
            foreach (var item in new[] { legacy, rows, service, locator }) if (item is not null && Marshal.IsComObject(item)) Marshal.FinalReleaseComObject(item);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PolicyInformation { public Guid Subcategory; public uint Mask; public Guid Category; }
    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private struct TokenPrivilege { public uint Count; public long Luid; public uint Attributes; }

    internal sealed class SecurityPrivilege : IDisposable
    {
        private readonly IntPtr _token;
        private TokenPrivilege _previous;
        public SecurityPrivilege()
        {
            if (!OpenProcessToken(System.Diagnostics.Process.GetCurrentProcess().Handle, 0x28, out _token))
                throw new FileAuditNativeReadException("agent_audit_privilege_unavailable", unchecked((uint)Marshal.GetLastPInvokeError()));
            if (!LookupPrivilegeValue(null, "SeSecurityPrivilege", out var luid))
            {
                uint status = unchecked((uint)Marshal.GetLastPInvokeError());
                CloseHandle(_token);
                throw new FileAuditNativeReadException("agent_audit_privilege_unavailable", status);
            }
            var desired = new TokenPrivilege { Count = 1, Luid = luid, Attributes = 2 };
            bool adjusted = AdjustTokenPrivileges(_token, false, ref desired, Marshal.SizeOf<TokenPrivilege>(), out _previous, out _);
            uint error = unchecked((uint)Marshal.GetLastPInvokeError());
            if (!adjusted || error != 0)
            {
                CloseHandle(_token);
                throw new FileAuditNativeReadException("agent_audit_privilege_unavailable", error);
            }
        }
        public void Dispose() { AdjustTokenPrivileges(_token, false, ref _previous, 0, out _, out _); CloseHandle(_token); }
    }

    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AuditQuerySystemPolicy([In] Guid[] ids, uint count, out IntPtr policies);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AuditSetSystemPolicy([In] PolicyInformation[] policies, uint count);
    [DllImport("advapi32.dll")] private static extern void AuditFree(IntPtr buffer);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LookupPrivilegeValue(string? system, string name, out long luid);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AdjustTokenPrivileges(IntPtr token, [MarshalAs(UnmanagedType.Bool)] bool disable, ref TokenPrivilege desired, int size, out TokenPrivilege previous, out int length);
    [DllImport("kernel32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)] private static extern int NetGetJoinInformation(string? server, out IntPtr name, out int status);
    [DllImport("netapi32.dll")] private static extern int NetApiBufferFree(IntPtr buffer);
}

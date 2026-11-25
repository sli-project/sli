using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json.Nodes;
using Microsoft.Win32.SafeHandles;
using Sli.Agent.Core;

namespace Sli.Agent.Windows;

public enum LocalSmbCatalogState { Ready, Incomplete, Unavailable }
public sealed record LocalSmbShare(string Name, string Path);
public sealed record LocalSmbCatalog(LocalSmbCatalogState State, IReadOnlyList<LocalSmbShare> Shares, uint? NativeStatus = null);

/// <summary>Handle based local operations. No file contents, DACL writes, remote paths or executable server input.</summary>
[SupportedOSPlatform("windows")]
public sealed class NativeFileAuditApi : IFileAuditApi
{
    private readonly WindowsAuditApi _audit = new();
    public string AuditOwnership => _audit.Ownership();
    public Dictionary<string,int> QueryMasks(IReadOnlyCollection<string> guids) => _audit.Query(guids);
    public string Preflight(JsonArray roots) => Preflight(roots, false);
    public string Preflight(JsonArray roots, bool describeReadErrors) => Preflight(roots, describeReadErrors, readOnlyCheck: false);
    public string CheckPreflight(JsonArray roots, bool describeReadErrors) => Preflight(roots, describeReadErrors, readOnlyCheck: true);

    private string Preflight(JsonArray roots, bool describeReadErrors, bool readOnlyCheck)
    {
        if (!_audit.IsSystem) return "system_required";
        var owner=_audit.Ownership(); if (owner is not ("ok" or "managed_by_gpo")) return owner;
        using var privilege=new WindowsAuditApi.SecurityPrivilege();
        using (var reader=new System.Diagnostics.Eventing.Reader.EventLogReader(new System.Diagnostics.Eventing.Reader.EventLogQuery("Security",System.Diagnostics.Eventing.Reader.PathType.LogName,"*")))
        using (reader.ReadEvent(TimeSpan.FromSeconds(1))) { }
        bool globalSaclRead = AuditQueryGlobalSacl("File", out var acl);
        uint globalSaclStatus = globalSaclRead ? 0u : unchecked((uint)Marshal.GetLastPInvokeError());
        string? globalSaclBlock;
        try
        {
            int aceCount = globalSaclRead && acl != IntPtr.Zero ? (ushort)Marshal.ReadInt16(acl, 4) : 0;
            globalSaclBlock = GlobalFileSaclPreflight.BlockReason(globalSaclRead, aceCount, globalSaclStatus, readOnlyCheck);
        }
        finally { if (globalSaclRead && acl != IntPtr.Zero) LocalFree(acl); }
        if (globalSaclBlock is not null)
        {
            if (describeReadErrors && globalSaclBlock == "global_sacl_unknown")
                throw new FileAuditNativeReadException(globalSaclBlock, globalSaclStatus);
            return globalSaclBlock;
        }
        object? locator=null, service=null, rows=null;
        try
        {
            locator=Activator.CreateInstance(Type.GetTypeFromProgID("WbemScripting.SWbemLocator")!);
            service=((dynamic)locator!).ConnectServer(".",@"root\RSOP\Computer"); rows=((dynamic)service).ExecQuery("SELECT * FROM RSOP_File");
            foreach (dynamic row in (System.Collections.IEnumerable)rows)
            {
                try
                {
                    var path=FileAuditPolicy.LocalPath(Environment.ExpandEnvironmentVariables((string)row.Path));
                    if (roots.Count == 0 || roots.Any(r => FileAuditPolicy.InRoot(r!["path"]!.ToString(),path) || FileAuditPolicy.InRoot(path,r!["path"]!.ToString()))) return "managed_by_gpo";
                }
                finally { Marshal.FinalReleaseComObject(row); }
            }
            return "ok";
        }
        catch (Exception e) when (!describeReadErrors && e is not OperationCanceledException) { return "unknown"; }
        finally { foreach (var item in new[] {rows,service,locator}) if (item is not null && Marshal.IsComObject(item)) Marshal.FinalReleaseComObject(item); }
    }

    public IFileAuditObject Open(string path,string root) => new NativeObject(path,root);
    public void CheckPath(string path,string root)
    {
        // Deleted targets are acceptable only after the configured root and all existing ancestors were pinned.
        using var pinned=new PinnedPath(path,root,attributesOnly:true,allowMissing:true);
    }
    public JsonObject Share(string name,string root)
    {
        uint status = NetShareGetInfo(null,name,502,out var buffer);
        try
        {
            if (status != 0) throw new FileAuditNativeReadException("file_audit_share_unavailable", status);
            var info=Marshal.PtrToStructure<Share502>(buffer);
            if (!FileAuditPolicy.LocalPath(info.Path).Equals(root,StringComparison.OrdinalIgnoreCase)) throw new AgentException("file_audit_share_root_mismatch");
            return new JsonObject { ["name"]=name,["path"]=root,["dacl"]=Format(info.Descriptor,4),["complete"]=true };
        }
        finally { if (buffer != IntPtr.Zero) NetApiBufferFree(buffer); }
    }
    public static LocalSmbCatalog ListLocalShares(CancellationToken cancellationToken)
    {
        const uint moreData = 234, diskTypeMask = 0xff, maxEntries = 1024;
        const int maxPages = 32, maxShares = 128;
        var shares = new List<LocalSmbShare>();
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var size = Marshal.SizeOf<Share2>();
        uint resume = 0;
        for (var page = 0; page < maxPages; page++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var before = resume;
            // NULL names the enrolled host itself. Level 2 provides the local path.
            var status = NetShareEnum(null, 2, out var buffer, 8192, out var entries, out _, ref resume);
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (status is not (0 or moreData)) return new(LocalSmbCatalogState.Unavailable, [], status);
                if (entries > maxEntries || entries != 0 && buffer == IntPtr.Zero)
                    return new(LocalSmbCatalogState.Incomplete, [], status == moreData ? status : null);

                for (var i = 0; i < entries; i++)
                {
                    var info = Marshal.PtrToStructure<Share2>(IntPtr.Add(buffer, i * size));
                    if ((info.Type & diskTypeMask) != 0) continue;
                    var name = Marshal.PtrToStringUni(info.Name);
                    if (name?.ToUpperInvariant() is "ADMIN$" or "IPC$" or "PRINT$" or "FAX$" or "SYSVOL" or "NETLOGON")
                        continue;
                    var path = Marshal.PtrToStringUni(info.Path);
                    if (name is not { Length: >= 1 and <= 80 } || name.Trim() != name
                        || name.Any(c => c < 32 || "\\/:*?\"<>|".Contains(c)) || path is null)
                        return new(LocalSmbCatalogState.Incomplete, []);
                    string local;
                    try { local = FileAuditPolicy.LocalPath(path); }
                    catch (AgentException) { return new(LocalSmbCatalogState.Incomplete, []); }
                    if (name.Length == 2 && name[1] == '$' && local.Length == 3
                        && char.ToUpperInvariant(name[0]) == char.ToUpperInvariant(local[0]))
                        continue;
                    if (shares.Count == maxShares || !names.Add(name))
                        return new(LocalSmbCatalogState.Incomplete, []);
                    shares.Add(new(name, local));
                }
                if (status == 0) return new(LocalSmbCatalogState.Ready, shares);
                if (resume == 0 || resume == before) return new(LocalSmbCatalogState.Incomplete, [], status);
            }
            finally
            {
                if (buffer != IntPtr.Zero) NetApiBufferFree(buffer);
            }
        }
        return new(LocalSmbCatalogState.Incomplete, [], moreData);
    }

    public JsonObject LocalGroups(int limit, bool allowUnresolvedSid = false)
    {
        var bound = Math.Min(limit, 100);
        var groups = new JsonArray();
        bool complete;
        var seen = 0;
        nuint resume = 0;
        var status = NetLocalGroupEnum(null, 0, out var buffer, 4096, out var count, out _, ref resume);
        try
        {
            EnsureLocalGroupRead(status);
            complete = status == 0 && resume == 0;
            if (count == 0) return new() { ["complete"] = complete, ["groups"] = groups };

            var builtinSid = new SecurityIdentifier(WellKnownSidType.BuiltinDomainSid, null);
            var builtinAdmin = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var builtinAccount = (NTAccount)builtinAdmin.Translate(typeof(NTAccount));
            var builtinAuthority = builtinAccount.Value.Split('\\')[0];
            var (accountAuthority, accountDomainSid) = LocalAccountDomain();

            for (var i = 0; i < count; i++)
            {
                if (seen >= bound) { complete = false; break; }
                seen++;
                var name = Marshal.PtrToStringUni(Marshal.ReadIntPtr(buffer, i * IntPtr.Size));
                var sid = string.IsNullOrEmpty(name) ? null : SelectLocalGroupSid(
                    ResolveGroupSid(builtinAuthority, name), builtinSid,
                    ResolveGroupSid(accountAuthority, name), accountDomainSid);
                if (sid is null)
                {
                    if (!allowUnresolvedSid) throw new AgentException("file_audit_group_sid_unresolved");
                    complete = false;
                    continue;
                }

                nuint memberResume = 0;
                var memberStatus = NetLocalGroupGetMembers(null, name, 0, out var members, 4096,
                    out var memberCount, out _, ref memberResume);
                var ids = new JsonArray();
                try
                {
                    EnsureLocalGroupRead(memberStatus);
                    complete &= memberStatus == 0 && memberResume == 0;
                    for (var j = 0; j < memberCount; j++)
                    {
                        if (seen >= bound) { complete = false; break; }
                        ids.Add(new SecurityIdentifier(Marshal.ReadIntPtr(members, j * IntPtr.Size)).Value);
                        seen++;
                    }
                }
                finally
                {
                    if (members != IntPtr.Zero) NetApiBufferFree(members);
                }
                groups.Add(new JsonObject { ["group_sid"] = sid.Value, ["member_sids"] = ids });
            }
        }
        finally
        {
            if (buffer != IntPtr.Zero) NetApiBufferFree(buffer);
        }
        return new() { ["complete"] = complete, ["groups"] = groups };
    }

    internal static void EnsureLocalGroupRead(uint status)
    {
        const uint ErrorMoreData = 234;
        if (status is not (0 or ErrorMoreData))
            throw new FileAuditNativeReadException("file_audit_groups_unavailable", status);
    }

    private static SecurityIdentifier? ResolveGroupSid(string authority, string name)
    {
        try
        {
            return (SecurityIdentifier)new NTAccount(authority, name).Translate(typeof(SecurityIdentifier));
        }
        catch (IdentityNotMappedException)
        {
            return null;
        }
    }

    internal static SecurityIdentifier? SelectLocalGroupSid(
        SecurityIdentifier? builtin, SecurityIdentifier builtinDomain,
        SecurityIdentifier? account, SecurityIdentifier accountDomain)
    {
        if (builtin?.IsEqualDomainSid(builtinDomain) != true) builtin = null;
        if (account?.IsEqualDomainSid(accountDomain) != true) account = null;
        if (builtin is not null && account is not null && !builtin.Equals(account)) return null;
        return builtin ?? account;
    }

    // Ask the local SAM for its actual account domain. On a DC this is the AD domain,
    // and using the computer name would miss its domain-local aliases.
    private static (string Name, SecurityIdentifier Sid) LocalAccountDomain()
    {
        const uint PolicyViewLocalInformation = 1;
        const int PolicyAccountDomainInformation = 5;
        var attributes = new LsaObjectAttributes();
        var status = LsaOpenPolicy(IntPtr.Zero, ref attributes, PolicyViewLocalInformation, out var policy);
        if (status != 0)
            throw new FileAuditNativeReadException("file_audit_groups_unavailable", LsaNtStatusToWinError(status));
        try
        {
            status = LsaQueryInformationPolicy(policy, PolicyAccountDomainInformation, out var buffer);
            if (status != 0)
                throw new FileAuditNativeReadException("file_audit_groups_unavailable", LsaNtStatusToWinError(status));
            try
            {
                if (buffer == IntPtr.Zero) throw new AgentException("file_audit_group_domain_unavailable");
                var info = Marshal.PtrToStructure<LsaAccountDomainInfo>(buffer);
                var name = Marshal.PtrToStringUni(info.Name.Buffer, info.Name.Length / sizeof(char));
                if (string.IsNullOrEmpty(name) || info.Sid == IntPtr.Zero)
                    throw new AgentException("file_audit_group_domain_unavailable");
                return (name, new SecurityIdentifier(info.Sid));
            }
            finally { LsaFreeMemory(buffer); }
        }
        finally { LsaClose(policy); }
    }

    private sealed class PinnedPath : IDisposable
    {
        public List<SafeFileHandle> Handles { get; } = [];
        private readonly WindowsAuditApi.SecurityPrivilege? _privilege;
        public PinnedPath(string path,string root,bool attributesOnly=false,bool allowMissing=false)
        {
            path=FileAuditPolicy.LocalPath(path); root=FileAuditPolicy.LocalPath(root);
            if (!FileAuditPolicy.InRoot(path,root)) throw new AgentException("file_audit_scope_escape");
            if (!attributesOnly) _privilege=new WindowsAuditApi.SecurityPrivilege();
            try
            {
                var components=new List<string> {path[..3]};
                foreach (var part in path[3..].Split('\\',StringSplitOptions.RemoveEmptyEntries)) components.Add(components[^1].TrimEnd('\\')+"\\"+part);
                var verifiedRoot=false;
                foreach (var component in components)
                {
                    var access=component == path && !attributesOnly ? 0x03000000u : 0x80u;
                    var handle=CreateFile(component,access,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
                    if (handle.IsInvalid)
                    {
                        var error=Marshal.GetLastPInvokeError(); handle.Dispose();
                        if (allowMissing && verifiedRoot && error is 2 or 3) return;
                        throw new FileAuditNativeReadException("file_audit_path_unavailable", unchecked((uint)error));
                    }
                    Handles.Add(handle);
                    if (!GetFileInformationByHandle(handle,out var info))
                        throw new FileAuditNativeReadException("file_audit_path_unavailable", unchecked((uint)Marshal.GetLastPInvokeError()));
                    if ((info.Attributes & 0x400) != 0) throw new AgentException("file_audit_reparse_point");
                    if (component.Equals(root,StringComparison.OrdinalIgnoreCase)) verifiedRoot=true;
                }
            }
            catch { Dispose(); throw; }
        }
        public void Dispose() { for (var i=Handles.Count-1; i>=0; i--) Handles[i].Dispose(); Handles.Clear(); _privilege?.Dispose(); }
    }
    private sealed class NativeObject : IFileAuditObject
    {
        private readonly string _path;
        private readonly PinnedPath _pin;
        private SafeFileHandle Handle => _pin.Handles[^1];
        public NativeObject(string path,string root) { _path=FileAuditPolicy.LocalPath(path); _pin=new(path,root); }
        private static byte[] Descriptor(SafeFileHandle handle,uint parts=15)
        {
            uint status = GetSecurityInfo(handle,1,parts,out _,out _,out _,out _,out var sd);
            if (status != 0) throw new FileAuditNativeReadException("file_audit_descriptor_unavailable", status);
            try { var size=GetSecurityDescriptorLength(sd); if (size is < 20 or > 1048576) throw new AgentException("file_audit_descriptor_invalid"); var bytes=new byte[size]; Marshal.Copy(sd,bytes,0,(int)size); return bytes; }
            finally { LocalFree(sd); }
        }
        public JsonObject Describe()
        {
            var bytes=Descriptor(Handle); var sd=new RawSecurityDescriptor(bytes,0);
            if (!GetFileInformationByHandle(Handle,out var info))
                throw new FileAuditNativeReadException("file_audit_descriptor_unavailable", unchecked((uint)Marshal.GetLastPInvokeError()));
            return new JsonObject { ["object_id"]=$"{info.Volume}:{info.IndexHigh}:{info.IndexLow}",["object_type"]=(info.Attributes&16) != 0 ? "directory" : "file",
                ["owner_sid"]=sd.Owner!.Value,["dacl"]=Format(bytes,4),["sacl"]=Format(bytes,8),["sacl_protected"]=(sd.ControlFlags&ControlFlags.SystemAclProtected) != 0 };
        }
        public string Plan(JsonArray aces)
        {
            var sd=new RawSecurityDescriptor(Descriptor(Handle),0); var acl=sd.SystemAcl ?? new RawAcl(4,0);
            var directory=Describe()["object_type"]!.ToString() == "directory";
            foreach (var spec in aces.OfType<JsonObject>())
            {
                var sid=new SecurityIdentifier(spec["sid"]!.ToString()); var flags=spec["flags"]!.GetValue<int>(); var mask=spec["mask"]!.GetValue<int>();
                if (!directory) flags &= ~3;
                var covered=Enumerable.Range(0,acl.Count).Any(i => acl[i] is CommonAce a && a.AceType == AceType.SystemAudit && ((int)a.AceFlags&12) == 0 && ((int)a.AceFlags&flags) == flags && (a.AccessMask&mask) == mask && a.SecurityIdentifier.Equals(sid));
                if (!covered) acl.InsertAce(acl.Count,new CommonAce((AceFlags)flags,AceQualifier.SystemAudit,mask,sid,false,null));
            }
            sd.SystemAcl=acl; sd.SetFlags(sd.ControlFlags|ControlFlags.SystemAclPresent);
            return ExpectedSacl(Format(Binary(sd),8));
        }
        public string ExpectedSacl(string value)
        {
            var current=new RawSecurityDescriptor(Descriptor(Handle),0); var proposed=new RawSecurityDescriptor(value);
            if ((current.ControlFlags&ControlFlags.SystemAclProtected) != (proposed.ControlFlags&ControlFlags.SystemAclProtected)) throw new AgentException("file_audit_sacl_plan_failed");
            current.SystemAcl=proposed.SystemAcl; current.SetFlags(current.ControlFlags|ControlFlags.SystemAclPresent);
            var parentPath=Path.GetDirectoryName(_path) ?? _path;
            if (GetNamedSecurityInfo(parentPath,1,8,out _,out _,out _,out _,out var parentSd) != 0) throw new AgentException("file_audit_sacl_plan_failed");
            byte[] parent;
            try { var size=GetSecurityDescriptorLength(parentSd); if (size is < 20 or > 1048576) throw new AgentException("file_audit_sacl_plan_failed"); parent=new byte[size]; Marshal.Copy(parentSd,parent,0,(int)size); }
            finally { LocalFree(parentSd); }
            var mapping=new GenericMapping {Read=0x120089,Write=0x120116,Execute=0x1200a0,All=0x1f01ff};
            // Same in-memory inheritance operation and flags as Python LocalObject.expected_sacl.
            if (!CreatePrivateObjectSecurityEx(parent,Binary(current),out var result,IntPtr.Zero,Describe()["object_type"]!.ToString() == "directory",2|8|16,IntPtr.Zero,ref mapping)) throw new AgentException("file_audit_sacl_plan_failed");
            try { return Format(result,8); }
            finally { DestroyPrivateObjectSecurity(ref result); }
        }
        public void SetSacl(string value)
        {
            var sd=new RawSecurityDescriptor(value == "" ? "S:" : value); var acl=sd.SystemAcl;
            var bytes=acl is null ? null : new byte[acl.BinaryLength]; if (bytes is not null) acl!.GetBinaryForm(bytes,0);
            // MAXIMUM_ALLOWED pins the target without triggering uncontrolled propagation to descendants.
            if (SetSecurityInfo(Handle,1,8,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,bytes) != 0) throw new AgentException("file_audit_sacl_write_failed");
        }
        public IEnumerable<string> Children() => Directory.EnumerateFileSystemEntries(_path).Select(p => Path.GetFileName(p));
        public bool InheritedFrom(string previous,string applied)
        {
            static CommonAce[] Aces(string s) { var a=string.IsNullOrEmpty(s) ? null : new RawSecurityDescriptor(s).SystemAcl; return a is null ? [] : Enumerable.Range(0,a.Count).Select(i => a[i]).OfType<CommonAce>().ToArray(); }
            static string Key(CommonAce a) => $"{a.AceType}:{a.AceFlags}:{a.AccessMask}:{a.SecurityIdentifier.Value}";
            var prior=Aces(previous).GroupBy(Key).ToDictionary(g => g.Key,g => g.Count());
            var added=new List<CommonAce>(); foreach (var a in Aces(applied)) { var key=Key(a); if (prior.GetValueOrDefault(key)>0) prior[key]--; else added.Add(a); }
            return Aces(Describe()["sacl"]!.ToString()).Any(a => a.AceType == AceType.SystemAudit && (a.AceFlags&AceFlags.Inherited) != 0 && added.Any(b => ((int)b.AceFlags&3) != 0 && ((int)a.AceFlags&192) == ((int)b.AceFlags&192) && a.AccessMask == b.AccessMask && a.SecurityIdentifier.Equals(b.SecurityIdentifier)));
        }
        public void Dispose() => _pin.Dispose();
    }
    private static byte[] Binary(RawSecurityDescriptor sd) { var bytes=new byte[sd.BinaryLength]; sd.GetBinaryForm(bytes,0); return bytes; }
    private static string Format(byte[] sd,uint parts)
    {
        var pin=GCHandle.Alloc(sd,GCHandleType.Pinned);
        try { return Format(pin.AddrOfPinnedObject(),parts); } finally { pin.Free(); }
    }
    private static string Format(IntPtr sd,uint parts)
    {
        if (!ConvertSecurityDescriptorToStringSecurityDescriptor(sd,1,parts,out var text,out _))
            throw new FileAuditNativeReadException("file_audit_descriptor_invalid", unchecked((uint)Marshal.GetLastPInvokeError()));
        try { return Marshal.PtrToStringUni(text)!; } finally { LocalFree(text); }
    }
    [StructLayout(LayoutKind.Sequential)] private struct FileInfo { public uint Attributes,CreateLow,CreateHigh,AccessLow,AccessHigh,WriteLow,WriteHigh,Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow; }
    [StructLayout(LayoutKind.Sequential)] private struct GenericMapping { public uint Read,Write,Execute,All; }
    [StructLayout(LayoutKind.Sequential)]
    private struct Share2
    {
        public IntPtr Name;
        public uint Type;
        public IntPtr Remark;
        public uint Permissions, MaxUses, CurrentUses;
        public IntPtr Path, Password;
    }

    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] private struct Share502 { [MarshalAs(UnmanagedType.LPWStr)] public string Name; public uint Type; public IntPtr Remark; public uint Permissions,MaxUses,Uses; [MarshalAs(UnmanagedType.LPWStr)] public string Path; public IntPtr Password; public uint Reserved; public IntPtr Descriptor; }
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern SafeFileHandle CreateFile(string name,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool GetFileInformationByHandle(SafeFileHandle handle,out FileInfo info);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr value);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.U1)] private static extern bool AuditQueryGlobalSacl(string type,out IntPtr acl);
    [DllImport("advapi32.dll")] private static extern uint GetSecurityInfo(SafeFileHandle handle,int type,uint parts,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr sd);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode)] private static extern uint GetNamedSecurityInfo(string path,int type,uint parts,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr sd);
    [DllImport("advapi32.dll")] private static extern uint SetSecurityInfo(SafeFileHandle handle,int type,uint parts,IntPtr owner,IntPtr group,IntPtr dacl,byte[]? sacl);
    [DllImport("advapi32.dll")] private static extern uint GetSecurityDescriptorLength(IntPtr sd);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(IntPtr sd,uint revision,uint parts,out IntPtr text,out uint size);
    [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CreatePrivateObjectSecurityEx(byte[] parent,byte[] creator,out IntPtr result,IntPtr type,[MarshalAs(UnmanagedType.U1)] bool container,uint flags,IntPtr token,ref GenericMapping mapping);
    [DllImport("advapi32.dll")] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool DestroyPrivateObjectSecurity(ref IntPtr result);
    [DllImport("netapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint NetShareEnum(string? server, uint level, out IntPtr buffer, uint preferred,
        out uint entries, out uint total, ref uint resume);

    [DllImport("netapi32.dll",CharSet=CharSet.Unicode)] private static extern uint NetShareGetInfo(string? server,string name,uint level,out IntPtr buffer);
    [DllImport("netapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint NetLocalGroupEnum(string? server, uint level, out IntPtr buffer, uint preferred,
        out uint read, out uint total, ref nuint resume);
    [DllImport("netapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint NetLocalGroupGetMembers(string? server, string group, uint level, out IntPtr buffer,
        uint preferred, out uint read, out uint total, ref nuint resume);
    [DllImport("netapi32.dll")] private static extern uint NetApiBufferFree(IntPtr buffer);

    [StructLayout(LayoutKind.Sequential)]
    private struct LsaObjectAttributes
    {
        public uint Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct LsaUnicodeString
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct LsaAccountDomainInfo
    {
        public LsaUnicodeString Name;
        public IntPtr Sid;
    }

    [DllImport("advapi32.dll", ExactSpelling = true)]
    private static extern uint LsaOpenPolicy(IntPtr system, ref LsaObjectAttributes attributes, uint access, out IntPtr handle);
    [DllImport("advapi32.dll", ExactSpelling = true)]
    private static extern uint LsaQueryInformationPolicy(IntPtr policy, int infoClass, out IntPtr buffer);
    [DllImport("advapi32.dll", ExactSpelling = true)]
    private static extern uint LsaNtStatusToWinError(uint status);
    [DllImport("advapi32.dll", ExactSpelling = true)]
    private static extern uint LsaFreeMemory(IntPtr buffer);
    [DllImport("advapi32.dll", ExactSpelling = true)]
    private static extern uint LsaClose(IntPtr policy);
}

internal static class GlobalFileSaclPreflight
{
    private const uint ErrorFileNotFound = 2;

    internal static string? BlockReason(bool readSucceeded, int aceCount, uint status, bool readOnlyCheck)
    {
        if (readSucceeded)
            return aceCount > 0 ? "global_sacl_present" : null;

        // On a clean host, an absent global File SACL can yield ERROR_FILE_NOT_FOUND.
        // An inventory-only check may continue to the remaining policy checks.
        return readOnlyCheck && status == ErrorFileNotFound ? null : "global_sacl_unknown";
    }
}

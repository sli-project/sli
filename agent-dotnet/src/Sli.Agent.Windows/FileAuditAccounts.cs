using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text;
using Sli.Agent.Core;

namespace Sli.Agent.Windows;

/// <summary>One bounded batch cache, matching Python UserAccountFilter. Unknown identities become coverage gaps.</summary>
[SupportedOSPlatform("windows")]
public sealed class FileAuditAccounts
{
    private HashSet<string>? _services;
    private readonly Dictionary<string,bool> _accounts = [];
    public bool IsUser(string sid)
    {
        _services ??= ReadServices();
        if (_accounts.TryGetValue(sid,out var known)) return known;
        var identity=new SecurityIdentifier(sid); var bytes=new byte[identity.BinaryLength]; identity.GetBinaryForm(bytes,0);
        uint nameLength=0,domainLength=0;
        LookupAccountSid(null,bytes,null,ref nameLength,null,ref domainLength,out _);
        if (nameLength is 0 or > 4096 || domainLength > 4096) throw new AgentException("file_audit_account_unavailable");
        var name=new StringBuilder((int)nameLength); var domain=new StringBuilder((int)domainLength);
        if (!LookupAccountSid(null,bytes,name,ref nameLength,domain,ref domainLength,out var kind)) throw new AgentException("file_audit_account_unavailable");
        return _accounts[sid]=kind == 1 && !name.ToString().EndsWith('$') && !_services.Contains(sid);
    }
    private static HashSet<string> ReadServices()
    {
        var scm=OpenSCManager(null,null,4); if (scm == IntPtr.Zero) throw new AgentException("file_audit_account_unavailable");
        try
        {
            uint resume=0;
            var listed=EnumServicesStatusEx(scm,0,0x30,3,IntPtr.Zero,0,out var needed,out _,ref resume,null);
            if (!listed && Marshal.GetLastPInvokeError() != 234) throw new AgentException("file_audit_account_unavailable");
            if (needed > 4*1024*1024) throw new AgentException("file_audit_account_unavailable");
            if (needed == 0) return [];
            var buffer=Marshal.AllocHGlobal((int)needed);
            try
            {
                resume=0;
                if (!EnumServicesStatusEx(scm,0,0x30,3,buffer,needed,out _,out var count,ref resume,null) || resume != 0 || count > 10000) throw new AgentException("file_audit_account_unavailable");
                var result=new HashSet<string>(); var size=Marshal.SizeOf<ServiceRow>();
                for (var i=0; i<count; i++)
                {
                    var row=Marshal.PtrToStructure<ServiceRow>(buffer+i*size); var service=OpenService(scm,Marshal.PtrToStringUni(row.Name)!,1);
                    if (service == IntPtr.Zero) throw new AgentException("file_audit_account_unavailable");
                    try
                    {
                        QueryServiceConfig(service,IntPtr.Zero,0,out var length);
                        if (length is 0 or > 65536) throw new AgentException("file_audit_account_unavailable");
                        var config=Marshal.AllocHGlobal((int)length);
                        try
                        {
                            if (!QueryServiceConfig(service,config,length,out _)) throw new AgentException("file_audit_account_unavailable");
                            var account=Marshal.PtrToStringUni(Marshal.PtrToStructure<ServiceConfig>(config).Account)!;
                            result.Add(account.Equals("LocalSystem",StringComparison.OrdinalIgnoreCase) ? "S-1-5-18" : ((SecurityIdentifier)new NTAccount(account).Translate(typeof(SecurityIdentifier))).Value);
                        }
                        finally { Marshal.FreeHGlobal(config); }
                    }
                    finally { CloseServiceHandle(service); }
                }
                return result;
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        finally { CloseServiceHandle(scm); }
    }
    [StructLayout(LayoutKind.Sequential)] private struct ServiceRow { public IntPtr Name,Display; public uint Type,State,Accepted,WinExit,ServiceExit,CheckPoint,WaitHint,Pid,Flags; }
    [StructLayout(LayoutKind.Sequential)] private struct ServiceConfig { public uint Type,Start,Error; public IntPtr Binary,Group; public uint Tag; public IntPtr Dependencies,Account,Display; }
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern IntPtr OpenSCManager(string? machine,string? database,uint access);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern IntPtr OpenService(IntPtr scm,string name,uint access);
    [DllImport("advapi32.dll")] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CloseServiceHandle(IntPtr service);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool QueryServiceConfig(IntPtr service,IntPtr config,uint size,out uint needed);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool EnumServicesStatusEx(IntPtr scm,int level,uint type,uint state,IntPtr buffer,uint size,out uint needed,out int count,ref uint resume,string? group);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool LookupAccountSid(string? system,byte[] sid,StringBuilder? name,ref uint nameLength,StringBuilder? domain,ref uint domainLength,out int kind);
}

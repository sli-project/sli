using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using System.Xml.Linq;
using Microsoft.Win32.SafeHandles;

namespace Sli.Server.Sources;

public interface IEventLogSession : IDisposable { }
public sealed record EventLogState(long? LatestRecordId, long? OldestRecordId, string? GenerationIdentity);
public interface IWindowsEventLog
{
    IEventLogSession Open(EventLogLogin login);
    EventLogState Probe(IEventLogSession? session, string channel);
    long? Latest(IEventLogSession? session, string channel) => Probe(session,channel).LatestRecordId;
    IReadOnlyList<string> Read(IEventLogSession? session, string channel, string xpath, Action? heartbeat, CancellationToken ct);
}

// The Windows API already returns Unicode. No whoami subprocess/OEM decoding.
public sealed class WindowsEventLog : IWindowsEventLog
{
    private sealed class Handle : SafeHandleZeroOrMinusOneIsInvalid, IEventLogSession
    {
        internal Handle(nint value) : base(true) => SetHandle(value);
        protected override bool ReleaseHandle() => EvtClose(handle);
    }
    [StructLayout(LayoutKind.Sequential)] private struct Login { public nint Server, User, Domain, Password; public int Flags; }
    [DllImport("wevtapi.dll", SetLastError=true)] private static extern nint EvtOpenSession(int loginClass, ref Login login, int timeout, int flags);
    [DllImport("wevtapi.dll", CharSet=CharSet.Unicode, SetLastError=true)] private static extern nint EvtQuery(nint session, string channel, string xpath, int flags);
    [DllImport("wevtapi.dll", SetLastError=true)] private static extern bool EvtNext(Handle query, int size, [Out] nint[] events, int timeout, int flags, out int returned);
    [DllImport("wevtapi.dll", CharSet=CharSet.Unicode, SetLastError=true)] private static extern bool EvtRender(nint context, nint value, int flags, int bufferSize, nint buffer, out int used, out int count);
    [DllImport("wevtapi.dll")] private static extern bool EvtClose(nint handle);
    private static nint Session(IEventLogSession? session) => session is Handle h ? h.DangerousGetHandle() : session is null ? 0 : throw new ArgumentException();
    private static void RequireWindows() { if (!OperatingSystem.IsWindows()) throw new CollectionSourceException("ad_source_backend_unsupported"); }
    public IEventLogSession Open(EventLogLogin value)
    {
        RequireWindows();
        var login = new Login();
        try {
            login.Server = Marshal.StringToHGlobalUni(value.Server);
            login.User = value.User is null ? 0 : Marshal.StringToHGlobalUni(value.User);
            login.Domain = value.Domain is null ? 0 : Marshal.StringToHGlobalUni(value.Domain);
            login.Password = value.Password is null ? 0 : Marshal.StringToHGlobalUni(value.Password);
            nint result = EvtOpenSession(1,ref login,0,0);
            if (result == 0) throw new Win32Exception(Marshal.GetLastWin32Error());
            return new Handle(result);
        }
        finally {
            foreach (nint p in new[] {login.Server,login.User,login.Domain}) if (p != 0) Marshal.FreeHGlobal(p);
            if (login.Password != 0) Marshal.ZeroFreeGlobalAllocUnicode(login.Password);
        }
    }
    private static Handle Query(IEventLogSession? session, string channel, string xpath, bool reverse)
    {
        RequireWindows();
        nint h = EvtQuery(Session(session),channel,xpath,1 | (reverse ? 0x200 : 0x100));
        if (h == 0) throw new Win32Exception(Marshal.GetLastWin32Error());
        return new(h);
    }
    private static string Render(nint value)
    {
        _ = EvtRender(0,value,1,0,0,out int size,out _);
        int error = Marshal.GetLastWin32Error();
        if (error != 122 || size <= 0) throw new Win32Exception(error);
        nint buffer = Marshal.AllocHGlobal(size);
        try {
            if (!EvtRender(0,value,1,size,buffer,out _,out _)) throw new Win32Exception(Marshal.GetLastWin32Error());
            return Marshal.PtrToStringUni(buffer) ?? throw new FormatException();
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }
    private static bool Next(Handle query, nint[] values, out int count)
    {
        // Infinite native wait, controlled by the owner process; no arbitrary deadline.
        if (EvtNext(query,values.Length,values,-1,0,out count)) return true;
        int error = Marshal.GetLastWin32Error();
        if (error == 259) return false;
        throw new Win32Exception(error);
    }
    private static long? Edge(IEventLogSession? session, string channel, bool reverse)
    {
        using var query = Query(session,channel,"*",reverse);
        nint[] values = new nint[1];
        if (!Next(query,values,out int count) || count == 0) return null;
        using var value = new Handle(values[0]);
        var xml = XElement.Parse(Render(values[0]));
        return long.Parse(xml.Descendants().Single(x => x.Name.LocalName == "EventRecordID").Value,System.Globalization.CultureInfo.InvariantCulture);
    }
    public EventLogState Probe(IEventLogSession? session, string channel) => new(Edge(session,channel,true),Edge(session,channel,false),null);
    public long? Latest(IEventLogSession? session, string channel) => Edge(session,channel,true);
    public IReadOnlyList<string> Read(IEventLogSession? session, string channel, string xpath, Action? heartbeat, CancellationToken ct)
    {
        using var query = Query(session,channel,xpath,false);
        var result = new List<string>(); nint[] values = new nint[64];
        while (true) {
            ct.ThrowIfCancellationRequested(); heartbeat?.Invoke();
            if (!Next(query,values,out int count)) return result;
            try { for (int i=0;i<count;i++) { ct.ThrowIfCancellationRequested(); result.Add(Render(values[i])); } }
            finally { for (int i=0;i<count;i++) _ = EvtClose(values[i]); }
        }
    }
}

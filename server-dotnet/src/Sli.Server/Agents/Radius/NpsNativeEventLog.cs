using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Win32.SafeHandles;
using Sli.Agent.Core;
using Sli.Agent.Protocol;

namespace Sli.Server.Agents.Radius;

// The Windows acquisition boundary; no EventLog package or Python runtime.
internal sealed class NpsNativeEventLog : INpsRemoteSession
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct Login { public string Server; public string? User, Domain, Password; public int Flags; }
    private sealed class EvtHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public EvtHandle() : base(true) { }
        protected override bool ReleaseHandle() => EvtClose(handle);
    }
    [DllImport("wevtapi.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern EvtHandle EvtOpenSession(int loginClass, ref Login login, int timeout, int flags);
    [DllImport("wevtapi.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool EvtClose(IntPtr handle);
    [DllImport("wevtapi.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern EvtHandle EvtQuery(EvtHandle session, string path, string query, int flags);
    [DllImport("wevtapi.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool EvtNext(EvtHandle query, int size, [Out] IntPtr[] events, int timeout, int flags, out int returned);
    [DllImport("wevtapi.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool EvtRender(IntPtr context, IntPtr fragment, int flags, int size, IntPtr buffer, out int used, out int count);
    [DllImport("wevtapi.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern EvtHandle EvtOpenLog(EvtHandle session, string path, int flags);
    [DllImport("wevtapi.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool EvtGetLogInfo(EvtHandle log, int property, int size, IntPtr buffer, out int used);
    private readonly EvtHandle session;

    internal static (string? User, string? Domain) LoginIdentity(NpsSourceCredentials? credentials)
    {
        string? user = credentials?.Username;
        if (user?.Contains('\\') != true) return (user, null); // Native UPN requires a null domain.
        var parts = user.Split('\\', 2);
        return (parts[1], parts[0]);
    }

    internal NpsNativeEventLog(string target, NpsSourceCredentials? credentials)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("ad_source_backend_unsupported");
        var (user, domain) = LoginIdentity(credentials);
        var login = new Login { Server = target, User = user, Domain = domain, Password = credentials?.Password, Flags = 0 };
        session = EvtOpenSession(1, ref login, 0, 0);
        if (session.IsInvalid) { int code = Marshal.GetLastWin32Error(); session.Dispose(); throw new Win32Exception(code); }
    }

    private static string Render(IntPtr record)
    {
        if (EvtRender(IntPtr.Zero, record, 1, 0, IntPtr.Zero, out int size, out _)) throw new InvalidDataException("event_xml_invalid");
        int error = Marshal.GetLastWin32Error();
        if (error != 122) throw new Win32Exception(error);
        // Reuse the parser's evidence-size bound before allocating native XML.
        if (size < 2 || size > 2 * (EventXml.MaxBytes + 1)) throw new InvalidDataException("event_xml_invalid");
        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (!EvtRender(IntPtr.Zero, record, 1, size, buffer, out _, out _)) throw new Win32Exception(Marshal.GetLastWin32Error());
            return Marshal.PtrToStringUni(buffer) ?? throw new InvalidDataException("event_xml_invalid");
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private IEnumerable<string> ReadQuery(string channel, string xpath, bool reverse, Action heartbeat, CancellationToken ct)
    {
        using var query = EvtQuery(session, channel, xpath, reverse ? 0x201 : 0x101);
        if (query.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
        var handles = new IntPtr[1];
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            // A polling wait permits heartbeat/cancellation. It is not a limit
            // on the query's lifetime, number of batches or total events.
            if (!EvtNext(query, 1, handles, 1000, 0, out int returned))
            {
                int error = Marshal.GetLastWin32Error();
                if (error == 259) yield break;
                if (error == 1460) { heartbeat(); continue; }
                throw new Win32Exception(error);
            }
            if (returned == 0) continue;
            string xml;
            try { xml = Render(handles[0]); }
            finally { EvtClose(handles[0]); handles[0] = IntPtr.Zero; }
            yield return xml;
        }
    }

    public IEnumerable<string> Read(string channel, string xpath, Action heartbeat, CancellationToken ct) => ReadQuery(channel, xpath, false, heartbeat, ct);

    private static long LogValue(EvtHandle log, int property, int type)
    {
        IntPtr buffer = Marshal.AllocHGlobal(16);
        try
        {
            if (!EvtGetLogInfo(log, property, 16, buffer, out _)) throw new Win32Exception(Marshal.GetLastWin32Error());
            if (Marshal.ReadInt32(buffer, 12) != type) throw new InvalidDataException("event_log_state_invalid");
            return Marshal.ReadInt64(buffer);
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    public NpsChannelState Probe(string channel, Action heartbeat, CancellationToken ct)
    {
        string? xml = ReadQuery(channel, "*", true, heartbeat, ct).FirstOrDefault();
        long? latest = xml is null ? null : EventXml.Parse(xml, "", "", channel)["record_id"]?.GetValue<long>();
        using var log = EvtOpenLog(session, channel, 1);
        if (log.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
        var created = DateTimeOffset.FromFileTime(LogValue(log, 0, 17)).ToUniversalTime(); // EvtVarTypeFileTime
        string stamp = Iso8601.Format(created);
        string payload = CanonicalJson.Serialize(new JsonObject { ["channel"] = channel, ["creation_time"] = stamp });
        string generation = "sli.windows-event-channel-generation.v1:" + Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(payload)));
        return new(latest, LogValue(log, 6, 10), generation); // EvtVarTypeUInt64
    }

    public void Dispose() => session.Dispose();
}

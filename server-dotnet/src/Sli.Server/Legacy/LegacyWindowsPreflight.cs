using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json.Nodes;

namespace Sli.Server.Legacy;

public interface ILegacyWindowsContext
{
    string[] IdentityReasons();
    JsonObject Probe(string server);
}

public interface ILegacyEventSession : IDisposable
{
    bool ReadOne(string channel);
}

public sealed class LegacyWindowsContext(LegacySettings settings) : ILegacyWindowsContext
{
    internal static string[] ValidateIdentity(string expectedPrincipal, string expectedSid, string principal, string sid, bool interactive)
    {
        var reasons = new List<string>();
        if (expectedPrincipal.Length == 0) reasons.Add("expected_principal_missing");
        if (expectedSid.Length == 0) reasons.Add("expected_sid_missing");
        if (!interactive) reasons.Add("interactive_session_required");
        if (!principal.Equals(expectedPrincipal, StringComparison.OrdinalIgnoreCase)) reasons.Add("principal_mismatch");
        if (!sid.Equals(expectedSid, StringComparison.OrdinalIgnoreCase)) reasons.Add("sid_mismatch");
        return reasons.ToArray();
    }
    public string[] IdentityReasons()
    {
        if (!OperatingSystem.IsWindows()) return ["windows_required"];
        try {
            using var identity = WindowsIdentity.GetCurrent();
            using var process = Process.GetCurrentProcess();
            return ValidateIdentity((settings.Get("ADLOG_COLLECTION_PRINCIPAL") ?? "").Trim(),
                (settings.Get("ADLOG_COLLECTION_PRINCIPAL_SID") ?? "").Trim(), identity.Name, identity.User?.Value ?? "", process.SessionId != 0);
        }
        catch { return ["identity_probe_failed"]; }
    }
    public JsonObject Probe(string server)
    {
        string mode = settings.Get("ADLOG_AD_SOURCE_CREDENTIAL_MODE") ?? "process";
        if (mode != "process") return new() { ["status"] = "failed", ["failure_code"] = mode == "dpapi_current_user"
            ? "ad_source_backend_unsupported" : "ad_source_credential_mode_invalid" };
        return Probe(server, target => new NativeSession(target));
    }
    internal static JsonObject Probe(string server, Func<string, ILegacyEventSession> open)
    {
        try {
            using var session = open(server);
            bool observed = session.ReadOne("Security");
            return new() { ["status"] = "ok", ["server"] = server, ["channel"] = "Security", ["query_access"] = "verified", ["event_observed"] = observed };
        }
        catch (Exception error) {
            int code = (error is Win32Exception native ? native.NativeErrorCode : error.HResult) & 0xffff;
            return new() { ["status"] = "failed", ["server"] = server, ["channel"] = "Security", ["error_type"] = error.GetType().Name,
                ["winerror"] = code, ["failure_code"] = code == 5 ? "windows_event_log_access_denied" : LegacyCollectionFailurePolicy.Classify([error]).Code };
        }
    }

    private sealed class NativeSession : ILegacyEventSession
    {
        private readonly IntPtr handle;
        public NativeSession(string server)
        {
            if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
            var login = new RpcLogin { Server = server, Flags = 0 }; // EvtRpcLoginAuthDefault, calling process token only.
            handle = EvtOpenSession(1, ref login, 0, 0);
            if (handle == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        public bool ReadOne(string channel)
        {
            IntPtr query = EvtQuery(handle, channel, "*", 0x201); // Channel path, newest first.
            if (query == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            try {
                var events = new IntPtr[1];
                if (!EvtNext(query, 1, events, -1, 0, out int returned)) {
                    int error = Marshal.GetLastWin32Error();
                    if (error == 259) return false; // An empty accessible channel is still verified.
                    throw new Win32Exception(error);
                }
                foreach (IntPtr item in events) if (item != IntPtr.Zero) EvtClose(item);
                return returned != 0;
            }
            finally { EvtClose(query); }
        }
        public void Dispose() => EvtClose(handle);
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct RpcLogin { [MarshalAs(UnmanagedType.LPWStr)] public string Server; public IntPtr User, Domain, Password; public int Flags; }
    [DllImport("wevtapi.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr EvtOpenSession(int loginClass, ref RpcLogin login, int timeout, int flags);
    [DllImport("wevtapi.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr EvtQuery(IntPtr session, string path, string query, int flags);
    [DllImport("wevtapi.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool EvtNext(IntPtr query, int size, [Out] IntPtr[] events, int timeout, int flags, out int returned);
    [DllImport("wevtapi.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool EvtClose(IntPtr handle);
}

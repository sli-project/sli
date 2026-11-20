using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using Sli.Server.Agents.Deployment;

namespace Sli.Server.Agents.Radius;

internal sealed class VpnSourceAuthException(string code) : Exception(code);

internal sealed class VpnSourceCredentials(string username, string password)
{
    internal string Username { get; } = username;
    internal string Password { get; } = password;
    public override string ToString() => nameof(VpnSourceCredentials);
}

internal interface IVpnSourceWindows
{
    // Null means ERROR_NO_TOKEN, never an arbitrary token-query failure.
    IDisposable? OpenThreadToken();
    IDisposable Logon(string user, string? domain, string password, int type, int provider);
    void Impersonate(IDisposable token);
    void Revert();
    void Terminate(int code);
}

internal static class VpnSourceAuth
{
    internal const string ModeEnvironment = "ADLOG_VPN_SOURCE_CREDENTIAL_MODE";
    internal static string ValidateMode(string mode) => mode is "process" or "dpapi_current_user"
        ? mode : throw new VpnSourceAuthException("vpn_source_credential_mode_invalid");

    internal static T Read<T>(string directory, string credentialRoot, System.Text.Json.JsonElement route,
        IReadOnlyDictionary<string, string?> environment, Func<T> read)
    {
        string RequireSource()
        {
            _ = RadiusCollectionRoute.Validate(route, environment);
            string? share = environment.TryGetValue("ADLOG_RADIUS_ACCOUNTING_SHARE_UNC", out var configured)
                ? configured : route.GetProperty("accounting_route").GetProperty("share_unc").GetString();
            if (string.IsNullOrWhiteSpace(share)) throw new VpnSourceAuthException("vpn_source_endpoint_invalid");
            return Sli.Server.Compatibility.PythonText.Strip(share);
        }
        return Read(directory, environment.GetValueOrDefault(ModeEnvironment) ?? "process", RequireSource,
            () => OperatingSystem.IsWindows() ? VpnSourceCredentialStore.Load(credentialRoot)
                : throw new VpnSourceAuthException("vpn_source_windows_required"), read);
    }

    // Synchronous by design: no await or local DB/evidence work while impersonated.
    internal static T Read<T>(string directory, string mode, Func<string> requireSource,
        Func<VpnSourceCredentials> loadCredentials, Func<T> read, IVpnSourceWindows? windows = null)
    {
        if (ValidateMode(mode) == "process") return read();
        try
        {
            if (!StringComparer.OrdinalIgnoreCase.Equals(Path.TrimEndingDirectorySeparator(directory),
                    Path.TrimEndingDirectorySeparator(requireSource())))
                throw new VpnSourceAuthException("vpn_source_endpoint_invalid");
        }
        catch { throw new VpnSourceAuthException("vpn_source_endpoint_invalid"); }
        try
        {
            windows ??= new VpnSourceWindows();
            IDisposable? existing;
            try { existing = windows.OpenThreadToken(); }
            catch { throw new VpnSourceAuthException("vpn_source_thread_identity_unavailable"); }
            if (existing is not null)
            {
                existing.Dispose();
                throw new VpnSourceAuthException("vpn_source_thread_impersonation_forbidden");
            }
            var credentials = loadCredentials();
            AdOperationCredentials.ValidateUsername(credentials.Username);
            string[] parts = credentials.Username.Split('\\', 2);
            using var token = windows.Logon(parts.Length == 2 ? parts[1] : parts[0],
                parts.Length == 2 ? parts[0] : null, credentials.Password, 9, 3);
            try
            {
                windows.Impersonate(token);
                return read();
            }
            finally
            {
                try { windows.Revert(); }
                catch
                {
                    // A child with unknown thread identity must never unwind into local work.
                    windows.Terminate(74);
                    Environment.FailFast("vpn_source_identity_revert_failed");
                }
            }
        }
        catch (VpnSourceAuthException) { throw; }
        catch { throw new VpnSourceAuthException("vpn_source_access_failed"); }
    }
}

internal sealed class VpnSourceWindows : IVpnSourceWindows
{
    internal VpnSourceWindows()
    {
        if (!OperatingSystem.IsWindows()) throw new VpnSourceAuthException("vpn_source_windows_required");
    }
    public IDisposable? OpenThreadToken()
    {
        if (OpenThreadTokenNative(GetCurrentThread(), 8, true, out var token)) return token;
        int error = Marshal.GetLastWin32Error();
        token.Dispose();
        if (error == 1008) return null;
        throw new Win32Exception(error);
    }
    public IDisposable Logon(string user, string? domain, string password, int type, int provider)
    {
        if (!LogonUser(user, domain, password, type, provider, out var token))
        { token.Dispose(); throw new Win32Exception(Marshal.GetLastWin32Error()); }
        return token;
    }
    public void Impersonate(IDisposable token)
    { if (!ImpersonateLoggedOnUser((SafeAccessTokenHandle)token)) throw new Win32Exception(Marshal.GetLastWin32Error()); }
    public void Revert()
    { if (!RevertToSelf()) throw new Win32Exception(Marshal.GetLastWin32Error()); }
    public void Terminate(int code) => Environment.Exit(code);

    [DllImport("kernel32.dll")] private static extern nint GetCurrentThread();
    [DllImport("advapi32.dll", EntryPoint = "OpenThreadToken", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool OpenThreadTokenNative(nint thread, uint access, [MarshalAs(UnmanagedType.Bool)] bool self, out SafeAccessTokenHandle token);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool LogonUser(string user, string? domain, string password, int type, int provider, out SafeAccessTokenHandle token);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool ImpersonateLoggedOnUser(SafeAccessTokenHandle token);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool RevertToSelf();
}

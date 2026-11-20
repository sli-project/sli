using Sli.Server.Compatibility;

namespace Sli.Server.Agents.Radius;

internal static class RadiusChildEnvironment
{
    internal static void ConfigureMode(IDictionary<string, string> child, string component, string purpose, Func<string, string?> get)
    {
        child.Remove(VpnSourceAuth.ModeEnvironment);
        if (component == "radius-acquisition" && purpose == "handler")
            child[VpnSourceAuth.ModeEnvironment] = VpnSourceAuth.ValidateMode(get(VpnSourceAuth.ModeEnvironment) ?? "process");
    }

    internal static void ConfigureWindows(IDictionary<string, string> child, Func<string, string?> get)
    {
        string account = PythonText.Strip(get("ADLOG_COLLECTION_PRINCIPAL") ?? "");
        string sid = PythonText.Strip(get("ADLOG_COLLECTION_PRINCIPAL_SID") ?? "");
        if (account.Length == 0 || sid.Length == 0) throw new InvalidOperationException("plugin_child_identity_missing");
        string root = get("SystemRoot") ?? @"C:\Windows";
        string powershell = Path.GetFullPath(Path.Combine(root, "System32", "WindowsPowerShell", "v1.0"));
        if (!Directory.Exists(powershell)) throw new InvalidOperationException("plugin_child_powershell_missing");
        child["PATH"] = powershell;
        child["SystemRoot"] = root;
        child["WINDIR"] = get("WINDIR") ?? @"C:\Windows";
        child["ADLOG_COLLECTION_PRINCIPAL"] = account;
        child["ADLOG_COLLECTION_PRINCIPAL_SID"] = sid;
        string[] parts = account.Split('\\', 2);
        child["USERDOMAIN"] = parts[0];
        child["USERNAME"] = parts.Length == 2 ? parts[1] : "";
    }
}

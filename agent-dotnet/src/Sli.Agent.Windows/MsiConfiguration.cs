using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using Sli.Agent.Core;

namespace Sli.Agent.Windows;

/// <summary>MSI owns this separate registry key; it never uses the Python agent's state.</summary>
[SupportedOSPlatform("windows")]
public static class MsiConfiguration
{
    public const string RegistryPath = @"SOFTWARE\SLI\AgentNet";
    public static string? ValidateInstanceName(string? value)
    {
        if (string.IsNullOrEmpty(value)) return null; // Optional MSI property.
        if (!Regex.IsMatch(value, @"\A[a-z0-9][a-z0-9_-]{0,47}\z", RegexOptions.CultureInvariant))
            throw new AgentException("invalid_agent_instance_name");
        return value;
    }

    public static Dictionary<string, string?> ReadSettings()
    {
        using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = root.OpenSubKey(RegistryPath);
        var result = new Dictionary<string, string?>();
        foreach (var name in new[] { "ServerUrl", "CaBundle", "CaFingerprint", "CaCertificate", "TokenFile", "InstanceName" })
            if (key?.GetValue(name) is string { Length: > 0 } value)
                result["Agent:" + name] = name == "InstanceName" ? ValidateInstanceName(value) : value;
        if (key?.GetValue("StateDirectory") is string { Length: > 0 } directory) result["Agent:StateDir"] = directory;
        return result;
    }

    public static string? ReadToken()
    {
        using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = root.OpenSubKey(RegistryPath);
        var value = key?.GetValue("EnrollmentToken") as string;
        if (string.IsNullOrEmpty(value)) return null;
        if (value.Length > 8192) throw new AgentException("agent_bootstrap_invalid");
        return value;
    }

    public static void ClearToken()
    {
        using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = root.OpenSubKey(RegistryPath, writable: true);
        key?.DeleteValue("EnrollmentToken", throwOnMissingValue: false);
    }
}

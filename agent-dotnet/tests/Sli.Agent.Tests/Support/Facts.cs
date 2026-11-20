using Xunit;

namespace Sli.Agent.Tests.Support;

/// <summary>Runs only on Windows: real Event Log, DPAPI, ACLs. Elsewhere it is reported as skipped.</summary>
public sealed class WindowsFactAttribute : FactAttribute
{
    public WindowsFactAttribute()
    {
        if (!OperatingSystem.IsWindows()) Skip = "Windows only";
    }
}

/// <summary>Windows and an elevated account: creating an Event Log and reading Security need it. Skipped otherwise.</summary>
public sealed class WindowsAdminFactAttribute : FactAttribute
{
    public WindowsAdminFactAttribute()
    {
        if (!OperatingSystem.IsWindows()) Skip = "Windows only";
        else if (!IsElevated()) Skip = "Needs an elevated (administrator) account";
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static bool IsElevated()
    {
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        return new System.Security.Principal.WindowsPrincipal(identity).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }
}

/// <summary>Runs only when <c>SLI_DOTNET_INTEROP_DIR</c> names a directory: it writes packets for the Python server code to verify.</summary>
public sealed class InteropFactAttribute : FactAttribute
{
    public const string Variable = "SLI_DOTNET_INTEROP_DIR";

    public InteropFactAttribute()
    {
        if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable(Variable))) Skip = "Set " + Variable + " to export interop data";
    }
}

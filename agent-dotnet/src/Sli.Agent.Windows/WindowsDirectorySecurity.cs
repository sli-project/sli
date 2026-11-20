using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Sli.Agent.Core;

namespace Sli.Agent.Windows;

/// <summary>
/// A protected DACL on the state directory: full control only for the identity the service runs as and SYSTEM
/// (and, when the installer owns the directory, Administrators). Inherited entries are removed.
/// A failure is fatal: a key next to an open ACL is not protected.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsDirectorySecurity(bool includeAdministrators = false) : IDirectorySecurity
{
    public void Secure(string directory)
    {
        var info = new DirectoryInfo(directory);
        if (info.LinkTarget is not null) throw new AgentException("agent_state_path_invalid");
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        var owner = WindowsIdentity.GetCurrent().User ?? throw new AgentException("agent_state_acl_failed");
        var principals = new List<SecurityIdentifier> { owner, new(WellKnownSidType.LocalSystemSid, null) };
        if (includeAdministrators) principals.Add(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
        foreach (var sid in principals)
        {
            security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        }
        try
        {
            info.SetAccessControl(security);
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or IOException or InvalidOperationException)
        {
            throw new AgentException("agent_state_acl_failed");
        }
    }
}

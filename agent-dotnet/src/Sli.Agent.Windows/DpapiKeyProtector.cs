using System.Runtime.Versioning;
using System.Security.Cryptography;
using Sli.Agent.Core;

namespace Sli.Agent.Windows;

/// <summary>
/// DPAPI with machine scope, as the Python agent does (<c>sli_agent/protection.py</c>): the service needs no logged-on user,
/// and any local reader of the blob could decrypt it, so the state directory's ACL remains the real barrier.
/// The fixed entropy only separates this blob from other DPAPI users on the machine; it is not a secret.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DpapiKeyProtector : IKeyProtector
{
    private static readonly byte[] Entropy = "SLI agent key v1"u8.ToArray();

    public string Name => "dpapi_local_machine";

    public byte[] Protect(byte[] data) => ProtectedData.Protect(data, Entropy, DataProtectionScope.LocalMachine);

    public byte[] Unprotect(byte[] data) => ProtectedData.Unprotect(data, Entropy, DataProtectionScope.LocalMachine);
}

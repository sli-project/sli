using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Service;
using Sli.Agent.Windows;
using Sli.Agent.Tests.Support;
using Xunit;

namespace Sli.Agent.Tests;

[SupportedOSPlatform("windows")]
public sealed class IdentityPersistenceWindowsTests
{
    [WindowsFact]
    public void MachineDpapiIdentityReloadsWithFreshStoreAndProtector()
    {
        var directory = Helpers.TempDirectory();
        try
        {
            var options = new AgentOptions { StateDir = directory };
            var prepared = AgentRuntime.CreateIdentityStore(options).Prepare();
            var body = JsonNode.Parse(File.ReadAllText(Path.Combine(directory, "identity-key.json")))!;
            var wrapped = Convert.FromBase64String(body["data"]!.GetValue<string>());
            var clear = ProtectedData.Unprotect(wrapped, "SLI agent key v1"u8.ToArray(), DataProtectionScope.LocalMachine);
            try { Assert.NotEmpty(clear); }
            finally { CryptographicOperations.ZeroMemory(clear); }
            using var ca = new TestAuthority();
            using var accepted = AgentRuntime.CreateIdentityStore(options).Accept(ca.Issue(AgentRuntime.CreateIdentityStore(options)), Helpers.Now);
            using var restored = AgentRuntime.CreateIdentityStore(options).Load()!;
            Assert.Equal(accepted.Certificate.Thumbprint, restored.Certificate.Thumbprint);
            Assert.Equal(prepared, AgentRuntime.CreateIdentityStore(options).Prepare());
            Assert.True(restored.Certificate.HasPrivateKey);
        }
        finally { Directory.Delete(directory, true); }
    }
}

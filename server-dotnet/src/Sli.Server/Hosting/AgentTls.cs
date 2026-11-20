using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Server.Kestrel.Https;

namespace Sli.Server.Hosting;

// Listener trust is distinct from the issuance root and its private key.
// Each handshake receives its offline policy before certificate validation.
public sealed class AgentTlsTrust : IDisposable
{
    private readonly X509Certificate2Collection roots = new();

    public AgentTlsTrust(string path)
    {
        try
        {
            roots.ImportFromPem(File.ReadAllText(path));
            if (roots.Count == 0) throw new CryptographicException("Agent listener CA bundle is empty");
        }
        catch { Dispose(); throw; }
    }

    public static bool TryLoad(IConfiguration configuration, out AgentTlsTrust? trust)
    {
        trust = null;
        string? path = configuration["Sli:AgentMtlsCaFile"] ?? Environment.GetEnvironmentVariable("SLI_AGENT_MTLS_CA_FILE");
        if (string.IsNullOrWhiteSpace(path)) return true;
        try { trust = new AgentTlsTrust(path); return true; }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or CryptographicException or ArgumentException or FormatException)
        { return false; }
    }

    public void Configure(HttpsConnectionAdapterOptions https)
    {
        https.ClientCertificateMode = ClientCertificateMode.AllowCertificate;
        https.CheckCertificateRevocation = false;
        https.ClientCertificateValidation = null;
        https.OnAuthenticate = (_, ssl) =>
        {
            var policy = new X509ChainPolicy
            {
                TrustMode = X509ChainTrustMode.CustomRootTrust,
                RevocationMode = X509RevocationMode.NoCheck,
                DisableCertificateDownloads = true
            };
            policy.CustomTrustStore.AddRange(roots);
            policy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.2"));
            ssl.CertificateChainPolicy = policy;
        };
    }

    public void Dispose() { foreach (var root in roots) root.Dispose(); }
}

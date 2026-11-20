using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Server.Kestrel.Https;

namespace Sli.Server.Hosting;

// Listener trust is distinct from the issuance root and its private key.
// Each handshake receives its offline policy before certificate validation.
public sealed class AgentTlsTrust : IDisposable
{
    private readonly X509Certificate2Collection roots = new();
    private readonly X509Certificate2Collection issuers = new();

    public AgentTlsTrust(string path, string? issuerPath = null)
    {
        try
        {
            roots.ImportFromPem(File.ReadAllText(path));
            if (roots.Count == 0) throw new CryptographicException("Agent listener CA bundle is empty");
            if (issuerPath is not null)
            {
                issuers.ImportFromPem(File.ReadAllText(issuerPath));
                if (issuers.Count == 0) throw new CryptographicException("Agent listener issuer bundle is empty");
                using var chain = new X509Chain { ChainPolicy = CreateChainPolicy() };
                foreach (var issuer in issuers)
                {
                    if (issuer.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault()?.CertificateAuthority != true
                        || !chain.Build(issuer) || chain.ChainElements.Count != 2)
                        throw new CryptographicException("Agent listener issuer is not issued by a trusted root");
                }
            }
        }
        catch { Dispose(); throw; }
    }

    public static bool TryLoad(IConfiguration configuration, out AgentTlsTrust? trust)
    {
        trust = null;
        string? path = configuration["Sli:AgentMtlsCaFile"] ?? Environment.GetEnvironmentVariable("SLI_AGENT_MTLS_CA_FILE");
        if (string.IsNullOrWhiteSpace(path)) return true;
        const string issuerSetting = "SLI_AGENT_CA_ISSUER_CERT_FILE";
        string? issuerPath = configuration[issuerSetting] ?? Environment.GetEnvironmentVariable(issuerSetting);
        try
        {
            if (issuerPath is not null) issuerPath = InstalledConfiguration.CredentialPath(configuration, issuerPath, issuerSetting);
            trust = new AgentTlsTrust(path, issuerPath);
            return true;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or CryptographicException or ArgumentException or FormatException or ServerConfigurationException)
        { return false; }
    }

    public void Configure(HttpsConnectionAdapterOptions https)
    {
        https.ClientCertificateMode = ClientCertificateMode.AllowCertificate;
        https.CheckCertificateRevocation = false;
        https.ClientCertificateValidation = null;
        https.OnAuthenticate = (_, ssl) =>
        {
            var policy = CreateChainPolicy();
            policy.ExtraStore.AddRange(issuers);
            ssl.CertificateChainPolicy = policy;
        };
    }

    private X509ChainPolicy CreateChainPolicy()
    {
        var policy = new X509ChainPolicy
        {
            TrustMode = X509ChainTrustMode.CustomRootTrust,
            RevocationMode = X509RevocationMode.NoCheck,
            DisableCertificateDownloads = true
        };
        policy.CustomTrustStore.AddRange(roots);
        policy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.2"));
        return policy;
    }

    public void Dispose()
    {
        foreach (var issuer in issuers) issuer.Dispose();
        foreach (var root in roots) root.Dispose();
    }
}

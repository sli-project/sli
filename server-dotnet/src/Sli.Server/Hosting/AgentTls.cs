using System.Net.Security;
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
                        || !chain.Build(issuer))
                        throw new CryptographicException("Agent listener issuer is not issued by a trusted root");
                    if (chain.ChainElements.Count != 2)
                        throw new CryptographicException("Agent listener issuer chain has an unexpected length");
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

    public void Configure(HttpsConnectionAdapterOptions https, AgentCertificateRejections rejections)
    {
        https.ClientCertificateMode = ClientCertificateMode.AllowCertificate;
        https.CheckCertificateRevocation = false;
        https.ClientCertificateValidation = (certificate, chain, errors) =>
        {
            if (errors == SslPolicyErrors.None) return true;
            rejections.Record(certificate, RejectionReason(certificate, chain, issuers.Count == 0 ? 2 : 3));
            return false;
        };
        https.OnAuthenticate = (_, ssl) =>
        {
            var policy = CreateChainPolicy();
            policy.ExtraStore.AddRange(issuers);
            ssl.CertificateChainPolicy = policy;
        };
    }

    private static string RejectionReason(X509Certificate2 certificate, X509Chain? chain, int expectedLength)
    {
        var flags = X509ChainStatusFlags.NoError;
        foreach (var status in chain?.ChainStatus ?? []) flags |= status.Status;
        if (flags.HasFlag(X509ChainStatusFlags.Revoked)) return "revoked";
        if (flags.HasFlag(X509ChainStatusFlags.NotTimeValid))
        {
            var now = DateTime.UtcNow;
            return certificate.NotAfter.ToUniversalTime() <= now
                || chain!.ChainElements.Cast<X509ChainElement>().Any(element => element.Certificate.NotAfter.ToUniversalTime() <= now)
                ? "expired" : "not_yet_valid";
        }
        if (flags.HasFlag(X509ChainStatusFlags.NotValidForUsage)) return "wrong_eku";
        if (flags.HasFlag(X509ChainStatusFlags.UntrustedRoot)) return "untrusted_root";
        // Classify an already-rejected partial chain. Trusted direct-root leaves remain valid.
        if (flags.HasFlag(X509ChainStatusFlags.PartialChain))
            return chain!.ChainElements.Count < expectedLength ? "unexpected_chain_length" : "untrusted_root";
        return "invalid_chain";
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

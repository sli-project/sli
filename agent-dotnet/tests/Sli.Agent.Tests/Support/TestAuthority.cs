using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Sli.Agent.Core;

namespace Sli.Agent.Tests.Support;

public sealed class TestAuthority : IDisposable
{
    private readonly ECDsa _key = Helpers.NewKey();
    private readonly DateTimeOffset _now;
    public X509Certificate2 Root { get; }
    public TestAuthority(DateTimeOffset? now = null)
    {
        _now = now ?? Helpers.Now;
        var request = new CertificateRequest("CN=Synthetic agent CA", _key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        Root = request.CreateSelfSigned(_now.AddDays(-30), _now.AddDays(90));
    }

    public JsonObject Issue(HostIdentityStore store, string? hostId = null, string agentId = Helpers.AgentId,
        string usage = "1.3.6.1.5.5.7.3.2", bool isCa = false, int days = 30, bool extraSan = false)
    {
        using var key = store.LoadKey();
        var request = new CertificateRequest("CN=" + agentId, key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(isCa, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid(usage)], true));
        var san = new SubjectAlternativeNameBuilder();
        san.AddUri(new Uri("urn:sli:agent:" + agentId));
        san.AddUri(new Uri("urn:sli:host:" + (hostId ?? store.ReadHostId())));
        if (extraSan) san.AddDnsName("extra.example.test");
        request.CertificateExtensions.Add(san.Build());
        using var certificate = request.Create(Root, _now.AddHours(-1), _now.AddDays(days), [1,2,3,4]);
        return new JsonObject { ["agent_id"] = agentId, ["certificate_pem"] = certificate.ExportCertificatePem(), ["ca_chain_pem"] = Root.ExportCertificatePem() };
    }

    public void Dispose() { Root.Dispose(); _key.Dispose(); }
}

public sealed class TestClock : TimeProvider
{
    public DateTimeOffset Now { get; set; } = Helpers.Now;
    public override DateTimeOffset GetUtcNow() => Now;
}

using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Sli.Agent.Core;
using Xunit;

namespace Sli.Agent.Tests;

public sealed class ServerTrustTests
{
    [Fact]
    public void Embedded_root_must_match_the_pin_and_validate_the_named_server()
    {
        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var wrongKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var serverKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var root = Root("CN=Install CA", rootKey);
        using var wrong = Root("CN=Other CA", wrongKey);
        var request = new CertificateRequest("CN=agents.example.test", serverKey, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, false));
        using var server = request.Create(root, DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddHours(1), RandomNumberGenerator.GetBytes(16));
        using var otherServer = request.Create(wrong, DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddHours(1), RandomNumberGenerator.GetBytes(16));
        var embedded = new X509Certificate2Collection(root);
        var pin = Convert.ToHexStringLower(SHA256.HashData(root.RawData));
        var wrongPin = Convert.ToHexStringLower(SHA256.HashData(wrong.RawData));
        Assert.True(ServerTrust.IsPinned(server, null, SslPolicyErrors.RemoteCertificateChainErrors, pin, embedded));
        Assert.False(ServerTrust.IsPinned(server, null, SslPolicyErrors.None, wrongPin, embedded));
        Assert.False(ServerTrust.IsPinned(otherServer, null, SslPolicyErrors.None, pin, embedded));
        Assert.False(ServerTrust.IsPinned(server, null, SslPolicyErrors.RemoteCertificateNameMismatch, pin, embedded));
    }

    private static X509Certificate2 Root(string name, ECDsa key)
    {
        var request = new CertificateRequest(name, key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }
}

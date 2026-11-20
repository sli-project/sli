using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Sli.Server.Agents.Certificates;
using Sli.Server.Agents.Registry;
using Xunit;

namespace Sli.Server.Tests.Agents;

[CollectionDefinition("Agent CA environment", DisableParallelization = true)]
public class AgentCaEnvironmentCollection;

[Collection("Agent CA environment")]
public class AgentCaFixRoundTests
{
    [Fact]
    public void Group_directory_dn_accepts_2048_codepoints_and_rejects_2049()
    {
        var valid = "CN=" + string.Concat(Enumerable.Repeat("\U00010400", 2040)) + ",OU=x";
        Assert.Equal(2048, valid.EnumerateRunes().Count());
        Assert.True(valid.Length > 2048);
        var parts = AgentEnrollmentService.ParseDirectoryDn(valid, false);
        Assert.Equal("ou=x", parts[^1]);
        var tooLong = "CN=" + string.Concat(Enumerable.Repeat("\U00010400", 2041)) + ",OU=x";
        Assert.Equal(2049, tooLong.EnumerateRunes().Count());
        Assert.Throws<FormatException>(() => AgentEnrollmentService.ParseDirectoryDn(tooLong, false));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Issued_aki_is_derived_from_issuer_public_key_not_issuer_ski(bool customSki)
    {
        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var root = CaRequest("CN=Root", rootKey, 1).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(2));
        using var issuerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var issuerRequest = CaRequest("CN=Issuer", issuerKey, 0);
        if (customSki) issuerRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension("0102030405060708090A0B0C0D0E0F1011121314", false));
        using var issuerPublic = issuerRequest.Create(root, DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddYears(1), RandomNumberGenerator.GetBytes(16));
        using var issuer = issuerPublic.CopyWithPrivateKey(issuerKey);
        using var agentKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var host = Guid.NewGuid();
        var request = new CertificateRequest($"CN={host}", agentKey, HashAlgorithmName.SHA256);
        using var leaf = new AgentIssuingCa(root, issuer).Issue(AgentCertificateAuthority.ParseCsr(request.CreateSigningRequestPem(), host), Guid.NewGuid(), host);
        var aki = leaf.Extensions.OfType<X509AuthorityKeyIdentifierExtension>().Single();
        var expected = SHA1.HashData(issuer.PublicKey.EncodedKeyValue.RawData);
        Assert.False(aki.Critical);
        Assert.NotNull(aki.KeyIdentifier);
        Assert.Equal(expected, aki.KeyIdentifier!.Value.ToArray());
        var fixturePath = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "Agents", "fixtures", "pss-root-public.cer"));
        using var sourceFixture = X509CertificateLoader.LoadCertificateFromFile(fixturePath);
        Assert.Equal("aa62548d52357e3071e85a0864f243b533e994b0", Convert.ToHexStringLower(SHA1.HashData(sourceFixture.PublicKey.EncodedKeyValue.RawData)));
        if (customSki) Assert.NotEqual(issuer.Extensions.OfType<X509SubjectKeyIdentifierExtension>().Single().SubjectKeyIdentifierBytes.ToArray(), aki.KeyIdentifier.Value.ToArray());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Environment_loader_accepts_public_root_only_and_separate_issuer_key(bool pkcs8)
    {
        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var root = CaRequest("CN=Root", rootKey, 1).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(2));
        using var issuerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var issuerPublic = CaRequest("CN=Issuer", issuerKey, 0).Create(root, DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddYears(1), RandomNumberGenerator.GetBytes(16));
        var folder = Path.Combine(Path.GetTempPath(), "sli-ca-r1-" + Guid.NewGuid().ToString("N"));
        var rootPath = Path.Combine(folder, "root-cert.pem");
        var issuerPath = Path.Combine(folder, "issuer-cert.pem");
        var keyPath = Path.Combine(folder, "issuer-synthetic-key.pem");
        var names = new[] { "SLI_AGENT_CA_ROOT_CERT_FILE", "SLI_AGENT_CA_ISSUER_CERT_FILE", "SLI_AGENT_CA_ISSUER_KEY_FILE", "SLI_AGENT_CERT_DAYS" };
        var previous = names.Select(Environment.GetEnvironmentVariable).ToArray();
        Directory.CreateDirectory(folder);
        try
        {
            File.WriteAllText(rootPath, root.ExportCertificatePem());
            Assert.DoesNotContain("PRIVATE KEY", File.ReadAllText(rootPath));
            File.WriteAllText(issuerPath, issuerPublic.ExportCertificatePem());
            File.WriteAllText(keyPath, pkcs8 ? issuerKey.ExportPkcs8PrivateKeyPem() : issuerKey.ExportECPrivateKeyPem());
            Environment.SetEnvironmentVariable(names[0], rootPath);
            Environment.SetEnvironmentVariable(names[1], issuerPath);
            Environment.SetEnvironmentVariable(names[2], keyPath);
            Environment.SetEnvironmentVariable(names[3], "30");

            using var ca = AgentIssuingCa.FromEnvironment();
            using var clientKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var host = Guid.NewGuid();
            var csr = new CertificateRequest($"CN={host}", clientKey, HashAlgorithmName.SHA256);
            using var cert = ca.Issue(AgentCertificateAuthority.ParseCsr(csr.CreateSigningRequestPem(), host), Guid.NewGuid(), host);
            ca.VerifyClient(cert);
        }
        finally
        {
            for (var i = 0; i < names.Length; i++) Environment.SetEnvironmentVariable(names[i], previous[i]);
            File.Delete(keyPath); File.Delete(issuerPath); File.Delete(rootPath); Directory.Delete(folder);
        }
    }

    private static CertificateRequest CaRequest(string name, ECDsa key, int pathLength)
    {
        var request = new CertificateRequest(name, key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, pathLength, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") }, false));
        return request;
    }
}

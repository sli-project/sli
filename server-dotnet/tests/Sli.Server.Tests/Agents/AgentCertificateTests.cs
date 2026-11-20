using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Sli.Server.Agents.Certificates;
using Xunit;

namespace Sli.Server.Tests.Agents;

public class AgentCertificateTests
{
    [Fact]
    public void Csr_with_matching_host_and_supported_key_is_accepted()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var host = Guid.NewGuid();
        var csr = new CertificateRequest($"CN={host}", key, HashAlgorithmName.SHA256);
        var parsed = AgentCertificateAuthority.ParseCsr(csr.CreateSigningRequestPem(), host);
        Assert.NotNull(parsed);
    }

    [Fact]
    public void Csr_extensions_and_wrong_subject_are_rejected()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var host = Guid.NewGuid();
        var csr = new CertificateRequest($"CN={host}", key, HashAlgorithmName.SHA256);
        csr.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        Assert.Throws<AgentCertificateException>(() => AgentCertificateAuthority.ParseCsr(csr.CreateSigningRequestPem(), host));
        var wrong = new CertificateRequest($"CN={Guid.NewGuid()}", key, HashAlgorithmName.SHA256);
        Assert.Throws<AgentCertificateException>(() => AgentCertificateAuthority.ParseCsr(wrong.CreateSigningRequestPem(), host));
    }

    [Fact]
    public void Issued_certificate_has_fixed_profile_and_expected_chain()
    {
        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var rootReq = CaRequest("CN=Root", rootKey, 1);
        using var root = rootReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(2));
        using var issuerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var issuerReq = CaRequest("CN=Issuer", issuerKey, 0);
        using var issuerPublic = issuerReq.Create(root, DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddYears(1), RandomNumberGenerator.GetBytes(16));
        using var issuer = issuerPublic.CopyWithPrivateKey(issuerKey);
        using var clientKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var host = Guid.NewGuid();
        var agent = Guid.NewGuid();
        var csr = new CertificateRequest($"CN={host}", clientKey, HashAlgorithmName.SHA256);
        var ca = new AgentIssuingCa(root, issuer, 30);
        using var cert = ca.Issue(AgentCertificateAuthority.ParseCsr(csr.CreateSigningRequestPem(), host), agent, host);
        Assert.Equal($"CN={agent}", cert.Subject);
        var san = new AsnReader(cert.Extensions.OfType<X509SubjectAlternativeNameExtension>().Single().RawData, AsnEncodingRules.DER).ReadSequence();
        var tag = new Asn1Tag(TagClass.ContextSpecific, 6);
        Assert.Equal($"urn:sli:agent:{agent}", san.ReadCharacterString(UniversalTagNumber.IA5String, tag));
        Assert.Equal($"urn:sli:host:{host}", san.ReadCharacterString(UniversalTagNumber.IA5String, tag));
        Assert.False(san.HasData);
        Assert.False(cert.Extensions.OfType<X509BasicConstraintsExtension>().Single().CertificateAuthority);
        Assert.Equal(X509KeyUsageFlags.DigitalSignature, cert.Extensions.OfType<X509KeyUsageExtension>().Single().KeyUsages);
        Assert.Equal("1.3.6.1.5.5.7.3.2", cert.Extensions.OfType<X509EnhancedKeyUsageExtension>().Single().EnhancedKeyUsages[0]!.Value);
        ca.VerifyClient(cert);
    }

    [Fact]
    public void Malformed_csr_and_unsupported_key_are_safe_errors()
    {
        var error = Assert.Throws<AgentCertificateException>(() => AgentCertificateAuthority.ParseCsr("secret invalid csr", Guid.NewGuid()));
        Assert.Equal("invalid_agent_csr", error.Code);
        Assert.DoesNotContain("secret", error.Message);
        using var key = RSA.Create(1024);
        var host = Guid.NewGuid();
        var request = new CertificateRequest($"CN={host}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        Assert.Equal("unsupported_agent_key", Assert.Throws<AgentCertificateException>(() => AgentCertificateAuthority.ParseCsr(request.CreateSigningRequestPem(), host)).Code);
        var corrupt = request.CreateSigningRequest(); corrupt[^1] ^= 1;
        Assert.Equal("unsupported_agent_key", Assert.Throws<AgentCertificateException>(() => AgentCertificateAuthority.ParseCsr(PemEncoding.WriteString("CERTIFICATE REQUEST", corrupt), host)).Code);

    }

    [Fact]
    public void Rsa_csr_signature_is_checked()
    {
        using var key = RSA.Create(2048);
        var host = Guid.NewGuid();
        var request = new CertificateRequest($"CN={host}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var der = request.CreateSigningRequest();
        der[^1] ^= 1;
        var corrupt = PemEncoding.WriteString("CERTIFICATE REQUEST", der);
        Assert.Equal("invalid_agent_csr_signature", Assert.Throws<AgentCertificateException>(() => AgentCertificateAuthority.ParseCsr(corrupt, host)).Code);
        Assert.NotNull(AgentCertificateAuthority.ParseCsr(request.CreateSigningRequestPem(), host));
    }
    [Fact]
    public void Rsa_pss_csr_with_sha256_is_accepted()
    {
        using var key = RSA.Create(2048);
        var host = Guid.NewGuid();
        var request = new CertificateRequest($"CN={host}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        Assert.NotNull(AgentCertificateAuthority.ParseCsr(request.CreateSigningRequestPem(), host));
    }
    [Fact]
    public void Rsa_ca_can_issue_for_ec_agent()
    {
        using var rootKey = RSA.Create(3072);
        var rootRequest = RsaCaRequest("CN=RSA Root", rootKey, 1);
        using var root = rootRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(2));
        using var issuerKey = RSA.Create(3072);
        var issuerRequest = RsaCaRequest("CN=RSA Issuer", issuerKey, 0);
        using var issuerPublic = issuerRequest.Create(root, DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddYears(1), RandomNumberGenerator.GetBytes(16));
        using var issuer = issuerPublic.CopyWithPrivateKey(issuerKey);
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var host = Guid.NewGuid();
        var request = new CertificateRequest($"CN={host}", key, HashAlgorithmName.SHA256);
        var ca = new AgentIssuingCa(root, issuer);
        using var cert = ca.Issue(AgentCertificateAuthority.ParseCsr(request.CreateSigningRequestPem(), host), Guid.NewGuid(), host);
        ca.VerifyClient(cert);
    }
    [Fact]
    public void Rsa_pss_signed_ca_chain_is_accepted()
    {
        using var rootKey = RSA.Create(3072);
        var rootRequest = RsaCaRequest("CN=PSS Root", rootKey, 1, RSASignaturePadding.Pss);
        using var root = rootRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(2));
        using var issuerKey = RSA.Create(3072);
        var issuerRequest = RsaCaRequest("CN=PSS Issuer", issuerKey, 0, RSASignaturePadding.Pss);
        using var publicCert = issuerRequest.Create(root, DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddYears(1), RandomNumberGenerator.GetBytes(16));
        using var issuer = publicCert.CopyWithPrivateKey(issuerKey);
        var ca = new AgentIssuingCa(root, issuer);
        ca.Validate();
    }
    private static CertificateRequest RsaCaRequest(string name, RSA key, int pathLength, RSASignaturePadding? padding = null)
    {
        var request = new CertificateRequest(name, key, HashAlgorithmName.SHA256, padding ?? RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, pathLength, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") }, false));
        return request;
    }
    [Fact]
    public void Source_accepted_pss_max_salt_certificates_and_csr_verify_offline()
    {
        var path = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "Agents", "fixtures"));
        using var root = X509CertificateLoader.LoadCertificateFromFile(Path.Combine(path, "pss-root-public.cer"));
        using var forged = X509CertificateLoader.LoadCertificateFromFile(Path.Combine(path, "pss-forged-root-public.cer"));
        using var issuer = X509CertificateLoader.LoadCertificateFromFile(Path.Combine(path, "pss-issuer-public.cer"));
        using var alternateName = X509CertificateLoader.LoadCertificateFromFile(Path.Combine(path, "pss-alt-issuer-public.cer"));
        Assert.ThrowsAny<Exception>(() => AgentSignatureVerifier.VerifyCertificate(alternateName, root));
        using var differentName = X509CertificateLoader.LoadCertificateFromFile(Path.Combine(path, "pss-case-issuer-public.cer"));
        Assert.ThrowsAny<Exception>(() => AgentSignatureVerifier.VerifyCertificate(differentName, root));
        AgentSignatureVerifier.VerifyCertificate(root, root);
        AgentSignatureVerifier.VerifyCertificate(issuer, root);
        Assert.ThrowsAny<Exception>(() => AgentSignatureVerifier.VerifyCertificate(forged, forged));
        var csr = File.ReadAllBytes(Path.Combine(path, "pss-max-public.csr"));
        var pem = PemEncoding.WriteString("CERTIFICATE REQUEST", csr);
        Assert.NotNull(AgentCertificateAuthority.ParseCsr(pem, Guid.Parse("ef56c9d2-8d16-4b13-8262-541b66c07556")));
        csr[^1] ^= 1;
        var rejected = Assert.Throws<AgentCertificateException>(() => AgentCertificateAuthority.ParseCsr(PemEncoding.WriteString("CERTIFICATE REQUEST", csr), Guid.Parse("ef56c9d2-8d16-4b13-8262-541b66c07556")));
        Assert.Equal("invalid_agent_csr_signature", rejected.Code);
    }
    [Fact]
    public void Source_accepted_pss_mixed_mgf_and_short_salt_verify_offline()
    {
        var path = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "Agents", "fixtures"));
        using var root = X509CertificateLoader.LoadCertificateFromFile(Path.Combine(path, "pss-mixed-root-public.cer"));
        using var issuer = X509CertificateLoader.LoadCertificateFromFile(Path.Combine(path, "pss-mixed-issuer-public.cer"));
        using var alternateName = X509CertificateLoader.LoadCertificateFromFile(Path.Combine(path, "pss-alt-issuer-public.cer"));
        Assert.ThrowsAny<Exception>(() => AgentSignatureVerifier.VerifyCertificate(alternateName, root));
        using var differentName = X509CertificateLoader.LoadCertificateFromFile(Path.Combine(path, "pss-case-issuer-public.cer"));
        Assert.ThrowsAny<Exception>(() => AgentSignatureVerifier.VerifyCertificate(differentName, root));
        AgentSignatureVerifier.VerifyCertificate(root, root);
        AgentSignatureVerifier.VerifyCertificate(issuer, root);
        var csr = File.ReadAllBytes(Path.Combine(path, "pss-mixed-public.csr"));
        Assert.NotNull(AgentCertificateAuthority.ParseCsr(PemEncoding.WriteString("CERTIFICATE REQUEST", csr), Guid.Parse("ef56c9d2-8d16-4b13-8262-541b66c07556")));
    }
    [Fact]
    public void Expired_client_and_ca_with_wrong_constraints_are_rejected_safely()
    {
        using var rootKey=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var root=CaRequest("CN=Root",rootKey,1).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-3),DateTimeOffset.UtcNow.AddYears(1));
        using var issuerKey=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var issuerPublic=CaRequest("CN=Issuer",issuerKey,0).Create(root,DateTimeOffset.UtcNow.AddDays(-2),DateTimeOffset.UtcNow.AddMonths(6),RandomNumberGenerator.GetBytes(16));
        using var issuer=issuerPublic.CopyWithPrivateKey(issuerKey);
        var ca=new AgentIssuingCa(root,issuer);
        using var clientKey=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var client=new CertificateRequest("CN=expired",clientKey,HashAlgorithmName.SHA256);
        client.CertificateExtensions.Add(new X509BasicConstraintsExtension(false,false,0,true));
        client.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature,true));
        client.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection {new Oid("1.3.6.1.5.5.7.3.2")},true));
        using var expired=client.Create(issuer,DateTimeOffset.UtcNow.AddHours(-2),DateTimeOffset.UtcNow.AddHours(-1),RandomNumberGenerator.GetBytes(16));
        var error=Assert.Throws<AgentCertificateException>(()=>ca.VerifyClient(expired));
        Assert.Equal("agent_certificate_rejected",error.Code); Assert.Equal(401,error.Status);
        using var badKey=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var badRoot=CaRequest("CN=Bad Root",badKey,0).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),DateTimeOffset.UtcNow.AddYears(1));
        Assert.Equal("agent_ca_unavailable",Assert.Throws<AgentCertificateException>(()=>new AgentIssuingCa(badRoot,issuer)).Code);
    }
    private static CertificateRequest CaRequest(string name, ECDsa key, int pathLength)
    {
        var request = new CertificateRequest(name, key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, pathLength, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        var usages = new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") };
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(usages, false));
        return request;
    }

}

using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Sli.Server.Agents.Certificates;

public sealed class AgentCertificateException(string code, int status = 400) : Exception(code)
{
    public string Code { get; } = code;
    public int Status { get; } = status;
}

public static class AgentCertificateAuthority
{
    public static CertificateRequest ParseCsr(string? pem, Guid hostId)
    {
        if (pem is null || pem.Length is < 1 or > 16384 || pem.Any(c => c > 127))
            throw new AgentCertificateException("invalid_agent_csr");
        try
        {
            var der = PemEncoding.TryFind(pem, out var fields) && pem[fields.Label] == "CERTIFICATE REQUEST"
                ? Convert.FromBase64String(pem[fields.Base64Data]) : throw new CryptographicException();
            AgentSignatureVerifier.VerifyCsr(der);
            // BCL only parses after BC has verified the original request signature.
            var request = CertificateRequest.LoadSigningRequest(der, HashAlgorithmName.SHA256,
                CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions | CertificateRequestLoadOptions.SkipSignatureValidation);
            var name = new AsnReader(request.SubjectName.RawData, AsnEncodingRules.DER).ReadSequence();
            var rdn = name.ReadSetOf();
            var attribute = rdn.ReadSequence();
            if (attribute.ReadObjectIdentifier() != "2.5.4.3") throw new AgentCertificateException("agent_csr_subject_mismatch");
            var tag = attribute.PeekTag();
            var value = attribute.ReadCharacterString((UniversalTagNumber)tag.TagValue);
            if (attribute.HasData || rdn.HasData || name.HasData || value != hostId.ToString())
                throw new AgentCertificateException("agent_csr_subject_mismatch");
            if (request.CertificateExtensions.Count != 0) throw new AgentCertificateException("agent_csr_extensions_forbidden");
            return request;
        }
        catch (AgentCertificateException) { throw; }
        catch (Exception ex) when (ex is CryptographicException or AsnContentException or FormatException or ArgumentException or InvalidOperationException)
        { throw new AgentCertificateException("invalid_agent_csr"); }
    }

    public static void ValidateKey(PublicKey key, bool ca)
    {
        using var rsa = key.GetRSAPublicKey();
        if (rsa is not null)
        {
            var p = rsa.ExportParameters(false);
            if (rsa.KeySize >= (ca ? 3072 : 2048) && rsa.KeySize <= 8192 && p.Exponent!.SequenceEqual(new byte[] { 1, 0, 1 })) return;
        }
        using var ec = key.GetECDsaPublicKey();
        if (ec is not null)
        {
            var oid = ec.ExportParameters(false).Curve.Oid.Value;
            if (oid is "1.2.840.10045.3.1.7" or "1.3.132.0.34") return;
        }
        throw new AgentCertificateException("unsupported_agent_key");
    }
}

public sealed class AgentIssuingCa : IDisposable
{
    private readonly X509Certificate2 root;
    private readonly X509Certificate2 issuer;
    private readonly int days;
    public void Dispose() { root.Dispose(); issuer.Dispose(); }
    public AgentIssuingCa(X509Certificate2 root, X509Certificate2 issuer, int days = 30)
    {
        this.root = root;
        this.issuer = issuer;
        this.days = days;
        Validate();
    }
    public static AgentIssuingCa FromEnvironment()
    {
        try
        {
            var rootPath = Environment.GetEnvironmentVariable("SLI_AGENT_CA_ROOT_CERT_FILE") ?? throw new CryptographicException();
            var issuerPath = Environment.GetEnvironmentVariable("SLI_AGENT_CA_ISSUER_CERT_FILE") ?? throw new CryptographicException();
            var keyPath = Environment.GetEnvironmentVariable("SLI_AGENT_CA_ISSUER_KEY_FILE") ?? throw new CryptographicException();
            var daysText = Environment.GetEnvironmentVariable("SLI_AGENT_CERT_DAYS");
            var days = daysText is null ? 30 : int.Parse(daysText, System.Globalization.CultureInfo.InvariantCulture);
            var root = X509Certificate2.CreateFromPem(File.ReadAllText(rootPath));
            try
            {
                var issuer = X509Certificate2.CreateFromPemFile(issuerPath, keyPath);
                try { return new AgentIssuingCa(root, issuer, days); }
                catch { issuer.Dispose(); throw; }
            }
            catch { root.Dispose(); throw; }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException or FormatException or OverflowException or ArgumentException or AgentCertificateException)
        { throw new AgentCertificateException("agent_ca_unavailable", 503); }
    }
    public void Validate()
    {
        try
        {
            if (days is < 1 or > 90 || !issuer.HasPrivateKey) throw new CryptographicException();
            ValidateCa(root, true);
            ValidateCa(issuer, false);
            AgentSignatureVerifier.VerifyCertificate(root, root);
            AgentSignatureVerifier.VerifyCertificate(issuer, root);
            using var rsa = issuer.GetRSAPrivateKey();
            using var ec = issuer.GetECDsaPrivateKey();
            var privateSpki = rsa is not null ? rsa.ExportSubjectPublicKeyInfo() : ec?.ExportSubjectPublicKeyInfo();
            if (privateSpki is null || !privateSpki.AsSpan().SequenceEqual(issuer.PublicKey.ExportSubjectPublicKeyInfo())) throw new CryptographicException();
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        { throw new AgentCertificateException("agent_ca_unavailable", 503); }
    }
    private static void ValidateCa(X509Certificate2 cert, bool root)
    {
        AgentCertificateAuthority.ValidateKey(cert.PublicKey, true);
        var bc = cert.Extensions.OfType<X509BasicConstraintsExtension>().Single();
        var ku = cert.Extensions.OfType<X509KeyUsageExtension>().Single();
        var eku = cert.Extensions.OfType<X509EnhancedKeyUsageExtension>().Single();
        var now = DateTime.UtcNow;
        if (!AgentSignatureVerifier.HasAllowedCaSignatureHash(cert) || !bc.CertificateAuthority || (!root && (!bc.HasPathLengthConstraint || bc.PathLengthConstraint != 0)) ||
            (root && bc.HasPathLengthConstraint && bc.PathLengthConstraint < 1) ||
            (ku.KeyUsages & (X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign)) != (X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign) ||
            eku.EnhancedKeyUsages.Count != 1 || eku.EnhancedKeyUsages[0]!.Value != "1.3.6.1.5.5.7.3.2" ||
            now < cert.NotBefore.ToUniversalTime() || now >= cert.NotAfter.ToUniversalTime()) throw new CryptographicException();
    }
    public X509Certificate2 Issue(CertificateRequest csr, Guid agentId, Guid hostId)
    {
        Validate();
        var now = DateTimeOffset.UtcNow;
        var end = new[] { now.AddDays(days), new DateTimeOffset(issuer.NotAfter.ToUniversalTime()), new DateTimeOffset(root.NotAfter.ToUniversalTime()) }.Min();
        if (end <= now.AddHours(1)) throw new AgentCertificateException("agent_ca_unavailable", 503);
        var request = new CertificateRequest(new X500DistinguishedName($"CN={agentId}"), csr.PublicKey, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") }, true));
        var san = new SubjectAlternativeNameBuilder();
        san.AddUri(new Uri($"urn:sli:agent:{agentId}"));
        san.AddUri(new Uri($"urn:sli:host:{hostId}"));
        request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(new X509SubjectKeyIdentifierExtension(issuer.PublicKey, false)));
        var serial = RandomNumberGenerator.GetBytes(20);
        serial[0] &= 0x7f;
        using var rsa = issuer.GetRSAPrivateKey();
        using var ec = issuer.GetECDsaPrivateKey();
        var generator = rsa is not null ? X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pkcs1)
            : ec is not null ? X509SignatureGenerator.CreateForECDsa(ec)
            : throw new AgentCertificateException("agent_ca_unavailable", 503);
        return request.Create(issuer.SubjectName, generator, now.AddMinutes(-1), end, serial);
    }
    public void VerifyClient(X509Certificate2 cert)
    {
        try
        {
            Validate();
            AgentSignatureVerifier.VerifyCertificate(cert, issuer);
            AgentCertificateAuthority.ValidateKey(cert.PublicKey, false);
            var now = DateTime.UtcNow;
            if (now < cert.NotBefore.ToUniversalTime() || now >= cert.NotAfter.ToUniversalTime() ||
                cert.Extensions.OfType<X509BasicConstraintsExtension>().Single().CertificateAuthority ||
                (cert.Extensions.OfType<X509KeyUsageExtension>().Single().KeyUsages & X509KeyUsageFlags.DigitalSignature) == 0) throw new CryptographicException();
            var eku = cert.Extensions.OfType<X509EnhancedKeyUsageExtension>().Single().EnhancedKeyUsages;
            if (eku.Count != 1 || eku[0]!.Value != "1.3.6.1.5.5.7.3.2") throw new CryptographicException();
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        { throw new AgentCertificateException("agent_certificate_rejected", 401); }
    }
    public string RootFingerprint => Convert.ToHexStringLower(SHA256.HashData(root.RawData));
    public string ChainPem() => issuer.ExportCertificatePem() + "\n" + root.ExportCertificatePem() + "\n";
}

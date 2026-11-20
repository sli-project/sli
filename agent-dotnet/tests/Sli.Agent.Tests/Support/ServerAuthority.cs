using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Sli.Agent.Core;

namespace Sli.Agent.Tests.Support;

/// <summary>Repeats ca.py/provision.py: UTF8String CNs, P-384 CAs, SHA-256, issuer then root.</summary>
internal sealed class ServerAuthority : IDisposable
{
    private readonly ECDsa _rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP384);
    private readonly ECDsa _issuerKey = ECDsa.Create(ECCurve.NamedCurves.nistP384);
    public X509Certificate2 Root { get; }
    private readonly X509Certificate2 _issuer;

    public ServerAuthority(string defect = "")
    {
        var root = CaRequest("SLI Agent Root CA", _rootKey, 1);
        Root = root.CreateSelfSigned(Helpers.Now.AddMinutes(-1), Helpers.Now.AddDays(3650));
        var issuer = CaRequest("SLI Agent Issuing CA", _issuerKey, 0, Root, defect);
        using var issued = issuer.Create(Root, Helpers.Now.AddMinutes(-1), Helpers.Now.AddDays(365), [2]);
        _issuer = issued.CopyWithPrivateKey(_issuerKey);
    }

    private static X500DistinguishedName Name(string commonName)
    {
        var builder = new X500DistinguishedNameBuilder();
        builder.Add("2.5.4.3", commonName, UniversalTagNumber.UTF8String);
        return builder.Build();
    }

    private static X509Extension AuthorityKey(PublicKey key)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        writer.WriteOctetString(Convert.FromHexString(new X509SubjectKeyIdentifierExtension(key, false).SubjectKeyIdentifier!),
            new Asn1Tag(TagClass.ContextSpecific, 0));
        writer.PopSequence();
        return new X509Extension("2.5.29.35", writer.Encode(), false);
    }

    private static CertificateRequest CaRequest(string name, ECDsa key, int pathLength, X509Certificate2? parent = null, string defect = "")
    {
        var request = new CertificateRequest(Name(name), key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(defect != "issuer_ca", true, pathLength, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid(defect == "chain_build" ? "1.3.6.1.5.5.7.3.1" : "1.3.6.1.5.5.7.3.2")], false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        request.CertificateExtensions.Add(AuthorityKey(parent?.PublicKey ?? request.PublicKey));
        return request;
    }

    public JsonObject Issue(HostIdentityStore store, string defect = "")
    {
        using var key = store.LoadKey();
        var name = defect switch
        {
            "subject" => Name(Helpers.HostId),
            "extra_subject" => new X500DistinguishedName("CN=" + Helpers.AgentId + ", O=unexpected"),
            "duplicate_subject" => new X500DistinguishedName("CN=" + Helpers.AgentId + ", CN=" + Helpers.AgentId),
            _ => Name(Helpers.AgentId),
        };
        var request = new CertificateRequest(name, key, HashAlgorithmName.SHA256);
        if (defect != "missing_ca") request.CertificateExtensions.Add(new X509BasicConstraintsExtension(defect == "ca", false, 0, true));
        if (defect != "missing_key_usage") request.CertificateExtensions.Add(new X509KeyUsageExtension(
            defect == "key_usage" ? X509KeyUsageFlags.KeyAgreement : X509KeyUsageFlags.DigitalSignature, true));
        if (defect != "missing_eku") request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.2")], true));
        var san = new SubjectAlternativeNameBuilder();
        var agent = new Uri("urn:sli:agent:" + Helpers.AgentId);
        var host = new Uri("urn:sli:host:" + store.ReadHostId());
        san.AddUri(defect == "reversed_san" ? host : agent);
        san.AddUri(defect == "reversed_san" ? agent : host);
        if (defect == "extra_san") san.AddDnsName("unexpected.example.test");
        if (defect != "missing_san") request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        request.CertificateExtensions.Add(AuthorityKey(_issuer.PublicKey));
        // The signer overload permits malformed issuer constraints for the rejection test.
        using var leaf = request.Create(_issuer.SubjectName, X509SignatureGenerator.CreateForECDsa(_issuerKey),
            defect == "future" ? Helpers.Now.AddMinutes(1) : Helpers.Now.AddMinutes(-1), Helpers.Now.AddDays(30), [3]);
        var pem = leaf.ExportCertificatePem();
        if (defect == "signature")
        {
            var raw = leaf.RawData;
            raw[^1] ^= 1;
            pem = PemEncoding.WriteString("CERTIFICATE", raw);
        }
        return new JsonObject
        {
            ["agent_id"] = Helpers.AgentId, ["certificate_pem"] = pem,
            ["ca_chain_pem"] = defect switch
            {
                "empty_chain" => "",
                "long_chain" => string.Concat(Enumerable.Repeat(Root.ExportCertificatePem() + "\n", 5)),
                "reversed_chain" => Root.ExportCertificatePem() + "\n" + _issuer.ExportCertificatePem() + "\n",
                _ => _issuer.ExportCertificatePem() + "\n" + Root.ExportCertificatePem() + "\n",
            },
        };
    }

    public void Dispose() { _issuer.Dispose(); Root.Dispose(); _issuerKey.Dispose(); _rootKey.Dispose(); }
}

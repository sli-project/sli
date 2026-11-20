using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;

namespace Sli.Server.Agents.Certificates;

// Only public certificate/CSR signature checks; all signing and private-key operations stay in BCL.
public static class AgentSignatureVerifier
{
    public static bool HasAllowedCaSignatureHash(X509Certificate2 certificate)
    {
        var algorithm = new X509CertificateParser().ReadCertificate(certificate.RawData).CertificateStructure.SignatureAlgorithm;
        var oid = algorithm.Algorithm.Id;
        if (oid == "1.2.840.113549.1.1.10")
        {
            var hash = RsassaPssParameters.GetInstance(algorithm.Parameters).HashAlgorithm.Algorithm.Id;
            return hash is "2.16.840.1.101.3.4.2.1" or "2.16.840.1.101.3.4.2.2" or "2.16.840.1.101.3.4.2.3";
        }
        return oid is "1.2.840.113549.1.1.11" or "1.2.840.113549.1.1.12" or "1.2.840.113549.1.1.13" or "1.2.840.10045.4.3.2" or "1.2.840.10045.4.3.3" or "1.2.840.10045.4.3.4";
    }
    public static void VerifyCertificate(X509Certificate2 certificate, X509Certificate2 signer)
    {
        var parser = new X509CertificateParser();
        var parsed = parser.ReadCertificate(certificate.RawData);
        var issuer = parser.ReadCertificate(signer.RawData);
        if (!certificate.IssuerName.RawData.AsSpan().SequenceEqual(signer.SubjectName.RawData)) throw new CryptographicException();
        var algorithm = parsed.CertificateStructure.SignatureAlgorithm;
        if (algorithm.Algorithm.Id == "1.2.840.113549.1.1.10")
        {
            if (!algorithm.Equals(parsed.CertificateStructure.TbsCertificate.Signature)) throw new CryptographicException();
            VerifyPss(algorithm, issuer.GetPublicKey(), parsed.GetTbsCertificate(), parsed.GetSignature());
        }
        else parsed.Verify(issuer.GetPublicKey());
    }

    private static void VerifyPss(AlgorithmIdentifier algorithm, Org.BouncyCastle.Crypto.AsymmetricKeyParameter key, byte[] data, byte[] signature)
    {
        var pss = RsassaPssParameters.GetInstance(algorithm.Parameters);
        if (pss.MaskGenAlgorithm.Algorithm.Id != "1.2.840.113549.1.1.8" || pss.TrailerField.Value.IntValueExact != 1 || key is not RsaKeyParameters rsa)
            throw new CryptographicException();
        var mask = AlgorithmIdentifier.GetInstance(pss.MaskGenAlgorithm.Parameters);
        var saltLength = pss.SaltLength.Value.IntValueExact;
        if (saltLength < 0 || saltLength > (rsa.Modulus.BitLength + 7) / 8) throw new CryptographicException();
        var verifier = new PssSigner(new RsaEngine(), DigestUtilities.GetDigest(pss.HashAlgorithm), DigestUtilities.GetDigest(mask), saltLength);
        verifier.Init(false, key);
        verifier.BlockUpdate(data, 0, data.Length);
        if (!verifier.VerifySignature(signature)) throw new CryptographicException();
    }
    public static void VerifyCsr(byte[] der)
    {
        Pkcs10CertificationRequest request;
        try { request = new Pkcs10CertificationRequest(der); }
        catch (Exception) { throw new AgentCertificateException("invalid_agent_csr"); }
        try
        {
            var key = request.GetPublicKey();
            if (key is RsaKeyParameters rsa)
            {
                if (rsa.Modulus.BitLength is < 2048 or > 8192 || !rsa.Exponent.Equals(Org.BouncyCastle.Math.BigInteger.ValueOf(65537)))
                    throw new AgentCertificateException("unsupported_agent_key");
            }
            else if (key is ECPublicKeyParameters ec)
            {
                if (ec.PublicKeyParamSet?.Id is not ("1.2.840.10045.3.1.7" or "1.3.132.0.34"))
                    throw new AgentCertificateException("unsupported_agent_key");
            }
            else throw new AgentCertificateException("unsupported_agent_key");
            var alg = request.SignatureAlgorithm;
            var oid = alg.Algorithm.Id;
            if (oid == "1.2.840.113549.1.1.10")
            {
                var hash = RsassaPssParameters.GetInstance(alg.Parameters).HashAlgorithm.Algorithm.Id;
                if (hash is not ("2.16.840.1.101.3.4.2.1" or "2.16.840.1.101.3.4.2.2" or "2.16.840.1.101.3.4.2.3"))
                    throw new AgentCertificateException("invalid_agent_csr_signature");
            }
            else if (oid is not ("1.2.840.113549.1.1.11" or "1.2.840.113549.1.1.12" or "1.2.840.113549.1.1.13" or "1.2.840.10045.4.3.2" or "1.2.840.10045.4.3.3" or "1.2.840.10045.4.3.4"))
                throw new AgentCertificateException("invalid_agent_csr_signature");
            if (oid == "1.2.840.113549.1.1.10")
                VerifyPss(alg, key, request.GetCertificationRequestInfo().GetDerEncoded(), request.Signature.GetBytes());
            else if (!request.Verify()) throw new AgentCertificateException("invalid_agent_csr_signature");
        }
        catch (AgentCertificateException) { throw; }
        catch (Exception) { throw new AgentCertificateException("invalid_agent_csr_signature"); }
    }
}

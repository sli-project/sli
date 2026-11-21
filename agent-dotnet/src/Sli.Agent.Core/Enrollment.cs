using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using Sli.Agent.Protocol;

namespace Sli.Agent.Core;

/// <summary>Enrollment and renewal use the existing server contract and the same key as the durable spool.</summary>
public sealed class Enrollment(HostIdentityStore store, IAgentControlTransport transport, TimeProvider clock,
    Func<string?>? readProductType = null, Func<(string Dns, string Forest, string Sid)?>? readDomain = null)
{
    private static string? ReadProductType()
    {
        if (!OperatingSystem.IsWindows()) return null;
        try
        {
            return Registry.GetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ProductOptions", "ProductType", null) as string;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        { return null; }
    }

    public async Task<AgentIdentity> EnrollAsync(string token, CancellationToken cancellationToken, string? instanceName = null)
    {
        using var existing = store.Load();
        if (existing is not null) throw new AgentException("agent_already_enrolled");
        if (!Regex.IsMatch(token, "^[A-Za-z0-9_-]{43}$")) throw new AgentException("agent_token_invalid");
        var request = new JsonObject { ["token"] = token, ["csr_pem"] = store.CreateCsrPem(), ["reported_hostname"] = Environment.MachineName };
        request["agent_version"]=typeof(Enrollment).Assembly.GetName().Version!.ToString(3);
        // Local discovery is a registration hint. The server owns scope authorization.
        bool isDc = (readProductType ?? ReadProductType)() == "LanmanNT";
        request["machine_role"] = isDc ? "domain_controller" : "workstation";
        if (isDc && (readDomain is not null ? readDomain() : OperatingSystem.IsWindows() ? EnrollmentDomain.Read() : null) is { } domain)
        {
            request["domain_dns"] = domain.Dns;
            request["forest_dns"] = domain.Forest;
            request["domain_sid"] = domain.Sid;
        }
        if (instanceName is not null) request["instance_name"] = instanceName;
        return store.Accept(await transport.PostAsync("/api/v1/agent/enroll", request, cancellationToken).ConfigureAwait(false), clock.GetUtcNow());
    }

    public async Task<AgentIdentity?> EnrollGroupAsync(string token, long computerEntityId, CancellationToken cancellationToken, string? instanceName = null)
    {
        if (computerEntityId < 1) throw new AgentException("agent_group_scope_invalid");
        using var existing = store.Load();
        if (existing is not null) throw new AgentException("agent_already_enrolled");
        var request = new JsonObject
        {
            ["token"] = token, ["computer_entity_id"] = computerEntityId,
            ["host_id"] = store.Prepare().HostId, ["csr_pem"] = store.CreateCsrPem(),
        };
        if (instanceName is not null) request["instance_name"] = instanceName;
        var answer = await transport.PostAsync("/api/v1/agent/group-enroll", request, cancellationToken).ConfigureAwait(false);
        if (answer["status"]?.GetValue<string>() == "pending") return null;
        if (answer["status"]?.GetValue<string>() != "approved" || !JsonRead.TryString(answer["token"], out var approved))
            throw new AgentException("agent_group_approval_invalid");
        return await EnrollAsync(approved, cancellationToken, instanceName).ConfigureAwait(false);
    }

    public async Task<bool> RenewIfDueAsync(AgentIdentity identity, CancellationToken cancellationToken, long renewBeforeSeconds = 3 * 86400)
    {
        var now = clock.GetUtcNow();
        if (identity.Certificate.NotAfter.ToUniversalTime() <= now) throw new AgentException("agent_certificate_expired");
        if (now.AddSeconds(renewBeforeSeconds) < identity.Certificate.NotAfter.ToUniversalTime()) return false;
        var response = await transport.PostAsync("/api/v1/agent/renew", new JsonObject { ["csr_pem"] = store.CreateCsrPem() }, cancellationToken).ConfigureAwait(false);
        using var renewed = store.Accept(response, now, identity.AgentId);
        return true;
    }
}

public static class IssuedCertificate
{
    public static bool IsValidationError(string code) => code is "agent_certificate_invalid"
        or "agent_certificate_invalid_shape" or "agent_certificate_invalid_key_mismatch"
        or "agent_certificate_invalid_ca_flag" or "agent_certificate_invalid_key_usage"
        or "agent_certificate_invalid_eku" or "agent_certificate_invalid_san"
        or "agent_certificate_invalid_issuer_chain" or "agent_certificate_invalid_validity"
        or "agent_certificate_invalid_chain_build";

    /// <summary>Do not trust enrollment response metadata: validate the certificate, key, exact SAN and every chain signature.</summary>
    public static void Validate(JsonObject body, string hostId, ECDsa key, DateTimeOffset now, string? expectedAgent)
    {
        var issuers = new X509Certificate2Collection();
        var failureCode = "agent_certificate_invalid_shape";
        try
        {
            var agentId = body["agent_id"]!.GetValue<string>();
            if (!Guid.TryParseExact(agentId, "D", out var id) || id.ToString("D") != agentId || expectedAgent is not null && expectedAgent != agentId)
                throw new CryptographicException();
            using var leaf = X509Certificate2.CreateFromPem(body["certificate_pem"]!.GetValue<string>());
            ValidateSubject(leaf.SubjectName, agentId);
            failureCode = "agent_certificate_invalid_key_mismatch";
            var publicKeyFingerprint = Convert.ToHexStringLower(SHA256.HashData(leaf.PublicKey.ExportSubjectPublicKeyInfo()));
            if (publicKeyFingerprint != HostIdentityStore.Fingerprint(key))
                throw new CryptographicException();
            failureCode = "agent_certificate_invalid_ca_flag";
            if (leaf.Extensions.OfType<X509BasicConstraintsExtension>().Single().CertificateAuthority) throw new CryptographicException();
            failureCode = "agent_certificate_invalid_key_usage";
            if (!leaf.Extensions.OfType<X509KeyUsageExtension>().Single().KeyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature))
                throw new CryptographicException();
            failureCode = "agent_certificate_invalid_eku";
            var eku = leaf.Extensions.OfType<X509EnhancedKeyUsageExtension>().Single().EnhancedKeyUsages;
            if (eku.Count != 1 || eku[0].Value != "1.3.6.1.5.5.7.3.2") throw new CryptographicException();
            failureCode = "agent_certificate_invalid_san";
            var san = leaf.Extensions.Single(extension => extension.Oid?.Value == "2.5.29.17");
            var namesReader = new AsnReader(san.RawData, AsnEncodingRules.DER);
            var names = namesReader.ReadSequence();
            var uriTag = new Asn1Tag(TagClass.ContextSpecific, 6);
            if (names.ReadCharacterString(UniversalTagNumber.IA5String, uriTag) != "urn:sli:agent:" + agentId
                || names.ReadCharacterString(UniversalTagNumber.IA5String, uriTag) != "urn:sli:host:" + hostId)
                throw new CryptographicException();
            names.ThrowIfNotEmpty();
            namesReader.ThrowIfNotEmpty();
            failureCode = "agent_certificate_invalid_issuer_chain";
            issuers.ImportFromPem(body["ca_chain_pem"]!.GetValue<string>());
            if (issuers.Count is < 1 or > 4) throw new CryptographicException();
            var child = leaf;
            foreach (var issuer in issuers)
            {
                if (!issuer.Extensions.OfType<X509BasicConstraintsExtension>().Single().CertificateAuthority) throw new CryptographicException();
                VerifySignature(child, issuer);
                child = issuer;
            }
            VerifySignature(child, child);
            failureCode = "agent_certificate_invalid_validity";
            foreach (var certificate in issuers.Cast<X509Certificate2>().Prepend(leaf))
                if (now < certificate.NotBefore.ToUniversalTime() || now >= certificate.NotAfter.ToUniversalTime()) throw new CryptographicException();
            failureCode = "agent_certificate_invalid_chain_build";
            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(issuers[^1]);
            chain.ChainPolicy.ExtraStore.AddRange(issuers);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.DisableCertificateDownloads = true;
            chain.ChainPolicy.VerificationTime = now.UtcDateTime;
            chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.2"));
            if (!chain.Build(leaf)) throw new CryptographicException();
        }
        catch (Exception exception) when (exception is CryptographicException or AsnContentException or InvalidOperationException
            or ArgumentException or NullReferenceException or FormatException or System.Text.Json.JsonException)
        {
            throw new AgentException(failureCode);
        }
        catch (Exception)
        {
            throw new AgentException("agent_certificate_invalid");
        }
        finally
        {
            foreach (var issuer in issuers) issuer.Dispose();
        }
    }

    private static void ValidateSubject(X500DistinguishedName subject, string agentId)
    {
        // Python cryptography emits UTF8String; .NET commonly emits PrintableString for UUIDs.
        // Compare the single CN value, while rejecting extra RDNs/attributes and trailing DER.
        var reader = new AsnReader(subject.RawData, AsnEncodingRules.DER);
        var name = reader.ReadSequence();
        var rdn = name.ReadSetOf();
        var attribute = rdn.ReadSequence();
        if (attribute.ReadObjectIdentifier() != "2.5.4.3") throw new CryptographicException();
        var tag = attribute.PeekTag();
        if (tag.TagClass != TagClass.Universal || tag.TagValue is not ((int)UniversalTagNumber.UTF8String or (int)UniversalTagNumber.PrintableString)
            || attribute.ReadCharacterString((UniversalTagNumber)tag.TagValue) != agentId)
            throw new CryptographicException();
        attribute.ThrowIfNotEmpty();
        rdn.ThrowIfNotEmpty();
        name.ThrowIfNotEmpty();
        reader.ThrowIfNotEmpty();
    }

    private static void VerifySignature(X509Certificate2 child, X509Certificate2 issuer)
    {
        if (!child.IssuerName.RawData.AsSpan().SequenceEqual(issuer.SubjectName.RawData)) throw new CryptographicException();
        var reader = new AsnReader(child.RawData, AsnEncodingRules.DER).ReadSequence();
        var data = reader.ReadEncodedValue();
        var algorithm = reader.ReadSequence().ReadObjectIdentifier();
        var signature = reader.ReadBitString(out var unused);
        if (unused != 0) throw new CryptographicException();
        var hash = algorithm switch
        {
            "1.2.840.10045.4.3.2" or "1.2.840.113549.1.1.11" => HashAlgorithmName.SHA256,
            "1.2.840.10045.4.3.3" or "1.2.840.113549.1.1.12" => HashAlgorithmName.SHA384,
            "1.2.840.10045.4.3.4" or "1.2.840.113549.1.1.13" => HashAlgorithmName.SHA512,
            _ => throw new CryptographicException(),
        };
        using var ec = issuer.GetECDsaPublicKey();
        using var rsa = issuer.GetRSAPublicKey();
        var valid = algorithm.StartsWith("1.2.840.10045.", StringComparison.Ordinal)
            ? ec?.VerifyData(data.Span, signature, hash, DSASignatureFormat.Rfc3279DerSequence) == true
            : rsa?.VerifyData(data.Span, signature, hash, RSASignaturePadding.Pkcs1) == true;
        if (!valid) throw new CryptographicException();
    }
}

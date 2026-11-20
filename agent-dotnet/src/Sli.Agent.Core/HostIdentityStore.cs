using System.Security.Cryptography;
using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;

namespace Sli.Agent.Core;

public sealed record PreparedIdentity(string HostId, string KeyFingerprint);

/// <summary>An enrolled identity: the server-issued certificate with the agent's key, ready to sign packets and to open mTLS.</summary>
public sealed class AgentIdentity(string agentId, X509Certificate2 certificate, ECDsa key, string caChainPem) : IDisposable
{
    public string AgentId { get; } = agentId;

    public X509Certificate2 Certificate { get; } = certificate;

    public ECDsa Key { get; } = key;

    public string CaChainPem { get; } = caChainPem;

    public IPacketSigner Signer { get; } = new EcdsaPacketSigner(key);

    public void Dispose()
    {
        Certificate.Dispose();
        Key.Dispose();
    }
}

/// <summary>
/// The agent's local identity (<c>sli_agent/enrollment.py: IdentityStore</c>): an opaque host id, a P-256 key and, after
/// enrollment, the issued certificate. The key never leaves the state directory unprotected.
/// </summary>
public sealed class HostIdentityStore(string directory, IDurableFiles files, IKeyProtector protector)
{
    private string KeyPath => Path.Combine(directory, "identity-key.json");

    private string HostPath => Path.Combine(directory, "host.json");

    private string IdentityPath => Path.Combine(directory, "identity.json");

    /// <summary>Creates the host id and the key once; returns only public values.</summary>
    public PreparedIdentity Prepare(string? hostId = null)
    {
        files.EnsureDirectory(directory);
        var hasKey = files.ReadAll(KeyPath) is not null;
        var hasHost = files.ReadAll(HostPath) is not null;
        if (hasKey != hasHost || !hasKey && files.ReadAll(IdentityPath) is not null)
            throw new AgentException("agent_identity_invalid");
        if (!hasKey)
        {
            using var created = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var protectedKey = protector.Protect(created.ExportPkcs8PrivateKey());
            files.WriteAtomic(KeyPath, CanonicalJson.ToBytes(new JsonObject
            {
                ["format"] = "sli-agent-key-v1",
                ["protection"] = protector.Name,
                ["data"] = Convert.ToBase64String(protectedKey),
            }));
        }
        if (!hasHost)
        {
            files.WriteAtomic(HostPath, CanonicalJson.ToBytes(new JsonObject { ["host_id"] = hostId ?? Guid.NewGuid().ToString("D") }));
        }
        var existing = ReadHostId();
        if (hostId is not null && existing != hostId) throw new AgentException("agent_identity_invalid");
        using var key = LoadKey();
        return new PreparedIdentity(existing, Fingerprint(key));
    }

    public string ReadHostId()
    {
        try
        {
            var body = JsonNode.Parse(files.ReadAll(HostPath) ?? throw new AgentException("agent_identity_invalid"));
            var text = body?["host_id"]?.GetValue<string>();
            if (!Guid.TryParseExact(text, "D", out var guid) || guid.ToString("D") != text) throw new AgentException("agent_identity_invalid");
            return text;
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException or FormatException)
        {
            throw new AgentException("agent_identity_invalid");
        }
    }

    public ECDsa LoadKey()
    {
        try
        {
            var body = JsonNode.Parse(files.ReadAll(KeyPath) ?? throw new AgentException("agent_identity_invalid"));
            if (body?["protection"]?.GetValue<string>() != protector.Name || body["format"]?.GetValue<string>() != "sli-agent-key-v1")
                throw new AgentException("agent_identity_invalid");
            var pkcs8 = protector.Unprotect(Convert.FromBase64String(body["data"]!.GetValue<string>()));
            try { return ImportKey(pkcs8); }
            finally { CryptographicOperations.ZeroMemory(pkcs8); }
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException or FormatException or CryptographicException or AsnContentException)
        {
            throw new AgentException("agent_identity_invalid");
        }
    }

    /// <summary>SHA-256 of the SubjectPublicKeyInfo, lower-case hex: the value an administrator binds a token to.</summary>
    public static string Fingerprint(ECDsa key) => Convert.ToHexStringLower(SHA256.HashData(key.ExportSubjectPublicKeyInfo()));

    /// <summary>The enrollment request: subject <c>CN=host id</c>, no extensions (the server refuses any), SHA-256.</summary>
    public string CreateCsrPem()
    {
        var hostId = Prepare().HostId;
        using var key = LoadKey();
        var request = new CertificateRequest(new X500DistinguishedName("CN=" + hostId), key, HashAlgorithmName.SHA256);
        return request.CreateSigningRequestPem();
    }

    // ImportPkcs8PrivateKey on Windows can require a user profile for the temporary CNG PKCS#8 wrapper.
    // Import the same P-256 key through SEC1 instead: no persistent key container or profile is needed.
    private static ECDsa ImportKey(byte[] pkcs8)
    {
        var outer = new AsnReader(pkcs8, AsnEncodingRules.DER);
        var info = outer.ReadSequence();
        if (info.ReadInteger() != 0) throw new CryptographicException();
        var algorithm = info.ReadSequence();
        if (algorithm.ReadObjectIdentifier() != "1.2.840.10045.2.1" || algorithm.ReadObjectIdentifier() != "1.2.840.10045.3.1.7") throw new CryptographicException();
        algorithm.ThrowIfNotEmpty();
        var privateKey = info.ReadOctetString();
        info.ThrowIfNotEmpty();
        outer.ThrowIfNotEmpty();
        byte[]? encoded = null;
        try
        {
            var ec = new AsnReader(privateKey, AsnEncodingRules.DER).ReadSequence();
            if (ec.ReadInteger() != 1) throw new CryptographicException();
            var writer = new AsnWriter(AsnEncodingRules.DER);
            writer.PushSequence();
            writer.WriteInteger(1);
            writer.WriteOctetString(ec.ReadOctetString());
            var parameters = new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true);
            writer.PushSequence(parameters);
            writer.WriteObjectIdentifier("1.2.840.10045.3.1.7");
            writer.PopSequence(parameters);
            while (ec.HasData)
            {
                if (ec.PeekTag().HasSameClassAndValue(parameters)) ec.ReadEncodedValue();
                else writer.WriteEncodedValue(ec.ReadEncodedValue().Span);
            }
            writer.PopSequence();
            encoded = writer.Encode();
            var key = ECDsa.Create();
            try { key.ImportECPrivateKey(encoded, out _); return key; }
            catch { key.Dispose(); throw; }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKey);
            if (encoded is not null) CryptographicOperations.ZeroMemory(encoded);
        }
    }

    public AgentIdentity Accept(JsonObject response, DateTimeOffset now, string? expectedAgent = null)
    {
        using var key = LoadKey();
        IssuedCertificate.Validate(response, ReadHostId(), key, now, expectedAgent);
        var saved = new JsonObject
        {
            ["agent_id"] = response["agent_id"]!.DeepClone(),
            ["certificate_pem"] = response["certificate_pem"]!.DeepClone(),
            ["ca_chain_pem"] = response["ca_chain_pem"]!.DeepClone(),
        };
        try
        {
            files.WriteAtomic(IdentityPath, CanonicalJson.ToBytes(saved));
            return Load() ?? throw new AgentException("agent_identity_persist_failed");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            throw new AgentException("agent_identity_persist_failed");
        }
    }

    /// <summary>The issued identity, or null before enrollment.</summary>
    public AgentIdentity? Load()
    {
        var raw = files.ReadAll(IdentityPath);
        if (raw is null) return null;
        try
        {
            var body = JsonNode.Parse(raw)!;
            var agentId = body["agent_id"]!.GetValue<string>();
            var key = LoadKey();
            try
            {
                using var certificate = X509Certificate2.CreateFromPem(body["certificate_pem"]!.GetValue<string>());
                return new AgentIdentity(agentId, certificate.CopyWithPrivateKey(key), key, body["ca_chain_pem"]!.GetValue<string>());
            }
            catch { key.Dispose(); throw; }
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException or NullReferenceException or CryptographicException or ArgumentException)
        {
            throw new AgentException("agent_identity_invalid");
        }
    }
}

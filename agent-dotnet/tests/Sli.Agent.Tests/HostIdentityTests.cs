using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Agent.Tests.Support;
using Xunit;

namespace Sli.Agent.Tests;

public sealed class HostIdentityTests : IDisposable
{
    private readonly string _directory = Helpers.TempDirectory();

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    private HostIdentityStore Store(IKeyProtector? protector = null) => new(_directory, new PhysicalDurableFiles(), protector ?? new RestrictedFileKeyProtector());

    [Fact]
    public void PrepareCreatesTheIdentityOnceAndReturnsOnlyPublicValues()
    {
        var first = Store().Prepare();
        var second = Store().Prepare();
        Assert.Equal(first, second);
        Assert.True(Guid.TryParseExact(first.HostId, "D", out _));
        Assert.Matches("^[0-9a-f]{64}$", first.KeyFingerprint);
    }

    [Fact]
    public void TheFingerprintIsTheSha256OfTheSubjectPublicKeyInfo()
    {
        var store = Store();
        var prepared = store.Prepare();
        using var key = store.LoadKey();
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(key.ExportSubjectPublicKeyInfo())), prepared.KeyFingerprint);
    }

    [Fact]
    public void ANamedHostIdMustMatchTheStoredOne()
    {
        var store = Store();
        var prepared = store.Prepare("11111111-2222-4333-8444-555555555555");
        Assert.Equal("11111111-2222-4333-8444-555555555555", prepared.HostId);
        Assert.Equal("agent_identity_invalid", Assert.Throws<AgentException>(() => store.Prepare("22222222-2222-4333-8444-555555555555")).Code);
    }

    [Fact]
    public void TheKeyIsStoredThroughTheProtector()
    {
        var protector = new ReversingProtector();
        var store = Store(protector);
        store.Prepare();
        var body = JsonNode.Parse(File.ReadAllText(Path.Combine(_directory, "identity-key.json")))!;
        Assert.Equal("reversing", body["protection"]!.GetValue<string>());
        // The stored bytes are the protected form, not a loadable PKCS#8 key.
        var stored = Convert.FromBase64String(body["data"]!.GetValue<string>());
        using var probe = ECDsa.Create();
        Assert.ThrowsAny<CryptographicException>(() => probe.ImportPkcs8PrivateKey(stored, out _));
        using var loaded = store.LoadKey();
        Assert.NotNull(loaded);
        // A different protector cannot open it.
        Assert.Equal("agent_identity_invalid", Assert.Throws<AgentException>(() => Store().LoadKey()).Code);
    }

    [Fact]
    public void ACorruptKeyFileIsAnIdentityError()
    {
        var store = Store();
        store.Prepare();
        File.WriteAllText(Path.Combine(_directory, "identity-key.json"), "{\"format\":\"sli-agent-key-v1\",\"protection\":\"restricted_file\",\"data\":\"AAAA\"}");
        Assert.Equal("agent_identity_invalid", Assert.Throws<AgentException>(store.LoadKey).Code);
        File.WriteAllText(Path.Combine(_directory, "identity-key.json"), "nonsense");
        Assert.Equal("agent_identity_invalid", Assert.Throws<AgentException>(store.LoadKey).Code);
    }

    [Fact]
    public void TheCsrHasOnlyTheHostIdAsSubjectAndNoExtensions()
    {
        var store = Store();
        var prepared = store.Prepare();
        var request = CertificateRequest.LoadSigningRequestPem(store.CreateCsrPem(), HashAlgorithmName.SHA256, CertificateRequestLoadOptions.Default);
        Assert.Equal("CN=" + prepared.HostId, request.SubjectName.Name);
        Assert.Empty(request.CertificateExtensions);
        Assert.Equal(prepared.KeyFingerprint, Convert.ToHexStringLower(SHA256.HashData(request.PublicKey.ExportSubjectPublicKeyInfo())));
    }

    [Fact]
    public void LoadIsNullBeforeEnrollmentAndRebuildsTheIdentityAfter()
    {
        var store = Store();
        var prepared = store.Prepare();
        Assert.Null(store.Load());
        using var key = store.LoadKey();
        var request = new CertificateRequest("CN=" + Helpers.AgentId, key, HashAlgorithmName.SHA256);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
        File.WriteAllBytes(Path.Combine(_directory, "identity.json"), CanonicalJson.ToBytes(new JsonObject
        {
            ["agent_id"] = Helpers.AgentId,
            ["certificate_pem"] = certificate.ExportCertificatePem(),
            ["ca_chain_pem"] = certificate.ExportCertificatePem(),
        }));
        using var identity = store.Load()!;
        Assert.Equal(Helpers.AgentId, identity.AgentId);
        Assert.True(identity.Certificate.HasPrivateKey);
        // The key that signs packets is the key in the certificate.
        using var key2 = store.LoadKey();
        Assert.Equal(prepared.KeyFingerprint, HostIdentityStore.Fingerprint(key2));
        var packet = Packets.Make(identity.Signer, identity.AgentId, 1, Helpers.Sample("", "1"), Helpers.Now);
        using var publicKey = identity.Certificate.GetECDsaPublicKey()!;
        Assert.Equal(packet.Envelope.PacketId, PacketVerifier.Verify(packet.ToJson(), publicKey).PacketId);
    }

    [Fact]
    public void ACertificateThatDoesNotMatchTheKeyIsRefused()
    {
        var store = Store();
        store.Prepare();
        using var other = Helpers.NewKey();
        var request = new CertificateRequest("CN=" + Helpers.AgentId, other, HashAlgorithmName.SHA256);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
        File.WriteAllBytes(Path.Combine(_directory, "identity.json"), CanonicalJson.ToBytes(new JsonObject
        {
            ["agent_id"] = Helpers.AgentId,
            ["certificate_pem"] = certificate.ExportCertificatePem(),
            ["ca_chain_pem"] = certificate.ExportCertificatePem(),
        }));
        Assert.Equal("agent_identity_invalid", Assert.Throws<AgentException>(store.Load).Code);
    }

    [Theory]
    [InlineData("identity-key.json")]
    [InlineData("host.json")]
    public void PrepareNeverReplacesPartOfAnExistingIdentity(string missing)
    {
        var store = Store();
        store.Prepare();
        File.Delete(Path.Combine(_directory, missing));
        Assert.Equal("agent_identity_invalid", Assert.Throws<AgentException>(() => store.Prepare()).Code);
        Assert.False(File.Exists(Path.Combine(_directory, missing)));
    }

    [Fact]
    public void AnUnreadableIdentityIsNeverTreatedAsNotEnrolled()
    {
        Store().Prepare();
        // A directory in place of identity.json makes File.Exists return false, but is not an absent identity.
        Directory.CreateDirectory(Path.Combine(_directory, "identity.json"));
        Assert.Throws<UnauthorizedAccessException>(() => Store().Load());
    }

    private sealed class ReversingProtector : IKeyProtector
    {
        public string Name => "reversing";

        public byte[] Protect(byte[] data) => data.Reverse().ToArray();

        public byte[] Unprotect(byte[] data) => data.Reverse().ToArray();
    }
}

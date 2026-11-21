using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Tests.Support;
using Xunit;

namespace Sli.Agent.Tests;

public sealed class EnrollmentTests : IDisposable
{
    private readonly string _directory = Helpers.TempDirectory();
    private readonly TestAuthority _ca = new();
    private readonly TestClock _clock = new();
    private HostIdentityStore Store => new(_directory, new PhysicalDurableFiles(), new RestrictedFileKeyProtector());
    public void Dispose() { _ca.Dispose(); Directory.Delete(_directory, true); }
    private sealed class Transport(Func<string, JsonNode, JsonObject> post) : IAgentControlTransport
    {
        public Task<JsonObject> PostAsync(string path, JsonNode body, CancellationToken cancellationToken) => Task.FromResult(post(path, body));
        public Task<JsonObject> GetAsync(string path, CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    [Fact]
    public async Task EnrollPersistsOnlyValidatedIdentityAndReportsTheComputerName()
    {
        Store.Prepare();
        var fingerprint = Store.Prepare().KeyFingerprint;
        var transport = new Transport((path, body) =>
        {
            Assert.Equal("/api/v1/agent/enroll", path);
            Assert.Equal(new string('t', 43), body["token"]!.GetValue<string>());
            Assert.Equal(Environment.MachineName, body["reported_hostname"]!.GetValue<string>());
            Assert.Contains(body["machine_role"]!.GetValue<string>(), new[] { "workstation", "domain_controller" });
            Assert.StartsWith("-----BEGIN CERTIFICATE REQUEST-----", body["csr_pem"]!.GetValue<string>(), StringComparison.Ordinal);
            return _ca.Issue(Store);
        });
        using var enrolled = await new Enrollment(Store, transport, _clock).EnrollAsync(new string('t', 43), CancellationToken.None);
        Assert.Equal(Helpers.AgentId, enrolled.AgentId);
        Assert.True(enrolled.Certificate.HasPrivateKey);
        Assert.Equal(fingerprint, Store.Prepare().KeyFingerprint);
        Assert.DoesNotContain(new string('t', 43), File.ReadAllText(Path.Combine(_directory, "identity.json")), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("WinNT", "workstation", true, true)]
    [InlineData("ServerNT", "workstation", true, true)]
    [InlineData("LanmanNT", "domain_controller", true, true)]
    [InlineData("LanmanNT", "domain_controller", true, false)]
    [InlineData("LanmanNT", "domain_controller", false, false)]
    [InlineData(null, "workstation", false, false)]
    public async Task EnrollmentReportsDirectoryIdentityOnlyForADomainController(
        string? productType, string role, bool hasDomain, bool hasSid)
    {
        Store.Prepare();
        const string sid = "S-1-5-21-100000001-200000002-300000003";
        var transport = new Transport((path, body) =>
        {
            Assert.Equal("/api/v1/agent/enroll", path);
            Assert.Equal(role, body["machine_role"]!.GetValue<string>());
            bool reportsDomain = role == "domain_controller" && hasDomain;
            Assert.Equal(reportsDomain ? "child.example.test" : null, (string?)body["domain_dns"]);
            Assert.Equal(reportsDomain ? "example.test" : null, (string?)body["forest_dns"]);
            Assert.Equal(reportsDomain && hasSid ? sid : null, (string?)body["domain_sid"]);
            return _ca.Issue(Store);
        });
        using var identity = await new Enrollment(Store, transport, _clock, () => productType,
                () => hasDomain ? ("child.example.test", "example.test", hasSid ? sid : null) : null)
            .EnrollAsync(new string('t', 43), CancellationToken.None);
        Assert.Equal(Helpers.AgentId, identity.AgentId);
    }

    [Theory]
    [InlineData("host", "agent_certificate_invalid_san")]
    [InlineData("eku", "agent_certificate_invalid_eku")]
    [InlineData("ca", "agent_certificate_invalid_ca_flag")]
    [InlineData("san", "agent_certificate_invalid_san")]
    [InlineData("chain", "agent_certificate_invalid_issuer_chain")]
    [InlineData("key", "agent_certificate_invalid_key_mismatch")]
    [InlineData("expired", "agent_certificate_invalid_validity")]
    public void InvalidCertificatesNeverReplaceTheIdentity(string defect, string expected)
    {
        Store.Prepare();
        var body = _ca.Issue(Store, hostId: defect == "host" ? Guid.NewGuid().ToString("D") : null,
            usage: defect == "eku" ? "1.3.6.1.5.5.7.3.1" : "1.3.6.1.5.5.7.3.2", isCa: defect == "ca", extraSan: defect == "san");
        if (defect == "chain") { using var rogue = new TestAuthority(); body["ca_chain_pem"] = rogue.Root.ExportCertificatePem(); }
        if (defect == "key")
        {
            var other = new HostIdentityStore(Path.Combine(_directory, "other"), new PhysicalDurableFiles(), new RestrictedFileKeyProtector());
            other.Prepare();
            body = _ca.Issue(other, hostId: Store.ReadHostId());
        }
        var error = Assert.Throws<AgentException>(() => Store.Accept(body, defect == "expired" ? Helpers.Now.AddDays(31) : Helpers.Now));
        Assert.Equal(expected, error.Code);
        Assert.Equal(expected, error.Message);
        Assert.Null(error.InnerException);
        Assert.False(File.Exists(Path.Combine(_directory, "identity.json")));
    }

    [Fact]
    public void AcceptsTheServerProfileWithUtf8SubjectAndTwoP384CertificateAuthorities()
    {
        Store.Prepare();
        using var server = new ServerAuthority();
        using var identity = Store.Accept(server.Issue(Store), Helpers.Now);
        Assert.Equal(Helpers.AgentId, identity.AgentId);
        Assert.True(identity.Certificate.HasPrivateKey);
        using var loaded = Store.Load();
        Assert.Equal(identity.Certificate.Thumbprint, loaded!.Certificate.Thumbprint);
    }

    [Theory]
    [InlineData("subject", "agent_certificate_invalid_shape")]
    [InlineData("extra_subject", "agent_certificate_invalid_shape")]
    [InlineData("duplicate_subject", "agent_certificate_invalid_shape")]
    [InlineData("missing_ca", "agent_certificate_invalid_ca_flag")]
    [InlineData("ca", "agent_certificate_invalid_ca_flag")]
    [InlineData("missing_key_usage", "agent_certificate_invalid_key_usage")]
    [InlineData("key_usage", "agent_certificate_invalid_key_usage")]
    [InlineData("missing_eku", "agent_certificate_invalid_eku")]
    [InlineData("missing_san", "agent_certificate_invalid_san")]
    [InlineData("extra_san", "agent_certificate_invalid_san")]
    [InlineData("reversed_san", "agent_certificate_invalid_san")]
    [InlineData("empty_chain", "agent_certificate_invalid_issuer_chain")]
    [InlineData("long_chain", "agent_certificate_invalid_issuer_chain")]
    [InlineData("reversed_chain", "agent_certificate_invalid_issuer_chain")]
    [InlineData("issuer_ca", "agent_certificate_invalid_issuer_chain")]
    [InlineData("signature", "agent_certificate_invalid_issuer_chain")]
    [InlineData("future", "agent_certificate_invalid_validity")]
    [InlineData("chain_build", "agent_certificate_invalid_chain_build")]
    public void ServerProfileDefectsReportTheirStageAndKeepThePreviousIdentity(string defect, string expected)
    {
        Store.Prepare();
        using (Store.Accept(_ca.Issue(Store), Helpers.Now)) { }
        var previous = File.ReadAllBytes(Path.Combine(_directory, "identity.json"));
        using var server = new ServerAuthority(defect);
        var error = Assert.Throws<AgentException>(() => Store.Accept(server.Issue(Store, defect), Helpers.Now));
        Assert.Equal(expected, error.Code);
        Assert.Equal(expected, error.Message);
        Assert.Null(error.InnerException);
        Assert.Equal(previous, File.ReadAllBytes(Path.Combine(_directory, "identity.json")));
    }

    [Theory]
    [InlineData("agent_id")]
    [InlineData("certificate_pem")]
    public void MalformedResponseShapeNeverLeaksInputOrCryptoDetails(string field)
    {
        Store.Prepare();
        var body = _ca.Issue(Store);
        body[field] = "private invalid input";
        var error = Assert.Throws<AgentException>(() => Store.Accept(body, Helpers.Now));
        Assert.Equal("agent_certificate_invalid_shape", error.Code);
        Assert.Equal(error.Code, error.Message);
        Assert.Null(error.InnerException);
        Assert.Null(Store.Load());
    }

    [Fact]
    public async Task GroupPendingRetriesTheSameIdentityThenUsesTheApprovedToken()
    {
        Store.Prepare();
        var prepared = Store.Prepare();
        var approved = false;
        var transport = new Transport((path, body) =>
        {
            if (path.EndsWith("group-enroll", StringComparison.Ordinal))
            {
                Assert.Equal(prepared.HostId, body["host_id"]!.GetValue<string>());
                Assert.Equal(7, body["computer_entity_id"]!.GetValue<long>());
                return approved ? new JsonObject { ["status"] = "approved", ["token"] = new string('a', 43) } : new JsonObject { ["status"] = "pending" };
            }
            Assert.Equal(new string('a', 43), body["token"]!.GetValue<string>());
            return _ca.Issue(Store);
        });
        var enrollment = new Enrollment(Store, transport, _clock);
        Assert.Null(await enrollment.EnrollGroupAsync(new string('g', 43), 7, CancellationToken.None));
        approved = true;
        using var identity = await enrollment.EnrollGroupAsync(new string('g', 43), 7, CancellationToken.None);
        Assert.NotNull(identity);
        Assert.Equal(prepared, Store.Prepare());
    }

    [Fact]
    public async Task RenewalKeepsTheKeyAndRefusesADifferentAgent()
    {
        Store.Prepare();
        using var identity = Store.Accept(_ca.Issue(Store, days: 2), Helpers.Now);
        var prepared = Store.Prepare();
        var enrollment = new Enrollment(Store, new Transport((path, _) => { Assert.Equal("/api/v1/agent/renew", path); return _ca.Issue(Store); }), _clock);
        Assert.True(await enrollment.RenewIfDueAsync(identity, CancellationToken.None));
        Assert.Equal(prepared, Store.Prepare());
        using var current = Store.Load()!;
        Assert.False(await enrollment.RenewIfDueAsync(current, CancellationToken.None));
        var bad = new Enrollment(Store, new Transport((_, _) => _ca.Issue(Store, agentId: Guid.NewGuid().ToString("D"))), _clock);
        await Assert.ThrowsAsync<AgentException>(() => bad.RenewIfDueAsync(identity, CancellationToken.None));
        Assert.Equal(Helpers.AgentId, Store.Load()!.AgentId);
    }

    [Fact]
    public void BootstrapGroupDocumentIsBoundedAndExpires()
    {
        var doc = new JsonObject { ["kind"] = "group", ["token"] = new string('g', 43), ["computer_entity_id"] = 7,
            ["expires_at"] = Sli.Agent.Protocol.Iso8601.Format(Helpers.Now.AddHours(1)) }.ToJsonString();
        var encoded = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(doc)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        Assert.Equal(7, EnrollmentInput.Parse(encoded, Helpers.Now).ComputerEntityId);
        Assert.Throws<AgentException>(() => EnrollmentInput.Parse(doc, Helpers.Now.AddHours(2)));
        Assert.DoesNotContain("secret", Assert.Throws<AgentException>(() => EnrollmentInput.Parse("secret invalid", Helpers.Now)).Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AFailedIdentityWriteHasAnExplicitPersistenceCode()
    {
        Store.Prepare();
        var files = new FaultyFiles(new PhysicalDurableFiles()) { FailWrite = p => p.EndsWith("identity.json", StringComparison.Ordinal) };
        var store = new HostIdentityStore(_directory, files, new RestrictedFileKeyProtector());
        Assert.Equal("agent_identity_persist_failed", Assert.Throws<AgentException>(() => store.Accept(_ca.Issue(store), Helpers.Now)).Code);
        Assert.Null(Store.Load());
    }
}

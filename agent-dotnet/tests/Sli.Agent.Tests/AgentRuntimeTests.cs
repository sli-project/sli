using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.Versioning;
using Microsoft.Extensions.Options;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Agent.Service;
using Sli.Agent.Tests.Support;
using Sli.Agent.Windows;
using Xunit;

namespace Sli.Agent.Tests;

public sealed class AgentRuntimeTests : IDisposable
{
    private sealed class UnreachableServer : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            throw new HttpRequestException("synthetic connection refused");
    }

    private readonly string _directory = Helpers.TempDirectory();

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    private AgentOptions Options(string url = "https://localhost:1/") => new()
    {
        ServerUrl = url,
        CaBundle = Path.Combine(_directory, "server-ca.pem"),
        StateDir = Path.Combine(_directory, "state"),
        TokenFile = Path.Combine(_directory, "bootstrap-token"),
    };

    private AgentRuntime Runtime(AgentOptions options) => new(Microsoft.Extensions.Options.Options.Create(options), TimeProvider.System);

    private JsonNode Status() => JsonNode.Parse(File.ReadAllText(Path.Combine(_directory, "state", "status.json")))!;

    [Fact]
    public async Task WithoutServerSettingsItReportsAConfigurationErrorAndDoesNothing()
    {
        using var runtime = Runtime(Options(string.Empty));
        var status = await runtime.RunCycleAsync(CancellationToken.None);
        Assert.Equal("agent_config_invalid", status.ErrorCode);
        Assert.False(status.CollectionActive);
        Assert.Equal("agent_config_invalid", Status()["error_code"]!.GetValue<string>());
    }

    [Fact]
    public async Task EveryFinishedCycleAtomicallyReplacesLastCycleWithOnlyUtcCodeAndCounts()
    {
        var clock = new TestClock();
        var options = Options(string.Empty);
        using var runtime = new AgentRuntime(Microsoft.Extensions.Options.Options.Create(options), clock);
        await runtime.RunCycleAsync(CancellationToken.None);
        var path = Path.Combine(options.StateDir, "last-cycle.json");
        var first = JsonNode.Parse(File.ReadAllText(path))!.AsObject();
        Assert.Equal(new[] { "collection_active", "error_code", "observed_at_utc", "pending_packets" }, first.Select(p => p.Key).Order());
        Assert.Equal("2026-10-07T12:00:00+00:00", first["observed_at_utc"]!.GetValue<string>());
        Assert.Equal("agent_config_invalid", first["error_code"]!.GetValue<string>());
        Assert.False(first["collection_active"]!.GetValue<bool>());
        Assert.Equal(0, first["pending_packets"]!.GetValue<int>());
        options.ServerUrl = "https://core.example.test/";
        clock.Now = clock.Now.AddMinutes(1);
        await runtime.RunCycleAsync(CancellationToken.None);
        var next = JsonNode.Parse(File.ReadAllText(path))!;
        Assert.Equal("2026-10-07T12:01:00+00:00", next["observed_at_utc"]!.GetValue<string>());
        Assert.Equal("agent_not_enrolled", next["error_code"]!.GetValue<string>());
        Assert.Empty(Directory.GetFiles(options.StateDir, "*.tmp"));
    }

    [WindowsFact]
    [SupportedOSPlatform("windows")]
    public async Task LastCycleInheritsTheRestrictedStateDirectoryAcl()
    {
        if (!OperatingSystem.IsWindows()) return;
        var options = Options(string.Empty);
        using var runtime = Runtime(options);
        await runtime.RunCycleAsync(CancellationToken.None);
        var rules = new FileInfo(Path.Combine(options.StateDir, "last-cycle.json")).GetAccessControl()
            .GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
        var principals = rules.Select(r => r.IdentityReference.Value).Distinct().Order();
        Assert.Equal(new[] { WindowsIdentity.GetCurrent().User!.Value, "S-1-5-18", "S-1-5-32-544" }.Distinct().Order(), principals);
        Assert.All(rules, rule => { Assert.True(rule.IsInherited); Assert.Equal(AccessControlType.Allow, rule.AccessControlType); });
    }

    [Fact]
    public async Task BeforeEnrollmentItPreparesTheIdentityAndWaits()
    {
        using var runtime = Runtime(Options());
        var status = await runtime.RunCycleAsync(CancellationToken.None);
        Assert.Equal("agent_not_enrolled", status.ErrorCode);
        Assert.True(File.Exists(Path.Combine(_directory, "state", "identity-key.json")));
        Assert.True(File.Exists(Path.Combine(_directory, "state", "host.json")));
    }

    [Fact]
    public async Task WhenTheServerIsUnreachableTheQueuedPacketsStayAndTheErrorIsAFixedCode()
    {
        var options = Options();
        var store = AgentRuntime.CreateIdentityStore(options);
        var prepared = store.Prepare();
        using var key = store.LoadKey();
        var request = new CertificateRequest("CN=" + Helpers.AgentId, key, HashAlgorithmName.SHA256);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
        File.WriteAllBytes(Path.Combine(options.StateDir, "identity.json"), CanonicalJson.ToBytes(new JsonObject
        {
            ["agent_id"] = Helpers.AgentId,
            ["certificate_pem"] = certificate.ExportCertificatePem(),
            ["ca_chain_pem"] = certificate.ExportCertificatePem(),
        }));
        File.WriteAllText(options.CaBundle, certificate.ExportCertificatePem());
        using (var queue = new FilePacketQueue(Path.Combine(options.StateDir, "queue"), new PhysicalDurableFiles(), options.SpoolMaxBytes, options.SpoolMaxAgeSeconds))
        {
            queue.Capture(new EcdsaPacketSigner(key), Helpers.AgentId, Helpers.Sample("", "1") with { SourceInstanceId = prepared.HostId }, DateTimeOffset.UtcNow);
        }
        using var runtime = new AgentRuntime(Microsoft.Extensions.Options.Options.Create(options), TimeProvider.System,
            _ => new AgentHttpClient(new HttpClient(new UnreachableServer()) { BaseAddress = new Uri(options.ServerUrl) }));
        var status = await runtime.RunCycleAsync(CancellationToken.None);
        // Stage 2 requires a fresh check-in before any delivery. An unreachable server fails closed there.
        Assert.Equal("agent_transport_failed", status.ErrorCode);
        Assert.True(status.DeliveryFailed);
        Assert.Equal(1, status.Pending);
        // Collection is off in stage 1 unless enabled and on Windows: nothing was captured.
        Assert.Equal(0, status.Captured);
        Assert.False(status.CollectionActive);
        Assert.Equal(1, Status()["pending_packets"]!.GetValue<int>());
    }

    [Fact]
    public void StatusCarriesOnlySafeDiagnosticsAndCounts()
    {
        // Allow only counters and diagnostics at both levels of the status model.
        var keys = typeof(CycleStatus).GetProperties().Select(property => property.Name).Order().ToArray();
        Assert.Equal(new[] { "Captured", "CollectionActive", "DeliveryFailed", "ErrorCode", "ErrorDetail",
            "FileAuditCatalog", "Pending", "SnapshotFailures" }, keys);
        Assert.Equal(typeof(FileAuditCatalogDiagnostic),
            typeof(CycleStatus).GetProperty(nameof(CycleStatus.FileAuditCatalog))!.PropertyType);
        var catalogKeys = typeof(FileAuditCatalogDiagnostic).GetProperties().Select(property => property.Name).Order().ToArray();
        Assert.Equal(new[] { "EnumerationError", "HttpStatus", "NativeStatus", "ReportError" }, catalogKeys);
        Assert.Equal(typeof(IReadOnlyDictionary<string, SnapshotFailure>),
            typeof(CycleStatus).GetProperty(nameof(CycleStatus.SnapshotFailures))!.PropertyType);
        var snapshotKeys = typeof(SnapshotFailure).GetProperties().Select(property => property.Name).Order().ToArray();
        Assert.Equal(new[] { "Code", "Detail" }, snapshotKeys);
    }

    [Theory]
    [InlineData("agent_tls_client_key_unusable")]
    [InlineData("agent_tls_server_untrusted")]
    [InlineData("agent_tls_name_mismatch")]
    public async Task AFailedTlsClientCreationPreservesIdentityAndReportsItsCode(string code)
    {
        var options = Options();
        var store = AgentRuntime.CreateIdentityStore(options);
        store.Prepare();
        using var authority = new TestAuthority();
        using (store.Accept(authority.Issue(store), Helpers.Now)) { }
        var savedIdentity = File.ReadAllBytes(Path.Combine(options.StateDir, "identity.json"));
        var savedKey = File.ReadAllBytes(Path.Combine(options.StateDir, "identity-key.json"));
        using var runtime = new AgentRuntime(Microsoft.Extensions.Options.Options.Create(options), new TestClock(), identity =>
        {
            Assert.NotNull(identity);
            throw new TransportException(code);
        });
        var status = await runtime.RunCycleAsync(CancellationToken.None);
        Assert.Equal(code, status.ErrorCode);
        Assert.True(status.DeliveryFailed);
        Assert.False(status.CollectionActive);
        Assert.Equal(code, JsonNode.Parse(File.ReadAllText(Path.Combine(options.StateDir, "last-cycle.json")))!["error_code"]!.GetValue<string>());
        Assert.Equal(savedIdentity, File.ReadAllBytes(Path.Combine(options.StateDir, "identity.json")));
        Assert.Equal(savedKey, File.ReadAllBytes(Path.Combine(options.StateDir, "identity-key.json")));
    }

    [Fact]
    public async Task ExpiredBootstrapWithoutIdentityRequiresReenrollment()
    {
        var options = Options();
        options.TokenFile = Path.Combine(_directory, "token");
        File.WriteAllText(options.TokenFile, new string('t', 43));
        File.SetLastWriteTimeUtc(options.TokenFile, Helpers.Now.AddHours(-2).UtcDateTime);
        using var runtime = new AgentRuntime(Microsoft.Extensions.Options.Options.Create(options), new TestClock(),
            _ => throw new InvalidOperationException("No HTTP request may be made with an expired token"));
        for (var i = 0; i < 2; i++)
            Assert.Equal("agent_identity_missing_reenroll_required", (await runtime.RunCycleAsync(CancellationToken.None)).ErrorCode);
    }

    [Fact]
    public async Task ACorruptKeyRequiresReenrollmentWithoutReplacingIt()
    {
        var options = Options();
        AgentRuntime.CreateIdentityStore(options).Prepare();
        var path = Path.Combine(options.StateDir, "identity-key.json");
        File.WriteAllText(path, "broken");
        using var runtime = new AgentRuntime(Microsoft.Extensions.Options.Options.Create(options), new TestClock());
        Assert.Equal("agent_identity_missing_reenroll_required", (await runtime.RunCycleAsync(CancellationToken.None)).ErrorCode);
        Assert.Equal("broken", File.ReadAllText(path));
    }
}

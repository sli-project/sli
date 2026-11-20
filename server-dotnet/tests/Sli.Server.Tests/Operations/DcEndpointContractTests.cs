using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Server.Infrastructure;
using Sli.Server.Legacy;
using Sli.Server.Operations;
using Xunit;

namespace Sli.Server.Tests.Operations;

// Behavioral vectors from tests/sources/test_dc_endpoint_contract.py. Resolvers
// are local fixtures: these tests never query DNS, AD or an installed database.
public sealed class DcEndpointContractTests
{
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    const string One = """{"domain_controllers":[{"hostname":"DC1","connect_address":"dc1.example.test","owner_confirmed_ip":"198.51.100.23"}]}""";
    const string Two = """{"domain_controllers":[{"hostname":"DC1","connect_address":"dc1.example.test","owner_confirmed_ip":"198.51.100.23"},{"hostname":"DC2","connect_address":"dc2.example.test","owner_confirmed_ip":"198.51.100.24"}]}""";
    static readonly string[] Channels = ["Security", "System", "Directory Service", "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-TaskScheduler/Operational", "DNS Server"];

    sealed class Queries : IOperationsQueries
    {
        public JsonArray Targets = [];
        public bool FailTargets;
        public JsonArray Sources = JsonNode.Parse("""[{"hostname":"DC1","fqdn":"dc1.example.test","domain_fqdn":"example.test","role":"domain_controller"}]""")!.AsArray();
        public Task<JsonArray> ReadAsync(string sql, CancellationToken ct, params (string Name, object? Value)[] parameters)
        {
            ct.ThrowIfCancellationRequested();
            if (sql.Contains("from domain_controller_targets", StringComparison.Ordinal))
            {
                if (FailTargets) throw new InvalidOperationException("fixture_unavailable");
                return Task.FromResult(Targets.DeepClone().AsArray());
            }
            return Task.FromResult(sql == OperationsSql.Sources ? Sources.DeepClone().AsArray() : new JsonArray());
        }
    }

    sealed class Fixture : IDisposable
    {
        readonly string root = Path.Combine(Path.GetTempPath(), "sli-dc-contract-" + Guid.NewGuid().ToString("N"));
        public Queries Db = new();
        public IConfiguration Configuration;
        public OperationsFiles Files;
        public DomainControllerTargets Contract;
        public OperationsService Service;
        public Fixture(string? payload = One, string? overrideName = null)
        {
            Directory.CreateDirectory(Path.Combine(root, "config"));
            if (payload is not null) File.WriteAllText(Path.Combine(root, "config", "domain_controllers.json"), payload);
            var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
                ["Sli:ProjectRoot"] = root,
                ["Sli:Operations:ADLOG_DC_CONNECT_MAP"] = overrideName == "ADLOG_DC_CONNECT_MAP" ? "DC1=override.example.test" : "",
                ["Sli:Operations:ADLOG_DOMAIN_CONTROLLER_CONNECT_MAP"] = overrideName == "ADLOG_DOMAIN_CONTROLLER_CONNECT_MAP" ? "DC1=override.example.test" : ""
            }).Build();
            Configuration = config;
            Files = new(config); Contract = new(Db, Files); Service = new(Db, Files, new(), new(), TimeProvider.System);
        }
        public void Dispose() => Directory.Delete(root, true);
    }

    static Task<IPAddress[]> Resolve(string name, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        return Task.FromResult(new[] { IPAddress.Parse(name.StartsWith("dc1", StringComparison.Ordinal) ? "198.51.100.23" : "198.51.100.24") });
    }

    sealed class UnavailableConnections : IPostgresConnectionFactory
    {
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => throw new InvalidOperationException("fixture_unavailable");
    }

    [Fact]
    public async Task LegacyTargetEnumerationUsesTheSameEndpointAuthority()
    {
        using var f = new Fixture("""{"domain_controllers":[{"hostname":"DC1","connect_address":"dc1.example.test"}]}""");
        var environment = new LegacyEnvironment(new UnavailableConnections(), new(f.Configuration), f.Configuration);
        Assert.Equal(new[] { "DC1" }, await environment.TargetsAsync(Ct));
        using var stale = new Fixture("""{"domain_controllers":[{"hostname":"DC1","connect_address":"192.0.2.19"}]}""");
        var invalid = new LegacyEnvironment(new UnavailableConnections(), new(stale.Configuration), stale.Configuration);
        var error = await Assert.ThrowsAsync<OperationsInputException>(() => invalid.TargetsAsync(Ct));
        Assert.Contains("IP literal", error.Message);
    }

    [Fact]
    public async Task ConfiguredEndpointsKeepLogicalNamesFqdnsAndConfirmedDnsReadback()
    {
        using var f = new Fixture(Two);
        var expected = JsonNode.Parse(Two)!["domain_controllers"]!;
        Assert.True(JsonNode.DeepEquals(expected, await f.Contract.ConfiguredAsync(Ct)));
        var calls = new List<string>();
        var verified = await f.Contract.VerifyConfiguredAsync(Ct, (name, ct) => { calls.Add(name); return Resolve(name, ct); });
        Assert.True(JsonNode.DeepEquals(expected, verified));
        Assert.Equal(new[] { "dc1.example.test", "dc2.example.test" }, calls);
        Assert.True(JsonNode.DeepEquals(expected, await f.Service.TargetsAsync(Ct)));
    }

    [Theory]
    [InlineData("192.0.2.19", "IP literal")]
    [InlineData("192.0.2.20", "IP literal")]
    [InlineData("DC1", "FQDN")]
    public async Task InvalidEndpointsFailBeforeCollectionOrDns(string address, string error)
    {
        using var f = new Fixture(new JsonObject { ["domain_controllers"] = new JsonArray(new JsonObject { ["hostname"] = "DC1", ["connect_address"] = address }) }.ToJsonString());
        int dnsCalls = 0;
        var exception = await Assert.ThrowsAsync<OperationsInputException>(() => f.Contract.CollectionEndpointsAsync("DC1", Channels, Ct,
            (name, ct) => { dnsCalls++; return Resolve(name, ct); }));
        Assert.Contains(error, exception.Message); Assert.Equal(0, dnsCalls);
        await Assert.ThrowsAsync<OperationsInputException>(() => f.Service.TargetsAsync(Ct));
    }

    [Theory]
    [InlineData("ADLOG_DC_CONNECT_MAP")]
    [InlineData("ADLOG_DOMAIN_CONTROLLER_CONNECT_MAP")]
    public async Task EnvironmentOverridesFailClosed(string name)
    {
        using var f = new Fixture(overrideName: name);
        var error = await Assert.ThrowsAsync<OperationsInputException>(() => f.Contract.ConfiguredAsync(Ct));
        Assert.Contains("Environment DC endpoint override", error.Message);
        await Assert.ThrowsAsync<OperationsInputException>(() => f.Service.TargetsAsync(Ct));
        await Assert.ThrowsAsync<OperationsInputException>(() => f.Contract.ArchiveTargetsAsync(null, Ct, Resolve));
    }

    [Fact]
    public async Task UnconfiguredServerCannotBecomeAnEndpoint()
    {
        using var f = new Fixture();
        var error = await Assert.ThrowsAsync<OperationsInputException>(() => f.Contract.ResolveAsync("DC2", Ct, Resolve));
        Assert.Contains("not configured", error.Message);
        Assert.Equal("dc1.example.test", await f.Contract.ResolveAsync("\\\\dc1.example.test.", Ct, Resolve));
    }

    [Fact]
    public async Task SourceInventoryUsesOnlyOwnerConfirmedIpsWithoutDns()
    {
        using var f = new Fixture();
        var sources = await f.Service.SourcesAsync(Ct);
        Assert.Equal(new[] { "198.51.100.23" }, sources[0]!["ip_addresses"]!.AsArray().Select(n => (string)n!));
        // A legacy literal endpoint is not inventory evidence, even if it parses.
        using var stale = new Fixture("""{"domain_controllers":[{"hostname":"DC1","connect_address":"192.0.2.19"}]}""");
        Assert.Empty((await stale.Service.SourcesAsync(Ct))[0]!["ip_addresses"]!.AsArray());
    }

    [Fact]
    public async Task AllSixChannelsReceiveOneResolvedEndpoint()
    {
        using var f = new Fixture(); int calls = 0;
        var endpoints = await f.Contract.CollectionEndpointsAsync("DC1", Channels, Ct,
            (name, ct) => { calls++; Assert.Equal("dc1.example.test", name); return Resolve(name, ct); });
        Assert.Equal(1, calls); Assert.Equal(Channels, endpoints.Keys);
        Assert.All(endpoints.Values, endpoint => Assert.Equal("dc1.example.test", endpoint));
    }

    [Fact]
    public async Task ArchiveDefaultsToSharedFqdnTargetsAndVerifiesDnsFirst()
    {
        using var f = new Fixture(Two); var calls = new List<string>();
        var targets = await f.Contract.ArchiveTargetsAsync(null, Ct, (name, ct) => { calls.Add(name); return Resolve(name, ct); });
        Assert.Equal(2, targets.Count);
        Assert.Equal("dc1.example.test", targets["DC1"]); Assert.Equal("dc2.example.test", targets["DC2"]);
        Assert.Equal(new[] { "dc1.example.test", "dc2.example.test" }, calls);
    }

    [Theory]
    [InlineData("DC1=192.0.2.19")]
    [InlineData("DC1=override.example.test")]
    [InlineData("DC2=dc2.example.test")]
    public async Task ArchiveOverrideCannotBypassConfiguredFqdn(string requested)
    {
        using var f = new Fixture(); int calls = 0;
        var error = await Assert.ThrowsAsync<OperationsInputException>(() => f.Contract.ArchiveTargetsAsync([requested], Ct,
            (name, ct) => { calls++; return Resolve(name, ct); }));
        Assert.Contains("configured FQDN", error.Message); Assert.Equal(1, calls);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DnsMismatchOrFailureStopsCollectionAndArchive(bool fails)
    {
        using var f = new Fixture();
        Task<IPAddress[]> BadDns(string name, CancellationToken ct) => fails
            ? Task.FromException<IPAddress[]>(new SocketException((int)SocketError.HostNotFound))
            : Task.FromResult(new[] { IPAddress.Parse("192.0.2.19") });
        var collection = await Assert.ThrowsAsync<OperationsInputException>(() => f.Contract.CollectionEndpointsAsync("DC1", Channels, Ct, BadDns));
        Assert.Contains(fails ? "DNS readback failed" : "DNS readback mismatch", collection.Message);
        await Assert.ThrowsAsync<OperationsInputException>(() => f.Contract.ArchiveTargetsAsync(["DC1=dc1.example.test"], Ct, BadDns));
    }

    [Fact]
    public async Task ArchiveSubsetStillVerifiesEveryConfiguredTarget()
    {
        using var f = new Fixture(Two);
        var error = await Assert.ThrowsAsync<OperationsInputException>(() => f.Contract.ArchiveTargetsAsync(["dc1=DC1.EXAMPLE.TEST."], Ct,
            (name, ct) => Task.FromResult(new[] { IPAddress.Parse("198.51.100.23") })));
        Assert.Contains("dc2.example.test", error.Message);
        var selected = await f.Contract.ArchiveTargetsAsync(["dc1=DC1.EXAMPLE.TEST."], Ct, Resolve);
        Assert.Single(selected); Assert.Equal("dc1.example.test", selected["DC1"]);
    }

    [Fact]
    public async Task DatabaseAuthorityWinsAndDisabledRowsNeverFallbackToFile()
    {
        using var f = new Fixture();
        f.Db.Targets = JsonNode.Parse("""[{"hostname":"DC2","connect_address":"dc2.example.test","owner_confirmed_ip":"198.51.100.24","enabled":true}]""")!.AsArray();
        Assert.Equal("dc2.example.test", await f.Contract.ResolveAsync("DC2", Ct, Resolve));
        await Assert.ThrowsAsync<OperationsInputException>(() => f.Contract.ResolveAsync("DC1", Ct, Resolve));
        f.Db.Targets[0]!["enabled"] = false;
        Assert.Empty(await f.Contract.ConfiguredAsync(Ct));
        await Assert.ThrowsAsync<OperationsInputException>(() => f.Contract.ResolveAsync("DC1", Ct, Resolve));
    }

    [Fact]
    public async Task UnavailableDatabaseUsesFileAndNoContractKeepsLegacyIdentity()
    {
        using var f = new Fixture(); f.Db.FailTargets = true;
        Assert.Equal("dc1.example.test", await f.Contract.ResolveAsync("DC1", Ct, Resolve));
        using var absent = new Fixture(null);
        Assert.Equal("DC1", await absent.Contract.ResolveAsync("DC1", Ct, Resolve));
        await Assert.ThrowsAsync<OperationsInputException>(() => absent.Contract.ArchiveTargetsAsync(null, Ct, Resolve));
    }

    [Fact]
    public async Task CancellationIsPreserved()
    {
        using var f = new Fixture(); using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => f.Contract.ConfiguredAsync(cancellation.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => f.Contract.VerifyConfiguredAsync(Ct,
            (_, _) => Task.FromCanceled<IPAddress[]>(cancellation.Token)));
    }
}

using System.Diagnostics;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Sli.Server.Operations;
using Xunit;

namespace Sli.Server.Tests.Operations;

// Vectors from tests/core/test_source_inventory_ad_context.py.
public sealed class SourceInventoryAdContextTests
{
    sealed class Queries(JsonArray sources, JsonArray inventory, JsonArray targets) : IOperationsQueries
    {
        public Task<JsonArray> ReadAsync(string sql, CancellationToken ct, params (string Name, object? Value)[] parameters)
        {
            JsonArray result = sql == OperationsSql.Sources ? sources : sql == OperationsSql.SourceInventory ? inventory
                : sql.Contains("from domain_controller_targets", StringComparison.Ordinal) ? targets
                : throw new InvalidOperationException("Unexpected inventory query");
            return Task.FromResult(result.DeepClone().AsArray());
        }
    }

    static OperationsService Service(JsonArray sources, JsonArray inventory, JsonArray targets)
    {
        var config = new ConfigurationBuilder().Build();
        return new(new Queries(sources, inventory, targets), new OperationsFiles(config), new OperationsCatalog(), new OperationsJobs(), TimeProvider.System);
    }

    static JsonObject Registered(string hostname) => new()
    {
        ["hostname"] = hostname, ["fqdn"] = null, ["role"] = "domain_controller", ["is_active"] = true,
        ["os_name"] = null, ["os_version"] = null, ["domain_fqdn"] = "example.test", ["netbios_name"] = "EXAMPLE", ["site_name"] = "Site-1"
    };

    static JsonObject Inventory(string key) => new()
    {
        ["display_key"] = key, ["sam_key"] = key, ["dns_key"] = key, ["fqdn"] = key + ".example.test",
        ["os_name"] = "Windows Server", ["os_version"] = "10.0", ["last_observed_at_utc"] = "2026-07-26T03:00:00Z"
    };

    static JsonObject Target(string hostname, string ip) => new()
    {
        ["hostname"] = hostname, ["connect_address"] = hostname.Contains('.') ? hostname : hostname.ToLowerInvariant() + ".example.test", ["owner_confirmed_ip"] = ip, ["enabled"] = true
    };

    [Fact]
    public async Task RegisteredSourcesReuseCurrentAdComputerInventory()
    {
        var service = Service(new(Registered("DC1"), Registered("DC2")), new(Inventory("dc1"), Inventory("dc2")),
            new(Target("dc1", "192.0.2.10"), Target("dc2", "192.0.2.11")));
        var sources = await service.SourcesAsync(TestContext.Current.CancellationToken);

        Assert.Equal(new (string?, string?)[] { ("DC1", "dc1.example.test"), ("DC2", "dc2.example.test") },
            sources.Select(s => ((string?)s!["hostname"], (string?)s["fqdn"])));
        Assert.All(sources, s =>
        {
            Assert.Equal("Windows Server", (string?)s!["os_name"]);
            Assert.Equal("10.0", (string?)s["os_version"]);
            Assert.Equal("ad_context", (string?)s["inventory_source"]);
            Assert.Equal("2026-07-26T03:00:00Z", (string?)s["inventory_observed_at_utc"]);
            Assert.True((bool)s["is_active"]!);
            Assert.Equal("Site-1", (string?)s["site_name"]);
        });
        Assert.Equal(new[] { "192.0.2.10" }, sources[0]!["ip_addresses"]!.AsArray().Select(n => (string?)n));
        Assert.Equal(new[] { "192.0.2.11" }, sources[1]!["ip_addresses"]!.AsArray().Select(n => (string?)n));
    }

    [Fact]
    public async Task SourceInventoryParsesBoundedDiskRowsAndRejectsInvalidValues()
    {
        var inventory = Inventory("dc1");
        inventory["ip_addresses"] = new JsonArray("192.0.2.10", "not-an-ip");
        inventory["logical_disks"] = new JsonArray("C:|107374182400|53687091200", "D:|1000|100", "bad|100|50", "E:|10|20");
        inventory["technical_inventory_status"] = "complete";
        var service = Service(new(Registered("DC1")), new(inventory),
            new(Target("dc1", "192.0.2.10"), Target("dc1.example.test", "2001:db8::10")));
        var result = Assert.Single(await service.SourcesAsync(TestContext.Current.CancellationToken))!;

        Assert.Equal(new[] { "192.0.2.10", "2001:db8::10" }, result["ip_addresses"]!.AsArray().Select(n => (string?)n));
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""
            [{"name":"C:","total_bytes":107374182400,"free_bytes":53687091200,"free_percent":50.0},
             {"name":"D:","total_bytes":1000,"free_bytes":100,"free_percent":10.0}]
            """), result["disks"]));
        Assert.Equal("warning", (string?)result["disk_state"]);
    }

    static string Root([System.Runtime.CompilerServices.CallerFilePath] string file = "")
    {
        for (var directory = new FileInfo(file).Directory; directory is not null; directory = directory.Parent)
            if (File.Exists(Path.Combine(directory.FullName, "scripts", "ad_context", "DomainPosture.psm1"))) return directory.FullName;
        throw new DirectoryNotFoundException("Domain posture module not found");
    }

    [Fact]
    public void RunningExporterHasNoPathToDomainPostureModule()
    {
        string directory = Path.Combine(Root(), "scripts", "ad_context");
        string exporter = File.ReadAllText(Path.Combine(directory, "Export-AdAuditContextBundle.ps1"));
        string module = File.ReadAllText(Path.Combine(directory, "DomainPosture.psm1"));
        Assert.DoesNotContain("DomainPosture.psm1", exporter);
        Assert.DoesNotContain("Invoke-SLIDomainPostureRead", exporter);
        foreach (string command in new[] { "Set-AD", "New-AD", "Remove-AD", "Enable-AD", "Disable-AD" }) Assert.DoesNotContain(command, module);
    }
}

using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Sli.Server.Auth;
using Sli.Server.InstallationSetup;
using Xunit;

namespace Sli.Server.Tests.InstallationSetup;

public sealed class PluginStatusTests
{
    [Theory]
    [InlineData(null, false)]
    [InlineData("false", false)]
    [InlineData("true", true)]
    public async Task Only_remote_access_uses_the_server_preview_setting(string? configured, bool visible)
    {
        var database = new ScriptDatabase { Override = (sql, _) => sql.Contains("read_plugin_states_v1")
            ? new JsonArray(InstallationPackages.Bundled.Select(id =>
            {
                var row = ScriptDatabase.State();
                row["plugin_id"] = id;
                row["enabled"] = false;
                return (JsonNode)row;
            }).ToArray()) : null };
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            { ["modules:preview"] = configured }).Build();
        var service = new InstallationService(database, new InstallationPackages(configuration), configuration);
        var response = await service.DispatchAsync("GET", "/api/v1/plugins", new(),
            new Principal("session", 1, "admin", "fixture"), null, false, TestContext.Current.CancellationToken);
        var items = response["items"]!.AsArray().OfType<JsonObject>().ToDictionary(item => item["plugin_id"]!.GetValue<string>());
        Assert.Contains("sli.ad", items.Keys);
        Assert.Contains("sli.gpo", items.Keys);
        Assert.Contains("sli.file-audit", items.Keys);
        Assert.Contains("sli.workstations", items.Keys);
        Assert.Contains("sli.sigma", items.Keys);
        Assert.Equal(visible, items.ContainsKey("sli.remote-access"));
        Assert.All(items.Values, item => Assert.Equal("disabled", item["status"]!["state"]!.GetValue<string>()));
    }

    [Fact]
    public async Task Lists_assigned_file_servers_before_they_start_collecting()
    {
        var file = ScriptDatabase.State();
        file["plugin_id"] = "sli.file-audit";
        var database = new ScriptDatabase { Override = (sql, _) => sql.Contains("read_plugin_states_v1")
            ? new JsonArray(file) : sql.Contains("from sli_agents a")
            ? ScriptDatabase.Rows("""
                [{"module":"sli.file-audit","agent_id":"00000000-0000-4000-8000-000000000001",
                  "source_name":"FS01","collects":false}]
                """) : null };
        var configuration = new ConfigurationBuilder().Build();
        var service = new InstallationService(database, new InstallationPackages(configuration), configuration);
        var response = await service.DispatchAsync("GET", "/api/v1/plugins", new(),
            new Principal("session", 1, "admin", "fixture"), null, false, TestContext.Current.CancellationToken);
        var item = Assert.Single(response["items"]!.AsArray())!;
        Assert.Equal(1, item["source_count"]!.GetValue<int>());
        Assert.Equal("FS01", Assert.Single(item["source_names"]!.AsArray())!.GetValue<string>());
        Assert.Equal("no_sources", item["status"]!["state"]!.GetValue<string>());
    }

    [Theory]
    [InlineData(false, true, 2, false, "disabled")]
    [InlineData(true, false, null, false, "no_sources")]
    [InlineData(true, true, null, false, "waiting")]
    [InlineData(true, true, 5, false, "working")]
    [InlineData(true, true, 6, false, "error")]
    [InlineData(true, true, 1, true, "error")]
    public void Derives_one_state_with_applicable_time(
        bool enabled, bool source, int? ageMinutes, bool failed, string expected)
    {
        var now = new DateTimeOffset(2026, 11, 26, 8, 0, 0, TimeSpan.Zero);
        var observed = ageMinutes is int age ? now.AddMinutes(-age) : (DateTimeOffset?)null;
        var result = InstallationService.DerivePluginStatus(
            enabled, source, observed, TimeSpan.FromMinutes(5), failed ? now : null, now);
        Assert.Equal(expected, result.State);
        Assert.Equal(expected == "working" ? observed : null, result.LastDataAt);
        Assert.Equal(expected == "error" ? failed ? now : observed!.Value.AddMinutes(5) : null, result.ErrorAt);
    }
}

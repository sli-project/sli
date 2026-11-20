using Microsoft.Extensions.Hosting;
using System.Globalization;
using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Access.Administration;
using Sli.Server.Infrastructure;
using Sli.Server.Workspace;
using Xunit;

namespace Sli.Server.Tests.Workspace;

public sealed class WorkspaceReadTests
{
    [Theory]
    [InlineData("completed", "stale-reason", null)]
    [InlineData("partial", "stale-reason", null)]
    [InlineData("failed", null, "failed")]
    [InlineData("timeout", "", "timeout")]
    [InlineData("access_denied", "backend-denied", "backend-denied")]
    public void Failure_reason_only_describes_error_status(string status, string? reason, string? expected)
    {
        var channel = Body(new { server = "dc.example.test", channel = "Security", last_status = status, failure_reason = reason });
        var result = Body(WorkspaceOverview.Compose([], [channel], default, [], default, [], Now.AddHours(-24), Now, null, Now, [], true));
        var source = result.GetProperty("sources")[0].GetProperty("channels")[0];
        Assert.Equal(expected, source.GetProperty("failure_reason").GetString());
        var progress = result.GetProperty("collection_progress").GetProperty("items")[0];
        Assert.Equal(expected, progress.GetProperty("failure_reason").GetString());
    }
    private static readonly DateTimeOffset Now = new(2026, 1, 2, 12, 0, 0, TimeSpan.Zero);
    private static readonly JsonElement Reference = Load();
    private static JsonElement Load()
    {
        using var stream = typeof(WorkspaceReadTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Workspace.reference.json")!;
        return JsonDocument.Parse(stream).RootElement.Clone();
    }
    private static JsonElement J(string json) => JsonDocument.Parse(json).RootElement.Clone();
    private static JsonElement Body(object value) => JsonSerializer.SerializeToElement(value);
    private static JsonNode? Normalize(JsonNode? value)
    {
        if (value is JsonObject obj)
            foreach (var key in obj.Select(p=>p.Key).ToArray()) { var normalized=Normalize(obj[key]); if (!ReferenceEquals(normalized,obj[key])) obj[key]=normalized; }
        else if (value is JsonArray array)
            for (int i=0;i<array.Count;i++) { var normalized=Normalize(array[i]); if (!ReferenceEquals(normalized,array[i])) array[i]=normalized; }
        else if (value is JsonValue scalar && scalar.TryGetValue<string>(out var text) && text.Contains('T') && text.Contains(':')
            && DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var time))
            return JsonValue.Create(time.ToUniversalTime().ToString("O"));
        return value;
    }
    private static void Same(JsonElement expected, object actual) => Assert.True(JsonNode.DeepEquals(
        Normalize(JsonNode.Parse(expected.GetRawText())), Normalize(JsonSerializer.SerializeToNode(actual))),
        "Reference mismatch. Actual: " + JsonSerializer.Serialize(actual));

    [Fact]
    public void NonemptyAgentPoliciesStreamsAndFailureDatesMatchPythonReference()
    {
        foreach (var scenario in Reference.GetProperty("health").EnumerateArray())
        {
            var agents = scenario.GetProperty("agents").EnumerateArray().ToArray();
            var streams = scenario.GetProperty("streams").EnumerateArray().ToArray();
            Same(scenario.GetProperty("requested"), AgentCollectionOverview.RequestedStreams(agents));
            Same(scenario.GetProperty("expected"), AgentCollectionOverview.Compose(agents, streams, Now, scenario.GetProperty("diagnostics").GetBoolean()));
        }
    }

    private sealed class FakeRows(Func<string, NpgsqlParameter[], IReadOnlyList<JsonElement>> read) : IWorkspaceRows
    {
        public int Calls;
        public Task<IReadOnlyList<JsonElement>> ReadAsync(string sql, CancellationToken ct, params NpgsqlParameter[] parameters)
        { Calls++; return Task.FromResult(read(sql, parameters)); }
    }

    [Fact]
    public async Task AgentReadUsesRequestedRevisionChannelsAndRetainsContactOnDiagnosticsFailure()
    {
        var scenario = Reference.GetProperty("health")[0];
        var agents = scenario.GetProperty("agents").EnumerateArray().ToArray();
        var streams = scenario.GetProperty("streams").EnumerateArray().ToArray();
        var source = new FakeRows((sql, parameters) =>
        {
            if (sql.Contains("from sli_agents a")) return agents;
            Assert.Contains("sli_agent_stream_import_health",sql);
            Assert.Contains("sli_agent_snapshot_cycles",sql);
            var requested = Assert.Single(parameters);
            Assert.Equal("requested",requested.ParameterName);
            Same(scenario.GetProperty("requested"), JsonSerializer.Deserialize<JsonElement>((string)requested.Value!));
            return streams;
        });
        var health = Body(await new AgentCollectionOverview(source).ReadAsync(TestContext.Current.CancellationToken));
        Assert.Equal(7, health.GetProperty("items").GetArrayLength());
        Assert.Equal(2,source.Calls);
        var unavailable = new FakeRows((sql, _) => sql.Contains("from sli_agents a") ? agents : throw new TimeoutException());
        health = Body(await new AgentCollectionOverview(unavailable).ReadAsync(TestContext.Current.CancellationToken));
        Assert.Equal("timeout",health.GetProperty("diagnostics").GetProperty("reason").GetString());
        Assert.All(health.GetProperty("items").EnumerateArray(),a=> Assert.Equal("unknown",a.GetProperty("state").GetString()));
        Assert.Equal("offline",health.GetProperty("items")[0].GetProperty("connection").GetString());
    }

    private static AccessReadEvaluation Access(JsonElement input)
    {
        var caps = new CapabilityDecisionSet(false,input.GetProperty("capabilities").Strings(),new HashSet<string>(),[],new Dictionary<string,JsonElement>());
        var reports = input.GetProperty("reports").EnumerateArray().Select(r=>new ReportDecision(r.GetProperty("report_key").GetString()!,r.GetProperty("allowed").GetBoolean(),
            r.GetProperty("grants").EnumerateArray().Select(g=>new AtomicReportGrant(g.GetProperty("scope"),g.GetProperty("field_categories").Strings(),g.GetProperty("allowed_actions").Strings(),1,1)).ToArray())).ToArray();
        var facts = new AccessFacts(false,"admin",[],[],[],[],[],[],[]);
        return new(facts,caps,new("admin",caps,reports));
    }

    [Fact]
    public async Task AuthorizedCatalogProvidesDescriptionsAndExecutableHomeViews()
    {
        var access = Access(Reference.GetProperty("access"));
        var states = Reference.GetProperty("states").EnumerateArray().ToArray();
        var source = new FakeRows((sql, _) => { Assert.Contains("read_plugin_states_v1()", sql); return states; });
        var provider = new ReportRuleCatalog(new PluginGenerationReader(null));
        var body = Body(await new WorkspaceReportCatalog(source, provider).ReadAsync(access, TestContext.Current.CancellationToken));
        Assert.Equal("sli.report-catalog.v2", body.GetProperty("contract_id").GetString());
        var items = body.GetProperty("items").EnumerateArray().ToArray();
        Assert.NotEmpty(items);
        Assert.Contains(items, item => item.GetProperty("key").GetString() == "ad.infrastructure");
        Assert.Contains(items, item => item.GetProperty("key").GetString() == "security.problems");
        foreach (var item in items)
        {
            var rule = provider.Rules.Single(r => r.RegistryKey == item.GetProperty("key").GetString());
            Assert.Contains(access.Reports.Reports, report => report.Allowed && report.ReportKey == rule.ReportKey);
            Assert.Equal(rule.OwnerId, item.GetProperty("owner_id").GetString());
            Assert.False(string.IsNullOrWhiteSpace(item.GetProperty("title").GetString()));
            Assert.Equal(JsonValueKind.String, item.GetProperty("description").ValueKind);
            Assert.True(item.GetProperty("executable").GetBoolean());
        }
        Assert.NotEmpty(body.GetProperty("navigation").GetProperty("sections").EnumerateArray());
        Assert.Equal(1, source.Calls);
    }

    [Fact]
    public void CatalogDoesNotInventAuthorityOrMultiplyAtomicFieldsAndScopes()
    {
        var access = Access(Reference.GetProperty("access"));
        var rules = new ReportRuleCatalog(new PluginGenerationReader(null)).Rules;
        var report = access.Reports.Reports.Single(r=>r.ReportKey=="ad.state");
        var split = report with { Grants = [new(J("{\"kind\":\"domain\",\"ids\":[1]}"),new HashSet<string>{"identity_basic"},new HashSet<string>{"view"},1,1),
            new(J("{\"kind\":\"domain\",\"ids\":[2]}"),new HashSet<string>{"security","technical"},new HashSet<string>{"view"},1,1)] };
        var restricted = access with { Reports = access.Reports with { Reports = [split] } };
        var body = Body(WorkspaceReportCatalog.Compose(restricted,rules,[]));
        var item = Assert.Single(body.GetProperty("items").EnumerateArray());
        Assert.Equal("ad.infrastructure",item.GetProperty("key").GetString());
        Assert.False(item.GetProperty("executable").GetBoolean());
        body = Body(WorkspaceReportCatalog.Compose(access with { Reports = access.Reports with { Reports = [] } },rules,[]));
        Assert.Empty(body.GetProperty("items").EnumerateArray());
        Assert.DoesNotContain(body.GetProperty("navigation").GetProperty("enabled_plugins").EnumerateArray(),i=>i.GetString()=="sli.remote-access");
        body = Body(WorkspaceReportCatalog.Compose(access,rules.Where(r=>r.OwnerId!="sli.ad").ToArray(),[]));
        Assert.DoesNotContain(body.GetProperty("items").EnumerateArray(),i=>i.GetProperty("owner_id").GetString()=="sli.ad");
    }

    [Theory]
    [InlineData("",24)]
    [InlineData("shell",24)]
    [InlineData("other",7)]
    public async Task DefaultOverviewReadsNonemptyPostgresProjectionsAndBindsUntrustedFilters(string view,int bucketCount)
    {
        const string host = "dc'--.example.test";
        string from = bucketCount==7 ? "2026-01-01T12:00:00Z" : "2026-01-02T11:00:00Z";
        string to = bucketCount==7 ? "2026-01-08T12:00:00Z" : "2026-01-02T12:00:00Z";
        var inventory = new { hostname=host,fqdn=host,role="dc",is_active=true,os_name="Windows",os_version="test",site="test",
            ip_addresses=new[]{"192.0.2.1","not-an-ip"},logical_disks=new[]{"C:|1000|100"},technical_inventory_status="complete" };
        var channel = new { server=host,channel="Security",last_status="completed",last_successful_collection_utc=DateTimeOffset.UtcNow,
            last_event_time_utc="2020-01-01T00:00:00Z",adaptive_action="exit_recovery:source_boundary_reached",recovery_mode=false };
        var snapshot = UiWorkspaceParityTests.Snapshot();
        snapshot["sources"]!["items"] = JsonSerializer.SerializeToNode(new[] { inventory });
        snapshot["collector_health"]!["items"] = JsonSerializer.SerializeToNode(new[] { channel });
        snapshot["events_summary"] = JsonSerializer.SerializeToNode(new { total_events=1234,estimated=true,security_24h_summary=new { important_total=9 } });
        snapshot["entity_summary"] = JsonSerializer.SerializeToNode(new { total_entities=56,estimated=true });
        snapshot["findings"]!["items"] = JsonSerializer.SerializeToNode(new[] { new { id=17,title="<script>fixture</script>",severity="high",status="open",source=host,last_seen_utc=from,evidence_count=2,last_evidence_event_id=9 } });
        var source = new FakeRows((sql,p) =>
        {
            Assert.DoesNotContain(host,sql);
            if (sql==WorkspaceOverview.CollectorSql) return [Body(channel)];
            if (sql==WorkspaceOverview.WorkerSql) return [J("{\"worker_id\":\"fixture\",\"status\":\"idle\"}")];
            Assert.Equal(host,p.Single(v=>v.ParameterName=="server").Value);
            Assert.Equal(bucketCount,p.Single(v=>v.ParameterName=="buckets").Value);
            return [J("{\"bucket\":0,\"final_security_severity\":\"high\",\"count\":11}"), J("{\"bucket\":0,\"final_security_severity\":\"medium\",\"count\":3}")];
        });
        var query = new QueryCollection(new Dictionary<string,Microsoft.Extensions.Primitives.StringValues> { ["view"]=view,["time_from"]=from,["time_to"]=to,["server"]=host });
        var result = Body(await UiWorkspaceParityTests.Overview(source, snapshot).ReadAsync(query,TestContext.Current.CancellationToken));
        Assert.Equal("v1",result.GetProperty("api_version").GetString());
        Assert.Equal("ok",result.GetProperty("status").GetString());
        Assert.Equal(1234,result.GetProperty("metrics").GetProperty("events_total").GetInt64());
        Assert.Equal(9,result.GetProperty("metrics").GetProperty("important_recent").GetInt64());
        var returnedInventory = Assert.Single(result.GetProperty("sources").EnumerateArray());
        Assert.Equal("warning",returnedInventory.GetProperty("disk_state").GetString());
        Assert.Single(returnedInventory.GetProperty("ip_addresses").EnumerateArray());
        Assert.Equal("current",result.GetProperty("collection_freshness").GetProperty("state").GetString());
        Assert.Equal("completed",result.GetProperty("collection_progress").GetProperty("status").GetString());
        Assert.Equal(17,Assert.Single(result.GetProperty("alerts").EnumerateArray()).GetProperty("id").GetInt64());
        var bars=result.GetProperty("activity").GetProperty("items");
        Assert.Equal(bucketCount,bars.GetArrayLength());
        Assert.Equal(11,bars[0].GetProperty("critical").GetInt64());
        Assert.Equal(3,bars[0].GetProperty("important").GetInt64());
        Assert.Equal(3,source.Calls);
    }

    [Fact]
    public async Task OverviewAggregatesCanonicalContextualSeverityInPostgres()
    {
        // Vectors from tests/reporting/test_dashboard_canonical_semantics.py.
        var (activity, sql, parameters) = await CanonicalOverview([
            J("{\"bucket\":0,\"final_security_severity\":\"high\",\"count\":2}"),
            J("{\"bucket\":0,\"final_security_severity\":\"unknown\",\"count\":1}")]);

        Assert.Contains("event_data_json", sql);
        Assert.DoesNotContain("powershell", sql);
        Assert.Contains(parameters, p => p.Value is string text && text.Contains("powershell", StringComparison.OrdinalIgnoreCase));
        Assert.Contains("final_security_severity", sql);
        Assert.Contains("group by bucket,final_security_severity", sql);
        Assert.Equal(2, activity.GetProperty("items")[0].GetProperty("critical").GetInt64());
        Assert.Equal(1, activity.GetProperty("items")[0].GetProperty("informational").GetInt64());
        Assert.True(activity.GetProperty("exact").GetBoolean());
        Assert.True(activity.GetProperty("available").GetBoolean());
        Assert.Equal(JsonValueKind.Null, activity.GetProperty("reason").ValueKind);
    }

    private static async Task<(JsonElement Activity, string Sql, NpgsqlParameter[] Parameters)> CanonicalOverview(
        IReadOnlyList<JsonElement> activityRows)
    {
        var queries = new List<(string Sql, NpgsqlParameter[] Parameters)>();
        var source = new FakeRows((sql, parameters) =>
        {
            if (!sql.Contains("semantic_events", StringComparison.Ordinal)) return [];
            queries.Add((sql.ToLowerInvariant(), parameters));
            return activityRows;
        });
        var query = new QueryCollection(new Dictionary<string, Microsoft.Extensions.Primitives.StringValues>
        {
            ["time_from"] = "2026-07-17T00:00:00Z",
            ["time_to"] = "2026-07-17T01:00:00Z"
        });
        var result = Body(await UiWorkspaceParityTests.Overview(source, UiWorkspaceParityTests.Snapshot()).ReadAsync(query, TestContext.Current.CancellationToken));
        var captured = Assert.Single(queries);
        return (result.GetProperty("activity"), captured.Sql, captured.Parameters);
    }

    [Fact]
    public async Task OverviewUsesSafeDefaultWindowAndHonestUnavailableActivity()
    {
        var source=new FakeRows((sql,parameters)=>
        {
            if (sql.Contains("semantic_events"))
            {
                var start=(DateTimeOffset)parameters.Single(p=>p.ParameterName=="start").Value!;
                var end=(DateTimeOffset)parameters.Single(p=>p.ParameterName=="end").Value!;
                Assert.Equal(TimeSpan.FromHours(24),end-start);
                throw new TimeoutException();
            }
            return [];
        });
        var query=new QueryCollection(new Dictionary<string,Microsoft.Extensions.Primitives.StringValues>{["time_from"]="2000-01-01",["time_to"]="2026-01-01"});
        var body=Body(await UiWorkspaceParityTests.Overview(source, UiWorkspaceParityTests.Snapshot()).ReadAsync(query,TestContext.Current.CancellationToken));
        Assert.Equal("ok",body.GetProperty("status").GetString());
        Assert.False(body.GetProperty("activity").GetProperty("available").GetBoolean());
        Assert.False(body.GetProperty("activity").GetProperty("exact").GetBoolean());
        Assert.Empty(body.GetProperty("activity").GetProperty("items").EnumerateArray());
    }

    private sealed class NoDatabase : IPostgresConnectionFactory
    {
        public int Opens;
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) { Opens++; throw new InvalidOperationException("guard opened DB"); }
    }
    [Fact]
    public async Task ActualRoutesRequireAuthenticationBeforeAnyPostgresRead()
    {
        var db=new NoDatabase();
        using var host=new WebApplicationFactory<Program>().WithWebHostBuilder(Sli.Server.Tests.Domains.SafeTestEnvironment.ConfigureApiHost).WithWebHostBuilder(b=>b.ConfigureLogging(l=>l.ClearProviders())
            .ConfigureServices(s=> {
                s.AddSingleton<IPostgresConnectionFactory>(db);
                // Count reads made by HTTP requests, independently of startup's
                // registry reconciliation, which has its own worker tests.
                foreach (var service in s.Where(d=>d.ServiceType==typeof(IHostedService)
                    && d.ImplementationType==typeof(Sli.Server.Agents.Registry.AgentRegistrationReconciliation)).ToArray()) s.Remove(service);
            }).ConfigureAppConfiguration((_,cfg)=>cfg.AddInMemoryCollection(new Dictionary<string,string?> {
                ["Sli:AgentMtlsCaFile"]="",["Sli:TrustedProxies"]="",["Sli:AuthRequired"]="0",["Sli:AllowUnauthenticated"]="1",["urls"]="http://127.0.0.1:0",["Sli:AuthAllowInsecureHttp"]="1",["Sli:OwnerSetup"]="0" })));
        host.UseKestrel(k=>k.Listen(IPAddress.Loopback,0));host.StartServer();
        var address=Assert.Single(host.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses);
        using var client=new HttpClient { BaseAddress=new Uri(address) };
        foreach(string path in new[]{"/api/v1/overview?view=agents","/api/v1/overview","/api/v1/overview?view=shell","/api/v2/reports"})
        {
            using var response=await client.GetAsync(path,TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.Unauthorized,response.StatusCode);
            Assert.True(response.Headers.CacheControl?.NoStore);
        }
        Assert.Equal(0,db.Opens);
    }
}

using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Sli.Server.Legacy;
using Sli.Server.Workspace;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Xunit;

namespace Sli.Server.Tests.Workspace;

// Vectors from tests/reporting/test_ui_workspace_api.py; storage is the only fake.
public sealed class UiWorkspaceParityTests
{
    static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-07-17T04:00:00Z");
    static JsonElement J(string json) => JsonSerializer.Deserialize<JsonElement>(json);
    static JsonElement Body(object value) => JsonSerializer.SerializeToElement(value);
    internal static JsonObject Snapshot() => JsonNode.Parse("""
        {"generated_at_utc":"2026-07-16T04:00:00Z","status":"ok",
         "diagnostics":{"response_model":"fresh_cache","stale":false,"failures":[]},
         "events_summary":{"total_events":10,"estimated":true,"security_24h_summary":{"important_total":2}},
         "entity_summary":{"total_entities":3,"estimated":true},
         "findings":{"items":[{"id":7,"title":"Check","severity":"high","status":"new","evidence_count":1}]},
         "sources":{"items":[{"hostname":"DC1","is_active":1,"fqdn":null,"os_name":null,"os_version":null,"ip_addresses":[]}]},
         "collector_health":{"items":[]}}
        """)!.AsObject();

    internal static WorkspaceOverview Overview(IWorkspaceRows rows, JsonObject snapshot, DashboardRiskProjection? riskProjection = null)
    {
        var cache = new DashboardSnapshotCache { Payload = snapshot, Created = Stopwatch.GetTimestamp() };
        var settings = new LegacySettings(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            { ["Sli:Legacy:ADLOG_DASHBOARD_CACHE_TTL_SECONDS"] = "60" }).Build());
        var reader = new DashboardSnapshotReader(null!, null!, null!, settings, cache, null!);
        return new WorkspaceOverview(rows, reader) { RiskProjection = riskProjection ?? DashboardRiskProjection.Bundled };
    }

    sealed class Rows(Func<string, NpgsqlParameter[], IReadOnlyList<JsonElement>> read) : IWorkspaceRows
    {
        public Task<IReadOnlyList<JsonElement>> ReadAsync(string sql, CancellationToken ct, params NpgsqlParameter[] parameters)
            => Task.FromResult(read(sql, parameters));
    }
    sealed class Facts(AccessFacts facts) : IAccessFactsRepository
    {
        public Task<AccessFacts> LoadAsync(Principal principal, CancellationToken ct) => Task.FromResult(facts);
    }
    sealed class Authentication : IPrincipalAuthenticator
    {
        public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext context, CancellationToken ct)
            => ValueTask.FromResult(AuthenticationResult.Success(new("session", 1, "viewer")));
    }

    [Fact]
    public async Task WorkspaceAdapterSerializesOnlyAuthorizedRecentObjectsWithoutTechnicalFallbackLeaks()
    {
        var policies = new[] { "workspace.view", "objects.view", "field.technical" }.Select(c => Body(new { capability_key = c, effect = "allow", scope_json = new { kind = "all" } })).ToList();
        policies.Add(J("""{"capability_key":"objects.view","effect":"deny","scope_json":{"kind":"server","ids":[22]}}"""));
        policies.Add(J("""{"capability_key":"field.technical","effect":"deny","scope_json":{"kind":"domain","ids":[11]}}"""));
        var facts = new AccessFacts(false, "viewer", [], [], policies, [], [], [], []);
        var rows = new Rows((_, _) => [
            J("""{"id":99999,"object_type":"account","display_name":"DENIED_IDENTITY_SENTINEL","natural_key":"TECHNICAL_SENTINEL","domain_id":11,"server_id":22}"""),
            J("""{"id":8,"object_type":"account","display_name":"","natural_key":"TECHNICAL_SENTINEL","domain_id":11,"server_id":23}""")]);
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> { ["Sli:AuthRequired"] = "true" }).Build();
        using var services = new ServiceCollection().AddLogging().AddSingleton<IConfiguration>(config).AddSingleton(new AuthRequestPolicy(config)).AddSingleton(new TransportGate(config))
            .AddSingleton<IPrincipalAuthenticator>(new Authentication()).AddSingleton<IAccessFactsRepository>(new Facts(facts)).AddSingleton<IWorkspaceCompatibilityReader>(new WorkspaceCompatibilityReader(rows, config, null!, null!, null!)).BuildServiceProvider();
        var context = new DefaultHttpContext { RequestServices = services }; context.Request.Scheme = "https"; context.Request.Path = "/api/v1/workspace"; context.Response.Body = new MemoryStream();
        await WorkspaceCompatibilityEndpoints.HandleAsync(context); Assert.Equal(200, context.Response.StatusCode);
        var body = JsonNode.Parse(((MemoryStream)context.Response.Body).ToArray())!;
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""[{"object_type":"account","object_id":"8","display_name":"8","natural_key":null,"observed_at_utc":null,"source":"Storage V2"}]"""), body["recent_objects"]), body.ToJsonString());
        Assert.DoesNotContain("DENIED_IDENTITY_SENTINEL", body.ToJsonString()); Assert.DoesNotContain("TECHNICAL_SENTINEL", body.ToJsonString());
    }

    [Fact]
    public async Task CachedSnapshotPreservesMetricsAlertsAndDataStateWithoutRefreshingSummary()
    {
        var rows = new Rows((sql, _) =>
        {
            Assert.DoesNotContain("pg_class", sql);
            Assert.DoesNotContain("findings_active", sql);
            Assert.NotEqual(WorkspaceOverview.SourcesSql, sql);
            return [];
        });
        var body = Body(await Overview(rows, Snapshot()).ReadAsync(new QueryCollection(), TestContext.Current.CancellationToken));
        Assert.Equal(J("""{"events_total":10,"events_estimated":true,"entities_total":3,"entities_estimated":true,"important_recent":2,"sources_total":1}""").GetRawText(), body.GetProperty("metrics").GetRawText());
        Assert.Equal("2026-07-16T04:00:00Z", body.GetProperty("generated_at_utc").GetString());
        Assert.Equal("fresh_cache", body.GetProperty("data_state").GetProperty("cache").GetString());
        var alert = Assert.Single(body.GetProperty("alerts").EnumerateArray());
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""{"id":7,"title":"Check","severity":"high","status":"new","actor":null,"target":null,"source":null,"last_seen_utc":null,"evidence_count":1,"assigned_to":null,"updated_at":null,"event_db_id":null}"""), JsonNode.Parse(alert.GetRawText())));
        Assert.False(body.GetProperty("limits").GetProperty("full_history").GetBoolean());
        Assert.True(body.GetProperty("sources")[0].GetProperty("active").GetBoolean());
    }

    [Fact]
    public async Task OldCachedInventoryIsEnrichedAndDeduplicatedWithOriginalHostname()
    {
        var snapshot = Snapshot();
        snapshot["sources"]!["items"] = JsonNode.Parse("""[{"hostname":"DC1","role":"domain_controller","is_active":true}]""");
        int inventoryReads = 0;
        var rows = new Rows((sql, _) =>
        {
            if (sql != WorkspaceOverview.SourcesSql) return [];
            inventoryReads++;
            return [J("""{"hostname":"DC1","fqdn":null,"os_name":null,"os_version":null,"ip_addresses":["192.0.2.19"]}"""),
                    J("""{"hostname":"dc1","fqdn":null,"os_name":null,"os_version":null,"ip_addresses":["192.0.2.19"]}""")];
        });
        var body = Body(await Overview(rows, snapshot).ReadAsync(new QueryCollection(), TestContext.Current.CancellationToken));
        Assert.Equal(1, inventoryReads);
        Assert.Equal(1, body.GetProperty("metrics").GetProperty("sources_total").GetInt32());
        var source = Assert.Single(body.GetProperty("sources").EnumerateArray());
        Assert.Equal("DC1", source.GetProperty("hostname").GetString());
        Assert.Equal("domain_controller", source.GetProperty("role").GetString());
        Assert.Equal("192.0.2.19", Assert.Single(source.GetProperty("ip_addresses").EnumerateArray()).GetString());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ObservedAndWarmingSourcesKeepInventoryAndFreshnessFields(bool warming)
    {
        var snapshot = Snapshot(); snapshot["sources"]!["items"] = new JsonArray();
        var channel = J("""{"server":"DC2","channel":"Security","last_successful_collection_utc":"2026-07-23T03:58:00Z","last_event_time_utc":"2026-07-23T03:57:00Z","last_status":"completed"}""");
        if (warming) { snapshot["status"] = "warming"; snapshot["diagnostics"]!["request_model"] = "startup_warming_response"; }
        else snapshot["collector_health"]!["items"] = new JsonArray(JsonNode.Parse(channel.GetRawText()));
        var rows = new Rows((sql, _) => sql == WorkspaceOverview.SourcesSql
            ? [J("""{"hostname":"DC2","role":"domain_controller","is_active":true,"ip_addresses":["192.0.2.19"]}""")]
            : sql == WorkspaceOverview.CollectorSql ? [channel] : []);
        var body = Body(await Overview(rows, snapshot).ReadAsync(new QueryCollection(), TestContext.Current.CancellationToken));
        var source = Assert.Single(body.GetProperty("sources").EnumerateArray());
        Assert.Equal("DC2", source.GetProperty("hostname").GetString());
        Assert.Equal(warming, source.GetProperty("registered").GetBoolean());
        if (warming) { Assert.True(source.GetProperty("active").GetBoolean()); Assert.Equal("domain_controller", source.GetProperty("role").GetString()); }
        else Assert.Equal(JsonValueKind.Null, source.GetProperty("active").ValueKind);
        Assert.Equal(1, source.GetProperty("channels_total").GetInt32());
        Assert.Equal(DateTimeOffset.Parse("2026-07-23T03:58:00Z"), DateTimeOffset.Parse(source.GetProperty("last_successful_collection_utc").GetString()!));
        Assert.Contains(body.GetProperty("collection_freshness").GetProperty("state").GetString(), new[] { "current", "lagging", "stale" });
    }

    [Theory]
    [InlineData("2026-07-16T04:00:00Z", 24, "24 часа")]
    [InlineData("2026-07-10T04:00:00Z", 7, "7 дней")]
    public async Task ActivityUsesHourlyOrDailyBuckets(string start, int buckets, string label)
    {
        int activityReads = 0;
        var rows = new Rows((sql, parameters) =>
        {
            if (sql.Contains("semantic_events", StringComparison.Ordinal)) { activityReads++; Assert.Equal(buckets, parameters.Single(p => p.ParameterName == "buckets").Value); }
            return [];
        });
        var context = new DefaultHttpContext(); context.Request.QueryString = new($"?time_from={start}&time_to=2026-07-17T04:00:00Z");
        var body = Body(await Overview(rows, Snapshot()).ReadAsync(context.Request.Query, TestContext.Current.CancellationToken));
        Assert.Equal(1, activityReads); Assert.Equal(label, body.GetProperty("activity").GetProperty("period_label").GetString());
    }

    [Theory]
    [InlineData("2026-07-17T03:57:00Z", "completed", "current")]
    [InlineData("2026-07-17T03:48:00Z", "completed", "lagging")]
    [InlineData("2026-07-17T03:39:00Z", "completed", "stale")]
    [InlineData("2026-07-17T03:57:00Z", "failed", "error")]
    public void FreshnessUsesSuccessfulCheckRatherThanEventAge(string check, string status, string expected)
    {
        var channel = Body(new { server = "DC1", channel = "Security", last_successful_collection_utc = check, last_event_time_utc = "2026-07-16T18:00:00Z", last_status = status });
        var result = WorkspaceOverview.Freshness([channel], Now);
        Assert.Equal(expected, result["state"]!.ToString()); Assert.Equal(600, result["worst_event_lag_minutes"]!.GetValue<int>());
    }

    [Fact]
    public void FreshnessDistinguishesPartialFailureAndWorstCheck()
    {
        var good = J("""{"server":"DC1","channel":"Security","last_successful_collection_utc":"2026-07-17T03:59:00Z","last_event_time_utc":"2026-07-16T18:00:00Z","last_status":"completed"}""");
        var bad = J("""{"server":"DC1","channel":"DNS Server","last_successful_collection_utc":"2026-07-17T03:57:00Z","last_status":"failed"}""");
        var result = WorkspaceOverview.Freshness([good, bad], Now);
        Assert.Equal("partial", result["state"]!.ToString()); Assert.Equal("Частичный сбор", result["label"]!.ToString()); Assert.Equal(1, result["channels_failed"]!.GetValue<int>());
        var old = J("""{"server":"DC1","channel":"Directory Service","last_successful_collection_utc":"2026-07-17T03:30:00Z","last_status":"completed"}""");
        result = WorkspaceOverview.Freshness([good, old], Now);
        Assert.Equal("stale", result["state"]!.ToString()); Assert.Equal(600, result["worst_event_lag_minutes"]!.GetValue<int>());
    }
}
